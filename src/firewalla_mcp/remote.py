"""Dependency-free helper sent in memory to Python 3 on the router.

Never installed on the router. Only this operation dispatch is reachable.
Raw command/config output is projected here before crossing SSH.
"""
import ipaddress
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import time

LIMIT = 131072

class Unsupported(Exception):
    pass


def run(argv, seconds=5):
    """Bound time AND bytes while reading; discard stderr and never return it."""
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        raise Unsupported("utility unavailable")
    data = bytearray()
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(p.stdout, selectors.EVENT_READ)
            end = time.monotonic() + seconds
            while True:
                left = end - time.monotonic()
                if left <= 0:
                    raise Unsupported("command timeout")
                events = sel.select(left)
                if not events:
                    raise Unsupported("command timeout")
                chunk = os.read(p.stdout.fileno(), 8192)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > LIMIT:
                    raise Unsupported("output limit exceeded; narrow query")
        if p.wait(timeout=max(.01, end-time.monotonic())) != 0:
            raise Unsupported("command unavailable or permission denied")
        return data.decode("utf-8", errors="strict")
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()
        p.stdout.close()


def atom(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.:@/+*-]{1,80}", value):
        raise Unsupported("unrecognized field format")
    return value


def ip(value):
    return str(ipaddress.ip_address(value))


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("invalid port")
    return value


def port_range(value):
    pieces = str(value).replace(":", "-").split("-")
    if not 1 <= len(pieces) <= 2 or not all(x.isdigit() for x in pieces):
        raise Unsupported("unknown port range")
    nums = [port(int(x)) for x in pieces]
    if nums[0] > nums[-1]:
        raise Unsupported("reversed port range")
    return nums


def network(kind):
    commands = {"interfaces": ["ip", "-j", "-d", "link", "show"],
                "addresses": ["ip", "-j", "address", "show"],
                "routes": ["ip", "-j", "route", "show", "table", "all"],
                "rules": ["ip", "-j", "rule", "show"],
                "neighbors": ["ip", "-j", "neighbor", "show"]}
    rows = json.loads(run(commands[kind]))
    if not isinstance(rows, list):
        raise Unsupported("unknown ip JSON schema")
    # Explicit projection: omit aliases, arbitrary names, extensions, and nested secrets.
    keys = {"ifindex", "ifname", "mtu", "operstate", "address", "dst", "gateway", "dev", "table", "priority", "src", "prefsrc", "lladdr", "protocol"}
    out = []
    for row in rows[:256]:
        item = {k: v for k,v in row.items() if k in keys and isinstance(v,(str,int))}
        if "addr_info" in row:
            item["addresses"] = [{"address": ip(a["local"]), "prefixlen": int(a["prefixlen"])} for a in row["addr_info"][:32]]
        info = row.get("linkinfo", {})
        if info.get("info_kind") == "vlan":
            item["vlan_id"] = int(info.get("info_data", {})["id"])
        out.append(item)
    return {"rows": out, "truncated": len(rows)>256}


def mappings():
    data = json.loads(run(["redis-cli", "--raw", "GET", "extension.portforward.config"]))
    if not isinstance(data, dict) or not isinstance(data.get("maps"), list):
        raise Unsupported("unknown port forwarding schema")
    out = []
    for row in data["maps"][:128]:
        if row.get("protocol") not in ("tcp", "udp"):
            raise Unsupported("unknown forwarding protocol")
        item = {"protocol": row["protocol"], "external_ports": port_range(row["dport"]),
                "destination": ip(row["toIP"]), "destination_ports": port_range(row["toPort"])}
        item["enabled"] = row.get("enabled", True) is True
        out.append(item)
    return {"configured_mappings": out, "truncated": len(data["maps"])>128,
            "note": "Configured intent only; kernel rules and external probes are separate evidence."}


def firewall(table):
    # Numeric listing omits arbitrary comments and log prefixes; expose only parsed rows.
    raw = run(["sudo", "-n", "iptables", "-t", table, "-L", "-n", "-v", "-x"])
    rows, chain = [], None
    for line in raw.splitlines():
        if line.startswith("Chain "):
            chain = atom(line.split()[1])
        parts = line.split()
        if len(parts) >= 9 and parts[0].isdigit() and parts[1].isdigit():
            rows.append(dict(chain=chain, packets=int(parts[0]), bytes=int(parts[1]),
                             target=atom(parts[2]), protocol=atom(parts[3]),
                             input=atom(parts[5]), output=atom(parts[6]),
                             source=str(ipaddress.ip_network(parts[7], strict=False)),
                             destination=str(ipaddress.ip_network(parts[8], strict=False))))
    return {"rows": rows[:256], "truncated": len(rows)>256,
            "note": "IPv4 counters only; match extensions and NAT translations omitted. Not a complete effective policy."}


def write_spec(spec):
    """Validate independently on the router; never accept executable/flag strings."""
    import hashlib
    kind=spec.get("kind")
    if kind == "route":
        if set(spec)-{"kind","destination","table","route_type","gateway","interface"}:
            raise ValueError("unknown route field")
        network=ipaddress.IPv4Network(spec["destination"], strict=True)
        table=spec["table"]
        if type(table) is not int or not 1<=table<=4294967295 or table in (253,254,255):
            raise ValueError("reserved route table")
        typ=spec["route_type"]
        if typ not in ("unicast","blackhole"):
            raise ValueError("route type")
        argv=["ip","-4","route","add"]
        if typ=="blackhole":
            if spec.get("gateway") or spec.get("interface"):
                raise ValueError("blackhole arguments")
            argv += ["blackhole",str(network)]
        else:
            gateway=str(ipaddress.IPv4Address(spec["gateway"]))
            interface=spec["interface"]
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}",interface):
                raise ValueError("interface")
            argv += [str(network),"via",gateway,"dev",interface]
        return argv+["table",str(table),"proto","static"], None
    if kind not in ("filter_rule","dnat"):
        raise ValueError("unsupported write")
    allowed={"kind","chain","source","destination","protocol","destination_port","action"} if kind=="filter_rule" else {"kind","chain","public_address","protocol","external_port","destination_address","destination_port","interface"}
    if set(spec)-allowed:
        raise ValueError("unknown rule field")
    chain=spec["chain"]
    if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_-]{0,27}",chain):
        raise ValueError("chain")
    protocol=spec["protocol"]
    if protocol not in ("tcp","udp"):
        raise ValueError("protocol")
    table="filter" if kind=="filter_rule" else "nat"
    argv=["iptables","-w","2","-t",table,"-A",chain]
    if kind=="filter_rule":
        source=str(ipaddress.IPv4Network(spec["source"],strict=True))
        destination=str(ipaddress.IPv4Network(spec["destination"],strict=True))
        if spec["action"] not in ("ACCEPT","DROP","REJECT"):
            raise ValueError("action")
        argv += ["-s",source,"-d",destination,"-p",protocol,"-m",protocol,"--dport",str(port(spec["destination_port"]))]
    else:
        interface=spec["interface"]
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}",interface):
            raise ValueError("interface")
        address=str(ipaddress.IPv4Address(spec["public_address"]))
        argv += ["-d",address+"/32","-i",interface,"-p",protocol,"-m",protocol,"--dport",str(port(spec["external_port"]))]
    tag="fw-mcp-"+hashlib.sha256(json.dumps(spec,sort_keys=True,separators=(",",":")).encode()).hexdigest()[:20]
    argv += ["-m","comment","--comment",tag,"-j",spec["action"] if kind=="filter_rule" else "DNAT"]
    if kind=="dnat":
        argv += ["--to-destination",str(ipaddress.IPv4Address(spec["destination_address"]))+":"+str(port(spec["destination_port"]))]
    return argv,tag


def write_state(spec):
    import hashlib
    argv,tag=write_spec(spec)
    if spec["kind"]=="route":
        rows=json.loads(run(["ip","-4","-N","-j","route","show","table","all"]))
        if not isinstance(rows,list):
            raise Unsupported("route schema")
        normalized=[]
        for row in rows:
            if not isinstance(row,dict):
                raise Unsupported("route row schema")
            table=row.get("table",254)
            if isinstance(table,str) and table in ("unspec","default","main","local"):
                table={"unspec":0,"default":253,"main":254,"local":255}[table]
            elif isinstance(table,str) and re.fullmatch(r"[0-9]{1,10}",table):
                table=int(table)
            if type(table) is not int or not 0<=table<=4294967295:
                # -N must resolve custom names. Never silently omit a possibly matching table.
                raise Unsupported("numeric route tables required")
            if table!=spec["table"]:
                continue
            destination=row.get("dst")
            if not isinstance(destination,str) or not destination:
                raise Unsupported("route destination schema")
            destination=str(ipaddress.IPv4Network("0.0.0.0/0" if destination=="default" else destination,strict=True))
            normalized.append({**row,"table":table,"dst":destination})
        canonical=json.dumps(sorted(normalized,key=lambda r:json.dumps(r,sort_keys=True)),sort_keys=True)
        destination=str(ipaddress.IPv4Network(spec["destination"],strict=True))
        exists=any(row["dst"]==destination for row in normalized)
    else:
        table="filter" if spec["kind"]=="filter_rule" else "nat"
        canonical=run(["sudo","-n","iptables","-w","2","-t",table,"-S",spec["chain"]])
        exists=tag in canonical
    return {"fingerprint":hashlib.sha256(canonical.encode()).hexdigest(),"present":exists}


def write_operation(args):
    spec=args["spec"]
    argv,tag=write_spec(spec)
    mode=args["mode"]
    if mode=="preview":
        return write_state(spec)
    if mode not in ("apply","rollback") or not re.fullmatch(r"[a-f0-9]{64}",args["expected"]):
        raise ValueError("write mode")
    # No claim of cross-process atomicity against Firewalla or other administrators.
    before=write_state(spec)
    if before["fingerprint"]!=args["expected"]:
        return {"outcome":"stale","state":before,"changed":False}
    if mode=="apply" and before["present"]:
        return {"outcome":"already_present","state":before,"changed":False}
    if mode=="rollback" and not before["present"]:
        return {"outcome":"already_absent","state":before,"changed":False}
    if mode=="rollback":
        argv[3 if spec["kind"]=="route" else 5]="del" if spec["kind"]=="route" else "-D"
    try:
        if "expires_at" in args:require_action_deadline(args)
        run(["sudo","-n"]+argv)
    except (Unsupported, OSError, subprocess.TimeoutExpired):
        return {"outcome":"uncertain","changed":None,"reason":"Mutation command failed or timed out. Inspect actual state; do not retry automatically."}
    try:
        after=write_state(spec)
    except (Unsupported, ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
        return {"outcome":"uncertain","changed":None,"reason":"After-state could not be read. Inspect actual state; do not retry automatically."}
    expected_presence=mode=="apply"
    if after["present"]!=expected_presence:
        return {"outcome":"uncertain","state":after,"changed":None}
    return {"outcome":"applied" if mode=="apply" else "rolled_back","state":after,"changed":True,
            "scope":"temporary kernel state, not Firewalla-managed persistent configuration"}


def selected_fields(key, fields):
    values=run(["redis-cli","--raw","HMGET",key]+fields).splitlines()
    if len(values)!=len(fields):
        raise Unsupported("selected field schema")
    return dict(zip(fields,values))


def policy_feature(raw, feature, global_scope=False):
    if raw=="":
        return {"present":False,"raw_state":"missing","meaning":"unset"}
    value=json.loads(raw)
    if feature in ("safeSearch","unbound","doh"):
        if not isinstance(value,dict) or "state" not in value:
            raise Unsupported("feature policy schema")
        value=value["state"]
    if value is not None and type(value) is not bool:
        raise Unsupported("feature tri-state schema")
    meaning=("enable" if value is True else "disable") if global_scope else ("enable" if value is True else "inherit" if value is False else "explicit_disable")
    return {"present":True,"raw_state":value,"meaning":meaning if feature != "doh" else "uninterpreted","effective":"unknown"}


def control_state(args):
    kind,target=args["target_kind"],args["target"]
    if kind=="device":
        if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}",target):
            raise ValueError("mac")
        key="policy:mac:"+target.upper()
    elif kind=="group" and re.fullmatch(r"[0-9]{1,20}",target):
        key="policy:tag:"+target
    else:
        raise ValueError("target")
    fields=["adblock","safeSearch","unbound","doh"]
    direct=selected_fields(key,fields)
    global_values=selected_fields("policy:system",fields)
    return {"explicit":{k:policy_feature(v,k) for k,v in direct.items()},
            "global":{k:policy_feature(v,k,True) for k,v in global_values.items()},
            "group_network_inheritance":"unresolved","effective":"unknown",
            "rule_controls":{k:"ordinary rule; use control_rule_page" for k in ("internet","gaming","social","video","porn","apps")},
            "note":"False means unset/inherit and null means explicit disable for these scoped feature policies in reviewed source. Global policy uses different semantics. Removing an override does not prove a global block is bypassed. VPN is read separately. No controls changed."}


def app_catalog(args):
    raw=run(["redis-cli","--raw","GET","app_time_usage_cloud_config"])
    data=json.loads(raw)
    if not isinstance(data,dict) or not isinstance(data.get("appConfs"),dict):
        raise Unsupported("app catalog absent")
    entries=[]
    for identifier,conf in sorted(data["appConfs"].items()):
        if not isinstance(conf,dict):
            raise Unsupported("app config shape")
        features=conf.get("features")
        if features is None:
            continue
        if isinstance(features,list):
            projected=[atom(x) for x in features[:32]]
        elif isinstance(features,dict):
            projected={atom(k):v for k,v in features.items() if type(v) is bool}
        else:
            raise Unsupported("feature flags shape")
        entries.append({"id":atom(identifier),"declared_features":projected,
                        "ordinary_block_target":"TLX-fw-"+atom(identifier) if isinstance(features,dict) and features.get("acl") is True else None})
    return {"apps":entries[:256],"truncated":len(entries)>256,"note":"Cached firmware app feature declarations only. Usage-tracked apps are not necessarily blockable. No cloud request performed; beta/model/firmware support may differ. No app labels or domains inferred."}


# Read-only bounded Redis batches. No HGETALL, credentials, or management writes.
RULE_FIELDS = ['type','target','action','disabled','direction','scope','tag','localPort','remotePort',
               'protocol','cronTime','duration','expire','description','name','matchAppId','timezone','timestamp']
RULE_PAGE_LUA = """
local typ=redis.call('TYPE','policy_active').ok
if typ~='zset' then return cjson.encode({unsupported=true}) end
local total=redis.call('ZCARD','policy_active')
if total>2000 then return cjson.encode({too_many=true,total=total}) end
local ids=redis.call('ZREVRANGE','policy_active',0,-1)
local version=redis.sha1hex(cjson.encode(ids))
local offset=tonumber(ARGV[1]); local count=tonumber(ARGV[2]); local fields=cjson.decode(ARGV[3])
local rows={}; local bytes=0
for i=offset+1,math.min(#ids,offset+count) do
 local id=ids[i]; if not string.match(id,'^%d+$') or #id>20 then return cjson.encode({unsupported=true}) end
 local row={id=id,values={}}
 for _,f in ipairs(fields) do
  local size=redis.call('HSTRLEN','policy:'..id,f)
  if size>2048 then return cjson.encode({oversized=true}) end
  bytes=bytes+size; if bytes>70000 then return cjson.encode({oversized=true}) end
  row.values[f]=redis.call('HGET','policy:'..id,f)
 end
 table.insert(rows,row)
end
return cjson.encode({total=total,version=version,rows=rows})
"""
RULE_NAMES_LUA = """
local result={};local bytes=0
for _,key in ipairs(KEYS) do
 local row={}
 for _,field in ipairs({'name','bname','intf'}) do
  if redis.call('HSTRLEN',key,field)>256 then return cjson.encode({oversized=true}) end
  local value=redis.call('HGET',key,field);if value then bytes=bytes+#value end
  if bytes>16000 then return cjson.encode({oversized=true}) end
  row[field]=value
 end
 result[key]=row
end
return cjson.encode(result)
"""


def rule_text(value, size=256):
    if value is False or value is None or value == '':
        return None
    if not isinstance(value,str) or len(value)>size or any(ord(c)<32 for c in value):
        return None
    return value


def rule_list(value):
    if value in (None,False,''):
        return []
    try:
        rows=json.loads(value)
    except (ValueError,TypeError):
        return None
    if not isinstance(rows,list) or len(rows)>32 or not all(rule_text(v,128) for v in rows):
        return None
    return rows


def rule_page(args):
    import hashlib
    started=time.monotonic()
    limit=args.get('limit',5); cursor=args.get('cursor','0')
    enabled=args.get('enabled'); action=args.get('action'); device=args.get('device'); category=args.get('category')
    if type(limit) is not int or not 1<=limit<=50 or enabled is not None and type(enabled) is not bool:
        raise ValueError('rule page')
    if action not in (None,'allow','block','route','match','alarm','qos','snat'):
        raise ValueError('action filter')
    if device is not None:
        if not isinstance(device,str) or not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',device):
            raise ValueError('device filter must be MAC')
        device=device.upper()
    if category is not None and (not isinstance(category,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',category)):
        raise ValueError('category filter')
    signature=hashlib.sha256(json.dumps([enabled,action,device,category],separators=(',',':')).encode()).hexdigest()[:16]
    offset=0; version=None
    if cursor!='0':
        if not isinstance(cursor,str) or not re.fullmatch(r'[0-9]{1,4}:[a-f0-9]{40}:[a-f0-9]{16}',cursor):
            raise ValueError('cursor')
        pos,version,bound=cursor.split(':');offset=int(pos)
        if offset>2000 or bound!=signature:
            raise ValueError('cursor filter mismatch')
    raw=json.loads(run(['redis-cli','--raw','EVAL',RULE_PAGE_LUA,'0',str(offset),str(limit),json.dumps(RULE_FIELDS)]))
    if not isinstance(raw,dict) or not all(k in raw for k in ('total','version','rows')):
        raise Unsupported('rule index exceeds bound or selected-field schema unavailable')
    if version and version!=raw['version']:
        return {'records':[],'total':raw['total'],'total_semantics':'unfiltered_index_count','has_more':True,
                'cursor':None,'next_cursor':None,'restart_required':True,'reason':'Rule index changed; restart at cursor 0'}
    rows=raw['rows'] or []
    if not isinstance(rows,list) or len(rows)>limit:
        raise Unsupported('rule page schema')
    projected=[]; name_keys=set(); missing=0
    for entry in rows:
        p=entry['values']
        if not p.get('type'):
            missing+=1;continue
        disabled=p.get('disabled')
        if disabled in (False,None,'','0','false'):
            state='enabled'; disabled_value=False
        elif disabled in ('1','true'):
            state='disabled'; disabled_value=True
        else:
            state='unknown'; disabled_value=None
        scope=rule_list(p.get('scope')); tags=rule_list(p.get('tag'))
        if enabled is not None and (disabled_value is None or enabled==disabled_value):continue
        if action is not None and p.get('action')!=action:continue
        if category is not None and not (p.get('type')=='category' and p.get('target')==category):continue
        if device is not None and not (scope is not None and device in [s.upper() for s in scope] or p.get('type')=='mac' and str(p.get('target','')).upper()==device):continue
        if p.get('type')=='mac' and isinstance(p.get('target'),str) and re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',p['target']) and scope is not None:
            scope=list(dict.fromkeys(scope+[p['target'].upper()]))
        scopes=[]
        if scope is None or tags is None:
            scopes.append({'kind':'unknown','id':None,'name':None})
        for value in scope or []:
            if re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',value):
                value=value.upper(); key='host:mac:'+value;name_keys.add(key)
                scopes.append({'kind':'device','id':value,'_keys':[key]})
            else:scopes.append({'kind':'unknown','id':rule_text(value,128),'name':None})
        for value in tags or []:
            if value.startswith('tag:') and re.fullmatch(r'[0-9]{1,20}',value[4:]):
                keys=[prefix+value[4:] for prefix in ('tag:uid:','deviceTag:uid:','userTag:uid:','ssidTag:uid:')]
                name_keys.update(keys);scopes.append({'kind':'group','id':value[4:],'_keys':keys})
            elif value.startswith('intf:') and re.fullmatch(r'[A-Za-z0-9_-]{1,64}',value[5:]):
                key='network:uuid:'+value[5:];name_keys.add(key)
                scopes.append({'kind':'network','id':value[5:],'_keys':[key]})
            else:scopes.append({'kind':'unknown','id':rule_text(value,128),'name':None})
        if not scopes:scopes=[{'kind':'global','id':None,'name':'All devices (configured scope)'}]
        item={k:rule_text(p.get(k)) for k in ('type','target','action','direction','localPort','remotePort','protocol','cronTime','duration','expire','description','name','matchAppId','timezone','timestamp')}
        item.update({'id':entry['id'],'disabled':disabled_value,'configured_state':state,'scopes':scopes,
                     'effective_state':'unknown','state_explanation':'Stored rule setting only; schedules, expiry, exceptions and inherited applicability are not evaluated.'})
        if disabled in (False,None,''):item['state_explanation']='Missing disabled flag defaults to enabled in reviewed Firewalla Policy.isDisabled; enforcement is not verified.'
        item['app_id']=item['matchAppId'] or (item['target'][7:] if item['type']=='category' and item['target'] and item['target'].startswith('TLX-fw-') else None)
        projected.append(item)
    if len(name_keys)>128:raise Unsupported('name resolution bound; narrow page')
    names=json.loads(run(['redis-cli','--raw','EVAL',RULE_NAMES_LUA,str(len(name_keys))]+sorted(name_keys))) if name_keys else {}
    if not isinstance(names,dict) or names.get('oversized'):raise Unsupported('name metadata bound')
    for item in projected:
        for scope in item['scopes']:
            keys=scope.pop('_keys',[])
            if keys:
                candidates=[rule_text(names.get(key,{}).get(field)) for key in keys for field in ('name','bname','intf')]
                scope['name']=next((v for v in candidates if v),None)
                scope['name_resolution']='resolved' if scope['name'] else 'unavailable'
    next_offset=offset+len(rows); more=next_offset<raw['total']
    token=f"{next_offset}:{raw['version']}:{signature}" if more else None
    return {'records':projected,'total':raw['total'],'total_semantics':'unfiltered_index_count',
            'returned':len(projected),'scanned':len(rows),'skipped_missing':missing,'has_more':more,
            'may_have_more':more,'cursor':token,'next_cursor':token,'restart_required':False,
            'matched_total':None,'elapsed_ms':round((time.monotonic()-started)*1000,2),
            'note':'Cursor advances scanned index entries, including filtered-out rules. Follow empty pages while has_more. Index changes require restart; field changes are not snapshot-isolated. Device filter matches explicit scope only; inherited group/network/global applicability is not evaluated. No enforcement claim.'}


def control_rules(args):
    kind,target=args["target_kind"],args["target"]
    if kind=="device":
        if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}",target):
            raise ValueError("mac")
        target=target.upper()
    elif kind!="group" or not re.fullmatch(r"[0-9]{1,20}",target):
        raise ValueError("group")
    offset,limit=args["offset"],args["limit"]
    if type(offset) is not int or not 0<=offset<=10000 or type(limit) is not int or not 1<=limit<=20:
        raise ValueError("page")
    if run(["redis-cli","--raw","TYPE","policy_active"]).strip()!="zset":
        raise Unsupported("policy index")
    ids=[v for v in run(["redis-cli","--raw","ZREVRANGE","policy_active",str(offset),str(offset+limit-1)]).splitlines() if v]
    fields=["type","target","action","scope","tag","disabled","expire","cronTime","duration","idleTs","matchAppId"]
    rows=[]
    for identifier in ids:
        if not re.fullmatch(r"[0-9]{1,20}",identifier):
            raise Unsupported("policy id")
        p=selected_fields("policy:"+identifier,fields)
        if p["type"] not in ("category","internet","mac"):
            continue
        scope=json.loads(p["scope"] or "[]");tags=json.loads(p["tag"] or "[]")
        if not isinstance(scope,list) or not isinstance(tags,list):
            raise Unsupported("rule scope")
        if kind=="device" and (target in scope or (p["type"]=="mac" and p["target"]==target)):
            applicability="explicit_device"
        elif kind=="group" and "tag:"+target in tags:
            applicability="explicit_group"
        elif not scope and not tags:
            applicability="global_candidate"
        else:
            continue
        if p["type"]=="mac" and p["target"] not in ("", "TAG", target):
            continue
        item={"id":identifier,"type":p["type"],"applicability":applicability,
              "target_id":atom(p["target"]) if p["type"]=="category" else "internet_candidate",
              "action":atom(p["action"]) if p["action"] else None,
              "disabled":p["disabled"]=="1" if p["disabled"] in ("0","1") else None,
              "app_id":atom(p["matchAppId"]) if p["matchAppId"] else None}
        for k in ("expire","duration","idleTs"):
            if p[k]:
                v=float(p[k])
                if not 0<=v<=4102444800:
                    raise Unsupported("timer shape")
                item[k]=v
        # Cron content is metadata, validated tightly; no interpretation or execution.
        if p["cronTime"]:
            if not re.fullmatch(r"[0-9*/?, A-Za-z#L-]{1,100}",p["cronTime"]):
                raise Unsupported("schedule format")
            item["schedule_expression"]=p["cronTime"]
        rows.append(item)
    return {"rules":rows,"next_offset":offset+len(ids) if len(ids)==limit else None,
            "scanned":len(ids),"complete":False,"effective":"unknown",
            "note":"Filtered page of ordinary rules, not full policy evaluation. Group/network inheritance, exceptions, precedence, schedule timezone and enforcement remain unresolved. No rule mutation performed."}


def category_enum():
    raw=run(["redis-cli","--raw","GET","intel:enum:category"]).strip()
    if not raw:
        return {}
    data=json.loads(raw)
    if not isinstance(data,dict) or len(data)>512:
        raise Unsupported("category enum")
    return {str(v):atom(k) for k,v in data.items() if type(v) is int}


def domain_name(value):
    if not isinstance(value,str) or len(value)>253:
        return None
    value=value.rstrip(".").lower()
    if all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",label) for label in value.split(".")):
        return value
    return None


def project_flow(flow,blocked,categories):
    ts=flow.get("ts",flow.get("_ts"))
    if type(ts) not in (int,float) or not 0<=ts<=4102444800:
        raise Unsupported("flow timestamp")
    if blocked:
        outbound=flow.get("type")=="dns" or flow.get("fd")!="out"
    else:
        outbound=ip(flow["lh"])==ip(flow["sh"])
    destination=flow.get("dh" if outbound else "sh")
    destination=ip(destination) if destination else None
    number=flow.get("dp") if outbound else flow.get("sp")
    if type(number) is list:
        number=number[0] if number else None
    number=port(int(number)) if number not in (None,0,"0") else None
    names=[]
    if flow.get("dn"):
        name=domain_name(flow["dn"])
        if name:names.append(name)
    if isinstance(flow.get("af"),dict):
        names += [n for n in (domain_name(x) for x in list(flow["af"])[:8]) if n]
    category=categories.get(str(flow.get("c")))
    if isinstance(flow.get("category"),str):
        category=atom(flow["category"])
    protocol=flow.get("pr")
    if protocol not in ("tcp","udp","icmp","icmp6"):
        protocol="unknown"
    up=down=None
    if "ob" in flow and "rb" in flow:
        ob,rb=flow["ob"],flow["rb"]
        if type(ob) not in (int,float) or type(rb) not in (int,float) or not 0<=ob<=2**63 or not 0<=rb<=2**63:
            raise Unsupported("flow bytes")
        up,down=(ob,rb) if outbound else (rb,ob)
    return {"timestamp":ts,"direction":"outbound" if outbound else "inbound",
            "verdict":"blocked_observation" if blocked else "connection_observed",
            "destination_ip":destination,"domains":sorted(set(names)),"destination_port":number,
            "protocol":protocol,"upload_bytes":up,"download_bytes":down,"category":category,
            "country":None,"attribution":"observed DNS/app-host metadata only; not proof of deliberate browsing"}


def device_flow_page(args):
    mac=args["mac"].upper()
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}",mac):raise ValueError("mac")
    start,end,offset,limit=(args[k] for k in ("start","end","offset","limit"))
    if any(type(x) is not int for x in (start,end,offset,limit)) or not 0<=start<end<=4102444800 or end-start>604800 or not 0<=offset<=10000 or not 1<=limit<=25:
        raise ValueError("bounded interval/page")
    verdict,direction=args["verdict"],args["direction"]
    if verdict not in ("connections","blocked","all") or direction not in ("all","inbound","outbound"):
        raise ValueError("flow selector")
    include,exclude=args["include_categories"],args["exclude_categories"]
    if not isinstance(include,list) or not isinstance(exclude,list) or len(include)+len(exclude)>16:
        raise ValueError("category filters")
    for name in include+exclude:atom(name)
    sources=[]
    if verdict!="blocked":sources += [("flow:conn:in:"+mac,False),("flow:conn:out:"+mac,False)]
    if verdict!="connections":sources += [("audit:drop:"+mac,True)]
    categories=category_enum()
    records=[];counts={};coverage={};more=False;unknown=0
    for key,blocked in sources:
        label="blocked" if blocked else "connection_"+key.split(":")[2]
        kind=run(["redis-cli","--raw","TYPE",key]).strip()
        if kind=="none":
            counts[label]=0;coverage[label]="absent_or_expired";continue
        if kind!="zset":raise Unsupported("flow key schema")
        count=run(["redis-cli","--raw","ZCOUNT",key,str(start),str(end)]).strip()
        if not count.isdigit():raise Unsupported("flow count")
        counts[label]=int(count);coverage[label]="observed_index"
        raw=run(["redis-cli","--raw","ZREVRANGEBYSCORE",key,str(end),str(start),"LIMIT",str(offset),str(limit),"WITHSCORES"]).splitlines()
        if len(raw)%2 or len(raw)>limit*2:raise Unsupported("flow page schema")
        more |= len(raw)//2==limit and offset+limit<counts[label]
        for i in range(0,len(raw),2):
            flow=json.loads(raw[i]);row=project_flow(flow,blocked,categories)
            if not start<=row["timestamp"]<=end:continue
            if direction!="all" and row["direction"]!=direction:continue
            if row["category"] is None:unknown+=1
            if include and row["category"] not in include:continue
            if row["category"] in exclude:continue
            records.append(row)
    records.sort(key=lambda row:row["timestamp"],reverse=True)
    return {"records":records,"next_offset":offset+limit if more else None,"index_counts_before_filters":counts,
            "coverage":coverage,"unknown_category_records_in_page":unknown,"timezone":"UTC","start":start,"end":end,
            "pagination":"Same offset per selected source; up to 3*limit rows. Mutable indexes can cause duplicates/gaps across pages.",
            "limitations":"Index scores select candidates; event timestamps are then filtered. Retention and index/event time differences can omit records. Connections are not guaranteed allowed or deliberate browsing; blocked bytes may be unknown. Domain/category/country attribution may be absent. No payloads."}


def service_features(feature):
    if feature not in ("all","doh","unbound","ntp","radius","custom_dns"):
        raise ValueError("service")
    requested=("doh","unbound","ntp","radius","custom_dns") if feature=="all" else (feature,)
    results={}
    for item in requested:
        if item=="custom_dns":
            results[item]={"status":"unsupported","reason":"Custom DNS rule schema and CRUD management not validated"}
            continue
        flag={"doh":"doh","unbound":"unbound","ntp":"ntp_redirect","radius":"freeradius_server"}[item]
        raw=run(["redis-cli","--raw","HGET","sys:features",flag]).strip()
        if raw not in ("","0","1"):
            raise Unsupported("feature flag shape")
        data={"dynamic_override":None if raw=="" else raw=="1","effective_enabled":"unknown; base/platform flags not resolved"}
        if item=="doh":
            selected=run(["redis-cli","--raw","GET","ext.dnscrypt.servers"]).strip()
            if selected:
                names=json.loads(selected)
                if not isinstance(names,list) or len(names)>32:
                    raise Unsupported("selected provider names")
                data["selected_provider_ids"]=[atom(name) for name in names]
            else:data["selected_provider_ids"]=None
            data["limits"]="Names only; provider stamps, URLs, customized-server secrets and scope evaluation not read"
        elif item=="unbound":
            fields=selected_fields("ext.unbound",["upstream","dnssec","killSwitch","vpnClient"])
            for key in ("dnssec","killSwitch"):
                value=json.loads(fields[key]) if fields[key] else None
                if value is not None and type(value) is not bool:
                    raise Unsupported("unbound boolean")
                data[key]=value
            value=json.loads(fields["upstream"]) if fields["upstream"] else None
            if value not in (None,"tcp","udp"):
                raise Unsupported("unbound upstream")
            data["upstream"]=value
            data["dns_over_vpn"]=None
            if fields["vpnClient"]:
                policy=json.loads(fields["vpnClient"])
                if not isinstance(policy,dict) or type(policy.get("state")) is not bool:
                    raise Unsupported("DNS VPN reference schema")
                data["dns_over_vpn"]={"state":policy["state"],"profile_id":atom(policy["profileId"]) if policy.get("profileId") else None}
            data["limits"]="Configured fields only; absent fields do not imply defaults. No VPN profile/config read or effective DNS-route claim"
        elif item=="ntp":
            value=run(["redis-cli","--raw","GET","sys:ntp:status"]).strip()
            if value not in ("","0","1"):
                raise Unsupported("ntp status")
            data["observed_cached_server_status"]=None if value=="" else value=="1"
            data["limits"]="Cached sensor observation can be stale; target networks/interception effectiveness unresolved. No clock/time or service changes"
        else:
            data["runtime_status"]="unsupported"
            data["limits"]="Only dynamic feature flag read. No RADIUS policies, users, certificates, private keys or shared secrets accessed"
        results[item]={"status":"ok","data":data}
    return results


# Independently implemented protocol adapter; reviewed upstream revision only.
MANAGEMENT_REVISION = '4b4d9fecbd9fd56613ffba91a7c88b26f1b67396'

# Two release commits with the identical reviewed source tree. VPN operations only.
VPN_MANAGEMENT_REVISIONS = ('173ac36dccb5239a5195a5b4e64d20cb1b618a91',
                            'a92caef41689e5d4c929207c003b1a667f39ece2')
VPN_SOURCE_TREE = '85d99a2bc15d97cc4523d00d4a2f67263a0b22a1'
VPN_SOURCE_HASHES = {'controllers/netbot.js': 'd7ae7676389d54fff71c0dadf83540a8cd454a8d1dca9336fa8d8b83cc7c9871', 'api/routes/encipher.js': '719469781ebbd9096981594d00bc40f1ae6f9f90366f615a1a317cb1c1a8df3a', 'api/app-local.js': '9a65a851ed8a72142f8ce2379e1e08226aeb62c58a6ed0311f8ea15c91eb595f', 'net2/Host.js': 'c5656272ffe1fc82bab90f6ba556b0b257d2deabaa680b7d4c5086407cf8dbff', 'net2/HostManager.js': '8e01724086e36e10c0e182449d4edefba7577b6d18666a7049752997af0c2771', 'net2/Monitorable.js': '69bf2bcf8e0895e4cc2a515ad53bcf0e11dcd0986eb87fbcb897a6feb527bc77', 'net2/PolicyManager.js': '49f5c1de644f09c2bd3700a06acdc8ff8aa158a7ffb2c623cba461aeac625b2a', 'extension/vpnclient/VPNClient.js': 'a08e6c378758504ea57a96136ea1d3d35fc2634aef299b8b5d40de1e0fff52c1', 'extension/vpnclient/OpenVPNClient.js': 'bf3bca904c057949f453992c3c8f004ead43bb6dd968dab63e0f94b62e84efb6', 'extension/vpnclient/WGVPNClient.js': 'd13525533885603985f503994b3d4fc555cb02eafb7807a97c7be2d71a5615f8', 'util/i18n.js': 'c8b93144f1b3bbc79a07198d44f17e6c948fa8d1de275dc2d75c91678935069e'}
VPN_SAFETY_DEFAULTS = {'strictVPN':False, 'routeDNS':True,
                       'overrideDefaultRoute':True, 'c2sSNATDisabled':False}


def contract_file(root, relative, maximum=2097152):
    import stat
    path = os.path.join(root, relative)
    parent = os.path.dirname(path)
    while parent != '/':
        if not stat.S_ISDIR(os.lstat(parent).st_mode):
            raise Unsupported('source ancestor is not a real directory')
        parent = os.path.dirname(parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise Unsupported('source file type or size changed')
        data = os.read(fd, maximum + 1)
        if len(data) != info.st_size or len(data) > maximum:
            raise Unsupported('source file changed while reading')
        return data
    finally:
        os.close(fd)


def vpn_source_guard(revision, root='/home/pi/firewalla', runner=None):
    """No management call, credentials or mutation; exact reviewed source check."""
    import hashlib
    runner = runner or run
    if revision not in VPN_MANAGEMENT_REVISIONS:
        raise Unsupported('unreviewed VPN revision')
    if runner(['git','-C',root,'rev-parse','HEAD']).strip() != revision:
        raise Unsupported('installed source revision mismatch')
    if runner(['git','-C',root,'rev-parse','HEAD^{tree}']).strip() != VPN_SOURCE_TREE:
        raise Unsupported('installed source tree mismatch')
    changed = runner(['git','-C',root,'status','--porcelain','-z','--untracked-files=no'])
    rows = [row for row in changed.split('\0') if row]
    if any(row not in (' M locales/en.json','M  locales/en.json','MM locales/en.json') for row in rows):
        raise Unsupported('modified executable or unreviewed source')
    for name, expected in VPN_SOURCE_HASHES.items():
        if hashlib.sha256(contract_file(root,name)).hexdigest() != expected:
            raise Unsupported('reviewed VPN source digest mismatch')
    # i18n consumes this only as translation data; no policy/control value comes
    # from it. Permit string dictionaries, not arbitrary files or symlinks.
    if rows:
        value = json.loads(contract_file(root,'locales/en.json'))
        def strings(v, depth=0):
            return depth < 12 and (isinstance(v,str) or isinstance(v,dict) and
                all(isinstance(k,str) and strings(x,depth+1) for k,x in v.items()))
        if not isinstance(value,dict) or not strings(value):
            raise Unsupported('locale edit is not a translation dictionary')
    return {'revision':revision,'tree':VPN_SOURCE_TREE,'contract_files_verified':len(VPN_SOURCE_HASHES),
            'translation_only_edit':bool(rows)}



# Reviewed installed policy/control contracts; DoH/NTP implementations excluded.
POLICY_SOURCE_HASHES = {'alarm/Policy.js': 'd05901cc617be04bdda3a5b225386c04d597a28313449d2a67afa68aea0a6677', 'alarm/PolicyManager2.js': 'd1d290f38c12ca5b2a2a94e0c05f3d5cef69c7018fd92dbc8e6e76fe8f40a27f', 'sensor/AdblockPlugin.js': '81a5e3c3fa68d4d31af674394ca6bd5c8608c6ce22b0dd65756994e259082667', 'sensor/SafeSearchPlugin.js': 'a60f7e208b4eeb62d67ae72f4ed6990f7ec2c7cfc4c67f2319c12e062897e1d7', 'sensor/UnboundPlugin.js': '2e2b57900d207c46579e03e6c97bc687a30919c4dd5313d2a1143ec6d3581d55'}
POLICY_FEATURES = ('adblock','safeSearch','unbound')


def policy_source_guard(revision, root='/home/pi/firewalla', runner=None):
    import hashlib
    result = vpn_source_guard(revision, root, runner)
    for name, expected in POLICY_SOURCE_HASHES.items():
        if hashlib.sha256(contract_file(root,name)).hexdigest() != expected:
            raise Unsupported('reviewed policy source digest mismatch')
    return {**result, 'policy_contract_files_verified':len(POLICY_SOURCE_HASHES)}


def canonical_rule_ip(value):
    if not isinstance(value,str) or '%' in value or any(c.isspace() or ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError('unscoped literal IP required')
    return str(ipaddress.ip_address(value))


def rule_identity(kind,target):
    if not isinstance(kind,str) or not isinstance(target,str):
        raise Unsupported('rule identity schema')
    if kind in ('dns','domain'):
        return ('dns',target.lower())
    if kind=='mac':
        return (kind,target.upper())
    if kind=='ip':
        if '%' in target or any(c.isspace() or ord(c)<32 or ord(c)==127 for c in target):
            raise Unsupported('scoped or malformed existing IP rule')
        return (kind,str(ipaddress.ip_network(target,strict=False)))
    return (kind,target)


def managed_rule_matches(row,desired,spec,disabled):
    if not row or len(row)<9:
        return False
    matched=row[1:5]==[desired['type'],desired['target'],desired['action'],'outbound'] and (desired['type']=='mac' or json.loads(row[5])==[spec['device']]) and row[6] in (('1',) if disabled else (False,'0',None,'')) and row[8] in (False,None,'')
    if 'schedule' in spec:
        matched=matched and len(row)>9 and row[7]==desired['cronTime'] and str(row[9])==str(desired['duration'])
    else:
        matched=matched and row[7] in (False,None,'')
    if spec['rule_type']=='dns_override':
        matched=matched and len(row)>12 and row[10]==desired['resolver'] and row[11] in ('0','false') and row[12] in ('1','true')
    return matched


# Independently implemented adapter for the reviewed FireMain message contract.
FORWARD_SOURCE_HASHES = {
    'extension/portforward/portforward.js':'0db0a855be5d04a5110b949342d26b5f62db6d48b9b249110321f0c410958158',
    'control/IptablesControl.js':'a6017d3f0d81cbb50d34fe7c835aa3a2dc284bd8d67d73f4587fd5582f74f772',
    'net2/Iptables.js':'891e5af9244d1b73ddb8b381129a29df8954d93344d12376f0a2f63679530ee1',
    'net2/MessageBus.js':'4388bfbaf52f6e96a622bb3030139e00c85f3740f2b9b1fa2ceb9f8a2cd6dc26',
}


def forward_digest(value):
    import hashlib
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def forward_port_range(value):
    if isinstance(value,bool):raise Unsupported('invalid existing mapping port')
    text=str(value)
    if not re.fullmatch(r'[0-9]{1,5}(?:[-:][0-9]{1,5})?',text):raise Unsupported('unrecognized existing mapping port')
    parts=re.split('[-:]',text);lo=int(parts[0]);hi=int(parts[-1])
    if not 1<=lo<=hi<=65535:raise Unsupported('invalid existing mapping range')
    return lo,hi


def forward_value(spec, state=True):
    # Never send wildcards: native removePort/find matches more broadly with them.
    return {'wanUUID':'VC:'+spec['profile'],'protocol':spec['protocol'],
            'dport':str(spec['external_port']),'toPort':str(spec['destination_port']),
            'toMac':spec['device'],'toIP':spec['destination_ip'],
            '_type':'port_forward','enabled':True,'state':state,
            'description':'mcp:'+spec['owner_token']}


def forward_matches(row,spec):
    desired=forward_value(spec)
    return (all(row.get(k)==v for k,v in desired.items() if k not in ('dport','toPort'))
            and forward_port_range(row.get('dport'))==(spec['external_port'],)*2
            and forward_port_range(row.get('toPort'))==(spec['destination_port'],)*2
            and row.get('active') is not False and not row.get('applyToAll') and not row.get('extIP'))


def forward_ingress_guard(profile):
    # Native shared NAT chain matches tunnel IP sets, not the ingress interface
    # again. Overlapping tunnel addresses across clients would make selection
    # ambiguous; reject rather than promise isolation the native rule lacks.
    import shlex
    selected='c_ip_'+profile[:13]+'_set4'
    names=[v for v in run(['sudo','-n','ipset','list','-name']).splitlines() if re.fullmatch(r'c_ip_[A-Za-z0-9_]+_set4',v)]
    if selected not in names or len(names)>32:raise Unsupported('VPN ingress set missing or inventory bound')
    sets={}
    for name in names:
        addresses=[]
        for line in run(['sudo','-n','ipset','save',name]).splitlines():
            parts=shlex.split(line)
            if parts and parts[0]=='add':
                if len(parts)!=3 or parts[1]!=name:raise Unsupported('unsupported VPN self-address set shape')
                addresses.append(str(ipaddress.IPv4Address(parts[2])))
        if len(addresses)>32:raise Unsupported('VPN address set bound')
        sets[name]=sorted(addresses)
    if not sets[selected]:raise Unsupported('selected VPN has no observed tunnel address')
    if any(set(sets[selected]) & set(values) for name,values in sets.items() if name!=selected):
        raise Unsupported('overlapping VPN tunnel addresses; native shared NAT cannot guarantee profile isolation')
    return forward_digest(sets)


def forward_snapshot(spec, expected_policy_profile=None, defer_ingress=False):
    raw=run(['redis-cli','--raw','GET','extension.portforward.config']).strip()
    config=json.loads(raw) if raw else {'maps':[]}
    if not isinstance(config,dict) or set(config)!={'maps'} or not isinstance(config['maps'],list) or len(config['maps'])>256:
        raise Unsupported('mapping schema or bound')
    maps=config['maps'];collisions=[];owned=[]
    for row in maps:
        if not isinstance(row,dict):raise Unsupported('mapping schema')
        # A DMZ is a competing catch-all. A generic/default WAN forward does not
        # necessarily cover VPN, but applyToAll or the selected VC does.
        relevant=bool(row.get('applyToAll')) or row.get('wanUUID')=='VC:'+spec['profile'] or row.get('_type')=='dmz_host'
        if relevant and row.get('protocol') not in (None,'','tcp','udp'):raise Unsupported('unrecognized mapping protocol')
        if relevant and row.get('protocol') in (None,'',spec['protocol']):
            lo,hi=forward_port_range(row['dport']) if row.get('dport') else (1,65535)
            if lo<=spec['external_port']<=hi:collisions.append(row)
        if row.get('description')=='mcp:'+spec['owner_token']:owned.append(row)
    if len(owned)>1:raise Unsupported('ambiguous mapping ownership')
    ip=run(['redis-cli','--raw','HGET','host:mac:'+spec['device'],'ipv4Addr']).strip()
    if ip!=spec['destination_ip']:raise Unsupported('destination device/IP binding changed')
    policy_raw=run(['redis-cli','--raw','HGET','policy:mac:'+spec['device'],'vpnClient']).strip()
    policy=json.loads(policy_raw) if policy_raw else None
    if not isinstance(policy,dict) or policy.get('state') is not True or policy.get('profileId')!=(expected_policy_profile or spec['profile']):
        raise Unsupported('explicit device VPN policy must match selected profile; inherited routing unsupported')
    safety,settings_hash=managed_vpn_safety(spec['profile'])
    ingress_hash='deferred until declared VPN start' if defer_ingress else forward_ingress_guard(spec['profile'])
    return {'maps':maps,'owned':owned,'collisions':collisions,
            'fingerprint':forward_digest({'maps':maps,'ip':ip,'vpn_policy':policy,'settings':settings_hash,'ingress':ingress_hash}),
            'present':bool(collisions),'field':{k:owned[0].get(k) for k in forward_value(spec)} if owned else None,
            'environment_fingerprint':forward_digest({'ip':ip,'vpn_policy':policy,'settings':settings_hash,'ingress':ingress_hash}),
            'scope':'Persistent FireMain VPN mapping only; no firewall allow, provider port, VPN routing or conntrack change'}


def forward_kernel_evidence(spec):
    import shlex
    ipset='c_ip_'+spec['profile'][:13]+'_set4';interface='vpn_'+spec['profile']
    def rules(chain):return [shlex.split(v) for v in run(['sudo','-n','iptables','-t','nat','-S',chain]).splitlines() if v.startswith('-A ')]
    def has(row,flag,value):
        return any(row[i:i+1]==[flag] and row[i+1:i+1+len(value)]==value for i in range(len(row)))
    nat=any(has(r,'-p',[spec['protocol']]) and has(r,'--dport',[str(spec['external_port'])]) and
            has(r,'--match-set',[ipset,'dst']) and has(r,'-j',['DNAT']) and
            has(r,'--to-destination',[spec['destination_ip']+':'+str(spec['destination_port'])])
            for r in rules('FW_PRERT_VC_PORT_FORWARD'))
    ingress=any(has(r,'-i',[interface]) and has(r,'--match-set',[ipset,'dst']) and
                has(r,'-j',['FW_PRERT_VC_PORT_FORWARD']) for r in rules('FW_PREROUTING_VC_EXT_IP'))
    return {'nat_rule_observed':nat,'vpn_ingress_link_observed':ingress,
            'return_routing':'configured matching device VPN policy; effective reply path unverified',
            'firewall_acceptance':'not tested or changed','external_reachability':'not tested',
            'conntrack':'existing flows not flushed; test a new independent external flow',
            'restart_persistence':'native stored mapping is restored by FireMain startup; no restart/reboot tested'}


def managed_forward(args):
    spec=args['spec'];mode=args['mode'];context=args.get('context')
    if context is not None and context!={'owner_token':spec['owner_token']}:
        raise ValueError('mapping rollback ownership mismatch')
    before=forward_snapshot(spec)
    if mode=='preview':
        return {k:before[k] for k in ('fingerprint','present','field','scope')}
    if args.get('expected')!=before['fingerprint']:return {'outcome':'stale','changed':False}
    if not time.time()<spec['maintenance_until']<=time.time()+600:raise ValueError('forward maintenance window expired')
    if mode=='apply' and (before['collisions'] or before['owned']):return {'outcome':'stale','changed':False}
    if mode=='rollback' and (len(before['owned'])!=1 or not forward_matches(before['owned'][0],spec) or len(before['collisions'])!=1):
        return {'outcome':'stale','changed':False}
    # Native queue has no compare-and-set. The approved maintenance window must
    # exclude concurrent app/API mapping edits; do not claim atomic protection.
    try:
        require_action_deadline(args)
        management_request('set','policy','0.0.0.0',{'portforward':forward_value(spec,mode=='apply')})
        end=min(time.monotonic()+5,time.monotonic()+max(0,args['expires_at']-time.time()))
        after=None
        while time.monotonic()<end:
            time.sleep(.25);after=forward_snapshot(spec)
            if mode=='apply' and len(after['owned'])==1 and forward_matches(after['owned'][0],spec):break
            if mode=='rollback' and not after['owned']:break
        verified=after is not None and (len(after['owned'])==1 and forward_matches(after['owned'][0],spec) if mode=='apply' else not after['owned'])
        if not verified:return {'outcome':'uncertain','changed':None,'reason':'Queued mapping not verified; do not retry or remove unknown entries'}
        before_other=[r for r in before['maps'] if r.get('description')!='mcp:'+spec['owner_token']]
        after_other=[r for r in after['maps'] if r.get('description')!='mcp:'+spec['owner_token']]
        if forward_digest(before_other)!=forward_digest(after_other) or before['environment_fingerprint']!=after['environment_fingerprint']:
            return {'outcome':'uncertain','changed':None,'reason':'Concurrent state change detected after submission; inspect without rollback'}
        evidence=forward_kernel_evidence(spec)
        kernel_verified=(evidence['nat_rule_observed'] and evidence['vpn_ingress_link_observed']) if mode=='apply' else not evidence['nat_rule_observed']
        # Confirm configured state, separately reporting kernel evidence. Never
        # call this effective reachability or firewall permission.
        return {'outcome':('applied' if mode=='apply' else 'rolled_back') if kernel_verified else 'uncertain',
                'verification':'stored_mapping_verified','evidence':evidence,
                'context':{'owner_token':spec['owner_token']},
                'state':{k:after[k] for k in ('fingerprint','present','field','scope')}}
    except Exception:
        return {'outcome':'uncertain','changed':None,'reason':'Queued operation may have executed; inspect before any further action'}


def workflow_specs(spec):
    required={'kind','device','destination_ip','expected_profile','destination_profile','vpn_type','forwards','maintenance_until'}
    if not isinstance(spec,dict) or set(spec)!=required or spec['kind']!='vpn_workflow':raise ValueError('workflow shape')
    lifecycle={'kind':'managed_lifecycle','profile':spec['destination_profile'],'vpn_type':spec['vpn_type'],'desired':'connect'}
    switch={'kind':'managed_vpn','device':spec['device'],'expected_profile':spec['expected_profile'],'destination_profile':spec['destination_profile']}
    validate_managed(lifecycle);validate_managed(switch)
    if not isinstance(spec['forwards'],list) or not 1<=len(spec['forwards'])<=2:raise ValueError('one or two exact forwarding actions required')
    forwards=[]
    for row in spec['forwards']:
        if not isinstance(row,dict) or set(row)!={'protocol','external_port','destination_port','owner_token'}:raise ValueError('workflow forward shape')
        item=dict(kind='managed_forward',device=spec['device'],destination_ip=spec['destination_ip'],profile=spec['destination_profile'],maintenance_until=spec['maintenance_until'],**row)
        validate_managed(item);forwards.append(item)
    if len(forwards)==2:validate_managed({'kind':'managed_forward_batch','steps':forwards})
    return [lifecycle,switch]+forwards


def workflow_profile_version(profile):
    # File identity/change metadata only: never read configs, keys or passwords.
    # ctime detects ordinary replacement/in-place edits even if mtime is restored.
    import stat
    rows=[]
    for folder,suffixes in (('ovpn_profile',('.ovpn','.settings','.userpass','.password')),('wg_profile',('.json','.settings'))):
        parent='/home/pi/.firewalla/run/'+folder
        if not os.path.isdir(parent):continue
        if not stat.S_ISDIR(os.lstat(parent).st_mode):raise Unsupported('profile parent is not a real directory')
        for suffix in suffixes:
            path=parent+'/'+profile+suffix
            try:info=os.lstat(path)
            except FileNotFoundError:rows.append([folder,suffix,None]);continue
            if not stat.S_ISREG(info.st_mode):raise Unsupported('profile input not regular')
            rows.append([folder,suffix,info.st_ino,info.st_dev,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_mode,info.st_uid,info.st_gid])
    return forward_digest(rows)


def workflow_state(args):
    spec=args['spec'];steps=workflow_specs(spec)
    management_guard(args.get('revision'),'managed_forward')
    policy=managed_field_read(steps[1])
    if policy['profileId'] not in (spec['expected_profile'],spec['destination_profile']):raise Unsupported('workflow device policy outside declared transition')
    old,old_hash=managed_vpn_safety(spec['expected_profile']);new,new_hash=managed_vpn_safety(spec['destination_profile'])
    if old!=new:raise Unsupported('workflow safety/DNS mismatch')
    life=managed_lifecycle_state(steps[0])
    snapshots=[forward_snapshot(step,expected_policy_profile=policy['profileId'],defer_ingress=True) for step in steps[2:]]
    maps=snapshots[0]['maps'];tokens={s['owner_token']:i for i,s in enumerate(steps[2:])};owned=[];unrelated=[]
    for row in maps:
        token=str(row.get('description','')).removeprefix('mcp:')
        if token in tokens:
            index=tokens[token]
            if index in owned or not forward_matches(row,steps[index+2]):raise Unsupported('workflow owned mapping changed')
            owned.append(index)
        else:unrelated.append(row)
    # Existing/range/disabled conflicts are blockers unless they are exact earlier
    # results from this immutable workflow. Later own additions are rejected by host.
    for item in snapshots:
        if any(row not in [r for r in maps if str(r.get('description','')).removeprefix('mcp:') in tokens] for row in item['collisions']):
            raise Unsupported('workflow existing mapping conflict')
    ip=run(['redis-cli','--raw','HGET','host:mac:'+spec['device'],'ipv4Addr']).strip()
    return {'stable':forward_digest({'maps':unrelated,'ip':ip,'profiles':[old_hash,new_hash],
                    'profile_file_versions':[workflow_profile_version(spec['expected_profile']),workflow_profile_version(spec['destination_profile'])]}),
            'policy':policy,'lifecycle':life,'owned_forward_steps':sorted(owned),
            'limits':'Observed connection only; no peer/provider reachability or effective device-route claim'}


def managed_forward_batch(args):
    steps=args['spec']['steps'];mode=args['mode']
    if mode=='rollback':raise Unsupported('compound rollback requires separately reviewed reverse actions')
    states=[forward_snapshot(step) for step in steps]
    fingerprint=forward_digest([s['fingerprint'] for s in states])
    if mode=='preview':
        return {'fingerprint':fingerprint,'present':any(s['present'] for s in states),
                'field':None,'scope':'Ordered persistent VPN mappings; not atomic; stop on first unverified step',
                'rollback':'No batch automatic rollback; inspect completed mappings before a separate exact removal plan'}
    if args.get('expected')!=fingerprint:return {'outcome':'stale','changed':False,'steps':[]}
    if any(s['present'] for s in states):return {'outcome':'stale','changed':False,'steps':[]}
    baseline=forward_digest(states[0]['maps']);environment=states[0]['environment_fingerprint'];results=[];completed=[]
    for index,step in enumerate(steps):
        try:current=forward_snapshot(step)
        except Exception:return {'outcome':'partial' if results else 'stale','steps':results,'stopped_at':index,'reason':'precondition read failed; inspect before further action'}
        # Only exact mappings created by earlier verified steps may differ from
        # the initial snapshot. Never adopt arbitrary fresh state as approved.
        own={s['owner_token']:s for s in completed};remaining=[];seen=set()
        for row in current['maps']:
            token=str(row.get('description','')).removeprefix('mcp:')
            if token in own:
                if token in seen or not forward_matches(row,own[token]):
                    return {'outcome':'partial','steps':results,'stopped_at':index,'reason':'earlier step changed; inspect'}
                seen.add(token)
            else:remaining.append(row)
        if seen!=set(own) or forward_digest(remaining)!=baseline or current['environment_fingerprint']!=environment:
            return {'outcome':'partial' if results else 'stale','steps':results,'stopped_at':index,'reason':'unexpected state drift; inspect'}
        try:
            require_action_deadline(args)
            result=managed_forward({'spec':step,'mode':'apply','expected':current['fingerprint'],'expires_at':args['expires_at']})
        except Exception:
            return {'outcome':'partial' if results else 'uncertain','steps':results,'stopped_at':index,'reason':'step interrupted or deadline elapsed; inspect before retry'}
        results.append({'index':index,'result':result})
        if result.get('outcome')!='applied':
            return {'outcome':'partial' if index else result.get('outcome','uncertain'),'steps':results,'stopped_at':index,
                    'resume':'No blind retry or rollback. Inspect the uncertain step; prepare a fresh plan for remaining actions.'}
        completed.append(step)
    return {'outcome':'applied','steps':results,'atomic':False,'rollback':'Separate verified removal plans only',
            'resume':'Completed plan cannot be replayed'}


def validate_managed(spec):
    if not isinstance(spec, dict) or spec.get('kind') not in ('managed_feature', 'managed_rule', 'managed_vpn', 'managed_scoped', 'managed_lifecycle', 'managed_forward', 'managed_forward_batch'):
        raise ValueError('managed kind')
    if spec['kind']=='managed_forward_batch':
        if set(spec)!={'kind','steps'} or not isinstance(spec['steps'],list) or not 2<=len(spec['steps'])<=4:raise ValueError('bounded forward plan required')
        seen=set();owners=set();scope=None
        for step in spec['steps']:
            if not isinstance(step,dict) or step.get('kind')!='managed_forward':raise ValueError('unsupported compound step')
            validate_managed(step)
            current=(step['device'],step['destination_ip'],step['profile'],step['maintenance_until'])
            if scope is not None and current!=scope:raise ValueError('compound forwards require same target/profile/window')
            scope=current;key=(step['protocol'],step['external_port'])
            if key in seen or step['owner_token'] in owners:raise ValueError('overlapping compound mapping')
            seen.add(key);owners.add(step['owner_token'])
        return spec
    if spec['kind']=='managed_forward':
        keys={'kind','profile','device','destination_ip','protocol','external_port','destination_port','owner_token','maintenance_until'}
        if set(spec)!=keys or spec['protocol'] not in ('tcp','udp'):raise ValueError('forward arguments')
        if not re.fullmatch(r'[A-Za-z0-9_]{1,10}',spec['profile']) or not re.fullmatch(r'[a-f0-9]{32}',spec['owner_token']):raise ValueError('forward profile/ownership')
        if not re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}',spec['device']):raise ValueError('forward device')
        spec['destination_ip']=str(ipaddress.IPv4Address(spec['destination_ip']))
        if any(type(spec[k]) is not int or not 1<=spec[k]<=65535 for k in ('external_port','destination_port')):raise ValueError('forward ports')
        if type(spec['maintenance_until']) is not int:raise ValueError('maintenance window')
        return spec
    if spec['kind']=='managed_lifecycle':
        if set(spec)!={'kind','profile','vpn_type','desired'} or spec['vpn_type'] not in ('openvpn','wireguard') or spec['desired'] not in ('connect','disconnect') or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,10}',spec['profile']):
            raise ValueError('lifecycle arguments')
        return spec
    if spec['kind']=='managed_scoped':
        if set(spec)!={'kind','scope','target','feature','desired'} or spec['scope'] not in ('group','network') or spec['feature'] not in ('adblock','safeSearch','unbound','doh','ntp_redirect') or spec['desired'] not in ('enable','disable','inherit'):
            raise ValueError('scoped arguments')
        pattern=r'[0-9]{1,20}' if spec['scope']=='group' else r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
        if not re.fullmatch(pattern,spec['target']) or (spec['feature']=='ntp_redirect' and spec['scope']!='network'):
            raise ValueError('scoped target')
        return spec
    mac = spec.get('device', '')
    if not isinstance(mac, str) or not re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}', mac):
        raise ValueError('canonical device MAC required')
    kind = spec['kind']
    if kind == 'managed_feature':
        if set(spec) != {'kind','device','feature','desired'} or spec['feature'] not in ('adblock','safeSearch','unbound','doh') or spec['desired'] not in ('enable','disable','inherit'):
            raise ValueError('feature arguments')
    elif kind == 'managed_vpn':
        if set(spec) != {'kind','device','expected_profile','destination_profile'}:
            raise ValueError('VPN arguments')
        for key in ('expected_profile','destination_profile'):
            if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}',spec[key]):
                raise ValueError('profile identifier')
        if spec['expected_profile'] == spec['destination_profile']:
            raise ValueError('same profile')
    else:
        if set(spec)-{'schedule','address'} != {'kind','device','rule_type','target'} or spec['rule_type'] not in ('internet','category','app','ip','dns','dns_override'):
            raise ValueError('rule arguments')
        if 'schedule' in spec:
            schedule=spec['schedule']
            if spec['rule_type'] not in ('category','app') or not isinstance(schedule,dict) or set(schedule)!={'hour','minute','days','duration','timezone'}:
                raise ValueError('schedule shape')
            for key,maximum in (('hour',23),('minute',59)):
                if type(schedule[key]) is not int or not 0<=schedule[key]<=maximum:raise ValueError('schedule time')
            if type(schedule['duration']) is not int or not 60<=schedule['duration']<=79200:raise ValueError('duration')
            days=schedule['days']
            if not isinstance(days,list) or not 1<=len(days)<=7 or any(type(d) is not int or not 0<=d<=6 for d in days) or len(set(days))!=len(days):raise ValueError('weekdays')
            if not isinstance(schedule['timezone'],str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+-]+){0,2}',schedule['timezone']):raise ValueError('timezone')
        if spec['rule_type']=='dns_override':
            spec['address']=canonical_rule_ip(spec['address'])
        elif 'address' in spec:raise ValueError('address only for DNS override')
        target = spec['target']
        if spec['rule_type'] == 'internet' and target != 'internet':
            raise ValueError('internet target')
        if spec['rule_type'] == 'category' and target not in ('games','social','av','porn','vpn'):
            raise ValueError('category identifier')
        if spec['rule_type'] == 'app' and not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}',target):
            raise ValueError('app identifier')
        if spec['rule_type'] == 'ip':
            spec['target']=canonical_rule_ip(target)
        if spec['rule_type'] in ('dns','dns_override') and (len(target)>253 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?',part) for part in target.split('.'))):
            raise ValueError('domain')
        if spec['rule_type'] in ('dns','dns_override'):
            spec['target']=target.lower()
        if 'schedule' in spec:
            spec['schedule']['days']=sorted(spec['schedule']['days'])
    return spec


def management_request(command, item, target, value, want_pid=False, lifecycle=False):
    # Fixed loopback endpoint, no proxy, redirects, cookies, or arbitrary request tool.
    # set policy returns the WHOLE target policy: never read that body.
    import http.client
    import urllib.parse
    connection = http.client.HTTPConnection('127.0.0.1',8834,timeout=80 if lifecycle else 3)
    try:
        query = urllib.parse.urlencode({'command':command,'item':item,'target':target})
        body = json.dumps(value,separators=(',',':'))
        if len(body)>4096:
            raise Unsupported('request limit')
        connection.request('POST','/v1/encipher/simple?'+query,body,{'Content-Type':'application/json'})
        response = connection.getresponse()
        if response.status != 200:
            raise Unsupported('management response rejected')
        if not want_pid:
            return None
        raw = response.read(16385)
        if len(raw)>16384:
            raise Unsupported('management response limit')
        payload = json.loads(raw)
        if payload.get('code') != 200 or not isinstance(payload.get('data'),dict):
            raise Unsupported('management response schema')
        pid = str(payload['data'].get('pid',''))
        if not re.fullmatch(r'[0-9]{1,20}',pid) or payload['data'].get('updated'):
            raise Unsupported('unexpected rule response')
        return pid
    finally:
        connection.close()


def management_guard(revision, kind=None, feature=None):
    if kind in ("managed_forward","managed_forward_batch") and revision not in VPN_MANAGEMENT_REVISIONS:
        raise Unsupported("persistent forwarding requires its reviewed installed revision")
    if revision in VPN_MANAGEMENT_REVISIONS:
        if kind in ('managed_feature','managed_scoped') and feature not in POLICY_FEATURES:
            raise Unsupported('feature implementation not reviewed for installed revision')
        if kind in ('managed_feature','managed_scoped','managed_rule'):
            policy_source_guard(revision)
        elif kind in ('managed_lifecycle','managed_vpn','managed_forward','managed_forward_batch'):
            vpn_source_guard(revision)
        else:
            raise Unsupported('operation not reviewed for installed revision')
        if kind in ('managed_forward','managed_forward_batch'):
            import hashlib
            for name,expected in FORWARD_SOURCE_HASHES.items():
                if hashlib.sha256(contract_file('/home/pi/firewalla',name)).hexdigest()!=expected:raise Unsupported('port forwarding source changed')
        management_request('cmd','ping','0.0.0.0',{})
        return
    if revision != MANAGEMENT_REVISION:
        raise Unsupported('unreviewed management revision')
    root = '/home/pi/firewalla'
    if run(['git','-C',root,'rev-parse','HEAD']).strip() != revision:
        raise Unsupported('installed source revision mismatch')
    if run(['git','-C',root,'status','--porcelain','--untracked-files=no']).strip():
        raise Unsupported('modified installed source')
    # Existing endpoint only. Never start a service or enable a development route.
    management_request('cmd','ping','0.0.0.0',{})


def managed_rule_value(spec):
    kind,target = spec['rule_type'],spec['target']
    if kind == 'app':
        catalog = app_catalog({})
        matches = [v for v in catalog['apps'] if v['id']==target and v['ordinary_block_target']]
        if catalog['truncated'] or len(matches)!=1:
            raise Unsupported('app ACL not declared')
        target=matches[0]['ordinary_block_target']
    result={'type':'mac' if kind=='internet' else 'category' if kind=='app' else 'dns' if kind=='dns_override' else kind,
            'target':spec['device'] if kind=='internet' else target,
            'action':'block','direction':'outbound'}
    if kind!='internet':
        result['scope']=[spec['device']]
    if kind=='dns_override':
        result.update(action='address',resolver=spec['address'],domainExactMatch=False,ipOnly=True)
    if 'schedule' in spec:
        schedule=spec['schedule']
        timezone=run(['redis-cli','--raw','HGET','sys:config','timezone']).strip() or 'UTC'
        if timezone!=schedule['timezone']:raise Unsupported('router timezone differs')
        result['cronTime']=f"{schedule['minute']} {schedule['hour']} * * {','.join(str(v) for v in sorted(schedule['days']))}"
        result['duration']=schedule['duration']
    return result


def managed_target(spec):
    if spec['kind']=='managed_scoped':
        return ('tag:' if spec['scope']=='group' else 'network:')+spec['target']
    return spec['device']


def managed_policy_key(spec):
    if spec['kind']=='managed_scoped':
        return 'policy:'+('tag:' if spec['scope']=='group' else 'network:')+spec['target']
    return 'policy:mac:'+spec['device']


def managed_field(spec):
    return 'vpnClient' if spec['kind']=='managed_vpn' else spec['feature']


def managed_field_read(spec):
    raw=run(['redis-cli','--raw','HGET',managed_policy_key(spec),managed_field(spec)]).strip()
    # Missing policies cannot be exactly restored through set; fail closed.
    if not raw or len(raw)>2048:
        raise Unsupported('existing explicit policy required for exact rollback')
    value=json.loads(raw)
    if spec['kind']=='managed_vpn':
        if not isinstance(value,dict) or set(value)!={'state','profileId'} or value['state'] is not True or not isinstance(value['profileId'],str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}',value['profileId']):
            raise Unsupported('VPN policy must be an explicit enabled profile without unknown fields')
    else:
        state=value
        if spec['feature']!='adblock':
            if not isinstance(value,dict) or set(value)!={'state'}:
                raise Unsupported('unknown feature fields')
            state=value['state']
        if state is not None and type(state) is not bool:
            raise Unsupported('tri-state schema')
    return value


def managed_rule_snapshot():
    # Reject large rule sets, avoid unbounded per-rule reads, and never return raw policies.
    ids=run(['redis-cli','--raw','ZRANGE','policy_active','0','512']).splitlines()
    if len(ids)>512 or any(not re.fullmatch(r'[0-9]{1,20}',p) for p in ids):
        raise Unsupported('rule set outside bounded adapter limit')
    if not ids:
        return []
    # One Redis Lua read, constrained to explicit public policy fields, no mutation.
    script="local r={} local total=0 for _,k in ipairs(KEYS) do if redis.call('HLEN',k)>64 then return redis.error_reply('policy size limit') end for _,f in ipairs(redis.call('HKEYS',k)) do local n=redis.call('HSTRLEN',k,f); total=total+n; if n>8192 or total>131072 then return redis.error_reply('policy size limit') end end local row=redis.call('HMGET',k,'type','target','action','direction','scope','disabled','cronTime','expire','duration','resolver','domainExactMatch','ipOnly'); table.insert(row,redis.sha1hex(cjson.encode(redis.call('HGETALL',k)))); table.insert(r,row) end return cjson.encode(r)"
    rows=json.loads(run(['redis-cli','--raw','EVAL',script,str(len(ids))]+['policy:'+p for p in ids]))
    if not isinstance(rows,list) or len(rows)!=len(ids):
        raise Unsupported('rule projection schema')
    projected=[]
    for pid,row in zip(ids,rows):
        if not isinstance(row,list) or len(row)!=13:
            raise Unsupported('rule fields')
        projected.append([pid]+row)
    return projected


def managed_vpn_safety(profile):
    # Metadata only; never open .ovpn/.conf/private keys or query vpnProfiles.
    import hashlib
    import stat
    matches=[]
    for folder,suffix in (('ovpn_profile','.ovpn'),('wg_profile','.json')):
        base='/home/pi/.firewalla/run/'+folder+'/'+profile
        if os.path.isfile(base+suffix):
            matches.append(base)
    if len(matches)!=1:
        raise Unsupported('existing unambiguous OpenVPN/WireGuard profile required')
    fd=os.open(matches[0]+'.settings',os.O_RDONLY|os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Unsupported('settings file type')
        raw=os.read(fd,32769)
    finally:
        os.close(fd)
    if len(raw)>32768:
        raise Unsupported('settings size')
    settings=json.loads(raw)
    if not isinstance(settings,dict):
        raise Unsupported('settings shape')
    selected={k:settings.get(k,default) for k,default in VPN_SAFETY_DEFAULTS.items()}
    if any(type(v) is not bool for v in selected.values()):
        raise Unsupported('invalid explicit safety setting; only absent fields use reviewed defaults')
    # Include full settings hash in the stale-state fingerprint, never return settings.
    return selected,hashlib.sha256(raw).hexdigest()


def managed_state(spec, context=None):
    import hashlib
    if spec['kind']=='managed_rule':
        value=managed_rule_value(spec)
        rows=managed_rule_snapshot()
        if context:
            pid=context['pid']
            selected=[row for row in rows if row[0]==pid]
            present=bool(selected)
            field=selected[0] if selected else None
        else:
            # Conservative duplicate rejection, including disabled/scheduled rules.
            present=any(rule_identity(row[1],row[2])==rule_identity(value['type'],value['target']) for row in rows)
            field=None
        data={'rows':rows,'field':field,'present':present}
    else:
        value=managed_field_read(spec)
        desired=(spec['destination_profile'] if spec['kind']=='managed_vpn' else {'enable':True,'disable':None,'inherit':False}[spec['desired']])
        present=(value['profileId']==desired if spec['kind']=='managed_vpn' else (value if spec['feature']=='adblock' else value['state']) is desired)
        data={'field':value,'present':present}
        if spec['kind']=='managed_vpn':
            old,old_hash=managed_vpn_safety(spec['expected_profile'])
            new,new_hash=managed_vpn_safety(spec['destination_profile'])
            if old!=new:
                raise Unsupported('VPN safety/DNS settings differ; explicit changes are not supported')
            data['profile_safety_fingerprints']=[old_hash,new_hash]
    fingerprint=hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    result={'fingerprint':fingerprint,'present':data['present'],'field':data['field']}
    if spec['kind']=='managed_rule':result['known_policy_ids']=[row[0] for row in rows]
    return result


def managed_lifecycle_state(spec):
    import hashlib
    profile=spec['profile']
    # Validate existing profile metadata locally; no raw credential-bearing profile query.
    safety,settings_hash=managed_vpn_safety(profile)
    folder='ovpn_profile' if spec['vpn_type']=='openvpn' else 'wg_profile'
    suffix='.ovpn' if spec['vpn_type']=='openvpn' else '.json'
    if not os.path.isfile('/home/pi/.firewalla/run/'+folder+'/'+profile+suffix):
        raise Unsupported('profile type mismatch')
    cached=run(['redis-cli','--raw','GET','VC:'+profile+':connState']).strip()
    if cached not in ('true','false',''):
        raise Unsupported('cached lifecycle state malformed')
    rows=json.loads(run(['ip','-j','link','show']))
    links=[row for row in rows if row.get('ifname')=='vpn_'+profile]
    if len(links)>1:raise Unsupported('ambiguous interface')
    up=bool(links and 'UP' in links[0].get('flags',[]))
    connected=(cached=='true') if cached else None
    if (connected is True and not up) or (connected is not True and links):
        raise Unsupported('transitional or conflicting lifecycle observations')
    unit=None
    if spec['vpn_type']=='openvpn':
        raw=run(['systemctl','show','openvpn_client@'+profile+'.service','--property=ActiveState,UnitFileState'])
        unit=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
        if unit.get('UnitFileState')!='disabled' or unit.get('ActiveState')!=('active' if connected else 'inactive'):
            raise Unsupported('OpenVPN unit must be disabled and match observed connection state')
    data={'connected':connected,'settings_hash':settings_hash,'safety':safety,'unit':unit}
    return {'fingerprint':hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'configuration_fingerprint':settings_hash,'present':spec['desired']=='connect' and connected is True,'field':{'observed_connected':connected,'administrative_intent':'unknown'},
            'rollback':'not_supported; inverse requires a separately approved preview',
            'scope':'profile-wide; all routed devices may be affected; native start may restart the unit and stop disables it; no persistent system VPN policy is changed'}


def require_action_deadline(args):
    expiry=args.get('expires_at')
    if type(expiry) is not int or not time.time()<expiry<=time.time()+600:
        raise ValueError('Missing or expired bounded action deadline')


def managed_lifecycle(args):
    spec=args['spec']
    if args['mode']=='rollback':raise Unsupported('no exact lifecycle rollback')
    state=managed_lifecycle_state(spec)
    if args['mode']=='preview':return state
    if args.get('expected')!=state['fingerprint'] or state['present']:
        return {'outcome':'stale','changed':False}
    try:
        require_action_deadline(args)
        management_request('cmd','startVpnClient' if spec['desired']=='connect' else 'stopVpnClient','0.0.0.0',
                           {'type':spec['vpn_type'],'profileId':spec['profile']},lifecycle=True)
        after=managed_lifecycle_state(spec)
        verified=after['field']['observed_connected']==(spec['desired']=='connect') and after['configuration_fingerprint']==state['configuration_fingerprint']
        return {'outcome':'applied' if verified else 'uncertain','state':after,
                'observed_lifecycle_verified':verified,'management_operation_acknowledged':spec['desired'],'administrative_intent':'requested; asynchronous listeners unverified','effective_device_path':'unverified',
                'enforcement':'unverified_async','rollback':'not_supported',
                'note':'Cached link state and interface/service observations only. No claim of peer reachability, Internet access or device routing. Setup/start/stop can affect all routed devices and background reconnect state.'}
    except Exception:
        return {'outcome':'uncertain','reason':'Lifecycle request or bounded verification failed; operation may continue on appliance. Do not retry automatically.'}


def managed_write(args):
    spec=validate_managed(args['spec'])
    mode=args['mode']
    if mode not in ('preview','apply','rollback'):
        raise ValueError('managed mode')
    if mode!='preview':require_action_deadline(args)
    management_guard(args.get('revision'), spec['kind'], spec.get('feature'))
    if spec['kind']=='managed_forward_batch':
        return managed_forward_batch(args)
    if spec['kind']=='managed_forward':
        return managed_forward(args)
    if spec['kind']=='managed_lifecycle':
        return managed_lifecycle(args)
    if spec['kind']=='managed_scoped':
        if spec['scope']=='network':
            exists=run(['redis-cli','--raw','EXISTS','network:uuid:'+spec['target']]).strip()=='1'
        else:
            exists=any(run(['redis-cli','--raw','EXISTS',prefix+spec['target']]).strip()=='1' for prefix in ('tag:uid:','deviceTag:uid:','userTag:uid:','ssidTag:uid:'))
        if not exists:raise Unsupported('scope missing')
        if spec['feature']=='ntp_redirect':
            if run(['redis-cli','--raw','HGET','sys:features','ntp_redirect']).strip()!='1' or run(['redis-cli','--raw','GET','sys:ntp:status']).strip()!='1':
                raise Unsupported('NTP service must already be enabled and healthy')
    # Ensure exact device exists; no IP->MAC ambiguity or accidental global target.
    if spec['kind']!='managed_scoped' and run(['redis-cli','--raw','EXISTS','host:mac:'+spec['device']]).strip()!='1':
        raise Unsupported('device missing')
    context=args.get('context')
    if spec['kind']=='managed_vpn' and context is not None:
        if (not isinstance(context,dict) or set(context)!={'before'} or
                context['before']!={'state':True,'profileId':spec['expected_profile']}):
            raise ValueError('VPN rollback context must restore the approved expected profile only')
    state=managed_state(spec,context)
    if mode=='preview':
        if spec['kind']=='managed_vpn' and not context and state['field']['profileId']!=spec['expected_profile']:
            raise Unsupported('expected VPN profile mismatch')
        return state
    if args.get('expected')!=state['fingerprint']:
        return {'outcome':'stale','changed':False}
    # All failures once a mutation is sent remain uncertain; never automatic retry.
    try:
        require_action_deadline(args)
        if spec['kind']=='managed_rule':
            if mode=='apply':
                if state['present']:
                    return {'outcome':'stale','changed':False}
                value=managed_rule_value(spec)
                # Upstream create can reactivate a duplicate disabled rule. Creating disabled
                # first prevents that behavior even if a duplicate races the snapshot.
                pid=management_request('cmd','policy:create','0.0.0.0',{**value,'disabled':'1'},True)
                context={'pid':pid,'before':None}
                if pid in state['known_policy_ids']:
                    raise Unsupported('creation returned pre-existing ID')
                created=managed_state(spec,context)
                if not managed_rule_matches(created['field'],value,spec,True):
                    raise Unsupported('new disabled rule did not match approved specification')
                management_request('cmd','policy:enable','0.0.0.0',{'policyID':pid})
            else:
                if not context or not state['present']:
                    return {'outcome':'stale','changed':False}
                management_request('cmd','policy:delete','0.0.0.0',{'policyID':context['pid']})
        else:
            if mode=='apply':
                context={'before':state['field']}
                if spec['kind']=='managed_vpn':
                    if state['field']['profileId']!=spec['expected_profile']:
                        return {'outcome':'stale','changed':False}
                    value={**state['field'],'profileId':spec['destination_profile']}
                else:
                    desired={'enable':True,'disable':None,'inherit':False}[spec['desired']]
                    value=desired if spec['feature']=='adblock' else {'state':desired}
            else:
                if not context or 'before' not in context:
                    raise Unsupported('rollback context')
                value=context['before']
            management_request('set','policy',managed_target(spec),{managed_field(spec):value})
        after=managed_state(spec,context)
        if spec['kind']=='managed_rule':
            verified=after['present'] if mode=='apply' else not after['present']
            if mode=='apply' and verified:
                verified=managed_rule_matches(after['field'],managed_rule_value(spec),spec,False)
        else:
            verified=after['field']==value
        return {'outcome':('applied' if mode=='apply' else 'rolled_back') if verified else 'uncertain',
                'state':after,'context':context,'persistent_state_verified':verified,
                'enforcement':'unverified_async','effective_device_path':'unverified',
                'note':'Management acknowledgment and selected stored state only. Enforcement, DNS behavior and kill-switch behavior require independent tests; existing global/group/network rules still apply.'}
    except Exception:
        return {'outcome':'uncertain','context':context,'reason':'Management request or selected verification failed; a new rule may remain disabled. Inspect before any new attempt.'}


# Selected fields only: never HGETALL/init/getAttributes for these reads.
MEMBERSHIP_LUA = r"""
local bytes=0
local function field(k,f,max)
 if redis.call('HSTRLEN',k,f)>max then error('field limit') end
 local v=redis.call('HGET',k,f)
 if v then bytes=bytes+#v; if bytes>90000 then error('byte limit') end end
 return v
end
local tags={}
for _,spec in ipairs({{'user','userTag:uid:'},{'group','tag:uid:'},{'device','deviceTag:uid:'},{'ssid','ssidTag:uid:'}}) do
 local key='tag:'..spec[1]..':active'
 if redis.call('SCARD',key)>256 then error('tag limit') end
 for _,id in ipairs(redis.call('SMEMBERS',key)) do
  if not string.match(id,'^%d+$') or #id>20 then error('tag schema') end
  local row={type=spec[1],uid=id,name=field(spec[2]..id,'name',256)}
  for _,f in ipairs({'userTags','tags','deviceTags','ssidTags'}) do row[f]=field('policy:tag:'..id,f,4096) end
  table.insert(tags,row)
  if #tags>256 then error('tag limit') end
 end
end
local cursor='0';local hosts={};local seen={};local complete=false
for i=1,1024 do
 local page=redis.call('SCAN',cursor,'MATCH','host:mac:*','COUNT',256);cursor=page[1]
 for _,key in ipairs(page[2]) do
  if not seen[key] then
   seen[key]=true
   if #hosts>=1024 then error('host limit') end
   local mac=string.sub(key,10)
   local row={mac=mac,name=field(key,'name',256),bname=field(key,'bname',256)}
   for _,f in ipairs({'userTags','tags','deviceTags','ssidTags'}) do row[f]=field('policy:mac:'..mac,f,4096) end
   table.insert(hosts,row)
  end
 end
 if cursor=='0' then complete=true;break end
end
return cjson.encode({tags=tags,hosts=hosts,complete=complete})
"""

def membership_snapshot():
    result=json.loads(run(['redis-cli','--raw','EVAL',MEMBERSHIP_LUA,'0']))
    # Redis cjson encodes empty Lua arrays as {}.
    for key in ('tags','hosts'):
        if result.get(key)=={}: result[key]=[]
    return result


def safe_profile_file(path, cap=262144):
    """Local-only bounded read, no following symlinks, never returned verbatim."""
    import stat
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size>cap:
            raise Unsupported('profile file bounds')
        data=os.read(fd,cap+1)
        if len(data)>cap: raise Unsupported('profile file bounds')
        return data.decode('utf-8')
    finally: os.close(fd)


def endpoint_host(value):
    if not isinstance(value,str) or not 1<=len(value)<=253 or '%' in value:
        raise ValueError('endpoint host')
    try: return str(ipaddress.ip_address(value))
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?',value):
            raise ValueError('endpoint host') from None
        return value.lower()


def openvpn_endpoints(content):
    # Never interpret script directives, inline keys, includes, or external paths.
    import shlex
    remotes=[]; proto=None; default_port=None; block=None; complex_blocks=False
    for line in content.splitlines():
        line=line.strip()
        if line.startswith('<'):
            if line=='<connection>': complex_blocks=True
            if line.startswith('</'): block=None
            else: block=line
            continue
        if block or not line or line.startswith(('#',';')): continue
        if line.split(None,1)[0] not in ('remote','proto','port','rport'): continue
        parts=shlex.split(line,comments=True)
        if parts[0]=='proto' and len(parts)==2: proto=parts[1]
        elif parts[0] in ('port','rport') and len(parts)==2: default_port=port(int(parts[1]))
        elif parts[0]=='remote' and 2<=len(parts)<=4:
            remotes.append(parts[1:])
            if len(remotes)>32: raise Unsupported('remote limit')
        else: raise Unsupported('endpoint directive schema')
    out=[]
    for row in remotes:
        protocol=row[2] if len(row)>2 else proto
        transport='udp' if protocol in ('udp','udp4','udp6') else 'tcp' if protocol in ('tcp','tcp-client','tcp4-client','tcp6-client') else None
        out.append({'hostname_or_ip':endpoint_host(row[0]),'port':port(int(row[1])) if len(row)>1 else default_port,
                    'transport':transport,'active':None})
    return {'configured_endpoints':out,'endpoints_complete':not complex_blocks,
            'note':'Configured remotes, not active server or DNS resolvers. Omitted port/protocol remain unknown; connection blocks are not projected.'}


def wireguard_endpoints(config):
    peers=config.get('peers',[])
    if not isinstance(peers,list) or len(peers)>32: raise Unsupported('peer limit')
    out=[]
    for peer in peers:
        value=peer.get('endpoint')
        if not value: continue
        if not isinstance(value,str): raise Unsupported('endpoint schema')
        if value.startswith('['):
            host,sep,number=value[1:].partition(']:')
        else: host,sep,number=value.rpartition(':')
        if not sep: raise Unsupported('endpoint schema')
        out.append({'hostname_or_ip':endpoint_host(host),'port':port(int(number)),'transport':'udp','active':None})
    return {'configured_endpoints':out,'endpoints_complete':True,
            'note':'Configured peer endpoints only, not current handshake or DNS resolvers.'}


def saved_vpn_profiles(base='/home/pi/.firewalla/run'):
    from pathlib import Path
    profiles=[]; inventory_complete=True
    links=network('interfaces'); interfaces={r['ifname']:r for r in links['rows'] if 'ifname' in r}
    for kind,directory,suffix in [('openvpn','ovpn_profile','.ovpn'),('wireguard','wg_profile','.settings')]:
        folder=Path(base)/directory
        if not folder.exists(): continue
        if folder.is_symlink() or not folder.is_dir(): raise Unsupported('profile directory schema')
        entries=[]
        with os.scandir(folder) as scan:
            for entry in scan:
                if len(entries)>=1024: raise Unsupported('directory bound')
                entries.append(entry.name)
        ids=sorted(name[:-len(suffix)] for name in entries if name.endswith(suffix))
        if len(profiles)+len(ids)>128: raise Unsupported('profile limit')
        for identifier in ids:
            if not re.fullmatch(r'[A-Za-z0-9_]{1,10}',identifier): raise Unsupported('profile ID schema')
            name=None; metadata='ok'
            try:
                settings=json.loads(safe_profile_file(folder/(identifier+'.settings'),32768))
                name=rule_text(settings.get('displayName') or settings.get('serverBoxName'))
            except FileNotFoundError: metadata='settings_missing'
            endpoint_data={'configured_endpoints':[],'endpoints_complete':False}
            try:
                if kind=='openvpn': endpoint_data=openvpn_endpoints(safe_profile_file(folder/(identifier+'.ovpn')))
                else: endpoint_data=wireguard_endpoints(json.loads(safe_profile_file(folder/(identifier+'.json'))))
            except (ValueError,OSError,Unsupported,TypeError,AttributeError):
                metadata='endpoint_metadata_unavailable'
            intf='vpn_'+identifier
            observed=interfaces.get(intf)
            raw=run(['redis-cli','--raw','GET','VC:'+identifier+':connState']).strip()
            cached={'true':True,'false':False,'1':True,'0':False}.get(raw)
            profiles.append({'profile_id':identifier,'name':name,'vpn_type':kind,'saved':True,
                'interface':intf if observed else None,'interface_present':True if observed else None if links['truncated'] else False,
                'interface_operstate':observed.get('operstate') if observed else None,
                'cached_connected':cached,'administrative_state':'unknown','effective_device_routing':'unknown',
                'metadata_status':metadata,**endpoint_data})
    matched={'vpn_'+r['profile_id'] for r in profiles}
    return {'profiles':profiles,'supported_types':['openvpn','wireguard'],'inventory_complete_for_supported_types':inventory_complete,
            'interface_inventory_truncated':links['truncated'],
            'unmatched_interfaces':[n for n in interfaces if re.match(r'^(vpn_|tun|tap|wg)',n) and n not in matched],
            'note':'Names are configured labels; duplicate/missing names are preserved. Other VPN types are not inventoried. Cached connectivity/interface presence do not prove health, stopped intent, or device routing.'}


def dispatch(op, args):
    if op == "managed_workflow_state": return workflow_state(args)
    if op == "membership_snapshot": return membership_snapshot()
    if op == "saved_vpn_profiles": return saved_vpn_profiles()
    if op == "managed_write":
        return managed_write(args)
    if op == "service_features":
        return service_features(args["feature"])
    if op == "control_state":
        return control_state(args)
    if op == "app_catalog":
        return app_catalog(args)
    if op == "control_rules":
        return control_rules(args)
    if op == "device_flows":
        return device_flow_page(args)
    if op == "write":
        return write_operation(args)
    if op == "policy_summaries":
        return rule_page(args)
    if op in ("alarm_summaries", "policy_summaries"):
        limit=args["limit"]
        if type(limit) is not int or not 1<=limit<=10:
            raise ValueError("limit")
        alarm=op=="alarm_summaries"
        index="alarm_active" if alarm else "policy_active"
        if run(["redis-cli","--raw","TYPE",index]).strip()!="zset":
            raise Unsupported("index schema")
        ids=[x for x in run(["redis-cli","--raw","ZREVRANGE",index,"0",str(limit-1)]).splitlines() if x]
        if len(ids)>limit or not all(re.fullmatch(r"[0-9]{1,20}",x) for x in ids):
            raise Unsupported("id schema")
        result=[]
        skipped=0
        for identifier in ids:
            fields=["type","timestamp","alarmTimestamp"] if alarm else ["type","action","disabled","direction"]
            raw=run(["redis-cli","--raw","HMGET",("_alarm:" if alarm else "policy:")+identifier]+fields).splitlines()
            if not any(raw):
                skipped+=1
                continue
            if len(raw)!=len(fields):
                raise Unsupported("selected-field schema")
            if alarm:
                if not re.fullmatch(r"ALARM_[A-Z0-9_]{1,64}",raw[0]):
                    raise Unsupported("alarm type")
                timestamp=float(raw[1] or raw[2])
                if not 0<=timestamp<=4102444800:
                    raise Unsupported("alarm timestamp")
                item={"id":identifier,"type":raw[0],"timestamp":timestamp}
            else:
                if raw[2] not in ("","0","1"):
                    raise Unsupported("disabled shape")
                item={"id":identifier,"type":atom(raw[0]),"action":atom(raw[1]) if raw[1] else None,
                      "disabled":None if raw[2]=="" else raw[2]=="1","direction":atom(raw[3]) if raw[3] else None}
            result.append(item)
        return {"records":result,"skipped_missing":skipped,"may_have_more":len(ids)==limit,
                "note":"Bounded active-index sample; index order is not an event-time guarantee. Descriptions, targets, device identity and alarm details omitted. Policy record state is not proof of kernel enforcement."}
    if op == "flow_sample":
        limit=args["limit"]
        if type(limit) is not int or not 1<=limit<=100:
            raise ValueError("limit")
        key="flow:conn:system"
        if run(["redis-cli","--raw","TYPE",key]).strip()!="zset":
            raise Unsupported("flow index absent")
        lines=[x for x in run(["redis-cli","--raw","ZREVRANGE",key,"0",str(limit-1)]).splitlines() if x]
        if len(lines)>limit:
            raise Unsupported("sample bound")
        upload=download=0
        protocols={}
        for line in lines:
            flow=json.loads(line)
            ob,rb=flow["ob"],flow["rb"]
            if type(ob) not in (int,float) or type(rb) not in (int,float) or not 0<=ob<=2**63 or not 0<=rb<=2**63:
                raise Unsupported("byte schema")
            outbound=ip(flow["lh"])==ip(flow["sh"])
            upload+=ob if outbound else rb
            download+=rb if outbound else ob
            protocol=flow.get("pr")
            if protocol not in ("tcp","udp","icmp","icmp6"):
                protocol="other"
            protocols[protocol]=protocols.get(protocol,0)+1
        return {"sample_records":len(lines),"sample_upload_bytes":upload,"sample_download_bytes":download,
                "protocol_counts":protocols,"may_have_more":len(lines)==limit,
                "note":"Latest bounded system-flow sample only, projected on router. May overlap aggregated records; not a time-window total, per-device usage, or billing measurement. No endpoints, names or payload returned."}
    if op == "services":
        result = {}
        for unit in ("firemain", "firemon", "firerouter", "redis-server", "openvpn@server"):
            raw = run(["systemctl", "show", unit, "--property=LoadState,ActiveState,SubState", "--no-pager"])
            fields = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
            result[unit] = {key: atom(fields[key]) for key in ("LoadState", "ActiveState", "SubState") if key in fields}
        return {"units": result, "note": "Known unit names only. Missing units are not proof that an equivalent service is absent. openvpn@server is a service observation, not tunnel/client health."}
    if op == "inventory":
        cursor = args["cursor"]
        if not isinstance(cursor,str) or not re.fullmatch(r"[0-9]{1,20}",cursor):
            raise ValueError("invalid cursor")
        raw = run(["redis-cli", "--raw", "SCAN", cursor, "MATCH", "host:mac:*", "COUNT", "32"]).splitlines()
        if not raw or not re.fullmatch(r"[0-9]{1,20}",raw[0]) or len(raw)>257:
            raise Unsupported("unknown SCAN shape or page too large")
        macs=[]
        for key in raw[1:]:
            if not key:
                continue
            if not re.fullmatch(r"host:mac:(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", key):
                raise Unsupported("unknown device key schema")
            macs.append(key[9:].upper())
        return {"cursor":raw[0], "macs":macs, "note":"SCAN may return duplicates or empty nonterminal pages; stop only at cursor 0. No names or hash dumps."}
    if op == "device_policy":
        mac=args["mac"].upper()
        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}",mac):
            raise ValueError("invalid mac")
        raw=run(["redis-cli","--raw","HGET","policy:mac:"+mac,"vpnClient"]).strip()
        if not raw:
            return {"explicit_policy":None,"effective_path":"unknown; inherited policies not resolved"}
        policy=json.loads(raw)
        if not isinstance(policy,dict) or (policy.get("state") is not None and type(policy.get("state")) is not bool):
            raise Unsupported("unknown policy schema")
        out={"state":policy.get("state")}
        if policy.get("profileId") is not None:
            out["profile_id"]=atom(policy["profileId"])
        return {"explicit_policy":out,"effective_path":"unknown; inherited policies and kernel marks not resolved"}
    if op == "vpn_interfaces":
        rows=network("addresses")["rows"]
        return {"interfaces":[r for r in rows if re.match(r"^(vpn_|tun|tap|wg)",r.get("ifname",""))], "note":"Interface naming heuristic only, not an inventory of configured VPN profiles."}
    if op == "traffic":
        rows=json.loads(run(["ip","-j","-s","link","show"]))
        result=[]
        for row in rows[:256]:
            stats=row.get("stats64",row.get("stats"))
            if not isinstance(stats,dict):
                raise Unsupported("missing interface statistics")
            item={"interface":atom(row["ifname"])}
            for direction in ("rx","tx"):
                item[direction]={k:int(stats[direction][k]) for k in ("bytes","packets","errors","dropped")}
            result.append(item)
        return {"interfaces":result,"truncated":len(rows)>256,"note":"Cumulative kernel counters; reset on interface recreation. Not Firewalla per-device usage or a billing total."}
    if op == "alarm_count":
        seconds=args["seconds"]
        if type(seconds) is not int or not 60<=seconds<=604800:
            raise ValueError("invalid time window")
        kind=run(["redis-cli","--raw","TYPE","alarm_active"]).strip()
        if kind!="zset":
            raise Unsupported("active alarm index absent or changed")
        now=int(time.time())
        count=run(["redis-cli","--raw","ZCOUNT","alarm_active",str(now-seconds),str(now)]).strip()
        if not count.isdigit():
            raise Unsupported("unknown count")
        return {"active_alarm_count":int(count),"start_epoch":now-seconds,"end_epoch":now,"note":"Active-index score window only; not archived alarms or alarm descriptions."}
    if op == "dns_config":
        with open("/etc/resolv.conf") as f:
            raw=f.read(8193)
        if len(raw)>8192:
            raise Unsupported("resolver config oversized")
        return {"nameservers":[ip(line.split()[1]) for line in raw.splitlines() if line.strip().startswith("nameserver ")][:16],"note":"System resolver only; split DNS, DNS rules, encrypted DNS and search domains omitted."}
    if op == "conntrack":
        address=ip(args["address"])
        raw=run(["sudo","-n","conntrack","-L","-s",address,"-o","extended"])
        result=[]
        for line in raw.splitlines():
            fields=line.split()
            tuples=[]
            for field in fields:
                if "=" not in field:
                    continue
                k,v=field.split("=",1)
                if k in ("src","dst"):
                    tuples.append({k:ip(v)})
                elif k in ("sport","dport"):
                    tuples.append({k:port(int(v))})
            if tuples:
                result.append({"tuples_in_kernel_order":tuples})
        return {"connections":result[:128],"truncated":len(result)>128,"note":"Original/reply address/port metadata for one source. No payload, application attribution or NAT policy verdict."}
    if op == "capabilities":
        return {"utilities": {x: shutil.which(x) is not None for x in ["python3", "ip", "ss", "redis-cli", "iptables", "ipset", "conntrack", "getent", "nc"]},
                "adapters": "schema-probed on each call; no firmware version is assumed supported"}
    if op == "health":
        with open("/proc/uptime") as f:
            uptime = float(f.read(128).split()[0])
        with open("/proc/meminfo") as f:
            mem = dict(re.findall(r"^(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+)", f.read(8192), re.M))
        return {"uptime_seconds": uptime, "load_average": list(os.getloadavg()), "memory_kib": {k:int(v) for k,v in mem.items()}}
    if op == "network":
        return network(args["kind"])
    if op == "device":
        mac = args["mac"].upper()
        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
            raise ValueError("invalid mac")
        address = run(["redis-cli", "--raw", "HGET", "host:mac:"+mac, "ipv4Addr"]).strip()
        if not address:
            raise Unsupported("device absent or unsupported schema")
        return {"mac": mac, "ipv4": ip(address), "note": "Known MAC lookup; no device names or full host hashes."}
    if op == "vpn":
        interface = atom(args["interface"])
        addresses = network("addresses")["rows"]
        found = [r for r in addresses if r.get("ifname")==interface]
        if not found:
            raise Unsupported("interface absent")
        return {"interface": found, "note": "Interface state only; does not establish VPN provider health or device selection."}
    if op == "mappings":
        return mappings()
    if op == "firewall":
        if args["table"] not in ("filter", "nat", "mangle"):
            raise ValueError("invalid table")
        return firewall(args["table"])
    if op == "ipsets":
        rows = run(["sudo", "-n", "ipset", "list", "-name"]).splitlines()
        return {"names": [atom(x) for x in rows[:256]], "truncated": len(rows)>256}
    if op == "connections":
        # ss socket summary contains counts, not traffic or payload.
        raw = run(["ss", "-s"])
        total = re.search(r"Total:\s+(\d+)", raw)
        if not total:
            raise Unsupported("unknown ss schema")
        return {"local_socket_count": int(total.group(1)), "note": "Router-local sockets only; not forwarded conntrack/NAT sessions."}
    if op == "tcp":
        target, number = ip(args["address"]), port(args["port"])
        # nc emits no payload, and stderr is discarded. Failure remains inconclusive.
        try:
            run(["nc", "-z", "-w", "3", target, str(number)], 4)
            return {"outcome": "connected", "meaning": "TCP handshake succeeded from this site; application protocol not tested."}
        except Unsupported:
            return {"outcome": "inconclusive", "meaning": "Timeout, rejection, missing utility, or path failure; not proof of global closure."}
    if op == "dns":
        name = args["name"]
        if len(name)>253 or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", s) for s in name.split(".")):
            raise ValueError("invalid DNS name")
        raw = run(["getent", "ahosts", name])
        return {"addresses": sorted(set(ip(line.split()[0]) for line in raw.splitlines()))[:32], "resolver": "router system resolver"}
    raise Unsupported("adapter not implemented")


def execute(op, args):
    try:
        return {"status": "ok", "data": dispatch(op, args)}
    except (Unsupported, ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired):
        return {"status": "unsupported", "reason": "Unavailable utility, permission, output/time limit, or unrecognized schema. No raw output returned."}

if __name__ == "__main__":
    request = json.loads(sys.argv[1])
    print(json.dumps(execute(request["operation"], request["arguments"])))
