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
        rows=json.loads(run(["ip","-4","-j","route","show","table","all"]))
        if not isinstance(rows,list):
            raise Unsupported("route schema")
        rows=[r for r in rows if str(r.get("table","main"))==str(spec["table"])]
        canonical=json.dumps(sorted(rows,key=lambda r:json.dumps(r,sort_keys=True)),sort_keys=True)
        destination=str(ipaddress.IPv4Network(spec["destination"]))
        exists=any(r.get("dst","0.0.0.0/0")==destination or (destination=="0.0.0.0/0" and r.get("dst")=="default") for r in rows)
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


def dispatch(op, args):
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
