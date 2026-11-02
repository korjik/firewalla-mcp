"""Strict native app-style IPv4 inbound-policy contract.

Not registered as a standalone write tool. A combined forwarding adapter must
supply reviewed source guards, full inventory and post-write enforcement proof.
"""
import ipaddress
import re

# Upstream Policy.isEqual comparison fields, plus selected dependency selectors.
IDENTITY_FIELDS=('type','target','expire','cronTime','remotePort','localPort','protocol','direction','action',
 'upnp','dnsmasq_only','trust','trafficDirection','transferredBytes','transferredPackets','avgPacketBytes',
 'parentRgId','targetRgId','ipttl','wanUUID','owanUUID','seq','routeType','resolver','ipOnly','origDst','origDport',
 'snatIP','flowIsolation','dscpClass','appTimeUsage','useBf','affectedPids','scope','tag','targets','guids')
PROJECTION_FIELDS=IDENTITY_FIELDS+('disabled','description','timestamp','activatedTime','lastActivatedTime','idleTs','duration','pid')


def native_allow(device,interface_uuid,source_network,protocol,external_port,internal_port,owner):
    if not isinstance(device,str) or not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',device):raise ValueError('device')
    if not isinstance(interface_uuid,str) or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',interface_uuid):raise ValueError('WAN UUID')
    if protocol!='tcp':raise ValueError('Initial complete lifecycle supports TCP only')
    if any(type(v) is not int or not 1<=v<=65535 for v in (external_port,internal_port)):raise ValueError('port')
    if not isinstance(owner,str) or not re.fullmatch('[a-f0-9]{32}',owner):raise ValueError('owner token')
    network=str(ipaddress.IPv4Network(source_network,strict=True))
    return {'type':'net','target':network,'scope':[device.upper()],'action':'allow','direction':'inbound',
            'protocol':'tcp','localPort':str(internal_port),'origDport':str(external_port),'owanUUID':interface_uuid,
            'description':'mcp:'+owner}


def scope_disclosure(value):
    return {'ipv4_sources':value['target'],'device':value['scope'][0],'wan_uuid':value['owanUUID'],
            'protocol':value['protocol'],'internal_port':int(value['localPort']),'original_port':int(value['origDport']),
            'ipv6_allowed':False,'ipv6_exclusion_requires':'positive source set with verified empty IPv6 counterpart',
            'original_destination_ip_restricted':False,'dnat_required':False,
            'device_address_scope':'native device address set, not a single internal IP',
            'other_mappings_or_routed_traffic':'can match the disclosed WAN/device/source/port scope',
            'external_reachability':'unverified'}


def identity(row):
    import json
    result={}
    for field in IDENTITY_FIELDS:
        value=row.get(field)
        if value in ('',None,False):value=None
        if field in ('scope','tag','targets','guids','affectedPids'):
            if isinstance(value,str):value=json.loads(value)
            if value is None:value=[]
            if not isinstance(value,list) or any(not isinstance(v,str) for v in value):raise ValueError('array identity')
            if field=='scope' and any(not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',v) for v in value):
                raise ValueError('Ambiguous native scope normalization')
            value=sorted(v.upper() for v in value) if field=='scope' else sorted(value)
        # Be conservative across native numeric/boolean Redis coercions. Any
        # ambiguity blocks creation rather than reactivating an existing rule.
        elif value is not None:value=str(value)
        result[field]=value
    return result


def reject_duplicate(rows,value):
    desired=identity(value)
    for row in rows:
        # The pinned native isEqual contract compares primary selectors before
        # ancillary metadata. Unknown metadata cannot turn a disjoint policy
        # into a duplicate. Legacy type/target aliases can, so reject those.
        if not isinstance(row.get('type'),str) or row.get('legacy_identity'):
            raise ValueError('Incomplete or legacy policy identity')
        candidate=identity(row)
        # Primary scope equality is intentionally broader than isEqual. Native
        # constructor defaults (false, regular sequence, numeric coercion) must
        # never let a disabled existing object be reactivated as 'new'. Unknown
        # ancillary semantics cause a conservative conflict, not an update.
        primary=('type','target','scope','tag','guids','protocol','direction','action','localPort','origDport','owanUUID')
        if all(candidate[k]==desired[k] for k in primary):
            if row.get('identity_complete') is not True:raise ValueError('Incomplete policy identity for matching selectors')
            raise ValueError('Existing policy, including disabled or differently prioritized policy; preserve it')


def projection_script():
    """Bounded atomic metadata-only read; full rows never cross the transport."""
    import json
    fields=json.dumps(list(PROJECTION_FIELDS),separators=(',',':'))
    return """
local fields=cjson.decode(ARGV[1]);local ids=redis.call('ZRANGE','policy_active',0,512)
if #ids>512 then error('policy inventory bound') end
local rows={};local bytes=0
local observational={hitCount=true,lastHitTs=true,lastHitFlow=true,statsResetTs=true}
for _,id in ipairs(ids) do
 if not string.match(id,'^%d+$') or #id>20 then error('policy identity') end
 local key='policy:'..id;local names=redis.call('HKEYS',key)
 if #names==0 or #names>96 then error('policy schema bound') end
 local row={pid=id};local known={};for _,f in ipairs(fields) do known[f]=true end
 local complete=true
 for _,f in ipairs(names) do
  local n=redis.call('HSTRLEN',key,f);bytes=bytes+n
  if n>8192 or bytes>90000 then error('policy byte bound') end
  if not known[f] and not observational[f] then complete=false end
 end
 for _,f in ipairs(fields) do local v=redis.call('HGET',key,f); if v then row[f]=v end end
 row.pid=id;row.identity_complete=complete
 row.legacy_identity=redis.call('HEXISTS',key,'i.type')==1 or redis.call('HEXISTS',key,'i.target')==1
 -- Bind every original field without returning unselected values. Sorting keys
 -- avoids HGETALL enumeration order affecting the canonical fingerprint.
 table.sort(names);local all={};for _,f in ipairs(names) do if not observational[f] then table.insert(all,f);table.insert(all,redis.call('HGET',key,f)) end end
 row.full_fingerprint=redis.sha1hex(cjson.encode(all));table.insert(rows,row)
end
return cjson.encode(rows)
""",fields


def read_projection(run):
    import json
    script,fields=projection_script()
    rows=json.loads(run(['redis-cli','--raw','EVAL',script,'0',fields]))
    if rows=={}:rows=[]
    if not isinstance(rows,list) or len(rows)>512:raise ValueError('Projection bound')
    seen=set()
    for row in rows:
        if not isinstance(row,dict) or set(row)-set(PROJECTION_FIELDS)-{'identity_complete','full_fingerprint','legacy_identity'}:raise ValueError('Projection fields')
        pid=row.get('pid')
        if not isinstance(pid,str) or not re.fullmatch('[0-9]{1,20}',pid) or pid in seen:raise ValueError('Projection identity')
        seen.add(pid)
        if 'legacy_identity' in row and type(row['legacy_identity']) is not bool:raise ValueError('Legacy identity shape')
        if type(row.get('identity_complete')) is not bool or not re.fullmatch('[a-f0-9]{40}',row.get('full_fingerprint','')):raise ValueError('Projection completeness')
    return rows
