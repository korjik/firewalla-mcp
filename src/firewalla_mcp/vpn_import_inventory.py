"""Credential-free result projection of reviewed VPN reference stores.

Read-only Redis EVAL. Selected field values stay inside Redis; only exact target
hits, counts and completeness leave it. This does not observe FireMain intent.
"""
import json
from .vpn_import import need, profile_id, ImportBlocked

REFERENCE_LUA = r'''
local targets=cjson.decode(ARGV[1]);local hits={};local counts={policy=0,virtual_wan=0,dns_vpn=0}
local fields=0;local bytes=0;local issues={};local seen={};local complete=false
for _,id in ipairs(targets) do hits[id]={} end
local function issue(code) issues[code]=true end
local function match(value,family)
 if type(value)=='string' then
  for _,id in ipairs(targets) do
   if value==id or value=='VC:'..id then hits[id][family]=true end
  end
 end
end
local function walk(value,family,depth)
 if depth>16 then issue('depth_limit');return end
 if type(value)=='table' then
  for k,v in pairs(value) do match(k,family);walk(v,family,depth+1) end
 else match(value,family) end
end
local function readfield(key,field,family,isjson)
 local size=redis.call('HSTRLEN',key,field)
 if size>65536 then issue('field_limit');return end
 bytes=bytes+size
 if bytes>1048576 then issue('byte_limit');return end
 local value=redis.call('HGET',key,field)
 if not value then return end
 fields=fields+1
 if isjson then
  local ok,decoded=pcall(cjson.decode,value)
  if not ok or type(decoded)~='table' then issue('json_schema');return end
  walk(decoded,family,0)
 else match(value,family) end
end
local function policy(key)
 if key=='policy:id' or key=='policy:state' or key=='policy:enforce:spend' then
  if redis.call('TYPE',key).ok~='string' then issue('metadata_type') end
  return
 end
 counts.policy=counts.policy+1
 if counts.policy>4096 then issue('policy_limit');return end
 if redis.call('TYPE',key).ok~='hash' then issue('policy_type');return end
 readfield(key,'vpnClient','policy_vpn',true)
 readfield(key,'wanUUID','route_wan',false)
 readfield(key,'owanUUID','route_wan',false)
end
local cursor='0'
for i=1,1024 do
 local page=redis.call('SCAN',cursor,'COUNT',512);cursor=page[1]
 for _,key in ipairs(page[2]) do
  if not seen[key] and (string.sub(key,1,7)=='policy:' or string.sub(key,1,15)=='virt_wan_group:') then
   seen[key]=true
   if string.sub(key,1,7)=='policy:' then policy(key)
   else
    counts.virtual_wan=counts.virtual_wan+1
    if counts.virtual_wan>256 then issue('virtual_wan_limit')
    elseif redis.call('TYPE',key).ok~='hash' then issue('virtual_wan_type')
    else readfield(key,'wans','virtual_wan',true) end
   end
  end
 end
 if cursor=='0' then complete=true;break end
 if bytes>1048576 or counts.policy>4096 or counts.virtual_wan>256 then break end
end
local dtype=redis.call('TYPE','ext.unbound').ok
if dtype=='hash' then counts.dns_vpn=1;readfield('ext.unbound','vpnClient','dns_vpn',true)
elseif dtype~='none' then issue('dns_type') end
local out={}
for _,id in ipairs(targets) do
 local families={};for family,_ in pairs(hits[id]) do table.insert(families,family) end
 table.sort(families);table.insert(out,{profile_id=id,reference_families=families})
end
local errors={};for code,_ in pairs(issues) do table.insert(errors,code) end;table.sort(errors)
return cjson.encode({targets=out,counts=counts,selected_fields=fields,selected_bytes=bytes,scan_complete=complete,issues=errors})
'''


def collect_references(targets, runner):
    """runner receives argv; must enforce timeout/output bounds, no stderr export."""
    need(isinstance(targets,(tuple,list)) and 1<=len(targets)<=3,'Invalid target list')
    targets=[profile_id(t) for t in targets]
    need(len(set(targets))==len(targets),'Duplicate target')
    try:
        data=json.loads(runner(['redis-cli','--raw','EVAL',REFERENCE_LUA,'0',json.dumps(targets)]))
    except Exception:
        raise ImportBlocked('Reference collection unavailable') from None
    need(isinstance(data,dict) and type(data.get('scan_complete')) is bool,'Unknown inventory schema')
    issues=data.get('issues');issues=[] if issues=={} else issues
    need(isinstance(issues,list) and all(isinstance(x,str) for x in issues),'Unknown inventory issues')
    rows=data.get('targets')
    need(isinstance(rows,list) and {r.get('profile_id') for r in rows}==set(targets) and len(rows)==len(targets),'Incomplete target projection')
    complete=data['scan_complete'] and not issues
    result={}
    for row in rows:
        families=row['reference_families'];families=[] if families=={} else families
        need(isinstance(families,list) and set(families)<={'policy_vpn','route_wan','virtual_wan','dns_vpn'},'Unknown reference family')
        result[row['profile_id']]={'unreferenced':not families if complete else None,'reference_families':families,
                                  'administrative_intent':'unknown'}
    return {'targets':result,'reference_enumeration_complete':complete,'issues':issues,
            'scan_complete':data['scan_complete'],'counts':data.get('counts'),
            'scope':'Reviewed policy:* vpnClient/wanUUID/owanUUID, virt_wan_group:* wans, ext.unbound vpnClient',
            'safe_to_import':False,'blocker':'No authenticated in-process administrative-state observation'}
