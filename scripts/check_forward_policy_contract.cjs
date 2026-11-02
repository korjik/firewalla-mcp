// Isolated source-contract probe: extract pure rule-building functions only.
// Does not load appliance modules, contact a router or execute kernel commands.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(process.argv[2], 'utf8');
function extract(name) {
  const re = new RegExp('(?:async )?function '+name+'\\(');
  const match = re.exec(source);
  if (!match) throw Error('Missing contract function: '+name);
  const rest=source.slice(match.index);
  const next=/\n(?:async )?function \w+\(/.exec(rest.slice(1));
  if (!next) throw Error('Missing function boundary: '+name);
  return rest.slice(0,next.index+1);
}
const names=['prepareOutboundOptions','flipSrcDst','generateV46Rule','generateRules'];
const network={ensureCreateEnforcementEnv:async()=>{},getOifIpsetName:()=> 'synthetic_wan_set'};
const sandbox={VPN_CLIENT_WAN_PREFIX:'VC:',VPNClient:network,
  require:name=>{assert.equal(name,'../net2/NetworkProfile.js');return network;}};
vm.createContext(sandbox);
vm.runInContext(names.map(extract).join('\n')+'\nthis.probe={prepareOutboundOptions,generateRules};',sandbox,{timeout:1000});
(async()=>{
 const p=await sandbox.probe.prepareOutboundOptions({pid:'123',remoteSet4:'source_v4',remoteSet6:'source_v6_empty',
   proto:'tcp',direction:'inbound',action:'allow',family:4,af:4,owanUUID:'synthetic_wan',origDst:'198.51.100.2',origDport:'443'});
 p.src={set:'device_v4',set6:'device_v6',specs:['src'],portSet:'local443'};
 const rules=await sandbox.probe.generateRules(p);
 assert.equal(rules.length,4);
 assert.deepEqual(Array.from(new Set(rules.map(r=>r.af))).sort(),[4,6]);
 assert(rules.every(r=>r.origDst==='198.51.100.2'));
 const original=rules.find(r=>r.af===4 && r.ctDir==='ORIGINAL');
 assert.equal(original.src.ifSet,'synthetic_wan_set');
 assert.equal(original.src.set,'source_v4');assert.equal(original.dst.set,'device_v4');
 assert.equal(original.dst.portSet,'local443');
 // App-style source/device/internal-port/WAN scope without original IP.
 // This is an explicitly different scope, not a substitute for origDst.
 const scoped=await sandbox.probe.prepareOutboundOptions({pid:'124',remoteSet4:'source_v4',remoteSet6:'source_v6_empty',
   proto:'tcp',direction:'inbound',action:'allow',owanUUID:'synthetic_wan',origDport:'443'});
 scoped.src={set:'device_v4',set6:'device_v6',specs:['src'],portSet:'local443'};
 const scopedRules=await sandbox.probe.generateRules(scoped);
 assert.equal(scopedRules.length,4);
 assert(scopedRules.every(r=>!r.origDst && r.origDport==='443'));
 const scoped6=scopedRules.find(r=>r.af===6 && r.ctDir==='ORIGINAL');
 assert.equal(scoped6.src.set6,'source_v6_empty');
 assert.equal(scoped6.src.ifSet,'synthetic_wan_set');
 assert.equal(scoped6.src.negate,false);
 assert(scopedRules.every(r=>r.proto==='tcp' && r.ctstate===null));
 assert.equal(scoped6.dst.portSet,'local443');
 // IPv6 pinholes cannot use an IPv6 origDst through this dual-family builder:
 // it is copied unchanged into IPv4 rules as well. Device-wide source-scoped
 // IPv6 access is a different contract and must be explicitly disclosed.
 for (const proto of ['tcp','udp']) {
  const v6=await sandbox.probe.prepareOutboundOptions({pid:'125',remoteSet4:'source_v4_empty',remoteSet6:'source_v6',
   proto,direction:'inbound',action:'allow',family:6,af:6,owanUUID:'synthetic_wan',origDst:'2001:db8::2',origDport:'443'});
  v6.src={set:'device_v4',set6:'device_v6',specs:['src'],portSet:'local443'};
  const generated=await sandbox.probe.generateRules(v6);
  assert.equal(generated.length,4);
  assert(generated.every(r=>r.origDst==='2001:db8::2' && r.proto===proto));
  assert(generated.some(r=>r.af===4));
  delete v6.origDst;
  const deviceWide=await sandbox.probe.generateRules(v6);
  assert(deviceWide.every(r=>!r.origDst));
  assert.equal(deviceWide.find(r=>r.af===6&&r.ctDir==='ORIGINAL').src.set6,'source_v6');
  assert.equal(deviceWide.find(r=>r.af===4&&r.ctDir==='ORIGINAL').src.set,'source_v4_empty');
 }
 console.log(JSON.stringify({source_contract:'ordinary_inbound_allow',families:[4,6],family_option_honored:false,
  wan_and_source_match:'original_source',internal_device_port_match:'original_destination',
  original_destination_constraint_copied_to_both:true,
  alternative_requires_explicit_scope_change:true,alternative_ipv6_source_set:"empty_by_policy_contract",ipv6_exact_destination_copied_into_ipv4:true,ipv6_device_wide_alternative_requires_explicit_scope:true,router_or_kernel_actions:false}));
})().catch(e=>{console.error(e.message);process.exitCode=1;});
