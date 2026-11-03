// Extract only reviewed pure selectors/rule builders; never load appliance modules.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const source=fs.readFileSync(process.argv[2],'utf8');
assert.equal(crypto.createHash('sha256').update(source).digest('hex'),'0db0a855be5d04a5110b949342d26b5f62db6d48b9b249110321f0c410958158');
function method(name,next){
 const start=source.indexOf('  '+name+'('),end=source.indexOf('\n  '+next,start);
 assert(start>=0 && end>start);return source.slice(start,end);
}
const recorded=[];
class Rule {
 constructor(){this.value={};}
 pro(x){this.value.protocol=x;return this;}
 dst(x){this.value.destination=x;return this;}
 set(x,y){this.value.set=[x,y];return this;}
 dport(x){this.value.port=x;return this;}
 opr(x){this.value.operation=x;return this;}
 jmp(x){this.value.jump=x;return this;}
 chn(x){this.value.chain=x;return this;}
 dnat(x){this.value.dnat=x;return this;}
}
const sandbox={Rule,log:{debug(){},error(){}},_: {isEmpty:x=>!x.length},VPN_CLIENT_WAN_PREFIX:'VC:',
 NetworkProfile:{ensureCreateEnforcementEnv:async()=>{},getSelfIpsetName:id=>'wan_set_'+id},
 iptc:{addRule:async rule=>recorded.push({...rule.value})}};
vm.createContext(sandbox);
const enforce=source.slice(source.indexOf('  async enforceIptables('),source.lastIndexOf('\n}'));
vm.runInContext('this.Probe=class {'+method('find','// save config')+method('async removePort','async restore')+enforce+'}',sandbox,{timeout:1000});
(async()=>{
 const p=new sandbox.Probe();
 const base={protocol:'tcp',dport:'80',toPort:'80',toIP:'192.0.2.20',toMac:'02:00:00:00:00:01',enabled:true,active:true,state:true,description:'App HTTP',autoFirewall:1};
 const selected={...base,wanUUID:'selected'},nullScope={...base,wanUUID:null},https={...base,dport:'443',toPort:'443'};
 p.config={maps:[selected,nullScope,{...base},https]};
 assert.equal(Number(p.find(base)),1); // native loose equality: omitted also matches null
 await p.removePort({...base,state:false});
 assert.deepEqual(p.config.maps,[selected,https]); // proves why ambiguity must block
 assert(recorded.every(r=>!r.set));
 recorded.length=0;
 await p.enforceIptables({...base});
 assert.equal(recorded.length,2);
 assert.equal(recorded[0].chain,'FW_PRERT_PORT_FORWARD');assert.equal(recorded[0].set,undefined);
 assert.equal(recorded[1].chain,'FW_POSTROUTING_PORT_FORWARD');
 recorded.length=0;
 await p.enforceIptables({...selected,toPort:'8080'});
 assert.deepEqual(recorded[0].set,['wan_set_selected','dst']);
 assert.equal(recorded[0].dnat,'192.0.2.20:8080');
 console.log('PASS: pinned native omitted/null matching, removal scope, default-WAN and selected-WAN NAT/hairpin builders; no appliance modules loaded');
})().catch(e=>{console.error(e);process.exit(1);});
