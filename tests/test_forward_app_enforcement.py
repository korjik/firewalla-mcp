import pytest
from firewalla_mcp.forward_app_enforcement import verify_legacy_allow


def evidence(proto):
 v={'scope':['02:00:00:00:00:01'],'localPort':'19132','protocol':proto}
 lines=[]
 for direction,r,n in [('ORIGINAL','src','dst'),('REPLY','dst','src')]:
  lines.append(f'-A FW_FIREWALL_DEV_ALLOW_LO -p {proto} -m {proto} -m set ! --match-set monitored_net_set {r},{r} -m set --match-set c_02:00:00:00:00:01_set {n} -m set --match-set c_bp_123_local_port {n} -m conntrack --ctdir {direction} -m comment --comment rule_123 -j MARK --set-xmark 0x7b/0xffff')
 sets={'c_bp_123_local_port':'create c_bp_123_local_port bitmap:port range 0-65535\nadd c_bp_123_local_port 19132'}
 return v,lines,sets

@pytest.mark.parametrize('proto',['tcp','udp'])
def test_dual_family_native_allow(proto):
 v,lines,sets=evidence(proto)
 assert verify_legacy_allow(v,'123',lines,lines,sets,True)
 assert not verify_legacy_allow(v,'123',lines,[],sets,True)
 assert not verify_legacy_allow(v,'123',[],lines,sets,True)
 assert verify_legacy_allow(v,'123',[],[],{},False)
 assert not verify_legacy_allow(v,'123',lines,[],{},False)

@pytest.mark.parametrize('old,new',[('! --match-set','--match-set'),('src,src','src'),('monitored_net_set','other_set'),('19132','19133'),('--ctdir ORIGINAL','--ctdir REPLY'),('0x7b/0xffff','0x7c/0xffff')])
def test_changed_rule_or_set_does_not_prove_restore(old,new):
 v,lines,sets=evidence('udp');lines=[l.replace(old,new) for l in lines];sets={k:s.replace(old,new) for k,s in sets.items()}
 try:result=verify_legacy_allow(v,'123',lines,lines,sets,True)
 except ValueError:result=False
 assert not result

def test_unnegated_sentinel_named_set_not_accepted():
 v,lines,sets=evidence('tcp')
 lines=[l.replace('! --match-set monitored_net_set','--match-set !monitored_net_set') for l in lines]
 with pytest.raises(ValueError,match='Reserved'):verify_legacy_allow(v,'123',lines,lines,sets,True)
