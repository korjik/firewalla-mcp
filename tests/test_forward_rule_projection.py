import json
import os
import subprocess
import sys
import pytest
from firewalla_mcp.forward_rule_projection import PROJECTION_SCRIPT,read_policy_rules


def envelope(family='iptables',rules=None,**changes):
    return json.dumps(dict(version=1,family=family,pids=['123'],complete=True,scanned=5,bytes=1000,rules=rules or [],**changes))


def test_transport_reads_both_families_and_binds_ids():
    calls=[]
    def run(args):
        calls.append(args);return envelope(args[-2])
    assert read_policy_rules(run,['123','123'])==[[],[]]
    assert [c[-2] for c in calls]==['iptables','ip6tables']
    assert all(c[:3]==['python3','-I','-c'] for c in calls)


@pytest.mark.parametrize('change',[{'complete':False},{'scanned':4097},{'scanned':True},{'bytes':4194305},{'family':'ip6tables'},{'pids':['124']},{'extra':1},{'rules':['-A OTHER --comment rule_124 -j ACCEPT']},{'rules':['-A X --comment rule_123\n-j ACCEPT']}])
def test_untrusted_projection_is_not_absence(change):
    row=json.loads(envelope());row.update(change)
    with pytest.raises(ValueError):read_policy_rules(lambda args:json.dumps(row),['123'])


def test_duplicate_envelope_fields_and_oversize_rejected():
    for raw in ['{"version":1,"version":1}', 'x'*131073]:
        with pytest.raises(ValueError):read_policy_rules(lambda args:raw,['123'])


@pytest.mark.parametrize('pids',[[],['0'],['65536'],['*'],['123;id'],['0123'],[str(i) for i in range(1,66)]])
def test_selectors_rejected_without_commands(pids):
    with pytest.raises(ValueError):read_policy_rules(lambda args:pytest.fail('must not run'),pids)


@pytest.fixture
def producer(tmp_path):
    # The producer's fixed sudo/iptables invocation reads synthetic input only.
    fake=tmp_path/'sudo'
    fake.write_text('#!'+sys.executable+'\nimport os,sys,pathlib\nassert sys.argv[1:]==["-n","iptables","-t","filter","-S"]\nsys.stdout.buffer.write(pathlib.Path(os.environ["FIXTURE"]).read_bytes())\nsys.exit(int(os.environ.get("EXIT_CODE","0")))\n')
    fake.chmod(0o755);fixture=tmp_path/'rules'
    def run(raw,code=0):
        fixture.write_bytes(raw if isinstance(raw,bytes) else raw.encode())
        return subprocess.run([sys.executable,'-I','-c',PROJECTION_SCRIPT,'iptables','["123"]'],capture_output=True,text=True,timeout=10,
            env={**os.environ,'PATH':str(tmp_path)+':'+os.environ['PATH'],'FIXTURE':str(fixture),'EXIT_CODE':str(code)})
    return run


def test_large_table_is_scanned_and_only_exact_rules_cross_transport(producer):
    target='-A UNEXPECTED_CHAIN -m comment --comment "rule_123" -j ACCEPT\n'
    unrelated='-A OTHER -m comment --comment "unrelated '+('x'*200)+'" -j ACCEPT\n'
    raw='-P INPUT ACCEPT\n'+unrelated*700+target+target+'-A OTHER --comment rule_1234 -j ACCEPT\n'
    assert len(raw)>131072
    r=producer(raw);assert r.returncode==0,r.stderr
    data=json.loads(r.stdout)
    assert data['complete'] and data['scanned']==704 and data['bytes']==len(raw)
    assert data['rules']==[target.strip()]*2 # wrong chains and duplicates are preserved
    assert len(r.stdout)<1000


@pytest.mark.parametrize('raw,code',[
    ('',0),('-P INPUT ACCEPT',0),('-P INPUT ACCEPT\n',1),('-P INPUT ACCEPT\n'*4097,0),
    ('x'*16385+'\n',0),('-A X --comment "unterminated\n',0),(b'\xff\n',0),
    (('-A X --comment rule_123 --other '+('x'*1000)+'\n')*150,0),
    (('x'*16000+'\n')*263,0)])
def test_partial_malformed_or_bounded_failure_emits_no_proof(producer,raw,code):
    r=producer(raw,code)
    assert r.returncode!=0 and r.stdout==''
