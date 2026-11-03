"""Bounded full-table scan, exact policy-comment projection before transport.

Every chain is scanned so misplaced/duplicate rules still reach strict verifiers.
No filtering occurs after truncation. Failure, timeout or a bound emits no proof.
"""
import json
import re

PROJECTION_SCRIPT = r'''
import json,os,re,selectors,shlex,subprocess,sys,time
family=sys.argv[1];pids=json.loads(sys.argv[2])
if family not in ('iptables','ip6tables') or not isinstance(pids,list) or not 1<=len(pids)<=64 or len(set(pids))!=len(pids):raise ValueError('projection selector')
if any(not isinstance(p,str) or not re.fullmatch('[1-9][0-9]{0,4}',p) or int(p)>65535 for p in pids):raise ValueError('policy ID')
wanted={'rule_'+p for p in pids};rows=[];pending=b'';total=0;count=0
p=subprocess.Popen(['timeout','3','sudo','-n',family,'-t','filter','-S'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
end=time.monotonic()+4
try:
 with selectors.DefaultSelector() as sel:
  sel.register(p.stdout,selectors.EVENT_READ)
  while True:
   left=end-time.monotonic()
   if left<=0 or not sel.select(left):raise ValueError('projection deadline')
   chunk=os.read(p.stdout.fileno(),8192)
   if not chunk:break
   total+=len(chunk)
   if total>4194304:raise ValueError('scan byte bound')
   pending+=chunk
   while b'\n' in pending:
    line,pending=pending.split(b'\n',1);count+=1
    if count>4096 or len(line)>16384:raise ValueError('scan rule bound')
    line=line.decode('utf-8',errors='strict');tokens=shlex.split(line)
    if any(tokens[i]=='--comment' and tokens[i+1] in wanted for i in range(len(tokens)-1)):
     rows.append(line)
   if len(pending)>16384:raise ValueError('scan line bound')
  if pending or not count or p.wait(timeout=max(.01,end-time.monotonic()))!=0:raise ValueError('incomplete scan')
 output=json.dumps({'version':1,'family':family,'pids':pids,'complete':True,'scanned':count,'bytes':total,'rules':rows},separators=(',',':'))
 if len(output.encode())>131071:raise ValueError('projection output bound')
 print(output)
finally:
 if p.poll() is None:p.kill()
 p.wait();p.stdout.close()
'''


def read_policy_rules(run,pids):
    pids=sorted(set(pids))
    if not 1<=len(pids)<=64 or any(not isinstance(p,str) or not re.fullmatch('[1-9][0-9]{0,4}',p) or int(p)>65535 for p in pids):
        raise ValueError('Bounded exact policy IDs required')
    result=[]
    for family in ('iptables','ip6tables'):
        raw=run(['python3','-I','-c',PROJECTION_SCRIPT,family,json.dumps(pids,separators=(',',':'))])
        if not isinstance(raw,str) or len(raw.encode())>131072:raise ValueError('Projection output bound')
        def unique(pairs):
            row={}
            for k,v in pairs:
                if k in row:raise ValueError('Duplicate projection field')
                row[k]=v
            return row
        row=json.loads(raw,object_pairs_hook=unique)
        if (not isinstance(row,dict) or set(row)!={'version','family','pids','complete','scanned','bytes','rules'}
            or type(row['version']) is not int or row['version']!=1 or row['family']!=family or row['pids']!=pids
            or row['complete'] is not True or type(row['scanned']) is not int or not 1<=row['scanned']<=4096
            or type(row['bytes']) is not int or not 1<=row['bytes']<=4194304):raise ValueError('Incomplete rule projection')
        lines=row['rules']
        if not isinstance(lines,list) or len(lines)>row['scanned'] or any(not isinstance(s,str) or '\n' in s or len(s.encode())>16384 for s in lines):
            raise ValueError('Projected rule bound')
        import shlex
        for line in lines:
            tokens=shlex.split(line)
            if not any(tokens[i]=='--comment' and tokens[i+1] in {'rule_'+p for p in pids} for i in range(len(tokens)-1)):
                raise ValueError('Unselected projected rule')
        result.append(lines)
    return result
