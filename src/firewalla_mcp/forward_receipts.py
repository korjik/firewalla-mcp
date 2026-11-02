"""Private durable forwarding receipts; not approvals and never automatic retries."""
import json
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 262144

class ForwardReceipts:
    def __init__(self, directory):
        self.directory = directory

    def root(self):
        p=Path(self.directory or '')
        if not p.is_absolute(): raise ValueError('Absolute forwarding recovery directory required')
        st=p.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700:
            raise ValueError('Forwarding recovery directory must be private and process-owned')
        return p

    def path(self, ident):
        if not isinstance(ident,str) or not re.fullmatch('[a-f0-9]{32}',ident):raise ValueError('Invalid forwarding receipt ID')
        return self.root()/(ident+'.json')

    def load(self, ident):
        p=self.path(ident)
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1 or st.st_size>MAX_BYTES:
                raise ValueError('Unsafe forwarding receipt')
            raw=os.read(fd,MAX_BYTES+1)
            if len(raw)!=st.st_size:raise ValueError('Incomplete forwarding receipt')
            data=json.loads(raw)
            if data.get('version')!=1 or data.get('plan',{}).get('plan_id')!=ident:raise ValueError('Invalid forwarding receipt')
            return data
        finally:os.close(fd)

    def save(self, plan, phase):
        p=self.path(plan['plan_id'])
        if phase not in ('started','completed'):raise ValueError('Receipt phase')
        if phase=='completed':
            before=self.load(plan['plan_id'])
            if before['phase']!='started' or before['plan']['digest']!=plan['digest']:raise ValueError('Receipt transition mismatch')
        raw=json.dumps({'version':1,'phase':phase,'plan':plan},sort_keys=True,separators=(',',':')).encode()
        if len(raw)>MAX_BYTES:raise ValueError('Forwarding receipt exceeds bound')
        tmp=p.with_suffix('.tmp')
        fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
            if phase=='started':
                os.link(tmp,p,follow_symlinks=False);os.unlink(tmp)
            else:os.replace(tmp,p)
            fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:
            if tmp.exists():tmp.unlink()
