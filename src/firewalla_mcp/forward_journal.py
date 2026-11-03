"""Private append-only write-ahead journal for forwarding transactions.

Each event is immutable and fsynced before dispatch. A torn last event blocks
recovery; it is never silently discarded. Directory is deployment-provisioned.
"""
import fcntl
import json
import os
import re
import stat
from contextlib import contextmanager
from .forward_receipts import ForwardReceipts, MAX_BYTES
from .writes import digest

class ForwardJournal:
    def __init__(self, directory):
        self.root = ForwardReceipts(directory)

    @contextmanager
    def locked(self, ident, create=True):
        path=self.root.path(ident).with_suffix('.journal')
        fd=os.open(path,os.O_RDWR|(os.O_CREAT if create else 0)|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1:
                raise ValueError('Unsafe forwarding journal')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(directory)
            finally:os.close(directory)
            yield JournalSession(fd,ident)
        finally:os.close(fd)

class JournalSession:
    def __init__(self,fd,ident):
        self.fd,self.ident=fd,ident
        self.events=self.read()

    def read(self):
        os.lseek(self.fd,0,os.SEEK_SET)
        raw=os.read(self.fd,MAX_BYTES+1)
        if len(raw)>MAX_BYTES or raw and not raw.endswith(b'\n'):
            raise ValueError('Oversized or interrupted journal; manual inspection required')
        events=[];previous='0'*64
        for line in raw.splitlines():
            event=json.loads(line)
            if set(event)!={'sequence','previous','data','digest'} or event['sequence']!=len(events) or event['previous']!=previous:
                raise ValueError('Journal chain mismatch')
            if digest({k:v for k,v in event.items() if k!='digest'})!=event['digest']:
                raise ValueError('Journal digest mismatch')
            previous=event['digest'];events.append(event)
        if events and events[0]['data'].get('plan',{}).get('plan_id')!=self.ident:
            raise ValueError('Journal identity mismatch')
        return events

    def append(self,data):
        event={'sequence':len(self.events),'previous':self.events[-1]['digest'] if self.events else '0'*64,'data':data}
        event['digest']=digest(event)
        raw=json.dumps(event,sort_keys=True,separators=(',',':')).encode()+b'\n'
        if os.fstat(self.fd).st_size+len(raw)>MAX_BYTES:raise ValueError('Journal capacity exceeded')
        os.lseek(self.fd,0,os.SEEK_END)
        offset=0
        while offset<len(raw):
            n=os.write(self.fd,raw[offset:])
            if n<=0:raise OSError('Journal write failed')
            offset+=n
        os.fsync(self.fd)
        self.events.append(event)
