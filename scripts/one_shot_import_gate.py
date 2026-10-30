"""Reviewed building block for a temporary exact-command SSH gate; not installed.

Preserve the normal read gate. A separately approved operator supplies fixed paths,
nonce, digest and a <=10-minute expiry. Consume before execution; never auto-retry.
"""
import hashlib
import os
import re
import shlex
import stat
import time


def one_shot_command(command, *, nonce, helper_path, helper_digest, deadline, used_path, now=None):
    current=time.time() if now is None else now
    if not isinstance(nonce,str) or not re.fullmatch(r'[a-f0-9]{32}',nonce):raise ValueError('invalid nonce')
    if type(deadline) is not int or not current<deadline<=current+600:raise ValueError('expired window')
    if shlex.split(command)!=['firewalla-import-once',nonce]:raise ValueError('unapproved command')
    if not re.fullmatch(r'[a-f0-9]{64}',helper_digest):raise ValueError('invalid digest')
    for path in (helper_path,used_path):
        parent=os.stat(os.path.dirname(path),follow_symlinks=False)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.getuid() or parent.st_mode&0o077:
            raise ValueError('unsafe parent')
    fd=os.open(helper_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077 or info.st_nlink!=1 or info.st_size>65536:
            raise ValueError('unsafe helper')
        code=os.read(fd,65537)
    finally:os.close(fd)
    if hashlib.sha256(code).hexdigest()!=helper_digest:raise ValueError('helper changed')
    # Execute these verified bytes, avoiding a second path lookup.
    source=code.decode('utf-8')
    compile(source,'approved-import-helper','exec')
    fd=os.open(used_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:os.fsync(fd)
    finally:os.close(fd)
    return ['timeout','110','python3','-c',source,str(deadline)]
