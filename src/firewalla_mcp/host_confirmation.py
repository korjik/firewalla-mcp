"""Single-use execution claims for an explicitly trusted confirming MCP host.

This validates execution state, NOT human consent. The authenticated host must
obtain confirmation before apply. No consent boolean or external issuer is used.
"""
import json
import os
from pathlib import Path
import stat
import time


def validate_ledger(config):
    path=Path(config.approval_consumed_directory or '')
    if not path.is_absolute():raise ValueError('Absolute execution ledger required')
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError('Execution ledger must be a private process-owned directory')
    return path


def claim(config,plan):
    path=validate_ledger(config)
    if time.time()>=plan['expires_at']:raise ValueError('Plan expired')
    try:fd=os.open(path/(plan['plan_id']+'.used'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:raise ValueError('Plan already consumed') from None
    try:
        data=json.dumps({'plan_id':plan['plan_id'],'digest':plan['digest'],'authorization_model':'trusted_mcp_host'}).encode()
        if os.write(fd,data)!=len(data):raise OSError('Incomplete execution claim')
        os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
