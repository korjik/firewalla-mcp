#!/usr/bin/env python3
"""Privileged issuer invoked ONLY by an independently authorized host action.

Not an MCP tool and not proof of user consent. The SSH/operator authorization
boundary must review the exact preview and authorize this command. Fixed inbox;
no commands, paths, credentials, or user-consent boolean accepted as arguments.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

INBOX = Path('/volume1/opt/firewalla-mcp-runtime/operator-approvals')
READER_GID = 10001


def issue(directory, plan_id, digest, expires_at, reader_gid=READER_GID):
    if os.geteuid() != 0:
        raise ValueError('Issuer requires an independently authorized root host action')
    if not re.fullmatch(r'[a-f0-9]{32}', plan_id) or not re.fullmatch(r'[a-f0-9]{64}', digest):
        raise ValueError('Invalid exact-plan identity')
    if type(expires_at) is not int or not time.time() < expires_at <= time.time() + 600:
        raise ValueError('Preview expired or deadline exceeds ten minutes')
    directory = Path(directory)
    if not directory.is_absolute(): raise ValueError('Absolute fixed inbox required')
    # Reject redirected path components; deployment must protect each ancestor
    # against replacement by the MCP UID. Never create/chmod parent directories.
    for parent in (directory, *directory.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode): raise ValueError('Unsafe inbox path')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = '.' + secrets.token_hex(16) + '.tmp'
    created = False
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_gid != reader_gid or stat.S_IMODE(info.st_mode) != 0o750:
            raise ValueError('Inbox must be root-owned 0750 with the MCP reader group')
        out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        created = True
        try:
            payload = json.dumps(dict(plan_id=plan_id, digest=digest, expires_at=expires_at, approved=True)).encode()
            os.fchown(out, 0, reader_gid)
            os.fchmod(out, 0o640)
            if os.write(out, payload) != len(payload): raise OSError('Incomplete approval write')
            os.fsync(out)
        finally:
            os.close(out)
        if time.time() >= expires_at: raise ValueError('Preview expired while issuing')
        # Atomic publication, never overwrite even an expired/consumed approval.
        os.link(temporary, plan_id + '.json', src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.fsync(fd)
        return {'status':'issued', 'plan_id':plan_id, 'digest':digest, 'expires_at':expires_at}
    finally:
        if created: os.unlink(temporary, dir_fd=fd)
        os.fsync(fd)
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan-id', required=True)
    parser.add_argument('--digest', required=True)
    parser.add_argument('--expires-at', required=True, type=int)
    args = parser.parse_args()
    try:
        result = issue(INBOX, args.plan_id, args.digest, args.expires_at)
    except (ValueError, OSError):
        raise SystemExit('Approval not issued or outcome uncertain; inspect the exact plan file before retry') from None
    print(json.dumps(result))


if __name__ == '__main__': main()
