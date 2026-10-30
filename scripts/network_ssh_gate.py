"""Candidate VPN/network forced-command gate; installation requires separate approval.

An operator replaces the two digest placeholders with reviewed artifact hashes.
No unrestricted shell, arbitrary helper path, general write operation or approval.
"""
import hashlib
import json
import os
import re
import shlex
import stat
import sys

READ_DIGEST = 'REPLACE_WITH_REVIEWED_REMOTE_SHA256'
IMPORT_DIGEST = 'REPLACE_WITH_REVIEWED_IMPORT_SHA256'
ALLOWED = frozenset('managed_workflow_state membership_snapshot saved_vpn_profiles service_features control_state app_catalog control_rules device_flows alarm_summaries policy_summaries flow_sample services inventory device_policy vpn_interfaces traffic alarm_count dns_config conntrack capabilities health network device vpn mappings firewall ipsets connections tcp dns'.split())


def validated(command, read_digest=READ_DIGEST, import_digest=IMPORT_DIGEST, import_path=None):
    if not isinstance(command,str) or len(command)>131072: raise ValueError('command bound')
    if not re.fullmatch(r'[a-f0-9]{64}',read_digest) or not re.fullmatch(r'[a-f0-9]{64}',import_digest):
        raise ValueError('reviewed pins required')
    if command=='firewalla-vpn-import-v1':
        path=import_path or '/home/pi/.ssh/firewalla-mcp-vpn-import.pyz'
        parent=os.lstat(os.path.dirname(path))
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)!=0o700:
            raise ValueError('unsafe helper parent')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>262144:
                raise ValueError('unsafe import helper')
            data=os.read(fd,262145)
            if len(data)!=info.st_size or hashlib.sha256(data).hexdigest()!=import_digest:
                raise ValueError('import helper pin mismatch')
            os.set_inheritable(fd,True)
            # Execute the verified open inode, not a second lookup of its pathname.
            return ['timeout','110','python3','-I','/proc/self/fd/'+str(fd)],fd
        except BaseException:
            os.close(fd);raise
    parts=shlex.split(command)
    if len(parts)!=6 or parts[0]!='timeout' or parts[2:4]!=['python3','-c']:
        raise ValueError('unsupported command')
    if hashlib.sha256(parts[4].encode()).hexdigest()!=read_digest:raise ValueError('remote helper pin mismatch')
    request=json.loads(parts[5])
    if not isinstance(request,dict) or set(request)!={'operation','arguments'} or not isinstance(request['arguments'],dict):
        raise ValueError('request shape')
    operation,args=request['operation'],request['arguments']
    if operation in ALLOWED:
        if parts[1]!='20':raise ValueError('read deadline')
    elif operation=='managed_write':
        if not isinstance(args.get('spec'),dict) or args['spec'].get('kind') not in ('managed_vpn','managed_lifecycle','managed_forward','managed_forward_batch'):
            raise ValueError('outside reviewed network capability')
        if args.get('mode') not in ('preview','apply','rollback'):raise ValueError('write mode')
        expected='110' if args['spec']['kind']=='managed_lifecycle' else '20'
        if parts[1]!=expected:raise ValueError('VPN deadline')
    else:raise ValueError('operation denied')
    return parts,None


if __name__=='__main__':
    try:argv,fd=validated(os.environ.get('SSH_ORIGINAL_COMMAND',''))
    except Exception:sys.exit(126)
    os.execve('/usr/bin/timeout',argv,{'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/home/pi','LANG':'C.UTF-8'})
