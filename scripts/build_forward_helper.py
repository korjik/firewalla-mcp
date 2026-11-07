#!/usr/bin/env python3
"""Build deterministic local forwarding helper; does not install or trust it."""
import hashlib
from pathlib import Path
import sys
import zipfile
MODULES=('forward_rule_projection','forward_default_wan','forward_dispatch','forward_native','forward_policy','forward_enforcement','forward_dependencies',
         'forward_transaction','forward_journal','forward_receipts','forward_provenance','forward_app_adapter','forward_app_adoption','forward_app_enforcement','ipv6_adapter','ipv6_policy','forwarding_guidance','writes','remote')
def build(destination):
    root=Path(__file__).resolve().parents[1]/'src/firewalla_mcp'
    files={'__main__.py':b'from firewalla_mcp.forward_dispatch import main\nmain()\n','firewalla_mcp/__init__.py':b''}
    files.update({'firewalla_mcp/'+name+'.py':(root/(name+'.py')).read_bytes() for name in MODULES})
    with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,data in sorted(files.items()):
            info=zipfile.ZipInfo(name,date_time=(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o100600<<16;archive.writestr(info,data)
    return hashlib.sha256(Path(destination).read_bytes()).hexdigest()
if __name__=='__main__':print(build(sys.argv[1]))
