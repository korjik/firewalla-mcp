#!/usr/bin/env python3
"""Create a deterministic dependency-free router helper; never deploy or trust it."""
import hashlib
from pathlib import Path
import sys
import zipfile

MODULES = ('vpn_import', 'vpn_archive', 'vpn_import_inventory', 'vpn_new_id_guard', 'vpn_import_dispatch', 'remote')


def build(destination):
    root = Path(__file__).resolve().parents[1] / 'src/firewalla_mcp'
    files = {'__main__.py':b'from firewalla_mcp.vpn_import_dispatch import main\nmain()\n', 'firewalla_mcp/__init__.py':b''}
    files.update({'firewalla_mcp/'+name+'.py':(root/(name+'.py')).read_bytes() for name in MODULES})
    with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,data in sorted(files.items()):
            info=zipfile.ZipInfo(name,date_time=(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o100600 << 16;archive.writestr(info,data)
    return hashlib.sha256(Path(destination).read_bytes()).hexdigest()


if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Usage: build_vpn_import_helper.py OUTPUT.pyz')
    print(build(sys.argv[1]))
