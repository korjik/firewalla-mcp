#!/usr/bin/env python3
"""Read-only source/profile metadata; never authorizes import or opens credentials."""
import argparse
import json

from firewalla_mcp.vpn_import import ImportBlocked
from firewalla_mcp.vpn_import_state import preflight


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--profiles", required=True)
    parser.add_argument("--source-label", required=True)
    parser.add_argument("--target", action="append", required=True)
    parser.add_argument("--legacy-readable-userpass-source", help="Exact source ID; stat-only compatibility check, not import permission")
    args = parser.parse_args()
    try:
        result = preflight(args.source_root, args.profiles, args.source_label, args.target,
                           legacy_readable_userpass_source=args.legacy_readable_userpass_source)
    except (ImportBlocked, OSError):
        result = {"status": "blocked", "live_import_ready": False,
                  "reason": "Source/profile metadata unavailable, ambiguous or unsupported; no credential read performed"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("live_import_ready") else 2


if __name__ == "__main__":
    raise SystemExit(main())
