#!/usr/bin/env python3
"""Run a disposable synthetic import/rollback. Accepts no router or directory arguments."""
import json
import ssl
import tempfile
from pathlib import Path

from firewalla_mcp.vpn_import import InactiveImport, digest


def main():
    cert = ssl.DER_cert_to_PEM_cert(ssl.create_default_context().get_ca_certs(binary_form=True)[0])
    profile = ("client\ndev tun\nproto udp\nremote vpn.example.test 1194\nremote-cert-tls server\n"
               "auth-user-pass\ncipher AES-128-GCM\n<ca>\n" + cert + "</ca>\n").encode()
    def synthetic_state(ids):
        return {i: {"inactive": True, "unreferenced": True, "administrative_intent": "stopped"} for i in ids}
    with tempfile.TemporaryDirectory(prefix="firewalla-import-sandbox-") as directory:
        root = Path(directory)
        for suffix, content in {"ovpn": profile, "userpass": b"synthetic-user\nsynthetic-password",
                                "settings": b'{"strictVPN":true,"routeDNS":true,"overrideDefaultRoute":true}'}.items():
            file = root / ("source." + suffix)
            file.write_bytes(content)
            file.chmod(0o600)
        tool = InactiveImport(root, synthetic_state)
        try:
            targets = [{"id": "target_" + letter, "display_name": "Target " + letter,
                        "content": profile, "sha256": digest(profile), "endpoint": "vpn.example.test"} for letter in "abc"]
            plan = tool.plan("source", targets)
            def synthetic_approval(preview, operation):
                path = root / ".mcp-import" / (preview["transaction"] + ".approval")
                path.write_text(json.dumps({"transaction": preview["transaction"], "operation": operation, "digest": preview["approval_digest"]}))
                path.chmod(0o600)
            synthetic_approval(plan, "apply")
            assert tool.apply(plan["transaction"])["state"] == "imported_inactive"
            assert tool.apply(plan["transaction"])["state"] == "already_imported"
            rollback = tool.rollback_plan(plan["transaction"])
            synthetic_approval(rollback, "rollback")
            assert tool.rollback(plan["transaction"])["state"] == "rolled_back"
            assert not list(root.glob("target_*"))
            print("PASS: three synthetic inactive imports, idempotent apply, separately approved rollback; temporary files removed")
            print("No network access, real credentials, router operations or live state claims")
        finally:
            tool.close()


if __name__ == "__main__":
    main()
