"""Fixed-command stdin RPC. Archives and credentials remain on the router."""
import asyncio
import json
from .transport import ssh_argv, bounded_read

COMMAND = "firewalla-vpn-import-v1"


class ImportTransport:
    async def request(self, site, request):
        raw = json.dumps(request, separators=(",", ":")).encode()
        if len(raw) > 8192:
            raise ValueError("Import request limit")
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(*ssh_argv(site, COMMAND),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            async with asyncio.timeout(110):
                proc.stdin.write(raw); await proc.stdin.drain(); proc.stdin.close()
                result = await bounded_read(proc.stdout)
                code = await proc.wait()
            data = json.loads(result)
            if code or not isinstance(data, dict) or data.get("status") not in ("ok", "blocked"):
                raise ValueError("Invalid import response")
            return data
        except (OSError, ValueError, TimeoutError):
            return {"status": "unavailable", "reason": "Import transport failed; outcome may be uncertain. Inspect before retry."}
        finally:
            if proc is not None and proc.returncode is None:
                proc.kill(); await proc.wait()
