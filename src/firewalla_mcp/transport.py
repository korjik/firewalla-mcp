import asyncio
import json
import shlex
from pathlib import Path
from .models import Site

MAX_OUTPUT = 131072


def remote_command(operation: str, arguments: dict) -> str:
    source = Path(__file__).with_name("remote.py").read_text()
    deadline = "110" if operation == "managed_write" and arguments.get("spec", {}).get("kind") == "managed_lifecycle" else "20"
    return shlex.join(["timeout", deadline, "python3", "-c", source,
                       json.dumps({"operation": operation, "arguments": arguments})])


def ssh_argv(site: Site, command: str) -> list[str]:
    return ["ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "UserKnownHostsFile="+site.known_hosts_file,
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2", "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no", "-o", "LogLevel=ERROR",
            "-i", site.identity_file, "-p", str(site.port),
            "--", site.user+"@"+site.host, command]


async def bounded_read(stream):
    chunks, size = [], 0
    while True:
        part = await stream.read(8192)
        if not part:
            return b"".join(chunks)
        size += len(part)
        if size > MAX_OUTPUT:
            raise ValueError("output limit")
        chunks.append(part)


class SSHTransport:
    def __init__(self):
        self.limit = asyncio.Semaphore(4)

    async def run(self, site: Site, operation: str, arguments: dict):
        async with self.limit:
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *ssh_argv(site, remote_command(operation, arguments)),
                    stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL)
                deadline = 115 if operation == "managed_write" and arguments.get("spec", {}).get("kind") == "managed_lifecycle" else 25
                async with asyncio.timeout(deadline):
                    raw = await bounded_read(proc.stdout)
                    code = await proc.wait()
                if code:
                    return {"status": "unavailable", "reason": "SSH or remote Python failed; verify host fingerprint, key, reachability and utilities locally."}
                data = json.loads(raw)
                if not isinstance(data, dict) or data.get("status") not in ("ok", "unsupported"):
                    raise ValueError("protocol")
                return data
            except (OSError, ValueError, TimeoutError):
                return {"status": "unavailable", "reason": "Transport timeout, output limit, or invalid response; details suppressed."}
            finally:
                if proc is not None and proc.returncode is None:
                    proc.kill()
                    await proc.wait()
