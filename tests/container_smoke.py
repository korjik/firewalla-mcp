"""Real MCP initialize/list/call roundtrip against the built Docker image; no SSH."""
import asyncio
import pathlib
import sys
import subprocess
import tempfile
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    subprocess.run(["docker","--host=unix:///var/run/docker.sock","run","--rm","--network","none","--entrypoint","ssh",sys.argv[1],"-G","-F","/dev/null","example.invalid"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    with tempfile.TemporaryDirectory() as tmp:
        path=pathlib.Path(tmp)/"config.json"
        path.write_text('{"sites":{}}'); path.chmod(0o644)
        params=StdioServerParameters(command="docker",args=["--host=unix:///var/run/docker.sock","run","--rm","-i","--read-only","--cap-drop=ALL","--security-opt=no-new-privileges", "-v",str(path)+":/config/config.json:ro",sys.argv[1]])
        async with stdio_client(params) as (read,write):
            async with ClientSession(read,write) as session:
                await session.initialize()
                names={t.name for t in (await session.list_tools()).tools}
                assert len(names)==36
                assert not {'apply_change','apply_vpn_change','apply_vpn_import','start_capture','apply_network_plan'} & names
                assert not (await session.call_tool("list_boxes",{})).isError
                print("Docker MCP initialize, 36 read-only tools, list_boxes: PASS")

if __name__=="__main__": asyncio.run(main())
