"""Real MCP initialize/list/call roundtrip against the built Docker image; no SSH."""
import asyncio
import pathlib
import sys
import tempfile
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    with tempfile.TemporaryDirectory() as tmp:
        path=pathlib.Path(tmp)/"config.json"
        path.write_text('{"sites":{}}'); path.chmod(0o644)
        params=StdioServerParameters(command="docker",args=["--host=unix:///var/run/docker.sock","run","--rm","-i","--read-only","--cap-drop=ALL","--security-opt=no-new-privileges", "-v",str(path)+":/config/config.json:ro",sys.argv[1]])
        async with stdio_client(params) as (read,write):
            async with ClientSession(read,write) as session:
                await session.initialize()
                assert len((await session.list_tools()).tools)==46
                assert not (await session.call_tool("list_boxes",{})).isError
                print("Docker MCP initialize, 46 tools, list_boxes: PASS")

if __name__=="__main__": asyncio.run(main())
