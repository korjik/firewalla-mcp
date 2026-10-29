import json
import sys
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def test_real_stdio_protocol(tmp_path):
    path=tmp_path/'config.json'; path.write_text(json.dumps({"sites":{}}))
    params=StdioServerParameters(command=sys.executable,args=["-m","firewalla_mcp.server"],env={"FIREWALLA_MCP_CONFIG":str(path)})
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write) as session:
            await session.initialize()
            assert len((await session.list_tools()).tools)==21
            result=await session.call_tool("list_boxes",{})
            assert not result.isError
            result=await session.call_tool("tcp_probe",{"box_name":"bad", "address":";id", "port":0})
            assert result.isError
