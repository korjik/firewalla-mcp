"""Actual MCP protocol with lifecycle opt-in, no boxes/network/SSH configured."""
import asyncio
import sys
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client

BOOT='''import json,os,sys
from pathlib import Path
for directory in ("/state/ledger","/state/forwarding"):Path(directory).mkdir(mode=0o700)
Path("/state/config.json").write_text(json.dumps({"sites":{},"writes_enabled":True,"write_confirmation_mode":"host_confirmed","forwarding_lifecycle_enabled":True,"forwarding_recovery_directory":"/state/forwarding","approval_consumed_directory":"/state/ledger","audit_file":"/state/audit.jsonl"}))
os.environ["FIREWALLA_MCP_CONFIG"]="/state/config.json"
sys.argv=["firewalla-mcp","--allow-write-catalog"]
from firewalla_mcp.server import main
main()
'''
async def main():
    params=StdioServerParameters(command='docker',args=['run','--rm','-i','--network','none','--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--tmpfs','/state:uid=10001,gid=10001,mode=700','--entrypoint','python',sys.argv[1],'-c',BOOT])
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write) as session:
            await session.initialize()
            tools={t.name:t for t in (await session.list_tools()).tools}
            assert {'inspect_forwarding_lifecycle','preview_forwarding_lifecycle','apply_forwarding_lifecycle','preview_forwarding_recovery'}<=tools.keys()
            schema=tools['preview_forwarding_lifecycle'].inputSchema
            assert schema['$defs']['LifecycleAction']['properties']['protocol']['const']=='tcp'
            assert (await session.call_tool('apply_forwarding_lifecycle',{'plan_id':'a'*32})).isError
            caps=await session.call_tool('write_capabilities',{})
            assert not caps.isError and caps.structuredContent['forwarding_lifecycle_enabled'] is True
            print('PASS: Docker MCP initialize/list/capabilities, typed lifecycle schema, unknown-plan rejection; no router calls')
asyncio.run(main())
