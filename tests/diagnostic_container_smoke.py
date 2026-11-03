"""MCP grant/revoke smoke in disposable network-none container; no real probes."""
import asyncio
import sys
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client
BOOT='''import json,os,sys
from pathlib import Path
for name in ("ledger","grants"):Path('/state/'+name).mkdir(mode=0o700)
config={"sites":{"router-a":{"host":"10.0.0.1","identity_file":"/nonexistent/key","known_hosts_file":"/nonexistent/hosts","vantage_group":"a"}},"writes_enabled":True,"write_confirmation_mode":"host_confirmed","diagnostic_grants_enabled":True,"diagnostic_grants_directory":"/state/grants","approval_consumed_directory":"/state/ledger","audit_file":"/state/audit"}
Path('/state/config.json').write_text(json.dumps(config));os.environ['FIREWALLA_MCP_CONFIG']='/state/config.json';sys.argv=['firewalla-mcp','--allow-write-catalog']
from firewalla_mcp.server import main
main()
'''
async def main():
    params=StdioServerParameters(command='docker',args=['run','--rm','-i','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--tmpfs','/state:uid=10001,gid=10001,mode=700','--entrypoint','python',sys.argv[1],'-c',BOOT])
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write) as session:
            await session.initialize()
            names={t.name for t in (await session.list_tools()).tools}
            assert {'preview_diagnostic_grant','preview_diagnostic_revoke','apply_diagnostic_grant_plan','diagnostic_grants'}<=names
            p=await session.call_tool('preview_diagnostic_grant',{'box_name':'router-a','address':'10.0.0.20','ports':[80,443],'ttl_seconds':600})
            assert not p.isError
            result=await session.call_tool('apply_diagnostic_grant_plan',{'plan_id':p.structuredContent['plan_id']});assert not result.isError
            assert (await session.call_tool('apply_diagnostic_grant_plan',{'plan_id':p.structuredContent['plan_id']})).isError
            r=await session.call_tool('preview_diagnostic_revoke',{'grant_id':result.structuredContent['grant_id']});assert not r.isError
            assert not (await session.call_tool('apply_diagnostic_grant_plan',{'plan_id':r.structuredContent['plan_id']})).isError
            inventory=await session.call_tool('diagnostic_grants',{})
            assert inventory.structuredContent['grants'][0]['revoked'] is True
            print('PASS: MCP catalog, exact synthetic grant/apply/replay rejection/revoke; network-none, no probes')
asyncio.run(main())
