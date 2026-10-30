import json
from unittest.mock import AsyncMock
import pytest
from firewalla_mcp.server import build_server
from firewalla_mcp.presentation import describe_rule, schedule_summary
from firewalla_mcp.analysis import summarize_page
from test_server import config


def unpack(result):
    if isinstance(result,tuple):return result[1]
    return json.loads(result[0].text)


async def test_read_catalog_capability_consistency(config):
    server=build_server(config,AsyncMock(),readonly_catalog=True)
    catalog=await server.list_tools()
    assert len(catalog)==36
    assert all(t.annotations.readOnlyHint for t in catalog)
    assert not any(t.name.startswith('preview_') or t.name=='apply_change' for t in catalog)
    data=unpack(await server.call_tool('write_capabilities',{}))
    assert data['enabled'] is False and data['live_writes_available'] is False
    assert data['executable_write_tools_exposed'] is False
    assert 'implemented' not in data


@pytest.mark.parametrize('arguments',[{'cursor':'not-a-cursor'},{'action':'__audit_no_match__'},
    {'device':'not-a-MAC'},{'cursor':'1:'+'a'*40+':'+'b'*16}])
async def test_rule_invalid_argument_rejected_before_ssh(config,arguments):
    transport=AsyncMock();server=build_server(config,transport)
    with pytest.raises(Exception):
        await server.call_tool('managed_rule_summaries',{'box_name':'router-a',**arguments})
    transport.run.assert_not_called()


async def test_partial_traversal_retains_rows_and_resume_cursor(config):
    transport=AsyncMock()
    transport.run.side_effect=[{'status':'ok','data':{'records':[{'id':'1','scopes':[]}],'scanned':1,'total':2,'has_more':True,'next_cursor':'resume'}},
                               {'status':'unavailable','reason':'timeout'}]
    result=unpack(await build_server(config,transport).call_tool('managed_rule_summaries',{'box_name':'router-a','all_pages':True}))
    assert result['status']=='partial' and result['data']['records'][0]['id']=='1'
    assert result['data']['next_cursor']=='resume' and result['data']['traversal_complete'] is False


def test_rule_scope_and_category_uncertainty():
    row=describe_rule({'type':'category','target':'dap_unknown','scopes':[{'kind':'global','name':'All devices'}]})
    assert not row['target_label_resolved']
    assert row['scopes'][0]['kind']=='global_candidate'
    assert 'All devices' not in json.dumps(row)
    assert describe_rule({'type':'category','target':'av'})['target_display']=='Video'


@pytest.mark.parametrize('expression,text',[('0 12 * * *','Daily at 12:00'),('0 0 12 * * 1-5','Monday–Friday at 12:00'),
    ('*/5 * * * *','Schedule expression requires interpretation')])
def test_cron_no_timezone_assumptions(expression,text):
    result=schedule_summary(expression,None)
    assert result['text']==text and result['evaluated'] is False
    assert 'not reported' in result['timezone']


def test_unknown_bytes_are_not_zero_and_coverage_survives():
    result=summarize_page({'records':[{'timestamp':1700000000,'domains':[],'destination_ip':None,'upload_bytes':None,'download_bytes':None}],
                           'next_offset':None,'index_counts_before_filters':{},'coverage':{'blocked':'absent_or_expired'},'limitations':'retention incomplete'})
    assert result['page_totals']['upload_bytes'] is None
    assert result['coverage']['blocked']=='absent_or_expired'
    assert result['source_limitations']=='retention incomplete'


async def test_people_tool_uses_explicit_membership_and_advertises_selector(config):
    from test_membership import snapshot
    transport=AsyncMock();transport.run.return_value={'status':'ok','data':snapshot()}
    server=build_server(config,transport,readonly_catalog=True)
    catalog=await server.list_tools()
    tool=next(t for t in catalog if t.name=='people_and_devices')
    assert 'person' in tool.inputSchema['properties']
    result=unpack(await server.call_tool('people_and_devices',{'box_name':'router-a','person':'Jordan'}))
    assert result['data']['assigned_device_count']==0
    assert len(result['data']['unassigned_name_matches'])==1
    assert transport.run.call_args.args[1]=='membership_snapshot'


async def test_saved_profile_tool_routes_only_fixed_read_operation(config):
    transport=AsyncMock();transport.run.return_value={'status':'ok','data':{'profiles':[]}}
    server=build_server(config,transport,readonly_catalog=True)
    result=unpack(await server.call_tool('saved_vpn_profiles',{'box_name':'router-a'}))
    assert result['data']['profiles']==[]
    assert transport.run.call_args.args[1:] == ('saved_vpn_profiles',{})
