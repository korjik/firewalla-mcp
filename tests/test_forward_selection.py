import copy
import re
import time
import pytest
from pydantic import ValidationError
from firewalla_mcp.models import AppMappingSelection,LifecycleRemoval
from firewalla_mcp.forward_manager import ForwardManager
from firewalla_mcp.forward_selection import mapping_reset_support
from firewalla_mcp.forward_dependencies import require_mapping_removal
from firewalla_mcp.server import build_server
from firewalla_mcp.writes import digest
from test_forward_reconcile import legacy_mapping
from test_forward_reset_manager import reset_fixture,metadata,coordinator,manager,native_fixture


def test_digest_key_routes_to_app_schema_without_widening_lifecycle():
    selection={'key':'mapping:'+'a'*64,'fingerprint':'b'*64}
    assert AppMappingSelection(**selection).key==selection['key']
    with pytest.raises(ValidationError):LifecycleRemoval(**selection)
    with pytest.raises(ValidationError):AppMappingSelection(**{**selection,'key':'policy:'+'a'*64})


async def test_advertised_and_runtime_app_schema_accept_digest(reset_fixture,monkeypatch):
    fm,spec,store=reset_fixture;calls=[]
    async def preview(self,*args):calls.append(args);return {'status':'synthetic'}
    monkeypatch.setattr(ForwardManager,'preview_app_reset',preview)
    server=build_server(fm.config)
    tools={t.name:t for t in await server.list_tools()}
    reset=tools['preview_forwarding_reset'].inputSchema
    lifecycle=tools['preview_forwarding_lifecycle'].inputSchema
    key='mapping:'+'a'*64
    assert re.fullmatch(reset['$defs']['AppMappingSelection']['properties']['key']['pattern'],key)
    assert not re.fullmatch(lifecycle['$defs']['LifecycleRemoval']['properties']['key']['pattern'],key)
    args=dict(box_name='router-a',device=spec['device'],destination_ip=spec['destination_ip'],interface_uuid=spec['interface_uuid'],
              mappings=[{'key':key,'fingerprint':'b'*64}],policies=[],recreate=[],all_mappings=False,maintenance_until=int(time.time())+300)
    await server.call_tool('preview_forwarding_reset',args)
    assert len(calls)==1 and calls[0][4]==args['mappings']
    assert not store['calls']


@pytest.mark.parametrize('value',[None,'',False,'*','invalid'])
def test_unreviewed_wan_is_not_normalized(value):
    mapping=legacy_mapping();wan=mapping['wanUUID'];mapping['wanUUID']=value
    before=copy.deepcopy(mapping)
    report=mapping_reset_support(mapping,[mapping],wan)
    assert not report['supported'] and report['code']=='unreviewed_wan_selector'
    assert mapping==before


@pytest.mark.parametrize('extra',[{}, {'autoFirewall':1}])
def test_omitted_wan_reports_scope_not_bad_key(extra):
    mapping=legacy_mapping();wan=mapping.pop('wanUUID');mapping.update(extra)
    report=mapping_reset_support(mapping,[mapping],wan)
    assert report['scope']=='native_default_wans' and report['code']=='missing_wan_uuid'
    assert not report['supported'] and not report['automatic_policy_selection']
    assert not report['scope_change_authorized']
    # Preserve the underlying selector guard, not just presentation guidance.
    with pytest.raises(ValueError,match='Exact native removal selector'):require_mapping_removal(mapping,[mapping])


@pytest.mark.parametrize('extra',[{'applyToAll':True},{'applyToAll':False},{'extIP':'198.51.100.9'},{'extIP':None}])
def test_additional_scope_never_mislabeled_as_default_wan(extra):
    mapping=legacy_mapping();wan=mapping.pop('wanUUID');mapping.update(extra)
    report=mapping_reset_support(mapping,[mapping],wan)
    assert not report['supported'] and report['scope']=='additional_selectors'


def test_other_wan_and_ambiguous_native_matches_are_not_eligible():
    mapping=legacy_mapping()
    report=mapping_reset_support(mapping,[mapping],'22222222-2222-4222-8222-222222222222')
    assert report['code']=='different_wan'
    duplicate={**mapping,'description':'different label'}
    report=mapping_reset_support(mapping,[mapping,duplicate],mapping['wanUUID'])
    assert not report['supported'] and report['code']=='unsupported_removal'


def test_dmz_is_not_reported_as_a_default_wan_port_forward():
    mapping=legacy_mapping();wan=mapping.pop('wanUUID');mapping['_type']='dmz_host'
    report=mapping_reset_support(mapping,[mapping],wan)
    assert not report['supported'] and report['scope']=='unreviewed'


async def test_inspection_explains_scope_and_reset_creates_no_plan(reset_fixture):
    fm,spec,store=reset_fixture
    store['maps'][0].update(description='Synthetic app HTTP',autoFirewall=1)
    store['maps'][0].pop('wanUUID')
    before=copy.deepcopy(store)
    args=('router-a',spec['device'],spec['destination_ip'],spec['interface_uuid'])
    app=await fm.inspect_app_objects(*args,int(time.time())+300)
    general=await fm.inspect(*args,int(time.time())+300)
    key='mapping:'+digest(store['maps'][0])
    selected=next(r for r in app['mappings'] if r['key']==key)
    other=next(r for r in general['objects'] if r['key']==key)
    assert selected['app_reset']==other['app_reset']
    assert selected['app_reset']['code']=='missing_wan_uuid'
    assert selected['fingerprint']==digest({k:v for k,v in selected.items() if k not in ('key','fingerprint','app_reset')})
    with pytest.raises(ValueError,match='Default WAN migration requires one mapping'):
        await fm.preview_app_reset(*args,[{k:selected[k] for k in ('key','fingerprint')}],[],[],False,int(time.time())+300)
    assert not fm.plans and store==before


async def test_explicit_wan_app_key_still_previews_without_implicit_policies(reset_fixture):
    fm,spec,store=reset_fixture
    store['maps'][0].update(description='Synthetic app HTTP',autoFirewall=1)
    args=('router-a',spec['device'],spec['destination_ip'],spec['interface_uuid'])
    inv=await fm.inspect_app_objects(*args,int(time.time())+300)
    selected=next(m for m in inv['mappings'] if m['value']['description']=='Synthetic app HTTP')
    assert selected['app_reset']['supported']
    plan=await fm.preview_app_reset(*args,[{k:selected[k] for k in ('key','fingerprint')}],[],[],False,int(time.time())+300)
    assert len(plan['steps'])==1 and plan['steps'][0]['before']['kind']=='mapping'
    assert not plan['app_adoptions']['policies'] and not store['calls']
