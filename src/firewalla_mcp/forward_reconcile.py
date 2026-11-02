"""Pure reconciliation decisions. No transport or implicit adoption/deletion.

The native NAT+allow adapter is intentionally not registered until its complete
installed enforcement contract is validated. This planner never executes writes.
"""
import copy
from ipaddress import IPv4Address, IPv4Network
import re
from .writes import digest


def desired_set(device, destination, interface_uuid, public_address, actions):
    if not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',device):raise ValueError('device')
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',interface_uuid):raise ValueError('interface UUID')
    destination=str(IPv4Address(destination));public_address=str(IPv4Address(public_address))
    if not isinstance(actions,list) or not 1<=len(actions)<=4:raise ValueError('one to four actions')
    seen=set();result=[]
    for row in actions:
        if set(row)!={'protocol','external_port','destination_port','source_network'}:raise ValueError('explicit source scope required')
        if row['protocol'] not in ('tcp','udp'):raise ValueError('protocol')
        if any(type(row[k]) is not int or not 1<=row[k]<=65535 for k in ('external_port','destination_port')):raise ValueError('port')
        source=str(IPv4Network(row['source_network'],strict=True))
        key=(row['protocol'],row['external_port'])
        if key in seen:raise ValueError('duplicate external port/protocol')
        seen.add(key)
        result.append({'device':device.upper(),'destination':destination,'interface_uuid':interface_uuid,
                       'public_address':public_address,**row,'source_network':source})
    return result


def reconcile(existing, desired, *, remove_ids=(), verified_owned_ids=()):
    """All existing rows are adapter-normalized exact objects, never raw Redis data.

    Explicit removals require a matching trusted provenance ID. Legacy entries
    remain preserved/blocked until a separate inspected-adoption contract exists.
    """
    if len(existing)>256 or len(desired)>8:raise ValueError('snapshot/desired bound')
    for r in existing+desired:
        if not isinstance(r,dict) or not isinstance(r.get('id'),str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',r['id']):raise ValueError('object ID')
        if not isinstance(r.get('value'),dict) or not re.fullmatch(r'[a-f0-9]{64}',r.get('fingerprint','')):raise ValueError('normalized object/fingerprint required')
        if not isinstance(r.get('dependencies',[]),list) or any(not isinstance(x,str) for x in r.get('dependencies',[])):raise ValueError('dependencies')
    if len({r['id'] for r in desired})!=len(desired) or len({(r['kind'],digest(r['value'])) for r in desired})!=len(desired):raise ValueError('duplicate desired identity')
    rows={r['id']:r for r in existing}
    if len(rows)!=len(existing):raise ValueError('ambiguous existing IDs')
    if len(set(remove_ids))!=len(remove_ids):raise ValueError('duplicate removals')
    if not set(remove_ids)<=set(rows):raise ValueError('unknown removal')
    if not set(remove_ids)<=set(verified_owned_ids):raise ValueError('unproven ownership; explicit inspected adoption needed')
    for row in existing+desired:
        if set(row)-{'id','kind','value','fingerprint','supported','dependencies'}:raise ValueError('unknown object fields')
        if row['kind'] not in ('mapping','allow_policy'):raise ValueError('unsupported object kind')
        if row.get('supported') is not True:raise ValueError('unsupported or inherited object')
    if any(not set(r.get('dependencies',[]))<=set(rows) for r in existing):raise ValueError('incomplete dependency inventory')
    if any(r['id'] not in remove_ids and set(r.get('dependencies',[]))&set(remove_ids) for r in existing):raise ValueError('preserved object depends on removal')
    preserve=[copy.deepcopy(r) for r in existing if r['id'] not in remove_ids]
    remove=[copy.deepcopy(rows[k]) for k in remove_ids]
    for row in remove:
        if any(x not in remove_ids for x in row.get('dependencies',[])):
            raise ValueError('removal affects a preserved dependency')
    create=[]
    preserved_ids={r["id"]:r for r in preserve}
    for row in desired:
        if row["id"] in preserved_ids and (row["kind"],row["value"])!=(preserved_ids[row["id"]]["kind"],preserved_ids[row["id"]]["value"]):raise ValueError("desired ID collides with preserved object")
        matches=[r for r in preserve if r['kind']==row['kind'] and r['value']==row['value']]
        if len(matches)>1:raise ValueError('ambiguous duplicate desired object')
        if not matches:create.append(copy.deepcopy(row))
    final_ids=set(preserved_ids)|{r["id"] for r in create}
    if any(not set(r.get("dependencies",[]))<=final_ids for r in desired):raise ValueError("unresolved desired dependency")
    # Revoke owned allowance before removing NAT; create allowance disabled,
    # create NAT, then activate exact allowance only after all preconditions pass.
    steps=[{'operation':'remove','object':r} for r in sorted(remove,key=lambda r:r['kind']!='allow_policy')]
    steps += [{'operation':'create_disabled' if r['kind']=='allow_policy' else 'create','object':r}
              for r in sorted(create,key=lambda r:r['kind']!='allow_policy')]
    steps += [{'operation':'enable','object':r} for r in create if r['kind']=='allow_policy']
    plan={'snapshot_digest':digest(existing),'preserve':preserve,'steps':steps,'atomic':False,
          'recovery':'Stop on drift or uncertainty. Fresh inspection and confirmation required; never blind compensation.'}
    return {**plan,'digest':digest(plan)}


def adopt_mapping_removal(mappings, selection, dependency_report):
    """Prepare exact legacy adoption, not retrospective proof of MCP ownership.

    Must be fed by a bounded trusted on-box collector. A caller-supplied tag or
    stale plan ID is insufficient. This function cannot execute any removal.
    """
    required={'device','destination','interface_uuid','protocol','external_port','destination_port','expected_fingerprint'}
    if not isinstance(selection,dict) or set(selection)!=required:raise ValueError('complete explicit selection required')
    checked=desired_set(selection['device'],selection['destination'],selection['interface_uuid'],'192.0.2.1',[
        {'protocol':selection['protocol'],'external_port':selection['external_port'],'destination_port':selection['destination_port'],'source_network':'192.0.2.1/32'}])[0]
    if not isinstance(mappings,list) or len(mappings)>256:raise ValueError('bounded complete mapping inventory required')
    selected=[]
    for row in mappings:
        if row.get('wanUUID')==checked['interface_uuid'] and row.get('protocol')==checked['protocol'] and str(row.get('dport'))==str(checked['external_port']):selected.append(row)
    if len(selected)!=1:raise ValueError('absent or ambiguous mapping identity')
    row=selected[0]
    allowed={'_type','active','description','dport','enabled','protocol','state','toIP','toMac','toPort','wanUUID'}
    if set(row)!=allowed or row['_type']!='port_forward' or any(row[k] is not True for k in ('active','state','enabled')):raise ValueError('unsupported mapping shape/state')
    if row['toIP']!=checked['destination'] or row['toMac'].upper()!=checked['device'] or str(row['toPort'])!=str(checked['destination_port']):raise ValueError('destination drift')
    if not isinstance(row['description'],str) or not re.fullmatch('mcp:[a-f0-9]{32}',row['description']):raise ValueError('not an eligible MCP-tagged mapping')
    fingerprint=digest(row)
    if selection['expected_fingerprint']!=fingerprint:raise ValueError('selected object changed')
    if not isinstance(dependency_report,dict) or dependency_report.get('complete') is not True or dependency_report.get('referring_policy_ids')!=[] or dependency_report.get('shared') is not False or dependency_report.get('unresolved_policy_ids',[])!=[]:raise ValueError('unresolved dependencies; no adoption')
    return {'kind':'mapping','value':copy.deepcopy(row),'fingerprint':fingerprint,
            'inventory_fingerprint':digest(mappings),'authorization_required':'fresh exact-object removal confirmation',
            'provenance':'explicitly inspected legacy adoption, not historical ownership proof',
            'preserved_mapping_count':len(mappings)-1,'execution_enabled':False}
