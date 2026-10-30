"""Explicit People/group joins from allowlisted metadata; no ownership inference.

Read-only join used by the People MCP tool. The input
must be produced by bounded complete typed-tag and host/policy enumeration.
"""
import json
import re


def require(condition):
    if not condition:
        raise ValueError("Unsupported membership metadata; no inferred assignment")


def label(value):
    if value in (None, False, ''):
        return None
    require(isinstance(value, str) and len(value) <= 256 and all(ord(c) >= 32 for c in value))
    return value


def ids(value):
    if value in (None, False, ''):
        return []
    if isinstance(value, str):
        require(len(value) <= 4096)
        try:
            value = json.loads(value)
        except ValueError:
            raise ValueError("Malformed membership list") from None
    require(isinstance(value, list) and len(value) <= 64)
    require(all(isinstance(v, (str, int)) and not isinstance(v, bool) and re.fullmatch(r'[0-9]{1,20}', str(v)) for v in value))
    return sorted(set(map(str, value)))


def membership_directory(snapshot):
    require(isinstance(snapshot, dict) and type(snapshot.get('complete')) is bool)
    tags = snapshot.get('tags'); hosts = snapshot.get('hosts')
    require(isinstance(tags, list) and len(tags) <= 256 and isinstance(hosts, list) and len(hosts) <= 1024)
    catalog = {}
    for row in tags:
        require(isinstance(row, dict) and row.get('type') in ('user', 'group', 'device', 'ssid'))
        uid = ids([row.get('uid')])[0]; key = (row['type'], uid)
        require(key not in catalog)
        catalog[key] = {'id':uid, 'kind':row['type'], 'name':label(row.get('name')), 'devices':[]}
    fields = [('user','userTags','people'),('group','tags','groups'),('device','deviceTags','device_tags'),('ssid','ssidTags','ssid_tags')]
    parents = {(r['type'],str(r['uid'])):[(kind,uid) for kind,field,_ in fields for uid in ids(r.get(field))] for r in tags}
    def ancestry(key, path=()):
        require(key not in path and len(path)<16)
        found=set()
        for parent in parents.get(key,[]):
            found.add(parent)
            found.update(ancestry(parent,path+(key,)))
        return found
    devices = {}; unresolved = []
    for row in hosts:
        require(isinstance(row, dict))
        mac = row.get('mac')
        require(isinstance(mac, str) and re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', mac))
        mac = mac.upper()
        device = {'mac':mac, 'name':label(row.get('name')) or label(row.get('bname')),
                  'people':[], 'groups':[], 'device_tags':[], 'ssid_tags':[]}
        for kind, field, output in [('user','userTags','people'),('group','tags','groups'),
                                    ('device','deviceTags','device_tags'),('ssid','ssidTags','ssid_tags')]:
            for uid in ids(row.get(field)):
                tag = catalog.get((kind, uid))
                device[output].append({'id':uid, 'name':tag['name'] if tag else None, 'resolved':tag is not None})
                if tag is None:
                    unresolved.append({'mac':mac, 'kind':kind, 'id':uid})
        # Explicit tag-to-tag edges also carry People membership (device tags).
        direct={(kind,ref['id']) for kind,_,output in fields for ref in device[output]}
        derived=set()
        for key in direct: derived.update(ancestry(key))
        for kind,_,output in fields:
            for parent_kind,uid in sorted(derived-direct):
                if parent_kind!=kind: continue
                tag=catalog.get((kind,uid))
                device[output].append({'id':uid,'name':tag['name'] if tag else None,'resolved':tag is not None,'basis':'explicit_tag_relationship'})
                if tag is None: unresolved.append({'mac':mac,'kind':kind,'id':uid})
        if mac in devices:
            require(devices[mac] == device)  # Identical SCAN duplicates are safe; changed rows are not.
            continue
        devices[mac] = device
        for kind, output in [('user','people'),('group','groups'),('device','device_tags'),('ssid','ssid_tags')]:
            for ref in device[output]:
                tag = catalog.get((kind, ref['id']))
                if tag is not None:tag['devices'].append({'mac':mac, 'name':device['name']})
    complete = snapshot['complete'] and not unresolved
    for tag in catalog.values():
        tag['observed_device_count'] = len(tag['devices'])
        tag['assigned_device_count'] = len(tag['devices']) if complete else None
    return {'people':[t for (kind,_),t in catalog.items() if kind=='user'],
            'groups':[t for (kind,_),t in catalog.items() if kind=='group'],
            'other_tags':[t for (kind,_),t in catalog.items() if kind in ('device','ssid')],
            'devices':list(devices.values()), 'complete':complete, 'unresolved_memberships':unresolved,
            'ungrouped_devices':[d for d in devices.values() if not d['groups'] and not d['people']],
            'membership_basis':'Explicit device policy and tag-to-tag membership edges; no name inference or effective policy enforcement claim'}


def person_devices(directory, person):
    require(isinstance(person, str) and 1 <= len(person) <= 256)
    matches=[p for p in directory['people'] if p['id']==person]
    if not matches:
        matches=[p for p in directory['people'] if p['name'] and p['name'].casefold()==person.casefold()]
    require(len(matches)==1)
    entry=matches[0]
    possible=[{'mac':d['mac'],'name':d['name']} for d in directory['devices']
              if not d['people'] and entry['name'] and d['name'] and entry['name'].casefold() in d['name'].casefold()]
    return {'person':{'id':entry['id'],'name':entry['name']}, 'assigned_devices':entry['devices'],
            'assigned_device_count':entry['assigned_device_count'], 'complete':directory['complete'],
            'unassigned_name_matches':possible, 'name_match_is_membership':False,
            'note':'Only explicit People membership, including explicit tag relationships, answers this query; name matches are separate and do not imply ownership.'}
