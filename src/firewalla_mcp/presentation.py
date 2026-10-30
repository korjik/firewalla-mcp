"""Conservative presentation of selected metadata; never an enforcement evaluator."""
import re

CATEGORY_LABELS = {'games':'Gaming','av':'Video','social':'Social','porn':'Adult content','vpn':'VPN'}


def schedule_summary(expression, timezone):
    if not expression:
        return {'text':'No cron schedule reported; expiry/duration may still apply','timezone':timezone or 'not reported','evaluated':False}
    fields=expression.split()
    if len(fields)==6 and fields[0]=='0':
        fields=fields[1:]
    text='Schedule expression requires interpretation'
    if len(fields)==5:
        minute,hour,day,month,weekday=fields
        if minute.isdigit() and hour.isdigit() and 0<=int(minute)<60 and 0<=int(hour)<24 and day==month=='*':
            when={'*':'Daily','1-5':'Monday–Friday','0,6':'Sunday and Saturday'}.get(weekday)
            if when:text=f'{when} at {int(hour):02d}:{int(minute):02d}'
        elif fields==['*']*5:text='Every minute'
    return {'text':text,'expression':expression,'timezone':timezone or 'router schedule timezone not reported',
            'evaluated':False,'note':'Start schedule only; duration/expiry and enforcement are separate. No timezone assumption.'}


def describe_rule(row):
    result=dict(row)
    target=row.get('target');kind=row.get('type')
    if kind=='category':
        label=CATEGORY_LABELS.get(target)
        result['target_display']=label or ('App/category '+str(row['app_id']) if row.get('app_id') else 'Unresolved category '+str(target))
        result['target_label_resolved']=bool(label)
    else:
        result['target_display']=target
        result['target_label_resolved']=target is not None
    result['schedule_summary']=schedule_summary(row.get('cronTime'),row.get('timezone'))
    result['scopes']=[dict(scope) for scope in row.get('scopes',[])]
    for scope in result['scopes']:
        if scope.get('kind')=='global':
            scope['kind']='global_candidate'
            scope['name']='No device/group/network scope in selected fields'
            scope['applicability']='Unknown: other scope types and inheritance are not evaluated'
    result['units']={'duration':'seconds','expire':'Unix epoch seconds','timestamp':'Unix epoch seconds'}
    return result


def describe_vpn_inventory(data, checked_at):
    """Passive observations only; never infer administrative intent or health."""
    result=dict(data)
    result['profiles']=[]
    for profile in data.get('profiles',[]):
        row=dict(profile)
        connected=profile.get('cached_connected')
        present=profile.get('interface_present')
        row['enabled']={'value':None,'source':'Administrative start/stop intent is not exposed by this adapter'}
        row['connected']={'value':connected,'source':'Firewalla Redis VC connection-state cache',
                          'source_timestamp':None,'freshness':'unknown'}
        disconnected=connected is False and present is False
        conflict=connected is True and present is False
        row['health']={'status':'disconnected' if disconnected else 'unknown',
                       'healthy':False if disconnected else None,
                       'checked_at':checked_at,'check_type':'passive metadata only',
                       'reason':'No interface observed and cached connectivity is false; this does not prove administrative stop intent' if disconnected else
                       'Cached connectivity conflicts with absent interface; cache may be stale' if conflict else
                       'Interface/cache observations do not establish handshake freshness or provider reachability',
                       'active_probe_performed':False}
        result['profiles'].append(row)
    return result
