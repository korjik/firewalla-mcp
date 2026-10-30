"""Explicitly weaker new-ID maintenance evidence; NOT FireMain stopped intent.

Only usable after exact plan/window approval. No vendor module imports, API calls,
credential reads, writes, starts/stops or active network tests.
"""
import json
import os
import re
from pathlib import Path
from .vpn_import import need, ImportBlocked
from .vpn_import_inventory import collect_references


class NewIdObservation:
    def __init__(self, targets, runner):
        need(isinstance(targets,(tuple,list)) and 1<=len(targets)<=3
             and len(set(targets))==len(targets)
             and all(isinstance(t,str) and re.fullmatch(r'[a-f0-9]{10}',t) for t in targets), 'Fresh nonce IDs required')
        self.targets=tuple(targets)
        self.runner=runner

    def collision_check(self, run_directory):
        root=Path(run_directory)
        need(root.is_dir() and not root.is_symlink(),'Invalid runtime directory')
        paths=[]
        with os.scandir(root) as scan:
            for entry in scan:
                need(len(paths)<1024,'Runtime directory bound')
                paths.append(entry)
        for entry in paths:
            need(not any(entry.name==t or entry.name.startswith(t+'.') for t in self.targets),'Runtime filename collision')
            if entry.name.endswith('_profile'):
                need(entry.is_dir(follow_symlinks=False),'Profile directory symlink/type')
                with os.scandir(entry.path) as scan:
                    for index,item in enumerate(scan):
                        need(index<2048,'Profile directory bound')
                        need(not any(item.name==t or item.name.startswith(t+'.') for t in self.targets),'Profile ID collision')
        for target in self.targets:
            need(self.runner(['redis-cli','--raw','EXISTS','VC:'+target+':connState']).strip()=='0',
                 'Existing target cache before fresh-ID transaction')
        return {'file_collision_check_complete':True}

    def __call__(self, targets):
        need(tuple(targets)==self.targets,'Target set changed')
        refs=collect_references(targets,self.runner)
        need(refs['reference_enumeration_complete'] and all(v['unreferenced'] is True for v in refs['targets'].values()),'Target references present or unknown')
        try:
            links=json.loads(self.runner(['ip','-j','link','show']))
            need(isinstance(links,list) and len(links)<=256,'Interface inventory incomplete')
            names={row['ifname'] for row in links}
            result={}
            for target in targets:
                need('vpn_'+target not in names,'Target interface exists')
                unit=self.runner(['systemctl','show','openvpn_client@'+target+'.service','--property=LoadState,ActiveState,SubState,UnitFileState','--no-pager'])
                state=dict(line.split('=',1) for line in unit.splitlines() if '=' in line)
                need(state.get('LoadState') in ('loaded','not-found') and state.get('ActiveState')=='inactive'
                     and state.get('SubState')=='dead' and state.get('UnitFileState','') in ('','disabled','static'), 'Target unit is active, enabled or unknown')
                cache=self.runner(['redis-cli','--raw','GET','VC:'+target+':connState']).strip()
                need(cache in ('','false'),'Target connection cache is true or unknown')
                result[target]={'unreferenced':True,'reference_enumeration_complete':True,
                                'runtime_observation':'no_interface_inactive_unit_cache_not_true','administrative_intent':'unknown'}
            return result
        except (ValueError,KeyError,TypeError,OSError):
            raise ImportBlocked('Passive runtime observations unavailable') from None
