"""Host-side inspection guidance; never adopt or rewrite a native WAN selector."""
import re
from .forward_dependencies import require_mapping_removal


def mapping_reset_support(mapping, mappings, selected_wan):
    report={'supported':False,'preview_tool':'preview_forwarding_reset',
            'selected_wan_uuid':selected_wan,'automatic_policy_selection':False,
            'scope_change_authorized':False}
    if mapping.get('_type','port_forward')!='port_forward':
        return {**report,'scope':'unreviewed','code':'unsupported_removal',
                'reason':'This mapping kind is not supported by the port-forward reset tool.'}
    if 'applyToAll' in mapping or 'extIP' in mapping:
        return {**report,'scope':'additional_selectors','code':'additional_scope_selectors',
                'reason':'Additional native scope selectors are unsupported by this single-WAN reset tool; preserve the mapping.'}
    if 'wanUUID' not in mapping:
        return {**report,'scope':'native_default_wans','code':'missing_wan_uuid',
                'reason':'Mapping has no explicit wanUUID. Native default WAN scope is not the selected single WAN. Preserve this mapping; a scope-preserving workflow or separately approved scope migration is required and is not implemented by this reset tool.'}
    wan=mapping.get('wanUUID')
    if not isinstance(wan,str) or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',wan):
        return {**report,'scope':'unreviewed','code':'unreviewed_wan_selector',
                'reason':'Mapping has an unreviewed WAN selector; it must not be replaced with the selected WAN.'}
    if wan!=selected_wan:
        return {**report,'scope':'different_explicit_wan','code':'different_wan',
                'reason':'Mapping belongs to a different explicit WAN; this preview cannot migrate its scope.'}
    report={**report,'scope':'selected_explicit_wan'}
    try:
        require_mapping_removal(mapping,mappings)
        if not isinstance(mapping.get('description'),str) or len(mapping['description'])>256:
            raise ValueError('Mapping label bound')
        if not isinstance(mapping.get('toMac'),str) or not re.fullmatch(r'(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}',mapping['toMac']):
            raise ValueError('Mapping device identity')
    except (ValueError,TypeError,KeyError):
        return {**report,'code':'unsupported_removal',
                'reason':'Native selector or structural dependency checks failed; preserve the mapping.'}
    return {**report,'supported':True,'code':'eligible_for_preview',
            'reason':'Structural checks passed, not authorization. Fresh selection, policy association, live binding, enforcement and confirmation checks still apply.'}


def require_reset_scope(mapping, mappings, selected_wan):
    report=mapping_reset_support(mapping,mappings,selected_wan)
    if report['code'] in ('missing_wan_uuid','unreviewed_wan_selector','additional_scope_selectors','different_wan'):
        raise ValueError(report['reason'])
