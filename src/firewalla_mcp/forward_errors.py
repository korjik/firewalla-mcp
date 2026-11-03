"""Public diagnostic codes; never serialize exception text or remote output."""
ERROR_CODES = frozenset({
    'unsupported_contract', 'permission_denied', 'deadline_exceeded',
    'invalid_state_or_request', 'os_failure', 'internal_failure',
})


def failure_code(error):
    from .remote import Unsupported
    if isinstance(error, Unsupported):
        return 'unsupported_contract'
    if isinstance(error, PermissionError):
        return 'permission_denied'
    if isinstance(error, TimeoutError):
        return 'deadline_exceeded'
    if isinstance(error, (ValueError, KeyError, TypeError)):
        return 'invalid_state_or_request'
    if isinstance(error, OSError):
        return 'os_failure'
    return 'internal_failure'
