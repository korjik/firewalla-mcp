import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from firewalla_mcp import forward_dispatch as dispatch
from firewalla_mcp.forward_errors import failure_code
from firewalla_mcp.forward_transport import decode_response
from firewalla_mcp.remote import Unsupported


@pytest.mark.parametrize('error,code', [
    (Unsupported('secret'), 'unsupported_contract'),
    (PermissionError('secret'), 'permission_denied'),
    (TimeoutError('secret'), 'deadline_exceeded'),
    (ValueError('secret'), 'invalid_state_or_request'),
    (KeyError('secret'), 'invalid_state_or_request'),
    (OSError('secret'), 'os_failure'),
    (RuntimeError('secret'), 'internal_failure'),
])
def test_safe_failure_codes(error, code):
    assert failure_code(error) == code


@pytest.mark.parametrize('operation,status', [('snapshot', 'unsupported'), ('mutate', 'uncertain')])
def test_helper_failure_roundtrip_preserves_uncertainty(monkeypatch, capsys, operation, status):
    async def fail(request):
        raise PermissionError('secret remote command and credentials')
    monkeypatch.setattr(dispatch, 'handle', fail)
    monkeypatch.setattr(sys, 'stdin', io.TextIOWrapper(io.BytesIO(json.dumps({'operation': operation}).encode())))
    dispatch.main()
    raw = capsys.readouterr().out
    assert 'secret' not in raw
    assert json.loads(raw)['status'] == status
    with pytest.raises(ValueError, match=f'{status}.*permission_denied.*no retry'):
        decode_response(raw, 0)


@pytest.mark.parametrize('payload', [None, [], {}, {'status': 'ok'}, {'status': 'ok', 'data': []}, {'status': 'secret'}])
def test_invalid_response_is_sanitized(payload):
    with pytest.raises(ValueError, match='response protocol failed; no retry'):
        decode_response(json.dumps(payload), 0)


@pytest.mark.parametrize('raw', [b'secret not JSON', b'\xff', b''])
def test_process_failure_precedes_json_parsing(raw):
    with pytest.raises(ValueError, match='SSH/helper process failed; no retry'):
        decode_response(raw, 126)
    with pytest.raises(ValueError, match='response protocol failed; no retry'):
        decode_response(raw, 0)


@pytest.mark.parametrize('code', [None, 'secret', [], {}])
def test_old_or_unrecognized_helper_diagnostic_is_not_echoed(code):
    with pytest.raises(ValueError, match=r'unsupported \(unspecified\); no retry'):
        decode_response(json.dumps({'status': 'unsupported', 'reason': 'secret', 'error_code': code}), 0)


def test_success():
    assert decode_response(b'{"status":"ok","data":{"state":{}}}', 0) == {'state': {}}


def test_built_helper_includes_diagnostics(tmp_path):
    root = Path(__file__).resolve().parents[1]
    helper = tmp_path / 'forward.pyz'
    subprocess.run([sys.executable, str(root / 'scripts/build_forward_helper.py'), str(helper)], check=True, capture_output=True)
    result = subprocess.run([sys.executable, '-I', str(helper)], input=b'{}', capture_output=True, check=True)
    payload = json.loads(result.stdout)
    assert payload['status'] == 'unsupported'
    assert payload['error_code'] == 'invalid_state_or_request'
    assert not result.stderr
