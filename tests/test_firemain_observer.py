import shutil
import subprocess
from pathlib import Path

import pytest


def test_observation_only_javascript_contract():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is needed only for the uninstalled FireMain observer prototype")
    script = Path(__file__).with_name("firemain_import_observer.test.cjs")
    result = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert "PASS:" in result.stdout
