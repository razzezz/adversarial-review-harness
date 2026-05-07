"""Regression test for posttooluse_audit.py FND-PATH-0204.

The audit hook uses os.open(..., O_NOFOLLOW) on the final path component
but allows ancestor symlinks to silently redirect the log. The fix walks
the path ancestors and refuses (logs to stderr, exits 0) if any ancestor
is a symlink.

Posture: the audit hook MUST NOT break the run. On refusal it logs a
warning and exits 0. The attack is "audit log redirected"; the defence
is "audit log not written"; the contract is "run continues."
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
AUDIT_HOOK = REPO_ROOT / ".claude" / "hooks" / "posttooluse_audit.py"


def _invoke(cwd: Path) -> subprocess.CompletedProcess:
    """Invoke the audit hook against the supplied cwd with a minimal payload."""
    payload = {
        "tool_name": "Read",
        "tool_input": {"file_path": "some/file.py"},
        "tool_response": "content",
    }
    env = os.environ.copy()
    env.pop("HARNESS_DEV_MODE", None)
    return subprocess.run(
        [sys.executable, str(AUDIT_HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=5,
        cwd=str(cwd),
        env=env,
    )


def test_audit_refuses_ancestor_symlink(tmp_path):
    """FND-PATH-0204: an ancestor-symlink in AUDIT_LOG's path must be refused.

    Set up cwd/.claude/ with output/ as a symlink to a pre-staged attacker
    dir. Expect the hook to NOT write into the attacker dir, and still
    exit 0 (never break the run).
    """
    (tmp_path / ".claude").mkdir()
    attacker_dir = tmp_path / "attacker"
    attacker_dir.mkdir()
    try:
        (tmp_path / ".claude" / "output").symlink_to(attacker_dir)
    except OSError:
        pytest.skip("cannot create symlink in this environment")

    proc = _invoke(cwd=tmp_path)
    assert proc.returncode == 0, (
        f"audit hook broke the run on refusal: stderr={proc.stderr}"
    )
    # The attacker dir must not have received an audit write.
    assert not list(attacker_dir.glob("audit.jsonl")), (
        f"audit log written into attacker dir: "
        f"{list(attacker_dir.glob('*'))}"
    )
    # A refusal notice on stderr is expected.
    assert "symlink" in proc.stderr.lower() or "refus" in proc.stderr.lower(), (
        f"no refusal notice on stderr: {proc.stderr!r}"
    )


def test_audit_normal_write_still_works(tmp_path):
    """Companion: a clean cwd with no symlinks produces the audit log normally."""
    (tmp_path / ".claude" / "output").mkdir(parents=True)
    proc = _invoke(cwd=tmp_path)
    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    audit = tmp_path / ".claude" / "output" / "audit.jsonl"
    assert audit.exists(), "audit log was not written on the clean path"
    entry = json.loads(audit.read_text().splitlines()[-1])
    assert entry["tool_name"] == "Read"
