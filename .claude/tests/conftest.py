"""Shared pytest fixtures for hook regression tests.

Each hook is invoked as a subprocess with a JSON payload on stdin, mirroring
the Claude Code PreToolUse contract. Fixtures return (exit_code, stderr_text).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BASH_GUARD = REPO_ROOT / ".claude" / "hooks" / "pretooluse_bash_guard.py"
FILE_GUARD = REPO_ROOT / ".claude" / "hooks" / "pretooluse_file_guard.py"


@dataclass(frozen=True)
class GuardResult:
    exit_code: int
    stderr: str


def _run_guard(script: Path, payload: dict) -> GuardResult:
    # Default to STRICT mode for tests. HARNESS_DEV_MODE loosens the
    # hook/tool/settings write-block; we must not let it leak into the
    # subprocess env or tests that target strict behaviour (FND-PATH-0009,
    # FND-INJ-0010) would silently pass in dev-mode sessions.
    env = os.environ.copy()
    env.pop("HARNESS_DEV_MODE", None)
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        cwd=str(REPO_ROOT),
        env=env,
    )
    return GuardResult(exit_code=proc.returncode, stderr=proc.stderr)


@pytest.fixture
def run_bash_guard():
    def _run(command: str) -> GuardResult:
        return _run_guard(
            BASH_GUARD,
            {"tool_name": "Bash", "tool_input": {"command": command}},
        )
    return _run


@pytest.fixture
def run_file_guard():
    def _run(tool_name: str, file_path: str) -> GuardResult:
        return _run_guard(
            FILE_GUARD,
            {"tool_name": tool_name, "tool_input": {"file_path": file_path}},
        )
    return _run
