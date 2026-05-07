"""Regression tests for .claude/tools/scope_resolve.py.

Covers: authoritative list declaration, target resolution, containment
refusal, SELF_EXCLUDE application rule (iff target resolves to cwd), and
the drift check against the orchestrator's prose documentation.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SCOPE_RESOLVE = REPO_ROOT / ".claude" / "tools" / "scope_resolve.py"
ORCHESTRATOR_MD = REPO_ROOT / ".claude" / "commands" / "adversarial-review.md"


def _load_scope_resolve():
    """Import scope_resolve.py directly by file path."""
    spec = importlib.util.spec_from_file_location("scope_resolve", SCOPE_RESOLVE)
    assert spec and spec.loader, f"cannot load {SCOPE_RESOLVE}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Module-level constants.
# ---------------------------------------------------------------------------


def test_always_exclude_constants_declared():
    mod = _load_scope_resolve()
    assert isinstance(mod.ALWAYS_EXCLUDE, tuple)
    assert ".git" in mod.ALWAYS_EXCLUDE
    assert "__pycache__" in mod.ALWAYS_EXCLUDE
    assert ".venv" in mod.ALWAYS_EXCLUDE
    assert "node_modules" in mod.ALWAYS_EXCLUDE


def test_self_exclude_constants_declared():
    mod = _load_scope_resolve()
    assert isinstance(mod.SELF_EXCLUDE, tuple)
    assert ".claude" in mod.SELF_EXCLUDE
    assert "sandbox" in mod.SELF_EXCLUDE
    assert "docs" in mod.SELF_EXCLUDE


# ---------------------------------------------------------------------------
# resolve_scope() — SELF_EXCLUDE application.
# ---------------------------------------------------------------------------


def test_resolve_scope_default_target_applies_self_exclude(tmp_path):
    mod = _load_scope_resolve()
    result = mod.resolve_scope(".", cwd=tmp_path)
    assert result["target_root"] == str(tmp_path.resolve())
    for item in mod.SELF_EXCLUDE:
        assert item in result["excluded_subpaths"]
    for item in mod.ALWAYS_EXCLUDE:
        assert item in result["excluded_subpaths"]


def test_resolve_scope_explicit_cwd_still_applies_self_exclude(tmp_path):
    mod = _load_scope_resolve()
    # Explicit `.` and default `.` are treated identically.
    result = mod.resolve_scope(str(tmp_path), cwd=tmp_path)
    for item in mod.SELF_EXCLUDE:
        assert item in result["excluded_subpaths"]


def test_resolve_scope_explicit_subdir_skips_self_exclude(tmp_path):
    mod = _load_scope_resolve()
    subdir = tmp_path / "sandbox" / "toy"
    subdir.mkdir(parents=True)
    result = mod.resolve_scope(str(subdir), cwd=tmp_path)
    assert result["target_root"] == str(subdir.resolve())
    for item in mod.SELF_EXCLUDE:
        assert item not in result["excluded_subpaths"]
    for item in mod.ALWAYS_EXCLUDE:
        assert item in result["excluded_subpaths"]


def test_resolve_scope_dot_claude_target_skips_self_exclude(tmp_path):
    mod = _load_scope_resolve()
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    result = mod.resolve_scope(str(claude_dir), cwd=tmp_path)
    assert result["target_root"] == str(claude_dir.resolve())
    # Explicit .claude target: user opted into self-review, no self-exclusion.
    assert ".claude" not in result["excluded_subpaths"]


# ---------------------------------------------------------------------------
# Containment.
# ---------------------------------------------------------------------------


def test_resolve_scope_refuses_target_outside_cwd(tmp_path):
    mod = _load_scope_resolve()
    outside = tmp_path.parent / "not_in_cwd"
    with pytest.raises(mod.ScopeError, match="outside"):
        mod.resolve_scope(str(outside), cwd=tmp_path)


def test_resolve_scope_refuses_absolute_system_path(tmp_path):
    mod = _load_scope_resolve()
    with pytest.raises(mod.ScopeError, match="outside"):
        mod.resolve_scope("/etc", cwd=tmp_path)


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def test_cli_prints_json_to_stdout(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / "sandbox").mkdir()
    proc = subprocess.run(
        [sys.executable, str(SCOPE_RESOLVE), "."],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    data = json.loads(proc.stdout)
    assert "target_root" in data
    assert "excluded_subpaths" in data
    assert ".claude" in data["excluded_subpaths"]


def test_cli_refuses_out_of_cwd_target(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(SCOPE_RESOLVE), "/etc"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert proc.returncode == 2, f"should reject: stdout={proc.stdout} stderr={proc.stderr}"


# ---------------------------------------------------------------------------
# Drift check: orchestrator prose must match module constants.
# ---------------------------------------------------------------------------


def _extract_list_from_markdown(md_text: str, list_name: str) -> set[str]:
    """Extract the bracket-style list declaration for ALWAYS_EXCLUDE or SELF_EXCLUDE.

    The orchestrator declares them in a fenced code block:

        ALWAYS_EXCLUDE  = [.git, __pycache__, .venv, ...]
        SELF_EXCLUDE    = [.claude, sandbox, docs]
    """
    # Match the assignment and capture the bracket contents across newlines.
    pattern = re.compile(
        rf"{list_name}\s*=\s*\[([^\]]+)\]",
        re.DOTALL,
    )
    m = pattern.search(md_text)
    assert m, f"{list_name} assignment not found in orchestrator prose"
    items = [tok.strip().strip(",") for tok in m.group(1).split()]
    return {tok for tok in items if tok and tok != ","}


def test_drift_check_always_exclude():
    mod = _load_scope_resolve()
    text = ORCHESTRATOR_MD.read_text(encoding="utf-8")
    md_items = _extract_list_from_markdown(text, "ALWAYS_EXCLUDE")
    code_items = set(mod.ALWAYS_EXCLUDE)
    assert md_items == code_items, (
        f"ALWAYS_EXCLUDE drift: orchestrator prose has {md_items - code_items}, "
        f"code has {code_items - md_items}"
    )


def test_drift_check_self_exclude():
    mod = _load_scope_resolve()
    text = ORCHESTRATOR_MD.read_text(encoding="utf-8")
    md_items = _extract_list_from_markdown(text, "SELF_EXCLUDE")
    code_items = set(mod.SELF_EXCLUDE)
    assert md_items == code_items, (
        f"SELF_EXCLUDE drift: orchestrator prose has {md_items - code_items}, "
        f"code has {code_items - md_items}"
    )
