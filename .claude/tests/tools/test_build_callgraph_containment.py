"""Containment + slim-defaults tests for build_callgraph.py.

Covers:
  - FND-PATH-0205: positional <target> must resolve under cwd, else exit 2.
  - The --exclude default list equals ALWAYS_EXCLUDE (no more 'tests'/'test').
  - Positive happy-path on a minimal fixture tree.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
BUILD_CALLGRAPH = REPO_ROOT / ".claude" / "tools" / "build_callgraph.py"
SCOPE_RESOLVE = REPO_ROOT / ".claude" / "tools" / "scope_resolve.py"


def _run(target: str, cwd: Path, extra: list[str] | None = None) -> subprocess.CompletedProcess:
    args = [sys.executable, str(BUILD_CALLGRAPH), target]
    if extra:
        args.extend(extra)
    return subprocess.run(
        args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize(
    "bad_target",
    ["/etc", "/tmp", "../outside"],
)
def test_out_of_cwd_target_refused(tmp_path, bad_target):
    # Build a minimal tree in cwd so the tool has something to otherwise analyse.
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("def f(): pass\n")
    proc = _run(bad_target, cwd=tmp_path)
    assert proc.returncode == 2, (
        f"out-of-cwd target accepted: stdout={proc.stdout} stderr={proc.stderr}"
    )
    assert "cwd" in proc.stderr.lower() or "outside" in proc.stderr.lower()


def test_happy_path_inside_cwd(tmp_path):
    # Minimal target tree.
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "mod.py").write_text(
        "def greet(name):\n    return f'hello {name}'\n"
    )
    output_dir = tmp_path / ".claude" / "output"
    output_dir.mkdir(parents=True)
    proc = _run(
        "src",
        cwd=tmp_path,
        extra=["--output", str(output_dir / "callgraph.json")],
    )
    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    data = json.loads((output_dir / "callgraph.json").read_text())
    assert data["statistics"]["module_count"] >= 1


def test_default_excludes_match_always_exclude():
    """The tool's default --exclude list must match scope_resolve.ALWAYS_EXCLUDE.

    Prevents a new tests/test back-slide or drift from the scope policy.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("scope_resolve", SCOPE_RESOLVE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Invoke with --help and parse the default; easier: import build_callgraph's
    # argparse and inspect. Since the tool uses `action=append, default=[...]`,
    # the default list is a Python literal we can read statically.
    text = BUILD_CALLGRAPH.read_text(encoding="utf-8")
    # Extract the default argument to --exclude by matching the literal list.
    # This is a drift check, not a parser; keep it mechanical.
    import re
    match = re.search(
        r"add_argument\(\s*['\"]--exclude['\"].*?default=\[([^\]]*)\]",
        text,
        re.DOTALL,
    )
    assert match, "could not locate --exclude default literal in build_callgraph.py"
    raw = match.group(1)
    items = {tok.strip().strip("'\"") for tok in raw.split(",") if tok.strip()}
    assert items == set(mod.ALWAYS_EXCLUDE), (
        f"build_callgraph default --exclude drifted from ALWAYS_EXCLUDE. "
        f"Tool has: {items}. Policy has: {set(mod.ALWAYS_EXCLUDE)}."
    )
