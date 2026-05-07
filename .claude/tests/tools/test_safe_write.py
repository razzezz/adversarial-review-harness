"""Regression tests for .claude/tools/_safe_write.py.

Covers the three primitives (safe_open_append, safe_write_text,
safe_mkdir_p) against:
  - Happy path: write creates ancestors + leaf with expected content.
  - Ancestor-symlink refusal: any symlink in the parent chain triggers
    OSError with errno=ELOOP; nothing written to the attacker-controlled
    target (FND-PATH-0301 / 0302 shared root cause).
  - Leaf-symlink refusal: the final path component is a pre-existing
    symlink; refused.
  - safe_mkdir_p idempotency: second call against an existing dir is a
    no-op and does not raise.
"""

from __future__ import annotations

import errno
import importlib.util
import os
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SAFE_WRITE = REPO_ROOT / ".claude" / "tools" / "_safe_write.py"


def _load():
    spec = importlib.util.spec_from_file_location("_safe_write", SAFE_WRITE)
    assert spec and spec.loader, f"cannot load {SAFE_WRITE}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Happy paths.
# ---------------------------------------------------------------------------


def test_safe_mkdir_p_creates_nested(tmp_path):
    mod = _load()
    target = tmp_path / "a" / "b" / "c"
    mod.safe_mkdir_p(target)
    assert target.is_dir()


def test_safe_mkdir_p_idempotent(tmp_path):
    mod = _load()
    target = tmp_path / "existing"
    target.mkdir()
    # Second call must not raise.
    mod.safe_mkdir_p(target)
    assert target.is_dir()


def test_safe_write_text_creates_file_with_content(tmp_path):
    mod = _load()
    mod.safe_mkdir_p(tmp_path / "sub")
    target = tmp_path / "sub" / "out.txt"
    mod.safe_write_text(target, "hello slice-5")
    assert target.read_text() == "hello slice-5"


def test_safe_open_append_appends(tmp_path):
    mod = _load()
    target = tmp_path / "audit.jsonl"
    fd = mod.safe_open_append(target)
    try:
        os.write(fd, b'{"line": 1}\n')
    finally:
        os.close(fd)
    fd2 = mod.safe_open_append(target)
    try:
        os.write(fd2, b'{"line": 2}\n')
    finally:
        os.close(fd2)
    assert target.read_text() == '{"line": 1}\n{"line": 2}\n'


# ---------------------------------------------------------------------------
# Ancestor-symlink refusal.
# ---------------------------------------------------------------------------


# Either errno is a valid symlink-refusal signal from openat(O_NOFOLLOW|O_DIRECTORY):
# - ELOOP:   kernel explicitly rejected following a symlink
# - ENOTDIR: kernel opened the symlink inode (O_NOFOLLOW) but O_DIRECTORY rejected
#            it because a symlink is not a directory. Structurally equivalent refusal.
_SYMLINK_REFUSED_ERRNOS = (errno.ELOOP, errno.ENOTDIR)


def test_safe_write_text_refuses_ancestor_symlink(tmp_path):
    """Pre-stage tmp_path/output as a symlink to /tmp/attacker; attempt
    to write under it; assert OSError and no write lands."""
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    try:
        (tmp_path / "output").symlink_to(attacker)
    except OSError:
        pytest.skip("cannot create symlink in this environment")

    mod = _load()
    target = tmp_path / "output" / "file.txt"
    with pytest.raises(OSError) as exc:
        mod.safe_write_text(target, "pwned")
    assert exc.value.errno in _SYMLINK_REFUSED_ERRNOS, (
        f"expected symlink refusal (ELOOP or ENOTDIR), got errno={exc.value.errno}"
    )
    assert not list(attacker.iterdir()), (
        f"write leaked into attacker dir: {list(attacker.iterdir())}"
    )


def test_safe_mkdir_p_refuses_ancestor_symlink(tmp_path):
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    try:
        (tmp_path / "a").symlink_to(attacker)
    except OSError:
        pytest.skip("cannot create symlink in this environment")

    mod = _load()
    with pytest.raises(OSError) as exc:
        mod.safe_mkdir_p(tmp_path / "a" / "b" / "c")
    assert exc.value.errno in _SYMLINK_REFUSED_ERRNOS


def test_safe_open_append_refuses_ancestor_symlink(tmp_path):
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    try:
        (tmp_path / "d").symlink_to(attacker)
    except OSError:
        pytest.skip("cannot create symlink in this environment")

    mod = _load()
    with pytest.raises(OSError) as exc:
        mod.safe_open_append(tmp_path / "d" / "audit.jsonl")
    assert exc.value.errno in _SYMLINK_REFUSED_ERRNOS


# ---------------------------------------------------------------------------
# Leaf-symlink refusal.
# ---------------------------------------------------------------------------


def test_safe_write_text_refuses_leaf_symlink(tmp_path):
    attacker = tmp_path / "victim"
    attacker.write_text("untouched")
    link = tmp_path / "file.txt"
    try:
        link.symlink_to(attacker)
    except OSError:
        pytest.skip("cannot create symlink in this environment")

    mod = _load()
    with pytest.raises(OSError):
        mod.safe_write_text(link, "pwned")
    # Verify the victim wasn't overwritten.
    assert attacker.read_text() == "untouched"


def test_safe_open_append_refuses_leaf_symlink(tmp_path):
    attacker = tmp_path / "victim"
    attacker.write_text("untouched")
    link = tmp_path / "audit.jsonl"
    try:
        link.symlink_to(attacker)
    except OSError:
        pytest.skip("cannot create symlink in this environment")

    mod = _load()
    with pytest.raises(OSError):
        mod.safe_open_append(link)
    assert attacker.read_text() == "untouched"
