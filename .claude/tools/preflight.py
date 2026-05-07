#!/usr/bin/env python3
"""Orchestrator preflight checks.

Replaces three Bash calls the orchestrator used to make inline
(echo "${GEMINI_API_KEY:0:6}", stat /usr/bin/docker, docker version). One tool
lets the bash_guard schema pin the check path to a single allowed pattern.

Usage: python .claude/tools/preflight.py

Exits 0 on all-green, 2 on any red. stdout has [OK] lines; stderr has [FAIL]
lines. Each check's result is one line.
"""

from __future__ import annotations

import os
import subprocess
import sys


def check_gemini_api_key() -> tuple[bool, str]:
    key = os.environ.get("GEMINI_API_KEY", "")
    if not key:
        return False, "GEMINI_API_KEY is not set"
    return True, f"GEMINI_API_KEY present (prefix: {key[:6]}...)"


def check_gemini_import() -> tuple[bool, str]:
    try:
        import google.generativeai  # noqa: F401
    except ImportError as exc:
        return False, f"google.generativeai not importable: {exc}"
    return True, "google.generativeai importable"


def check_docker() -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        return False, "docker binary not found on PATH"
    except subprocess.TimeoutExpired:
        return False, "docker version timed out (daemon unreachable?)"

    if proc.returncode != 0:
        stderr_head = proc.stderr.strip().splitlines()[:1]
        return False, f"docker version failed: {stderr_head}"
    return True, f"docker server version: {proc.stdout.strip()}"


def main() -> int:
    checks = [
        ("gemini_api_key", check_gemini_api_key),
        ("gemini_import", check_gemini_import),
        ("docker", check_docker),
    ]
    any_failed = False
    for name, fn in checks:
        ok, msg = fn()
        marker = "[OK]  " if ok else "[FAIL]"
        stream = sys.stdout if ok else sys.stderr
        print(f"{marker} {name}: {msg}", file=stream)
        if not ok:
            any_failed = True
    return 0 if not any_failed else 2


if __name__ == "__main__":
    sys.exit(main())
