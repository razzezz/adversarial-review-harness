#!/usr/bin/env python3
"""Resolve the effective scope for a /adversarial-review invocation.

Owns the two authoritative exclusion lists declared by the orchestrator's
scope policy (see docs/DECISIONS.md D15):

  - ALWAYS_EXCLUDE: never reviewable code (VCS metadata, caches, build
    artefacts, vendored deps). Applied regardless of target.
  - SELF_EXCLUDE:   harness-internal paths. Applied iff target resolves
    to cwd (i.e. user did not supply an explicit subpath).

Usage (CLI):
  python .claude/tools/scope_resolve.py <target>

Prints JSON on stdout:
  {"target_root": "<abs>", "excluded_subpaths": ["<rel>", ...]}

Exits 2 with a clear stderr message if <target> does not resolve under
the current working directory. The orchestrator treats a non-zero exit
as "refuse to start the review."
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ALWAYS_EXCLUDE: tuple[str, ...] = (
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "build",
    "dist",
    "node_modules",
)

SELF_EXCLUDE: tuple[str, ...] = (
    ".claude",
    "sandbox",
    "docs",
)


class ScopeError(ValueError):
    """Raised when a target cannot be resolved to an acceptable scope."""


def resolve_scope(target: str, cwd: Path) -> dict:
    """Resolve a user-supplied target string to a scope contract.

    Parameters
    ----------
    target
        The positional argument from the /adversarial-review invocation.
        Relative paths are resolved against `cwd`.
    cwd
        The working directory the orchestrator is running in. The resolved
        target must be contained under this path.

    Returns
    -------
    dict
        ``{"target_root": "<absolute path>", "excluded_subpaths": ["<rel>", ...]}``.
        ``excluded_subpaths`` is ``ALWAYS_EXCLUDE`` plus ``SELF_EXCLUDE`` iff
        the resolved target equals the resolved cwd.

    Raises
    ------
    ScopeError
        If the resolved target is not under `cwd`.
    """
    cwd_resolved = cwd.resolve()
    target_path = (cwd_resolved / target) if not Path(target).is_absolute() else Path(target)
    target_resolved = target_path.resolve()

    try:
        target_resolved.relative_to(cwd_resolved)
    except ValueError as e:
        raise ScopeError(
            f"target {target!r} resolves to {target_resolved} which is outside "
            f"cwd {cwd_resolved}"
        ) from e

    excludes: list[str] = list(ALWAYS_EXCLUDE)
    if target_resolved == cwd_resolved:
        excludes.extend(SELF_EXCLUDE)

    return {
        "target_root": str(target_resolved),
        "excluded_subpaths": excludes,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve /adversarial-review scope")
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target path; defaults to cwd when omitted",
    )
    args = parser.parse_args()

    try:
        result = resolve_scope(args.target, cwd=Path.cwd())
    except ScopeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
