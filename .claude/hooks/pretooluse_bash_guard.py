#!/usr/bin/env python3
"""
PreToolUse hook: Bash allowlist enforcement (schema-v2).

Replaces the v1 prefix-allowlist with a per-command argv validator dispatch.
Every allowed command has a schema entry; anything not matched is blocked.

Global pre-checks (before tokenisation):
  1. Forbidden-operator substring scan (;, &&, ||, |, &, `, $(, >, >>, <, \\n).
  2. Hard-deny substring scan (curl, wget, pip install, etc.).

Per-schema dispatch (after shlex tokenisation):
  - Read-only utilities (ls, cat, grep, rg, etc.) with blocked-flag lists.
  - find with no -exec/-fprint; -delete restricted to .claude/output/.
  - mkdir restricted to .claude/output/.
  - python dispatches to helper-script schemas (build_callgraph,
    baseline_sast, gemini_critique, preflight) plus -m pytest.
  - bash dispatches to docker_poc.sh with FINDING_ID regex.

See docs/DECISIONS.md D13.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path
from typing import Callable


FORBIDDEN_OPERATORS = [
    ";", "&&", "||", "|", "&", "`", "$(", "$'", "$", ">", ">>", "<", "\n",
]

HARD_DENY_SUBSTRINGS = [
    "curl", "wget", "nc ", "ncat", "netcat", "ssh ", "scp ", "rsync",
    "pip install", "pip3 install", "uv pip install", "npm install",
    "git push", "git commit", "git clone", "git fetch", "git pull",
    "rm -rf", "chmod 777", "sudo",
    "docker build", "docker run", "docker exec",
]

OUTPUT_ROOT = ".claude/output"
TESTS_ROOT = ".claude/tests"

FINDING_ID_RE = re.compile(r"^[A-Z]+-[A-Z]+-[0-9]{4}$")


def _resolves_under(path_str: str, root_str: str) -> bool:
    try:
        resolved = Path(path_str).resolve(strict=False)
        root = Path(root_str).resolve(strict=False)
        return resolved.is_relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False


def _allow_with_blocked_flags(blocked: list[str]) -> Callable[[list[str]], tuple[bool, str]]:
    """Build a validator that rejects a command if any token matches a blocked flag.

    Handles four spellings:
      - exact match:            `--output`
      - `--flag=VALUE`:         `--output=/tmp/x`
      - POSIX short concat:     `-oFILE`  (short flags only)
      - GNU prefix abbreviation: `--out`, `--outp`, ... (FND-INJ-0101)
        Any proper prefix of a blocked long flag binds to the blocked
        option under getopt_long's unambiguous-prefix rule. We treat
        every prefix of length >= 3 as equivalent to the full long flag.
        Prefixes of length 2 ('--') are excluded.
    """
    # Pre-compute long-flag prefix set once. Index by the bare flag name so
    # we can reconstruct a clear block reason.
    long_prefix_index: list[tuple[str, str]] = []  # (prefix, full_flag)
    for flag in blocked:
        if flag.startswith("--") and len(flag) > 2:
            # Enumerate every proper prefix of length >= 3 of the long flag.
            for n in range(3, len(flag)):
                long_prefix_index.append((flag[:n], flag))

    def _validator(tokens: list[str]) -> tuple[bool, str]:
        for flag in blocked:
            is_short = (
                len(flag) == 2
                and flag.startswith("-")
                and not flag.startswith("--")
            )
            for tok in tokens[1:]:
                # Exact match.
                if tok == flag:
                    return False, f"flag {flag!r} is blocked for {tokens[0]!r}"
                # `--flag=VALUE` long-option form. shlex keeps `--output=/path`
                # as a single token that does not equal `--output` (FND-INJ-0008,
                # FND-INJ-0011, FND-INJ-0013).
                if tok.startswith(flag + "="):
                    return False, (
                        f"flag {flag!r} (=VALUE form) is blocked for {tokens[0]!r}"
                    )
                # POSIX short-option concatenated-value form: `-oFILE` is
                # equivalent to `-o FILE`. shlex keeps it as one token. Only
                # apply to short flags (`-X`) — for long flags, `--xyzABC`
                # could be a different option entirely (FND-INJ-0014).
                if is_short and tok.startswith(flag) and len(tok) > 2:
                    return False, (
                        f"flag {flag!r} (concat-value form) is blocked for "
                        f"{tokens[0]!r}"
                    )
        # GNU long-option prefix abbreviation (FND-INJ-0101). Done as a
        # separate pass so the clearer specific-form messages above take
        # precedence when they match.
        for tok in tokens[1:]:
            # Strip `=VALUE` suffix for prefix comparison.
            bare = tok.split("=", 1)[0] if "=" in tok else tok
            for prefix, full in long_prefix_index:
                if bare == prefix:
                    return False, (
                        f"flag {bare!r} is a GNU prefix abbreviation of "
                        f"blocked flag {full!r} for {tokens[0]!r}"
                    )
        return True, ""
    return _validator


def _find_validator(tokens: list[str]) -> tuple[bool, str]:
    BLOCKED_FLAGS = {
        "-exec", "-execdir", "-ok", "-okdir",
        "-fprint", "-fprintf", "-fls",
        # Symlink-following flags. `-L` + a pre-staged traversal symlink
        # under .claude/output/ can escape OUTPUT_ROOT during `-delete`
        # (FND-PATH-0108). `-H` is narrower but has the same shape.
        "-L", "-H", "-follow",
    }
    has_delete = False
    paths: list[str] = []
    i = 1
    flags_taking_value = {
        "-maxdepth", "-mindepth", "-type", "-name", "-iname",
        "-path", "-ipath", "-regex", "-iregex",
    }
    while i < len(tokens):
        t = tokens[i]
        if t in BLOCKED_FLAGS:
            return False, f"find flag {t!r} is blocked"
        if t == "-delete":
            has_delete = True
            i += 1
            continue
        if t in flags_taking_value:
            i += 2  # consume value too
            continue
        if t.startswith("-") or t in {"-not", "-and", "-or", "!"}:
            i += 1
            continue
        # Positional — a path.
        paths.append(t)
        i += 1

    if has_delete:
        if not paths:
            return False, "find -delete with no positional path"
        for p in paths:
            if not _resolves_under(p, OUTPUT_ROOT):
                return False, (
                    f"find -delete path {p!r} does not resolve under {OUTPUT_ROOT!r}"
                )

    return True, ""


def _uniq_validator(tokens: list[str]) -> tuple[bool, str]:
    """FND-INJ-0102: uniq [OPTION]... [INPUT [OUTPUT]].

    The second positional is a write target. GNU uniq with two positionals
    writes its output to the second file, which is an arbitrary-write
    primitive. Allow at most one positional; callers must use `--output`
    explicitly (blocked elsewhere) or redirect with `>` (blocked by
    FORBIDDEN_OPERATORS) to get output anywhere other than stdout.
    """
    blocked = _allow_with_blocked_flags(["-o", "--output"])
    allow, reason = blocked(tokens)
    if not allow:
        return allow, reason
    # Count positionals (non-flag tokens after the command name).
    # GNU uniq flags that take a value: -f, --skip-fields, -s, --skip-chars,
    # -w, --check-chars, -D, --all-repeated (optional arg form).
    flags_taking_value = {"-f", "--skip-fields", "-s", "--skip-chars",
                          "-w", "--check-chars", "--group"}
    positionals: list[str] = []
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if t in flags_taking_value:
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        positionals.append(t)
        i += 1
    if len(positionals) > 1:
        return False, (
            f"uniq rejects second positional argument {positionals[1]!r} "
            f"(OUTPUT form is an arbitrary-write primitive; use stdout)"
        )
    return True, ""


def _mkdir_validator(tokens: list[str]) -> tuple[bool, str]:
    allowed_flags = {"-p", "--parents"}
    paths: list[str] = []
    for t in tokens[1:]:
        if t.startswith("-"):
            if t not in allowed_flags:
                return False, f"mkdir flag {t!r} not allowed"
            continue
        paths.append(t)
    if not paths:
        return False, "mkdir with no path"
    for p in paths:
        if not _resolves_under(p, OUTPUT_ROOT) and p != OUTPUT_ROOT:
            return False, f"mkdir path {p!r} not under {OUTPUT_ROOT!r}"
    return True, ""


def _bash_helper_validator(tokens: list[str]) -> tuple[bool, str]:
    """Only bash .claude/tools/docker_poc.sh <FINDING_ID>."""
    if len(tokens) < 2:
        return False, "bash with no script"
    script = tokens[1]
    if script != ".claude/tools/docker_poc.sh":
        return False, f"bash script {script!r} not allowed"
    if len(tokens) != 3:
        return False, "docker_poc.sh requires exactly one argument (FINDING_ID)"
    if not FINDING_ID_RE.match(tokens[2]):
        return False, (
            f"FINDING_ID {tokens[2]!r} does not match ^[A-Z]+-[A-Z]+-[0-9]{{4}}$"
        )
    return True, ""


def _pytest_validator(tokens_after_pytest: list[str]) -> tuple[bool, str]:
    ALLOWED_FLAGS_BOOL = {"-v", "-x", "-q", "--collect-only"}
    ALLOWED_FLAGS_VAL = {"-k", "--tb"}
    i = 0
    paths: list[str] = []
    while i < len(tokens_after_pytest):
        t = tokens_after_pytest[i]
        if t in ALLOWED_FLAGS_BOOL:
            i += 1
            continue
        if t.startswith("--tb="):
            i += 1
            continue
        if t in ALLOWED_FLAGS_VAL:
            i += 2
            continue
        if t.startswith("-"):
            return False, f"pytest flag {t!r} not allowed"
        paths.append(t)
        i += 1

    if not paths:
        return True, ""
    for p in paths:
        if not _resolves_under(p, TESTS_ROOT):
            return False, f"pytest path {p!r} not under {TESTS_ROOT!r}"
    return True, ""


def _baseline_sast_validator(tokens: list[str]) -> tuple[bool, str]:
    """baseline_sast.py <target_dir> [--output <path>]

    The guard validates that --output, if present, resolves under OUTPUT_ROOT.
    The tool's own argv validation is a second layer (defence in depth), but
    the guard must also block path-traversal attempts so that the hook layer
    alone is sufficient to stop the bypass.
    """
    i = 2  # tokens[0]=python, tokens[1]=script path
    while i < len(tokens):
        t = tokens[i]
        if t == "--output":
            if i + 1 >= len(tokens):
                return False, "baseline_sast.py --output requires a value"
            out_path = tokens[i + 1]
            if not _resolves_under(out_path, OUTPUT_ROOT):
                return False, (
                    f"baseline_sast.py --output path {out_path!r} does not "
                    f"resolve under {OUTPUT_ROOT!r}"
                )
            i += 2
            continue
        # `--output=VALUE` single-token form (FND-INJ-0012). shlex keeps the
        # concatenation as one token that never equals `--output`, so the
        # above branch misses it.
        if t.startswith("--output="):
            out_path = t[len("--output="):]
            if not _resolves_under(out_path, OUTPUT_ROOT):
                return False, (
                    f"baseline_sast.py --output path {out_path!r} does not "
                    f"resolve under {OUTPUT_ROOT!r}"
                )
            i += 1
            continue
        i += 1
    return True, ""


def _python_helper_validator(tokens: list[str]) -> tuple[bool, str]:
    if len(tokens) < 2:
        return False, "python with no script/module"

    if tokens[1] == "-m":
        if len(tokens) < 3:
            return False, "python -m with no module"
        if tokens[2] != "pytest":
            return False, f"python -m {tokens[2]!r}: only pytest allowed"
        return _pytest_validator(tokens[3:])

    script = tokens[1]
    if script == ".claude/tools/preflight.py":
        if len(tokens) != 2:
            return False, "preflight.py takes no arguments"
        return True, ""

    if script == ".claude/tools/baseline_sast.py":
        return _baseline_sast_validator(tokens)

    if script in {
        ".claude/tools/build_callgraph.py",
        ".claude/tools/gemini_critique.py",
        ".claude/tools/scope_resolve.py",
        ".claude/tools/scout_supply_chain_detect.py",
        ".claude/tools/scout_sqli_detect.py",
        ".claude/tools/scout_template_detect.py",
        ".claude/tools/scout_crypto_detect.py",
        ".claude/tools/scout_xxe_detect.py",
        ".claude/tools/scout_import_fallback_detect.py",
    }:
        # Argv is re-validated inside each tool; the guard only pins the
        # script path.
        return True, ""

    return False, f"python script {script!r} not in allowed helpers"


COMMAND_SCHEMAS: dict[str, Callable[[list[str]], tuple[bool, str]]] = {
    "rg":     _allow_with_blocked_flags(["--search-zip", "--pre"]),
    "grep":   _allow_with_blocked_flags([]),
    "ls":     _allow_with_blocked_flags([]),
    "cat":    _allow_with_blocked_flags([]),
    "head":   _allow_with_blocked_flags([]),
    "tail":   _allow_with_blocked_flags(["-F", "-f", "--follow"]),
    "wc":     _allow_with_blocked_flags([]),
    "sort":   _allow_with_blocked_flags(["-o", "--output", "--compress-program"]),
    "uniq":   _uniq_validator,
    "file":   _allow_with_blocked_flags([]),
    "stat":   _allow_with_blocked_flags([]),
    "pwd":    _allow_with_blocked_flags([]),
    "echo":   _allow_with_blocked_flags([]),
    "tree":   _allow_with_blocked_flags([]),
    "find":   _find_validator,
    "mkdir":  _mkdir_validator,
    "python": _python_helper_validator,
    "bash":   _bash_helper_validator,
}


def block(reason: str) -> None:
    print(f"BLOCKED by pretooluse_bash_guard: {reason}", file=sys.stderr)
    sys.exit(2)


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        block("hook received malformed JSON; failing closed")
        return

    if payload.get("tool_name", "") != "Bash":
        sys.exit(0)

    command = payload.get("tool_input", {}).get("command", "")
    if not command or not command.strip():
        block("empty bash command")

    for bad in HARD_DENY_SUBSTRINGS:
        if bad in command:
            block(f"command contains hard-deny substring: {bad!r}")

    for op in FORBIDDEN_OPERATORS:
        if op in command:
            block(
                f"command contains shell operator {op!r} which could chain "
                f"disallowed commands or redirect output"
            )

    try:
        tokens = shlex.split(command)
    except ValueError as e:
        block(f"could not tokenise command: {e}")
        return

    if not tokens:
        block("empty token list after shlex")

    cmd_name = tokens[0]
    validator = COMMAND_SCHEMAS.get(cmd_name)
    if validator is None:
        block(f"command {cmd_name!r} is not in the schema. Tokens: {tokens!r}")

    allow, reason = validator(tokens)
    if not allow:
        block(f"{cmd_name} rejected: {reason}. Tokens: {tokens!r}")

    sys.exit(0)


if __name__ == "__main__":
    main()
