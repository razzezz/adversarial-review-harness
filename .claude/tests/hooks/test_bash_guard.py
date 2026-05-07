"""Regression tests for pretooluse_bash_guard.

The _BYPASS_CASES list documents the 7 known bypasses from the 2026-04-23
/adversarial-review run. Each case currently FAILS (exit 0 instead of 2) on
the v1 guard and documents the motivation for the v2 rewrite (D13). After
Task 10 of the 2026-04-23 slice lands v2, every case must pass (exit 2).
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Happy path — must pass both v1 and v2.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        "ls -la .claude/tools/",
        "wc -l .claude/output/audit.jsonl",
        "cat docs/DECISIONS.md",
        "head -n 20 docs/DESIGN.md",
        "tail -n 5 .claude/output/audit.jsonl",
        "grep -c error .claude/output/audit.jsonl",
        "grep -H pattern docs/TODO.md",
        "rg definition .claude/",
        "mkdir -p .claude/output",
        "stat .claude/hooks/pretooluse_bash_guard.py",
        "python .claude/tools/gemini_critique.py --finding-file .claude/output/tmp_FND-X.json",
        "bash .claude/tools/docker_poc.sh FND-DESER-0001",
        "python .claude/tools/build_callgraph.py .",
        # Slice-4 companion: uniq with ONE positional must still be allowed.
        "uniq .claude/output/audit.jsonl",
        # Slice-4: scope_resolve.py invoked by the orchestrator in "Before you start".
        "python .claude/tools/scope_resolve.py .",
        "python .claude/tools/scope_resolve.py sandbox/toy_vulnerable_app/",
        "python .claude/tools/scope_resolve.py .claude/",
        # Slice-5: scout-supply-chain detector helper.
        "python .claude/tools/scout_supply_chain_detect.py sandbox/toy_vulnerable_app",
        # Slice-6: scout-sqli detector helper.
        "python .claude/tools/scout_sqli_detect.py sandbox/toy_vulnerable_app",
        # Slice-6: scout-template detector helper.
        "python .claude/tools/scout_template_detect.py sandbox/toy_vulnerable_app",
    ],
)
def test_allowed_commands(run_bash_guard, cmd):
    result = run_bash_guard(cmd)
    assert result.exit_code == 0, f"unexpectedly blocked: {cmd!r}\n{result.stderr}"


# ---------------------------------------------------------------------------
# Known bypasses — fail against v1, pass against v2.
# ---------------------------------------------------------------------------


_BYPASS_CASES = [
    # Round 1 (2026-04-23, closed by bash_guard v2).
    pytest.param("find . -maxdepth 0 -exec touch /tmp/pwn {} +",     id="find-exec"),
    pytest.param("awk 'BEGIN{system(\"touch /tmp/pwn\")}'",           id="awk-system"),
    pytest.param("sed -n '1e touch /tmp/pwn' /etc/hostname",          id="sed-e-command"),
    pytest.param("echo ok & awk 'BEGIN{system(\"touch /tmp/pwn\")}'", id="ampersand-background"),
    pytest.param("python .claude/tools/baseline_sast.py /etc --output /tmp/out.json",
                 id="baseline-sast-traversal"),
    pytest.param("python -c 'import os; os.system(\"touch /tmp/pwn\")'",
                 id="python-dash-c"),
    pytest.param("bash .claude/tools/docker_poc.sh ../../../../etc/passwd",
                 id="docker-poc-finding-id-traversal"),
    # Round 2 (2026-04-23 re-run, closed by round-2 guard hardening).
    # FND-INJ-0008 (crit): rg --pre=<path> is the ripgrep preprocessor RCE.
    # Equality check missed the `--flag=value` form; now prefix-matched.
    pytest.param("rg --pre=/usr/bin/python3 needle .claude/output/",
                 id="rg-pre-equals-bypass"),
    # FND-INJ-0011: sort --output=<path> / uniq --output=<path> both wrote arbitrary files.
    pytest.param("sort --output=/tmp/pwn .claude/output/audit.jsonl",
                 id="sort-output-equals-bypass"),
    pytest.param("uniq --output=/tmp/pwn .claude/output/audit.jsonl",
                 id="uniq-output-equals-bypass"),
    # FND-INJ-0013: tail -f (lowercase) and tail --follow=<mode> were not blocked.
    pytest.param("tail -f /tmp/log",                                 id="tail-dash-f"),
    pytest.param("tail --follow=name /tmp/log",                      id="tail-follow-equals"),
    # FND-INJ-0012: baseline_sast.py --output=<path> form bypassed the
    # guard-layer containment check (defence-in-depth invariant).
    pytest.param(
        "python .claude/tools/baseline_sast.py sandbox --output=/tmp/out.json",
        id="baseline-sast-output-equals",
    ),
    # FND-INJ-0009 (crit): ANSI-C quoted string re-expands to shell operators
    # at exec time. `cat $'\\x3bwhoami'` decodes at runtime to `cat ;whoami`.
    pytest.param("cat $'\\x3bwhoami'",                               id="ansi-c-escape-semicolon"),
    # Round 3 (post-round-2 review, closed by round-3 hardening).
    # FND-INJ-0014 (crit): POSIX short-flag concat `-oFILE` bypassed the
    # equality + `=VALUE` checks.
    pytest.param("sort -o/tmp/pwn .claude/output/audit.jsonl",
                 id="sort-short-flag-concat"),
    pytest.param("uniq -o/tmp/pwn .claude/output/audit.jsonl",
                 id="uniq-short-flag-concat"),
    # FND-INJ-0017: bare `$` parameter expansion (`cat $FOO`) is now rejected
    # because `$` is in FORBIDDEN_OPERATORS.
    pytest.param("cat $FOO",                                         id="bare-dollar-expansion"),
    # FND-PATH-0108: `find -L` (follow symlinks) is rejected — a traversal
    # symlink under .claude/output could escape OUTPUT_ROOT during -delete.
    pytest.param("find -L .claude/output -name tmp.json -delete",
                 id="find-dash-capital-L"),
    pytest.param("find -H .claude/output -name tmp.json",            id="find-dash-capital-H"),
    pytest.param("find .claude/output -follow -name tmp.json",       id="find-follow"),
    # Slice-4 (2026-04-23) residuals — closed by the T12 slice.
    # FND-INJ-0100 (high): sort --compress-program=PATH executes arbitrary binary.
    pytest.param("sort --compress-program=/usr/bin/false input.txt",
                 id="sort-compress-program-equals"),
    pytest.param("sort --compress-program /usr/bin/false input.txt",
                 id="sort-compress-program-space"),
    # FND-INJ-0101 (high): GNU long-option prefix abbreviation.
    # `--compress-p=X`, `--compress=X`, `--comp=X` all bind to --compress-program
    # under getopt_long's prefix-abbreviation rule and must be blocked.
    pytest.param("sort --compress-p=/usr/bin/false input.txt",
                 id="sort-compress-abbrev-long"),
    pytest.param("sort --compress=/usr/bin/false input.txt",
                 id="sort-compress-abbrev-medium"),
    pytest.param("sort --comp=/usr/bin/false input.txt",
                 id="sort-compress-abbrev-short"),
    # And the same prefix-abbreviation rule must apply to every blocked long flag
    # on every command — not just sort.
    pytest.param("sort --out=/tmp/pwn input.txt",
                 id="sort-output-abbrev"),
    pytest.param("rg --p=/usr/bin/python3 needle .claude/output/",
                 id="rg-pre-abbrev"),
    pytest.param("tail --fol=name /tmp/log",
                 id="tail-follow-abbrev"),
    # FND-INJ-0102 (high): uniq [INPUT [OUTPUT]] — second positional is a write target.
    pytest.param("uniq .claude/output/audit.jsonl /tmp/pwn",
                 id="uniq-second-positional-output"),
]


@pytest.mark.parametrize("cmd", _BYPASS_CASES)
def test_known_bypass_blocked(run_bash_guard, cmd):
    """After v2 lands, every known bypass must block (exit 2)."""
    result = run_bash_guard(cmd)
    assert result.exit_code == 2, (
        f"bypass NOT blocked by current guard: {cmd!r}\n"
        f"stderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# Hard-deny — both v1 and v2.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        "curl http://example.com/",
        "wget http://example.com/",
        "pip install requests",
        "git push origin master",
        "git commit -m 'x'",
        "rm -rf /tmp",
        "sudo ls",
        "docker build -t x .",
    ],
)
def test_hard_deny(run_bash_guard, cmd):
    result = run_bash_guard(cmd)
    assert result.exit_code == 2, f"hard-deny failed to block: {cmd!r}\n{result.stderr}"


# ---------------------------------------------------------------------------
# Edge cases.
# ---------------------------------------------------------------------------


def test_empty_command_blocked(run_bash_guard):
    result = run_bash_guard("")
    assert result.exit_code == 2, f"empty command not blocked; stderr: {result.stderr}"


def test_whitespace_only_blocked(run_bash_guard):
    result = run_bash_guard("   \t  ")
    assert result.exit_code == 2, f"whitespace-only not blocked; stderr: {result.stderr}"


def test_unknown_command_blocked(run_bash_guard):
    result = run_bash_guard("xyzzy_nonexistent --flag")
    assert result.exit_code == 2, f"unknown command not blocked; stderr: {result.stderr}"
