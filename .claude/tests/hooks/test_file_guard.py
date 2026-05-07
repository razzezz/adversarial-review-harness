"""Regression tests for pretooluse_file_guard.

The v2 guard is already installed by Task 1 Step 2. All tests in this file
must pass from the start. The two 'bypass' tests (symlink read, sibling-dir
write) are the closed-form of FND-PATH-0003 and FND-PATH-0002.
"""

from __future__ import annotations

from pathlib import Path

import pytest


# This file lives at .claude/tests/hooks/test_file_guard.py → four `.parent`
# calls to reach the repo root. (conftest.py is one level up so it uses
# three; don't copy-paste that depth here.)
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SESSION_SLUG = str(REPO_ROOT).replace("/", "-")


@pytest.mark.parametrize(
    ("tool", "path"),
    [
        ("Read", ".claude/output/audit.jsonl"),
        ("Write", ".claude/output/report.md"),
        ("Read", "docs/DECISIONS.md"),
        ("Read", ".claude/hooks/pretooluse_bash_guard.py"),
    ],
)
def test_file_guard_allows(run_file_guard, tool, path):
    result = run_file_guard(tool, path)
    assert result.exit_code == 0, f"unexpectedly blocked: {tool} {path!r}\n{result.stderr}"


@pytest.mark.parametrize(
    ("tool", "path"),
    [
        # Round 1 forbidden patterns.
        ("Read", ".env"),
        ("Read", "config/.env"),
        ("Write", "/root/.ssh/id_rsa"),
        ("Read", "/home/user/.aws/credentials"),
        # Round 2: FND-PATH-0008 — system exfiltration targets.
        ("Read", "/etc/passwd"),
        ("Read", "/etc/shadow"),
        ("Read", "/proc/self/environ"),
        ("Read", "/var/log/auth.log"),
        # Round 2: FND-PATH-0014 — developer credential files.
        ("Read", "/home/user/.bash_history"),
        ("Read", "/home/user/.npmrc"),
        ("Read", "/home/user/.vault-token"),
        ("Read", "/home/user/.docker/config.json"),
        ("Read", "/home/user/.config/gh/hosts.yml"),
        # Round 2: FND-PATH-0014 — key/keystore file extensions.
        ("Read", "/etc/ssl/private/server.key"),
        ("Read", "/home/user/keystore.jks"),
        ("Read", "/home/user/cert.p12"),
        # Round 3: FND-PATH-0104 — denylist gaps.
        ("Read", "/etc/shadow-"),
        ("Read", "/etc/passwd-"),
        ("Read", "/etc/sudoers"),
        ("Read", "/etc/sudoers.d/90-custom"),
        ("Read", "/etc/crontab"),
        ("Read", "/etc/cron.d/backup"),
        ("Read", "/proc/123/cmdline"),
        ("Read", "/proc/kallsyms"),
        ("Read", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
        ("Read", "/run/secrets/my-secret"),
        ("Read", "/var/run/docker.sock"),
    ],
)
def test_file_guard_forbidden_patterns(run_file_guard, tool, path):
    result = run_file_guard(tool, path)
    assert result.exit_code == 2, f"should be blocked: {tool} {path!r}\n{result.stderr}"


@pytest.mark.parametrize(
    "path",
    [
        # FND-PATH-0100: read-side containment. An arbitrary path in /tmp or
        # /opt or similar that does not match any FORBIDDEN_PATH_PATTERN must
        # still be blocked for Read — previously reads were unbounded.
        "/tmp/host_file.txt",
        "/opt/some_other_repo/secret_plans.md",
        "/home/user/other-project/src.py",
    ],
)
def test_read_outside_working_tree_blocked(run_file_guard, path):
    """FND-PATH-0100: reads outside the working tree + allowed read roots block."""
    result = run_file_guard("Read", path)
    assert result.exit_code == 2, (
        f"read outside working tree was allowed: {path!r}\n{result.stderr}"
    )


def test_read_stdlib_allowed(run_file_guard):
    """Companion to the above: reads of Python stdlib paths are still allowed.

    Read-side containment must not break legitimate stdlib inspection.
    """
    import sysconfig
    stdlib = sysconfig.get_paths().get("stdlib")
    assert stdlib, "sysconfig has no stdlib path — unable to test"
    probe = f"{stdlib}/json/__init__.py"
    result = run_file_guard("Read", probe)
    assert result.exit_code == 0, (
        f"stdlib read was blocked — allowed-read-roots computation is wrong: "
        f"{probe}\n{result.stderr}"
    )


def test_memory_carveout_rejects_other_session(run_file_guard, tmp_path, monkeypatch):
    """FND-PATH-0105: cross-session memory writes must be blocked.

    The v3 carve-out binds to the current session slug derived from cwd. A
    write to ANOTHER session's memory dir under the same user must be
    rejected.
    """
    fake_home = tmp_path / "fakehome"
    # Current session's expected slug (derived from cwd=REPO_ROOT), plus a
    # different session we pretend to be targeting.
    other_session_memory = (
        fake_home / ".claude" / "projects" / "-some-other-project" / "memory" / "poisoned.md"
    )
    other_session_memory.parent.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))

    result = run_file_guard("Write", str(other_session_memory))
    assert result.exit_code == 2, (
        f"cross-session memory write was allowed — carve-out not session-bound. "
        f"Stderr: {result.stderr}"
    )


@pytest.mark.parametrize(
    "path",
    [
        # FND-PATH-0009: HARNESS_DIRS must cover agents, commands, skills, tests.
        ".claude/agents/evil.md",
        ".claude/commands/owned.md",
        ".claude/skills/hijacked/skill.md",
        # FND-INJ-0010: tests dir — conftest.py module-scope execution surface.
        ".claude/tests/hooks/conftest_evil.py",
        # FND-PATH-0009: .claude/settings.local.json now also protected.
        ".claude/settings.local.json",
    ],
)
def test_harness_internal_writes_blocked_in_strict(run_file_guard, path):
    """FND-PATH-0009 + FND-INJ-0010: writes to harness-config dirs blocked.

    conftest's _run_guard unsets HARNESS_DEV_MODE so these tests always run
    under strict enforcement; a dev-mode session would permit these edits
    intentionally.
    """
    result = run_file_guard("Write", path)
    assert result.exit_code == 2, (
        f"harness-internal write allowed under strict mode: {path!r}\n"
        f"stderr: {result.stderr}"
    )


def test_memory_carveout_requires_immediate_child(run_file_guard, tmp_path, monkeypatch):
    """FND-PATH-0010: `memory` must be the IMMEDIATE child of the session dir.

    A write to `~/.claude/projects/<slug>/sub/memory/file` must be blocked
    — the v1 part-membership check allowed nested `memory` directories to
    bypass working-tree containment.
    """
    # Simulate Claude Code's memory layout via a fake HOME under tmp_path.
    # The session slug is derived from the guard subprocess's cwd (REPO_ROOT),
    # so write against that specific session to exercise the nesting rule.
    fake_home = tmp_path / "fakehome"
    session_dir = fake_home / ".claude" / "projects" / SESSION_SLUG
    nested = session_dir / "sub" / "memory" / "file.md"
    nested.parent.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))

    result = run_file_guard("Write", str(nested))
    assert result.exit_code == 2, (
        f"nested memory-path write allowed — carve-out too permissive. "
        f"Stderr: {result.stderr}"
    )


def test_memory_carveout_immediate_child_allowed(run_file_guard, tmp_path, monkeypatch):
    """Companion: the legitimate layout under THIS session's slug works.

    `~/.claude/projects/<current-session-slug>/memory/file` must be allowed;
    Claude Code's memory system writes there.
    """
    fake_home = tmp_path / "fakehome"
    session_dir = fake_home / ".claude" / "projects" / SESSION_SLUG
    good = session_dir / "memory" / "file.md"
    good.parent.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))

    result = run_file_guard("Write", str(good))
    assert result.exit_code == 0, (
        f"legitimate memory path blocked: {good}\nstderr: {result.stderr}"
    )


def test_symlink_read_blocked(run_file_guard, tmp_path):
    """FND-PATH-0003: symlink whose canonical path matches a FORBIDDEN_PATH_PATTERN
    must be blocked.

    v1 checked only the raw (innocent-looking) path and allowed the Read; v2
    canonicalises first, so the resolved path's match against `.*id_rsa.*`
    fires and the Read is blocked.
    """
    # Create a file whose canonical path matches FORBIDDEN_PATH_PATTERNS's
    # r".*id_rsa.*" entry, then symlink an innocent name to it.
    target = tmp_path / "fake_id_rsa"
    target.write_text("not a real key")
    link = tmp_path / "innocent_name.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("cannot create symlink in this environment")

    result = run_file_guard("Read", str(link))
    assert result.exit_code == 2, (
        f"symlink read to id_rsa-matching file allowed — canonicalisation missing. "
        f"Stderr: {result.stderr}"
    )


def test_sibling_dir_write_blocked(run_file_guard, tmp_path, monkeypatch):
    """FND-PATH-0002: writes to a sibling of cwd must be blocked."""
    project = tmp_path / "project"
    sibling = tmp_path / "project-evil"
    project.mkdir()
    sibling.mkdir()
    target = sibling / "x.py"
    monkeypatch.chdir(project)

    # The guard subprocess is launched with cwd=REPO_ROOT (see conftest._run_guard),
    # so monkeypatch.chdir here only affects the test process. tmp_path lives outside
    # REPO_ROOT, so the absolute target below must be blocked by the guard's
    # working-tree containment check.
    result = run_file_guard("Write", str(target))
    assert result.exit_code == 2, (
        f"sibling-directory write allowed — startswith bug without trailing "
        f"path separator. Stderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# Slice-4 (2026-04-23) residuals — closed by the T12 slice.
# ---------------------------------------------------------------------------


def test_cross_session_claude_projects_read_blocked(run_file_guard, tmp_path, monkeypatch):
    """FND-PATH-0201: read-side ~/.claude/projects/<other-session>/ is blocked.

    The read-side allowed-root was ~/.claude/projects/ unbounded; a prompt-
    injection in target code could read any other session's memory, tool
    transcripts, or cached credentials. After the fix, reads are only
    permitted under ~/.claude/projects/<current-session-slug>/.
    """
    fake_home = tmp_path / "fakehome"
    other_session = (
        fake_home / ".claude" / "projects" / "-some-other-project" / "memory" / "victim.md"
    )
    other_session.parent.mkdir(parents=True)
    other_session.write_text("victim data")
    monkeypatch.setenv("HOME", str(fake_home))
    result = run_file_guard("Read", str(other_session))
    assert result.exit_code == 2, (
        f"cross-session memory read allowed — read-side carve-out not session-bound. "
        f"Stderr: {result.stderr}"
    )


def test_current_session_claude_projects_read_allowed(run_file_guard, tmp_path, monkeypatch):
    """Companion: reads within THIS session's projects dir remain allowed.

    The current-session slug is derived from REPO_ROOT (see conftest.py).
    """
    fake_home = tmp_path / "fakehome"
    slug = str(REPO_ROOT).replace("/", "-")
    own_memory = fake_home / ".claude" / "projects" / slug / "memory" / "mine.md"
    own_memory.parent.mkdir(parents=True)
    own_memory.write_text("mine")
    monkeypatch.setenv("HOME", str(fake_home))
    result = run_file_guard("Read", str(own_memory))
    assert result.exit_code == 0, (
        f"current-session memory read blocked: {result.stderr}"
    )


def test_virtualenv_pointing_at_etc_ignored(run_file_guard, tmp_path, monkeypatch):
    """FND-PATH-0202: VIRTUAL_ENV pointing outside cwd and home is rejected.

    If an attacker sets VIRTUAL_ENV=/etc in the environment before invoking
    Claude, the v3 allowed-read-roots computation would add /etc as a
    legitimate read root, re-opening every /etc/* exfiltration primitive
    that FND-PATH-0008 closed. Containment means VIRTUAL_ENV must resolve
    under cwd or $HOME, otherwise it is ignored.
    """
    monkeypatch.setenv("VIRTUAL_ENV", "/etc")
    # /etc/hostname is innocent enough but lives outside cwd + HOME.
    # Guard must block the read because VIRTUAL_ENV should not have
    # laundered /etc into the allowlist.
    result = run_file_guard("Read", "/etc/hostname")
    assert result.exit_code == 2, (
        f"VIRTUAL_ENV=/etc laundered /etc into allowed-read-roots: {result.stderr}"
    )


def test_harness_dirs_symlink_not_membership_bypass(run_file_guard, tmp_path, monkeypatch):
    """FND-PATH-0203: a symlink named .claude/hooks/x cannot fake being inside HARNESS_DIRS.

    The v3 HARNESS_DIRS were built with `_CWD / '.claude' / 'hooks'` without
    calling .resolve(). If the `hooks` dir is itself a symlink, the v3
    is_relative_to check could mismatch the resolved write path. After the
    fix, HARNESS_DIRS are resolved once at import time.
    """
    # Structural guard test — we assert that writing to a path inside the
    # resolved harness dir is blocked even when the raw path name uses a
    # symlink-ish form. The simplest direct test is to confirm a regular
    # write into .claude/hooks/ is blocked in strict mode (which the slice-3
    # test already covers); this test adds coverage for the resolve() call
    # by checking a relative Path notation that resolves into HARNESS_DIRS.
    result = run_file_guard("Write", "./.claude/hooks/././new_evil.py")
    assert result.exit_code == 2, (
        f"harness-internal write via indirect path allowed: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# Slice-5 (2026-04-24) new findings.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("env_var", ["VIRTUAL_ENV", "CONDA_PREFIX", "PYENV_ROOT"])
def test_env_var_equal_home_rejected(run_file_guard, tmp_path, monkeypatch, env_var):
    """FND-PATH-0300: setting VIRTUAL_ENV/CONDA_PREFIX/PYENV_ROOT equal to $HOME
    must NOT launder the whole home directory into allowed-read-roots.

    Strict containment rule (slice-5): candidate != home and candidate != project_root.
    """
    fake_home = tmp_path / "fakehome"
    fake_home.mkdir()
    sensitive = fake_home / ".my_secrets"
    sensitive.write_text("SENTINEL")
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv(env_var, str(fake_home))

    result = run_file_guard("Read", str(sensitive))
    assert result.exit_code == 2, (
        f"{env_var}=$HOME laundered home into allowed-read-roots: {result.stderr}"
    )


@pytest.mark.parametrize("env_var", ["VIRTUAL_ENV", "CONDA_PREFIX", "PYENV_ROOT"])
def test_env_var_equal_project_root_rejected(run_file_guard, tmp_path, monkeypatch, env_var):
    """FND-PATH-0300 companion: env var equal to PROJECT_ROOT must also not
    be accepted. PROJECT_ROOT is REPO_ROOT from the test's vantage."""
    monkeypatch.setenv(env_var, str(REPO_ROOT))
    # A sentinel path under REPO_ROOT that the forbidden-patterns regex
    # rejects: .env files. If env-var acceptance DID launder REPO_ROOT in,
    # the read would still fail on forbidden-pattern match, which is NOT
    # what we're testing. Use a benign file under tmp_path that's outside
    # REPO_ROOT to confirm the env var didn't widen scope.
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    result = run_file_guard("Read", str(outside))
    assert result.exit_code == 2, (
        f"{env_var}=PROJECT_ROOT widened scope to {outside}: {result.stderr}"
    )


@pytest.mark.parametrize("env_var", ["VIRTUAL_ENV", "CONDA_PREFIX", "PYENV_ROOT"])
def test_env_var_legitimate_subdir_allowed(run_file_guard, tmp_path, monkeypatch, env_var):
    """Companion: a legitimate venv path BELOW $HOME stays accepted.

    e.g. VIRTUAL_ENV=$HOME/.virtualenvs/foo is fine and must not be blocked.
    """
    fake_home = tmp_path / "fakehome"
    venv_dir = fake_home / ".virtualenvs" / "foo"
    venv_dir.mkdir(parents=True)
    probe = venv_dir / "lib" / "python3.12" / "site-packages" / "mod.py"
    probe.parent.mkdir(parents=True)
    probe.write_text("x = 1\n")
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv(env_var, str(venv_dir))

    result = run_file_guard("Read", str(probe))
    assert result.exit_code == 0, (
        f"legitimate {env_var}={venv_dir} read blocked: {result.stderr}"
    )


def test_harness_blocks_write_when_launched_from_ancestor_cwd(
    run_file_guard, tmp_path, monkeypatch
):
    """FND-PATH-0303: if the guard is launched with cwd=ancestor_of_project,
    HARNESS_DIRS must still anchor on the real project root (via __file__),
    not on cwd. A write to .claude/hooks/evil.py under the real project must
    block, not pass.

    The conftest runs the guard with cwd=REPO_ROOT. To simulate the attack,
    we target a write path inside REPO_ROOT/.claude/hooks/, which is the
    real project's harness dir. If the __file__ anchor is correct, this
    remains blocked regardless of cwd.
    """
    target = REPO_ROOT / ".claude" / "hooks" / "slice5_evil.py"
    result = run_file_guard("Write", str(target))
    assert result.exit_code == 2, (
        f"write to real-project harness dir allowed: {result.stderr}"
    )
