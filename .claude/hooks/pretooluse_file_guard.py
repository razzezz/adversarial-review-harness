#!/usr/bin/env python3
"""
PreToolUse hook: File access guard (schema-v2).

Enforces:
  1. Forbidden-pattern regex on BOTH the raw and canonical path, so
     symlinks cannot bypass the check. (FND-PATH-0003.)
  2. Working-tree containment using Path.is_relative_to, not str.startswith.
     (FND-PATH-0002: sibling-directory escape.)
  3. Write-specific protections split into two tiers:
       a. System prefixes (/etc, /usr, /var, /root, /boot, /sys, /proc) --
          unconditional block.
       b. Harness-internal paths (.claude/hooks/, .claude/tools/,
          .claude/settings.json) -- blocked UNLESS HARNESS_DEV_MODE=1 is set
          in the environment. Intended only for slices that edit harness
          internals. See docs/DECISIONS.md D14.
  4. Memory-system carve-out: writes to ~/.claude/projects/*/memory/ are
     always allowed (Claude Code's memory system writes there legitimately).

Input on stdin: JSON from Claude Code with tool_name and tool_input.
Exit 0: allow. Exit 2: block.
"""

from __future__ import annotations

import json
import os
import re
import sys
import sysconfig
from pathlib import Path


FORBIDDEN_PATH_PATTERNS = [
    r"\.env$",
    r"\.env\..*$",
    r".*\.pem$",
    r".*id_rsa.*",
    r".*id_dsa.*",
    r".*id_ecdsa.*",
    r".*id_ed25519.*",
    r".*\.ssh/.*",
    r".*\.aws/.*",
    r".*\.gcp/.*",
    r".*\.azure/.*",
    r".*\.kube/config.*",
    r".*credentials.*",
    r".*secrets\.ya?ml$",
    r".*\.git/config$",
    r".*\.git/credentials$",
    r".*/\.netrc$",
    r".*/\.pgpass$",
    r".*password.*\.txt$",
    # System files commonly used as exfiltration targets (FND-PATH-0008).
    r"^/etc/passwd$",
    r"^/etc/shadow$",
    r"^/etc/gshadow$",
    r"^/etc/ssl/private/.*",
    r"^/proc/[0-9]+/environ$",
    r"^/proc/self/environ$",
    r"^/var/log/auth\.log$",
    # Developer credential files and artefacts (FND-PATH-0014).
    r".*/\.bash_history$",
    r".*/\.zsh_history$",
    r".*/\.npmrc$",
    r".*/\.pypirc$",
    r".*/\.vault-token$",
    r".*/\.docker/config\.json$",
    r".*/\.config/gh/hosts\.yml$",
    r".*/\.cargo/credentials\.toml$",
    r".*/\.gnupg/.*",
    # Key / keystore file extensions.
    r".*\.key$",
    r".*\.jks$",
    r".*\.p12$",
    r".*\.pfx$",
    r".*\.keystore$",
    # Round-3 additions (FND-PATH-0104): shadow/passwd backup files,
    # sudoers, crontab, kubernetes service-account tokens, container
    # secrets, docker socket, browser credential stores, proc
    # process-inspection paths.
    r"^/etc/shadow-$",
    r"^/etc/passwd-$",
    r"^/etc/gshadow-$",
    r"^/etc/group-$",
    r"^/etc/sudoers$",
    r"^/etc/sudoers\.d/.*",
    r"^/etc/crontab$",
    r"^/etc/cron\.(d|daily|hourly|monthly|weekly)/.*",
    r"^/etc/fstab$",
    r"^/proc/[0-9]+/cmdline$",
    r"^/proc/[0-9]+/status$",
    r"^/proc/kallsyms$",
    r"^/var/run/secrets/kubernetes\.io/.*",
    r"^/var/run/secrets/tokens/.*",
    r"^/run/secrets/.*",
    r"^/var/run/docker\.sock$",
    r"^/run/docker\.sock$",
    # Firefox / Chrome credential stores (credentials filename is already
    # covered; these add the browser-specific filenames).
    r".*/Login Data$",
    r".*/signons\.sqlite$",
    r".*/logins\.json$",
    r".*/key[34]?\.db$",
    r".*/cookies\.sqlite$",
]

SYSTEM_WRITE_FORBIDDEN = [
    "/etc/", "/usr/", "/var/", "/root/", "/boot/", "/sys/", "/proc/",
]

# FND-PATH-0303 (slice-5): anchor the project root on the hook's own script
# location rather than process cwd. The scaffold invariant (D11) guarantees
# this file lives at .claude/hooks/pretooluse_file_guard.py, so three parents
# up is the project root regardless of what cwd the hook is invoked from. A
# user launching Claude from an ancestor of the project previously caused
# HARNESS_DIRS to shift upward and permitted writes to <real-project>/.claude/hooks/.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Back-compat alias so existing containment checks that reference `_CWD` keep
# working with one line change per call site. The semantic meaning changes
# from "process cwd" to "project root", which is the correctness fix.
_CWD = _PROJECT_ROOT

# FND-PATH-0203: each HARNESS_DIRS entry must be resolved so that a symlinked
# .claude/ or a symlinked hooks/ cannot defeat the is_relative_to() check.
# resolve(strict=False) is used so this module still imports cleanly when the
# dirs don't yet exist on disk (test fixtures, fresh checkouts).
HARNESS_DIRS = [
    (_PROJECT_ROOT / ".claude" / "hooks").resolve(strict=False),
    (_PROJECT_ROOT / ".claude" / "tools").resolve(strict=False),
    (_PROJECT_ROOT / ".claude" / "agents").resolve(strict=False),
    (_PROJECT_ROOT / ".claude" / "commands").resolve(strict=False),
    (_PROJECT_ROOT / ".claude" / "skills").resolve(strict=False),
    (_PROJECT_ROOT / ".claude" / "tests").resolve(strict=False),  # FND-INJ-0010
]
HARNESS_SETTINGS_FILES = {
    _PROJECT_ROOT / ".claude" / "settings.json",
    _PROJECT_ROOT / ".claude" / "settings.local.json",
}


def _current_session_memory_dir() -> Path | None:
    """Derive Claude Code's memory dir for the CURRENT project only.

    Claude Code stores per-project memory at
    `~/.claude/projects/<slug>/memory/` where `<slug>` is the working-directory
    path with `/` replaced by `-`. Binding the carve-out to this specific
    session prevents cross-session memory poisoning (FND-PATH-0105 / 0201).
    """
    try:
        home = Path.home()
    except RuntimeError:
        return None
    slug = str(_CWD).replace("/", "-")
    return (home / ".claude" / "projects" / slug / "memory").resolve()


_SESSION_MEMORY_DIR = _current_session_memory_dir()


def _compute_allowed_read_roots() -> list[Path]:
    """Roots outside the working tree where Reads are permitted.

    Read-side containment (FND-PATH-0100) must still allow Claude to inspect
    Python stdlib, installed packages, active virtualenv / conda prefix, and
    this session's own memory area.

    FND-PATH-0201: the ~/.claude/projects/ root is session-bound to the
    current session slug (mirror of the write-side carve-out added in round 3).
    FND-PATH-0202: VIRTUAL_ENV / CONDA_PREFIX / PYENV_ROOT are environment-
    controlled; they are ignored unless they resolve under _CWD or $HOME.
    """
    roots: list[Path] = []
    try:
        paths = sysconfig.get_paths()
        for key in ("stdlib", "purelib", "platlib", "include", "platinclude"):
            p = paths.get(key)
            if p:
                try:
                    roots.append(Path(p).resolve())
                except OSError:
                    pass
    except Exception:
        pass

    # FND-PATH-0202: containment on env-derived roots.
    # FND-PATH-0300 (slice-5): strict containment — candidate must be STRICTLY
    # below cwd or $HOME, not equal to them. Path.is_relative_to(X) is True
    # when path == X (a path is trivially relative to itself), which would
    # launder the whole anchor directory as a read root.
    try:
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        home = None
    for var in ("VIRTUAL_ENV", "CONDA_PREFIX", "PYENV_ROOT"):
        v = os.environ.get(var)
        if not v:
            continue
        try:
            candidate = Path(v).resolve()
        except OSError:
            continue
        accepted = False
        try:
            if candidate != _CWD and candidate.is_relative_to(_CWD):
                accepted = True
        except ValueError:
            pass
        if not accepted and home is not None:
            try:
                if candidate != home and candidate.is_relative_to(home):
                    accepted = True
            except ValueError:
                pass
        if accepted:
            roots.append(candidate)

    # FND-PATH-0201: bind the read-side ~/.claude/projects/ root to THIS
    # session. The write-side binding (round 3) was in is_memory_write_carveout;
    # the read-side needs its own narrowing because arbitrary reads are
    # otherwise unbounded within ~/.claude/projects/.
    if _SESSION_MEMORY_DIR is not None:
        # The whole session directory (not just the memory subdir) is
        # legitimately readable — Claude Code stores transcripts there that
        # the agent may need to inspect.
        try:
            session_root = _SESSION_MEMORY_DIR.parent.resolve()
            roots.append(session_root)
        except (OSError, RuntimeError):
            pass

    return roots


_ALLOWED_READ_ROOTS = _compute_allowed_read_roots()


def _is_in_allowed_read_area(resolved: Path) -> bool:
    for root in _ALLOWED_READ_ROOTS:
        try:
            if resolved.is_relative_to(root):
                return True
        except ValueError:
            continue
    return False


def block(reason: str) -> None:
    print(f"BLOCKED by pretooluse_file_guard: {reason}", file=sys.stderr)
    sys.exit(2)


def is_memory_write_carveout(resolved: Path) -> bool:
    """Allow writes only to THIS session's `~/.claude/projects/<slug>/memory/**`.

    The session slug is derived from the working directory. Writes to any
    other session's memory dir are rejected — this is FND-PATH-0105
    (cross-session memory poisoning via session-unbound carve-out).
    """
    if _SESSION_MEMORY_DIR is None:
        return False
    try:
        return resolved.is_relative_to(_SESSION_MEMORY_DIR)
    except ValueError:
        return False


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        block("hook received malformed JSON; failing closed")
        return

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    raw_path = (
        tool_input.get("file_path")
        or tool_input.get("path")
        or tool_input.get("notebook_path")
        or ""
    )

    if not raw_path:
        sys.exit(0)

    is_write = tool_name in ("Edit", "Write", "MultiEdit")

    try:
        resolved = Path(raw_path).resolve(strict=False)
    except (OSError, RuntimeError) as e:
        block(f"could not resolve path: {raw_path!r}: {e}")
        return

    resolved_str = str(resolved)

    for pattern in FORBIDDEN_PATH_PATTERNS:
        if re.search(pattern, resolved_str, re.IGNORECASE):
            block(
                f"path matches forbidden pattern {pattern!r}: "
                f"raw={raw_path!r} resolved={resolved_str!r}"
            )

    for pattern in FORBIDDEN_PATH_PATTERNS:
        if re.search(pattern, raw_path, re.IGNORECASE):
            block(f"raw path matches forbidden pattern {pattern!r}: {raw_path!r}")

    if not is_write:
        # FND-PATH-0100: read-side containment. Previously reads were subject
        # only to the FORBIDDEN_PATH_PATTERNS denylist, making any denylist
        # gap an exfiltration primitive. Require reads to land inside the
        # working tree OR inside a small set of legitimate external roots
        # (Python stdlib, site-packages, active virtualenv, Claude Code's
        # memory area).
        if not resolved.is_relative_to(_CWD) and not _is_in_allowed_read_area(resolved):
            block(
                f"read outside working tree and not in allowed read roots: "
                f"raw={raw_path!r} resolved={resolved_str!r}"
            )

    if is_write:
        for prefix in SYSTEM_WRITE_FORBIDDEN:
            if resolved_str.startswith(prefix):
                block(
                    f"write to system-forbidden prefix {prefix!r}: "
                    f"raw={raw_path!r} resolved={resolved_str!r}"
                )

        dev_mode = os.environ.get("HARNESS_DEV_MODE") == "1"
        if not dev_mode:
            for forbidden in HARNESS_DIRS:
                try:
                    if resolved.is_relative_to(forbidden):
                        block(
                            f"write to harness-internal path blocked "
                            f"(set HARNESS_DEV_MODE=1 to permit during "
                            f"harness-development sessions): "
                            f"raw={raw_path!r} resolved={resolved_str!r}"
                        )
                except ValueError:
                    pass
            if resolved in HARNESS_SETTINGS_FILES:
                block(
                    f"write to harness settings file blocked "
                    f"(set HARNESS_DEV_MODE=1 to permit during "
                    f"harness-development sessions): raw={raw_path!r} "
                    f"resolved={resolved_str!r}"
                )

        if not resolved.is_relative_to(_CWD) and not is_memory_write_carveout(resolved):
            block(
                f"write outside working tree and not in memory carve-out: "
                f"raw={raw_path!r} resolved={resolved_str!r} cwd={_CWD}"
            )

    sys.exit(0)


if __name__ == "__main__":
    main()
