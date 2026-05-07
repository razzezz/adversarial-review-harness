#!/usr/bin/env python3
"""Atomic path writes that refuse any symlink in the ancestor chain.

Linux-only. Uses O_PATH + O_NOFOLLOW + dir_fd walks so no path component
is ever re-resolved through the filesystem. Closes the TOCTOU window that
a precheck-then-open pattern leaves open (FND-PATH-0301).

Contract
--------
  safe_mkdir_p(path)        create path and any missing ancestors; refuse
                             if any existing ancestor is a symlink.
  safe_write_text(path, s)  write s to path (truncating any existing file);
                             refuse if any ancestor or leaf is a symlink.
  safe_open_append(path)    open path for O_WRONLY | O_CREAT | O_APPEND;
                             refuse symlinks; return the fd for caller use.

All three raise OSError on symlink refusal. The kernel's errno varies by
exact call pattern — ELOOP when it explicitly rejects a symlink follow,
or ENOTDIR when O_PATH|O_DIRECTORY|O_NOFOLLOW opens the symlink inode and
then rejects it as "not a directory." Both are valid refusal signals;
callers that need to distinguish should check errno in (ELOOP, ENOTDIR).

safe_open_append returns an fd; callers own closing it.

See docs/DECISIONS.md D16.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path


def _walk_to_parent_fd(path: Path) -> tuple[int, str]:
    """Walk to path's parent using openat-style dir_fd descent.

    Returns (parent_fd, leaf_name). Caller owns closing parent_fd.
    Raises OSError (ELOOP or ENOTDIR) if any ancestor is a symlink.
    """
    if not path.is_absolute():
        path = Path.cwd().resolve() / path
    # path.parts on an absolute path begins with "/"; walk from there.
    parts = path.parts
    if parts[0] != "/":
        # On non-root-relative absolute paths something has gone wrong;
        # surface it as ENOENT rather than a silent mis-walk.
        raise OSError(errno.ENOENT, f"unexpected path shape: {path}")
    leaf = parts[-1]
    ancestors = parts[1:-1]  # skip leading "/" and trailing leaf

    dir_fd = os.open("/", os.O_PATH | os.O_DIRECTORY)
    try:
        for part in ancestors:
            try:
                new_fd = os.open(
                    part,
                    os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=dir_fd,
                )
            except OSError:
                # Close the current dir_fd before re-raising so we don't leak.
                os.close(dir_fd)
                raise
            os.close(dir_fd)
            dir_fd = new_fd
        return dir_fd, leaf
    except BaseException:
        try:
            os.close(dir_fd)
        except OSError:
            pass
        raise


def safe_mkdir_p(path: Path, mode: int = 0o755) -> None:
    """Create path (and missing ancestors). Refuse symlink ancestors.

    Missing directories are created with `mode`. Existing directories are
    tolerated (EEXIST is swallowed). Any existing symlink in the chain
    raises OSError (ELOOP or ENOTDIR — see module docstring).
    """
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd().resolve() / path
    parts = path.parts
    if parts[0] != "/":
        raise OSError(errno.ENOENT, f"unexpected path shape: {path}")

    dir_fd = os.open("/", os.O_PATH | os.O_DIRECTORY)
    try:
        for part in parts[1:]:
            # Try to open the component as a directory, refusing symlinks.
            try:
                new_fd = os.open(
                    part,
                    os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=dir_fd,
                )
            except OSError as e:
                if e.errno == errno.ENOENT:
                    # Missing — create it relative to the current dir_fd.
                    os.mkdir(part, mode, dir_fd=dir_fd)
                    new_fd = os.open(
                        part,
                        os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=dir_fd,
                    )
                else:
                    os.close(dir_fd)
                    raise
            os.close(dir_fd)
            dir_fd = new_fd
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass


def safe_write_text(path: Path, content: str, mode: int = 0o644) -> None:
    """Write content to path atomically, refusing any symlink in the chain.

    Opens with O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW relative to the
    walked parent fd; encodes content as UTF-8.
    """
    path = Path(path)
    parent_fd, leaf = _walk_to_parent_fd(path)
    try:
        fd = os.open(
            leaf,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            mode,
            dir_fd=parent_fd,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    finally:
        os.close(parent_fd)


def safe_open_append(path: Path, mode: int = 0o600) -> int:
    """Open path for append; refuse symlinks; return the fd.

    Caller is responsible for closing the returned fd.
    """
    path = Path(path)
    parent_fd, leaf = _walk_to_parent_fd(path)
    try:
        fd = os.open(
            leaf,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
            mode,
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    return fd
