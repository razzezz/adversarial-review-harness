#!/usr/bin/env python3
"""
PostToolUse hook: Audit log.

Records every tool call made during a run. For a CSO audience this is
table stakes: at the end of the demo you show this log and say "here is
every action the agent took."

Output: append JSONL to .claude/output/audit.jsonl.

FND-PATH-0301 (closed slice-5): previous implementations used an ancestor-
symlink precheck plus os.open(O_NOFOLLOW). The precheck was TOCTOU-racy:
an attacker could swap a symlink into the ancestor chain between the check
and the open. This hook now writes through .claude/tools/_safe_write.py
which walks with dir_fd + O_NOFOLLOW on every component, closing the race.

Posture: the audit hook must never break the run. On any OSError from the
safe-write primitives, log a warning to stderr and exit 0.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Import the safe-write helper by file path (no package registration).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from _safe_write import safe_mkdir_p, safe_open_append  # noqa: E402


AUDIT_LOG = Path(".claude/output/audit.jsonl")


def truncate(s: str, limit: int = 2000) -> str:
    """Truncate a string to a reasonable length for the audit log."""
    if not isinstance(s, str):
        s = str(s)
    if len(s) <= limit:
        return s
    return s[:limit] + f"...[truncated, {len(s)} total chars]"


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Audit hook should never break the run.
        sys.exit(0)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_name": payload.get("tool_name", ""),
        "tool_input": {
            k: truncate(v) if isinstance(v, str) else v
            for k, v in payload.get("tool_input", {}).items()
        },
        "result_summary": truncate(
            str(payload.get("tool_response", payload.get("result", "")))
        ),
        "blocked": payload.get("blocked", False),
        "agent": os.environ.get("CLAUDE_AGENT_NAME", "orchestrator"),
    }

    try:
        safe_mkdir_p(AUDIT_LOG.parent)
        fd = safe_open_append(AUDIT_LOG)
        try:
            os.write(fd, (json.dumps(entry) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except OSError as e:
        # Never break the run; log to stderr and continue.
        print(
            f"audit log write refused/failed: {e.__class__.__name__}: {e}",
            file=sys.stderr,
        )

    sys.exit(0)


if __name__ == "__main__":
    main()
