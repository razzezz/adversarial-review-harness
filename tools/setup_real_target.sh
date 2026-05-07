#!/bin/bash
# Real-target install-flow helper for the adversarial-review harness.
#
# Usage: bash tools/setup_real_target.sh <target-repo-path>
#
# Copies .claude/ and pytest.ini from this repo into the target repo,
# then verifies the guard self-test passes from the target root. If
# self-test fails, the install is rolled back (copied files removed).
#
# This script runs at the user's shell — NOT via Claude's Bash tool.
# The bash_guard hard-denies git/rm -rf/etc., which this script needs
# for the install-and-verify flow.

set -euo pipefail

TARGET="${1:-}"
VULN_HUNTER="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -z "$TARGET" ]]; then
    echo "ERROR: usage: $0 <target-repo-path>" >&2
    exit 2
fi
if [[ ! -d "$TARGET" ]]; then
    echo "ERROR: target path does not exist or is not a directory: $TARGET" >&2
    exit 2
fi
if [[ ! -d "$TARGET/.git" ]]; then
    echo "WARNING: $TARGET is not a git repository — continuing anyway" >&2
fi
if [[ -d "$TARGET/.claude" ]]; then
    echo "ERROR: $TARGET/.claude already exists; refusing to overwrite" >&2
    echo "  Remove the existing .claude/ first, or pick a fresh target." >&2
    exit 2
fi

echo "[setup] copying .claude/ into $TARGET..."
cp -R "$VULN_HUNTER/.claude" "$TARGET/.claude"

if [[ -f "$VULN_HUNTER/pytest.ini" && ! -f "$TARGET/pytest.ini" ]]; then
    echo "[setup] copying pytest.ini into $TARGET..."
    cp "$VULN_HUNTER/pytest.ini" "$TARGET/pytest.ini"
fi

echo "[setup] running guard self-test from $TARGET..."
cd "$TARGET"
if ! python -m pytest .claude/tests/ -q; then
    echo "ERROR: guard self-test failed — rolling back install" >&2
    rm -rf "$TARGET/.claude"
    [[ -f "$TARGET/pytest.ini" ]] && rm -f "$TARGET/pytest.ini" || true
    exit 3
fi

echo "[setup] self-test passed. Recording target snapshot:"
if git -C "$TARGET" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    SHA="$(git -C "$TARGET" rev-parse HEAD)"
    TAG="$(git -C "$TARGET" describe --tags --always 2>/dev/null || echo '(no tag)')"
    echo "  commit: $SHA"
    echo "  tag:    $TAG"
else
    echo "  (not a git repo — record SHA manually)"
fi

echo ""
echo "[setup] Install complete."
echo ""
echo "Next steps:"
echo "  cd $TARGET"
echo "  claude"
echo "  /adversarial-review"
