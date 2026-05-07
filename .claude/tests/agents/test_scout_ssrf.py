"""Structural tests for the scout-ssrf persona.

Unlike scout-supply-chain, scout-ssrf's detection is context-sensitive grep
work done inside the sub-agent, not a pure Python helper. These tests assert
the persona file exists and contains the expected sections so E2E runs have
a well-formed scout to dispatch.
"""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SCOUT = REPO_ROOT / ".claude" / "agents" / "scout-ssrf.md"


def test_persona_exists():
    assert SCOUT.is_file(), f"scout-ssrf persona missing: {SCOUT}"


def test_frontmatter_has_required_fields():
    text = SCOUT.read_text(encoding="utf-8")
    assert text.startswith("---"), "missing YAML frontmatter"
    assert "name: scout-ssrf" in text
    assert "tools:" in text
    assert "model: opus" in text


def test_persona_declares_cwe_918():
    text = SCOUT.read_text(encoding="utf-8")
    assert "CWE-918" in text, "persona must explicitly declare CWE-918"


def test_persona_has_scope_section():
    text = SCOUT.read_text(encoding="utf-8")
    assert "## Scope" in text, "persona must include the identical Scope section"
    assert "recon_summary.json" in text
    assert "scope.target_root" in text
    assert "scope.excluded_subpaths" in text


def test_persona_lists_target_http_libs():
    text = SCOUT.read_text(encoding="utf-8")
    for lib in ("requests", "urllib", "httpx", "aiohttp", "urllib3"):
        assert lib in text, f"persona must list {lib!r} as a target HTTP library"


def test_persona_mentions_url_resolution_falsification_poc():
    text = SCOUT.read_text(encoding="utf-8")
    assert "URL-resolution falsification" in text or "URL resolution falsification" in text, (
        "persona must describe the URL-resolution-falsification PoC pathway"
    )


def test_persona_forbids_live_network_egress():
    """The PoC pathway is deterministic; it must not fetch."""
    text = SCOUT.read_text(encoding="utf-8")
    # Structural only — we check for a clear "no egress" / "without egress" /
    # "--network none" mention.
    low = text.lower()
    assert ("no egress" in low or "without egress" in low or
            "--network none" in low or "no live request" in low or
            "no real request" in low), (
        "persona must make the no-live-egress posture explicit"
    )
