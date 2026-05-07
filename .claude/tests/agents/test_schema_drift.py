"""Drift check: the finding-schema status enum in docs/DESIGN.md and the
set of statuses referenced by agent personas must stay consistent.

Slice-5 introduced CORROBORATED_STATIC_ONLY; this test keeps it honest.

Portability note (slice-6): when the scaffold is installed into a
foreign target repo, docs/DESIGN.md is NOT present — it's a
vuln-hunter-specific development artefact. The DESIGN-side drift check
is skipped automatically when the file is absent. Persona-side checks
still run because the personas travel with the scaffold.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DESIGN_MD = REPO_ROOT / "docs" / "DESIGN.md"
CRITIC_MD = REPO_ROOT / ".claude" / "agents" / "critic.md"
POC_BUILDER_MD = REPO_ROOT / ".claude" / "agents" / "poc-builder.md"
REPORTER_MD = REPO_ROOT / ".claude" / "agents" / "reporter.md"


EXPECTED_STATUSES = {
    "CANDIDATE",
    "CORROBORATED",
    "CONFIRMED",
    "REJECTED",
    "CONTESTED",
    "UNCORROBORATED_NO_POC",
    "CORROBORATED_STATIC_ONLY",
}


def _extract_design_statuses() -> set[str]:
    text = DESIGN_MD.read_text(encoding="utf-8")
    m = re.search(r'"status":\s*"([^"]+)"', text)
    assert m, "could not locate the status enum line in docs/DESIGN.md"
    raw = m.group(1)
    # Pipe-separated, whitespace-tolerant.
    return {tok.strip() for tok in raw.split("|") if tok.strip()}


def test_design_md_lists_all_expected_statuses():
    if not DESIGN_MD.is_file():
        pytest.skip(
            f"docs/DESIGN.md not present at {DESIGN_MD} — this is a "
            "vuln-hunter-specific development artefact. The scaffold "
            "was installed into a foreign target repo where DESIGN.md "
            "does not exist. The drift invariant is enforced at "
            "harness-dev time; portability-skipping here is intentional."
        )
    assert _extract_design_statuses() == EXPECTED_STATUSES


def test_corroborated_static_only_referenced_in_critic():
    text = CRITIC_MD.read_text(encoding="utf-8")
    assert "CORROBORATED_STATIC_ONLY" in text, (
        "critic persona must mention CORROBORATED_STATIC_ONLY per slice-5 schema expansion"
    )


def test_corroborated_static_only_referenced_in_poc_builder():
    text = POC_BUILDER_MD.read_text(encoding="utf-8")
    assert "CORROBORATED_STATIC_ONLY" in text, (
        "poc-builder persona must mention CORROBORATED_STATIC_ONLY"
    )


def test_corroborated_static_only_referenced_in_reporter():
    text = REPORTER_MD.read_text(encoding="utf-8")
    assert "CORROBORATED_STATIC_ONLY" in text, (
        "reporter persona must mention CORROBORATED_STATIC_ONLY"
    )
