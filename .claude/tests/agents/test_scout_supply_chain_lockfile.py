"""Unit tests for scout-supply-chain's lockfile-drift detector.

Tests the new sibling module `scout_supply_chain_lockfile.py` that
parses uv.lock / poetry.lock and detects three drift patterns
against the host pyproject's declared deps.

All tests use tmp_path fabrications — no toy-app fixture dependency.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DETECTOR = REPO_ROOT / ".claude" / "tools" / "scout_supply_chain_detect.py"
LOCKFILE_DETECTOR = REPO_ROOT / ".claude" / "tools" / "scout_supply_chain_lockfile.py"


def _load_detector():
    spec = importlib.util.spec_from_file_location(
        "scout_supply_chain_detect", DETECTOR,
    )
    assert spec and spec.loader, f"cannot load {DETECTOR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_lockfile():
    # Loading order matters: detector first so the lockfile module's
    # `from scout_supply_chain_detect import ...` resolves.
    _load_detector()
    spec = importlib.util.spec_from_file_location(
        "scout_supply_chain_lockfile", LOCKFILE_DETECTOR,
    )
    assert spec and spec.loader, f"cannot load {LOCKFILE_DETECTOR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# LockFormat enum.
# ---------------------------------------------------------------------------


def test_lock_format_enum_values():
    mod = _load_lockfile()
    assert mod.LockFormat.UV.value == "uv.lock"
    assert mod.LockFormat.POETRY.value == "poetry.lock"


# ---------------------------------------------------------------------------
# LockEntry + LockMetadata dataclasses.
# ---------------------------------------------------------------------------


def test_lock_entry_dataclass_shape():
    mod = _load_lockfile()
    e = mod.LockEntry(name="requests", version="2.28.0", line_no=42)
    assert e.name == "requests"
    assert e.version == "2.28.0"
    assert e.line_no == 42


def test_lock_metadata_dataclass_shape():
    mod = _load_lockfile()
    m = mod.LockMetadata(provides_extras=("demo", "test"))
    assert m.provides_extras == ("demo", "test")


# ---------------------------------------------------------------------------
# Name canonicalization (PEP 503).
# ---------------------------------------------------------------------------


def test_canonicalize_pep503_normalizes_separators_and_case():
    mod = _load_lockfile()
    assert mod._canonicalize("Foo_Bar") == "foo-bar"
    assert mod._canonicalize("foo.bar") == "foo-bar"
    assert mod._canonicalize("FOO--BAR") == "foo-bar"
    assert mod._canonicalize("  Requests  ") == "requests"
    assert mod._canonicalize("python-snap7") == "python-snap7"


# ---------------------------------------------------------------------------
# parse_uv_lock — uv.lock TOML schema.
# ---------------------------------------------------------------------------


def test_parse_uv_lock_extracts_packages_and_metadata(tmp_path):
    mod = _load_lockfile()
    lock = tmp_path / "uv.lock"
    lock.write_text(
        'version = 1\n'
        '\n'
        '[manifest]\n'
        'provides-extras = ["demo", "test"]\n'
        '\n'
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.28.0"\n'
        '\n'
        '[[package]]\n'
        'name = "Click_Pkg"\n'
        'version = "8.1.0"\n'
    )
    entries, meta = mod.parse_uv_lock(lock)
    # Canonical name keys.
    assert "requests" in entries
    assert "click-pkg" in entries
    assert entries["requests"].version == "2.28.0"
    assert entries["click-pkg"].version == "8.1.0"
    # Metadata extras.
    assert meta.provides_extras == ("demo", "test")


def test_parse_uv_lock_missing_manifest_table_returns_empty_extras(tmp_path):
    mod = _load_lockfile()
    lock = tmp_path / "uv.lock"
    lock.write_text(
        'version = 1\n'
        '\n'
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.28.0"\n'
    )
    entries, meta = mod.parse_uv_lock(lock)
    assert "requests" in entries
    assert meta.provides_extras == ()


def test_parse_uv_lock_malformed_toml_returns_empty(tmp_path):
    mod = _load_lockfile()
    lock = tmp_path / "uv.lock"
    lock.write_text("not valid toml [[[ \n")
    entries, meta = mod.parse_uv_lock(lock)
    assert entries == {}
    assert meta.provides_extras == ()


def test_parse_uv_lock_skips_packages_missing_name_or_version(tmp_path):
    mod = _load_lockfile()
    lock = tmp_path / "uv.lock"
    lock.write_text(
        '[[package]]\n'
        'name = "good"\n'
        'version = "1.0"\n'
        '\n'
        '[[package]]\n'
        'version = "2.0"\n'   # no name
        '\n'
        '[[package]]\n'
        'name = "bad"\n'      # no version
    )
    entries, _ = mod.parse_uv_lock(lock)
    assert "good" in entries
    assert "bad" not in entries
    assert len(entries) == 1


# ---------------------------------------------------------------------------
# parse_poetry_lock — poetry.lock TOML schema.
# ---------------------------------------------------------------------------


def test_parse_poetry_lock_extracts_packages_and_synthesizes_extras(tmp_path):
    mod = _load_lockfile()
    lock = tmp_path / "poetry.lock"
    lock.write_text(
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.28.0"\n'
        '[package.extras]\n'
        'security = ["pyOpenSSL"]\n'
        'socks = ["pysocks"]\n'
        '\n'
        '[[package]]\n'
        'name = "click"\n'
        'version = "8.1.0"\n'
    )
    entries, meta = mod.parse_poetry_lock(lock)
    assert "requests" in entries
    assert "click" in entries
    # provides_extras synthesized from [package.extras] keys, deduped.
    assert "security" in meta.provides_extras
    assert "socks" in meta.provides_extras


def test_parse_poetry_lock_no_extras_yields_empty_provides(tmp_path):
    mod = _load_lockfile()
    lock = tmp_path / "poetry.lock"
    lock.write_text(
        '[[package]]\n'
        'name = "click"\n'
        'version = "8.1.0"\n'
    )
    entries, meta = mod.parse_poetry_lock(lock)
    assert "click" in entries
    assert meta.provides_extras == ()


def test_parse_poetry_lock_malformed_toml_returns_empty(tmp_path):
    mod = _load_lockfile()
    lock = tmp_path / "poetry.lock"
    lock.write_text("[[broken\n")
    entries, meta = mod.parse_poetry_lock(lock)
    assert entries == {}
    assert meta.provides_extras == ()


# ---------------------------------------------------------------------------
# detect_extras_drift.
# ---------------------------------------------------------------------------


def _make_dep(mod_detect, name, section, extra=None, spec="==1.0.0"):
    """Helper to build a Dependency for unit tests."""
    return mod_detect.Dependency(
        name=name,
        spec=spec,
        source_file="/x/pyproject.toml",
        source_line=1,
        manifest_section=section,
        extra_name=extra,
    )


def test_extras_drift_fires_when_declared_extra_missing_from_metadata(tmp_path):
    mod = _load_lockfile()
    det = _load_detector()
    deps = [_make_dep(det, "psutil", det.ManifestSection.OPTIONAL_DEPENDENCIES, "demo")]
    meta = mod.LockMetadata(provides_extras=("test",))
    findings = mod.detect_extras_drift(
        deps, meta, tmp_path / "uv.lock", mod.LockFormat.UV,
    )
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert "demo" in findings[0].description


def test_extras_drift_silent_when_extra_present_in_metadata(tmp_path):
    mod = _load_lockfile()
    det = _load_detector()
    deps = [_make_dep(det, "psutil", det.ManifestSection.OPTIONAL_DEPENDENCIES, "demo")]
    meta = mod.LockMetadata(provides_extras=("demo",))
    findings = mod.detect_extras_drift(
        deps, meta, tmp_path / "uv.lock", mod.LockFormat.UV,
    )
    assert findings == []


def test_extras_drift_security_bearing_extra_name_records_extra_in_finding(tmp_path):
    """Drift baseline is "low"; _opt_in_severity preserves rather than bumps,
    so a security-bearing extra-name keeps severity "low". Regression check
    is that the extra-name is recorded on the Finding for cross-detector
    consistency with slice-8 unpinned-deps findings.
    """
    mod = _load_lockfile()
    det = _load_detector()
    deps = [_make_dep(det, "opaquepkg", det.ManifestSection.OPTIONAL_DEPENDENCIES, "auth")]
    meta = mod.LockMetadata(provides_extras=("test",))
    findings = mod.detect_extras_drift(
        deps, meta, tmp_path / "uv.lock", mod.LockFormat.UV,
    )
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].extra_name == "auth"


# ---------------------------------------------------------------------------
# detect_version_drift.
# ---------------------------------------------------------------------------


def test_version_drift_fires_when_pin_violated(tmp_path):
    mod = _load_lockfile()
    det = _load_detector()
    deps = [_make_dep(det, "requests", det.ManifestSection.PROJECT_DEPENDENCIES,
                     spec=">=2.30,<3")]
    entries = {"requests": mod.LockEntry(name="requests", version="2.28.0", line_no=5)}
    findings = mod.detect_version_drift(
        deps, entries, tmp_path / "uv.lock", mod.LockFormat.UV,
    )
    assert len(findings) == 1
    assert "2.28.0" in findings[0].evidence
    assert ">=2.30" in findings[0].evidence


def test_version_drift_silent_when_pin_satisfied(tmp_path):
    mod = _load_lockfile()
    det = _load_detector()
    deps = [_make_dep(det, "requests", det.ManifestSection.PROJECT_DEPENDENCIES,
                     spec=">=2.30,<3")]
    entries = {"requests": mod.LockEntry(name="requests", version="2.31.0", line_no=5)}
    findings = mod.detect_version_drift(
        deps, entries, tmp_path / "uv.lock", mod.LockFormat.UV,
    )
    assert findings == []


def test_version_drift_critical_name_bumps_severity(tmp_path):
    mod = _load_lockfile()
    det = _load_detector()
    deps = [_make_dep(det, "cryptography", det.ManifestSection.PROJECT_DEPENDENCIES,
                     spec=">=44.0,<45")]
    entries = {"cryptography": mod.LockEntry(name="cryptography", version="42.0.0", line_no=5)}
    findings = mod.detect_version_drift(
        deps, entries, tmp_path / "uv.lock", mod.LockFormat.UV,
    )
    assert len(findings) == 1
    # Baseline "low"; critical-name in non-opt-in section bumps to "medium".
    assert findings[0].severity == "medium"


def test_version_drift_skipped_when_specifier_empty(tmp_path):
    mod = _load_lockfile()
    det = _load_detector()
    deps = [_make_dep(det, "requests", det.ManifestSection.PROJECT_DEPENDENCIES, spec="")]
    entries = {"requests": mod.LockEntry(name="requests", version="2.28.0", line_no=5)}
    findings = mod.detect_version_drift(
        deps, entries, tmp_path / "uv.lock", mod.LockFormat.UV,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# detect_missing_from_lock.
# ---------------------------------------------------------------------------


def test_missing_from_lock_fires_when_dep_absent(tmp_path):
    mod = _load_lockfile()
    det = _load_detector()
    deps = [
        _make_dep(det, "orphan_pkg", det.ManifestSection.PROJECT_DEPENDENCIES, spec=""),
        _make_dep(det, "requests", det.ManifestSection.PROJECT_DEPENDENCIES, spec="==2.31.0"),
    ]
    entries = {"requests": mod.LockEntry(name="requests", version="2.31.0", line_no=3)}
    findings = mod.detect_missing_from_lock(
        deps, entries, tmp_path / "uv.lock", mod.LockFormat.UV,
    )
    assert len(findings) == 1
    assert findings[0].name == "orphan_pkg"


def test_missing_from_lock_silent_when_all_present(tmp_path):
    mod = _load_lockfile()
    det = _load_detector()
    deps = [_make_dep(det, "requests", det.ManifestSection.PROJECT_DEPENDENCIES, spec="==2.31.0")]
    entries = {"requests": mod.LockEntry(name="requests", version="2.31.0", line_no=3)}
    findings = mod.detect_missing_from_lock(
        deps, entries, tmp_path / "uv.lock", mod.LockFormat.UV,
    )
    assert findings == []


def test_missing_from_lock_short_circuits_when_lock_empty(tmp_path):
    mod = _load_lockfile()
    det = _load_detector()
    deps = [_make_dep(det, "requests", det.ManifestSection.PROJECT_DEPENDENCIES, spec="==2.31.0")]
    findings = mod.detect_missing_from_lock(
        deps, {}, tmp_path / "uv.lock", mod.LockFormat.UV,
    )
    # D7: empty lock indistinguishable from "lock not present"; silent.
    assert findings == []


# ---------------------------------------------------------------------------
# Evidence emission.
# ---------------------------------------------------------------------------


def test_extras_drift_evidence_carries_lock_name_and_drift_kind(tmp_path):
    mod = _load_lockfile()
    det = _load_detector()
    deps = [_make_dep(det, "psutil", det.ManifestSection.OPTIONAL_DEPENDENCIES, "demo")]
    meta = mod.LockMetadata(provides_extras=())
    findings = mod.detect_extras_drift(
        deps, meta, tmp_path / "uv.lock", mod.LockFormat.UV,
    )
    assert "lock=uv.lock" in findings[0].evidence
    assert "drift_kind=extras" in findings[0].evidence


def test_version_drift_evidence_carries_locked_and_pin(tmp_path):
    mod = _load_lockfile()
    det = _load_detector()
    deps = [_make_dep(det, "requests", det.ManifestSection.PROJECT_DEPENDENCIES,
                     spec=">=2.30,<3")]
    entries = {"requests": mod.LockEntry(name="requests", version="2.28.0", line_no=42)}
    findings = mod.detect_version_drift(
        deps, entries, tmp_path / "uv.lock", mod.LockFormat.UV,
    )
    ev = findings[0].evidence
    assert "locked=2.28.0" in ev
    assert "drift_kind=version" in ev
    assert "lock_line=42" in ev


def test_missing_from_lock_evidence_carries_drift_kind(tmp_path):
    mod = _load_lockfile()
    det = _load_detector()
    deps = [_make_dep(det, "orphan", det.ManifestSection.PROJECT_DEPENDENCIES, spec="")]
    entries = {"requests": mod.LockEntry(name="requests", version="2.31.0", line_no=1)}
    findings = mod.detect_missing_from_lock(
        deps, entries, tmp_path / "poetry.lock", mod.LockFormat.POETRY,
    )
    assert "drift_kind=missing" in findings[0].evidence
    assert "missing from poetry.lock" in findings[0].evidence


# ---------------------------------------------------------------------------
# scan_project integration — sibling lockfile discovery.
# ---------------------------------------------------------------------------


def test_scan_project_finds_sibling_uv_lock_and_emits_drift(tmp_path):
    det = _load_detector()
    _load_lockfile()  # ensure module is importable via scan_project's lazy import path
    # pyproject declares 'demo' extra and pins requests>=2.30; uv.lock has neither.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = ["requests>=2.30,<3"]\n'
        '\n'
        '[project.optional-dependencies]\n'
        'demo = ["psutil"]\n'
    )
    (tmp_path / "uv.lock").write_text(
        'version = 1\n'
        '\n'
        '[manifest]\n'
        'provides-extras = []\n'
        '\n'
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.28.0"\n'
    )
    findings = det.scan_project(tmp_path)
    rule_kinds = {
        "extras"  if "drift_kind=extras"  in f.evidence else
        "version" if "drift_kind=version" in f.evidence else
        "missing" if "drift_kind=missing" in f.evidence else
        None
        for f in findings
        if f.evidence and "drift_kind=" in f.evidence
    }
    rule_kinds.discard(None)
    assert "extras" in rule_kinds   # 'demo' missing from lock metadata
    assert "version" in rule_kinds  # requests>=2.30,<3 vs locked 2.28.0
    assert "missing" in rule_kinds  # psutil from 'demo' extra absent from lock


def test_scan_project_finds_sibling_poetry_lock_and_emits_drift(tmp_path):
    det = _load_detector()
    _load_lockfile()
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        '\n'
        '[tool.poetry.dependencies]\n'
        'python = "^3.10"\n'
        'requests = ">=2.30,<3"\n'
        'orphanpkg = "*"\n'
    )
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.28.0"\n'
    )
    findings = det.scan_project(tmp_path)
    drift_findings = [f for f in findings if "drift_kind=" in (f.evidence or "")]
    rule_kinds = set()
    for f in drift_findings:
        if "drift_kind=version" in f.evidence:
            rule_kinds.add("version")
        if "drift_kind=missing" in f.evidence:
            rule_kinds.add("missing")
    assert "version" in rule_kinds
    assert "missing" in rule_kinds


def test_scan_project_lockfile_inside_excluded_subpath_is_skipped(tmp_path):
    det = _load_detector()
    _load_lockfile()
    excluded = tmp_path / "vendored"
    excluded.mkdir()
    (excluded / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = ["requests>=2.30,<3"]\n'
    )
    (excluded / "uv.lock").write_text(
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.28.0"\n'
    )
    # Without exclusion: drift fires.
    unfiltered = det.scan_project(tmp_path)
    assert any("drift_kind=" in (f.evidence or "") for f in unfiltered)
    # With exclusion: zero drift findings.
    filtered = det.scan_project(tmp_path, excluded=["vendored"])
    assert not any("drift_kind=" in (f.evidence or "") for f in filtered)


def test_scan_project_safe_lockfile_emits_zero_drift_findings(tmp_path):
    det = _load_detector()
    _load_lockfile()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = ["requests==2.31.0"]\n'
        '\n'
        '[project.optional-dependencies]\n'
        'test = ["pytest==8.0.0"]\n'
    )
    (tmp_path / "uv.lock").write_text(
        'version = 1\n'
        '\n'
        '[manifest]\n'
        'provides-extras = ["test"]\n'
        '\n'
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.31.0"\n'
        '\n'
        '[[package]]\n'
        'name = "pytest"\n'
        'version = "8.0.0"\n'
    )
    findings = det.scan_project(tmp_path)
    drift = [f for f in findings if "drift_kind=" in (f.evidence or "")]
    assert drift == []
