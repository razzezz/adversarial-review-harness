#!/usr/bin/env python3
"""Lockfile-drift detection primitives for scout-supply-chain.

Parses uv.lock / poetry.lock and compares against the host pyproject's
declared deps. Emits three drift patterns:

  - extras-drift     — pyproject declares an extra not present in lock metadata
  - version-drift    — manifest specifier disagrees with the locked version
  - missing-from-lock — declared dep absent from the lock entirely

Severity inherits scout_supply_chain_detect's `_opt_in_severity` calibration
— LOW unless the package name or extra-name is security-bearing.

Imported by scout_supply_chain_detect.scan_project; not invoked directly.
"""

from __future__ import annotations

import dataclasses
import re
import sys
import tomllib
from enum import Enum
from pathlib import Path

from scout_supply_chain_detect import (
    Dependency,
    Finding,
    ManifestSection,
    OPT_IN_SECTIONS,
    _is_critical_name,
    _opt_in_severity,
)


class LockFormat(str, Enum):
    """Which lockfile schema we're reading. Drives the parser dispatch."""
    UV     = "uv.lock"
    POETRY = "poetry.lock"


@dataclasses.dataclass(frozen=True)
class LockEntry:
    """A single locked package's identity for drift comparison."""
    name: str       # canonical (PEP 503-normalized — lowercase, [-_.] runs → '-')
    version: str    # e.g. "2.28.0"
    line_no: int    # source line in the lock for evidence (best-effort)


@dataclasses.dataclass(frozen=True)
class LockMetadata:
    """Lock-level metadata fields used for drift comparison.

    `provides_extras` is the only field: it drives extras-drift detection by
    letting detect_extras_drift check whether each pyproject-declared extra is
    present in the lock's metadata.

    For uv.lock: read from the top-level [manifest].provides-extras list.
    For poetry.lock: synthesized as the union of all [[package]].extras keys.
    """
    provides_extras: tuple[str, ...]


def _canonicalize(name: str) -> str:
    """PEP 503 name normalization: lowercase + runs of [-_.] collapse to '-'.

    Avoids false LOCK-DRIFT-MISSING when manifest writes 'Foo_Bar' but lock
    stores 'foo-bar'.
    """
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def parse_uv_lock(path: Path) -> tuple[dict[str, LockEntry], LockMetadata]:
    """Parse a uv.lock file into (entries-by-canonical-name, metadata).

    uv.lock schema (uv 0.4+):
      version = 1
      [manifest]
      provides-extras = [...]
      [[package]]
      name = "..."
      version = "..."

    Returns ({}, LockMetadata(())) on any parse error — never raises.
    """
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
        return {}, LockMetadata(provides_extras=())
    try:
        entries: dict[str, LockEntry] = {}
        for i, pkg in enumerate(data.get("package", []) or [], start=1):
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            canonical = _canonicalize(name)
            entries[canonical] = LockEntry(
                name=canonical, version=version, line_no=i,
            )
        manifest = data.get("manifest", {})
        if isinstance(manifest, dict):
            extras_raw = manifest.get("provides-extras", []) or []
            provides_extras = tuple(
                e for e in extras_raw if isinstance(e, str)
            )
        else:
            provides_extras = ()
        return entries, LockMetadata(provides_extras=provides_extras)
    except (KeyError, TypeError, ValueError):
        return {}, LockMetadata(provides_extras=())


def parse_poetry_lock(path: Path) -> tuple[dict[str, LockEntry], LockMetadata]:
    """Parse a poetry.lock file into (entries-by-canonical-name, metadata).

    poetry.lock schema (poetry 1.5+):
      [[package]]
      name = "..."
      version = "..."
      [package.extras]
      <extra_name> = ["dep1", ...]

    `provides_extras` is synthesized as the union of all [[package]].extras
    keys across the lock. Returns ({}, LockMetadata(())) on any parse error.
    """
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
        return {}, LockMetadata(provides_extras=())
    try:
        entries: dict[str, LockEntry] = {}
        extras_seen: set[str] = set()
        for i, pkg in enumerate(data.get("package", []) or [], start=1):
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            canonical = _canonicalize(name)
            entries[canonical] = LockEntry(
                name=canonical, version=version, line_no=i,
            )
            extras_block = pkg.get("extras", {})
            if isinstance(extras_block, dict):
                for extra_name in extras_block:
                    if isinstance(extra_name, str):
                        extras_seen.add(extra_name)
        return entries, LockMetadata(
            provides_extras=tuple(sorted(extras_seen)),
        )
    except (KeyError, TypeError, ValueError):
        return {}, LockMetadata(provides_extras=())


def detect_extras_drift(
    deps: list[Dependency],
    meta: LockMetadata,
    lock_path: Path,
    lock_format: LockFormat,
) -> list[Finding]:
    """Emit one Finding per declared extra absent from the lock's metadata.

    Aggregates per-extra rather than per-package: an extra's absence is a
    metadata-level mismatch that affects all packages within it, so a
    single finding per extra is the right granularity.
    """
    declared_extras: dict[str, Dependency] = {}
    for d in deps:
        if d.manifest_section != ManifestSection.OPTIONAL_DEPENDENCIES:  # != not 'is not': enum identity is not preserved across importlib reloads in tests
            continue
        if d.extra_name and d.extra_name not in declared_extras:
            declared_extras[d.extra_name] = d
    findings: list[Finding] = []
    locked_extras = set(meta.provides_extras)
    for extra_name, sample_dep in declared_extras.items():
        if extra_name in locked_extras:
            continue
        # Extras-drift is metadata-level (no underlying package version to assess),
        # so baseline stays "low" and never bumps to MEDIUM — _opt_in_severity
        # directly rather than _critical_severity.
        severity = _opt_in_severity(sample_dep, "low")
        findings.append(Finding(
            name=f"<extra:{extra_name}>",
            cwe="CWE-1104",
            severity=severity,
            confidence="high",
            source_file=sample_dep.source_file,
            source_line=sample_dep.source_line,
            description=(
                f"Extra {extra_name!r} declared in pyproject "
                f"[project.optional-dependencies] is not present in "
                f"{lock_format.value} metadata (provides_extras)."
            ),
            evidence=(
                f"{sample_dep.source_file}:{sample_dep.source_line}: extra={extra_name!r}; "
                f"locked_extras={sorted(locked_extras)} "
                f"[lock={lock_path.name}; drift_kind=extras]"
            ),
            manifest_section=ManifestSection.OPTIONAL_DEPENDENCIES,
            extra_name=extra_name,
        ))
    return findings


# Optional dep (D10): packaging.specifiers for PEP 440 specifier matching.
# If missing, detect_version_drift becomes a no-op (logs once to stderr).
try:
    from packaging.specifiers import SpecifierSet, InvalidSpecifier
    from packaging.version import Version, InvalidVersion
    _PACKAGING_AVAILABLE = True
except ImportError:
    _PACKAGING_AVAILABLE = False

_VERSION_DRIFT_WARNED = False


def _critical_severity(d: Dependency) -> str:
    """Drift baseline is 'low'; critical-name bumps to 'medium'.

    For opt-in sections, _opt_in_severity preserves the bump only when the
    package or extra name is security-bearing — otherwise the floor is 'low'.
    """
    if _is_critical_name(d.name):
        base = "medium"
    elif d.extra_name and _is_critical_name(d.extra_name):
        base = "medium"
    else:
        base = "low"
    return _opt_in_severity(d, base)


def detect_version_drift(
    deps: list[Dependency],
    entries: dict[str, LockEntry],
    lock_path: Path,
    lock_format: LockFormat,
) -> list[Finding]:
    """Emit Findings for declared deps whose specifier disagrees with the lock."""
    global _VERSION_DRIFT_WARNED
    if not _PACKAGING_AVAILABLE:
        if not _VERSION_DRIFT_WARNED:
            print(
                "scout_supply_chain_lockfile: 'packaging' not importable; "
                "version-drift detection disabled (D10 fallback).",
                file=sys.stderr,
            )
            _VERSION_DRIFT_WARNED = True
        return []
    findings: list[Finding] = []
    for d in deps:
        spec = d.spec.strip()
        if not spec:
            continue
        canonical = _canonicalize(d.name)
        entry = entries.get(canonical)
        if entry is None:
            continue  # missing-from-lock handles this
        try:
            spec_set = SpecifierSet(spec)
            locked_v = Version(entry.version)
        except (InvalidSpecifier, InvalidVersion, TypeError):
            continue
        if locked_v in spec_set:
            continue
        severity = _critical_severity(d)
        findings.append(Finding(
            name=d.name,
            cwe="CWE-1104",
            severity=severity,
            confidence="high",
            source_file=d.source_file,
            source_line=d.source_line,
            description=(
                f"Dependency {d.name!r} pin {spec!r} disagrees with "
                f"locked version {entry.version!r} in {lock_format.value}."
            ),
            evidence=(
                f"{d.source_file}:{d.source_line}: {d.name}{spec} -> locked={entry.version} "
                f"[lock={lock_path.name}; drift_kind=version; lock_line={entry.line_no}]"
            ),
            manifest_section=d.manifest_section,
            extra_name=d.extra_name,
        ))
    return findings


def detect_missing_from_lock(
    deps: list[Dependency],
    entries: dict[str, LockEntry],
    lock_path: Path,
    lock_format: LockFormat,
) -> list[Finding]:
    """Emit Findings for declared deps with no entry in the lock.

    Short-circuits when the lock is empty (D7): the empty case is
    indistinguishable from "no lock present" semantically, so we emit
    nothing rather than flooding with one finding per declared dep.
    """
    if not entries:
        return []
    findings: list[Finding] = []
    for d in deps:
        canonical = _canonicalize(d.name)
        if canonical in entries:
            continue
        severity = _critical_severity(d)
        findings.append(Finding(
            name=d.name,
            cwe="CWE-1104",
            severity=severity,
            confidence="high",
            source_file=d.source_file,
            source_line=d.source_line,
            description=(
                f"Dependency {d.name!r} declared in pyproject "
                f"[{d.manifest_section.value}] has no entry in {lock_format.value}."
            ),
            evidence=(
                f"{d.source_file}:{d.source_line}: {d.name} [missing from {lock_path.name}; "
                f"drift_kind=missing]"
            ),
            manifest_section=d.manifest_section,
            extra_name=d.extra_name,
        ))
    return findings
