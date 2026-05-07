#!/usr/bin/env python3
"""Detection primitives for scout-supply-chain.

Parses Python dependency manifests and flags four classes of issue:

  - Unpinned deps (CWE-1104). Severity HIGH if the name substring-matches
    a short curated "security-critical" list (crypto/auth/http/yaml/etc.);
    LOW otherwise.
  - Source-specific risks (CWE-829). Git/http/file URLs or local paths.
    HIGH if not commit-SHA-pinned; MEDIUM otherwise.
  - Typosquat (CWE-20 / CWE-1357-family). Curated short list of known
    misspellings. MEDIUM with confidence MEDIUM.
  - Dev-dep leaks (CWE-1120). pytest/bandit/ruff/mypy/etc. declared in
    runtime deps (not dev-group).

Section-aware behaviour:
  - Walks [project.dependencies], [project.optional-dependencies],
    [dependency-groups] (PEP 735), [build-system].requires,
    [tool.poetry.dependencies], and [tool.poetry.group.*.dependencies].
  - Severity for opt-in sections (optional-dependencies / dependency-groups
    / non-canonical Poetry groups) is floored to LOW unless the package
    name or extra/group name is security-bearing — see _opt_in_severity().
  - Each finding's evidence carries (section=..., extra=...) annotation.

Invoked from the scout-supply-chain persona via:
    python .claude/tools/scout_supply_chain_detect.py <target_root>

Prints JSONL findings to stdout; every finding has poc_applicable: False.

Pure-function; no network; no external database.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from enum import Enum
from pathlib import Path
from typing import Iterable


class ManifestSection(str, Enum):
    """The manifest section a Dependency was found in.

    Values mirror their TOML path so they read cleanly in evidence strings.
    """
    PROJECT_DEPENDENCIES   = "project.dependencies"
    OPTIONAL_DEPENDENCIES  = "project.optional-dependencies"
    DEPENDENCY_GROUPS      = "dependency-groups"
    BUILD_SYSTEM_REQUIRES  = "build-system.requires"
    POETRY_DEPENDENCIES    = "tool.poetry.dependencies"
    POETRY_GROUP           = "tool.poetry.group"
    REQUIREMENTS_TXT       = "requirements.txt"


# Sections whose dependencies require explicit opt-in (an extra/group selector
# at install time). Severity is floored to "low" for these unless the package
# name or the extra/group name itself is security-bearing — see
# _opt_in_severity().
OPT_IN_SECTIONS: frozenset[ManifestSection] = frozenset({
    ManifestSection.OPTIONAL_DEPENDENCIES,
    ManifestSection.DEPENDENCY_GROUPS,
    ManifestSection.POETRY_GROUP,
})


# Substring-based severity calibration for unpinned deps. Case-insensitive
# match on the dep name. Keep short and conservative.
CRITICAL_NAME_SUBSTRINGS: tuple[str, ...] = (
    "crypto", "auth", "jwt", "request", "http", "urllib",
    "ssl", "tls", "yaml", "pickle", "secret", "oauth", "paramiko",
)

# Exact typosquat misspelling -> intended target. Static curated list.
TYPOSQUATS: dict[str, str] = {
    "requets": "requests",
    "urlib3": "urllib3",
    "pyyml": "pyyaml",
    "beautifulsop4": "beautifulsoup4",
    "python-dateutils": "python-dateutil",
    "djano": "django",
    "flsk": "flask",
    "fastap1": "fastapi",
}

# Dev-tooling names that should never appear in runtime dep lists.
DEV_TOOL_NAMES: tuple[str, ...] = (
    "pytest", "bandit", "ruff", "mypy", "black",
    "coverage", "flake8", "isort",
)

# A 40-char lowercase hex string is our commit-SHA pin marker.
_COMMIT_SHA_RE = re.compile(r"@[0-9a-f]{40}\b")

# PEP 508 name extraction (sloppy but sufficient for the narrow scope).
_PEP508_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")


@dataclasses.dataclass(frozen=True)
class Dependency:
    name: str
    spec: str       # everything after the name (may be "", "==1.0", git URL, etc.)
    source_file: str
    source_line: int
    manifest_section: ManifestSection
    extra_name: str | None = None  # the [extra]/group name when applicable


@dataclasses.dataclass(frozen=True)
class Finding:
    name: str
    cwe: str
    severity: str       # "critical" | "high" | "medium" | "low"
    confidence: str     # "high" | "medium" | "low"
    source_file: str
    source_line: int
    description: str
    evidence: str
    suspected_target: str | None = None  # typosquats only
    poc_applicable: bool = False
    manifest_section: ManifestSection | None = None
    extra_name: str | None = None


def _is_critical_name(name: str) -> bool:
    low = name.lower()
    return any(s in low for s in CRITICAL_NAME_SUBSTRINGS)


def _opt_in_severity(d: Dependency, name_severity: str) -> str:
    """Apply the D3 severity floor for opt-in manifest sections.

    Rule:
      - If section is not in OPT_IN_SECTIONS → severity unchanged.
      - If package name is security-bearing → preserve severity.
      - If extra/group name is security-bearing → preserve severity.
      - Otherwise → floor to "low".

    Tested directly via `test_opt_in_severity_*`; refactor with care.
    """
    if d.manifest_section not in OPT_IN_SECTIONS:
        return name_severity
    if _is_critical_name(d.name):
        return name_severity
    if d.extra_name and _is_critical_name(d.extra_name):
        return name_severity
    return "low"


def parse_pyproject(path: Path) -> list[Dependency]:
    """Extract dependency entries from every supported pyproject section.

    Walks:
      - [project.dependencies]
      - [project.optional-dependencies]
      - [dependency-groups] (PEP 735)
      - [build-system].requires
      - [tool.poetry.dependencies]
      - [tool.poetry.group.<name>.dependencies]

    Uses tomllib (stdlib on py3.11+).
    """
    import tomllib  # stdlib on Python 3.11+
    raw = path.read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))
    out: list[Dependency] = []

    project = data.get("project", {})

    # [project].dependencies — list of PEP 508 strings.
    for i, entry in enumerate(project.get("dependencies", []) or [], start=1):
        dep = _parse_pep508(
            entry, str(path), i, ManifestSection.PROJECT_DEPENDENCIES,
        )
        if dep is not None:
            out.append(dep)

    # [project.optional-dependencies] — dict[str, list[str]] keyed by extras name.
    for extra_name, entries in (project.get("optional-dependencies", {}) or {}).items():
        for i, entry in enumerate(entries or [], start=1):
            dep = _parse_pep508(
                entry, str(path), i,
                ManifestSection.OPTIONAL_DEPENDENCIES,
                extra_name=extra_name,
            )
            if dep is not None:
                out.append(dep)

    # [dependency-groups] (PEP 735) — dict[str, list[str | dict]] keyed by group name.
    # List entries that are dicts (e.g. {"include-group": "test"}) are skipped
    # with a stderr log line — group inclusion resolution is out of scope.
    for group_name, entries in (data.get("dependency-groups", {}) or {}).items():
        for i, entry in enumerate(entries or [], start=1):
            if isinstance(entry, dict):
                print(
                    f"scout_supply_chain_detect: skipping dependency-groups."
                    f"{group_name} entry {entry!r} (include-group / non-string)",
                    file=sys.stderr,
                )
                continue
            if not isinstance(entry, str):
                continue
            dep = _parse_pep508(
                entry, str(path), i,
                ManifestSection.DEPENDENCY_GROUPS,
                extra_name=group_name,
            )
            if dep is not None:
                out.append(dep)

    # [build-system].requires — list of PEP 508 strings, runs at install time.
    build_system = data.get("build-system", {})
    for i, entry in enumerate(build_system.get("requires", []) or [], start=1):
        if not isinstance(entry, str):
            continue
        dep = _parse_pep508(
            entry, str(path), i,
            ManifestSection.BUILD_SYSTEM_REQUIRES,
        )
        if dep is not None:
            out.append(dep)

    # [tool.poetry.dependencies] — mapping.
    poetry = data.get("tool", {}).get("poetry", {})
    if not isinstance(poetry, dict):
        return out
    poetry_deps = poetry.get("dependencies", {})
    if not isinstance(poetry_deps, dict):
        poetry_deps = {}
    for i, (name, spec) in enumerate(poetry_deps.items(), start=1):
        if name == "python":
            continue
        spec_str = spec if isinstance(spec, str) else json.dumps(spec, sort_keys=True)
        out.append(Dependency(
            name=name,
            spec=spec_str,
            source_file=str(path),
            source_line=i,
            manifest_section=ManifestSection.POETRY_DEPENDENCIES,
        ))

    # [tool.poetry.group.<name>.dependencies] — non-canonical Poetry groups.
    for group_name, group in (poetry.get("group", {}) or {}).items():
        deps_map = group.get("dependencies", {}) if isinstance(group, dict) else {}
        for i, (name, spec) in enumerate(deps_map.items(), start=1):
            if name == "python":
                continue
            spec_str = spec if isinstance(spec, str) else json.dumps(spec, sort_keys=True)
            out.append(Dependency(
                name=name,
                spec=spec_str,
                source_file=str(path),
                source_line=i,
                manifest_section=ManifestSection.POETRY_GROUP,
                extra_name=group_name,
            ))

    return out


def parse_requirements(path: Path) -> list[Dependency]:
    """Extract dependency entries from a requirements*.txt file.

    Lines starting with `-` (e.g. `-r other.txt`, `-e .`, `--hash`) are
    skipped — `-r` reference following is out of scope.
    """
    out: list[Dependency] = []
    for i, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        dep = _parse_pep508(
            line, str(path), i, ManifestSection.REQUIREMENTS_TXT,
        )
        if dep is not None:
            out.append(dep)
    return out


def _parse_pep508(
    entry: str,
    source_file: str,
    source_line: int,
    manifest_section: ManifestSection,
    extra_name: str | None = None,
) -> Dependency | None:
    if not isinstance(entry, str):
        return None
    at_split = entry.split(" @ ", 1)
    head = at_split[0]
    tail = (" @ " + at_split[1]) if len(at_split) == 2 else ""
    m = _PEP508_NAME_RE.match(head)
    if not m:
        return None
    name = m.group(1)
    spec_tail = head[len(m.group(0)):] + tail
    return Dependency(
        name=name,
        spec=spec_tail.strip(),
        source_file=source_file,
        source_line=source_line,
        manifest_section=manifest_section,
        extra_name=extra_name,
    )


def detect_unpinned(deps: Iterable[Dependency]) -> list[Finding]:
    findings: list[Finding] = []
    for d in deps:
        # URL-sourced deps are handled separately; skip them here.
        if "@ git+" in d.spec or "@ http" in d.spec or "@ file://" in d.spec:
            continue
        spec = d.spec.strip()
        # Exact-pin marker: "==X.Y.Z".
        if spec.startswith("==") and not spec.startswith("==="):
            continue
        # "===X.Y.Z" arbitrary-equality is also a pin.
        if spec.startswith("==="):
            continue
        base = "high" if _is_critical_name(d.name) else "low"
        severity = _opt_in_severity(d, base)
        findings.append(Finding(
            name=d.name,
            cwe="CWE-1104",
            severity=severity,
            confidence="high",
            source_file=d.source_file,
            source_line=d.source_line,
            description=f"Dependency {d.name!r} declared without an exact == pin (spec: {spec or '<bare>'}).",
            evidence=f"{d.source_file}:{d.source_line}: {d.name}{spec}",
            manifest_section=d.manifest_section,
            extra_name=d.extra_name,
        ))
    return findings


def detect_source_risks(deps: Iterable[Dependency]) -> list[Finding]:
    findings: list[Finding] = []
    for d in deps:
        spec = d.spec
        is_url_sourced = any(
            marker in spec
            for marker in ("@ git+", "@ http://", "@ https://", "@ file://")
        )
        if not is_url_sourced:
            continue
        commit_pinned = bool(_COMMIT_SHA_RE.search(spec))
        severity = "medium" if commit_pinned else "high"
        findings.append(Finding(
            name=d.name,
            cwe="CWE-829",
            severity=severity,
            confidence="high",
            source_file=d.source_file,
            source_line=d.source_line,
            description=(
                f"Dependency {d.name!r} is declared with a URL source "
                f"({'pinned to a commit SHA' if commit_pinned else 'not pinned to a commit SHA'})."
            ),
            evidence=f"{d.source_file}:{d.source_line}: {d.name} {spec}",
            manifest_section=d.manifest_section,
            extra_name=d.extra_name,
        ))
    return findings


def detect_typosquats(deps: Iterable[Dependency]) -> list[Finding]:
    findings: list[Finding] = []
    for d in deps:
        target = TYPOSQUATS.get(d.name.lower())
        if target is None:
            continue
        findings.append(Finding(
            name=d.name,
            cwe="CWE-1357",
            severity="medium",
            confidence="medium",
            source_file=d.source_file,
            source_line=d.source_line,
            description=(
                f"Dependency name {d.name!r} matches a known typosquat of {target!r}."
            ),
            evidence=f"{d.source_file}:{d.source_line}: {d.name}",
            suspected_target=target,
            manifest_section=d.manifest_section,
            extra_name=d.extra_name,
        ))
    return findings


def detect_dev_dep_leaks(deps: Iterable[Dependency]) -> list[Finding]:
    findings: list[Finding] = []
    for d in deps:
        # Opt-in sections are exactly where dev tooling belongs (extras like
        # [test], dependency-groups [dev], non-canonical Poetry groups).
        # Build-system.requires keeps the check (pytest there is still wrong).
        if d.manifest_section in OPT_IN_SECTIONS:
            continue
        low = d.name.lower()
        # Exact-name match against dev-tool names. Substring match would
        # false-positive on e.g. pytest-httpserver being legitimate.
        if low in DEV_TOOL_NAMES:
            findings.append(Finding(
                name=d.name,
                cwe="CWE-1120",
                severity="low",
                confidence="medium",
                source_file=d.source_file,
                source_line=d.source_line,
                description=(
                    f"Dev-tooling dependency {d.name!r} appears in a runtime "
                    f"dependency list. Consider moving it to a dev group."
                ),
                evidence=f"{d.source_file}:{d.source_line}: {d.name}",
                manifest_section=d.manifest_section,
                extra_name=d.extra_name,
            ))
    return findings


def scan_project(target_root: Path, excluded: list[str] | None = None) -> list[Finding]:
    """Scan every manifest under target_root and return aggregated findings.

    `excluded` is a list of subpath names (relative to target_root) to skip.
    Path-prefix match: excluding "docs" also excludes "docs/source/...".
    """
    excluded_paths = [
        (target_root / sub).resolve() for sub in (excluded or [])
    ]

    def _is_excluded(p: Path) -> bool:
        try:
            resolved = p.resolve()
        except OSError:
            return False
        for ep in excluded_paths:
            try:
                if resolved == ep or resolved.is_relative_to(ep):
                    return True
            except ValueError:
                continue
        return False

    deps: list[Dependency] = []
    pyproject_paths: list[Path] = []
    for pp in target_root.rglob("pyproject.toml"):
        if _is_excluded(pp):
            continue
        try:
            pp_deps = parse_pyproject(pp)
            deps.extend(pp_deps)
            pyproject_paths.append(pp)
        except Exception as e:
            print(f"scout_supply_chain_detect: skipped {pp}: {e}", file=sys.stderr)
    for rr in target_root.rglob("requirements*.txt"):
        if _is_excluded(rr):
            continue
        try:
            deps.extend(parse_requirements(rr))
        except Exception as e:
            print(f"scout_supply_chain_detect: skipped {rr}: {e}", file=sys.stderr)
    findings: list[Finding] = []
    findings.extend(detect_unpinned(deps))
    findings.extend(detect_source_risks(deps))
    findings.extend(detect_typosquats(deps))
    findings.extend(detect_dev_dep_leaks(deps))
    findings.extend(_scan_lockfiles(pyproject_paths, deps, _is_excluded))
    return findings


def _scan_lockfiles(
    pyproject_paths: list[Path],
    deps: list[Dependency],
    is_excluded,
) -> list[Finding]:
    """Discover sibling uv.lock / poetry.lock and dispatch drift detectors.

    Lazy-imports scout_supply_chain_lockfile to keep the module pure-Python
    importable even if `packaging` is missing (D10). The lockfile module
    then makes its own runtime decision about version-drift availability.
    """
    try:
        from scout_supply_chain_lockfile import (
            LockFormat,
            parse_uv_lock,
            parse_poetry_lock,
            detect_extras_drift,
            detect_version_drift,
            detect_missing_from_lock,
        )
    except ImportError as e:
        print(
            f"scout_supply_chain_detect: lockfile module unavailable ({e}); "
            f"skipping lockfile-drift detection.",
            file=sys.stderr,
        )
        return []
    findings: list[Finding] = []
    pp_deps_map: dict[Path, list[Dependency]] = {}
    for d in deps:
        pp = Path(d.source_file)
        pp_deps_map.setdefault(pp, []).append(d)
    for pp in pyproject_paths:
        pp_deps = pp_deps_map.get(pp, [])
        for lock_name, lock_format, parser in (
            ("uv.lock", LockFormat.UV, parse_uv_lock),
            ("poetry.lock", LockFormat.POETRY, parse_poetry_lock),
        ):
            lock_path = pp.parent / lock_name
            if not lock_path.exists():
                continue
            if is_excluded(lock_path):
                continue
            try:
                entries, meta = parser(lock_path)
            except Exception as e:
                print(
                    f"scout_supply_chain_detect: skipped {lock_path}: {e}",
                    file=sys.stderr,
                )
                continue
            findings.extend(detect_extras_drift(pp_deps, meta, lock_path, lock_format))
            findings.extend(detect_version_drift(pp_deps, entries, lock_path, lock_format))
            findings.extend(detect_missing_from_lock(pp_deps, entries, lock_path, lock_format))
    return findings


def _finding_to_jsonl(
    f: Finding,
    finding_id: str,
) -> dict:
    cwe_list = [f.cwe]
    evidence = f.evidence
    if f.manifest_section is not None:
        suffix = f" (section={f.manifest_section.value}"
        if f.extra_name:
            suffix += f", extra={f.extra_name}"
        suffix += ")"
        evidence = evidence + suffix
    return {
        "id": finding_id,
        "scout": "scout-supply-chain",
        "status": "CANDIDATE",
        "title": f.description,
        "cwe": cwe_list,
        "severity": f.severity,
        "confidence": f.confidence,
        "file": f.source_file,
        "line_range": [f.source_line, f.source_line],
        "description": f.description,
        "evidence": evidence,
        "poc_applicable": f.poc_applicable,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="scout-supply-chain detection primitives"
    )
    parser.add_argument("target", help="Target directory (usually scope.target_root)")
    parser.add_argument(
        "--exclude-subpath",
        action="append",
        default=[],
        metavar="SUBPATH",
        help=(
            "Subpath under the target to skip when enumerating manifests. "
            "Repeatable. Path-prefix match. Wire from scope.excluded_subpaths."
        ),
    )
    parser.add_argument("--id-prefix", default="FND-SUP-", help="Finding-ID prefix")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    findings = scan_project(target, excluded=args.exclude_subpath)
    for i, f in enumerate(findings, start=1):
        rec = _finding_to_jsonl(f, f"{args.id_prefix}{i:04d}")
        print(json.dumps(rec))


if __name__ == "__main__":
    main()
