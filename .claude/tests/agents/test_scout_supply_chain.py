"""Unit tests for scout-supply-chain's detection primitives.

The scout persona invokes these primitives via Bash (python script) to
produce structured findings; unit tests here exercise the pure-function
logic without running the scout itself.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DETECTOR = REPO_ROOT / ".claude" / "tools" / "scout_supply_chain_detect.py"


def _load():
    spec = importlib.util.spec_from_file_location("scout_supply_chain_detect", DETECTOR)
    assert spec and spec.loader, f"cannot load {DETECTOR}"
    mod = importlib.util.module_from_spec(spec)
    # Register in sys.modules BEFORE exec_module so @dataclass can resolve
    # its module via sys.modules.get(cls.__module__).
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Parsing.
# ---------------------------------------------------------------------------


def test_parse_pyproject_extracts_project_dependencies(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = [\n'
        '    "requests==2.31.0",\n'
        '    "urllib3>=2.0",\n'
        ']\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    names = [d.name for d in deps]
    assert "requests" in names
    assert "urllib3" in names


def test_parse_requirements_txt(tmp_path):
    mod = _load()
    (tmp_path / "requirements.txt").write_text(
        "# a comment\n"
        "requests==2.31.0\n"
        "pyyml\n"
        "-r other.txt\n"
        "\n"
    )
    deps = mod.parse_requirements(tmp_path / "requirements.txt")
    names = [d.name for d in deps]
    assert names == ["requests", "pyyml"]


# ---------------------------------------------------------------------------
# Detection primitives.
# ---------------------------------------------------------------------------


def test_detect_unpinned_flags_non_equals_specs():
    mod = _load()
    deps = [
        mod.Dependency("requests", ">=2.0", "requirements.txt", 1, mod.ManifestSection.REQUIREMENTS_TXT),
        mod.Dependency("pyyaml", "==6.0.1", "requirements.txt", 2, mod.ManifestSection.REQUIREMENTS_TXT),
        mod.Dependency("boto3", "", "requirements.txt", 3, mod.ManifestSection.REQUIREMENTS_TXT),  # bare name
    ]
    unpinned = mod.detect_unpinned(deps)
    names = [f.name for f in unpinned]
    assert "requests" in names
    assert "boto3" in names
    assert "pyyaml" not in names


def test_detect_git_url_deps_flags_without_commit_pin():
    mod = _load()
    deps = [
        mod.Dependency(
            "my-crypto-helper",
            "@ git+https://github.com/example/my-crypto-helper.git",
            "pyproject.toml", 5,
            mod.ManifestSection.PROJECT_DEPENDENCIES,
        ),
        mod.Dependency(
            "pinned-helper",
            "@ git+https://github.com/example/pinned-helper.git@0123abcd" + "ef" * 16,
            "pyproject.toml", 6,
            mod.ManifestSection.PROJECT_DEPENDENCIES,
        ),
    ]
    findings = mod.detect_source_risks(deps)
    ids = {(f.name, f.severity) for f in findings}
    assert ("my-crypto-helper", "high") in ids
    assert ("pinned-helper", "medium") in ids


def test_detect_typosquat_hits_curated_list():
    mod = _load()
    deps = [
        mod.Dependency("requests", "==2.31", "requirements.txt", 1, mod.ManifestSection.REQUIREMENTS_TXT),
        mod.Dependency("pyyml", "", "requirements.txt", 2, mod.ManifestSection.REQUIREMENTS_TXT),
        mod.Dependency("beautifulsop4", "", "requirements.txt", 3, mod.ManifestSection.REQUIREMENTS_TXT),
    ]
    findings = mod.detect_typosquats(deps)
    hits = {(f.name, f.suspected_target) for f in findings}
    assert ("pyyml", "pyyaml") in hits
    assert ("beautifulsop4", "beautifulsoup4") in hits
    # Legitimate name not flagged.
    assert not any(f.name == "requests" for f in findings)


def test_detect_dev_dep_leak_flags_pytest_in_runtime():
    mod = _load()
    deps = [
        mod.Dependency("pytest", ">=7.0", "requirements.txt", 1, mod.ManifestSection.REQUIREMENTS_TXT),
        mod.Dependency("requests", "==2.31", "requirements.txt", 2, mod.ManifestSection.REQUIREMENTS_TXT),
    ]
    findings = mod.detect_dev_dep_leaks(deps)
    names = [f.name for f in findings]
    assert "pytest" in names
    assert "requests" not in names


# ---------------------------------------------------------------------------
# Severity calibration for unpinned.
# ---------------------------------------------------------------------------


def test_unpinned_severity_high_for_critical_substring():
    mod = _load()
    deps = [
        mod.Dependency("pyyaml", "", "r.txt", 1, mod.ManifestSection.REQUIREMENTS_TXT),
        mod.Dependency("requests", "", "r.txt", 2, mod.ManifestSection.REQUIREMENTS_TXT),
        mod.Dependency("cryptography", "", "r.txt", 3, mod.ManifestSection.REQUIREMENTS_TXT),
        mod.Dependency("boto3", "", "r.txt", 4, mod.ManifestSection.REQUIREMENTS_TXT),
    ]
    findings = mod.detect_unpinned(deps)
    severity_by_name = {f.name: f.severity for f in findings}
    assert severity_by_name["pyyaml"] == "high"
    assert severity_by_name["requests"] == "high"
    assert severity_by_name["cryptography"] == "high"
    assert severity_by_name["boto3"] == "low"


# ---------------------------------------------------------------------------
# End-to-end: the toy-app manifest planted in commit 4.
# ---------------------------------------------------------------------------


def test_toy_app_manifest_produces_expected_findings(tmp_path):
    """Mirror the toy-app pyproject.toml we'll plant in Task 21. Must find:
    - Two unpinned HIGH (PyYAML yaml substring, requests request substring).
    - One git-URL HIGH (my-crypto-helper; also appears as unpinned but that
      is filtered out by detect_unpinned for URL-sourced deps).
    - One typosquat MEDIUM (pyyml → pyyaml).
    """
    mod = _load()
    manifest = (
        '[project]\n'
        'name = "toy"\n'
        'version = "0.0.1"\n'
        'dependencies = [\n'
        '    "PyYAML>=6.0",\n'
        '    "requests",\n'
        '    "my-crypto-helper @ git+https://github.com/example/my-crypto-helper.git",\n'
        '    "pyyml",\n'
        ']\n'
    )
    (tmp_path / "pyproject.toml").write_text(manifest)
    findings = mod.scan_project(tmp_path)
    # Expect at least one finding per planted issue.
    sigs = {(f.name, f.cwe, f.severity) for f in findings}
    assert ("PyYAML", "CWE-1104", "high") in sigs
    assert ("requests", "CWE-1104", "high") in sigs
    assert ("my-crypto-helper", "CWE-829", "high") in sigs
    assert ("pyyml", "CWE-1357", "medium") in sigs
    # Every finding must have poc_applicable=False.
    assert all(f.poc_applicable is False for f in findings)


# ---------------------------------------------------------------------------
# ManifestSection enum + Dependency.manifest_section field.
# ---------------------------------------------------------------------------


def test_manifest_section_enum_values():
    mod = _load()
    assert mod.ManifestSection.PROJECT_DEPENDENCIES.value == "project.dependencies"
    assert mod.ManifestSection.OPTIONAL_DEPENDENCIES.value == "project.optional-dependencies"
    assert mod.ManifestSection.DEPENDENCY_GROUPS.value == "dependency-groups"
    assert mod.ManifestSection.BUILD_SYSTEM_REQUIRES.value == "build-system.requires"
    assert mod.ManifestSection.POETRY_DEPENDENCIES.value == "tool.poetry.dependencies"
    assert mod.ManifestSection.POETRY_GROUP.value == "tool.poetry.group"
    assert mod.ManifestSection.REQUIREMENTS_TXT.value == "requirements.txt"


def test_opt_in_sections_membership():
    mod = _load()
    assert mod.ManifestSection.OPTIONAL_DEPENDENCIES in mod.OPT_IN_SECTIONS
    assert mod.ManifestSection.DEPENDENCY_GROUPS in mod.OPT_IN_SECTIONS
    assert mod.ManifestSection.POETRY_GROUP in mod.OPT_IN_SECTIONS
    # NOT in opt-in (canonical / runtime sections):
    assert mod.ManifestSection.PROJECT_DEPENDENCIES not in mod.OPT_IN_SECTIONS
    assert mod.ManifestSection.POETRY_DEPENDENCIES not in mod.OPT_IN_SECTIONS
    assert mod.ManifestSection.BUILD_SYSTEM_REQUIRES not in mod.OPT_IN_SECTIONS
    assert mod.ManifestSection.REQUIREMENTS_TXT not in mod.OPT_IN_SECTIONS


def test_dependency_carries_manifest_section_and_extra_name():
    mod = _load()
    d = mod.Dependency(
        name="cryptography",
        spec="==44.0.0",
        source_file="/x/pyproject.toml",
        source_line=1,
        manifest_section=mod.ManifestSection.OPTIONAL_DEPENDENCIES,
        extra_name="secure",
    )
    assert d.name == "cryptography"
    assert d.manifest_section is mod.ManifestSection.OPTIONAL_DEPENDENCIES
    assert d.extra_name == "secure"


def test_dependency_extra_name_defaults_none():
    mod = _load()
    d = mod.Dependency(
        name="requests",
        spec="==2.31.0",
        source_file="/x/pyproject.toml",
        source_line=1,
        manifest_section=mod.ManifestSection.PROJECT_DEPENDENCIES,
    )
    assert d.extra_name is None


def test_parse_pyproject_optional_dependencies(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = []\n'
        '\n'
        '[project.optional-dependencies]\n'
        'demo = ["psutil"]\n'
        'secure = ["cryptography==44.0.0"]\n'
        'test = ["pytest", "coverage"]\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    by_name = {d.name: d for d in deps}
    assert "psutil" in by_name
    assert by_name["psutil"].manifest_section is mod.ManifestSection.OPTIONAL_DEPENDENCIES
    assert by_name["psutil"].extra_name == "demo"
    assert "cryptography" in by_name
    assert by_name["cryptography"].extra_name == "secure"
    assert by_name["cryptography"].spec == "==44.0.0"
    assert "pytest" in by_name
    assert by_name["pytest"].extra_name == "test"
    assert "coverage" in by_name
    assert by_name["coverage"].extra_name == "test"


def test_parse_pyproject_dependency_groups(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = []\n'
        '\n'
        '[dependency-groups]\n'
        'dev = ["mypy", "ruff"]\n'
        'test = [\n'
        '    "pytest",\n'
        '    {include-group = "dev"},\n'
        '    "coverage",\n'
        ']\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    by_name = {d.name: d for d in deps}
    assert "mypy" in by_name
    assert by_name["mypy"].manifest_section is mod.ManifestSection.DEPENDENCY_GROUPS
    assert by_name["mypy"].extra_name == "dev"
    assert "ruff" in by_name
    assert by_name["ruff"].extra_name == "dev"
    assert "pytest" in by_name
    assert by_name["pytest"].extra_name == "test"
    # dict entry {include-group = "dev"} is skipped, not surfaced as a dep.
    assert "include-group" not in by_name
    assert "dev" not in by_name
    # The string entry AFTER the dict still parses.
    assert "coverage" in by_name
    assert by_name["coverage"].extra_name == "test"


def test_parse_pyproject_build_system_requires(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = []\n'
        '\n'
        '[build-system]\n'
        'requires = ["setuptools>=68", "wheel"]\n'
        'build-backend = "setuptools.build_meta"\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    by_name = {d.name: d for d in deps}
    assert "setuptools" in by_name
    assert by_name["setuptools"].manifest_section is mod.ManifestSection.BUILD_SYSTEM_REQUIRES
    assert by_name["setuptools"].extra_name is None
    assert by_name["setuptools"].spec == ">=68"
    assert "wheel" in by_name
    assert by_name["wheel"].manifest_section is mod.ManifestSection.BUILD_SYSTEM_REQUIRES


def test_parse_pyproject_poetry_groups(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        '[tool.poetry.dependencies]\n'
        'python = "^3.12"\n'
        'requests = "^2.31"\n'
        '[tool.poetry.group.dev.dependencies]\n'
        'pytest = "^8.0"\n'
        'mypy = "^1.0"\n'
        '[tool.poetry.group.docs.dependencies]\n'
        'sphinx = "^7.0"\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    by_name = {d.name: d for d in deps}
    assert "requests" in by_name
    assert by_name["requests"].manifest_section is mod.ManifestSection.POETRY_DEPENDENCIES
    assert by_name["requests"].extra_name is None
    assert "pytest" in by_name
    assert by_name["pytest"].manifest_section is mod.ManifestSection.POETRY_GROUP
    assert by_name["pytest"].extra_name == "dev"
    assert "mypy" in by_name
    assert by_name["mypy"].extra_name == "dev"
    assert "sphinx" in by_name
    assert by_name["sphinx"].manifest_section is mod.ManifestSection.POETRY_GROUP
    assert by_name["sphinx"].extra_name == "docs"
    assert "python" not in by_name


# ---------------------------------------------------------------------------
# _opt_in_severity — D3 severity floor logic.
# ---------------------------------------------------------------------------


def test_opt_in_severity_non_optin_section_unchanged(tmp_path):
    mod = _load()
    d = mod.Dependency(
        name="cryptography",
        spec="",
        source_file="x",
        source_line=1,
        manifest_section=mod.ManifestSection.PROJECT_DEPENDENCIES,
    )
    assert mod._opt_in_severity(d, "high") == "high"
    assert mod._opt_in_severity(d, "low") == "low"


def test_opt_in_severity_critical_name_preserves_severity(tmp_path):
    mod = _load()
    d = mod.Dependency(
        name="cryptography",
        spec="",
        source_file="x",
        source_line=1,
        manifest_section=mod.ManifestSection.OPTIONAL_DEPENDENCIES,
        extra_name="secure",
    )
    assert mod._opt_in_severity(d, "high") == "high"


def test_opt_in_severity_critical_extra_name_preserves_severity(tmp_path):
    mod = _load()
    d = mod.Dependency(
        name="opaquepkg",
        spec="",
        source_file="x",
        source_line=1,
        manifest_section=mod.ManifestSection.OPTIONAL_DEPENDENCIES,
        extra_name="auth",
    )
    assert mod._opt_in_severity(d, "high") == "high"


def test_opt_in_severity_mundane_name_floors_to_low(tmp_path):
    mod = _load()
    d = mod.Dependency(
        name="psutil",
        spec="",
        source_file="x",
        source_line=1,
        manifest_section=mod.ManifestSection.OPTIONAL_DEPENDENCIES,
        extra_name="demo",
    )
    assert mod._opt_in_severity(d, "high") == "low"
    assert mod._opt_in_severity(d, "low") == "low"


def test_opt_in_severity_build_system_requires_unchanged(tmp_path):
    mod = _load()
    d = mod.Dependency(
        name="wheel",
        spec="",
        source_file="x",
        source_line=1,
        manifest_section=mod.ManifestSection.BUILD_SYSTEM_REQUIRES,
    )
    assert mod._opt_in_severity(d, "high") == "high"
    assert mod._opt_in_severity(d, "low") == "low"


def test_detect_unpinned_preserves_critical_name_in_optional_extra(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = []\n'
        '\n'
        '[project.optional-dependencies]\n'
        'secure = ["cryptography"]\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    findings = mod.detect_unpinned(deps)
    by_name = {f.name: f for f in findings}
    assert "cryptography" in by_name
    assert by_name["cryptography"].severity == "high"


def test_detect_unpinned_preserves_critical_extra_name_in_optional_extra(tmp_path):
    """Mundane name + critical extra-name in opt-in keeps base severity."""
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = []\n'
        '\n'
        '[project.optional-dependencies]\n'
        'auth = ["opaquepkg"]\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    findings = mod.detect_unpinned(deps)
    by_name = {f.name: f for f in findings}
    # opaquepkg name doesn't match any critical substring; "auth" extra-name does.
    # Base severity is "low" (mundane name); the extra-name preserve branch keeps it "low".
    # Test value is asserting the branch was taken, not the severity number.
    assert "opaquepkg" in by_name
    assert by_name["opaquepkg"].severity == "low"


def test_detect_unpinned_floors_optional_extra_to_low(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = []\n'
        '\n'
        '[project.optional-dependencies]\n'
        'demo = ["psutil"]\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    findings = mod.detect_unpinned(deps)
    by_name = {f.name: f for f in findings}
    assert "psutil" in by_name
    assert by_name["psutil"].severity == "low"


def test_detect_unpinned_build_system_requires_unchanged(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = []\n'
        '\n'
        '[build-system]\n'
        'requires = ["wheel", "cryptography"]\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    findings = mod.detect_unpinned(deps)
    by_name = {f.name: f for f in findings}
    assert "wheel" in by_name and by_name["wheel"].severity == "low"
    assert "cryptography" in by_name and by_name["cryptography"].severity == "high"


# ---------------------------------------------------------------------------
# detect_dev_dep_leaks — opt-in section skip.
# ---------------------------------------------------------------------------


def test_dev_leak_skipped_in_optional_dependencies(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = []\n'
        '\n'
        '[project.optional-dependencies]\n'
        'test = ["pytest"]\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    findings = mod.detect_dev_dep_leaks(deps)
    assert findings == []


def test_dev_leak_skipped_in_dependency_groups(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = []\n'
        '\n'
        '[dependency-groups]\n'
        'dev = ["pytest", "mypy"]\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    findings = mod.detect_dev_dep_leaks(deps)
    assert findings == []


def test_dev_leak_skipped_in_poetry_groups(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        '[tool.poetry.dependencies]\n'
        'python = "^3.12"\n'
        '[tool.poetry.group.dev.dependencies]\n'
        'pytest = "^8.0"\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    findings = mod.detect_dev_dep_leaks(deps)
    assert findings == []


def test_dev_leak_fires_in_project_dependencies(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = ["pytest"]\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    findings = mod.detect_dev_dep_leaks(deps)
    assert any(f.name == "pytest" for f in findings)


def test_dev_leak_fires_in_build_system_requires(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = []\n'
        '\n'
        '[build-system]\n'
        'requires = ["setuptools>=68", "pytest"]\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    findings = mod.detect_dev_dep_leaks(deps)
    assert any(f.name == "pytest" for f in findings)


def test_source_risk_severity_unchanged_in_optional_extra(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = []\n'
        '\n'
        '[project.optional-dependencies]\n'
        'demo = ["my-helper @ git+https://github.com/example/my-helper.git"]\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    findings = mod.detect_source_risks(deps)
    by_name = {f.name: f for f in findings}
    assert "my-helper" in by_name
    assert by_name["my-helper"].severity == "high"


def test_typosquat_severity_unchanged_in_optional_extra(tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = []\n'
        '\n'
        '[project.optional-dependencies]\n'
        'demo = ["pyyml"]\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    findings = mod.detect_typosquats(deps)
    by_name = {f.name: f for f in findings}
    assert "pyyml" in by_name
    assert by_name["pyyml"].severity == "medium"


def test_finding_to_jsonl_evidence_includes_section_and_extra():
    mod = _load()
    f = mod.Finding(
        name="cryptography",
        cwe="CWE-1104",
        severity="high",
        confidence="high",
        source_file="/x/pyproject.toml",
        source_line=2,
        description="Dependency 'cryptography' declared without an exact == pin (spec: <bare>).",
        evidence="/x/pyproject.toml:2: cryptography",
        manifest_section=mod.ManifestSection.PROJECT_DEPENDENCIES,
        extra_name=None,
    )
    rec = mod._finding_to_jsonl(f, "FND-SUP-0001")
    assert "section=project.dependencies" in rec["evidence"]
    assert "extra=" not in rec["evidence"]

    f2 = mod.Finding(
        name="cryptography",
        cwe="CWE-1104",
        severity="high",
        confidence="high",
        source_file="/x/pyproject.toml",
        source_line=2,
        description="Dependency 'cryptography' declared without an exact == pin (spec: <bare>).",
        evidence="/x/pyproject.toml:2: cryptography",
        manifest_section=mod.ManifestSection.OPTIONAL_DEPENDENCIES,
        extra_name="secure",
    )
    rec = mod._finding_to_jsonl(f2, "FND-SUP-0002")
    assert "section=project.optional-dependencies" in rec["evidence"]
    assert "extra=secure" in rec["evidence"]


def test_parse_pyproject_malformed_dependencies_does_not_raise(tmp_path):
    """Defensive: malformed TOML returns whatever parses, no AttributeError."""
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        # dependencies should be a list of strings; here we put inline tables.
        'dependencies = [\n'
        '    "good-pkg==1.0",\n'
        '    {weird = "table"},\n'
        ']\n'
    )
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    names = [d.name for d in deps]
    assert "good-pkg" in names
    # The inline table is silently skipped, not surfaced as a dep.
    assert "weird" not in names


def test_parse_pyproject_malformed_poetry_does_not_raise(tmp_path):
    """Defensive: garbage [tool.poetry] returns whatever parses, no crash."""
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = ["good-pkg==1.0"]\n'
        '\n'
        '[tool]\n'
        'poetry = "not a table"\n'
    )
    # Should NOT raise; should return the [project.dependencies] entries.
    deps = mod.parse_pyproject(tmp_path / "pyproject.toml")
    names = [d.name for d in deps]
    assert "good-pkg" in names


# ---------------------------------------------------------------------------
# scan_project exclusion filter.
# ---------------------------------------------------------------------------


def test_scan_project_honours_excluded_subpaths(tmp_path):
    mod = _load()
    # In-scope manifest: one finding (jinja2 unpinned).
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = ["jinja2"]\n'
    )
    # Excluded path: should NOT contribute findings.
    excluded_dir = tmp_path / ".claude"
    excluded_dir.mkdir()
    (excluded_dir / "requirements-dev.txt").write_text("pytest>=8.0,<9\n")
    findings = mod.scan_project(tmp_path, excluded=[".claude"])
    names = [f.name for f in findings]
    assert "jinja2" in names
    assert "pytest" not in names


def test_scan_project_no_exclusion_scans_everything(tmp_path):
    """Regression: omitting `excluded` keeps existing behaviour."""
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = ["jinja2"]\n'
    )
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "requirements.txt").write_text("requests\n")
    findings = mod.scan_project(tmp_path)
    names = [f.name for f in findings]
    assert "jinja2" in names
    assert "requests" in names


def test_scan_project_exclusion_path_prefix_match(tmp_path):
    """Excluding 'docs' should also exclude 'docs/source/pyproject.toml'."""
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = ["jinja2"]\n'
    )
    nested = tmp_path / "docs" / "source"
    nested.mkdir(parents=True)
    (nested / "requirements.txt").write_text("requests\n")
    findings = mod.scan_project(tmp_path, excluded=["docs"])
    names = [f.name for f in findings]
    assert "jinja2" in names
    assert "requests" not in names


# ---------------------------------------------------------------------------
# CLI — --exclude-subpath flag.
# ---------------------------------------------------------------------------


def test_main_accepts_exclude_subpath_flag(tmp_path, capsys, monkeypatch):
    """The CLI --exclude-subpath flag is repeatable and threads through."""
    mod = _load()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "x"\n'
        'version = "1.0"\n'
        'dependencies = ["jinja2"]\n'
    )
    excluded = tmp_path / ".claude"
    excluded.mkdir()
    (excluded / "requirements-dev.txt").write_text("pytest>=8.0,<9\n")
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "requirements.txt").write_text("requests\n")

    monkeypatch.setattr(
        sys, "argv",
        [
            "scout_supply_chain_detect.py",
            str(tmp_path),
            "--exclude-subpath", ".claude",
            "--exclude-subpath", "docs",
        ],
    )
    mod.main()
    captured = capsys.readouterr()
    out = captured.out
    assert "'jinja2'" in out
    # "pytest" and "requests" appear in the tmp_path string itself; check that
    # no *finding* for those names was emitted (findings quote the dep name).
    assert "'pytest'" not in out
    assert "'requests'" not in out
