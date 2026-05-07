"""Unit tests for scout-import-fallback's detector.

Tests parse, try-import collection, shape classification, feature-flag
resolution, and suppression. _classify_signal + scan_project + stdlib-
fallback live in Task 3's tests.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
GRAPH_MODULE = REPO_ROOT / ".claude" / "tools" / "scout_import_fallback_graph.py"
DETECTOR_MODULE = REPO_ROOT / ".claude" / "tools" / "scout_import_fallback_detect.py"


def _load_graph():
    spec = importlib.util.spec_from_file_location(
        "scout_import_fallback_graph", GRAPH_MODULE,
    )
    assert spec and spec.loader, f"cannot load {GRAPH_MODULE}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_detector():
    _load_graph()  # detector imports from graph; load order matters.
    spec = importlib.util.spec_from_file_location(
        "scout_import_fallback_detect", DETECTOR_MODULE,
    )
    assert spec and spec.loader, f"cannot load {DETECTOR_MODULE}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# FallbackShape + Signal enums.
# ---------------------------------------------------------------------------


def test_fallback_shape_enum_values():
    mod = _load_detector()
    assert mod.FallbackShape.PAIRED_IMPORT.value == "paired-import"
    assert mod.FallbackShape.ANY_FALLBACK.value == "any-fallback"
    assert mod.FallbackShape.FEATURE_FLAG.value == "feature-flag"


def test_signal_enum_values():
    mod = _load_detector()
    assert mod.Signal.DIFF.value == "diff"
    assert mod.Signal.DIRECT.value == "direct"
    assert mod.Signal.TRANSITIVE.value == "transitive"
    assert mod.Signal.WEAK.value == "weak"


def test_security_bearing_leaves_corpus():
    mod = _load_detector()
    leaves = mod.SECURITY_BEARING_LEAVES
    for expected in ("cryptography", "ssl", "OpenSSL", "nacl", "paramiko",
                     "bcrypt", "argon2", "passlib", "jwt", "oauthlib",
                     "defusedxml", "secrets", "hashlib"):
        assert expected in leaves


# ---------------------------------------------------------------------------
# _parse — libcst preferred, ast fallback.
# ---------------------------------------------------------------------------


def test_parse_returns_libcst_module_when_available():
    mod = _load_detector()
    if not mod._LIBCST_AVAILABLE:
        # Test environment doesn't have libcst — skip; covered by stdlib path.
        import pytest
        pytest.skip("libcst not installed in test env")
    src = "import cryptography\n"
    tree = mod._parse(src)
    # libcst Module type is the truthy result.
    assert tree is not None
    # Sanity: contains an import statement.
    assert "cryptography" in mod._parse_to_string(tree)


def test_parse_falls_back_to_ast_when_libcst_missing(monkeypatch):
    mod = _load_detector()
    monkeypatch.setattr(mod, "_LIBCST_AVAILABLE", False)
    src = "import cryptography\n"
    tree = mod._parse(src)
    import ast as ast_module
    assert isinstance(tree, ast_module.Module)


# ---------------------------------------------------------------------------
# _collect_try_import_blocks.
# ---------------------------------------------------------------------------


def test_collect_try_import_blocks_paired_import():
    mod = _load_detector()
    src = (
        "try:\n"
        "    from snap7.s7commplus import Client\n"
        "except ImportError:\n"
        "    from snap7.s7legacy import Client\n"
    )
    tree = mod._parse(src)
    blocks = mod._collect_try_import_blocks(tree)
    assert len(blocks) == 1
    assert blocks[0].secure_module == "snap7.s7commplus"
    assert blocks[0].fallback_module == "snap7.s7legacy"


def test_collect_try_import_blocks_any_fallback_sentinel():
    mod = _load_detector()
    src = (
        "try:\n"
        "    import cryptography\n"
        "except ImportError:\n"
        "    cryptography = None\n"
    )
    tree = mod._parse(src)
    blocks = mod._collect_try_import_blocks(tree)
    assert len(blocks) == 1
    assert blocks[0].secure_module == "cryptography"
    # Fallback is not an import → fallback_module is None.
    assert blocks[0].fallback_module is None


def test_collect_try_import_blocks_module_not_found_error():
    """Catch tuple (ImportError, ModuleNotFoundError) is also a fallback."""
    mod = _load_detector()
    src = (
        "try:\n"
        "    import paramiko\n"
        "except (ImportError, ModuleNotFoundError):\n"
        "    pass\n"
    )
    tree = mod._parse(src)
    blocks = mod._collect_try_import_blocks(tree)
    assert len(blocks) == 1
    assert blocks[0].secure_module == "paramiko"


def test_collect_try_import_blocks_bare_except_matches():
    mod = _load_detector()
    src = (
        "try:\n"
        "    import cryptography\n"
        "except:\n"
        "    pass\n"
    )
    tree = mod._parse(src)
    blocks = mod._collect_try_import_blocks(tree)
    assert len(blocks) == 1


def test_collect_try_import_blocks_skips_non_import_try():
    mod = _load_detector()
    src = (
        "try:\n"
        "    x = compute()\n"
        "except ImportError:\n"
        "    x = 0\n"
    )
    tree = mod._parse(src)
    blocks = mod._collect_try_import_blocks(tree)
    # try-body is not just an import → not a candidate.
    assert blocks == []


def test_collect_try_import_blocks_skips_non_importerror_except():
    mod = _load_detector()
    src = (
        "try:\n"
        "    import cryptography\n"
        "except ValueError:\n"
        "    pass\n"
    )
    tree = mod._parse(src)
    blocks = mod._collect_try_import_blocks(tree)
    # except clause doesn't catch ImportError → not a fallback pattern.
    assert blocks == []


def test_collect_try_import_blocks_handles_try_star():
    """PEP 654 try* should match the same patterns as plain try."""
    mod = _load_detector()
    src = (
        "try:\n"
        "    import cryptography\n"
        "except* ImportError:\n"
        "    pass\n"
    )
    # Skip if running on Python <3.11 (no try* parser support).
    import ast as _ast
    if not hasattr(_ast, "TryStar"):
        import pytest
        pytest.skip("Python <3.11; try* not supported")
    tree = mod._parse(src)
    blocks = mod._collect_try_import_blocks(tree)
    assert len(blocks) == 1
    assert blocks[0].secure_module == "cryptography"


# ---------------------------------------------------------------------------
# _classify_shape.
# ---------------------------------------------------------------------------


def test_classify_shape_paired_import():
    mod = _load_detector()
    src = (
        "try:\n"
        "    from secure import C\n"
        "except ImportError:\n"
        "    from legacy import C\n"
    )
    tree = mod._parse(src)
    blocks = mod._collect_try_import_blocks(tree)
    shape = mod._classify_shape(blocks[0])
    assert shape == mod.FallbackShape.PAIRED_IMPORT


def test_classify_shape_any_fallback_sentinel():
    mod = _load_detector()
    src = (
        "try:\n"
        "    import cryptography\n"
        "except ImportError:\n"
        "    cryptography = None\n"
    )
    tree = mod._parse(src)
    blocks = mod._collect_try_import_blocks(tree)
    shape = mod._classify_shape(blocks[0])
    assert shape == mod.FallbackShape.ANY_FALLBACK


def test_classify_shape_any_fallback_pass():
    mod = _load_detector()
    src = (
        "try:\n"
        "    import cryptography\n"
        "except ImportError:\n"
        "    pass\n"
    )
    tree = mod._parse(src)
    blocks = mod._collect_try_import_blocks(tree)
    shape = mod._classify_shape(blocks[0])
    assert shape == mod.FallbackShape.ANY_FALLBACK


def test_classify_shape_feature_flag_positive():
    mod = _load_detector()
    src = (
        "try:\n"
        "    import secrets\n"
        "    HAS_SECRETS = True\n"
        "except ImportError:\n"
        "    HAS_SECRETS = False\n"
    )
    tree = mod._parse(src)
    blocks = mod._collect_try_import_blocks(tree)
    shape = mod._classify_shape(blocks[0])
    assert shape == mod.FallbackShape.FEATURE_FLAG


def test_classify_shape_not_feature_flag_when_flag_assigned_other_value():
    mod = _load_detector()
    # HAS_X assigned to a non-Boolean → not a feature-flag pattern.
    src = (
        "try:\n"
        "    import secrets\n"
        "    HAS_X = 1\n"
        "except ImportError:\n"
        "    HAS_X = 0\n"
    )
    tree = mod._parse(src)
    blocks = mod._collect_try_import_blocks(tree)
    shape = mod._classify_shape(blocks[0])
    # Falls through to ANY_FALLBACK.
    assert shape == mod.FallbackShape.ANY_FALLBACK


# ---------------------------------------------------------------------------
# _resolve_feature_flag_branches.
# ---------------------------------------------------------------------------


def test_resolve_feature_flag_single_if_site():
    mod = _load_detector()
    src = (
        "try:\n"
        "    import secrets\n"
        "    HAS_X = True\n"
        "except ImportError:\n"
        "    HAS_X = False\n"
        "\n"
        "def gen():\n"
        "    if HAS_X:\n"
        "        return secrets.token_hex()\n"
        "    return 'x'\n"
    )
    tree = mod._parse(src)
    sites = mod._resolve_feature_flag_branches(tree, "HAS_X")
    assert len(sites) == 1
    # Site has start and end line.
    assert sites[0].start_line >= 7  # the `if HAS_X:` line


def test_resolve_feature_flag_multiple_sites():
    mod = _load_detector()
    src = (
        "HAS_X = False\n"
        "if HAS_X:\n"
        "    a = 1\n"
        "if HAS_X:\n"
        "    b = 2\n"
    )
    tree = mod._parse(src)
    sites = mod._resolve_feature_flag_branches(tree, "HAS_X")
    assert len(sites) == 2


def test_resolve_feature_flag_zero_sites_when_unused():
    mod = _load_detector()
    src = (
        "HAS_X = False\n"
        "x = 1\n"
    )
    tree = mod._parse(src)
    sites = mod._resolve_feature_flag_branches(tree, "HAS_X")
    assert sites == []


# ---------------------------------------------------------------------------
# _is_suppressed.
# ---------------------------------------------------------------------------


def test_is_suppressed_named_noqa_silences():
    mod = _load_detector()
    src = (
        "try:                           # noqa: scout-import-fallback\n"
        "    import uvloop\n"
        "except ImportError:\n"
        "    import asyncio\n"
    )
    tree = mod._parse(src)
    assert mod._is_suppressed(tree, src, try_line=1) is True


def test_is_suppressed_bare_noqa_does_not_silence():
    mod = _load_detector()
    src = (
        "try:                           # noqa\n"
        "    import uvloop\n"
        "except ImportError:\n"
        "    import asyncio\n"
    )
    tree = mod._parse(src)
    assert mod._is_suppressed(tree, src, try_line=1) is False


def test_is_suppressed_case_insensitive():
    mod = _load_detector()
    src = (
        "try:    # NOQA: SCOUT-IMPORT-FALLBACK\n"
        "    import uvloop\n"
        "except ImportError:\n"
        "    import asyncio\n"
    )
    tree = mod._parse(src)
    assert mod._is_suppressed(tree, src, try_line=1) is True


def test_is_suppressed_silent_when_no_noqa():
    mod = _load_detector()
    src = (
        "try:\n"
        "    import uvloop\n"
        "except ImportError:\n"
        "    import asyncio\n"
    )
    tree = mod._parse(src)
    assert mod._is_suppressed(tree, src, try_line=1) is False


# ---------------------------------------------------------------------------
# ImportFallbackFinding dataclass.
# ---------------------------------------------------------------------------


def test_import_fallback_finding_dataclass_shape():
    mod = _load_detector()
    f = mod.ImportFallbackFinding(
        source_file="/x/client.py",
        source_line=12,
        line_range=(12, 18),
        shape=mod.FallbackShape.PAIRED_IMPORT,
        signal=mod.Signal.DIFF,
        secure_module="snap7.s7commplus",
        fallback_module="snap7.s7legacy",
        flag_symbol=None,
        matched_leaves=("cryptography",),
        trace_path=("snap7.s7commplus", "snap7.s7commplus.crypto", "cryptography"),
        suppressed=False,
    )
    assert f.shape == mod.FallbackShape.PAIRED_IMPORT
    assert f.signal == mod.Signal.DIFF
    assert f.matched_leaves == ("cryptography",)


# ---------------------------------------------------------------------------
# _match_leaves — closure ↔ corpus intersection on first-component projection.
# ---------------------------------------------------------------------------


def test_match_leaves_direct_hit():
    mod = _load_detector()
    closure = frozenset({"cryptography", "x.y"})
    matched = mod._match_leaves(closure)
    assert matched == frozenset({"cryptography"})


def test_match_leaves_first_component_projection():
    mod = _load_detector()
    closure = frozenset({"cryptography.hazmat.primitives", "snap7.types"})
    matched = mod._match_leaves(closure)
    # First-component projection picks "cryptography" out.
    assert matched == frozenset({"cryptography"})


def test_match_leaves_no_hit():
    mod = _load_detector()
    closure = frozenset({"snap7.types", "uvloop"})
    matched = mod._match_leaves(closure)
    assert matched == frozenset()


def test_match_leaves_multiple_hits():
    mod = _load_detector()
    closure = frozenset({"cryptography.x", "ssl", "passlib.utils"})
    matched = mod._match_leaves(closure)
    assert matched == frozenset({"cryptography", "ssl", "passlib"})


# ---------------------------------------------------------------------------
# _shortest_path — breadcrumb for evidence trace_path.
# ---------------------------------------------------------------------------


def test_shortest_path_direct():
    mod = _load_detector()
    g = _load_graph()
    graph = {
        "client": g.ModuleNode("client", Path("/x/client.py"), ("cryptography",)),
        "cryptography": g.ModuleNode("cryptography", None, ()),
    }
    path = mod._shortest_path(graph, "client", frozenset({"cryptography"}))
    assert path == ("client", "cryptography")


def test_shortest_path_two_hops():
    mod = _load_detector()
    g = _load_graph()
    graph = {
        "client": g.ModuleNode("client", Path("/x/client.py"), ("middle",)),
        "middle": g.ModuleNode("middle", Path("/x/middle.py"), ("cryptography.hazmat",)),
        "cryptography.hazmat": g.ModuleNode("cryptography.hazmat", None, ()),
    }
    path = mod._shortest_path(graph, "client", frozenset({"cryptography"}))
    assert path[0] == "client"
    assert path[-1] in ("cryptography.hazmat", "cryptography")


# ---------------------------------------------------------------------------
# _classify_signal — DIFF / DIRECT / TRANSITIVE / WEAK.
# ---------------------------------------------------------------------------


def test_classify_signal_direct_when_corpus_leaf():
    mod = _load_detector()
    g = _load_graph()
    graph = {
        "client": g.ModuleNode("client", Path("/x/client.py"), ("cryptography",)),
        "cryptography": g.ModuleNode("cryptography", None, ()),
    }
    block = mod.TryImportBlock(
        try_line=1, except_line=3, end_line=5,
        secure_module="cryptography", fallback_module=None,
        flag_assigned_true=None, flag_assigned_false=None,
        except_handler_body=[],
    )
    signal, leaves, path = mod._classify_signal(block, graph, cache={})
    assert signal == mod.Signal.DIRECT
    assert leaves == ("cryptography",)


def test_classify_signal_diff_when_paired_imports_diverge():
    mod = _load_detector()
    g = _load_graph()
    graph = {
        "client": g.ModuleNode("client", Path("/x/client.py"), ()),
        "secure": g.ModuleNode("secure", Path("/x/secure.py"), ("cryptography",)),
        "legacy": g.ModuleNode("legacy", Path("/x/legacy.py"), ()),
        "cryptography": g.ModuleNode("cryptography", None, ()),
    }
    block = mod.TryImportBlock(
        try_line=1, except_line=3, end_line=5,
        secure_module="secure", fallback_module="legacy",
        flag_assigned_true=None, flag_assigned_false=None,
        except_handler_body=[],
    )
    signal, leaves, path = mod._classify_signal(block, graph, cache={})
    assert signal == mod.Signal.DIFF
    assert "cryptography" in leaves


def test_classify_signal_transitive_for_indirect_match():
    mod = _load_detector()
    g = _load_graph()
    graph = {
        "client": g.ModuleNode("client", Path("/x/client.py"), ()),
        "midmod": g.ModuleNode("midmod", Path("/x/midmod.py"), ("cryptography.hazmat",)),
        "cryptography.hazmat": g.ModuleNode("cryptography.hazmat", None, ()),
    }
    block = mod.TryImportBlock(
        try_line=1, except_line=3, end_line=5,
        secure_module="midmod", fallback_module=None,
        flag_assigned_true=None, flag_assigned_false=None,
        except_handler_body=[],
    )
    signal, leaves, path = mod._classify_signal(block, graph, cache={})
    assert signal == mod.Signal.TRANSITIVE
    assert "cryptography" in leaves


def test_classify_signal_weak_when_no_corpus_contact():
    mod = _load_detector()
    g = _load_graph()
    graph = {
        "client": g.ModuleNode("client", Path("/x/client.py"), ("uvloop",)),
        "uvloop": g.ModuleNode("uvloop", None, ()),
    }
    block = mod.TryImportBlock(
        try_line=1, except_line=3, end_line=5,
        secure_module="uvloop", fallback_module=None,
        flag_assigned_true=None, flag_assigned_false=None,
        except_handler_body=[],
    )
    signal, leaves, path = mod._classify_signal(block, graph, cache={})
    assert signal == mod.Signal.WEAK
    assert leaves == ()


def test_classify_signal_diff_falls_through_to_transitive_when_diff_empty():
    mod = _load_detector()
    g = _load_graph()
    # Both branches import cryptography; diff is empty but transitive matches.
    graph = {
        "secure": g.ModuleNode("secure", Path("/x/s.py"), ("cryptography",)),
        "legacy": g.ModuleNode("legacy", Path("/x/l.py"), ("cryptography",)),
        "cryptography": g.ModuleNode("cryptography", None, ()),
    }
    block = mod.TryImportBlock(
        try_line=1, except_line=3, end_line=5,
        secure_module="secure", fallback_module="legacy",
        flag_assigned_true=None, flag_assigned_false=None,
        except_handler_body=[],
    )
    signal, leaves, path = mod._classify_signal(block, graph, cache={})
    # No DIFF (closures match); falls through to TRANSITIVE on secure-side.
    assert signal == mod.Signal.TRANSITIVE


def test_classify_signal_class_import_aliasing_degrades_gracefully():
    """Regression for I1: ``from M import ClassName as Alias`` resolves
    to ``M.ClassName`` via _extract_import_and_flag's asname heuristic,
    but if ClassName is NOT a submodule there's no graph node for it.
    Closure terminates at the external leaf {M.ClassName} and the
    detector degrades to a softer signal — never producing a false
    DIFF finding from a class-binding swap.
    """
    mod = _load_detector()
    g = _load_graph()
    # M is in-tree (has __init__.py); SecureClass and LegacyClass are
    # NOT submodules — they don't exist as graph nodes. Crucially, the
    # detector's _extract_import_and_flag returns "M.SecureClass" /
    # "M.LegacyClass" for the asname-aliased imports, but the graph
    # has no nodes for those FQ names.
    graph = {
        "M": g.ModuleNode("M", Path("/x/M/__init__.py"), ()),
        "M.SecureClass": g.ModuleNode("M.SecureClass", None, ()),
        "M.LegacyClass": g.ModuleNode("M.LegacyClass", None, ()),
    }
    block = mod.TryImportBlock(
        try_line=1, except_line=3, end_line=5,
        secure_module="M.SecureClass",
        fallback_module="M.LegacyClass",
        flag_assigned_true=None, flag_assigned_false=None,
        except_handler_body=[],
    )
    signal, leaves, _path = mod._classify_signal(block, graph, cache={})
    # Both branches' closures are external leaves with empty corpus
    # contact — diff is empty, no first-component match, falls through
    # to WEAK (no false-positive DIFF / DIRECT / TRANSITIVE).
    assert signal == mod.Signal.WEAK
    assert leaves == ()


# ---------------------------------------------------------------------------
# scan_file + scan_project.
# ---------------------------------------------------------------------------


def test_scan_file_emits_finding_for_paired_with_diff(tmp_path):
    mod = _load_detector()
    g = _load_graph()
    # Build a tiny project: client.py has try/except imports;
    # secure imports cryptography, legacy doesn't.
    pkg = tmp_path / "p"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "secure.py").write_text("import cryptography\n")
    (pkg / "legacy.py").write_text("\n")
    (pkg / "client.py").write_text(
        "try:\n"
        "    from p import secure as _backend\n"
        "except ImportError:\n"
        "    from p import legacy as _backend\n"
    )
    graph = g.build_import_graph(tmp_path)
    findings = mod.scan_file(pkg / "client.py", graph, cache={})
    assert len(findings) == 1
    f = findings[0]
    assert f.shape == mod.FallbackShape.PAIRED_IMPORT
    assert f.signal == mod.Signal.DIFF
    assert "cryptography" in f.matched_leaves


def test_scan_file_skips_weak_signal(tmp_path):
    mod = _load_detector()
    g = _load_graph()
    (tmp_path / "client.py").write_text(
        "try:\n"
        "    import uvloop\n"
        "except ImportError:\n"
        "    import asyncio\n"
    )
    graph = g.build_import_graph(tmp_path)
    findings = mod.scan_file(tmp_path / "client.py", graph, cache={})
    # uvloop / asyncio: no corpus contact → WEAK → not emitted.
    assert findings == []


def test_scan_file_respects_suppression(tmp_path):
    mod = _load_detector()
    g = _load_graph()
    (tmp_path / "client.py").write_text(
        "try:                           # noqa: scout-import-fallback\n"
        "    import cryptography\n"
        "except ImportError:\n"
        "    cryptography = None\n"
    )
    graph = g.build_import_graph(tmp_path)
    findings = mod.scan_file(tmp_path / "client.py", graph, cache={})
    # Suppressed → not in stdout return value.
    assert findings == []


def test_scan_project_aggregates_findings_across_files(tmp_path):
    mod = _load_detector()
    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "secure.py").write_text("import cryptography\n")
    (pkg / "legacy.py").write_text("\n")
    (pkg / "a.py").write_text(
        "try:\n"
        "    from app import secure as _b\n"
        "except ImportError:\n"
        "    from app import legacy as _b\n"
    )
    (pkg / "b.py").write_text(
        "try:\n"
        "    import cryptography\n"
        "except ImportError:\n"
        "    cryptography = None\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) == 2
    shapes = {f.shape for f in findings}
    assert mod.FallbackShape.PAIRED_IMPORT in shapes
    assert mod.FallbackShape.ANY_FALLBACK in shapes


def test_scan_project_honours_excluded_subpath(tmp_path):
    mod = _load_detector()
    excluded = tmp_path / "vendor"
    excluded.mkdir()
    (excluded / "client.py").write_text(
        "try:\n"
        "    import cryptography\n"
        "except ImportError:\n"
        "    cryptography = None\n"
    )
    findings = mod.scan_project(tmp_path, excluded=["vendor"])
    assert findings == []


def test_finding_to_jsonl_includes_evidence_keys():
    mod = _load_detector()
    f = mod.ImportFallbackFinding(
        source_file="/x/client.py",
        source_line=12,
        line_range=(12, 18),
        shape=mod.FallbackShape.PAIRED_IMPORT,
        signal=mod.Signal.DIFF,
        secure_module="snap7.s7commplus",
        fallback_module="snap7.s7legacy",
        flag_symbol=None,
        matched_leaves=("cryptography",),
        trace_path=("snap7.s7commplus", "cryptography"),
        suppressed=False,
    )
    rec = mod._finding_to_jsonl(f, "FND-IMP-0001")
    assert rec["scout"] == "scout-import-fallback"
    assert rec["cwe"] == ["CWE-636"]
    assert rec["severity"] == "low"
    assert rec["confidence"] == "high"   # DIFF → high
    assert rec["poc_applicable"] is False
    assert "drift_kind" not in rec        # not a supply-chain finding
    assert "shape=paired-import" in rec["evidence"]
    assert "signal=diff" in rec["evidence"]
    assert "trace=snap7.s7commplus→cryptography" in rec["evidence"]


# ---------------------------------------------------------------------------
# Stdlib-fallback path (libcst unavailable).
# ---------------------------------------------------------------------------


def test_stdlib_fallback_paired_import_still_fires(tmp_path, monkeypatch):
    mod = _load_detector()
    monkeypatch.setattr(mod, "_LIBCST_AVAILABLE", False)
    # Build a tiny project.
    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "secure.py").write_text("import cryptography\n")
    (pkg / "legacy.py").write_text("\n")
    (pkg / "client.py").write_text(
        "try:\n"
        "    from app import secure as _b\n"
        "except ImportError:\n"
        "    from app import legacy as _b\n"
    )
    findings = mod.scan_project(tmp_path)
    assert any(
        f.signal == mod.Signal.DIFF and "cryptography" in f.matched_leaves
        for f in findings
    )


def test_stdlib_fallback_suppression_via_tokenize(tmp_path, monkeypatch):
    mod = _load_detector()
    monkeypatch.setattr(mod, "_LIBCST_AVAILABLE", False)
    (tmp_path / "client.py").write_text(
        "try:    # noqa: scout-import-fallback\n"
        "    import cryptography\n"
        "except ImportError:\n"
        "    cryptography = None\n"
    )
    findings = mod.scan_project(tmp_path)
    assert findings == []


def test_stdlib_fallback_feature_flag_still_fires(tmp_path, monkeypatch):
    mod = _load_detector()
    monkeypatch.setattr(mod, "_LIBCST_AVAILABLE", False)
    (tmp_path / "tok.py").write_text(
        "try:\n"
        "    import secrets\n"
        "    HAS_X = True\n"
        "except ImportError:\n"
        "    HAS_X = False\n"
        "if HAS_X:\n"
        "    x = 1\n"
    )
    findings = mod.scan_project(tmp_path)
    assert any(
        f.shape == mod.FallbackShape.FEATURE_FLAG and f.signal == mod.Signal.DIRECT
        for f in findings
    )


def test_stdlib_fallback_warning_emitted_once(tmp_path, monkeypatch, capsys):
    mod = _load_detector()
    monkeypatch.setattr(mod, "_LIBCST_AVAILABLE", False)
    monkeypatch.setattr(mod, "_LIBCST_WARNED", False)
    (tmp_path / "a.py").write_text("import cryptography\n")
    (tmp_path / "b.py").write_text("import cryptography\n")
    mod.scan_project(tmp_path)
    captured = capsys.readouterr()
    # Warning should appear at most once.
    assert captured.err.count("libcst unavailable") <= 1
