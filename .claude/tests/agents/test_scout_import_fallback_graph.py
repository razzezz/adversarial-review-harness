"""Unit tests for scout-import-fallback's import-graph builder.

Tests the reusable graph + closure infrastructure that the slice-10
detector consumes (and that future AST-level scouts will share).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
GRAPH_MODULE = REPO_ROOT / ".claude" / "tools" / "scout_import_fallback_graph.py"


def _load_graph():
    spec = importlib.util.spec_from_file_location(
        "scout_import_fallback_graph", GRAPH_MODULE,
    )
    assert spec and spec.loader, f"cannot load {GRAPH_MODULE}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# ModuleNode dataclass.
# ---------------------------------------------------------------------------


def test_module_node_dataclass_shape():
    mod = _load_graph()
    n = mod.ModuleNode(
        fqname="snap7.s7commplus",
        source_file=Path("/x/snap7/s7commplus/__init__.py"),
        imports=("cryptography.hazmat.primitives", "snap7.types"),
    )
    assert n.fqname == "snap7.s7commplus"
    assert n.source_file == Path("/x/snap7/s7commplus/__init__.py")
    assert n.imports == ("cryptography.hazmat.primitives", "snap7.types")


def test_module_node_external_has_none_source_file():
    mod = _load_graph()
    n = mod.ModuleNode(fqname="cryptography", source_file=None, imports=())
    assert n.source_file is None
    assert n.imports == ()


# ---------------------------------------------------------------------------
# FQ name resolution from package layout.
# ---------------------------------------------------------------------------


def test_resolve_fqname_top_level_module(tmp_path):
    mod = _load_graph()
    (tmp_path / "client.py").write_text("")
    fq = mod._resolve_fqname(tmp_path / "client.py", tmp_path)
    assert fq == "client"


def test_resolve_fqname_package_init(tmp_path):
    mod = _load_graph()
    pkg = tmp_path / "snap7"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    fq = mod._resolve_fqname(pkg / "__init__.py", tmp_path)
    assert fq == "snap7"


def test_resolve_fqname_nested_subpackage(tmp_path):
    mod = _load_graph()
    pkg = tmp_path / "snap7" / "s7commplus"
    pkg.mkdir(parents=True)
    (pkg.parent / "__init__.py").write_text("")
    (pkg / "__init__.py").write_text("")
    (pkg / "client.py").write_text("")
    fq = mod._resolve_fqname(pkg / "client.py", tmp_path)
    assert fq == "snap7.s7commplus.client"


# ---------------------------------------------------------------------------
# Per-file import collection.
# ---------------------------------------------------------------------------


def test_collect_imports_handles_plain_import(tmp_path):
    mod = _load_graph()
    src = "import cryptography\nimport snap7.types\n"
    imports = mod._collect_imports(src, current_fqname="x", target_root=tmp_path)
    assert "cryptography" in imports
    assert "snap7.types" in imports


def test_collect_imports_handles_from_import(tmp_path):
    mod = _load_graph()
    src = "from cryptography.hazmat.primitives import ciphers\n"
    imports = mod._collect_imports(src, current_fqname="x", target_root=tmp_path)
    # `from cryptography.hazmat.primitives import ciphers` records the
    # PROVIDING module — `cryptography.hazmat.primitives`.
    assert "cryptography.hazmat.primitives" in imports


def test_collect_imports_resolves_relative(tmp_path):
    mod = _load_graph()
    # current is snap7.s7commplus.client; `from . import x` → snap7.s7commplus.x
    src = "from . import legacy\nfrom ..types import S7Type\n"
    imports = mod._collect_imports(
        src, current_fqname="snap7.s7commplus.client", target_root=tmp_path,
    )
    assert "snap7.s7commplus.legacy" in imports
    assert "snap7.types" in imports


def test_collect_imports_resolves_double_dot_pure_relative(tmp_path):
    mod = _load_graph()
    # current is snap7.s7commplus.client; `from .. import legacy`
    # → snap7.legacy (climb two levels above the file, then attach name)
    src = "from .. import legacy\n"
    imports = mod._collect_imports(
        src, current_fqname="snap7.s7commplus.client", target_root=tmp_path,
    )
    assert "snap7.legacy" in imports


def test_collect_imports_skips_type_checking_block(tmp_path):
    mod = _load_graph()
    src = (
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    import cryptography\n"
        "import snap7\n"
    )
    imports = mod._collect_imports(src, current_fqname="x", target_root=tmp_path)
    # cryptography is type-only; should NOT appear in runtime closure.
    assert "cryptography" not in imports
    assert "snap7" in imports


def test_collect_imports_returns_empty_on_syntax_error(tmp_path):
    mod = _load_graph()
    src = "import x.y.z(\n"  # malformed
    imports = mod._collect_imports(src, current_fqname="x", target_root=tmp_path)
    assert imports == ()


# ---------------------------------------------------------------------------
# build_import_graph.
# ---------------------------------------------------------------------------


def test_build_import_graph_minimal_project(tmp_path):
    mod = _load_graph()
    (tmp_path / "client.py").write_text("import cryptography\n")
    g = mod.build_import_graph(tmp_path)
    assert "client" in g
    assert g["client"].imports == ("cryptography",)
    # External module recorded with source_file=None.
    assert "cryptography" in g
    assert g["cryptography"].source_file is None


def test_build_import_graph_resolves_relative(tmp_path):
    mod = _load_graph()
    pkg = tmp_path / "snap7"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "client.py").write_text("from . import legacy\n")
    (pkg / "legacy.py").write_text("")
    g = mod.build_import_graph(tmp_path)
    assert "snap7.client" in g
    assert "snap7.legacy" in g["snap7.client"].imports
    # snap7.legacy is in-tree, has source_file.
    assert g["snap7.legacy"].source_file is not None


def test_build_import_graph_skips_excluded_subpath(tmp_path):
    mod = _load_graph()
    excluded = tmp_path / "vendor"
    excluded.mkdir()
    (excluded / "thirdparty.py").write_text("import cryptography\n")
    (tmp_path / "main.py").write_text("import x\n")
    g = mod.build_import_graph(tmp_path, excluded=["vendor"])
    assert "main" in g
    assert "vendor.thirdparty" not in g
    # cryptography also not pulled in via vendor.
    # (main doesn't import it, so it doesn't appear at all)
    assert "thirdparty" not in g


def test_build_import_graph_per_file_syntax_error_yields_empty_node(tmp_path):
    mod = _load_graph()
    (tmp_path / "broken.py").write_text("import x.(\n")
    (tmp_path / "good.py").write_text("import cryptography\n")
    g = mod.build_import_graph(tmp_path)
    assert "broken" in g
    assert g["broken"].imports == ()
    assert "good" in g
    assert g["good"].imports == ("cryptography",)


def test_build_import_graph_records_external_nodes(tmp_path):
    mod = _load_graph()
    (tmp_path / "main.py").write_text(
        "import cryptography\nfrom paramiko import SSHClient\n"
    )
    g = mod.build_import_graph(tmp_path)
    assert g["cryptography"].source_file is None
    assert g["paramiko"].source_file is None


# ---------------------------------------------------------------------------
# compute_closure.
# ---------------------------------------------------------------------------


def test_compute_closure_single_hop(tmp_path):
    mod = _load_graph()
    (tmp_path / "client.py").write_text("import cryptography\n")
    g = mod.build_import_graph(tmp_path)
    closure = mod.compute_closure(g, "client")
    assert "client" in closure
    assert "cryptography" in closure


def test_compute_closure_transitive(tmp_path):
    mod = _load_graph()
    pkg = tmp_path / "myapp"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "secure.py").write_text("import cryptography\n")
    (pkg / "client.py").write_text("from . import secure\n")
    g = mod.build_import_graph(tmp_path)
    closure = mod.compute_closure(g, "myapp.client")
    # Transitive: client → secure → cryptography
    assert "myapp.client" in closure
    assert "myapp.secure" in closure
    assert "cryptography" in closure


def test_compute_closure_terminates_at_external(tmp_path):
    mod = _load_graph()
    (tmp_path / "client.py").write_text("import cryptography\n")
    g = mod.build_import_graph(tmp_path)
    closure = mod.compute_closure(g, "client")
    # cryptography is external (source_file=None); closure includes it
    # but does NOT recurse into hypothetical cryptography imports.
    assert "cryptography" in closure
    # External nodes contribute themselves but no children.


def test_compute_closure_handles_cycles(tmp_path):
    mod = _load_graph()
    pkg = tmp_path / "p"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "a.py").write_text("from . import b\n")
    (pkg / "b.py").write_text("from . import a\n")
    g = mod.build_import_graph(tmp_path)
    closure = mod.compute_closure(g, "p.a")
    assert "p.a" in closure
    assert "p.b" in closure  # No infinite recursion.


def test_compute_closure_max_depth_caps(tmp_path):
    mod = _load_graph()
    # Build a chain: a → b → c → d → e
    for name, imports in [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e"), ("e", "")]:
        (tmp_path / f"{name}.py").write_text(f"import {imports}\n" if imports else "")
    g = mod.build_import_graph(tmp_path)
    closure = mod.compute_closure(g, "a", max_depth=2)
    assert "a" in closure
    assert "b" in closure
    assert "c" in closure
    # max_depth=2 means a (depth 0) → b (1) → c (2). d (depth 3) excluded.
    assert "d" not in closure


def test_compute_closure_uses_cache(tmp_path):
    mod = _load_graph()
    (tmp_path / "a.py").write_text("import cryptography\n")
    g = mod.build_import_graph(tmp_path)
    cache: dict[str, frozenset[str]] = {}
    c1 = mod.compute_closure(g, "a", cache=cache)
    assert "a" in cache
    # Second call returns cached value.
    c2 = mod.compute_closure(g, "a", cache=cache)
    assert c1 is c2 or c1 == c2


def test_compute_closure_cache_propagates_to_children(tmp_path):
    mod = _load_graph()
    # Build chain: a → b → c (external).
    (tmp_path / "a.py").write_text("import b\n")
    (tmp_path / "b.py").write_text("import c\n")
    g = mod.build_import_graph(tmp_path)
    cache: dict[str, frozenset[str]] = {}
    mod.compute_closure(g, "a", cache=cache)
    # After computing a's closure, b's closure must also be cached
    # (otherwise the detector would re-traverse b's subtree on its
    # next compute_closure call — the I-2 perf bug).
    assert "a" in cache
    assert "b" in cache
    assert cache["b"] == frozenset({"b", "c"})
