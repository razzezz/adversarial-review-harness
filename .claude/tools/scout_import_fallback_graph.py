#!/usr/bin/env python3
"""Import-graph + closure infrastructure for AST-level scouts.

Walks every .py file under target_root, FQ-resolves each, parses imports.
Provides `compute_closure` for transitive import traversal with
depth-cap and cycle-safety.

Reusable: slice-10's scout-import-fallback consumes this; future AST
scouts (scout-auth, scout-race-condition) can import the same primitives.

Pure-stdlib for the graph builder itself; no libcst dependency at this
layer — the per-file detector handles that separately.
"""

from __future__ import annotations

import ast
import dataclasses
import sys
from pathlib import Path


@dataclasses.dataclass(frozen=True)
class ModuleNode:
    """A single module's identity for graph-walking.

    `source_file` is None for external modules — pip-installed packages
    we don't have source for. Closure traversal terminates at external
    nodes (we record the leaf but don't recurse).
    """
    fqname: str
    source_file: Path | None
    imports: tuple[str, ...]


def _resolve_fqname(path: Path, target_root: Path) -> str:
    """Resolve a .py file path to its fully-qualified module name.

    Walks up from `path` while each parent contains __init__.py, then
    constructs the dotted name from the package chain. The file itself
    contributes its stem (or nothing if it's __init__.py).
    """
    rel = path.resolve().relative_to(target_root.resolve())
    parts = list(rel.parts)
    # Walk upward to find the package boundary — first ancestor lacking __init__.py.
    pkg_parts: list[str] = []
    cur = target_root.resolve()
    for p in parts[:-1]:
        cur = cur / p
        if not (cur / "__init__.py").exists():
            # Not a package; reset chain — the file isn't inside a package above this.
            return path.stem if path.name != "__init__.py" else parts[-2] if len(parts) >= 2 else ""
        pkg_parts.append(p)
    if path.name == "__init__.py":
        return ".".join(pkg_parts)
    return ".".join(pkg_parts + [path.stem])


def _collect_imports(src: str,
                     current_fqname: str,
                     target_root: Path) -> tuple[str, ...]:
    """Extract every runtime import statement from `src`.

    Skips `if TYPE_CHECKING:` blocks (typing-only, not runtime).
    Resolves relative imports against `current_fqname`.
    Returns the providing-module FQ name for each import edge.

    Returns empty tuple on SyntaxError — graph builder will record an
    empty-imports ModuleNode and continue.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return ()

    out: list[str] = []
    for node in _walk_skipping_type_checking(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            level = node.level or 0
            if level > 0:
                # Relative import — resolve against current package.
                base_parts = current_fqname.split(".")[:-1]  # drop file name
                if level - 1 > len(base_parts):
                    # Climbed past target_root; skip — invalid relative.
                    continue
                base = ".".join(base_parts[: len(base_parts) - (level - 1)])
                resolved = ".".join(p for p in (base, module) if p)
                if not resolved:
                    continue  # defence-in-depth; level-guard above usually catches this
                if module:
                    # `from .pkg import name` — providing module is `base.pkg`.
                    out.append(resolved)
                else:
                    # `from . import name` — names are sibling submodules.
                    for alias in node.names:
                        out.append(f"{resolved}.{alias.name}")
            elif module:
                out.append(module)
    return tuple(out)


def _walk_skipping_type_checking(tree: ast.AST):
    """Yield every node in `tree` except those nested inside an
    `if TYPE_CHECKING:` block (typing-only imports)."""
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.If) and _is_type_checking_test(node.test):
            # Skip the body — type-only.
            for child in node.orelse:
                yield from ast.walk(child)
            continue
        yield from ast.walk(node)


def _is_type_checking_test(test: ast.expr) -> bool:
    """Return True if `test` references the `TYPE_CHECKING` symbol.

    Accepts `TYPE_CHECKING`, `typing.TYPE_CHECKING`, and aliases.
    """
    if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
        return True
    if isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING":
        return True
    return False


def build_import_graph(target_root: Path,
                       excluded: list[str] | None = None) -> dict[str, ModuleNode]:
    """Walk `target_root.rglob('*.py')`, FQ-resolve each, parse imports.

    Returns a graph keyed by FQ module name. External modules
    (referenced via imports but not present in target_root) are
    recorded as ModuleNode with `source_file=None` and `imports=()`.

    `excluded` is a list of subpath names (relative to target_root)
    to skip. Path-prefix match — slice-8 invariant.

    Per-file SyntaxError → empty-imports node + stderr log.
    >20% parse-failure rate → end-of-build summary warning.
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

    graph: dict[str, ModuleNode] = {}
    seen_files: dict[str, Path] = {}  # FQ → file (for vendored-collision detection)
    total_files = 0
    failed_files = 0

    for path in target_root.rglob("*.py"):
        if _is_excluded(path):
            continue
        total_files += 1
        try:
            fqname = _resolve_fqname(path, target_root)
        except (ValueError, OSError) as e:
            print(
                f"scout_import_fallback_graph: skipped {path}: {e}",
                file=sys.stderr,
            )
            failed_files += 1
            continue
        if not fqname:
            continue
        if fqname in seen_files:
            print(
                f"scout_import_fallback_graph: vendored-copy collision "
                f"on {fqname!r}: kept {seen_files[fqname]}, ignored {path}",
                file=sys.stderr,
            )
            continue
        try:
            src = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            print(
                f"scout_import_fallback_graph: skipped {path}: {e}",
                file=sys.stderr,
            )
            failed_files += 1
            graph[fqname] = ModuleNode(fqname=fqname, source_file=path, imports=())
            seen_files[fqname] = path
            continue
        imports = _collect_imports(src, current_fqname=fqname, target_root=target_root)
        if not imports and src.strip() and "import" in src:
            # Heuristic: file mentions 'import' but we found none → likely SyntaxError.
            failed_files += 1
        graph[fqname] = ModuleNode(fqname=fqname, source_file=path, imports=imports)
        seen_files[fqname] = path

    # External nodes: every imported FQ name not yet in graph gets an
    # empty-imports node with source_file=None.
    all_imports: set[str] = set()
    for node in list(graph.values()):
        all_imports.update(node.imports)
    for ext in all_imports:
        if ext not in graph:
            graph[ext] = ModuleNode(fqname=ext, source_file=None, imports=())

    if total_files > 0 and failed_files / total_files > 0.20:
        print(
            f"scout_import_fallback_graph: WARNING — {failed_files}/{total_files} "
            f"({100 * failed_files / total_files:.0f}%) of files failed to parse; "
            f"results may be incomplete.",
            file=sys.stderr,
        )
    return graph


def compute_closure(graph: dict[str, ModuleNode],
                    start: str,
                    max_depth: int = 8,
                    cache: dict[str, frozenset[str]] | None = None) -> frozenset[str]:
    """Compute the transitive-import closure of `start` in `graph`.

    Returns a frozenset of every FQ module name reachable from `start`,
    including `start` itself. External nodes (`source_file=None`) are
    recorded as leaves but not recursed into.

    `max_depth` caps the recursion depth — `start` itself is depth 0;
    a node's children are only expanded while depth < max_depth.

    `cache` is shared memoisation across calls. When supplied, every
    intermediate node's closure is also written to the cache, so a
    subsequent `compute_closure(graph, child, cache=cache)` returns
    in O(1). Cycle-safe via an `in_progress` set: a node visited
    while it's already on the call stack contributes just `{itself}`,
    not its (in-progress) closure.
    """
    in_progress: set[str] = set()

    def _walk(node_name: str, depth: int) -> frozenset[str]:
        if cache is not None and node_name in cache:
            return cache[node_name]
        if node_name in in_progress:
            # Cycle — break by returning just self; callers continue.
            return frozenset({node_name})
        if depth >= max_depth:
            # Beyond cap: include self but don't recurse. Don't cache —
            # this result is depth-dependent, not a true closure.
            return frozenset({node_name})
        node = graph.get(node_name)
        if node is None or node.source_file is None:
            # External or unknown — leaf in the graph.
            result = frozenset({node_name})
            if cache is not None:
                cache[node_name] = result
            return result
        in_progress.add(node_name)
        accumulator: set[str] = {node_name}
        for imp in node.imports:
            accumulator |= _walk(imp, depth + 1)
        in_progress.discard(node_name)
        result = frozenset(accumulator)
        if cache is not None:
            cache[node_name] = result
        return result

    return _walk(start, 0)
