#!/usr/bin/env python3
"""Detector for scout-import-fallback.

Detects "silent fallback to less-secure default" patterns in Python
source by tracing import closures (via scout_import_fallback_graph)
against the SECURITY_BEARING_LEAVES corpus.

Three shapes:
- PAIRED_IMPORT: try: import X / except: import Y
- ANY_FALLBACK: try: import X / except: <anything>
- FEATURE_FLAG: try: import X; HAS_X=True / except: HAS_X=False, plus
  later if HAS_X: secure_path / else: insecure_path

Four signals:
- DIFF (paired): closure(secure) - closure(fallback) intersects corpus
- DIRECT: imported name is itself a corpus leaf
- TRANSITIVE: closure intersects corpus (no diff to compute)
- WEAK: no corpus contact (suppressed by default; stderr-audited)

Severity flat LOW (slice-6 calibration); CWE-636 (Failing Open).
Findings flow through CORROBORATED_STATIC_ONLY (poc_applicable=False).
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import json
import sys
import tokenize
from enum import Enum
from io import BytesIO
from pathlib import Path

from scout_import_fallback_graph import (
    ModuleNode,
    build_import_graph,
    compute_closure,
)


# Optional: libcst for comment-aware analysis. Graceful degradation
# per slice-9 D10: missing libcst → stdlib ast + tokenize fallback.
try:
    import libcst as cst
    _LIBCST_AVAILABLE = True
except ImportError:
    _LIBCST_AVAILABLE = False

_LIBCST_WARNED = False


class FallbackShape(str, Enum):
    """The structural shape of an import-fallback site."""
    PAIRED_IMPORT = "paired-import"
    ANY_FALLBACK  = "any-fallback"
    FEATURE_FLAG  = "feature-flag"


class Signal(str, Enum):
    """The closure-vs-corpus evidence strength."""
    DIFF       = "diff"
    DIRECT     = "direct"
    TRANSITIVE = "transitive"
    WEAK       = "weak"


# Audit-bounded list of well-known security primitives. Adding to this
# list is a deliberate slice action with rationale in the closing note.
SECURITY_BEARING_LEAVES: frozenset[str] = frozenset({
    "cryptography", "ssl", "OpenSSL", "nacl", "paramiko",
    "bcrypt", "argon2", "passlib", "jwt", "oauthlib",
    "defusedxml", "secrets", "hashlib",
})


def _parse(src: str):
    """Parse source. libcst Module when available; ast.Module fallback.

    Single warning at first call when libcst is unavailable.
    """
    global _LIBCST_WARNED
    if _LIBCST_AVAILABLE:
        return cst.parse_module(src)
    if not _LIBCST_WARNED:
        print(
            "scout_import_fallback_detect: libcst unavailable; using stdlib "
            "ast fallback. Comment suppression precision reduced.",
            file=sys.stderr,
        )
        _LIBCST_WARNED = True
    return ast.parse(src)


def _parse_to_string(tree) -> str:
    """Render a parsed tree back to source. libcst → tree.code; ast → ast.unparse."""
    if hasattr(tree, "code"):
        return tree.code
    return ast.unparse(tree)


@dataclasses.dataclass(frozen=True)
class TryImportBlock:
    """Raw try/except-import block before shape classification."""
    try_line: int
    except_line: int
    end_line: int
    secure_module: str               # the FQ name imported in try-body
    fallback_module: str | None      # the FQ name imported in except-body, if any
    flag_assigned_true: str | None   # symbol set to True in try-body (feature-flag candidate)
    flag_assigned_false: str | None  # symbol set to False in except-body (feature-flag candidate)
    except_handler_body: list        # raw nodes; used for shape classification


def _collect_try_import_blocks(tree) -> list[TryImportBlock]:
    """Walk `tree`; return every Try whose body is `Import|ImportFrom` and
    whose except handler catches ImportError/ModuleNotFoundError/bare.
    """
    nodes = _walk_tree(tree)
    out: list[TryImportBlock] = []
    for node in nodes:
        if not _is_try_node(node):
            continue
        try_body = _try_body(node)
        secure_module, flag_true = _extract_import_and_flag(try_body)
        if not secure_module:
            continue
        # Must have at least one except clause that catches ImportError.
        handlers = _try_handlers(node)
        ie_handler = next((h for h in handlers if _catches_import_error(h)), None)
        if ie_handler is None:
            continue
        except_body = _handler_body(ie_handler)
        fallback_module, flag_false = _extract_import_and_flag(except_body)
        try_line, except_line, end_line = _try_lines(node, ie_handler)
        out.append(TryImportBlock(
            try_line=try_line,
            except_line=except_line,
            end_line=end_line,
            secure_module=secure_module,
            fallback_module=fallback_module,
            flag_assigned_true=flag_true,
            flag_assigned_false=flag_false,
            except_handler_body=except_body,
        ))
    return out


def _walk_tree(tree):
    """Walk every node — libcst or ast."""
    if _LIBCST_AVAILABLE and isinstance(tree, cst.CSTNode):
        # libcst — collect via a visitor.
        nodes: list = []
        class _Collect(cst.CSTVisitor):
            def on_visit(self, node):
                nodes.append(node)
                return True
        tree.visit(_Collect())
        return nodes
    return list(ast.walk(tree))


def _is_try_node(node) -> bool:
    """True for `try:` and (PEP 654) `try*:` blocks across both parsers."""
    # ast.TryStar exists in 3.11+; cst.TryStar exists in libcst 1.0+.
    ast_try_types = (ast.Try, getattr(ast, "TryStar", ast.Try))
    if _LIBCST_AVAILABLE:
        cst_try_types = (cst.Try, getattr(cst, "TryStar", cst.Try))
        if isinstance(node, cst_try_types):
            return True
    return isinstance(node, ast_try_types)


def _try_body(node) -> list:
    if _LIBCST_AVAILABLE:
        cst_try_types = (cst.Try, getattr(cst, "TryStar", cst.Try))
        if isinstance(node, cst_try_types):
            return list(node.body.body)
    return list(node.body)


def _try_handlers(node) -> list:
    if _LIBCST_AVAILABLE:
        cst_try_types = (cst.Try, getattr(cst, "TryStar", cst.Try))
        if isinstance(node, cst_try_types):
            return list(node.handlers)
    return list(node.handlers)


def _handler_body(handler) -> list:
    if _LIBCST_AVAILABLE and isinstance(handler, cst.ExceptHandler):
        return list(handler.body.body)
    return list(handler.body)


def _catches_import_error(handler) -> bool:
    """Bare except, except ImportError, or except (ImportError, ...)?"""
    if _LIBCST_AVAILABLE and isinstance(handler, cst.ExceptHandler):
        if handler.type is None:
            return True  # bare except
        return _libcst_type_catches_ie(handler.type)
    if isinstance(handler, ast.ExceptHandler):
        if handler.type is None:
            return True
        return _ast_type_catches_ie(handler.type)
    return False


def _ast_type_catches_ie(node) -> bool:
    if isinstance(node, ast.Name) and node.id in ("ImportError", "ModuleNotFoundError"):
        return True
    if isinstance(node, ast.Tuple):
        return any(
            isinstance(e, ast.Name) and e.id in ("ImportError", "ModuleNotFoundError")
            for e in node.elts
        )
    return False


def _libcst_type_catches_ie(type_node) -> bool:
    if isinstance(type_node, cst.Name) and type_node.value in ("ImportError", "ModuleNotFoundError"):
        return True
    if isinstance(type_node, cst.Tuple):
        for elt in type_node.elements:
            if isinstance(elt.value, cst.Name) and elt.value.value in ("ImportError", "ModuleNotFoundError"):
                return True
    return False


def _extract_import_and_flag(body: list) -> tuple[str | None, str | None]:
    """From a try-body or except-body, return (imported_module, flag_symbol).

    `imported_module` is set if exactly one statement is Import/ImportFrom.
    `flag_symbol` is set if ALSO an Assign(name = True/False) sibling exists
    (feature-flag pattern).

    For `from M import X as Y` (asname present, single alias) the returned
    name is `M.X`, since that idiom is the "module aliasing" shape and X is
    the actual submodule whose closure we want to walk. For
    `from M import X` (no asname) we return `M` — X is more likely a
    class/symbol import in that case. Plain `import M` returns `M`.

    Module-aliasing resolution caveat: when ``from M import X as Y`` is
    interpreted as ``M.X``, the closure lookup in ``_classify_signal``
    only finds a graph node for ``M.X`` if ``M/X.py`` exists in the
    target tree (the graph builder enumerates files via
    ``_resolve_fqname``, independent of any import-edge recording).
    For class/function imports (e.g. ``from collections import
    namedtuple as nt``), no ``M.X`` graph node exists, so
    ``compute_closure(graph, "M.X")`` returns ``{M.X}`` as an external
    leaf and the detector gracefully degrades to a softer signal
    (TRANSITIVE/WEAK rather than DIFF). No false positives; the
    detector simply emits less-confident or no findings on
    class-import idioms — which is the conservative choice for an
    architectural detector.
    """
    imported: str | None = None
    flag: str | None = None
    for stmt in body:
        # Unwrap libcst SimpleStatementLine if needed.
        node = stmt
        if _LIBCST_AVAILABLE and isinstance(stmt, cst.SimpleStatementLine):
            for inner in stmt.body:
                node = inner
                if _LIBCST_AVAILABLE and isinstance(inner, cst.Import):
                    if inner.names:
                        imported = _libcst_dotted_name(inner.names[0].name)
                elif _LIBCST_AVAILABLE and isinstance(inner, cst.ImportFrom):
                    base = _libcst_dotted_name(inner.module) if inner.module else None
                    imported = base
                    # Module-aliasing idiom: from M import X as Y → resolve M.X.
                    if (base
                            and not isinstance(inner.names, cst.ImportStar)
                            and len(inner.names) == 1
                            and inner.names[0].asname is not None):
                        leaf = inner.names[0].name
                        if isinstance(leaf, cst.Name):
                            imported = f"{base}.{leaf.value}"
                elif _LIBCST_AVAILABLE and isinstance(inner, cst.Assign):
                    if len(inner.targets) == 1 and isinstance(inner.targets[0].target, cst.Name):
                        flag = inner.targets[0].target.value
        else:
            if isinstance(node, ast.Import) and node.names:
                imported = node.names[0].name
            elif isinstance(node, ast.ImportFrom):
                base = node.module
                imported = base
                # Module-aliasing idiom: from M import X as Y → resolve M.X.
                if (base
                        and len(node.names) == 1
                        and node.names[0].asname is not None
                        and node.names[0].name != "*"):
                    imported = f"{base}.{node.names[0].name}"
            elif isinstance(node, ast.Assign):
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    flag = node.targets[0].id
    return imported, flag


def _libcst_dotted_name(node) -> str:
    """Convert a libcst Attribute/Name chain to a dotted string."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, cst.Attribute):
        parts.append(cur.attr.value)
        cur = cur.value
    if isinstance(cur, cst.Name):
        parts.append(cur.value)
    return ".".join(reversed(parts))


def _try_lines(try_node, ie_handler) -> tuple[int, int, int]:
    """Return (try_line, except_line, end_line) for evidence emission."""
    # ast: nodes have `lineno` and `end_lineno`.
    if isinstance(try_node, ast.Try):
        try_line = try_node.lineno
        except_line = ie_handler.lineno
        end_line = try_node.end_lineno or try_node.lineno
        return try_line, except_line, end_line
    # libcst: requires PositionProvider metadata; here we use 0 as
    # placeholder and let scan_file populate via metadata wrapper.
    return 0, 0, 0


def _classify_shape(block: TryImportBlock) -> FallbackShape:
    """Classify the block as PAIRED_IMPORT, ANY_FALLBACK, or FEATURE_FLAG.

    PAIRED_IMPORT: except-body is exactly one Import/ImportFrom.
    FEATURE_FLAG: try-body and except-body both assign the same name
                  to a Boolean constant (True in try, False in except).
    ANY_FALLBACK: everything else.
    """
    # Feature-flag check first.
    # We verify the except-side assigns False, but trust that the try-side's
    # flag_assigned_true was paired with the import (extracted in
    # _extract_import_and_flag). This is asymmetric by design — the False side
    # is the load-bearing branch for the "fail-open" semantics, and downstream
    # `if HAS_X:` evaluates the runtime value regardless of literal True.
    if (block.flag_assigned_true and block.flag_assigned_false and
            block.flag_assigned_true == block.flag_assigned_false and
            _is_assigned_to_boolean(block.except_handler_body, block.flag_assigned_false, expected=False)):
        return FallbackShape.FEATURE_FLAG
    # Paired-import check.
    if block.fallback_module is not None:
        return FallbackShape.PAIRED_IMPORT
    return FallbackShape.ANY_FALLBACK


def _is_assigned_to_boolean(body: list, name: str, expected: bool) -> bool:
    """Return True if `body` contains `name = True/False` matching `expected`."""
    for stmt in body:
        node = stmt
        if _LIBCST_AVAILABLE and isinstance(stmt, cst.SimpleStatementLine):
            for inner in stmt.body:
                if isinstance(inner, cst.Assign) and len(inner.targets) == 1:
                    target = inner.targets[0].target
                    val = inner.value
                    if (isinstance(target, cst.Name) and target.value == name
                            and isinstance(val, cst.Name)
                            and val.value == ("True" if expected else "False")):
                        return True
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            val = node.value
            if (isinstance(target, ast.Name) and target.id == name
                    and isinstance(val, ast.Constant) and val.value is expected):
                return True
    return False


@dataclasses.dataclass(frozen=True)
class FlagBranchSite:
    """A site where `if <flag>:` gates code."""
    start_line: int
    end_line: int


def _resolve_feature_flag_branches(tree, flag_symbol: str) -> list[FlagBranchSite]:
    """Walk the tree; return every `if <flag_symbol>:` location."""
    out: list[FlagBranchSite] = []
    for node in _walk_tree(tree):
        if isinstance(node, ast.If):
            if isinstance(node.test, ast.Name) and node.test.id == flag_symbol:
                out.append(FlagBranchSite(
                    start_line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                ))
        elif _LIBCST_AVAILABLE and isinstance(node, cst.If):
            if isinstance(node.test, cst.Name) and node.test.value == flag_symbol:
                # libcst position via metadata; for now use 0 placeholder
                # (Task-3 scan_file populates via PositionProvider wrapper).
                out.append(FlagBranchSite(start_line=0, end_line=0))
    return out


def _is_suppressed(tree, src: str, try_line: int) -> bool:
    """Return True if `# noqa: scout-import-fallback` appears on `try_line`.

    Bare `# noqa` (no scope) is NOT honoured — too broad.

    Implementation: tokenize the source separately to find the
    trailing comment on the line. libcst metadata could do this for
    us when available, but the tokenize approach is portable across
    both parser modes.
    """
    try:
        for tok in tokenize.tokenize(BytesIO(src.encode("utf-8")).readline):
            if tok.type != tokenize.COMMENT:
                continue
            if tok.start[0] != try_line:
                continue
            comment = tok.string.lstrip("#").strip()
            # Match "noqa: scout-import-fallback" (case-insensitive),
            # allowing trailing tokens.
            if not comment.lower().startswith("noqa"):
                continue
            # Require explicit scope.
            after_noqa = comment[4:].lstrip()
            if not after_noqa.startswith(":"):
                return False
            scopes = after_noqa[1:].strip().lower()
            # Match against the scout name; allow comma-separated scopes.
            for scope in scopes.split(","):
                if scope.strip() == "scout-import-fallback":
                    return True
    except (tokenize.TokenizeError, IndentationError, SyntaxError):
        return False
    return False


@dataclasses.dataclass(frozen=True)
class ImportFallbackFinding:
    """A single emitted finding from the detector."""
    source_file: str
    source_line: int
    line_range: tuple[int, int]
    shape: FallbackShape
    signal: Signal
    secure_module: str
    fallback_module: str | None
    flag_symbol: str | None
    matched_leaves: tuple[str, ...]
    trace_path: tuple[str, ...]
    suppressed: bool


def _match_leaves(closure: frozenset[str],
                  corpus: frozenset[str] = SECURITY_BEARING_LEAVES) -> frozenset[str]:
    """Return the subset of `corpus` appearing in `closure`'s
    first-dotted-component projection.

    Examples:
      closure = {"cryptography.hazmat.primitives"} → match cryptography
      closure = {"snap7.s7commplus"} → no match (snap7 not in corpus)
    """
    first_components = {fq.split(".", 1)[0] for fq in closure}
    return frozenset(corpus & first_components)


def _shortest_path(graph: dict, start: str,
                   targets: frozenset[str]) -> tuple[str, ...]:
    """BFS from `start`; return the shortest path whose final node's
    first-dotted-component is in `targets`. Returns (start,) if no
    path found (caller treats empty-tail as WEAK signal).
    """
    if not start:
        return ()
    parents: dict[str, str] = {start: ""}  # "" means root
    frontier = [start]
    found_terminal: str | None = None
    while frontier:
        cur = frontier.pop(0)
        first = cur.split(".", 1)[0]
        if first in targets:
            found_terminal = cur
            break
        node = graph.get(cur)
        if node is None or node.source_file is None:
            continue
        for imp in node.imports:
            if imp not in parents:
                parents[imp] = cur
                frontier.append(imp)
    if found_terminal is None:
        return (start,)
    # Reconstruct.
    path = [found_terminal]
    while parents.get(path[-1]):
        path.append(parents[path[-1]])
    return tuple(reversed(path))


def _classify_signal(block: TryImportBlock,
                     graph: dict,
                     cache: dict[str, frozenset[str]]) -> tuple[Signal, tuple[str, ...], tuple[str, ...]]:
    """Compute closure-based signal for a try-import block.

    Returns (signal, matched_leaves, trace_path).

    PAIRED:
        diff = closure(secure) - closure(fallback); if diff ∩ corpus, DIFF.
        Else fall through to TRANSITIVE check on secure_module.
    ANY_FALLBACK / FEATURE_FLAG / fall-through:
        If secure_module name is itself a corpus leaf → DIRECT.
        Else closure(secure_module) ∩ corpus → TRANSITIVE.
        Else WEAK.
    """
    secure = block.secure_module
    fallback = block.fallback_module

    if fallback:
        secure_closure = compute_closure(graph, secure, cache=cache)
        fallback_closure = compute_closure(graph, fallback, cache=cache)
        diff_closure = secure_closure - fallback_closure
        diff_leaves = _match_leaves(diff_closure)
        if diff_leaves:
            return (
                Signal.DIFF,
                tuple(sorted(diff_leaves)),
                _shortest_path(graph, secure, diff_leaves),
            )

    # Direct: secure_module's first component is a leaf.
    secure_first = secure.split(".", 1)[0]
    if secure_first in SECURITY_BEARING_LEAVES:
        return Signal.DIRECT, (secure_first,), (secure,)

    # Transitive: closure(secure) intersects the corpus.
    secure_closure = compute_closure(graph, secure, cache=cache)
    leaves = _match_leaves(secure_closure)
    if leaves:
        return (
            Signal.TRANSITIVE,
            tuple(sorted(leaves)),
            _shortest_path(graph, secure, leaves),
        )

    return Signal.WEAK, (), (secure,)


def scan_file(path: Path,
              graph: dict,
              cache: dict[str, frozenset[str]]) -> list[ImportFallbackFinding]:
    """Per-file detection. Returns non-WEAK, non-suppressed findings.

    WEAK signals + suppressed findings are stderr-audited but not
    returned (operator-visible audit trail without polluting candidate
    stream).
    """
    try:
        src = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        print(
            f"scout_import_fallback_detect: skipped {path}: {e}",
            file=sys.stderr,
        )
        return []
    try:
        tree = _parse(src)
    except Exception as e:
        print(
            f"scout_import_fallback_detect: skipped {path}: {e}",
            file=sys.stderr,
        )
        return []

    blocks = _collect_try_import_blocks(tree)
    out: list[ImportFallbackFinding] = []
    for block in blocks:
        shape = _classify_shape(block)
        signal, matched_leaves, trace_path = _classify_signal(block, graph, cache)

        # Build line_range, possibly extended by feature-flag branches.
        start_line = block.try_line
        end_line = block.end_line
        flag_symbol = None
        if shape == FallbackShape.FEATURE_FLAG and block.flag_assigned_true:
            flag_symbol = block.flag_assigned_true
            sites = _resolve_feature_flag_branches(tree, flag_symbol)
            for s in sites:
                if s.start_line and s.end_line:
                    end_line = max(end_line, s.end_line)

        if signal == Signal.WEAK:
            print(
                f"scout_import_fallback_detect: WEAK signal at {path}:{start_line}: "
                f"shape={shape.value} secure={block.secure_module} "
                f"trace_terminates_at={trace_path[-1] if trace_path else block.secure_module}",
                file=sys.stderr,
            )
            continue

        suppressed = _is_suppressed(tree, src, block.try_line)
        finding = ImportFallbackFinding(
            source_file=str(path),
            source_line=start_line,
            line_range=(start_line, end_line),
            shape=shape,
            signal=signal,
            secure_module=block.secure_module,
            fallback_module=block.fallback_module,
            flag_symbol=flag_symbol,
            matched_leaves=matched_leaves,
            trace_path=trace_path,
            suppressed=suppressed,
        )
        if suppressed:
            print(
                f"scout_import_fallback_detect: suppressed {path}:{start_line}: "
                f"shape={shape.value} signal={signal.value}",
                file=sys.stderr,
            )
            continue
        out.append(finding)
    return out


def scan_project(target_root: Path,
                 excluded: list[str] | None = None) -> list[ImportFallbackFinding]:
    """One-shot graph build + per-file detection."""
    graph = build_import_graph(target_root, excluded=excluded)
    cache: dict[str, frozenset[str]] = {}
    out: list[ImportFallbackFinding] = []

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

    for path in target_root.rglob("*.py"):
        if _is_excluded(path):
            continue
        out.extend(scan_file(path, graph, cache))
    return out


_CONFIDENCE_BY_SIGNAL: dict[Signal, str] = {
    Signal.DIFF:       "high",
    Signal.DIRECT:     "high",
    Signal.TRANSITIVE: "medium",
}


def _finding_to_jsonl(f: ImportFallbackFinding, finding_id: str) -> dict:
    confidence = _CONFIDENCE_BY_SIGNAL.get(f.signal, "low")
    description = (
        f"Import-fallback site at {f.source_file}:{f.source_line}: "
        f"secure module {f.secure_module!r} traces to security-bearing "
        f"leaves {list(f.matched_leaves)}; fallback may silently degrade."
    )
    parts = [
        f"{f.source_file}:{f.source_line}: import-fallback",
        f"shape={f.shape.value}",
        f"signal={f.signal.value}",
        f"secure={f.secure_module}",
    ]
    if f.fallback_module:
        parts.append(f"fallback={f.fallback_module}")
    if f.flag_symbol:
        parts.append(f"flag={f.flag_symbol}")
    parts.append(f"leaves=[{','.join(f.matched_leaves)}]")
    parts.append(f"trace={'→'.join(f.trace_path)}")
    parts.append(f"(lines {f.line_range[0]}-{f.line_range[1]})")
    evidence = " ".join(parts)
    return {
        "id": finding_id,
        "scout": "scout-import-fallback",
        "status": "CANDIDATE",
        "title": description,
        "cwe": ["CWE-636"],
        "severity": "low",
        "confidence": confidence,
        "file": f.source_file,
        "line_range": list(f.line_range),
        "description": description,
        "evidence": evidence,
        "poc_applicable": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="scout-import-fallback detector"
    )
    parser.add_argument("target", help="Target directory (usually scope.target_root)")
    parser.add_argument(
        "--exclude-subpath",
        action="append",
        default=[],
        metavar="SUBPATH",
        help=(
            "Subpath under the target to skip when enumerating .py files. "
            "Repeatable. Path-prefix match. Wire from scope.excluded_subpaths."
        ),
    )
    parser.add_argument("--id-prefix", default="FND-IMP-", help="Finding-ID prefix")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    findings = scan_project(target, excluded=args.exclude_subpath)
    for i, f in enumerate(findings, start=1):
        rec = _finding_to_jsonl(f, f"{args.id_prefix}{i:04d}")
        print(json.dumps(rec))


if __name__ == "__main__":
    main()
