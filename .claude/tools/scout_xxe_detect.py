#!/usr/bin/env python3
"""AST-based detection for scout-xxe.

Walks Python source under the target root; emits findings for the three
XXE-relevant parser configurations described in
docs/superpowers/specs/2026-04-28-slice-7-crypto-xxe-scouts-design.md.

Tight-precision: does NOT fire on xml.etree.ElementTree.{parse,fromstring}
alone (safe on CPython 3.7.1+).
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import json
import sys
from pathlib import Path


SAX_EXTERNAL_FEATURE_NAMES: tuple[str, ...] = (
    "feature_external_ges", "feature_external_pes",
)
SAX_EXTERNAL_FEATURE_URIS: tuple[str, ...] = (
    "http://xml.org/sax/features/external-general-entities",
    "http://xml.org/sax/features/external-parameter-entities",
)

EXPATBUILDER_FUNCS: tuple[str, ...] = ("parseString", "parse")


@dataclasses.dataclass(frozen=True)
class Finding:
    source_file: str
    source_line: int
    cwe: str
    severity: str
    confidence: str
    pattern: str
    sink: str
    evidence: str
    description: str
    poc_applicable: bool = True
    enclosing_function: str = ""


def _parent_map(tree: ast.AST) -> dict[int, ast.AST]:
    parent_of: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_of[id(child)] = parent
    return parent_of


def _enclosing_function_name(node: ast.AST, parent_of: dict[int, ast.AST]) -> str:
    current: ast.AST | None = node
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
        current = parent_of.get(id(current))
    return ""


def _render_attribute(node: ast.AST) -> str:
    """Render `a.b.c` from an Attribute chain. Returns '' on unsupported nodes."""
    parts: list[str] = []
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _render_source_excerpt(source_lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(source_lines):
        return source_lines[lineno - 1].rstrip()
    return ""


def _detect_lxml_resolve_entities(node, parent_of, source_lines) -> list[Finding]:
    if not isinstance(node, ast.Call):
        return []
    if not isinstance(node.func, ast.Attribute):
        return []
    if node.func.attr != "XMLParser":
        return []
    # Check whatever's on the value side resolves to 'lxml.etree' or 'etree'.
    # Substring match traded for simplicity; pathological aliases like
    # `import x as metree_helper` would spuriously match but are not
    # encountered in practice.
    base = _render_attribute(node.func.value) or (
        node.func.value.id if isinstance(node.func.value, ast.Name) else ""
    )
    if "etree" not in base:
        return []
    # Look for resolve_entities=True kwarg.
    for kw in node.keywords:
        if kw.arg == "resolve_entities":
            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                enclosing = _enclosing_function_name(node, parent_of)
                excerpt = _render_source_excerpt(source_lines, node.lineno)
                return [Finding(
                    source_file="",
                    source_line=node.lineno,
                    cwe="CWE-611",
                    severity="high",
                    confidence="high",
                    pattern="lxml_resolve_entities",
                    sink=f"{base}.XMLParser(resolve_entities=True)",
                    evidence=excerpt,
                    description=(
                        "lxml XMLParser with resolve_entities=True — "
                        "external entities will be resolved, enabling XXE."
                    ),
                    enclosing_function=enclosing,
                )]
    return []


def _detect_sax_external_entities(node, parent_of, source_lines) -> list[Finding]:
    if not isinstance(node, ast.Call):
        return []
    if not isinstance(node.func, ast.Attribute):
        return []
    if node.func.attr != "setFeature":
        return []
    if len(node.args) < 2:
        return []
    feature_arg, value_arg = node.args[0], node.args[1]
    is_external = False
    if isinstance(feature_arg, ast.Attribute) and feature_arg.attr in SAX_EXTERNAL_FEATURE_NAMES:
        is_external = True
    if isinstance(feature_arg, ast.Constant) and isinstance(feature_arg.value, str):
        if feature_arg.value in SAX_EXTERNAL_FEATURE_URIS:
            is_external = True
    if not is_external:
        return []
    if isinstance(value_arg, ast.Constant) and value_arg.value is True:
        enclosing = _enclosing_function_name(node, parent_of)
        excerpt = _render_source_excerpt(source_lines, node.lineno)
        return [Finding(
            source_file="",
            source_line=node.lineno,
            cwe="CWE-611",
            severity="high",
            confidence="high",
            pattern="sax_external_entities",
            sink="parser.setFeature(feature_external_*=True)",
            evidence=excerpt,
            description=(
                "SAX parser configured with external general/parameter entity "
                "resolution enabled — XXE exploitable."
            ),
            enclosing_function=enclosing,
        )]
    return []


def _detect_expatbuilder_direct(node, parent_of, source_lines) -> list[Finding]:
    if not isinstance(node, ast.Call):
        return []
    if not isinstance(node.func, ast.Attribute):
        return []
    if node.func.attr not in EXPATBUILDER_FUNCS:
        return []
    base = _render_attribute(node.func.value) or (
        node.func.value.id if isinstance(node.func.value, ast.Name) else ""
    )
    if base != "expatbuilder":
        return []
    enclosing = _enclosing_function_name(node, parent_of)
    excerpt = _render_source_excerpt(source_lines, node.lineno)
    return [Finding(
        source_file="",
        source_line=node.lineno,
        cwe="CWE-611",
        severity="medium",
        confidence="medium",
        pattern="expatbuilder_direct",
        sink=f"expatbuilder.{node.func.attr}",
        evidence=excerpt,
        description=(
            f"Direct expatbuilder.{node.func.attr} bypasses minidom's safer "
            "wrappers; entity-resolution defaults are libexpat-controlled."
        ),
        enclosing_function=enclosing,
    )]


def scan_file(path: Path) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, OSError):
        return []
    source_lines = source.splitlines()
    parent_of = _parent_map(tree)
    findings: list[Finding] = []
    for node in ast.walk(tree):
        findings.extend(_detect_lxml_resolve_entities(node, parent_of, source_lines))
        findings.extend(_detect_sax_external_entities(node, parent_of, source_lines))
        findings.extend(_detect_expatbuilder_direct(node, parent_of, source_lines))
    return [dataclasses.replace(f, source_file=str(path)) for f in findings]


def scan_project(target_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for py in target_root.rglob("*.py"):
        findings.extend(scan_file(py))
    return findings


def _finding_to_jsonl(f: Finding, finding_id: str) -> dict:
    return {
        "id": finding_id,
        "scout": "scout-xxe",
        "status": "CANDIDATE",
        "title": f.description,
        "cwe": [f.cwe],
        "severity": f.severity,
        "confidence": f.confidence,
        "pattern": f.pattern,
        "file": f.source_file,
        "line_range": [f.source_line, f.source_line],
        "sink": f.sink,
        "enclosing_function": f.enclosing_function,
        "description": f.description,
        "evidence": f.evidence,
        "poc_applicable": f.poc_applicable,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="scout-xxe AST detector")
    parser.add_argument("target", help="Target directory (usually scope.target_root)")
    parser.add_argument("--id-prefix", default="FND-XXE-", help="Finding-ID prefix")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    findings = scan_project(target)
    for i, f in enumerate(findings, start=1):
        rec = _finding_to_jsonl(f, f"{args.id_prefix}{i:04d}")
        print(json.dumps(rec))


if __name__ == "__main__":
    main()
