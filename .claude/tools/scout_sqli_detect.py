#!/usr/bin/env python3
"""AST-based detection for scout-sqli.

Walks Python source under the target root; for each cursor-execute
or ORM-raw call whose first argument is non-constant (f-string,
% interpolation, .format(), + concat), emits a candidate finding.

Invoked from the scout-sqli persona via:
    python .claude/tools/scout_sqli_detect.py <target_root>

Prints JSONL findings to stdout. Each finding has poc_applicable: True
(SQL injection is PoC-able via second-statement / UNION-SELECT
falsification; see scout-sqli persona for the PoC pathway).
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import json
import sys
from pathlib import Path


# Method names on cursor-like objects that take a SQL string first arg.
CURSOR_EXECUTE_METHODS: tuple[str, ...] = (
    "execute", "executemany", "executescript",
)

# ORM raw-query method names.
ORM_RAW_METHODS: tuple[str, ...] = ("raw", "extra")

# Substrings in enclosing function names that suggest HTTP handler
# / request dispatch — upgrades severity from high to critical.
HANDLER_NAME_SUBSTRINGS: tuple[str, ...] = (
    "do_get", "do_post", "do_put", "do_delete", "do_patch", "do_head",
    "handle_", "_handler", "_view", "_route",
)


@dataclasses.dataclass(frozen=True)
class Finding:
    source_file: str
    source_line: int
    cwe: str
    severity: str
    confidence: str
    sink: str
    evidence: str
    description: str
    poc_applicable: bool = True
    enclosing_function: str = ""


def _is_interpolated_string(node: ast.AST) -> bool:
    """True if the AST node is an f-string, %-interp, +-concat, or .format()."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, (ast.Mod, ast.Add)):
            # At least one operand must be a string-ish leaf.
            return True
    if isinstance(node, ast.Call):
        # Pattern: "...".format(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            if isinstance(node.func.value, (ast.Constant, ast.JoinedStr)):
                return True
    return False


def _enclosing_function_name(node: ast.AST, tree: ast.AST) -> str:
    """Best-effort: walk up the AST to find the enclosing FunctionDef.

    ast doesn't natively track parents; we do a single pre-pass over the
    tree to build a parent map.
    """
    parent_of: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_of[id(child)] = parent
    current: ast.AST | None = node
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
        current = parent_of.get(id(current))
    return ""


def _severity_for(enclosing: str) -> str:
    low = enclosing.lower()
    if any(sub in low for sub in HANDLER_NAME_SUBSTRINGS):
        return "critical"
    return "high"


def _describe_sink(call_node: ast.Call) -> str:
    """Render a short 'obj.method' or 'text' description of the sink."""
    if isinstance(call_node.func, ast.Attribute):
        return f".{call_node.func.attr}"
    if isinstance(call_node.func, ast.Name):
        return call_node.func.id
    return "<call>"


def _render_source_excerpt(source_lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(source_lines):
        return source_lines[lineno - 1].rstrip()
    return ""


def scan_file(path: Path) -> list[Finding]:
    """Scan a single .py file for SQL-injection candidate patterns."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, OSError):
        return []
    source_lines = source.splitlines()
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not node.args:
            continue
        first_arg = node.args[0]
        if not _is_interpolated_string(first_arg):
            continue

        # Is this a cursor-execute-like call?
        is_cursor_execute = False
        is_text = False
        is_orm_raw = False
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in CURSOR_EXECUTE_METHODS:
                is_cursor_execute = True
            elif attr in ORM_RAW_METHODS:
                is_orm_raw = True
        elif isinstance(node.func, ast.Name):
            if node.func.id == "text":
                is_text = True

        if not (is_cursor_execute or is_text or is_orm_raw):
            continue

        enclosing = _enclosing_function_name(node, tree)
        severity = _severity_for(enclosing)
        sink_label = _describe_sink(node)
        excerpt = _render_source_excerpt(source_lines, node.lineno)

        findings.append(Finding(
            source_file=str(path),
            source_line=node.lineno,
            cwe="CWE-89",
            severity=severity,
            confidence="medium",
            sink=sink_label,
            evidence=excerpt,
            description=(
                f"Interpolated SQL passed to {sink_label!r} "
                f"(in function {enclosing!r}); SQL injection candidate."
            ),
            enclosing_function=enclosing,
        ))

    return findings


def scan_project(target_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for py in target_root.rglob("*.py"):
        findings.extend(scan_file(py))
    return findings


def _finding_to_jsonl(f: Finding, finding_id: str) -> dict:
    return {
        "id": finding_id,
        "scout": "scout-sqli",
        "status": "CANDIDATE",
        "title": f.description,
        "cwe": [f.cwe],
        "severity": f.severity,
        "confidence": f.confidence,
        "file": f.source_file,
        "line_range": [f.source_line, f.source_line],
        "sink": f.sink,
        "enclosing_function": f.enclosing_function,
        "description": f.description,
        "evidence": f.evidence,
        "poc_applicable": f.poc_applicable,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="scout-sqli AST detector")
    parser.add_argument("target", help="Target directory (usually scope.target_root)")
    parser.add_argument("--id-prefix", default="FND-SQLI-", help="Finding-ID prefix")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    findings = scan_project(target)
    for i, f in enumerate(findings, start=1):
        rec = _finding_to_jsonl(f, f"{args.id_prefix}{i:04d}")
        print(json.dumps(rec))


if __name__ == "__main__":
    main()
