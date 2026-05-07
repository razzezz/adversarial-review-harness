#!/usr/bin/env python3
"""AST-based detection for scout-template.

Walks Python source under the target root; for each template-engine call
(jinja2 from_string/Template, flask render_template_string, mako Template)
whose first argument is non-constant, emits a candidate finding.

Invoked from the scout-template persona via:
    python .claude/tools/scout_template_detect.py <target_root>

Prints JSONL findings to stdout. poc_applicable: True — SSTI is PoC-able
via template-source falsification (stub Environment captures payload).
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import json
from pathlib import Path


# Template-engine method/function call names to match on.
TEMPLATE_METHOD_NAMES: tuple[str, ...] = ("from_string", "Template")
TEMPLATE_FUNCTION_NAMES: tuple[str, ...] = (
    "render_template_string", "Template",
)

# Handler-name heuristic: upgrades severity.
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


def _is_non_constant_template_source(node: ast.AST) -> bool:
    """True if the argument is plausibly user-controlled template source.

    Covers:
      - f-strings (JoinedStr)
      - % / + interpolation (BinOp)
      - .format() results (Call -> Attribute(attr=format))
      - Any Name reference that isn't an UPPER_CASE module-level constant.
        UPPER_CASE is our convention for compile-time constants; other Names
        (function params, locals, lowercase module vars) may be tainted.
        Persona does final taint reasoning.
    """
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
    if isinstance(node, ast.Name) and not node.id.isupper():
        return True
    return False


def _enclosing_function(node: ast.AST, tree: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    parent_of: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_of[id(child)] = parent
    current: ast.AST | None = node
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = parent_of.get(id(current))
    return None


def _severity_for(enclosing_name: str) -> str:
    low = (enclosing_name or "").lower()
    if any(sub in low for sub in HANDLER_NAME_SUBSTRINGS):
        return "critical"
    return "high"


def _describe_sink(call_node: ast.Call) -> str:
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

        is_template_call = False
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in TEMPLATE_METHOD_NAMES:
                is_template_call = True
        elif isinstance(node.func, ast.Name):
            if node.func.id in TEMPLATE_FUNCTION_NAMES:
                is_template_call = True

        if not is_template_call:
            continue

        fn = _enclosing_function(node, tree)
        first_arg = node.args[0]
        if not _is_non_constant_template_source(first_arg):
            continue

        enclosing_name = fn.name if fn else ""
        severity = _severity_for(enclosing_name)
        sink_label = _describe_sink(node)
        excerpt = _render_source_excerpt(source_lines, node.lineno)

        findings.append(Finding(
            source_file=str(path),
            source_line=node.lineno,
            cwe="CWE-94",
            severity=severity,
            confidence="medium",
            sink=sink_label,
            evidence=excerpt,
            description=(
                f"Non-constant template source passed to {sink_label!r} "
                f"(in function {enclosing_name!r}); SSTI candidate."
            ),
            enclosing_function=enclosing_name,
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
        "scout": "scout-template",
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
    parser = argparse.ArgumentParser(description="scout-template AST detector")
    parser.add_argument("target", help="Target directory (usually scope.target_root)")
    parser.add_argument("--id-prefix", default="FND-TPL-", help="Finding-ID prefix")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    findings = scan_project(target)
    for i, f in enumerate(findings, start=1):
        rec = _finding_to_jsonl(f, f"{args.id_prefix}{i:04d}")
        print(json.dumps(rec))


if __name__ == "__main__":
    main()
