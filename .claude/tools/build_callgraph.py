#!/usr/bin/env python3
"""
Build a structural callgraph and symbol table for a Python project.

Produces a JSON summary that sub-agents can query without having to read
every file. Gives the threat modeller and scouts a map of the codebase.

Usage:
    python .claude/tools/build_callgraph.py <target_dir> [--output <path>]

Output format:
{
  "modules": {
    "<module.path>": {
      "file": "<relative path>",
      "classes": ["ClassName"],
      "functions": ["function_name"],
      "imports": ["imported.module"],
      "external_inputs": [  // best-effort detection of external data entry points
        {"line": 42, "type": "network|file|env|cli|http", "context": "..."}
      ]
    }
  },
  "callgraph": {
    "<caller>": ["<callee>", "<callee>"]
  },
  "statistics": {
    "module_count": 0,
    "function_count": 0,
    "class_count": 0,
    "loc": 0
  }
}
"""

import argparse
import ast
import json
import os
import sys
from pathlib import Path


EXTERNAL_INPUT_SIGNATURES = {
    "network": [
        "socket.recv",
        "socket.recvfrom",
        "socket.accept",
        "asyncio.open_connection",
    ],
    "http": [
        "request.get_json",
        "request.data",
        "request.form",
        "request.args",
        "request.files",
        "request.json",
        "request.body",
        "Request.body",
    ],
    "file": [
        "open",  # noisy; context matters
        "pathlib.Path.read_bytes",
        "pathlib.Path.read_text",
    ],
    "env": [
        "os.environ.get",
        "os.getenv",
    ],
    "cli": [
        "sys.argv",
        "argparse.ArgumentParser.parse_args",
    ],
}


class CodeAnalyser(ast.NodeVisitor):
    def __init__(self) -> None:
        self.classes: list[str] = []
        self.functions: list[str] = []
        self.imports: list[str] = []
        self.calls: list[tuple[str, str]] = []  # (caller, callee)
        self.external_inputs: list[dict] = []
        self._current_scope: list[str] = ["<module>"]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.classes.append(node.name)
        self._current_scope.append(node.name)
        self.generic_visit(node)
        self._current_scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        qualified_name = ".".join(self._current_scope + [node.name])
        self.functions.append(qualified_name)
        self._current_scope.append(node.name)
        self.generic_visit(node)
        self._current_scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        qualified_name = ".".join(self._current_scope + [node.name])
        self.functions.append(qualified_name)
        self._current_scope.append(node.name)
        self.generic_visit(node)
        self._current_scope.pop()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self.imports.append(f"{module}.{alias.name}" if module else alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee = self._render_call_target(node.func)
        caller = ".".join(self._current_scope)
        if callee:
            self.calls.append((caller, callee))
            # Check for external input signatures.
            for input_type, sigs in EXTERNAL_INPUT_SIGNATURES.items():
                for sig in sigs:
                    if callee == sig or callee.endswith("." + sig.split(".")[-1]):
                        self.external_inputs.append(
                            {
                                "line": node.lineno,
                                "type": input_type,
                                "context": callee,
                            }
                        )
        self.generic_visit(node)

    def _render_call_target(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._render_call_target(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""


def analyse_file(path: Path, repo_root: Path) -> dict:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, OSError):
        return {
            "file": str(path.relative_to(repo_root)),
            "error": "parse_failed",
            "classes": [],
            "functions": [],
            "imports": [],
            "external_inputs": [],
            "loc": 0,
        }

    analyser = CodeAnalyser()
    analyser.visit(tree)

    return {
        "file": str(path.relative_to(repo_root)),
        "classes": analyser.classes,
        "functions": analyser.functions,
        "imports": analyser.imports,
        "calls": analyser.calls,
        "external_inputs": analyser.external_inputs,
        "loc": len(source.splitlines()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build callgraph for a Python project")
    parser.add_argument("target", help="Target directory to analyse")
    parser.add_argument(
        "--output",
        default=".claude/output/callgraph.json",
        help="Output JSON path",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[
            ".git", "__pycache__", ".venv", "venv", ".tox",
            ".pytest_cache", ".mypy_cache", ".ruff_cache",
            "build", "dist", "node_modules",
        ],
        help=(
            "Directory names to exclude. Default set mirrors scope_resolve.py's "
            "ALWAYS_EXCLUDE (never-reviewable paths only). The orchestrator "
            "passes SELF_EXCLUDE separately when appropriate."
        ),
    )
    args = parser.parse_args()

    # FND-PATH-0205: positional <target> must resolve under cwd. Parity with
    # baseline_sast.py (FND-PATH-0103) and scope_resolve.py (D15). Containment
    # is checked BEFORE existence so attackers probing non-existent out-of-cwd
    # paths get the refusal exit code rather than a looser "not found."
    cwd = Path.cwd().resolve()
    target = Path(args.target).resolve()
    try:
        target.relative_to(cwd)
    except ValueError:
        print(
            f"ERROR: <target> must resolve under cwd. Got: {target} (cwd={cwd})",
            file=sys.stderr,
        )
        sys.exit(2)
    if not target.exists():
        print(f"Target does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    modules: dict[str, dict] = {}
    callgraph: dict[str, list[str]] = {}
    total_loc = 0
    class_count = 0
    func_count = 0

    target_resolved = target.resolve()
    for py_file in target.rglob("*.py"):
        if any(excl in py_file.parts for excl in args.exclude):
            continue
        # FND-PATH-0005: rglob matches FILE symlinks; a symlink named *.py
        # pointing at /etc/hostname leaks that file's content via read_text.
        # Skip anything whose realpath escapes the target root.
        try:
            resolved = py_file.resolve()
        except (OSError, RuntimeError):
            continue
        if not resolved.is_relative_to(target_resolved):
            print(
                f"Skipping symlink escape: {py_file} -> {resolved}",
                file=sys.stderr,
            )
            continue
        result = analyse_file(py_file, target)
        module_key = str(py_file.relative_to(target)).replace("/", ".").rstrip(".py")
        modules[module_key] = {
            "file": result["file"],
            "classes": result["classes"],
            "functions": result["functions"],
            "imports": result["imports"],
            "external_inputs": result["external_inputs"],
            "loc": result["loc"],
        }
        for caller, callee in result.get("calls", []):
            key = f"{module_key}:{caller}"
            callgraph.setdefault(key, []).append(callee)
        total_loc += result["loc"]
        class_count += len(result["classes"])
        func_count += len(result["functions"])

    summary = {
        "modules": modules,
        "callgraph": callgraph,
        "statistics": {
            "module_count": len(modules),
            "function_count": func_count,
            "class_count": class_count,
            "loc": total_loc,
        },
    }

    # FND-PATH-0006: --output accepts any path; the tool then mkdir's parents
    # and write_text's the JSON. Require confinement under .claude/output/.
    output_path = Path(args.output).resolve()
    allowed_root = Path(".claude/output").resolve()
    try:
        output_path.relative_to(allowed_root)
    except ValueError:
        print(
            f"ERROR: --output must resolve under .claude/output/. Got: {output_path}",
            file=sys.stderr,
        )
        sys.exit(2)
    # FND-PATH-0302 (closed slice-5): O_NOFOLLOW alone guards only the leaf;
    # an ancestor-symlink swap (.claude/output -> /tmp/evil) redirects the
    # write. Route through _safe_write which walks every component with
    # O_NOFOLLOW via dir_fd, eliminating the ancestor-symlink primitive.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _safe_write import safe_mkdir_p, safe_write_text  # noqa: E402

    safe_mkdir_p(output_path.parent)
    safe_write_text(output_path, json.dumps(summary, indent=2))
    print(f"Wrote callgraph summary to {output_path}")
    print(
        f"  {summary['statistics']['module_count']} modules, "
        f"{summary['statistics']['function_count']} functions, "
        f"{summary['statistics']['class_count']} classes, "
        f"{summary['statistics']['loc']} LOC"
    )


if __name__ == "__main__":
    main()
