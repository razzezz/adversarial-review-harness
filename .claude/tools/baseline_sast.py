#!/usr/bin/env python3
"""
Baseline SAST wrapper.

Runs Bandit and Semgrep against a target directory and writes a normalised
JSON output. Used for the "AI vs traditional SAST" comparison in the
final report. This comparison is the single most persuasive artefact for
a CSO audience, so keep it working.

Usage:
    python .claude/tools/baseline_sast.py <target_dir> [--output <path>]

Requires bandit and semgrep to be available on PATH. Installation is the
user's responsibility (documented in the README).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def run_bandit(target: Path) -> dict:
    if not shutil.which("bandit"):
        return {"error": "bandit not installed", "findings": [], "count": 0}

    result = subprocess.run(
        ["bandit", "-r", str(target), "-f", "json", "-q"],
        capture_output=True,
        text=True,
        timeout=600,
    )
    try:
        data = json.loads(result.stdout)
        findings = data.get("results", [])
        return {
            "findings": [
                {
                    "file": f.get("filename", "").replace(str(target) + "/", ""),
                    "line": f.get("line_number"),
                    "severity": f.get("issue_severity", "").lower(),
                    "confidence": f.get("issue_confidence", "").lower(),
                    "cwe": f.get("issue_cwe", {}).get("id"),
                    "title": f.get("test_name"),
                    "description": f.get("issue_text"),
                }
                for f in findings
            ],
            "count": len(findings),
        }
    except json.JSONDecodeError:
        return {
            "error": "bandit output was not valid JSON",
            "stderr": result.stderr[:1000],
            "findings": [],
            "count": 0,
        }


SEMGREP_CONFIG = ".claude/tools/semgrep_rules/default.yml"


def run_semgrep(target: Path) -> dict:
    if not shutil.which("semgrep"):
        return {"error": "semgrep not installed", "findings": [], "count": 0}

    # FND-INJ-0005: --config=auto pulls rules over HTTPS on every run, which
    # violates the no-network-for-sub-agents invariant. Ship local curated
    # rules; see .claude/tools/semgrep_rules/default.yml.
    result = subprocess.run(
        [
            "semgrep",
            f"--config={SEMGREP_CONFIG}",
            "--json",
            "--quiet",
            "--disable-metrics",
            str(target),
        ],
        capture_output=True,
        text=True,
        timeout=900,
    )
    try:
        data = json.loads(result.stdout)
        findings = data.get("results", [])
        return {
            "findings": [
                {
                    "file": f.get("path", "").replace(str(target) + "/", ""),
                    "line": f.get("start", {}).get("line"),
                    "severity": f.get("extra", {}).get("severity", "").lower(),
                    "confidence": f.get("extra", {})
                    .get("metadata", {})
                    .get("confidence", "")
                    .lower(),
                    "cwe": f.get("extra", {}).get("metadata", {}).get("cwe"),
                    "title": f.get("check_id"),
                    "description": f.get("extra", {}).get("message"),
                }
                for f in findings
            ],
            "count": len(findings),
        }
    except json.JSONDecodeError:
        return {
            "error": "semgrep output was not valid JSON",
            "stderr": result.stderr[:1000],
            "findings": [],
            "count": 0,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Baseline SAST wrapper")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument(
        "--output",
        default=".claude/output/baseline_sast.json",
        help="Output JSON path",
    )
    args = parser.parse_args()

    target = Path(args.target).resolve()
    # FND-PATH-0103: target was unconfined; Bandit/Semgrep enumerated
    # arbitrary filesystem and the critic phase shipped the JSON to Gemini.
    # Require target to resolve under the current working directory.
    cwd = Path.cwd().resolve()
    try:
        target.relative_to(cwd)
    except ValueError:
        print(
            f"ERROR: target must resolve under the current working tree ({cwd}). "
            f"Got: {target}",
            file=sys.stderr,
        )
        sys.exit(2)
    if not target.exists():
        print(f"Target does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    print(f"Running Bandit on {target}...")
    bandit_result = run_bandit(target)
    print(f"  Bandit: {bandit_result['count']} findings")

    print(f"Running Semgrep on {target}...")
    semgrep_result = run_semgrep(target)
    print(f"  Semgrep: {semgrep_result['count']} findings")

    combined = {
        "target": str(target),
        "bandit": bandit_result,
        "semgrep": semgrep_result,
    }

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
    # FND-PATH-0302 (closed slice-5): route through _safe_write to close the
    # ancestor-symlink gap that O_NOFOLLOW-on-leaf alone does not handle.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _safe_write import safe_mkdir_p, safe_write_text  # noqa: E402

    safe_mkdir_p(output_path.parent)
    safe_write_text(output_path, json.dumps(combined, indent=2))
    print(f"Wrote baseline SAST results to {output_path}")


if __name__ == "__main__":
    main()
