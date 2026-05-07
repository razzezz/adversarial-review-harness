#!/usr/bin/env python3
"""
Gemini second-opinion wrapper.

Called by the critic sub-agent for each candidate finding. Sends the finding
to Gemini 2.5 Pro and returns a structured verdict.

Usage:
    python .claude/tools/gemini_critique.py --finding-file <path>

Reads GEMINI_API_KEY from the environment. Does not touch any config files.
Designed to be the only bash path the critic sub-agent has access to.

Output: JSON on stdout with verdict, reasoning, and objections.
"""

import argparse
import json
import os
import sys
from pathlib import Path


CRITIC_PROMPT_TEMPLATE = """You are a senior application security reviewer. Another security reviewer has produced the following candidate finding for a Python codebase. Your job is to independently assess it.

Candidate finding:
{finding_json}

Relevant code snippet (provided by the original reviewer):
{code_snippet}

Your task: determine whether this finding is correct, and respond with a JSON object matching this schema exactly:

{{
  "verdict": "CONCUR" | "REJECT" | "UNSURE",
  "reasoning": "<2-4 sentences explaining your assessment>",
  "objections": [
    "<specific technical objection or concern, if any>",
    "<another objection, if any>"
  ],
  "severity_assessment": "<critical|high|medium|low|cannot_determine>",
  "reachability": "<clearly_reachable|unclear|not_reachable>"
}}

Guidance:
- CONCUR: the finding is a real vulnerability, the exploitation narrative is plausible, and the severity is approximately right.
- REJECT: the finding is a false positive, or the sink is not reachable from untrusted input as claimed, or there's a mitigating control the original reviewer missed.
- UNSURE: you have genuine uncertainty; explain what additional information would resolve it.

Do not add any text outside the JSON object. Do not use markdown fences. Respond only with the JSON."""


def build_prompt(finding: dict) -> str:
    code_snippet = finding.get("code_snippet", "<no snippet provided>")
    finding_without_snippet = {k: v for k, v in finding.items() if k != "code_snippet"}
    return CRITIC_PROMPT_TEMPLATE.format(
        finding_json=json.dumps(finding_without_snippet, indent=2),
        code_snippet=code_snippet,
    )


def call_gemini(prompt: str, api_key: str) -> dict:
    """Call Gemini 2.5 Pro with the given prompt. Returns parsed JSON response."""
    try:
        import google.generativeai as genai
    except ImportError:
        print(
            json.dumps(
                {
                    "verdict": "UNSURE",
                    "reasoning": "google-generativeai package not installed",
                    "objections": ["wrapper cannot run; install google-generativeai"],
                    "severity_assessment": "cannot_determine",
                    "reachability": "unclear",
                }
            )
        )
        sys.exit(0)

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.5-pro")
    response = model.generate_content(
        prompt,
        generation_config={
            "response_mime_type": "application/json",
            "temperature": 0.1,
        },
    )

    try:
        return json.loads(response.text)
    except json.JSONDecodeError:
        return {
            "verdict": "UNSURE",
            "reasoning": "Gemini returned non-JSON output",
            "objections": [f"raw output: {response.text[:500]}"],
            "severity_assessment": "cannot_determine",
            "reachability": "unclear",
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Gemini second-opinion wrapper")
    parser.add_argument(
        "--finding-file",
        required=True,
        help="Path to the finding JSON file to critique",
    )
    args = parser.parse_args()

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print(
            json.dumps(
                {
                    "verdict": "UNSURE",
                    "reasoning": "GEMINI_API_KEY not set in environment",
                    "objections": ["cannot consult second-opinion model"],
                    "severity_assessment": "cannot_determine",
                    "reachability": "unclear",
                }
            )
        )
        sys.exit(0)

    finding_path = Path(args.finding_file).resolve(strict=False)
    allowed_root = Path(".claude/output").resolve()
    # FND-PATH-0004: --finding-file used to accept any path and ship contents
    # to Gemini. Confine to .claude/output/.
    try:
        finding_path.relative_to(allowed_root)
    except ValueError:
        print(
            json.dumps(
                {
                    "verdict": "UNSURE",
                    "reasoning": (
                        f"finding file must resolve under .claude/output/; "
                        f"got {finding_path}"
                    ),
                    "objections": ["wrapper received out-of-scope path"],
                    "severity_assessment": "cannot_determine",
                    "reachability": "unclear",
                }
            )
        )
        sys.exit(0)
    if not finding_path.exists():
        print(
            json.dumps(
                {
                    "verdict": "UNSURE",
                    "reasoning": f"finding file not found: {finding_path}",
                    "objections": ["wrapper received invalid input"],
                    "severity_assessment": "cannot_determine",
                    "reachability": "unclear",
                }
            )
        )
        sys.exit(0)

    try:
        finding = json.loads(finding_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(
            json.dumps(
                {
                    "verdict": "UNSURE",
                    "reasoning": f"could not parse finding file: {e}",
                    "objections": ["wrapper received malformed input"],
                    "severity_assessment": "cannot_determine",
                    "reachability": "unclear",
                }
            )
        )
        sys.exit(0)

    prompt = build_prompt(finding)
    verdict = call_gemini(prompt, api_key)
    verdict["model"] = "gemini-2.5-pro"
    print(json.dumps(verdict))


if __name__ == "__main__":
    main()
