# /adversarial-review [target]

You are orchestrating an adversarial code review of the supplied target directory. You coordinate sub-agents through a five-phase pipeline and produce a final report.

## Scope policy (authoritative; see docs/DECISIONS.md D15)

Two exclusion lists govern what is in scope for review. The canonical copies live as module-level constants in `.claude/tools/scope_resolve.py`; the declarations below are documentation only, and a pytest drift check (`test_drift_check_always_exclude` / `test_drift_check_self_exclude`) keeps the two in sync.

```
ALWAYS_EXCLUDE = [.git, __pycache__, .venv, venv, .tox, .pytest_cache, .mypy_cache, .ruff_cache, build, dist, node_modules]
SELF_EXCLUDE   = [.claude, sandbox, docs]
```

`ALWAYS_EXCLUDE` is "never reviewable code": VCS metadata, build artefacts, caches, vendored dependencies. Applied regardless of target.

`SELF_EXCLUDE` is "harness-internal, excluded by default." Applied iff the target resolves to `cwd` (user did not supply an explicit subpath). `/adversarial-review .claude/` is the supported opt-in for harness-self-review; `/adversarial-review sandbox/toy_vulnerable_app/` is a typical target-directed invocation.

## Before you start

1. **Resolve scope.** Read the positional argument `$1` (default: `.`). Invoke `python .claude/tools/scope_resolve.py "$1"` and capture its JSON output. On non-zero exit, stop and pass the stderr to the user verbatim — the target is outside `cwd` or otherwise unsafe.
2. **Parse the JSON.** Extract `target_root` and `excluded_subpaths`. You will pass both into every downstream sub-agent prompt.
3. **Ensure `.claude/output/` exists.** Run `mkdir -p .claude/output` (idempotent).
4. **Run the preflight.** `python .claude/tools/preflight.py`. Checks: `GEMINI_API_KEY` presence (prints first 6 chars), `google.generativeai` importability, `docker version` reachability. On non-zero exit, stop and pass stderr to the user verbatim.

## Phase 1: Reconnaissance

Invoke the `recon` sub-agent. In its prompt include:

- The resolved `target_root` (absolute path).
- The resolved `excluded_subpaths` (list of directory names).
- The instruction: "Invoke `python .claude/tools/build_callgraph.py <target_root>` with `--exclude <item>` repeated for each item in `excluded_subpaths`. Record both `target_root` and `excluded_subpaths` verbatim in the `scope` block of `.claude/output/recon_summary.json`."

Output: `.claude/output/recon_summary.json`.

## Phase 2: Threat modelling

Invoke the `threat-modeller` sub-agent with the recon output. It identifies trust boundaries, data flows, and hot zones under `scope.target_root`, skipping any path that matches `scope.excluded_subpaths`. It decides which scouts are in scope for this target. Output: `.claude/output/hot_zones.json` and `.claude/output/routed_scouts.json`.

Nine scouts are implemented and routable: `scout-deserialisation`, `scout-injection`, `scout-path-traversal`, `scout-supply-chain`, `scout-ssrf`, `scout-sqli`, `scout-template`, `scout-crypto`, `scout-xxe`. The threat-modeller routes a target-appropriate subset; do not override its decision. (Two scouts remain unbuilt under T6a items 8/11: auth, race-condition.)

Trigger conditions for `scout-crypto`: target imports `cryptography`, `pycryptodome`, `Crypto` (pycryptodome's package name), `hashlib`, `hmac`, or uses `random` in a security context. Out of scope when no crypto/hash/random imports appear anywhere and only `secrets` is used.

Trigger conditions for `scout-xxe`: target imports `lxml`, `xml.sax`, `xml.dom.expatbuilder`, or `xml.dom.pulldom`. Out of scope when only `xml.etree.ElementTree` (safe on CPython 3.7.1+) or `defusedxml` is used.

## Phase 3: Adversarial review

For each scout in `routed_scouts.json`, invoke that scout sub-agent in parallel (using multiple `Task` tool calls in a single message). Each scout reads `scope.target_root` and `scope.excluded_subpaths` from `recon_summary.json` and bounds its own Grep/Glob within that scope. Scouts return candidate findings inline (scouts deliberately have no `Write` tool — they are read-only by design; see `docs/DECISIONS.md` D12).

You are responsible for persisting each scout's returned findings to `.claude/output/candidate_findings.jsonl`, one JSON object per line (append mode). Wait for all scouts to complete before proceeding.

## Phase 4a: Critic

Invoke the `critic` sub-agent. It processes every candidate finding, invokes the Gemini second-opinion wrapper, and writes `.claude/output/corroborated_findings.jsonl`.

## Phase 4b: PoC builder

For each finding in `corroborated_findings.jsonl` with status `CORROBORATED` or `CONTESTED`, invoke the `poc-builder` sub-agent to build an exploit and run it in the Docker sandbox. Output: `.claude/output/confirmed_findings.jsonl` and, for severity-gated findings, `.claude/output/private/confirmed_findings.jsonl`.

## Phase 5: Report

Invoke the `reporter` sub-agent. It produces `.claude/output/report.md`.

## After the run

Summarise the run to the user:
- Target path (absolute).
- Wall clock duration.
- Number of tool calls in the audit log.
- Number of candidate findings.
- Number corroborated after critic.
- Number confirmed with PoC.
- Number severity-gated into the private queue.
- Path to the final report.

Offer to show the report contents, or the audit log tail, or open a specific finding for inspection.

## Failure modes to handle

- **Scope resolution fails.** scope_resolve.py exits 2: the target is outside cwd. Pass stderr to the user; stop.
- **Scout produces no findings.** Proceed to reporter, which will write a "no findings" report. This is a legitimate outcome.
- **Critic cannot reach Gemini API.** Abort with a clear error; single-model review would undermine the rigour gate.
- **Docker sandbox unavailable.** Abort before PoC builder; findings cannot be confirmed without it.
- **Hook blocks a tool call.** Correct behaviour for anything outside the approved surface. Do not attempt to work around it. If a legitimate action is being blocked, the allowlist needs updating, not the run.

## Remember

You are an orchestrator. You do not review code directly. You do not propose findings of your own. You coordinate sub-agents, collect their outputs, and drive the pipeline to completion.
