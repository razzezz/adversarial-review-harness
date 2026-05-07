# Adversarial Code Review Harness

A scaffold that turns Claude Code into a purpose-built adversarial security reviewer for Python repositories. You drop the `.claude/` directory into the repo you want reviewed, run `claude`, invoke `/adversarial-review`, and a five-phase pipeline of specialist sub-agents reads, hunts, falsifies, and PoC-tests vulnerabilities. The output is a markdown report and a JSONL audit trail of every tool call the agents made along the way.

The framing is not "we built an AI SAST tool." It is closer to "here is what continuous adversarial code review starts to look like once frontier models are good enough to do it well, with frontier-grade defence-in-depth on the harness itself."

**Status:** ten scout personas live, pipeline runs end-to-end on real Python repositories. Two more scout families (`scout-auth`, `scout-race-condition`) are planned.

## Quick start

Prerequisites: [Claude Code](https://docs.claude.com/en/docs/claude-code), Docker, and a `GEMINI_API_KEY` exported in your shell.

```bash
# 1. Clone this repo.
git clone https://github.com/razzezz/adversarial-review-harness

# 2. Fork the Python repo you want to review.
gh repo fork <target-org>/<target-repo> --clone
cd <target-repo>

# 3. Copy the .claude/ scaffold in.
cp -r ../adversarial-review-harness/.claude .

# 4. Build the PoC sandbox image (one-time per machine).
docker build -t adversarial-review-poc:3.12 .claude/tools/poc_image/

# 5. Run the review.
export GEMINI_API_KEY=...
claude
# inside Claude Code:
/adversarial-review
```

Outputs land in `.claude/output/`. `report.md` is the headline artefact, `audit.jsonl` is the full record of tool calls, and severity-gated findings (high and critical) route to `.claude/output/private/` rather than the public report.

To review a specific subdirectory, pass a path: `/adversarial-review src/lib/`. To kick the tyres before pointing the harness at a real target, the `sandbox/toy_vulnerable_app/` in this repo is a small app with planted vulnerabilities you can review end-to-end by running `claude` from the root of this repo and invoking `/adversarial-review sandbox/toy_vulnerable_app/`.

## The five-phase pipeline

```
User runs: claude, then /adversarial-review
                │
                ▼
        Orchestrator (main session)
                │
                │ Phase 1: Reconnaissance, one sub-agent
                ▼
        recon  ──►  recon_summary.json
                │
                │ Phase 2: Threat modelling, one sub-agent
                ▼
        threat-modeller  ──►  hot_zones.json, routed_scouts.json
                │
                │ Phase 3: Adversarial review, parallel scouts
                ▼
        ┌──────────┬──────────┬──────────┐
        │ scout-A  │ scout-B  │   ...    │
        └────┬─────┴────┬─────┴────┬─────┘
             └──────────┴──────────┘
                        ▼
             candidate_findings.jsonl
                        │
                        │ Phase 4a: Critic (Gemini second opinion)
                        ▼
             corroborated_findings.jsonl
                        │
                        │ Phase 4b: PoC builder (Docker sandbox)
                        ▼
             confirmed_findings.jsonl
                        │
                        │ Phase 5: Reporter
                        ▼
                report.md, audit.jsonl
```

Each phase has its own sub-agent with a fresh context and a tightly scoped tool surface. The scouts are read-only by design (no Bash, no Write); only the PoC builder can invoke Docker; only the orchestrator and processing agents persist anything to disk. The structure is the security model.

## The scout roster

Ten specialists, each a narrow expert on one class of attack. They shard by attack class rather than by CWE, because that is how senior pentesters actually think. A scout hunting "deserialisation" naturally covers CWE-502 alongside the other patterns it lives next to; a scout hunting "CWE-502 specifically" silos findings that are really the same underlying idea.

The ten currently shipping:

- `scout-deserialisation`: pickle, yaml.load without SafeLoader, jsonpickle, marshal, joblib
- `scout-injection`: subprocess with shell=True, os.system, eval, exec
- `scout-sqli`: interpolated SQL, raw queries, ORM escape hatches
- `scout-path-traversal`: open, pathlib, tarfile and zipfile extractall
- `scout-ssrf`: requests, urllib, httpx, aiohttp without host allowlists or scheme checks
- `scout-xxe`: lxml resolve_entities, SAX with external GES or PES
- `scout-template`: jinja2 from_string with user-controlled source
- `scout-crypto`: weak hashes, non-cryptographic random, ECB, hardcoded keys
- `scout-supply-chain`: unpinned deps, unsafe sources, lockfile drift, typosquats
- `scout-import-fallback`: silent fallbacks from secure to insecure primitives

Two more are planned: `scout-auth` for authn and authz patterns, and `scout-race-condition` for TOCTOU and concurrent-state issues.

## Approach and process

### Falsification over assertion

The hardest problem with AI-generated security findings is signal-to-noise. The harness treats every candidate finding as a hypothesis that has to survive falsification before it earns a place in the report. Three pathways produce that survival.

The first is multi-model corroboration. Every runtime-demonstrable finding is run past Gemini 2.5 Pro as an independent second opinion. If both Opus and Gemini concur, confidence is materially higher than either alone. If they disagree, the finding is marked `CONTESTED` and surfaced with both verdicts visible.

The second is sandboxed PoC execution. Findings that survive the critic get a Docker-sandboxed exploit attempt with no network, a read-only filesystem, dropped capabilities, and a hard timeout. Only findings that actually execute against a stated success predicate reach `CONFIRMED`. Findings the critic corroborated but the PoC could not demonstrate are marked `UNCORROBORATED_NO_POC` and held for human review rather than dropped or upgraded.

The third pathway is for findings whose evidence is declarative: a manifest pinning a vulnerable version, a missing constant-time comparison, an import-graph closure terminating at `cryptography`. A runtime PoC is not meaningful for these; the source or manifest text is the evidence. They flow through the report as `CORROBORATED_STATIC_ONLY`.

### Defence-in-depth in the harness itself

The tool reviews code for a living, so it has to demonstrate the security practice it is reviewing for. Four layers, each doing a different job:

1. **Per-agent tool allowlists.** Each sub-agent declares only the tools it needs. Scouts get `Read, Grep, Glob`. The critic gets those plus `Bash`, scoped to the Gemini wrapper. Only the PoC builder can invoke Docker.
2. **Schema-validating PreToolUse hooks.** Claude Code's permissions config has documented enforcement gaps (piped commands bypassing bash allowlists, file deny rules behaving inconsistently across versions). Hooks run before permission evaluation and a non-zero exit blocks the tool call regardless. The bash guard is schema-based, dispatching to a per-command argv validator; the file guard canonicalises paths before matching to defeat symlink and prefix-collision tricks.
3. **Claude Code OS sandbox.** Enabled via `/sandbox`. Bounds filesystem and network reach at the OS level (Seatbelt on macOS, bubblewrap on Linux).
4. **Docker sandbox for PoC execution.** The only place untrusted target code actually runs. `--network none`, `--read-only`, non-root, all capabilities dropped, resource limits, hard timeout.

### Slice cadence

The codebase grew through ten focused slices, each one design-spec'd, planned, implemented, and closed in a single decisive sitting. The cadence is visible in the git log: every slice has a planning commit, several implementation commits, and a closeout commit. Working in slices that small forces honest scope. Each one delivers a working end-to-end capability rather than a half-built abstraction waiting to be finished.

## Key principles

- Permissions are for UX; hooks are for enforcement.
- Scouts are read-only by design; only the PoC builder can invoke Docker.
- Multi-model corroboration is the highest-leverage false-positive filter we have.
- A demonstrable PoC is the artefact that lands; everything else is a candidate.
- High and critical findings are severity-gated out of the public report and routed to a private queue for responsible disclosure.
- Python-only, scope-disciplined; structural specificity beats generic capability.

## What this is NOT

- Not a pip package. The honest artefact is a `.claude/` directory you fork into the repo you want reviewed.
- Not a SAST replacement. It complements Bandit, Semgrep, and similar tools rather than competing with them.
- Not pointed at private systems. Public repositories only.
- Not posting findings to public PRs. Severity-gated by design; high and critical findings never reach the public report.
- Not multi-language. Python-only, and the scout personas reference Python-specific patterns concretely. That specificity is what produces quality findings.
- Not a substitute for human review. It surfaces candidates and runs PoCs; a human still decides what to do with them.

## Repository layout

```
.claude/
  agents/        ten scout personas plus recon, threat-modeller, critic, poc-builder, reporter
  commands/      adversarial-review.md (the orchestrator)
  hooks/         PreToolUse bash and file guards, PostToolUse audit logger
  tools/         helpers Bash agents call (Gemini wrapper, Docker runner, scout detectors)
  tests/         pytest suite for the hooks and detector tools
sandbox/         toy vulnerable app with planted bugs for testing the harness end-to-end
README.md        this file
```
