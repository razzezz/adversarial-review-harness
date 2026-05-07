# Slice-10 import-fallback fixtures

Seven mini-projects exercising every shape × signal combination plus
suppression, weak-signal, and type-checking edge cases.

| Sub-tree | Shape | Signal | Notes |
|---|---|---|---|
| `direct_paired/` | paired-import | DIFF | secure = corpus leaf direct |
| `transitive_paired/` | paired-import | DIFF | secure = in-tree → cryptography (load-bearing D8) |
| `any_fallback_transitive/` | any-fallback | TRANSITIVE | secure = in-tree → passlib |
| `feature_flag/` | feature-flag | DIRECT | secrets module |
| `suppressed/` | paired-import | (silenced by # noqa) | would be DIRECT (OpenSSL) |
| `weak_signal/` | any-fallback | WEAK | uvloop/asyncio — never emitted |
| `type_checking_safe/` | (none) | (none) | TYPE_CHECKING block — never matched |

Run the detector against any sub-tree:

    python .claude/tools/scout_import_fallback_detect.py sandbox/toy_vulnerable_app/import_fallback/<sub-tree>

Validation gates land in `docs/superpowers/notes/2026-04-29-slice-10-import-fallback-run.md`.
