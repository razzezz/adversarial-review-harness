# drift_uv fixture

Exercises all three slice-9 drift patterns against `uv.lock`:

- **extras-drift** — `pyproject.toml` declares `[project.optional-dependencies] demo = ["psutil"]`; `uv.lock`'s `[manifest] provides-extras = []` doesn't list `demo`.
- **version-drift** — `requests>=2.30,<3` declared but lock has `requests==2.28.0`.
- **missing-from-lock** — `orphan-pkg` declared in `[project.dependencies]`, absent from the lock.

Expected detector output: exactly 3 findings (`LOCK-DRIFT-EXTRAS`, `LOCK-DRIFT-VERSION`, `LOCK-DRIFT-MISSING`).
