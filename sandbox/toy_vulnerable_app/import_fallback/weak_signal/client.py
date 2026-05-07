"""Slice-10 fixture: classic legitimate fallback (uvloop → asyncio).

Neither `uvloop` nor `asyncio` is in the corpus. Signal: WEAK.
Detector emits a stderr audit line; no JSONL finding.
"""
try:
    import uvloop
except ImportError:
    import asyncio
