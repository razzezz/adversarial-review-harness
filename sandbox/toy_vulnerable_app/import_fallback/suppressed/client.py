"""Slice-10 fixture: # noqa silences the would-be DIRECT finding.

The detector still produces an audit log to stderr for this site,
but the finding is NOT in the JSONL stdout output.
"""
try:                           # noqa: scout-import-fallback
    import OpenSSL
except ImportError:
    OpenSSL = None
