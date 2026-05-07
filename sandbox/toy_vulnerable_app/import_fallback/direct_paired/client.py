"""Slice-10 fixture: paired-import where the secure side is a corpus leaf
and the fallback side is an unrelated module.

DIFF signal: closure(cryptography) hits the corpus directly;
closure(dummy_legacy) doesn't. The diff intersects {cryptography}.
"""
try:
    import cryptography
except ImportError:
    import dummy_legacy
