"""Slice-10 fixture: feature-flag pattern.

The detector should match the try-import + flag-True / except + flag-False
pattern, then resolve the later `if HAS_SECRETS:` site to extend
line_range. Signal is DIRECT because `secrets` is a corpus leaf.
"""
try:
    import secrets
    HAS_SECRETS = True
except ImportError:
    HAS_SECRETS = False


def gen_token() -> str:
    if HAS_SECRETS:
        return secrets.token_hex(16)
    return "weak-fallback"
