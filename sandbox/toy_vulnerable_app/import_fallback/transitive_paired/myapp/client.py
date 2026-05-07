"""Slice-10 fixture: paired-import where the modules are PROJECT-INTERNAL.

Closure(myapp.secure) → {myapp.secure, cryptography}.
Closure(myapp.legacy) → {myapp.legacy}.
Diff includes cryptography → DIFF signal fires.

This is the D8 load-bearing test: detector must work with project-internal
modules without per-target corpus extension.
"""
try:
    from myapp import secure as _backend
except ImportError:
    from myapp import legacy as _backend
