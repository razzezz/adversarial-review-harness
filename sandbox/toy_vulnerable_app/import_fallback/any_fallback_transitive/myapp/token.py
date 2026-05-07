"""Slice-10 fixture: any-fallback shape, TRANSITIVE signal.

closure(myapp.wrapper) = {myapp.wrapper, passlib}. First-component
projection picks 'passlib' which is in the corpus. Signal: TRANSITIVE.
"""
try:
    from myapp import wrapper as _w
except ImportError:
    _w = None
