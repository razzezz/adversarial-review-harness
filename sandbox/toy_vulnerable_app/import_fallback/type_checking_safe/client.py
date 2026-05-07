"""Slice-10 fixture: imports under TYPE_CHECKING never run at runtime.

There is no runtime try/except fallback in this file. The graph builder
correctly excludes the TYPE_CHECKING-guarded import from the runtime
closure (see test_collect_imports_skips_type_checking_block), and the
detector finds no try/except shape to match — so no finding is emitted.
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import jwt  # type-only import; not runtime
