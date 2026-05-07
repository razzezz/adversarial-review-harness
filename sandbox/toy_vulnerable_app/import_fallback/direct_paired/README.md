# direct_paired fixture

Slice-10 paired-import with the secure module being a corpus leaf.

```python
try:
    import cryptography
except ImportError:
    import dummy_legacy
```

Expected detector output: 1 finding, `shape=paired-import`, `signal=diff`, `matched_leaves=("cryptography",)`. The `diff` signal fires because `closure(cryptography)` (corpus leaf, terminates external) contains "cryptography" but `closure(dummy_legacy)` doesn't.
