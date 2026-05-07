#!/usr/bin/env python3
"""AST-based detection for scout-crypto.

Walks Python source under the target root; emits findings for the eight
cryptographic-misuse patterns described in
docs/superpowers/specs/2026-04-28-slice-7-crypto-xxe-scouts-design.md.

Invoked from the scout-crypto persona via:
    python .claude/tools/scout_crypto_detect.py <target_root>

Prints JSONL findings to stdout. Each finding has poc_applicable: True.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import json
import sys
from pathlib import Path


# Identifier substrings that suggest a security context (variable names,
# parameter names, attribute names). Used by weak_hash_security,
# random_for_security, missing_compare_digest, deprecated_algo.
SECURITY_CONTEXT_NAMES: tuple[str, ...] = (
    "password", "passwd", "auth", "token", "secret", "signature",
    "mac", "hmac", "session", "key", "nonce", "iv", "salt", "digest",
)

# Keyword arguments to crypto APIs that should not receive literal bytes.
HARDCODED_KW_NAMES: tuple[str, ...] = ("key", "iv", "nonce", "salt")


@dataclasses.dataclass(frozen=True)
class Finding:
    source_file: str
    source_line: int
    cwe: str
    severity: str
    confidence: str
    pattern: str
    sink: str
    evidence: str
    description: str
    poc_applicable: bool = True
    enclosing_function: str = ""


# ---------------------------------------------------------------------------
# Helpers (parent-map, enclosing-function, security-context detection,
# excerpt rendering) — same shape as scout_sqli_detect.
# ---------------------------------------------------------------------------


def _parent_map(tree: ast.AST) -> dict[int, ast.AST]:
    parent_of: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_of[id(child)] = parent
    return parent_of


def _enclosing_function_name(node: ast.AST, parent_of: dict[int, ast.AST]) -> str:
    current: ast.AST | None = node
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
        current = parent_of.get(id(current))
    return ""


def _name_has_security_context(name: str) -> bool:
    low = name.lower()
    return any(sub in low for sub in SECURITY_CONTEXT_NAMES)


def _render_attribute(node: ast.AST) -> str:
    """Render `a.b.c` from an Attribute chain. Returns '' on unsupported nodes."""
    parts: list[str] = []
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _render_source_excerpt(source_lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(source_lines):
        return source_lines[lineno - 1].rstrip()
    return ""


# ---------------------------------------------------------------------------
# Per-pattern detectors. Each returns a list of Finding for one ast.AST node
# (or [] if the node doesn't match the pattern).
# ---------------------------------------------------------------------------


WEAK_HASH_FUNCS: tuple[str, ...] = ("md5", "sha1")

# Substrings that override security-context to false (avoid checksum FPs).
NON_SECURITY_HINTS: tuple[str, ...] = (
    "checksum", "fingerprint", "etag", "cache_key", "cache_id",
)


def _has_non_security_hint(*names: str) -> bool:
    for name in names:
        low = name.lower()
        if any(h in low for h in NON_SECURITY_HINTS):
            return True
    return False


def _detect_weak_hash_security(node: ast.AST, parent_of, source_lines) -> list[Finding]:
    if not isinstance(node, ast.Call):
        return []
    if not isinstance(node.func, ast.Attribute):
        return []
    if node.func.attr not in WEAK_HASH_FUNCS:
        return []
    # Module guard: hashlib.md5 / hashlib.sha1 (not arbitrary obj.md5).
    if not isinstance(node.func.value, ast.Name) or node.func.value.id != "hashlib":
        return []
    enclosing = _enclosing_function_name(node, parent_of)
    # Walk up to find the assignment target (if any) for var-name heuristic.
    var_target = ""
    p = parent_of.get(id(node))
    while p is not None and not isinstance(p, ast.Assign):
        p = parent_of.get(id(p))
    if isinstance(p, ast.Assign) and p.targets:
        t = p.targets[0]
        if isinstance(t, ast.Name):
            var_target = t.id
    in_security_context = (
        _name_has_security_context(enclosing)
        or _name_has_security_context(var_target)
    )
    if not in_security_context:
        return []
    # Non-security hints (checksum, fingerprint, etag) override.
    if _has_non_security_hint(enclosing, var_target):
        return []
    excerpt = _render_source_excerpt(source_lines, node.lineno)
    return [Finding(
        source_file="",
        source_line=node.lineno,
        cwe="CWE-327",
        severity="high",
        confidence="medium",
        pattern="weak_hash_security",
        sink=f"hashlib.{node.func.attr}",
        evidence=excerpt,
        description=(
            f"Weak hash 'hashlib.{node.func.attr}' used in security context "
            f"(function {enclosing!r}, var {var_target!r}); use sha256+ "
            f"or a password-hashing KDF."
        ),
        enclosing_function=enclosing,
    )]


RANDOM_FUNCS: tuple[str, ...] = (
    "random", "randint", "choice", "randbytes", "getrandbits",
    "sample", "shuffle", "uniform", "randrange",
)


def _detect_random_for_security(node: ast.AST, parent_of, source_lines) -> list[Finding]:
    if not isinstance(node, ast.Call):
        return []
    if not isinstance(node.func, ast.Attribute):
        return []
    if node.func.attr not in RANDOM_FUNCS:
        return []
    if not isinstance(node.func.value, ast.Name) or node.func.value.id != "random":
        return []
    # Walk up to find the bound name (Assign target or comprehension target).
    var_target = ""
    p = parent_of.get(id(node))
    while p is not None and not isinstance(p, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        p = parent_of.get(id(p))
    if isinstance(p, ast.Assign) and p.targets:
        t = p.targets[0]
        if isinstance(t, ast.Name):
            var_target = t.id
    elif isinstance(p, ast.AnnAssign) and isinstance(p.target, ast.Name):
        var_target = p.target.id
    if not _name_has_security_context(var_target):
        return []
    excerpt = _render_source_excerpt(source_lines, node.lineno)
    enclosing = _enclosing_function_name(node, parent_of)
    return [Finding(
        source_file="",
        source_line=node.lineno,
        cwe="CWE-330",
        severity="high",
        confidence="medium",
        pattern="random_for_security",
        sink=f"random.{node.func.attr}",
        evidence=excerpt,
        description=(
            f"Non-cryptographic 'random.{node.func.attr}' bound to "
            f"security-named target {var_target!r}; use 'secrets'."
        ),
        enclosing_function=enclosing,
    )]


CRYPTO_API_NAMES: tuple[str, ...] = (
    "Cipher", "AES", "DES", "DES3", "ARC4", "Fernet", "HMAC", "new",
)


def _is_bytes_or_str_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str))


def _is_int_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool)


def _is_literal_via_simple_op(node: ast.AST) -> bool:
    """Allow b'fA' * 22 + b'==' — composed bytes literals via constant ops.

    Accepts: bytes/str literal, bytes/str + bytes/str, bytes/str * int (or int * bytes/str).
    """
    if _is_bytes_or_str_literal(node):
        return True
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            return _is_literal_via_simple_op(node.left) and _is_literal_via_simple_op(node.right)
        if isinstance(node.op, ast.Mult):
            # bytes/str * int  OR  int * bytes/str — both produce bytes/str.
            left_lit = _is_literal_via_simple_op(node.left)
            right_lit = _is_literal_via_simple_op(node.right)
            left_int = _is_int_literal(node.left)
            right_int = _is_int_literal(node.right)
            return (left_lit and right_int) or (left_int and right_lit)
    return False


def _is_crypto_call(call: ast.Call) -> bool:
    """True if the call targets a known crypto constructor / factory."""
    if isinstance(call.func, ast.Name) and call.func.id in CRYPTO_API_NAMES:
        return True
    if isinstance(call.func, ast.Attribute) and call.func.attr in CRYPTO_API_NAMES:
        return True
    return False


def _detect_hardcoded_crypto_material(node: ast.AST, parent_of, source_lines) -> list[Finding]:
    if not isinstance(node, ast.Call):
        return []
    if not _is_crypto_call(node):
        return []
    findings: list[Finding] = []
    excerpt = _render_source_excerpt(source_lines, node.lineno)
    enclosing = _enclosing_function_name(node, parent_of)

    # First positional arg of Fernet / HMAC.new / AES.new / Cipher / etc.
    if node.args and _is_literal_via_simple_op(node.args[0]):
        sink = _render_attribute(node.func) or (
            node.func.id if isinstance(node.func, ast.Name) else "<call>"
        )
        # Be a little restrictive: only fire when the name suggests keying.
        target = sink.split(".")[-1]
        if target in ("Fernet", "new", "Cipher", "AES", "DES", "DES3", "ARC4", "HMAC"):
            findings.append(Finding(
                source_file="",
                source_line=node.lineno,
                cwe="CWE-798",
                severity="high",
                confidence="medium",
                pattern="hardcoded_crypto_material",
                sink=sink,
                evidence=excerpt,
                description=(
                    f"Hardcoded literal passed as first positional to {sink!r}; "
                    f"appears to be keying material."
                ),
                enclosing_function=enclosing,
            ))

    # key=/iv=/nonce=/salt= kwargs.
    for kw in node.keywords:
        if kw.arg in HARDCODED_KW_NAMES and _is_literal_via_simple_op(kw.value):
            sink = _render_attribute(node.func) or (
                node.func.id if isinstance(node.func, ast.Name) else "<call>"
            )
            findings.append(Finding(
                source_file="",
                source_line=node.lineno,
                cwe="CWE-798",
                severity="high",
                confidence="medium",
                pattern="hardcoded_crypto_material",
                sink=f"{sink}({kw.arg}=...)",
                evidence=excerpt,
                description=(
                    f"Hardcoded literal passed as {kw.arg!r} to {sink!r}."
                ),
                enclosing_function=enclosing,
            ))
    return findings


def _detect_ecb_mode(node: ast.AST, parent_of, source_lines) -> list[Finding]:
    excerpt_lineno = getattr(node, "lineno", 0)
    enclosing = _enclosing_function_name(node, parent_of)

    # Pattern A: ast.Attribute MODE_ECB on AES/DES/DES3.
    if isinstance(node, ast.Attribute) and node.attr == "MODE_ECB":
        if isinstance(node.value, ast.Name) and node.value.id in ("AES", "DES", "DES3"):
            return [Finding(
                source_file="",
                source_line=excerpt_lineno,
                cwe="CWE-327",
                severity="high",
                confidence="high",
                pattern="ecb_mode",
                sink=f"{node.value.id}.MODE_ECB",
                evidence=_render_source_excerpt(source_lines, excerpt_lineno),
                description="ECB mode does not provide semantic security; use CBC/CTR/GCM.",
                enclosing_function=enclosing,
            )]

    # Pattern B: ast.Call modes.ECB().
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "ECB":
            base = node.func.value
            if isinstance(base, ast.Name) and base.id == "modes":
                return [Finding(
                    source_file="",
                    source_line=excerpt_lineno,
                    cwe="CWE-327",
                    severity="high",
                    confidence="high",
                    pattern="ecb_mode",
                    sink="modes.ECB()",
                    evidence=_render_source_excerpt(source_lines, excerpt_lineno),
                    description="ECB mode does not provide semantic security; use CBC/CTR/GCM.",
                    enclosing_function=enclosing,
                )]
    return []


STATIC_IV_KWARGS: tuple[str, ...] = ("iv", "nonce")


def _detect_static_iv(node: ast.AST, parent_of, source_lines) -> list[Finding]:
    if not isinstance(node, ast.Call):
        return []
    if not _is_crypto_call(node):
        return []
    findings: list[Finding] = []
    enclosing = _enclosing_function_name(node, parent_of)
    excerpt = _render_source_excerpt(source_lines, node.lineno)
    for kw in node.keywords:
        if kw.arg in STATIC_IV_KWARGS and _is_literal_via_simple_op(kw.value):
            sink = _render_attribute(node.func) or "<call>"
            findings.append(Finding(
                source_file="",
                source_line=node.lineno,
                cwe="CWE-329",
                severity="high",
                confidence="high",
                pattern="static_iv",
                sink=f"{sink}({kw.arg}=...)",
                evidence=excerpt,
                description=(
                    f"Static {kw.arg!r} passed to {sink!r}; "
                    f"reusing IV/nonce breaks confidentiality (CBC) or "
                    f"forfeits authentication (GCM/ChaCha20-Poly1305)."
                ),
                enclosing_function=enclosing,
            ))
    return findings


COMPARE_DIGEST_TRIGGER_IMPORTS: tuple[str, ...] = ("hmac", "hashlib")
COMPARE_DIGEST_NAME_HINTS: tuple[str, ...] = (
    "hmac", "mac", "signature", "token", "digest", "hash",
)


def _is_security_named_compare_operand(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return any(h in node.id.lower() for h in COMPARE_DIGEST_NAME_HINTS)
    return False


def _detect_missing_compare_digest(node, parent_of, source_lines, file_imports) -> list[Finding]:
    if not isinstance(node, ast.Compare):
        return []
    if not any(imp in file_imports for imp in COMPARE_DIGEST_TRIGGER_IMPORTS):
        return []
    if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
        return []
    operands = [node.left, *node.comparators]
    if not any(_is_security_named_compare_operand(o) for o in operands):
        return []
    enclosing = _enclosing_function_name(node, parent_of)
    excerpt = _render_source_excerpt(source_lines, node.lineno)
    return [Finding(
        source_file="",
        source_line=node.lineno,
        cwe="CWE-208",
        severity="medium",
        confidence="medium",
        pattern="missing_compare_digest",
        sink="==/!=",
        evidence=excerpt,
        description=(
            "Equality compare on security-named variable in a file that "
            "imports hmac/hashlib; use hmac.compare_digest for "
            "constant-time comparison."
        ),
        enclosing_function=enclosing,
    )]


WEAK_CURVES: tuple[str, ...] = ("SECP192R1", "SECT163K1", "SECT163R2")


def _detect_weak_key_size(node: ast.AST, parent_of, source_lines) -> list[Finding]:
    if not isinstance(node, ast.Call):
        return []
    enclosing = _enclosing_function_name(node, parent_of)
    excerpt = _render_source_excerpt(source_lines, getattr(node, "lineno", 0))
    sink = _render_attribute(node.func) or (
        node.func.id if isinstance(node.func, ast.Name) else "<call>"
    )

    # RSA / DSA: look for key_size kwarg.
    for kw in node.keywords:
        if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
            v = kw.value.value
            if isinstance(v, int) and v < 2048:
                return [Finding(
                    source_file="",
                    source_line=node.lineno,
                    cwe="CWE-326",
                    severity="medium",
                    confidence="high",
                    pattern="weak_key_size",
                    sink=f"{sink}(key_size={v})",
                    evidence=excerpt,
                    description=(
                        f"Asymmetric key size {v} bits is below the 2048-bit "
                        f"floor for RSA/DSA."
                    ),
                    enclosing_function=enclosing,
                )]

    # EC: look for SECP192R1 / weak named curve as positional or attribute.
    for arg in node.args:
        candidate = arg
        if isinstance(candidate, ast.Call):
            candidate = candidate.func
        if isinstance(candidate, ast.Attribute) and candidate.attr in WEAK_CURVES:
            return [Finding(
                source_file="",
                source_line=node.lineno,
                cwe="CWE-326",
                severity="medium",
                confidence="high",
                pattern="weak_key_size",
                sink=f"{sink}({candidate.attr}())",
                evidence=excerpt,
                description=(
                    f"Weak named curve {candidate.attr!r}; use SECP256R1+."
                ),
                enclosing_function=enclosing,
            )]
    return []


DEPRECATED_ALGO_NAMES: tuple[str, ...] = (
    "TripleDES", "ARC4", "Blowfish", "DES", "DES3", "IDEA", "RC2",
)


def _detect_deprecated_algo(node: ast.AST, parent_of, source_lines) -> list[Finding]:
    # Match either algorithms.TripleDES (Attribute) or DES.new / DES3.new (Attribute),
    # or a bare Name (less common).
    target_name = ""
    if isinstance(node, ast.Attribute) and node.attr in DEPRECATED_ALGO_NAMES:
        # Filter out "DES" used as attribute root (e.g. AES.MODE_DES would be a
        # nonsense path; keep simple — accept any Attribute access matching the name).
        target_name = node.attr
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        # DES.new(...): the func is Attribute(value=Name('DES'), attr='new').
        if isinstance(node.func.value, ast.Name) and node.func.value.id in DEPRECATED_ALGO_NAMES:
            target_name = node.func.value.id
    if not target_name:
        return []
    enclosing = _enclosing_function_name(node, parent_of)
    excerpt = _render_source_excerpt(source_lines, getattr(node, "lineno", 0))
    severity = "medium"
    if _name_has_security_context(enclosing):
        severity = "high"
    return [Finding(
        source_file="",
        source_line=getattr(node, "lineno", 0),
        cwe="CWE-327",
        severity=severity,
        confidence="high",
        pattern="deprecated_algo",
        sink=target_name,
        evidence=excerpt,
        description=(
            f"Deprecated cryptographic primitive {target_name!r}; "
            f"use AES (cipher) or ChaCha20-Poly1305 (AEAD)."
        ),
        enclosing_function=enclosing,
    )]


# ---------------------------------------------------------------------------
# scan_file / scan_project / main
# ---------------------------------------------------------------------------


def _file_imports(tree: ast.AST) -> set[str]:
    """Return module-level import names (e.g., {'hmac', 'hashlib'})."""
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    return imported


def scan_file(path: Path) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, OSError):
        return []
    source_lines = source.splitlines()
    parent_of = _parent_map(tree)
    file_imports = _file_imports(tree)
    findings: list[Finding] = []
    for node in ast.walk(tree):
        findings.extend(_detect_weak_hash_security(node, parent_of, source_lines))
        findings.extend(_detect_random_for_security(node, parent_of, source_lines))
        findings.extend(_detect_hardcoded_crypto_material(node, parent_of, source_lines))
        findings.extend(_detect_ecb_mode(node, parent_of, source_lines))
        findings.extend(_detect_static_iv(node, parent_of, source_lines))
        findings.extend(_detect_missing_compare_digest(node, parent_of, source_lines, file_imports))
        findings.extend(_detect_weak_key_size(node, parent_of, source_lines))
        findings.extend(_detect_deprecated_algo(node, parent_of, source_lines))
    # Set source_file post-hoc (handlers don't know the path).
    return [dataclasses.replace(f, source_file=str(path)) for f in findings]


def scan_project(target_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for py in target_root.rglob("*.py"):
        findings.extend(scan_file(py))
    return findings


def _finding_to_jsonl(f: Finding, finding_id: str) -> dict:
    return {
        "id": finding_id,
        "scout": "scout-crypto",
        "status": "CANDIDATE",
        "title": f.description,
        "cwe": [f.cwe],
        "severity": f.severity,
        "confidence": f.confidence,
        "pattern": f.pattern,
        "file": f.source_file,
        "line_range": [f.source_line, f.source_line],
        "sink": f.sink,
        "enclosing_function": f.enclosing_function,
        "description": f.description,
        "evidence": f.evidence,
        "poc_applicable": f.poc_applicable,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="scout-crypto AST detector")
    parser.add_argument("target", help="Target directory (usually scope.target_root)")
    parser.add_argument("--id-prefix", default="FND-CRY-", help="Finding-ID prefix")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    findings = scan_project(target)
    for i, f in enumerate(findings, start=1):
        rec = _finding_to_jsonl(f, f"{args.id_prefix}{i:04d}")
        print(json.dumps(rec))


if __name__ == "__main__":
    main()
