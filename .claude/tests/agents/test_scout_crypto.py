"""Unit tests for scout-crypto's AST-based detection primitives.

Mirrors scout-sqli's helper-import pattern. Tests exercise the
pure-function detector against hand-crafted fixture files.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DETECTOR = REPO_ROOT / ".claude" / "tools" / "scout_crypto_detect.py"


def _load():
    spec = importlib.util.spec_from_file_location("scout_crypto_detect", DETECTOR)
    assert spec and spec.loader, f"cannot load {DETECTOR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _scan(src: str, tmp_path: Path):
    mod = _load()
    p = tmp_path / "x.py"
    p.write_text(src)
    return mod.scan_project(tmp_path)


# ---------------------------------------------------------------------------
# Pattern 1: weak_hash_security
# ---------------------------------------------------------------------------


def test_md5_assigned_to_password_var_flags(tmp_path):
    findings = _scan(
        "import hashlib\n"
        "def f(p):\n"
        "    password_hash = hashlib.md5(p).hexdigest()\n"
        "    return password_hash\n",
        tmp_path,
    )
    assert len(findings) == 1
    assert findings[0].pattern == "weak_hash_security"
    assert findings[0].severity == "high"


def test_sha1_passed_as_token_kwarg_flags(tmp_path):
    findings = _scan(
        "import hashlib\n"
        "def make_token(seed):\n"
        "    return hashlib.sha1(seed).hexdigest()\n"
        "def use():\n"
        "    return store(token=make_token(b'x'))\n",
        tmp_path,
    )
    # The hashlib call is in a function whose name ('make_token') matches the
    # security-context heuristic. Flag.
    assert any(f.pattern == "weak_hash_security" for f in findings)


def test_md5_for_checksum_does_not_flag(tmp_path):
    findings = _scan(
        "import hashlib\n"
        "def file_checksum(data):\n"
        "    digest = hashlib.md5(data).hexdigest()\n"
        "    return digest\n",
        tmp_path,
    )
    # The variable `digest` matches SECURITY_CONTEXT_NAMES (intentionally —
    # digest IS a security primitive), but the function name `file_checksum`
    # contains a non-security hint that overrides. No fire.
    assert not any(f.pattern == "weak_hash_security" for f in findings)


def test_sha256_for_password_does_not_flag(tmp_path):
    findings = _scan(
        "import hashlib\n"
        "def hash_password(p):\n"
        "    return hashlib.sha256(p).hexdigest()\n",
        tmp_path,
    )
    # sha256 is fine; pattern only fires on md5/sha1.
    assert not findings


def test_md5_in_function_param_default_edge_case(tmp_path):
    # Edge: hashlib.md5 referenced but not called — should NOT flag.
    findings = _scan(
        "import hashlib\n"
        "h = hashlib.md5\n"
        "def f(p):\n"
        "    return h(p).hexdigest()\n",
        tmp_path,
    )
    # Detector chooses to skip alias-via-assignment; the pattern fires on
    # direct .md5(...) calls only. Document that decision in the test.
    assert not findings


# ---------------------------------------------------------------------------
# Pattern 2: random_for_security
# ---------------------------------------------------------------------------


def test_random_random_assigned_to_token_var_flags(tmp_path):
    findings = _scan(
        "import random\n"
        "def gen():\n"
        "    auth_token = random.random()\n"
        "    return auth_token\n",
        tmp_path,
    )
    assert any(f.pattern == "random_for_security" for f in findings)


def test_random_randbytes_assigned_to_secret_kwarg_flags(tmp_path):
    findings = _scan(
        "import random\n"
        "def setup():\n"
        "    api_key = random.randbytes(32)\n"
        "    return api_key\n",
        tmp_path,
    )
    assert any(f.pattern == "random_for_security" for f in findings)


def test_random_for_simulation_does_not_flag(tmp_path):
    findings = _scan(
        "import random\n"
        "def sample():\n"
        "    dice_roll = random.randint(1, 6)\n"
        "    return dice_roll\n",
        tmp_path,
    )
    assert not findings


def test_secrets_token_bytes_does_not_flag(tmp_path):
    findings = _scan(
        "import secrets\n"
        "def gen():\n"
        "    token = secrets.token_bytes(32)\n"
        "    return token\n",
        tmp_path,
    )
    assert not findings


def test_random_in_listcomp_with_security_var_flags(tmp_path):
    # Edge: comprehension target binding still counts.
    findings = _scan(
        "import random\n"
        "def gen():\n"
        "    keys = [random.choice('abc') for _ in range(8)]\n"
        "    return keys\n",
        tmp_path,
    )
    assert any(f.pattern == "random_for_security" for f in findings)


# ---------------------------------------------------------------------------
# Pattern 3: hardcoded_crypto_material
# ---------------------------------------------------------------------------


def test_aes_new_with_literal_key_flags(tmp_path):
    findings = _scan(
        "from Crypto.Cipher import AES\n"
        "def enc(p):\n"
        "    c = AES.new(b'sixteenbytekey!!', AES.MODE_ECB)\n"
        "    return c.encrypt(p)\n",
        tmp_path,
    )
    assert any(f.pattern == "hardcoded_crypto_material" for f in findings)


def test_fernet_with_literal_key_kwarg_flags(tmp_path):
    findings = _scan(
        "from cryptography.fernet import Fernet\n"
        "def enc(p):\n"
        "    f = Fernet(key=b'fA' * 22 + b'==')\n"
        "    return f.encrypt(p)\n",
        tmp_path,
    )
    assert any(f.pattern == "hardcoded_crypto_material" for f in findings)


def test_aes_new_with_named_key_does_not_flag(tmp_path):
    findings = _scan(
        "from Crypto.Cipher import AES\n"
        "def enc(p, k):\n"
        "    c = AES.new(k, AES.MODE_ECB)\n"
        "    return c.encrypt(p)\n",
        tmp_path,
    )
    # Other patterns may flag (ECB), but hardcoded_crypto_material must not.
    assert not any(f.pattern == "hardcoded_crypto_material" for f in findings)


def test_hmac_new_with_literal_key_flags(tmp_path):
    findings = _scan(
        "import hmac, hashlib\n"
        "def sign(m):\n"
        "    return hmac.new(b'shared-secret', m, hashlib.sha256).hexdigest()\n",
        tmp_path,
    )
    assert any(f.pattern == "hardcoded_crypto_material" for f in findings)


def test_iv_kwarg_with_literal_flags(tmp_path):
    findings = _scan(
        "from Crypto.Cipher import AES\n"
        "def enc(p, k):\n"
        "    c = AES.new(k, AES.MODE_CBC, iv=b'\\x00' * 16)\n"
        "    return c.encrypt(p)\n",
        tmp_path,
    )
    assert any(f.pattern == "hardcoded_crypto_material" for f in findings)


# ---------------------------------------------------------------------------
# Pattern 4: ecb_mode
# ---------------------------------------------------------------------------


def test_aes_mode_ecb_attribute_flags(tmp_path):
    findings = _scan(
        "from Crypto.Cipher import AES\n"
        "def enc(p, k):\n"
        "    c = AES.new(k, AES.MODE_ECB)\n"
        "    return c.encrypt(p)\n",
        tmp_path,
    )
    assert any(f.pattern == "ecb_mode" for f in findings)


def test_modes_ecb_call_flags(tmp_path):
    findings = _scan(
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "def enc(p, k):\n"
        "    c = Cipher(algorithms.AES(k), modes.ECB())\n"
        "    return c.encryptor()\n",
        tmp_path,
    )
    assert any(f.pattern == "ecb_mode" for f in findings)


def test_aes_mode_cbc_does_not_flag_ecb(tmp_path):
    findings = _scan(
        "from Crypto.Cipher import AES\n"
        "def enc(p, k, iv):\n"
        "    c = AES.new(k, AES.MODE_CBC, iv=iv)\n"
        "    return c.encrypt(p)\n",
        tmp_path,
    )
    assert not any(f.pattern == "ecb_mode" for f in findings)


def test_string_ecb_does_not_flag(tmp_path):
    # Must be the AST attribute / call, not a string literal "ECB".
    findings = _scan(
        "def f():\n"
        "    return 'ECB is bad'\n",
        tmp_path,
    )
    assert not findings


def test_ecb_mode_in_dict_value_flags(tmp_path):
    # Edge: AES.MODE_ECB referenced as a dict value still counts.
    findings = _scan(
        "from Crypto.Cipher import AES\n"
        "MODES = {'default': AES.MODE_ECB}\n",
        tmp_path,
    )
    assert any(f.pattern == "ecb_mode" for f in findings)


# ---------------------------------------------------------------------------
# Pattern 5: static_iv
# ---------------------------------------------------------------------------


def test_static_iv_kwarg_flags(tmp_path):
    findings = _scan(
        "from Crypto.Cipher import AES\n"
        "def enc(p, k):\n"
        "    c = AES.new(k, AES.MODE_CBC, iv=b'\\x00' * 16)\n"
        "    return c.encrypt(p)\n",
        tmp_path,
    )
    # Both hardcoded_crypto_material AND static_iv may fire.
    assert any(f.pattern == "static_iv" for f in findings)


def test_static_nonce_kwarg_flags(tmp_path):
    findings = _scan(
        "from Crypto.Cipher import AES\n"
        "def enc(p, k):\n"
        "    c = AES.new(k, AES.MODE_GCM, nonce=b'twelve_byte!')\n"
        "    return c.encrypt(p)\n",
        tmp_path,
    )
    assert any(f.pattern == "static_iv" for f in findings)


def test_random_iv_does_not_flag_static(tmp_path):
    findings = _scan(
        "import os\n"
        "from Crypto.Cipher import AES\n"
        "def enc(p, k):\n"
        "    c = AES.new(k, AES.MODE_CBC, iv=os.urandom(16))\n"
        "    return c.encrypt(p)\n",
        tmp_path,
    )
    assert not any(f.pattern == "static_iv" for f in findings)


def test_iv_named_var_does_not_flag_static(tmp_path):
    findings = _scan(
        "from Crypto.Cipher import AES\n"
        "def enc(p, k, iv):\n"
        "    c = AES.new(k, AES.MODE_CBC, iv=iv)\n"
        "    return c.encrypt(p)\n",
        tmp_path,
    )
    assert not any(f.pattern == "static_iv" for f in findings)


def test_static_iv_via_constant_concat_flags(tmp_path):
    # Edge: iv constructed from constant ops still counts.
    findings = _scan(
        "from Crypto.Cipher import AES\n"
        "def enc(p, k):\n"
        "    c = AES.new(k, AES.MODE_CBC, iv=b'\\x00' * 8 + b'\\x01' * 8)\n"
        "    return c.encrypt(p)\n",
        tmp_path,
    )
    assert any(f.pattern == "static_iv" for f in findings)


# ---------------------------------------------------------------------------
# Pattern 6: missing_compare_digest
# ---------------------------------------------------------------------------


def test_eq_on_hmac_var_flags(tmp_path):
    findings = _scan(
        "import hmac, hashlib\n"
        "def verify(m, sig):\n"
        "    expected_hmac = hmac.new(b'k', m, hashlib.sha256).hexdigest()\n"
        "    return expected_hmac == sig\n",
        tmp_path,
    )
    assert any(f.pattern == "missing_compare_digest" for f in findings)


def test_neq_on_signature_var_flags(tmp_path):
    findings = _scan(
        "import hashlib\n"
        "def verify(provided_signature, expected_digest):\n"
        "    if provided_signature != expected_digest:\n"
        "        raise ValueError\n",
        tmp_path,
    )
    assert any(f.pattern == "missing_compare_digest" for f in findings)


def test_eq_on_non_security_var_does_not_flag(tmp_path):
    findings = _scan(
        "import hmac\n"
        "def f(a, b):\n"
        "    return a == b\n",
        tmp_path,
    )
    assert not any(f.pattern == "missing_compare_digest" for f in findings)


def test_eq_in_file_without_hmac_hashlib_does_not_flag(tmp_path):
    findings = _scan(
        "def verify(provided_signature, expected_digest):\n"
        "    return provided_signature == expected_digest\n",
        tmp_path,
    )
    # No hmac/hashlib import: out of scope.
    assert not any(f.pattern == "missing_compare_digest" for f in findings)


def test_compare_digest_called_does_not_flag(tmp_path):
    findings = _scan(
        "import hmac\n"
        "def verify(provided_signature, expected_digest):\n"
        "    return hmac.compare_digest(provided_signature, expected_digest)\n",
        tmp_path,
    )
    assert not any(f.pattern == "missing_compare_digest" for f in findings)


# ---------------------------------------------------------------------------
# Pattern 7: weak_key_size
# ---------------------------------------------------------------------------


def test_rsa_1024_flags(tmp_path):
    findings = _scan(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def gen():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=1024)\n",
        tmp_path,
    )
    assert any(f.pattern == "weak_key_size" for f in findings)


def test_dsa_1024_flags(tmp_path):
    findings = _scan(
        "from cryptography.hazmat.primitives.asymmetric import dsa\n"
        "def gen():\n"
        "    return dsa.generate_private_key(key_size=1024)\n",
        tmp_path,
    )
    assert any(f.pattern == "weak_key_size" for f in findings)


def test_secp192r1_flags(tmp_path):
    findings = _scan(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "def gen():\n"
        "    return ec.generate_private_key(ec.SECP192R1())\n",
        tmp_path,
    )
    assert any(f.pattern == "weak_key_size" for f in findings)


def test_rsa_2048_does_not_flag(tmp_path):
    findings = _scan(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def gen():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
        tmp_path,
    )
    assert not any(f.pattern == "weak_key_size" for f in findings)


def test_secp256r1_does_not_flag(tmp_path):
    findings = _scan(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "def gen():\n"
        "    return ec.generate_private_key(ec.SECP256R1())\n",
        tmp_path,
    )
    assert not any(f.pattern == "weak_key_size" for f in findings)


# ---------------------------------------------------------------------------
# Pattern 8: deprecated_algo
# ---------------------------------------------------------------------------


def test_algorithms_tripledes_flags(tmp_path):
    findings = _scan(
        "from cryptography.hazmat.primitives.ciphers import algorithms\n"
        "def enc(k):\n"
        "    return algorithms.TripleDES(k)\n",
        tmp_path,
    )
    assert any(f.pattern == "deprecated_algo" for f in findings)


def test_arc4_flags(tmp_path):
    findings = _scan(
        "from cryptography.hazmat.primitives.ciphers import algorithms\n"
        "def enc(k):\n"
        "    return algorithms.ARC4(k)\n",
        tmp_path,
    )
    assert any(f.pattern == "deprecated_algo" for f in findings)


def test_pycryptodome_des_flags(tmp_path):
    findings = _scan(
        "from Crypto.Cipher import DES\n"
        "def enc(p, k):\n"
        "    c = DES.new(k, DES.MODE_ECB)\n"
        "    return c.encrypt(p)\n",
        tmp_path,
    )
    assert any(f.pattern == "deprecated_algo" for f in findings)


def test_aes_does_not_flag_deprecated(tmp_path):
    findings = _scan(
        "from cryptography.hazmat.primitives.ciphers import algorithms\n"
        "def enc(k):\n"
        "    return algorithms.AES(k)\n",
        tmp_path,
    )
    assert not any(f.pattern == "deprecated_algo" for f in findings)


def test_chacha20_does_not_flag_deprecated(tmp_path):
    findings = _scan(
        "from cryptography.hazmat.primitives.ciphers import algorithms\n"
        "def enc(k, n):\n"
        "    return algorithms.ChaCha20(k, n)\n",
        tmp_path,
    )
    assert not any(f.pattern == "deprecated_algo" for f in findings)
