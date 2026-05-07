"""
Planted cryptographic bugs for scout-crypto E2E testing.

Each function below contains exactly one pattern from the scout-crypto
detector. The expected pattern ID is in the comment above each function.
Do not "fix" these bugs — they are how we verify the scout fires correctly.
"""

from __future__ import annotations

import hashlib
import random

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, DES


# pattern: weak_hash_security
def hash_password(p: bytes) -> str:
    password_digest = hashlib.md5(p).hexdigest()
    return password_digest


# pattern: random_for_security
def make_session_token() -> str:
    auth_token = str(random.random())
    return auth_token


# pattern: hardcoded_crypto_material
def encrypt_session(plaintext: bytes) -> bytes:
    f = Fernet(b"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=")
    return f.encrypt(plaintext)


# pattern: ecb_mode
def encrypt_credentials(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


# pattern: static_iv
def encrypt_message(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16)
    return cipher.encrypt(plaintext)


# pattern: missing_compare_digest
def verify_signature(provided_signature: str, expected_digest: str) -> bool:
    return provided_signature == expected_digest


# pattern: weak_key_size
def generate_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


# pattern: deprecated_algo
def encrypt_legacy(plaintext: bytes, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv=b"\x00" * 8)
    return cipher.encrypt(plaintext)
