"""
Negative-control crypto file for scout-crypto E2E testing.

Detector must NOT fire on any function below. If it does, the calibration
is wrong and the slice is blocked.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import os

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet


# md5 outside security context — checksum use, fine.
def file_checksum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


# secrets module for tokens — correct.
def make_session_token() -> bytes:
    return secrets.token_bytes(32)


# Constant-time compare — correct.
def verify_signature(provided: str, expected: str) -> bool:
    return hmac.compare_digest(provided, expected)


# RSA 2048 — at the floor, not below.
def generate_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# AES-GCM with random nonce — correct.
def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    enc = cipher.encryptor()
    return nonce + enc.update(plaintext) + enc.finalize()


# Fernet with a fresh key — correct.
def encrypt_message(plaintext: bytes) -> bytes:
    f = Fernet(Fernet.generate_key())
    return f.encrypt(plaintext)


# ChaCha20 — modern, fine.
def encrypt_chacha(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    enc = cipher.encryptor()
    return enc.update(plaintext)


# SECP256R1 — at the floor.
def generate_ec_key():
    return ec.generate_private_key(ec.SECP256R1())
