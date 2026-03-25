"""
manager/security/ — Auth, CSRF, hashing, session cookies, audit helpers.
"""

# ─── hashing.py content (inlined for brevity in one file) ────────────────────
# manager/security/hashing.py

import bcrypt as _bcrypt
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def hash_bcrypt(password: str, cost: int = 12) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(cost)).decode()


def verify_bcrypt(password: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def _get_aes_key() -> bytes:
    key = os.environ.get("ENCRYPTION_KEY", "")
    if not key or len(key) < 32:
        raise ValueError("ENCRYPTION_KEY must be at least 32 chars")
    return key[:32].encode()


def encrypt_secret(plaintext: str) -> str:
    """AES-256-GCM encrypt a secret string. Returns base64-encoded ciphertext."""
    key   = _get_aes_key()
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_secret(ciphertext_b64: str) -> str:
    """Decrypt an AES-256-GCM encrypted secret."""
    key  = _get_aes_key()
    raw  = base64.b64decode(ciphertext_b64)
    pt   = AESGCM(key).decrypt(raw[:12], raw[12:], None)
    return pt.decode()
