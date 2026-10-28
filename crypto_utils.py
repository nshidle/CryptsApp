"""Symmetric primitives: password hashing / key derivation (Scrypt) and
authenticated encryption (AES-256-GCM).

Design notes
------------
* Scrypt is a memory-hard KDF: it makes offline brute force of stolen
  password hashes expensive in both CPU and RAM (hurts GPU/ASIC attackers).
* The SAME password is run through Scrypt twice with two INDEPENDENT salts:
    - pw_salt  -> verifier stored in users.json (used only to check login)
    - kek_salt -> Key Encryption Key (never stored, lives only in RAM)
  Because the salts differ, the stored verifier reveals nothing about the KEK.
* AES-GCM gives confidentiality + integrity + authenticity in one primitive.
  A fresh 96-bit random nonce is used for EVERY encryption (nonce reuse with
  the same key would break GCM). Associated data (AAD) binds each ciphertext
  to its owner and purpose so blobs can't be swapped between users/records.
"""
import base64
import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from config import VERBOSE

# n = 2^15, r = 8 -> ~32 MiB of RAM per derivation (OWASP-recommended range).
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
KEY_LEN = 32  # 256-bit keys
NONCE_LEN = 12  # 96-bit GCM nonce (the size GCM is designed for)


def log(tag: str, msg: str) -> None:
    if VERBOSE:
        print(f"    [{tag}] {msg}")


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def aad_for(username: str, purpose: str) -> bytes:
    """Associated data: context the ciphertext is cryptographically bound to."""
    return f"cryptoapp|v1|{username}|{purpose}".encode("utf-8")


# --------------------------------------------------------------------------- KDF
def _scrypt(salt: bytes) -> Scrypt:
    return Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)


def derive_key(password: str, salt: bytes, label: str = "key") -> bytes:
    log("Scrypt", f"derive {label}: n=2^15 r=8 p=1, salt={salt.hex()[:16]}...")
    return _scrypt(salt).derive(password.encode("utf-8"))


def verify_password(password: str, salt: bytes, expected: bytes) -> bool:
    """Re-derive and compare in constant time (Scrypt.verify does that)."""
    try:
        _scrypt(salt).verify(password.encode("utf-8"), expected)
        log("Scrypt", "password verifier matched (constant-time compare)")
        return True
    except InvalidKey:
        log("Scrypt", "password verifier did NOT match")
        return False


# ---------------------------------------------------------------------- AES-GCM
def new_data_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> dict:
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)  # ct = ciphertext || 128-bit tag
    log("AES-256-GCM", f"encrypt {len(plaintext)} B  nonce={nonce.hex()}  aad={aad.decode()}")
    return {"nonce": b64e(nonce), "ct": b64e(ct)}


def aead_decrypt(key: bytes, blob: dict, aad: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag if anything was altered."""
    pt = AESGCM(key).decrypt(b64d(blob["nonce"]), b64d(blob["ct"]), aad)
    log("AES-256-GCM", f"decrypt OK, tag verified  aad={aad.decode()}")
    return pt
