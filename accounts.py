"""User accounts: sign-up, login, password change, account deletion.

Key hierarchy per user
----------------------
    password ──Scrypt(pw_salt)──► password verifier   (stored, only checks login)
    password ──Scrypt(kek_salt)─► KEK                 (RAM only, never stored)
                                   │
                                   ├─AES-GCM─► wrapped DEK          (stored)
                                   └─AES-GCM─► wrapped signing key  (stored)
    DEK (random 256-bit) ──AES-GCM──► user's notes
    signing key (RSA-3072) ──► certified by Sub_CA, used for RSA-PSS signatures

Changing the password only re-wraps the DEK and the signing key; the notes
themselves never need to be re-encrypted.
"""
import datetime
import os
import re
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import pki
from config import NOTES_DIR, USERS_FILE
from crypto_utils import (aad_for, aead_decrypt, aead_encrypt, b64d, b64e, derive_key,
                          log, new_data_key, verify_password)
from storage import load_json, save_json

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
GENERIC_LOGIN_ERROR = "Invalid username or password"


class AuthError(Exception):
    pass


@dataclass
class Session:
    """Everything a logged-in user needs, held only in memory."""
    username: str
    dek: bytes
    signing_key: rsa.RSAPrivateKey
    cert: x509.Certificate


# ------------------------------------------------------------------ helpers
def check_password_policy(password: str) -> None:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValueError("Password must contain at least one letter and one digit")


def user_exists(username: str) -> bool:
    return username.lower() in {u.lower() for u in load_json(USERS_FILE, {})}


def _key_to_der(key) -> bytes:
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _wrap_secrets(username: str, password: str, dek: bytes, key_der: bytes) -> dict:
    """Fresh salts -> new verifier + new KEK -> wrap DEK and signing key."""
    pw_salt, kek_salt = os.urandom(16), os.urandom(16)
    pw_hash = derive_key(password, pw_salt, "password verifier")
    kek = derive_key(password, kek_salt, "KEK")
    return {
        "pw_salt": b64e(pw_salt),
        "pw_hash": b64e(pw_hash),
        "kek_salt": b64e(kek_salt),
        "wrapped_dek": aead_encrypt(kek, dek, aad_for(username, "dek")),
        "wrapped_signing_key": aead_encrypt(kek, key_der, aad_for(username, "signing-key")),
    }


# ------------------------------------------------------------------ sign up
def register(username: str, password: str, ca_pass: str) -> None:
    if not USERNAME_RE.match(username):
        raise ValueError("Username must be 3-20 characters: letters, digits, underscore")
    if user_exists(username):
        raise ValueError("Username already taken")
    check_password_policy(password)

    # 1. Signing key pair + CSR, certified by the Sub_CA
    log("RSA", f"generating RSA-3072 signing key pair for '{username}'")
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)]))
           .sign(signing_key, hashes.SHA256()))
    cert = pki.issue_user_cert(csr, username, ca_pass)

    # 2. Random data-encryption key, then wrap everything under the KEK
    dek = new_data_key()
    log("KeyMgmt", "generated random 256-bit DEK")
    record = _wrap_secrets(username, password, dek, _key_to_der(signing_key))
    record["cert_pem"] = pki.cert_to_pem(cert)
    record["created"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    users = load_json(USERS_FILE, {})
    users[username] = record
    save_json(USERS_FILE, users)


# -------------------------------------------------------------------- login
def login(username: str, password: str) -> Session:
    users = load_json(USERS_FILE, {})
    rec = users.get(username)
    if rec is None:
        # Spend the same Scrypt effort so response time doesn't reveal
        # whether the username exists (user-enumeration defence).
        verify_password(password, os.urandom(16), os.urandom(32))
        raise AuthError(GENERIC_LOGIN_ERROR)
    if not verify_password(password, b64d(rec["pw_salt"]), b64d(rec["pw_hash"])):
        raise AuthError(GENERIC_LOGIN_ERROR)

    kek = derive_key(password, b64d(rec["kek_salt"]), "KEK")
    try:
        dek = aead_decrypt(kek, rec["wrapped_dek"], aad_for(username, "dek"))
        key_der = aead_decrypt(kek, rec["wrapped_signing_key"], aad_for(username, "signing-key"))
    except InvalidTag:
        raise AuthError("Stored key material failed its integrity check (tampered?)")
    signing_key = serialization.load_der_private_key(key_der, password=None)

    # Our own certificate must still be valid and must match our private key.
    cert = pki.cert_from_pem(rec["cert_pem"])
    try:
        pki.verify_chain(cert, expected_username=username)
    except pki.PKIError as e:
        raise AuthError(f"Your certificate is not trusted: {e}")
    if cert.public_key().public_numbers() != signing_key.public_key().public_numbers():
        raise AuthError("Certificate does not match the stored private key")
    log("KeyMgmt", "DEK and signing key unwrapped into memory for this session")
    return Session(username, dek, signing_key, cert)


# ---------------------------------------------------- modify account data
def change_password(session: Session, old_password: str, new_password: str) -> None:
    users = load_json(USERS_FILE, {})
    rec = users[session.username]
    if not verify_password(old_password, b64d(rec["pw_salt"]), b64d(rec["pw_hash"])):
        raise AuthError("Current password is incorrect")
    check_password_policy(new_password)
    log("KeyMgmt", "re-wrapping DEK and signing key under a new KEK (notes untouched)")
    rec.update(_wrap_secrets(session.username, new_password, session.dek,
                             _key_to_der(session.signing_key)))
    save_json(USERS_FILE, users)


def delete_account(session: Session, password: str, ca_pass: str) -> None:
    users = load_json(USERS_FILE, {})
    rec = users[session.username]
    if not verify_password(password, b64d(rec["pw_salt"]), b64d(rec["pw_hash"])):
        raise AuthError("Password is incorrect")
    pki.revoke(session.cert, ca_pass)  # signatures with this key are no longer trusted
    del users[session.username]
    save_json(USERS_FILE, users)
    note_file = NOTES_DIR / f"{session.username}.json"
    if note_file.exists():
        note_file.unlink()
    log("KeyMgmt", "account record and encrypted notes deleted; DEK is gone for good")
