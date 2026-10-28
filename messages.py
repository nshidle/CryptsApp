"""Signed messages between users (RSA-PSS with SHA-256).

The sender signs a canonical encoding of (id, from, to, timestamp, body), so
the signature also covers WHO it is for and WHEN it was sent: a message can't
be silently redirected to another user or back-dated.

The receiver trusts the sender's public key only after validating the
sender's certificate chain up to Root_CA (and checking the CRL). Messages
provide integrity, authenticity and non-repudiation; they are intentionally
NOT confidential (see README "Limitations").
"""
import datetime
import json
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import pki
from accounts import Session, user_exists
from config import MESSAGES_FILE
from crypto_utils import b64d, b64e, log
from storage import load_json, save_json

SIGNED_FIELDS = ("id", "from", "to", "timestamp", "body")
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def canonical(msg: dict) -> bytes:
    """Deterministic byte encoding: same message -> same bytes -> same hash."""
    return json.dumps({k: msg[k] for k in SIGNED_FIELDS}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def send(session: Session, to: str, body: str) -> dict:
    if not user_exists(to):
        raise ValueError(f"No such user: {to}")
    msg = {
        "id": secrets.token_hex(8),
        "from": session.username,
        "to": to,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "body": body,
    }
    sig = session.signing_key.sign(canonical(msg), PSS, hashes.SHA256())
    log("RSA-PSS", f"signed message {msg['id']} with SHA-256, signature = {len(sig) * 8} bits")
    msg["signature"] = b64e(sig)
    msg["signer_cert"] = pki.cert_to_pem(session.cert)
    msgs = load_json(MESSAGES_FILE, [])
    msgs.append(msg)
    save_json(MESSAGES_FILE, msgs)
    return msg


def verify(msg: dict) -> tuple[bool, str]:
    """Return (trusted?, reason)."""
    try:
        cert = pki.cert_from_pem(msg["signer_cert"])
        pki.verify_chain(cert, expected_username=msg["from"])  # 1. trust the key
        cert.public_key().verify(b64d(msg["signature"]), canonical(msg), PSS, hashes.SHA256())
        log("RSA-PSS", f"signature on message {msg['id']} VALID")
        return True, f"valid signature by '{msg['from']}' (certified by Sub_CA -> Root_CA)"
    except pki.PKIError as e:
        return False, f"untrusted signer certificate: {e}"
    except InvalidSignature:
        log("RSA-PSS", f"signature on message {msg['id']} INVALID")
        return False, "INVALID signature: message was altered or not signed by this key"
    except (KeyError, ValueError) as e:
        return False, f"malformed message: {e}"


def inbox(username: str) -> list[dict]:
    return [m for m in load_json(MESSAGES_FILE, []) if m.get("to") == username]


def sent(username: str) -> list[dict]:
    return [m for m in load_json(MESSAGES_FILE, []) if m.get("from") == username]
