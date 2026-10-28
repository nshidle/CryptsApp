"""Automated end-to-end demo + attack tests.

Runs in its own folder (demo_data/) so it never touches your real data.
Every step prints what the crypto layer does: use the output for report
screenshots. Exits with status 1 if any expected outcome is not met.

    python demo.py
"""
import copy
import datetime
import json
import os
import shutil
import sys
from pathlib import Path

DEMO_DIR = Path(__file__).parent / "demo_data"
os.environ["CRYPTOAPP_DATA"] = str(DEMO_DIR)
ROOT_PW, SUB_PW = "root-ca-demo-passphrase", "sub-ca-demo-passphrase"

import accounts  # noqa: E402  (must import after setting CRYPTOAPP_DATA)
import messages  # noqa: E402
import notes  # noqa: E402
import pki  # noqa: E402
from config import NOTES_DIR, USERS_FILE  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from crypto_utils import aad_for, aead_decrypt, b64d, b64e  # noqa: E402
from storage import load_json, save_json  # noqa: E402

results = []


def step(title):
    print(f"\n{'=' * 70}\n {title}\n{'=' * 70}")


def check(desc, ok):
    results.append((desc, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {desc}")


def expect_error(desc, fn, exc_types):
    try:
        fn()
        check(desc + "  (no error raised!)", False)
    except exc_types as e:
        print(f"    -> rejected: {e or type(e).__name__}")
        check(desc, True)


def flip_byte(b64: str, index: int = 5) -> str:
    raw = bytearray(b64d(b64))
    raw[index] ^= 0x01
    return b64e(bytes(raw))


shutil.rmtree(DEMO_DIR, ignore_errors=True)

# ---------------------------------------------------------------------------
step("1. CA operator creates the PKI (Root_CA -> Sub_CA)")
pki.init_pki(ROOT_PW, SUB_PW)
print("\nRoot_CA:\n" + pki.describe(pki.load_cert(pki.ROOT_CERT)))
print("\nSub_CA:\n" + pki.describe(pki.load_cert(pki.SUB_CERT)))
check("Root_CA and Sub_CA created", pki.is_initialised())

# ---------------------------------------------------------------------------
step("2. Sign up: alice and bob (key pair + CSR + certificate + wrapped keys)")
accounts.register("alice", "Alice2026pw", SUB_PW)
accounts.register("bob", "BobSecret99", SUB_PW)
check("alice and bob registered", accounts.user_exists("alice") and accounts.user_exists("bob"))
rec = load_json(USERS_FILE, {})["alice"]
print("\n  What users.json stores for alice (no password, no plaintext keys):")
def _short(v):
    if isinstance(v, dict):
        return {k: _short(x) for k, x in v.items()}
    return v[:44] + "..." if isinstance(v, str) and len(v) > 44 else v
print(json.dumps({k: _short(v) for k, v in rec.items() if k != "cert_pem"}, indent=4))
expect_error("duplicate username rejected", lambda: accounts.register("Alice", "Another123", SUB_PW), ValueError)
expect_error("weak password rejected", lambda: accounts.register("carol", "short", SUB_PW), ValueError)
expect_error("wrong CA passphrase cannot issue certs",
             lambda: accounts.register("carol", "CarolPass123", "wrong-pass"), pki.PKIError)

# ---------------------------------------------------------------------------
step("3. Login (Scrypt verifier, then unwrap DEK + signing key)")
expect_error("wrong password rejected", lambda: accounts.login("alice", "nope12345"), accounts.AuthError)
expect_error("unknown user gets the SAME generic error",
             lambda: accounts.login("nobody", "whatever1"), accounts.AuthError)
alice = accounts.login("alice", "Alice2026pw")
bob = accounts.login("bob", "BobSecret99")
check("alice and bob logged in", alice.username == "alice" and bob.username == "bob")

# ---------------------------------------------------------------------------
step("4. Authenticated encryption of private notes (AES-256-GCM)")
n1 = notes.add_note(alice, "Bank PIN hint", "Grandma's birthday backwards")
n2 = notes.add_note(alice, "Ideas", "Build a crypto app for the course")
print("\n  Raw on-disk content of notes/alice.json:")
print("  " + json.dumps(load_json(NOTES_DIR / "alice.json", {}), indent=2)[:400].replace("\n", "\n  "))
listed = {nid: n for nid, n, err in notes.list_notes(alice)}
check("alice decrypts her own notes", listed[n1]["body"] == "Grandma's birthday backwards")

blob = load_json(NOTES_DIR / "alice.json", {})[n1]
expect_error("bob's DEK cannot decrypt alice's note",
             lambda: aead_decrypt(bob.dek, blob, aad_for("alice", f"note:{n1}")), InvalidTag)

# copy alice's ciphertext into bob's file -> AAD mismatch
bob_notes = load_json(NOTES_DIR / "bob.json", {})
bob_notes["stolen"] = blob
save_json(NOTES_DIR / "bob.json", bob_notes)
check("ciphertext moved to another user is detected",
      any(err for _, _, err in notes.list_notes(bob)))

# tamper one bit of alice's ciphertext
data = load_json(NOTES_DIR / "alice.json", {})
original = copy.deepcopy(data)
data[n1]["ct"] = flip_byte(data[n1]["ct"])
save_json(NOTES_DIR / "alice.json", data)
errs = {nid: err for nid, _, err in notes.list_notes(alice)}
print(f"    -> note {n1}: {errs[n1]}")
check("1-bit tampering of a note is detected (GCM tag)", errs[n1] is not None and errs[n2] is None)
save_json(NOTES_DIR / "alice.json", original)

# ---------------------------------------------------------------------------
step("5. Digital signatures: alice -> bob (RSA-PSS + chain validation)")
m = messages.send(alice, "bob", "Meet at 18:00 by the library. -A")
ok, reason = messages.verify(messages.inbox("bob")[0])
print(f"    -> {reason}")
check("bob verifies alice's signed message", ok)

tampered = dict(m, body="Meet at 23:00 behind the gym. -A")
ok, reason = messages.verify(tampered)
print(f"    -> {reason}")
check("modified message body is rejected", not ok)

redirected = dict(m, to="carol")
ok, reason = messages.verify(redirected)
print(f"    -> {reason}")
check("redirected message (changed recipient) is rejected", not ok)

swapped = dict(m, signer_cert=pki.cert_to_pem(bob.cert))
ok, reason = messages.verify(swapped)
print(f"    -> {reason}")
check("attaching someone else's certificate is rejected", not ok)

# ---------------------------------------------------------------------------
step("6. Attack: mallory builds her OWN CA and forges a cert for 'alice'")
now = datetime.datetime.now(datetime.timezone.utc)
evil_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
evil_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CryptoApp Issuing CA")])
fake_alice_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
fake_cert = (x509.CertificateBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alice")]))
             .issuer_name(pki.load_cert(pki.SUB_CERT).subject)  # even copies the real issuer name
             .public_key(fake_alice_key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(pki._key_usage(digital_signature=True), critical=True)
             .sign(evil_key, hashes.SHA256()))
forged = {"id": "f0f0f0f0", "from": "alice", "to": "bob", "timestamp": now.isoformat(timespec="seconds"),
          "body": "Please send me your password. -A"}
forged["signature"] = b64e(fake_alice_key.sign(messages.canonical(forged), messages.PSS, hashes.SHA256()))
forged["signer_cert"] = pki.cert_to_pem(fake_cert)
ok, reason = messages.verify(forged)
print(f"    -> {reason}")
check("forged certificate from a rogue CA is rejected", not ok)

# ---------------------------------------------------------------------------
step("7. Modify account data: alice changes her password")
accounts.change_password(alice, "Alice2026pw", "NewAlicePw2026")
expect_error("old password no longer works", lambda: accounts.login("alice", "Alice2026pw"), accounts.AuthError)
alice = accounts.login("alice", "NewAlicePw2026")
listed = {nid: n for nid, n, _ in notes.list_notes(alice)}
check("notes still readable after password change (DEK re-wrapped, not re-encrypted)",
      listed[n1]["body"] == "Grandma's birthday backwards")

users = load_json(USERS_FILE, {})
saved = copy.deepcopy(users)
users["alice"]["wrapped_dek"]["ct"] = flip_byte(users["alice"]["wrapped_dek"]["ct"])
save_json(USERS_FILE, users)
expect_error("tampered wrapped DEK is detected at login",
             lambda: accounts.login("alice", "NewAlicePw2026"), accounts.AuthError)
save_json(USERS_FILE, saved)

# ---------------------------------------------------------------------------
step("8. Revocation: bob deletes his account -> Sub_CA revokes his cert (CRL)")
mb = messages.send(bob, "alice", "Thanks, see you there! -B")
check("bob's message valid before revocation", messages.verify(mb)[0])
accounts.delete_account(bob, "BobSecret99", SUB_PW)
ok, reason = messages.verify(messages.inbox("alice")[0])
print(f"    -> {reason}")
check("bob's signature rejected after his cert is revoked", not ok)
check("bob can no longer log in", not accounts.user_exists("bob"))

# ---------------------------------------------------------------------------
step("SUMMARY")
passed = sum(ok for _, ok in results)
print(f"  {passed}/{len(results)} checks passed")
for desc, ok in results:
    if not ok:
        print(f"  FAILED: {desc}")
sys.exit(0 if passed == len(results) else 1)
