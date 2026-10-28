# CryptoApp: Cryptography Project Report

October 28, 2026

## 1. High-level description

CryptoApp is a multi-user command-line application for **private notes** and **signed messages**. Each user's notes are stored encrypted with AES-256-GCM, and every message is signed with RSA-PSS and verified against a certificate chain that ends at our own Root\_CA.

The app is written in Python 3 and uses the `cryptography` library for every primitive. No algorithm is implemented by hand. State is stored in JSON files under a `data/` folder.

### Features

| Feature | What the user sees | Cryptography behind it |
| --- | --- | --- |
| Sign up | Choose a username and password | Scrypt verifier, RSA-3072 key pair, CSR, certificate from Sub\_CA, wrapped keys |
| Log in | Enter username and password | Constant-time Scrypt check, then unwrap DEK and signing key into memory |
| Private notes | Create, list, delete notes | AES-256-GCM with a per-user DEK; AAD binds owner and note id |
| Signed messages | Send to another user, read inbox | RSA-PSS / SHA-256; sender certificate validated up to Root\_CA |
| Change password | Optional account modification | DEK and signing key re-wrapped under a new KEK |
| Delete account | Remove the account | Certificate revoked in the Sub\_CA's signed CRL |
| CA administration | Separate `ca_admin.py` tool | Root\_CA and Sub\_CA creation, CRL refresh, list of issued certs |

### Threat model

We protect against an attacker who **reads or modifies the files on disk**: stolen `users.json`, edited ciphertexts, swapped records, forged messages and certificates from a rogue CA. We do **not** protect against malware on the machine while a user is logged in, since the keys are in memory at that point. We also assume the Root\_CA certificate on disk is genuine (see section 12).

## 2. Technical description: modules and main functionalities

The code is split into eight modules, so that all cryptographic primitives sit in two files (`crypto_utils.py` and `pki.py`). The application logic only calls those.

| Module | Responsibility | Main functions |
| --- | --- | --- |
| `config.py` | Paths and settings; `CRYPTOAPP_DATA` overrides the data folder | (constants) |
| `storage.py` | JSON load/save with atomic writes (temp file + `os.replace`) | `load_json`, `save_json` |
| `crypto_utils.py` | Symmetric primitives: Scrypt KDF and verifier, AES-GCM, Base64, AAD | `derive_key`, `verify_password`, `aead_encrypt`, `aead_decrypt`, `aad_for` |
| `pki.py` | Root\_CA and Sub\_CA, CSR-based issuance, CRL, chain validation | `init_pki`, `issue_user_cert`, `revoke`, `verify_chain` |
| `accounts.py` | Sign-up, login, password change, account deletion, key hierarchy | `register`, `login`, `change_password`, `delete_account` |
| `notes.py` | Encrypted private notes | `add_note`, `list_notes`, `delete_note` |
| `messages.py` | Signing and verifying messages | `send`, `verify`, `inbox`, `canonical` |
| `app.py` / `ca_admin.py` | Interactive CLI for users / for the CA operator | `main`, `user_menu` |

`demo.py` is a ninth file that runs the whole scenario automatically, including 12 attacks, and prints 23 PASS/FAIL checks.

After login, everything a user needs is held in a `Session` object that only exists in memory:

```python
@dataclass
class Session:
    """Everything a logged-in user needs, held only in memory."""
    username: str
    dek: bytes                       # data encryption key (AES-256)
    signing_key: rsa.RSAPrivateKey   # RSA-3072 private key
    cert: x509.Certificate           # the user's certificate
```

Logging out simply drops this object, so no key material stays reachable by the program.

## 3. Byte-like and text-like data: encoding and decoding

Cryptographic functions work on `bytes`, while our storage is JSON, which only holds text. We therefore apply four conversions consistently at the boundary between the two.

| Data | Direction | Encoding used | Where |
| --- | --- | --- | --- |
| Passwords, usernames, note text, AAD | text → bytes | UTF-8 (`str.encode("utf-8")`) | `crypto_utils.py`, `notes.py` |
| Salts, hashes, nonces, ciphertexts, signatures | bytes → text for JSON | Base64 (`b64e` / `b64d`) | everywhere data is saved |
| Note payload (title, body, timestamp) | dict → bytes before encryption | JSON, then UTF-8 | `notes.add_note` |
| Message to be signed | dict → bytes before signing | Canonical JSON: sorted keys, no spaces | `messages.canonical` |
| Certificates, CA keys, CRL | object ↔ text file | PEM (Base64 of DER with header lines) | `pki.py` |
| User private key before wrapping | object → bytes | DER, PKCS#8 | `accounts._key_to_der` |

The Base64 helpers are deliberately tiny:

```python
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s)
```

The canonical encoding for signatures matters. A signature covers exact bytes, so the same message must always serialise to the same bytes, whatever order the dictionary keys were inserted in:

```python
SIGNED_FIELDS = ("id", "from", "to", "timestamp", "body")

def canonical(msg: dict) -> bytes:
    return json.dumps({k: msg[k] for k in SIGNED_FIELDS}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

Hex is used only for display (salts, nonces and serial numbers in the log output), never for storage.

## 4. User authentication

Passwords are never stored. For each user we store a 128-bit random salt and `Scrypt(password, pw_salt)`, a 256-bit **password verifier**.

- **Why Scrypt and not SHA-256:** SHA-256 is designed to be fast, which helps an attacker test billions of guesses. Scrypt is slow and memory-hard. With n = 2^15, r = 8, p = 1 each guess needs about 32 MiB of RAM, which makes GPU and ASIC attacks expensive.
- **Why a salt:** it defeats precomputed rainbow tables, and two users with the same password get different verifiers.
- **Constant-time comparison:** `Scrypt.verify()` re-derives the value and compares it in constant time, so response timing leaks nothing about how many bytes matched.
- **No user enumeration:** an unknown username and a wrong password give the same message, `Invalid username or password`. For unknown users we still run one Scrypt derivation so the response time is the same.
- **Password policy:** at least 8 characters, containing letters and digits. Usernames are 3 to 20 characters of letters, digits and underscore.

```python
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1

def verify_password(password: str, salt: bytes, expected: bytes) -> bool:
    """Re-derive and compare in constant time (Scrypt.verify does that)."""
    try:
        _scrypt(salt).verify(password.encode("utf-8"), expected)
        return True
    except InvalidKey:
        return False
```

```python
def login(username: str, password: str) -> Session:
    users = load_json(USERS_FILE, {})
    rec = users.get(username)
    if rec is None:
        # Same Scrypt effort, so timing doesn't reveal which usernames exist
        verify_password(password, os.urandom(16), os.urandom(32))
        raise AuthError(GENERIC_LOGIN_ERROR)
    if not verify_password(password, b64d(rec["pw_salt"]), b64d(rec["pw_hash"])):
        raise AuthError(GENERIC_LOGIN_ERROR)
    ...
```

Terminal output from `demo.py`:

```text
    [Scrypt] password verifier did NOT match
    -> rejected: Invalid username or password
  PASS  wrong password rejected
    -> rejected: Invalid username or password
  PASS  unknown user gets the SAME generic error
```

## 5. Data encryption and authentication

All protected data is encrypted with **AES-256-GCM**, an authenticated encryption (AEAD) mode. A single call gives confidentiality, integrity and authenticity, which avoids the classic mistakes of combining a cipher and a MAC by hand (wrong order, MAC over the wrong data, key reuse between them).

```python
NONCE_LEN = 12  # 96-bit GCM nonce

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> dict:
    nonce = os.urandom(NONCE_LEN)                     # fresh for EVERY encryption
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)  # ciphertext || 128-bit tag
    return {"nonce": b64e(nonce), "ct": b64e(ct)}

def aead_decrypt(key: bytes, blob: dict, aad: bytes) -> bytes:
    """Raises InvalidTag if anything was altered."""
    return AESGCM(key).decrypt(b64d(blob["nonce"]), b64d(blob["ct"]), aad)
```

**Nonces.** A fresh random 96-bit nonce is generated for every encryption and stored next to the ciphertext. Reusing a (key, nonce) pair in GCM would reveal the XOR of the two plaintexts and let an attacker forge tags. With random 96-bit nonces the chance of a collision stays negligible below about 2^32 encryptions per key, far beyond what one user writes.

**Associated data (AAD).** Each ciphertext is bound to its owner and purpose with `cryptoapp|v1|<username>|<purpose>`. The purpose is `note:<id>` for notes, and `dek` or `signing-key` for wrapped keys. The AAD is not encrypted but is covered by the tag. A ciphertext copied into another user's file, or under another note id, fails to decrypt.

```python
def aad_for(username: str, purpose: str) -> bytes:
    return f"cryptoapp|v1|{username}|{purpose}".encode("utf-8")
```

**What is encrypted and what is not.** The assignment states that not all data must be protected, so we chose deliberately:

| Data | Protected? | Reason |
| --- | --- | --- |
| Note title, body and date | Encrypted (AES-GCM) | Private user content |
| DEK and user private key | Encrypted (AES-GCM under the KEK) | Secret key material |
| Note ids | Authenticated through AAD | Needed to address records; swapping is detected |
| Usernames | Plain | Needed to find the account before login |
| Salts | Plain | Salts are not secret by definition |
| Password verifier | Plain | Already one-way; Scrypt makes guessing costly |
| Certificates | Plain | Public by design |
| Messages | Signed, not encrypted | Integrity and authenticity are the goal (section 10) |

On disk, a note is only a nonce and a ciphertext:

```text
  Raw on-disk content of notes/alice.json:
  {
    "1e7f43600caa": {
      "nonce": "s+c0Q7uDit7qtIsd",
      "ct": "SfmgLJp6Ctk/eLl+xsJDZGRlD7VLJ5hsOhnuPbPmGLNhv4TiT+VnRCmsn3QfvTV5..."
    },
    ...
    [AES-256-GCM] decrypt OK, tag verified  aad=cryptoapp|v1|alice|note:1e7f43600caa
  PASS  alice decrypts her own notes
```

Tampering demo: flipping a single bit of the ciphertext makes the tag check fail.

```text
  PASS  bob's DEK cannot decrypt alice's note
  PASS  ciphertext moved to another user is detected
    -> note 1e7f43600caa: INTEGRITY CHECK FAILED: note was modified or moved
  PASS  1-bit tampering of a note is detected (GCM tag)
```

## 6. Symmetric key management

Each user has two levels of symmetric keys: a random **data encryption key (DEK)** that encrypts the notes, and a password-derived **key encryption key (KEK)** that wraps the DEK. Only the wrapped DEK is ever written to disk.

```text
                         ┌─────────────────────┐
                    ┌───►│ Password verifier   │  Scrypt + pw_salt, stored in users.json
                    │    └─────────────────────┘
┌──────────────┐    │
│  Password    │────┤
│ never stored │    │    ┌─────────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
└──────────────┘    └───►│ KEK  (RAM only)     │───►│ DEK (random)     │───►│ Notes               │
                         │ Scrypt + kek_salt   │    │ wrapped by KEK   │    │ AES-256-GCM,        │
                         └─────────┬───────────┘    │ in users.json    │    │ AAD: user + note id │
                                   │                └──────────────────┘    └─────────────────────┘
                                   │                ┌──────────────────┐    ┌─────────────────────┐
                                   └───────────────►│ Signing key      │───►│ Messages            │
                                                    │ RSA-3072, wrapped│    │ RSA-PSS, SHA-256    │
                                                    │ by KEK           │    │ cert from Sub_CA    │
                                                    └──────────────────┘    └─────────────────────┘
```

*Figure 1. Per-user key hierarchy: only the KEK, derived in RAM, can unwrap the user's keys.*

The stored verifier and the KEK come from the same password through different salts, so reading `users.json` reveals neither the KEK nor the keys it wraps.

| Key | Size | How it is created | Where it lives | Used for |
| --- | --- | --- | --- | --- |
| Password verifier | 256 bit | Scrypt(password, `pw_salt`) | `users.json` | Checking the password at login |
| KEK | 256 bit | Scrypt(password, `kek_salt`) | RAM only, during login or password change | Wrapping the DEK and the signing key |
| DEK | 256 bit | `AESGCM.generate_key(256)`, i.e. the OS random generator | `users.json`, wrapped by the KEK; RAM during a session | Encrypting notes |

**Two independent salts.** The verifier and the KEK come from the same password but different random salts. Knowing the stored verifier therefore gives no information about the KEK. If we used one derivation for both, whoever read `users.json` would hold the encryption key.

**Why a separate DEK.** Encrypting notes directly with the KEK would also work, but the DEK design has two advantages. The DEK is full-entropy rather than tied to the password's strength. And changing the password only re-wraps two small blobs; the notes themselves are never re-encrypted.

```python
def _wrap_secrets(username, password, dek, key_der) -> dict:
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
```

The same function is used at sign-up and at password change, so both salts are refreshed every time the password changes. Wrapping uses AES-GCM with its own AAD, so a tampered wrapped key is detected at login instead of producing a garbage key:

```text
    [KeyMgmt] re-wrapping DEK and signing key under a new KEK (notes untouched)
  PASS  old password no longer works
  PASS  notes still readable after password change (DEK re-wrapped, not re-encrypted)
    -> rejected: Stored key material failed its integrity check (tampered?)
  PASS  tampered wrapped DEK is detected at login
```

**Lifecycle.** Keys are created at sign-up, unwrapped into the `Session` at login, re-wrapped on password change, and destroyed on account deletion together with the encrypted notes. A forgotten password means the data cannot be recovered. This is intentional: there is no master key or backdoor.

## 7. Asymmetric key management

The system has three kinds of RSA key pairs. Each private key is protected by a secret belonging to whoever is responsible for it, so no single password unlocks everything.

| Key pair | Algorithm | Owner | Private key protection | Public key published as |
| --- | --- | --- | --- | --- |
| Root\_CA | RSA-4096, e = 65537 | CA operator | PKCS#8 encrypted with the Root\_CA passphrase, file mode 600 | Self-signed certificate (the trust anchor) |
| Sub\_CA | RSA-3072, e = 65537 | CA operator | PKCS#8 encrypted with the Sub\_CA passphrase, file mode 600 | Certificate signed by Root\_CA |
| User signing key | RSA-3072, e = 65537 | Each user | AES-GCM under the user's KEK, stored in `users.json` | Certificate signed by Sub\_CA |

**Key sizes.** RSA-3072 gives roughly 128-bit security, which NIST recommends for use beyond 2030. The Root\_CA uses RSA-4096 because its certificate lasts 10 years and everything else depends on it.

**Generation.** Each user's key pair is generated on their side at sign-up. Only the public key leaves, inside a CSR, so the CA never sees the user's private key.

```python
signing_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
csr = (x509.CertificateSigningRequestBuilder()
       .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)]))
       .sign(signing_key, hashes.SHA256()))
cert = pki.issue_user_cert(csr, username, ca_pass)
```

**Why user keys use our AES-GCM wrapping rather than PKCS#8 encryption.** `BestAvailableEncryption` produces PKCS#8 PBES2, which uses AES-CBC, an unauthenticated mode. Wrapping the DER bytes with AES-GCM under the KEK gives the same integrity guarantees as the rest of the user's data, and one password unlocks both the DEK and the signing key.

**Consistency check at login.** After unwrapping, the app checks that the stored certificate is still trusted and that its public key matches the private key. A swapped certificate in `users.json` is therefore refused:

```python
if cert.public_key().public_numbers() != signing_key.public_key().public_numbers():
    raise AuthError("Certificate does not match the stored private key")
```

**CA keys and separation of duties.** The Sub\_CA passphrase is required whenever a certificate is issued or revoked. A wrong passphrase stops the sign-up:

```text
    [PKI] CSR for 'carol' verified (proof of possession OK)
    -> rejected: Wrong passphrase for sub_ca.key.pem
  PASS  wrong CA passphrase cannot issue certs
```

## 8. Loading and serializing asymmetric keys and public key certificates

We use the standard formats so that every key, certificate and CRL can also be inspected and verified with OpenSSL.

| Object | Serialized as | Save | Load |
| --- | --- | --- | --- |
| CA private keys | PEM, PKCS#8, encrypted with a passphrase | `private_bytes(PEM, PKCS8, BestAvailableEncryption(pw))` | `load_pem_private_key(data, pw)` |
| User private key | DER, PKCS#8, unencrypted, then wrapped with AES-GCM | `private_bytes(DER, PKCS8, NoEncryption())` | `load_der_private_key(der, None)` |
| Certificates | PEM (X.509 v3) | `public_bytes(Encoding.PEM)` | `load_pem_x509_certificate` |
| CSR | Object passed in memory | (not stored) | `csr.is_signature_valid` |
| CRL | PEM | `crl.public_bytes(Encoding.PEM)` | `load_pem_x509_crl` |

CA key storage, including restricting the file to its owner:

```python
def _save_key(key, path, passphrase: str) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode()),
    ))
    os.chmod(path, 0o600)

def _load_key(path, passphrase: str):
    try:
        return serialization.load_pem_private_key(path.read_bytes(), passphrase.encode())
    except (ValueError, TypeError):
        raise PKIError(f"Wrong passphrase for {path.name}")
```

The user private key is turned into DER bytes and then encrypted as ordinary data, so it never touches disk in clear:

```python
def _key_to_der(key) -> bytes:
    return key.private_bytes(serialization.Encoding.DER,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())   # wrapped with AES-GCM right after
```

Certificates are stored as PEM text, both as files under `data/pki/` and embedded in `users.json` and in each message (`signer_cert`). This lets any receiver validate a sender without extra lookups. Interoperability check with OpenSSL:

```text
$ openssl verify -CAfile root_ca.crt.pem -untrusted sub_ca.crt.pem \
                 -crl_check -CRLfile sub_ca.crl.pem issued/7461c4..._alice.crt.pem
issued/7461c44c0e650f06c1e8210e97fd264a87643096_alice.crt.pem: OK
```

## 9. Digital signatures

Users sign every message they send with **RSA-PSS and SHA-256** using their RSA-3072 private key. Receivers verify the signature only after validating the sender's certificate chain up to Root\_CA. This gives integrity, authenticity and non-repudiation for messages.

**Why PSS rather than PKCS#1 v1.5.** PSS is randomised (a fresh salt per signature) and has a tight security proof that reduces forging to breaking RSA. PKCS#1 v1.5 is deterministic and has a history of implementation attacks. We use the maximum salt length with MGF1-SHA256.

**What is signed.** The signature covers the canonical encoding (section 3) of the id, sender, recipient, timestamp and body. Including `to` and `timestamp` means a signed message can't be redirected to someone else or presented as sent at another time.

```python
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

def send(session, to, body) -> dict:
    msg = {"id": secrets.token_hex(8), "from": session.username, "to": to,
           "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "body": body}
    sig = session.signing_key.sign(canonical(msg), PSS, hashes.SHA256())
    msg["signature"] = b64e(sig)
    msg["signer_cert"] = pki.cert_to_pem(session.cert)
    ...
```

**Verification order.** A signature is only as trustworthy as the public key used to check it. The receiver therefore (1) validates the attached certificate against our PKI and checks that its subject CN equals the `from` field, and only then (2) verifies the signature with the key from that certificate.

```python
def verify(msg: dict) -> tuple[bool, str]:
    try:
        cert = pki.cert_from_pem(msg["signer_cert"])
        pki.verify_chain(cert, expected_username=msg["from"])        # 1. trust the key
        cert.public_key().verify(b64d(msg["signature"]), canonical(msg),
                                 PSS, hashes.SHA256())               # 2. check the signature
        return True, f"valid signature by '{msg['from']}' (certified by Sub_CA -> Root_CA)"
    except pki.PKIError as e:
        return False, f"untrusted signer certificate: {e}"
    except InvalidSignature:
        return False, "INVALID signature: message was altered or not signed by this key"
```

Terminal output, one valid message followed by three attacks on it:

```text
    [RSA-PSS] signed message 522d2e7210d83bcb with SHA-256, signature = 3072 bits
    [PKI] cert[alice]: chain valid, dates valid, not revoked -> TRUSTED
    -> valid signature by 'alice' (certified by Sub_CA -> Root_CA)
  PASS  bob verifies alice's signed message
    -> INVALID signature: message was altered or not signed by this key
  PASS  modified message body is rejected
    -> INVALID signature: message was altered or not signed by this key
  PASS  redirected message (changed recipient) is rejected
    -> untrusted signer certificate: certificate belongs to 'bob', not 'alice'
  PASS  attaching someone else's certificate is rejected
```

The app in interactive mode shows the same result in the inbox:

```text
  [2026-10-26T19:00:32+00:00] alice -> bob  (id fd34d95828c3ccb9)
  hi bob
  ✔ TRUSTED: valid signature by 'alice' (certified by Sub_CA -> Root_CA)
```

## 10. Asymmetric and hybrid encryption

The current version does not use asymmetric encryption. The assignment asks for digital signatures **or** asymmetric encryption, and we chose signatures, because the app's goal for messages is to prove who wrote them and that they were not changed.

All confidentiality in the app is symmetric (AES-GCM), and each user only decrypts their own data. Since no secret is shared between users, no key exchange is needed.

**How it would be added.** Making messages confidential would use hybrid encryption with the recipient's certified public key:

1. The sender validates the recipient's certificate chain, exactly as for signatures.
2. The sender generates a random 256-bit message key and encrypts the body with AES-256-GCM.
3. The message key is encrypted with the recipient's RSA public key using **RSA-OAEP** (MGF1-SHA256). OAEP is the padding to use for encryption, as PSS is for signatures.
4. The sender signs the ciphertext, the wrapped key and the header fields (encrypt-then-sign), so the receiver can check authenticity before decrypting.

RSA is not used to encrypt the message directly because RSA-3072 with OAEP can only encrypt about 318 bytes and is much slower than AES. The recipients' key pairs would also need `keyEncipherment` in their KeyUsage, or better, a second key pair just for encryption, so that signing and encryption keys can be managed and revoked separately.

## 11. Public key certificates and mini-PKI

Our PKI has two levels: a self-signed **Root\_CA** that only certifies a subordinate **Sub\_CA**, and the Sub\_CA that issues every user certificate. All certificates are X.509 v3 and signed with SHA-256 with RSA.

```text
                  ┌──────────────────────────────────────┐
                  │ Root_CA (trust anchor)               │
                  │ self-signed, RSA-4096, 10 years      │
                  │ CA:TRUE, pathlen 1, offline          │
                  └──────────────────┬───────────────────┘
                                     │ signs
                  ┌──────────────────▼───────────────────┐  publishes  ┌───────────────────┐
                  │ Sub_CA (issuing CA)                  │────────────►│ CRL               │
                  │ signed by Root_CA, RSA-3072, 5 years │             │ signed by Sub_CA  │
                  │ CA:TRUE, pathlen 0                   │             │ 30-day nextUpdate │
                  └──────────────────┬───────────────────┘             └─────────┬─────────┘
                                     │ issues from CSR                           │ lists revoked
                    ┌────────────────┴─────────────────┐                         │ serial numbers
          ┌─────────▼──────────────┐         ┌─────────▼──────────────┐          │
          │ alice                  │         │ bob                    │◄─────────┘
          │ CA:FALSE, RSA-3072, 1y │         │ CA:FALSE, RSA-3072, 1y │
          │ digitalSignature       │         │ REVOKED (deleted)      │
          └────────────────────────┘         └────────────────────────┘
```

*Figure 2. Mini-PKI: every user certificate chains through Sub_CA to the Root_CA.*

A user certificate is trusted only if both signatures up the chain verify and its serial is absent from the Sub\_CA's CRL.

|  | Root\_CA | Sub\_CA | User certificate |
| --- | --- | --- | --- |
| Subject | CN=CryptoApp Root CA, OU=Root\_CA | CN=CryptoApp Issuing CA, OU=Sub\_CA | CN=\<username>, OU=Users |
| Signed by | Itself | Root\_CA | Sub\_CA |
| Key | RSA-4096 | RSA-3072 | RSA-3072 |
| Validity | 10 years | 5 years | 1 year, capped at the Sub\_CA's expiry |
| BasicConstraints (critical) | CA:TRUE, pathlen 1 | CA:TRUE, pathlen 0 | CA:FALSE |
| KeyUsage (critical) | keyCertSign, cRLSign | keyCertSign, cRLSign | digitalSignature, nonRepudiation |
| Key identifiers | SKI | SKI + AKI | SKI + AKI |
| Serial number | 159-bit random | 159-bit random | 159-bit random |

**Why a subordinate CA.** The Root\_CA key is used only twice: to self-sign and to sign the Sub\_CA. In a real deployment it would then be kept offline. If the Sub\_CA were compromised, it could be revoked and replaced without changing the trust anchor that every user already has. `pathlen 0` on the Sub\_CA stops it from creating further CAs.

**Issuance from a CSR.** At sign-up the Sub\_CA:

1. Checks the CSR signature, which proves the requester holds the matching private key (proof of possession).
2. Checks that the CSR's CN equals the username being registered.
3. Builds the subject itself rather than copying fields from the CSR, so a user can't request extra attributes or CA rights.
4. Signs the certificate and keeps a copy in `data/pki/issued/`.

```python
if not csr.is_signature_valid:
    raise PKIError("CSR signature invalid: requester does not hold the private key")
cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
if not cn or cn[0].value != expected_username:
    raise PKIError("CSR common name does not match the registering username")

cert = (x509.CertificateBuilder()
    .subject_name(_name(expected_username, "Users"))
    .issuer_name(sub_cert.subject)
    .public_key(csr.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now).not_valid_after(not_after)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(_key_usage(digital_signature=True, content_commitment=True), critical=True)
    ...
    .sign(sub_key, hashes.SHA256()))
```

**Chain validation.** `pki.verify_chain` runs before any user public key is trusted, both at login (our own certificate) and on every received message. It checks, in order:

1. Signatures: Root\_CA by itself, Sub\_CA by Root\_CA, user by Sub\_CA (`verify_directly_issued_by` checks the issuer name and the signature).
2. Validity dates of all three certificates.
3. BasicConstraints: both CAs are CAs and the user certificate is not. KeyUsage includes digitalSignature.
4. Identity binding: the certificate's CN equals the expected username.
5. Revocation: the CRL is signed by the Sub\_CA, is not past its nextUpdate date, and does not list this serial number.

**Revocation.** Deleting an account adds the certificate's serial to a CRL signed by the Sub\_CA, valid for 30 days. `ca_admin.py refresh-crl` re-signs it. From then on, all of that user's signatures are rejected.

Terminal output for the two PKI attacks: a certificate for "alice" forged by a rogue CA that even copies the real issuer name, and a revoked certificate.

```text
 6. Attack: mallory builds her OWN CA and forges a cert for 'alice'
    [PKI] signature on Root_CA verified with Root_CA (self-signed) public key
    [PKI] signature on Sub_CA verified with Root_CA public key
    -> untrusted signer certificate: cert[alice]: signature by Sub_CA is INVALID
  PASS  forged certificate from a rogue CA is rejected

 8. Revocation: bob deletes his account -> Sub_CA revokes his cert (CRL)
    [PKI] certificate serial=511ad411c4b453d0279bd31c5d09d3df2fac7f86 added to signed CRL
    -> untrusted signer certificate: cert[bob] has been REVOKED
  PASS  bob's signature rejected after his cert is revoked
```

Root\_CA certificate as printed by `ca_admin.py show`:

```text
  Subject     : CN=CryptoApp Root CA,OU=Root_CA,O=CryptoApp,C=ES
  Issuer      : CN=CryptoApp Root CA,OU=Root_CA,O=CryptoApp,C=ES
  Valid       : 2026-10-26 -> 2036-10-23
  Public key  : RSA-4096
  Sig. alg.   : SHA256 with RSA
  Extension   : basicConstraints  [critical]
  Extension   : keyUsage  [critical]
  Extension   : subjectKeyIdentifier
```

Certificates are signed with RSA PKCS#1 v1.5, the X.509 default that OpenSSL and browsers verify out of the box. Our own message signatures use PSS (section 9).

## 12. Other aspects

### Testing and attack demonstrations

`demo.py` runs the whole scenario in a separate `demo_data/` folder and ends with **23 of 23 checks passed**. Each attack is mounted by editing the files directly, the way an attacker with disk access would.

| Attack | Defence | Result |
| --- | --- | --- |
| Duplicate username, weak password | Input validation, password policy | Rejected |
| Issue a certificate with the wrong CA passphrase | Encrypted Sub\_CA key | Rejected |
| Wrong password, unknown user | Scrypt verifier, generic error, equal timing | Same error for both |
| Decrypt Alice's note with Bob's key | Per-user DEK | `InvalidTag` |
| Copy Alice's ciphertext into Bob's file | AAD binds owner and note id | Detected |
| Flip one bit of a note | GCM tag | Detected |
| Tamper with the wrapped DEK in `users.json` | GCM tag on wrapped keys | Login refused |
| Change a signed message's body | RSA-PSS signature | Invalid signature |
| Redirect a message to another recipient | `to` field is signed | Invalid signature |
| Attach someone else's certificate | CN must equal sender | Rejected |
| Certificate forged by a rogue CA | Chain validation to Root\_CA | Rejected |
| Use a revoked certificate | Signed CRL | Rejected |
| Old password after a password change | New verifier and KEK | Rejected, notes still readable |

### Other engineering choices

- **Atomic writes.** Every JSON file is written to a temporary file and then renamed with `os.replace`, so a crash mid-write cannot leave a half-written key file.
- **Verbose crypto log.** With `CRYPTOAPP_VERBOSE=1` (the default) every operation prints a tagged line such as `[AES-256-GCM]` or `[PKI]`. This makes the design visible during the defense.
- **Hidden password entry.** Passwords and CA passphrases are read with `getpass`, so they are not echoed or kept in shell history.

### Limitations and possible improvements

- **Trust anchor on the same disk.** An attacker who can replace both `root_ca.crt.pem` and the Sub\_CA could create a parallel PKI. In practice the Root\_CA certificate or its fingerprint would ship with the app or sit in the OS trust store.
- **CA keys on the same machine** as the app, protected only by passphrases. A real Sub\_CA is a separate service, and the Root\_CA key stays offline.
- **Messages are not confidential.** Hybrid encryption (section 10) would fix this.
- **No trusted timestamps.** After revocation, all of a user's signatures fail, even those made before. An RFC 3161 timestamp would let older signatures stay valid.
- **No CRL for the Root\_CA**, so the Sub\_CA itself cannot be revoked yet.
- **Memory.** Python cannot reliably wipe keys from RAM. They are released when the session ends but may stay in memory until garbage collection.
- **No username change.** The username is bound into the certificate and the AAD, so renaming would require a new certificate and re-encrypting the notes.

## 13. Conclusions

The project showed us that the hard part of applied cryptography is not calling the primitives but deciding how they fit together: which key protects which, what each ciphertext is bound to, and when a public key may be trusted.

### Learning moments

- **A signature is only as good as the trust in the key.** Verifying a signature with the key inside an attached certificate proves nothing until the chain to Root\_CA is checked. Our rogue-CA test, which copies even the real issuer name, made this concrete.
- **Key separation matters.** Deriving the verifier and the KEK from the same password with different salts, and keeping a random DEK under the KEK, made password changes cheap and kept the stored hash useless as a key.
- **Authenticated encryption needs context.** AES-GCM alone stops tampering but not a valid ciphertext being moved elsewhere. Adding the owner and record id as AAD closed that gap.
- **Bytes are not text.** Signatures and tags work on exact bytes. A canonical JSON encoding and a consistent UTF-8 / Base64 / PEM convention were necessary to make verification reliable.
- **X.509 extensions carry the policy.** BasicConstraints, KeyUsage and pathlen are what stop a user certificate from acting as a CA. The library builds whatever certificate you ask for, so the CA has to enforce these rules itself.
- **Choosing what not to encrypt is part of the design.** Salts, usernames and certificates stay in clear, and being able to justify that is as important as encrypting the rest.

### Main challenges

- **Designing the key hierarchy** so that one password unlocks the DEK and the signing key without ever being stored, while still allowing password changes.
- **Building the PKI with the right extensions** and a correct chain-validation order (signatures, dates, CA flags, identity, revocation), and confirming the result with `openssl verify`.
- **Revocation.** Deciding what happens to old signatures after a certificate is revoked showed us why real systems need trusted timestamps.
- **Testing attacks, not just features.** Writing `demo.py` to tamper with files on disk found cases that normal use never reaches, such as a swapped certificate or a moved ciphertext.
- **Balancing realism and scope.** A real CA would run on separate, offline hardware. We kept everything on one machine with passphrase-protected keys and documented the gap instead.


## Appendix: how to run

Requires Python 3.10 or newer.

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

python demo.py                    # automated scenario + 23 attack/sanity checks
python ca_admin.py init           # once: create Root_CA, Sub_CA and an empty CRL
python app.py                     # interactive app: sign up, log in, notes, messages
python ca_admin.py show           # print the CA certificates
python ca_admin.py list-issued    # issued user certificates and revocation status
python ca_admin.py refresh-crl    # re-sign the CRL (expires after 30 days)
```

Run the app in a real terminal so that `getpass` hides passwords. Delete the `data/` folder to start over.

Verify the PKI independently with OpenSSL:

```bash
P=data/pki
openssl x509 -in $P/sub_ca.crt.pem -text -noout
openssl verify -CAfile $P/root_ca.crt.pem -untrusted $P/sub_ca.crt.pem \
               -crl_check -CRLfile $P/sub_ca.crl.pem $P/issued/*_alice.crt.pem
openssl crl -in $P/sub_ca.crl.pem -text -noout
```
