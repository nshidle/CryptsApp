"""Mini-PKI: a two-level hierarchy built with X.509 v3 certificates.

    Root_CA  (self-signed, RSA-4096, 10 y, BasicConstraints CA:TRUE pathlen:1)
       |
       +-- Sub_CA  (signed by Root_CA, RSA-3072, 5 y, CA:TRUE pathlen:0)
              |
              +-- user certs (signed by Sub_CA, RSA-3072, 1 y, CA:FALSE,
                              KeyUsage: digitalSignature + nonRepudiation)

* Root_CA only signs the Sub_CA. In a real deployment its key would be kept
  offline; day-to-day issuance is done by the Sub_CA, so a Sub_CA compromise
  can be contained by revoking it without replacing the trust anchor.
* Users prove possession of their private key by sending a signed CSR.
* Revocation: Sub_CA publishes a signed CRL that is checked on every
  verification.
* CA private keys are stored as passphrase-encrypted PKCS#8 (PBES2), the
  standard format OpenSSL also reads.
"""
import datetime
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from config import ISSUED_DIR, PKI_DIR
from crypto_utils import log

ROOT_CERT = PKI_DIR / "root_ca.crt.pem"
ROOT_KEY = PKI_DIR / "root_ca.key.pem"
SUB_CERT = PKI_DIR / "sub_ca.crt.pem"
SUB_KEY = PKI_DIR / "sub_ca.key.pem"
CRL_FILE = PKI_DIR / "sub_ca.crl.pem"

ROOT_DAYS, SUB_DAYS, USER_DAYS, CRL_DAYS = 3650, 1825, 365, 30


class PKIError(Exception):
    pass


# --------------------------------------------------------------------- helpers
def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _name(cn: str, ou: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoApp"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _key_usage(**flags) -> x509.KeyUsage:
    base = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False)
    base.update(flags)
    return x509.KeyUsage(**base)


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


def load_cert(path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def cert_from_pem(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())


def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def common_name(cert: x509.Certificate) -> str:
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()


def is_initialised() -> bool:
    return ROOT_CERT.exists() and SUB_CERT.exists()


# --------------------------------------------------------------- CA set-up
def init_pki(root_pass: str, sub_pass: str) -> None:
    if is_initialised():
        raise PKIError("PKI already initialised (delete data/pki to start over)")
    PKI_DIR.mkdir(parents=True, exist_ok=True)
    ISSUED_DIR.mkdir(parents=True, exist_ok=True)
    now = _now()

    # ---- Root CA (self-signed trust anchor)
    log("PKI", "generating Root_CA RSA-4096 key pair ...")
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    root_name = _name("CryptoApp Root CA", "Root_CA")
    root_ski = x509.SubjectKeyIdentifier.from_public_key(root_key.public_key())
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name).issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=ROOT_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_key_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(root_ski, critical=False)
        .sign(root_key, hashes.SHA256())
    )

    # ---- Subordinate CA (signed by Root)
    log("PKI", "generating Sub_CA RSA-3072 key pair ...")
    sub_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    sub_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("CryptoApp Issuing CA", "Sub_CA"))
        .issuer_name(root_cert.subject)
        .public_key(sub_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=SUB_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(sub_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    ROOT_CERT.write_text(cert_to_pem(root_cert))
    SUB_CERT.write_text(cert_to_pem(sub_cert))
    _save_key(root_key, ROOT_KEY, root_pass)
    _save_key(sub_key, SUB_KEY, sub_pass)
    _write_crl(sub_key, sub_cert, [])
    log("PKI", f"Root_CA fingerprint SHA-256 = {fingerprint(root_cert)}")


# ------------------------------------------------------------ issuance (Sub CA)
def issue_user_cert(csr: x509.CertificateSigningRequest, expected_username: str,
                    sub_pass: str) -> x509.Certificate:
    """Sub_CA validates the CSR and issues an end-entity certificate."""
    if not csr.is_signature_valid:
        raise PKIError("CSR signature invalid: requester does not hold the private key")
    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn or cn[0].value != expected_username:
        raise PKIError("CSR common name does not match the registering username")
    log("PKI", f"CSR for '{expected_username}' verified (proof of possession OK)")

    sub_cert = load_cert(SUB_CERT)
    sub_key = _load_key(SUB_KEY, sub_pass)
    now = _now()
    not_after = min(now + datetime.timedelta(days=USER_DAYS), sub_cert.not_valid_after_utc)
    sub_ski = sub_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value

    cert = (
        x509.CertificateBuilder()
        # The CA decides the subject: it does not blindly copy every CSR field.
        .subject_name(_name(expected_username, "Users"))
        .issuer_name(sub_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(digital_signature=True, content_commitment=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(sub_ski), critical=False)
        .sign(sub_key, hashes.SHA256())
    )
    ISSUED_DIR.mkdir(parents=True, exist_ok=True)
    (ISSUED_DIR / f"{cert.serial_number:x}_{expected_username}.crt.pem").write_text(cert_to_pem(cert))
    log("PKI", f"Sub_CA issued cert for '{expected_username}', serial={cert.serial_number:x}")
    return cert


# ------------------------------------------------------------------ revocation
def _write_crl(sub_key, sub_cert, entries) -> None:
    now = _now()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(sub_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=CRL_DAYS))
    )
    for serial, when in entries:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when).build())
    crl = builder.sign(sub_key, hashes.SHA256())
    CRL_FILE.write_bytes(crl.public_bytes(serialization.Encoding.PEM))


def _current_entries():
    crl = x509.load_pem_x509_crl(CRL_FILE.read_bytes())
    return [(r.serial_number, r.revocation_date_utc) for r in crl]


def revoke(cert: x509.Certificate, sub_pass: str) -> None:
    sub_key = _load_key(SUB_KEY, sub_pass)
    entries = _current_entries()
    if cert.serial_number not in {s for s, _ in entries}:
        entries.append((cert.serial_number, _now()))
    _write_crl(sub_key, load_cert(SUB_CERT), entries)
    log("PKI", f"certificate serial={cert.serial_number:x} added to signed CRL")


def refresh_crl(sub_pass: str) -> None:
    """Re-sign the CRL with a new nextUpdate (CA operator task)."""
    _write_crl(_load_key(SUB_KEY, sub_pass), load_cert(SUB_CERT), _current_entries())


# ---------------------------------------------------------------- verification
def _check_validity(cert, label, now):
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise PKIError(f"{label} certificate is expired or not yet valid")


def _check_issued_by(child, parent, child_label, parent_label):
    try:
        child.verify_directly_issued_by(parent)  # issuer name + signature check
    except ValueError as e:
        raise PKIError(f"{child_label} was not issued by {parent_label}: {e}")
    except InvalidSignature:
        raise PKIError(f"{child_label}: signature by {parent_label} is INVALID")
    log("PKI", f"signature on {child_label} verified with {parent_label} public key")


def _basic_constraints(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return None


def verify_chain(cert: x509.Certificate, expected_username: str | None = None) -> None:
    """Validate user cert -> Sub_CA -> Root_CA (trust anchor). Raises PKIError."""
    root, sub = load_cert(ROOT_CERT), load_cert(SUB_CERT)
    now = _now()
    label = f"cert[{common_name(cert)}]"

    # 1. signatures along the chain
    _check_issued_by(root, root, "Root_CA", "Root_CA (self-signed)")
    _check_issued_by(sub, root, "Sub_CA", "Root_CA")
    _check_issued_by(cert, sub, label, "Sub_CA")

    # 2. validity periods
    for c, lbl in ((root, "Root_CA"), (sub, "Sub_CA"), (cert, label)):
        _check_validity(c, lbl, now)

    # 3. CA constraints: only CAs may sign certificates; the leaf must not be a CA
    for c, lbl in ((root, "Root_CA"), (sub, "Sub_CA")):
        bc = _basic_constraints(c)
        if bc is None or not bc.ca:
            raise PKIError(f"{lbl} is not marked as a CA")
    leaf_bc = _basic_constraints(cert)
    if leaf_bc is not None and leaf_bc.ca:
        raise PKIError("end-entity certificate must not be a CA")
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if not ku.digital_signature:
        raise PKIError("certificate is not allowed for digital signatures")

    # 4. identity binding
    if expected_username is not None and common_name(cert) != expected_username:
        raise PKIError(f"certificate belongs to '{common_name(cert)}', not '{expected_username}'")

    # 5. revocation status (CRL signed by Sub_CA)
    crl = x509.load_pem_x509_crl(CRL_FILE.read_bytes())
    if crl.issuer != sub.subject or not crl.is_signature_valid(sub.public_key()):
        raise PKIError("CRL signature invalid")
    if crl.next_update_utc is not None and crl.next_update_utc < now:
        raise PKIError("CRL is out of date: CA operator must run `python ca_admin.py refresh-crl`")
    if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
        raise PKIError(f"{label} has been REVOKED")
    log("PKI", f"{label}: chain valid, dates valid, not revoked -> TRUSTED")


# ------------------------------------------------------------------- display
def describe(cert: x509.Certificate) -> str:
    pub = cert.public_key()
    lines = [
        f"  Subject     : {cert.subject.rfc4514_string()}",
        f"  Issuer      : {cert.issuer.rfc4514_string()}",
        f"  Serial      : {cert.serial_number:x}",
        f"  Valid       : {cert.not_valid_before_utc:%Y-%m-%d} -> {cert.not_valid_after_utc:%Y-%m-%d}",
        f"  Public key  : RSA-{pub.key_size}",
        f"  Sig. alg.   : {cert.signature_hash_algorithm.name.upper()} with RSA",
        f"  SHA-256 FP  : {fingerprint(cert)}",
    ]
    for ext in cert.extensions:
        crit = "  [critical]" if ext.critical else ""
        lines.append(f"  Extension   : {ext.oid._name}{crit}")
    return "\n".join(lines)
