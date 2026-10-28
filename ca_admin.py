"""CA operator tool (run separately from the user app).

    python ca_admin.py init          # create Root_CA, Sub_CA and an empty CRL
    python ca_admin.py show          # print the CA certificates
    python ca_admin.py list-issued   # list issued user certificates + status
    python ca_admin.py refresh-crl   # re-sign the CRL with a new nextUpdate

Passphrases are asked interactively, or read from CRYPTOAPP_ROOTCA_PASS /
CRYPTOAPP_SUBCA_PASS (only meant for the automated demo).
"""
import argparse
import os
import sys
from getpass import getpass

from cryptography import x509

import pki
from config import ISSUED_DIR


def ask(env: str, prompt: str, confirm: bool = False) -> str:
    if os.environ.get(env):
        return os.environ[env]
    pw = getpass(prompt)
    if confirm and getpass("  repeat: ") != pw:
        sys.exit("Passphrases do not match")
    if len(pw) < 10:
        sys.exit("CA passphrases must be at least 10 characters")
    return pw


def main():
    p = argparse.ArgumentParser(description="CryptoApp CA administration")
    p.add_argument("command", choices=["init", "show", "list-issued", "refresh-crl"])
    cmd = p.parse_args().command

    if cmd == "init":
        root_pw = ask("CRYPTOAPP_ROOTCA_PASS", "Root_CA passphrase: ", confirm=True)
        sub_pw = ask("CRYPTOAPP_SUBCA_PASS", "Sub_CA passphrase: ", confirm=True)
        pki.init_pki(root_pw, sub_pw)
        print("\nPKI created.\n\nRoot_CA:\n" + pki.describe(pki.load_cert(pki.ROOT_CERT)))
        print("\nSub_CA:\n" + pki.describe(pki.load_cert(pki.SUB_CERT)))
        return

    if not pki.is_initialised():
        sys.exit("PKI not initialised. Run: python ca_admin.py init")

    if cmd == "show":
        print("Root_CA:\n" + pki.describe(pki.load_cert(pki.ROOT_CERT)))
        print("\nSub_CA:\n" + pki.describe(pki.load_cert(pki.SUB_CERT)))
    elif cmd == "list-issued":
        crl = x509.load_pem_x509_crl(pki.CRL_FILE.read_bytes())
        for f in sorted(ISSUED_DIR.glob("*.pem")):
            c = pki.load_cert(f)
            status = "REVOKED" if crl.get_revoked_certificate_by_serial_number(c.serial_number) else "valid"
            print(f"  {c.serial_number:x}  {pki.common_name(c):20} until "
                  f"{c.not_valid_after_utc:%Y-%m-%d}  [{status}]")
    elif cmd == "refresh-crl":
        pki.refresh_crl(ask("CRYPTOAPP_SUBCA_PASS", "Sub_CA passphrase: "))
        print("CRL re-signed.")


if __name__ == "__main__":
    try:
        main()
    except pki.PKIError as e:
        sys.exit(f"Error: {e}")
