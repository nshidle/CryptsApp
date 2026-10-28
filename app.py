"""CryptoApp: secure notes and signed messages (interactive CLI).

    python ca_admin.py init   # once, to create the PKI
    python app.py
"""
import os
import sys
from getpass import getpass

import accounts
import messages
import notes
import pki

BANNER = "=" * 60


def ca_passphrase() -> str:
    """Issuing/revoking certificates needs the Sub_CA operator's passphrase."""
    return os.environ.get("CRYPTOAPP_SUBCA_PASS") or getpass("  Sub_CA operator passphrase: ")


def print_msg(m: dict) -> None:
    ok, reason = messages.verify(m)
    mark = "✔ TRUSTED" if ok else "✘ REJECTED"
    print(f"\n  [{m['timestamp']}] {m['from']} -> {m['to']}  (id {m['id']})")
    print(f"  {m['body']}")
    print(f"  {mark}: {reason}")


# ------------------------------------------------------------- logged-out menu
def signup():
    username = input("  Choose username: ").strip()
    pw = getpass("  Choose password: ")
    if getpass("  Repeat password: ") != pw:
        print("  Passwords do not match."); return
    try:
        accounts.register(username, pw, ca_passphrase())
        print(f"\n  Account '{username}' created and certificate issued by Sub_CA.")
    except (ValueError, pki.PKIError) as e:
        print(f"  Error: {e}")


def login():
    username = input("  Username: ").strip()
    pw = getpass("  Password: ")
    try:
        session = accounts.login(username, pw)
    except accounts.AuthError as e:
        print(f"  {e}"); return
    print(f"\n  Welcome, {username}!")
    user_menu(session)


# -------------------------------------------------------------- logged-in menu
def user_menu(s: accounts.Session):
    while True:
        print(f"\n{BANNER}\n  Logged in as {s.username}\n{BANNER}")
        print("  1) New private note        2) List my notes      3) Delete a note")
        print("  4) Send signed message     5) Inbox (verify)     6) Sent messages")
        print("  7) Show my certificate     8) Change password    9) Delete account")
        print("  0) Log out")
        choice = input("  > ").strip()
        try:
            if choice == "1":
                title = input("  Title: ")
                body = input("  Text : ")
                print(f"  Note saved (id {notes.add_note(s, title, body)}), encrypted at rest.")
            elif choice == "2":
                found = False
                for nid, n, err in notes.list_notes(s):
                    found = True
                    print(f"\n  [{nid}] " + (f"{n['title']}  ({n['created']})\n    {n['body']}" if n else err))
                if not found:
                    print("  No notes yet.")
            elif choice == "3":
                print("  Deleted." if notes.delete_note(s, input("  Note id: ").strip()) else "  Not found.")
            elif choice == "4":
                to = input("  To (username): ").strip()
                body = input("  Message: ")
                m = messages.send(s, to, body)
                print(f"  Message {m['id']} signed and sent.")
            elif choice == "5":
                box = messages.inbox(s.username)
                print("  Inbox empty." if not box else "")
                for m in box:
                    print_msg(m)
            elif choice == "6":
                for m in messages.sent(s.username):
                    print_msg(m)
            elif choice == "7":
                print(pki.describe(s.cert))
            elif choice == "8":
                old = getpass("  Current password: ")
                new = getpass("  New password: ")
                if getpass("  Repeat new password: ") != new:
                    print("  Passwords do not match."); continue
                accounts.change_password(s, old, new)
                print("  Password changed. Your notes did not need re-encryption.")
            elif choice == "9":
                if input("  Type DELETE to confirm: ") != "DELETE":
                    continue
                accounts.delete_account(s, getpass("  Password: "), ca_passphrase())
                print("  Account deleted and certificate revoked.")
                return
            elif choice == "0":
                return  # session (DEK, private key) goes out of scope
        except (ValueError, accounts.AuthError, pki.PKIError) as e:
            print(f"  Error: {e}")


def main():
    if not pki.is_initialised():
        sys.exit("PKI not initialised. Ask the CA operator to run: python ca_admin.py init")
    while True:
        print(f"\n{BANNER}\n  CryptoApp — secure notes & signed messages\n{BANNER}")
        print("  1) Sign up   2) Log in   0) Exit")
        choice = input("  > ").strip()
        if choice == "1":
            signup()
        elif choice == "2":
            login()
        elif choice == "0":
            break


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nBye.")
