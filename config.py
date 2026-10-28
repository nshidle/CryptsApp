"""Paths and global settings.

All persistent state lives under DATA_DIR (override with the CRYPTOAPP_DATA
environment variable, e.g. to run the demo in a throw-away folder).
"""
import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("CRYPTOAPP_DATA") or Path(__file__).parent / "data")

PKI_DIR = DATA_DIR / "pki"
ISSUED_DIR = PKI_DIR / "issued"
USERS_FILE = DATA_DIR / "users.json"
NOTES_DIR = DATA_DIR / "notes"
MESSAGES_FILE = DATA_DIR / "messages.json"

# Print what the crypto layer is doing (handy for report screenshots).
VERBOSE = os.environ.get("CRYPTOAPP_VERBOSE", "1") == "1"
