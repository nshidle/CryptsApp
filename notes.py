"""Private notes, protected with AES-256-GCM under the user's DEK.

On disk each note is just {nonce, ct}. Title, body and timestamp are all
inside the ciphertext. The note id is bound through the AAD, so a ciphertext
cannot be moved to another id or to another user's file without decryption
failing.
"""
import datetime
import json
import secrets

from cryptography.exceptions import InvalidTag

from accounts import Session
from config import NOTES_DIR
from crypto_utils import aad_for, aead_decrypt, aead_encrypt
from storage import load_json, save_json


def _file(username: str):
    return NOTES_DIR / f"{username}.json"


def add_note(session: Session, title: str, body: str) -> str:
    notes = load_json(_file(session.username), {})
    note_id = secrets.token_hex(6)
    payload = json.dumps({
        "title": title,
        "body": body,
        "created": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }).encode("utf-8")
    notes[note_id] = aead_encrypt(session.dek, payload, aad_for(session.username, f"note:{note_id}"))
    save_json(_file(session.username), notes)
    return note_id


def list_notes(session: Session):
    """Yields (note_id, note_dict_or_None, error_or_None)."""
    notes = load_json(_file(session.username), {})
    for note_id, blob in notes.items():
        try:
            pt = aead_decrypt(session.dek, blob, aad_for(session.username, f"note:{note_id}"))
            yield note_id, json.loads(pt), None
        except InvalidTag:
            yield note_id, None, "INTEGRITY CHECK FAILED: note was modified or moved"


def delete_note(session: Session, note_id: str) -> bool:
    notes = load_json(_file(session.username), {})
    if note_id not in notes:
        return False
    del notes[note_id]
    save_json(_file(session.username), notes)
    return True
