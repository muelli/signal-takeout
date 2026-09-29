#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["sqlcipher3-binary", "cryptography"]
# ///
"""Build a synthetic Signal-shaped data dir to exercise signal_takeout.py.

Mirrors the parts of Signal Desktop's schema the exporter touches: an
SQLCipher db keyed in raw mode, conversations/messages/message_attachments,
and an attachment encrypted the way Signal encrypts local files.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sys
import time
from pathlib import Path

from sqlcipher3 import dbapi2 as sqlcipher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/fake-signal")
KEY = "a" * 64
ME = "00000000-0000-4000-8000-00000000000f"
ALICE = "11111111-1111-4111-8111-111111111111"
BOB = "22222222-2222-4222-8222-222222222222"
TOBY = "33333333-3333-4333-8333-333333333333"


def encrypt_local(plaintext: bytes) -> tuple[bytes, str]:
    """IV || AES-256-CBC(PKCS7) || HMAC-SHA256, keyed by a 64-byte localKey."""
    keys = secrets.token_bytes(64)
    aes_key, mac_key = keys[:32], keys[32:]
    iv = secrets.token_bytes(16)
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    body = iv + enc.update(padded) + enc.finalize()
    return body + hmac.new(mac_key, body, hashlib.sha256).digest(), base64.b64encode(keys).decode()


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "sql").mkdir(parents=True)
    (OUT / "attachments.noindex" / "ab").mkdir(parents=True)

    (OUT / "config.json").write_text(json.dumps({"key": KEY}))

    # A tiny valid PNG, encrypted the way Signal stores local attachments.
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
    )
    blob, local_key = encrypt_local(png)
    (OUT / "attachments.noindex" / "ab" / "cdef0123").write_bytes(blob)

    def encrypted_avatar(name: str) -> dict:
        blob, key = encrypt_local(png)
        (OUT / "attachments.noindex" / "ab" / name).write_bytes(blob)
        return {"path": f"ab/{name}", "localKey": key, "size": len(png),
                "version": 2, "contentType": "image/png"}

    (OUT / "attachments.noindex" / "ab" / "avatar-bob").write_bytes(png)

    db = sqlcipher.connect(str(OUT / "sql" / "db.sqlite"))
    db.execute(f"PRAGMA key = \"x'{KEY}'\"")
    db.executescript(
        """
        CREATE TABLE conversations (id TEXT PRIMARY KEY, json TEXT,
          active_at INTEGER, type TEXT, members TEXT, name TEXT, profileName TEXT);
        CREATE TABLE messages (id TEXT PRIMARY KEY, json TEXT, body TEXT,
          conversationId TEXT, sent_at INTEGER, received_at INTEGER,
          type TEXT, sourceServiceId TEXT, isErased INTEGER);
        CREATE TABLE items (id TEXT PRIMARY KEY, json TEXT);
        CREATE TABLE message_attachments (messageId TEXT, editHistoryIndex INTEGER,
          attachmentType TEXT, orderInMessage INTEGER, size INTEGER,
          contentType TEXT, path TEXT, localKey TEXT, fileName TEXT,
          width INTEGER, height INTEGER);
        """
    )

    db.execute("INSERT INTO items (id, json) VALUES ('uuid_id', ?)",
               (json.dumps({"id": "uuid_id", "value": f"{ME}.1"}),))

    convos = [
        ("conv-alice", {"type": "private", "serviceId": ALICE,
                        "profileName": "Alice", "profileFamilyName": "Anderson",
                        "profileAvatar": encrypted_avatar("avatar-alice")}),
        ("conv-bob", {"type": "private", "serviceId": BOB, "systemGivenName": "Bob",
                      "avatar": {"path": "ab/avatar-bob"}}),
        ("conv-group", {"type": "group", "name": "Weekend Plans"}),
        ("conv-toby", {"type": "private", "serviceId": TOBY, "systemGivenName": "Toby",
                       "profileName": "Tobias", "profileFamilyName": "Weber",
                       "avatar": {"path": "ab/gone", "localKey": "AAAA"},
                       "profileAvatar": encrypted_avatar("avatar-toby")}),
        ("conv-empty", {"type": "private", "e164": "+15550000000"}),
    ]
    for cid, data in convos:
        db.execute("INSERT INTO conversations (id, json, type) VALUES (?,?,?)",
                   (cid, json.dumps(data), data["type"]))

    now = int(time.time() * 1000)
    day = 86400_000
    rows = [
        # id, conv, type, sourceServiceId, sent_at, body, extra json
        ("m1", "conv-alice", "incoming", ALICE, now - 2 * day, "Hey, are we still on for Friday?", {}),
        ("m2", "conv-alice", "outgoing", None, now - 2 * day + 60000, "Yes! Looking forward to it.",
         {"reactions": [{"emoji": "👍", "fromId": ALICE, "timestamp": now}]}),
        ("m3", "conv-alice", "incoming", ALICE, now - day, "Here's the map",
         {}),  # carries the attachment
        ("m4", "conv-alice", "outgoing", None, now - day + 5000, "This message was removed",
         {"deletedForEveryone": True}),
        ("m5", "conv-alice", "incoming", ALICE, now - 3600_000, "Quoting you",
         {"quote": {"authorAci": ME, "text": "Yes! Looking forward to it."}}),
        ("m6", "conv-alice", "incoming", ALICE, now - 1800_000, None,
         {"expirationTimerUpdate": {"expireTimer": 300}}),
        ("m7", "conv-group", "incoming", BOB, now - 7200_000,
         "￼ what do you think?",
         {"bodyRanges": [{"start": 0, "length": 1, "mentionAci": ALICE}]}),
        ("m8", "conv-group", "outgoing", None, now - 3600_000, "Sounds good to me", {}),
        ("m9", "conv-bob", "incoming", BOB, now - 600_000, "Ping", {}),
        ("m11", "conv-group", "incoming", BOB, now - 1200_000, "Treffen im Caf\u00e9 bei Zo\u00eb?", {}),
        ("m10", "conv-bob", "incoming", BOB, now - 300_000, "Did you see what Alice said about Friday?", {}),
        ("m12", "conv-toby", "incoming", TOBY, now - 900_000, "Lunch tomorrow?", {}),
    ]
    for mid, cid, mtype, src, sent, body, extra in rows:
        payload = {"type": mtype, "sent_at": sent, "conversationId": cid, **extra}
        if body is not None:
            payload["body"] = body
        db.execute(
            "INSERT INTO messages (id, json, body, conversationId, sent_at,"
            " received_at, type, sourceServiceId, isErased) VALUES (?,?,?,?,?,?,?,?,0)",
            (mid, json.dumps(payload), body, cid, sent, sent, mtype, src),
        )

    db.execute(
        "INSERT INTO message_attachments (messageId, editHistoryIndex, attachmentType,"
        " orderInMessage, size, contentType, path, localKey, fileName, width, height)"
        " VALUES ('m3', -1, 'attachment', 0, ?, 'image/png', 'ab/cdef0123', ?, 'map.png', 1, 1)",
        (len(png), local_key),
    )

    db.commit()
    db.close()
    print(f"Fixture at {OUT} (key {KEY[:8]}..., {len(rows)} messages)")


if __name__ == "__main__":
    main()
