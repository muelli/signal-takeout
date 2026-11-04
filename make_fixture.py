#!/usr/bin/env -S uv run --script
# SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
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
from pathlib import Path

from sqlcipher3 import dbapi2 as sqlcipher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/fake-signal")
KEY = "a" * 64
ME = "00000000-0000-4000-8000-00000000000f"
ALICE = "11111111-1111-4111-8111-111111111111"
BOB = "22222222-2222-4222-8222-222222222222"
TOBY = "33333333-3333-4333-8333-333333333333"
CAROL = "44444444-4444-4444-8444-444444444444"
DAVE = "55555555-5555-4555-8555-555555555555"


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
          type TEXT, sourceServiceId TEXT, isErased INTEGER, isViewOnce INTEGER,
          readStatus INTEGER, storyId TEXT);
        CREATE TABLE items (id TEXT PRIMARY KEY, json TEXT);
        CREATE TABLE message_attachments (messageId TEXT, editHistoryIndex INTEGER,
          attachmentType TEXT, orderInMessage INTEGER, size INTEGER,
          contentType TEXT, path TEXT, localKey TEXT, fileName TEXT,
          width INTEGER, height INTEGER, caption TEXT, flags INTEGER,
          screenshotPath TEXT, screenshotLocalKey TEXT, screenshotSize INTEGER,
          screenshotContentType TEXT, wasTooBig INTEGER, pending INTEGER,
          error INTEGER, isCorrupted INTEGER, storyTextAttachmentJson TEXT);
        """
    )

    def store(name: str, data: bytes) -> tuple[str, str]:
        blob, key = encrypt_local(data)
        (OUT / "attachments.noindex" / "ab" / name).write_bytes(blob)
        return f"ab/{name}", key

    def attach(mid, kind, order, ctype, fname, data, **extra):
        path = key = None
        size = extra.pop("size", 0)
        if data is not None:
            path, key = store(f"{mid}-{kind}-{order}", data)
            size = len(data)
        row = {"messageId": mid, "editHistoryIndex": -1, "attachmentType": kind,
               "orderInMessage": order, "size": size, "contentType": ctype,
               "path": path, "localKey": key, "fileName": fname, **extra}
        db.execute(f"INSERT INTO message_attachments ({','.join(row)})"
                   f" VALUES ({','.join('?' * len(row))})", list(row.values()))

    db.execute("INSERT INTO items (id, json) VALUES ('uuid_id', ?)",
               (json.dumps({"id": "uuid_id", "value": f"{ME}.1"}),))

    db.execute("INSERT INTO items (id, json) VALUES ('defaultConversationColor', ?)",
               (json.dumps({"id": "defaultConversationColor", "value": {"color": "teal"}}),))
    db.execute("INSERT INTO items (id, json) VALUES ('customColors', ?)",
               (json.dumps({"id": "customColors", "value": {"version": 1, "colors": {
                   "c1": {"start": {"hue": 120, "saturation": 80}}}}}),))

    convos = [
        ("conv-alice", {"type": "private", "serviceId": ALICE,
                        "profileName": "Alice", "profileFamilyName": "Anderson",
                        "profileAvatar": encrypted_avatar("avatar-alice"),
                        "conversationColor": "crimson"}),
        ("conv-bob", {"type": "private", "serviceId": BOB, "systemGivenName": "Bob",
                      "avatar": {"path": "ab/avatar-bob"},
                      "conversationColor": "custom", "customColorId": "c1"}),
        ("conv-group", {"type": "group", "name": "Weekend Plans", "conversationColor": "ember"}),
        ("conv-toby", {"type": "private", "serviceId": TOBY, "systemGivenName": "Toby",
                       "profileName": "Tobias", "profileFamilyName": "Weber",
                       "avatar": {"path": "ab/gone", "localKey": "AAAA"},
                       "profileAvatar": encrypted_avatar("avatar-toby")}),
        ("conv-empty", {"type": "private", "e164": "+15550000000"}),
        ("conv-carol", {"type": "private", "serviceId": CAROL, "systemGivenName": "Carol"}),
        ("conv-dave", {"type": "private", "serviceId": DAVE, "systemGivenName": "Dave",
                       "conversationColor": "custom",
                       "customColor": {"start": {"hue": 300, "saturation": 90, "lightness": 0.5},
                                       "end": {"hue": 240, "saturation": 70}, "deg": 90}}),
    ]
    for cid, data in convos:
        db.execute("INSERT INTO conversations (id, json, type) VALUES (?,?,?)",
                   (cid, json.dumps(data), data["type"]))

    now = 1790769600000  # 2026-09-30 12:00 UTC, fixed so tests do not drift
    day = 86400_000
    t0 = now - 5 * day
    long_text = "Long message start. " + "lorem ipsum dolor sit amet " * 200 + "needle-in-the-long-text"
    rows = [
        # id, conv, type, sourceServiceId, sent_at, body, extra json
        ("m1", "conv-alice", "incoming", ALICE, now - 2 * day, "Hey, are we still on for Friday?",
         {"reactions": [{"emoji": "\U0001F44D", "fromId": "conv-bob", "timestamp": now},
                        {"emoji": "\U0001F44D", "fromId": "conv-toby", "timestamp": now},
                        {"emoji": "\u2764\ufe0f", "fromId": "conv-unknown", "timestamp": now}]}),
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
        ("m8b", "conv-group", "incoming", ALICE, now - 3000_000, "Count me in", {}),
        # View-once media: one unopened, then as Signal leaves it once viewed, expired or sent.
        ("v1", "conv-bob", "incoming", BOB, now - 3_100_000, None, {"isViewOnce": True}),
        ("v2", "conv-bob", "incoming", BOB, now - 3_000_000, None,
         {"isViewOnce": True, "isErased": True, "readStatus": 2,
          "reactions": [{"emoji": "\U0001F602", "fromId": "conv-bob", "timestamp": now}]}),
        ("v3", "conv-bob", "incoming", BOB, now - 2_900_000, None,
         {"isViewOnce": True, "isErased": True, "readStatus": 0}),
        ("v4", "conv-bob", "outgoing", None, now - 2_800_000, None,
         {"isViewOnce": True, "isErased": True}),
        ("v5", "conv-bob", "incoming", BOB, now - 2_700_000, None,
         {"isViewOnce": True, "isErased": True, "isTapToViewInvalid": True}),
        # Too new for this Signal: erased on arrival, only the needed version is kept.
        ("u1", "conv-bob", "incoming", BOB, now - 2_600_000, None,
         {"isErased": True, "requiredProtocolVersion": 8}),
        ("u2", "conv-bob", "incoming", BOB, now - 2_500_000, None, {"isErased": True}),
        # Alice's photo story, still here because Signal was closed when it expired.
        ("s1", "conv-alice", "story", ALICE, now - 40 * 3600_000, None, {}),
        ("s1r", "conv-alice", "outgoing", None, now - 39 * 3600_000, "Gorgeous!",
         {"storyId": "s1", "storyReplyContext": {"authorAci": ALICE}}),
        ("s1e", "conv-alice", "outgoing", None, now - 39 * 3600_000 + 60_000, None,
         {"storyId": "s1", "storyReplyContext": {"authorAci": ALICE},
          "storyReaction": {"emoji": "\U0001F60D", "targetAuthorAci": ALICE,
                            "targetTimestamp": now - 40 * 3600_000}}),
        # A reply to one of our stories that has long been deleted.
        ("s0r", "conv-alice", "incoming", ALICE, now - 38 * 3600_000, "Love your story!",
         {"storyId": "s-gone", "storyReplyContext": {"authorAci": ME}}),
        # Bob's text story in the group; its replies belong to the story, not the chat.
        ("gs", "conv-group", "story", BOB, now - 1_800_000, None, {}),
        ("gsr1", "conv-group", "incoming", ALICE, now - 1_750_000, "Haha, so true",
         {"storyId": "gs", "storyReplyContext": {"authorAci": BOB}}),
        ("gsr2", "conv-group", "incoming", TOBY, now - 1_700_000, None,
         {"storyId": "gs", "storyReplyContext": {"authorAci": BOB},
          "storyReaction": {"emoji": "\U0001F525", "targetAuthorAci": BOB,
                            "targetTimestamp": now - 1_800_000}}),
        ("gsr3", "conv-group", "outgoing", None, now - 1_650_000, "Me too",
         {"storyId": "gs", "storyReplyContext": {"authorAci": BOB}}),
        ("m9", "conv-bob", "incoming", BOB, now - 600_000, "Ping", {}),
        # Bob changed his vote; Alice's second vote was never sent, so it does not count.
        ("m8p", "conv-group", "incoming", ALICE, now - 2500_000, None,
         {"poll": {"question": "Saturday or Sunday?", "options": ["Saturday", "Sunday"],
                   "allowMultiple": False, "terminatedAt": now - 1500_000, "votes": [
                       {"fromConversationId": "conv-alice", "optionIndexes": [0],
                        "voteCount": 1, "timestamp": now - 2400_000},
                       {"fromConversationId": "conv-bob", "optionIndexes": [0],
                        "voteCount": 1, "timestamp": now - 2300_000},
                       {"fromConversationId": "conv-bob", "optionIndexes": [1],
                        "voteCount": 2, "timestamp": now - 2200_000},
                       {"fromConversationId": "conv-toby", "optionIndexes": [1],
                        "voteCount": 1, "timestamp": now - 2100_000},
                       {"fromConversationId": "conv-alice", "optionIndexes": [1],
                        "voteCount": 2, "timestamp": now - 2000_000,
                        "sendStateByConversationId": {"conv-group": {"status": "Pending"}}}]}}),
        ("m8q", "conv-group", "poll-terminate", ALICE, now - 1500_000, None,
         {"pollTerminateNotification": {"question": "Saturday or Sunday?",
                                        "pollTimestamp": now - 2500_000}}),
        ("m11", "conv-group", "incoming", BOB, now - 1200_000, "Treffen im Caf\u00e9 bei Zo\u00eb?", {}),
        ("m10", "conv-bob", "incoming", BOB, now - 300_000, "Did you see what Alice said about Friday?", {}),
        ("m30", "conv-alice", "outgoing", None, now - 1500_000, "Friday at 8 works",
         {"editHistory": [{"body": "Friday at 8 works", "timestamp": now - 1500_000},
                          {"body": "Friday at 7 works", "timestamp": now - 1560_000},
                          {"body": "Frday at 7 works", "timestamp": now - 1600_000}]}),
        ("m12", "conv-toby", "incoming", TOBY, now - 900_000, "Lunch tomorrow?", {}),
        # Carol's conversation exercises every attachment kind; added in time order.
        ("m13", "conv-carol", "incoming", CAROL, t0, "Look at this", {}),
        ("m14", "conv-carol", "incoming", CAROL, t0 + 60000, None, {}),
        ("m15", "conv-carol", "outgoing", None, t0 + 120000, None, {}),
        ("m16", "conv-carol", "incoming", CAROL, t0 + 180000, None, {}),
        ("m17", "conv-carol", "incoming", CAROL, t0 + 240000, None, {}),
        ("m18", "conv-carol", "incoming", CAROL, t0 + 300000, long_text[:2048], {}),
        ("m19", "conv-carol", "outgoing", None, t0 + 360000, "Same map again",
         {"quote": {"authorAci": ME, "text": "",
                    "attachments": [{"contentType": "image/png", "fileName": "map.png"}]}}),
        ("m20", "conv-carol", "incoming", CAROL, t0 + 420000, "https://example.com/a",
         {"preview": [{"url": "https://example.com/a", "title": "Example Domain",
                       "description": "Illustrative examples"}]}),
        ("m21", "conv-carol", "incoming", CAROL, t0 + 480000, None,
         {"sticker": {"packId": "aa", "stickerId": 1, "emoji": "\U0001F389"}}),
        ("m22", "conv-carol", "incoming", CAROL, t0 + 540000, None,
         {"contact": [{"name": {"givenName": "Dana", "familyName": "Diaz"},
                       "number": [{"value": "+15551234567", "type": 1}]}]}),
    ]
    # Dave spans about four months, so his page has several month chunks.
    for i in range(60):
        out = i % 3 == 2
        body = f"Dave message {i}" + (" archive-needle" if i == 1 else "")
        rows.append((f"d{i}", "conv-dave", "outgoing" if out else "incoming",
                     None if out else DAVE, now - (150 - 2 * i) * day + i * 1000, body, {}))
    for mid, cid, mtype, src, sent, body, extra in rows:
        # Like Signal's saveMessage, these go to columns and not into the json.
        columns = [extra.pop(c, None) for c in ("isErased", "isViewOnce", "readStatus", "storyId")]
        payload = {"type": mtype, "sent_at": sent, "conversationId": cid, **extra}
        if body is not None:
            payload["body"] = body
        db.execute(
            "INSERT INTO messages (id, json, body, conversationId, sent_at, received_at, type,"
            " sourceServiceId, isErased, isViewOnce, readStatus, storyId)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (mid, json.dumps(payload), body, cid, sent, sent, mtype, src, *columns),
        )

    db.execute(
        "INSERT INTO message_attachments (messageId, editHistoryIndex, attachmentType,"
        " orderInMessage, size, contentType, path, localKey, fileName, width, height)"
        " VALUES ('m3', -1, 'attachment', 0, ?, 'image/png', 'ab/cdef0123', ?, 'map.png', 1, 1)",
        (len(png), local_key),
    )

    poster, poster_key = store("m13-poster", png)
    attach("m13", "attachment", 0, "video/mp4", "beach.mp4", secrets.token_bytes(2_600_000),
           caption="Dog at the beach", screenshotPath=poster, screenshotLocalKey=poster_key,
           screenshotSize=len(png), screenshotContentType="image/png", width=640, height=360)
    attach("m14", "attachment", 0, "application/pdf", "Quarterly Report \u00dc.pdf",
           b"%PDF-1.4\n" + secrets.token_bytes(1000))
    attach("m15", "attachment", 0, "audio/aac", None, secrets.token_bytes(5000), flags=1)
    attach("m16", "attachment", 0, "video/mp4", None, secrets.token_bytes(3000), flags=8)
    attach("m17", "attachment", 0, "application/zip", "huge.zip", None,
           size=900_000_000, wasTooBig=1)
    attach("m18", "long-message", 0, "text/x-signal-plain", None, long_text.encode())
    attach("m19", "quote", 0, "image/png", "map.png", png)
    attach("m20", "preview", 0, "image/png", None, png)
    attach("m21", "sticker", 0, "image/png", None, png)
    attach("m22", "contact", 0, "image/png", None, png)
    attach("v1", "attachment", 0, "image/jpeg", None, png, width=1, height=1)
    attach("s1", "attachment", 0, "image/png", None, png, width=1, height=1,
           caption="Sunset at the lake")
    attach("gs", "attachment", 0, "text/x-signal-story", None, None,
           storyTextAttachmentJson=json.dumps({
               "text": "Mondays.", "textStyle": 3, "textForegroundColor": 0xFFFFFFFF,
               "gradient": {"angle": 180, "colors": [0xFF5B6BEF, 0xFFEE5B8E],
                            "positions": [0, 1]}}))

    db.commit()
    db.close()
    print(f"Fixture at {OUT} (key {KEY[:8]}..., {len(rows)} messages)")


if __name__ == "__main__":
    main()
