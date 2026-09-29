#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["sqlcipher3-binary", "cryptography"]
# ///
"""Export a local Signal Desktop database to static HTML.

Reads ~/.var/app/org.signal.Signal/config/Signal (or the native equivalent),
decrypts db.sqlite with the key Signal stores in config.json, and writes one
HTML file per conversation plus an index.

This only ever reads your own local Signal installation. Nothing is uploaded.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import html
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("signal_takeout")

try:
    from sqlcipher3 import dbapi2 as sqlcipher
except ImportError:  # pragma: no cover - dependency check
    sys.exit(
        "Missing sqlcipher3. Run with uv:\n"
        "  uv run signal_takeout.py\n"
        "or install with:\n"
        "  python3 -m venv .venv && .venv/bin/pip install sqlcipher3-binary cryptography"
    )

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover - dependency check
    sys.exit("Missing cryptography. Run with uv (uv run signal_takeout.py) or pip install cryptography")


# --------------------------------------------------------------------------
# Locating the Signal data directory
# --------------------------------------------------------------------------

CANDIDATE_DIRS = [
    "~/.var/app/org.signal.Signal/config/Signal",  # Flathub / this repo's build
    "~/.config/Signal",  # native Linux
    "~/Library/Application Support/Signal",  # macOS
    "~/AppData/Roaming/Signal",  # Windows
]


def find_data_dir(explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit).expanduser()
        if not (path / "config.json").is_file():
            sys.exit(f"No config.json under {path}")
        return path
    for candidate in CANDIDATE_DIRS:
        path = Path(candidate).expanduser()
        if (path / "config.json").is_file():
            return path
    sys.exit(
        "Could not find a Signal data directory. Pass --data-dir explicitly.\n"
        "Looked in:\n  " + "\n  ".join(CANDIDATE_DIRS)
    )


# --------------------------------------------------------------------------
# Recovering the SQLCipher key
#
# Signal stores it in config.json as either:
#   "key"          - raw hex, used when safeStorage is unavailable. This is the
#                    case for SIGNAL_PASSWORD_STORE=basic, the Flatpak default.
#   "encryptedKey" - hex of a Chromium os_crypt blob (Electron safeStorage).
# --------------------------------------------------------------------------


def oscrypt_decrypt(blob: bytes, password: bytes) -> str:
    """Decrypt a Chromium os_crypt v10/v11 blob (AES-128-CBC, fixed salt/IV)."""
    body = blob[3:] if blob[:3] in (b"v10", b"v11") else blob
    key = hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", 1, dklen=16)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).decryptor()
    padded = decryptor.update(body) + decryptor.finalize()
    if not padded:
        raise ValueError("empty plaintext")
    pad = padded[-1]
    if not 1 <= pad <= 16:
        raise ValueError("bad PKCS7 padding - wrong password?")
    return padded[:-pad].decode("utf-8")


def keyring_password(service: str, account: str) -> bytes | None:
    """Best-effort lookup of the safeStorage password from the OS keyring."""
    if sys.platform == "darwin":
        try:
            out = subprocess.run(
                ["security", "find-generic-password", "-w", "-s", service, "-a", account],
                capture_output=True, text=True, check=True,
            )
            return out.stdout.strip().encode()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None
    if shutil.which("secret-tool"):
        for attrs in (
            ["application", "Signal"],
            ["application", "chromium"],
        ):
            try:
                out = subprocess.run(
                    ["secret-tool", "lookup", *attrs],
                    capture_output=True, check=True,
                )
                if out.stdout:
                    return out.stdout
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
    return None


def load_key(data_dir: Path, args) -> str:
    if args.key:
        return args.key.strip().lower()

    config = json.loads((data_dir / "config.json").read_text())

    plain = config.get("key")
    if isinstance(plain, str):
        return plain.strip().lower()

    encrypted = config.get("encryptedKey")
    if not isinstance(encrypted, str):
        sys.exit(
            "config.json has neither 'key' nor 'encryptedKey'. Is this really a "
            "Signal data directory?"
        )

    blob = bytes.fromhex(encrypted)
    version = blob[:3]

    candidates: list[bytes] = []
    if args.safe_storage_password:
        candidates.append(args.safe_storage_password.encode())
    if version == b"v10":
        # v10 means "no keyring available"; Chromium uses a hardcoded password.
        candidates.append(b"peanuts")
    found = keyring_password("Signal Safe Storage", "Signal")
    if found:
        candidates.append(found)
    candidates.append(b"peanuts")

    for password in candidates:
        try:
            return oscrypt_decrypt(blob, password).strip().lower()
        except (ValueError, UnicodeDecodeError):
            continue

    sys.exit(
        f"Could not decrypt 'encryptedKey' (os_crypt {version.decode(errors='replace')}).\n"
        "Signal's key is sealed by your desktop keyring. Either pass the keyring\n"
        "secret with --safe-storage-password, or read the key directly out of a\n"
        "running Signal and pass it with --key."
    )


def open_db(db_path: Path, key: str):
    if not re.fullmatch(r"[0-9a-f]{64}", key):
        sys.exit(f"Key should be 64 hex characters, got {len(key)}")
    conn = sqlcipher.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlcipher.Row
    # Raw-key mode: no KDF is applied, matching Signal's keyDatabase().
    conn.execute(f"PRAGMA key = \"x'{key}'\"")
    try:
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except sqlcipher.DatabaseError:
        sys.exit("Could not decrypt the database - wrong key.")
    return conn


# --------------------------------------------------------------------------
# Attachments: IV(16) || AES-256-CBC ciphertext || HMAC-SHA256(32),
# keyed by the per-file base64 'localKey' (32 bytes AES + 32 bytes MAC).
# --------------------------------------------------------------------------


def decrypt_attachment(raw: bytes, local_key_b64: str, size: int | None) -> bytes:
    keys = base64.b64decode(local_key_b64)
    if len(keys) != 64:
        raise ValueError(f"localKey should be 64 bytes, got {len(keys)}")
    aes_key, mac_key = keys[:32], keys[32:]

    if len(raw) < 48:
        raise ValueError("attachment too short to contain IV and MAC")
    iv, ciphertext, their_mac = raw[:16], raw[16:-32], raw[-32:]

    our_mac = hmac.new(mac_key, raw[:-32], hashlib.sha256).digest()
    if not hmac.compare_digest(our_mac, their_mac):
        raise ValueError("MAC mismatch - file corrupt or wrong key")

    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    if size is not None and 0 <= size <= len(padded):
        return padded[:size]
    pad = padded[-1] if padded else 0
    return padded[:-pad] if 1 <= pad <= 16 else padded


def safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return cleaned[:120] or "file"


# --------------------------------------------------------------------------
# Reading the database
# --------------------------------------------------------------------------


def table_exists(conn, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def conversation_title(data: dict) -> str:
    if data.get("type") == "group":
        return data.get("name") or "Unnamed group"
    parts = [data.get("systemGivenName"), data.get("systemFamilyName")]
    name = " ".join(p for p in parts if p).strip()
    if name:
        return name
    parts = [data.get("profileName"), data.get("profileFamilyName")]
    name = " ".join(p for p in parts if p).strip()
    return name or data.get("e164") or data.get("serviceId") or "Unknown"


def load_conversations(conn) -> dict:
    convos = {}
    for row in conn.execute("SELECT id, json FROM conversations"):
        try:
            data = json.loads(row["json"] or "{}")
        except json.JSONDecodeError:
            data = {}
        convos[row["id"]] = {
            "id": row["id"],
            "title": conversation_title(data),
            "type": data.get("type") or "private",
            "serviceId": data.get("serviceId"),
            "e164": data.get("e164"),
        }
    return convos


def load_attachments(conn) -> dict:
    """messageId -> list of attachment rows, ordered as they appear in the message."""
    if not table_exists(conn, "message_attachments"):
        return {}
    by_message = defaultdict(list)
    rows = conn.execute(
        """
        SELECT messageId, attachmentType, orderInMessage, size, contentType,
               path, localKey, fileName, width, height
        FROM message_attachments
        WHERE path IS NOT NULL AND editHistoryIndex = -1
        ORDER BY messageId, orderInMessage
        """
    )
    for row in rows:
        by_message[row["messageId"]].append(dict(row))
    return by_message


def load_our_aci(conn) -> str | None:
    """Our own ACI, stored in items as {"value": "<aci>.<deviceId>"}."""
    if not table_exists(conn, "items"):
        return None
    row = conn.execute("SELECT json FROM items WHERE id = 'uuid_id'").fetchone()
    if not row or not row["json"]:
        return None
    try:
        value = json.loads(row["json"]).get("value")
    except json.JSONDecodeError:
        return None
    return value.split(".")[0] if isinstance(value, str) else None


def load_messages(conn, conversation_id: str, limit: int | None):
    sql = """
        SELECT id, json, body, type, sent_at, received_at, sourceServiceId, isErased
        FROM messages
        WHERE conversationId = ?
        ORDER BY received_at ASC, sent_at ASC
    """
    if limit:
        sql += f" LIMIT {int(limit)}"
    return conn.execute(sql, (conversation_id,)).fetchall()


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

CSS = """
:root { color-scheme: light dark;
  --bg:#f6f6f8; --fg:#16161a; --muted:#6b6b78; --card:#fff;
  --in:#e9e9ee; --out:#2c6bed; --out-fg:#fff; --line:#dcdce3; }
@media (prefers-color-scheme: dark) { :root {
  --bg:#17171b; --fg:#e9e9ee; --muted:#9a9aa8; --card:#1f1f25;
  --in:#2a2a32; --out:#2c6bed; --out-fg:#fff; --line:#33333d; } }
* { box-sizing: border-box; }
body { margin:0; padding:2rem 1rem; background:var(--bg); color:var(--fg);
  font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
.wrap { max-width: 820px; margin: 0 auto; }
h1 { font-size:1.4rem; margin:0 0 .25rem; }
.sub { color:var(--muted); font-size:.85rem; margin-bottom:1.5rem; }
a { color:#2c6bed; }
.convo-list { list-style:none; padding:0; margin:0; }
.convo-list li { background:var(--card); border:1px solid var(--line);
  border-radius:10px; margin-bottom:.5rem; }
.convo-list a { display:flex; justify-content:space-between; gap:1rem;
  padding:.75rem 1rem; text-decoration:none; color:inherit; }
.convo-list a:hover { background:var(--in); }
.convo-name { font-weight:600; }
.convo-meta { color:var(--muted); font-size:.8rem; white-space:nowrap; }
.day { text-align:center; color:var(--muted); font-size:.78rem;
  margin:1.5rem 0 .75rem; }
.msg { display:flex; margin:.2rem 0; }
.msg.out { justify-content:flex-end; }
.bubble { max-width:78%; padding:.5rem .75rem; border-radius:14px;
  background:var(--in); }
.msg.out .bubble { background:var(--out); color:var(--out-fg); }
.author { font-size:.75rem; font-weight:600; opacity:.75;
  margin-bottom:.15rem; }
.body { white-space:pre-wrap; overflow-wrap:anywhere; }
.time { font-size:.7rem; opacity:.6; margin-top:.25rem; text-align:right; }
.system { text-align:center; color:var(--muted); font-size:.8rem;
  margin:.6rem 0; font-style:italic; }
.deleted { font-style:italic; opacity:.7; }
.quote { border-left:3px solid currentColor; opacity:.75; padding-left:.5rem;
  margin-bottom:.35rem; font-size:.85rem; }
.reactions { margin-top:.3rem; font-size:.85rem; }
.att img, .att video { max-width:100%; border-radius:8px; margin-top:.35rem;
  display:block; }
.att-file { display:inline-block; margin-top:.35rem; font-size:.85rem; }
.missing { font-size:.8rem; opacity:.7; font-style:italic; }
"""

PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><link rel="stylesheet" href="{css}"></head>
<body><div class="wrap">{content}</div></body></html>
"""


def esc(text) -> str:
    return html.escape(str(text if text is not None else ""))


def fmt_time(ms) -> str:
    if not ms:
        return ""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).astimezone().strftime(
        "%Y-%m-%d %H:%M"
    )


def fmt_day(ms) -> str:
    if not ms:
        return "Unknown date"
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).astimezone().strftime(
        "%A, %d %B %Y"
    )


def apply_mentions(body: str, body_ranges, name_for_aci) -> str:
    """Replace the \\uFFFC placeholders Signal uses for mentions."""
    if not body or not body_ranges:
        return body or ""
    mentions = [
        r for r in body_ranges
        if isinstance(r, dict) and r.get("mentionAci") and r.get("start") is not None
    ]
    if not mentions:
        return body
    out = body
    for r in sorted(mentions, key=lambda r: r["start"], reverse=True):
        start, length = r["start"], r.get("length", 1)
        name = name_for_aci(r["mentionAci"])
        out = out[:start] + f"@{name}" + out[start + length:]
    return out


def render_attachment(att: dict, rel_dir: str) -> str:
    if att.get("_exported"):
        href = f"{rel_dir}/{att['_exported']}"
        ctype = att.get("contentType") or ""
        label = esc(att.get("fileName") or att["_exported"])
        if ctype.startswith("image/"):
            return f'<div class="att"><a href="{esc(href)}"><img src="{esc(href)}" alt="{label}"></a></div>'
        if ctype.startswith("video/"):
            return f'<div class="att"><video controls src="{esc(href)}"></video></div>'
        if ctype.startswith("audio/"):
            return f'<div class="att"><audio controls src="{esc(href)}"></audio></div>'
        return f'<a class="att-file" href="{esc(href)}">📎 {label}</a>'
    reason = att.get("_error") or "not exported"
    name = esc(att.get("fileName") or att.get("contentType") or "attachment")
    return f'<div class="missing">[attachment {name}: {esc(reason)}]</div>'


def describe_system(data: dict) -> str | None:
    """Best-effort one-liner for non-bubble messages."""
    mapping = {
        "groupV2Change": "Group updated",
        "group_update": "Group updated",
        "expirationTimerUpdate": "Disappearing message timer changed",
        "keyChange": "Safety number changed",
        "key_changed": "Safety number changed",
        "profileChange": "Contact changed their profile name",
        "verifiedChanged": "Safety number verification changed",
        "conversationMerge": "Conversation merged",
        "titleTransition": "Contact name changed",
        "phoneNumberDiscovery": "Phone number discovered",
        "messageRequestResponseEvent": "Message request updated",
    }
    for field, text in mapping.items():
        if data.get(field) is not None:
            return text
    msg_type = data.get("type")
    if msg_type == "call-history":
        return "Call"
    if msg_type in ("timer-notification", "universal-timer-notification"):
        return "Disappearing message timer changed"
    return None


def render_conversation(convo, rows, attachments, name_for_aci, att_rel_dir):
    parts = []
    rendered = 0
    last_day = None
    for seen, row in enumerate(rows, 1):
        if seen % 500 == 0:
            log.info("    %d messages read, %d rendered", seen, rendered)
        try:
            data = json.loads(row["json"] or "{}")
        except json.JSONDecodeError:
            data = {}

        msg_type = row["type"]
        body = "" if data.get("deletedForEveryone") else apply_mentions(
            row["body"] or data.get("body") or "", data.get("bodyRanges"), name_for_aci
        )
        atts = attachments.get(row["id"], [])
        quote = data.get("quote") if isinstance(data.get("quote"), dict) else None
        has_content = bool(
            body or atts or quote or data.get("deletedForEveryone")
        )

        # Anything with no renderable content is either a system event (group
        # update, timer change, call) or nothing worth a bubble.
        if msg_type not in ("incoming", "outgoing") or not has_content:
            text = describe_system(data) or describe_system({"type": msg_type})
            if text:
                if fmt_day(row["sent_at"]) != last_day:
                    last_day = fmt_day(row["sent_at"])
                    parts.append(f'<div class="day">{esc(last_day)}</div>')
                parts.append(f'<div class="system">{esc(text)}</div>')
                rendered += 1
                log.debug("    #%d system: %s", rendered, text)
            continue

        day = fmt_day(row["sent_at"])
        if day != last_day:
            parts.append(f'<div class="day">{esc(day)}</div>')
            last_day = day

        outgoing = msg_type == "outgoing"
        rendered += 1
        log.debug("    #%d %s %s", rendered, msg_type, fmt_time(row["sent_at"]))
        inner = []

        if convo["type"] == "group" and not outgoing:
            inner.append(f'<div class="author">{esc(name_for_aci(row["sourceServiceId"]))}</div>')

        if quote:
            qauthor = name_for_aci(quote.get("authorAci"))
            qtext = quote.get("text") or "(attachment)"
            inner.append(f'<div class="quote"><b>{esc(qauthor)}</b><br>{esc(qtext)}</div>')

        if data.get("deletedForEveryone"):
            inner.append('<div class="body deleted">This message was deleted.</div>')
        else:
            if body:
                inner.append(f'<div class="body">{esc(body)}</div>')
            for att in atts:
                inner.append(render_attachment(att, att_rel_dir))

        reactions = data.get("reactions") or []
        if reactions:
            shown = " ".join(
                f'{esc(r.get("emoji"))}' for r in reactions if isinstance(r, dict)
            )
            inner.append(f'<div class="reactions">{shown}</div>')

        inner.append(f'<div class="time">{esc(fmt_time(row["sent_at"]))}</div>')
        css_class = "msg out" if outgoing else "msg"
        parts.append(f'<div class="{css_class}"><div class="bubble">{"".join(inner)}</div></div>')

    header = (
        f"<h1>{esc(convo['title'])}</h1>"
        f'<div class="sub">{rendered} entries &middot; '
        f'<a href="../index.html">back to index</a></div>'
    )
    return header + "\n".join(parts), rendered


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", help="Signal data directory (auto-detected by default)")
    ap.add_argument("-o", "--out", default="signal-export", help="output directory")
    ap.add_argument("--key", help="64-char hex SQLCipher key, bypassing config.json")
    ap.add_argument("--safe-storage-password",
                    help="keyring secret protecting 'encryptedKey'")
    ap.add_argument("--no-attachments", action="store_true",
                    help="skip decrypting and copying attachment files")
    ap.add_argument("--limit", type=int, help="max messages per conversation (for testing)")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="log progress per conversation; repeat (-vv) for every message")
    args = ap.parse_args()
    logging.basicConfig(
        level=(logging.WARNING, logging.INFO, logging.DEBUG)[min(args.verbose, 2)],
        format="%(message)s", stream=sys.stderr,
    )

    data_dir = find_data_dir(args.data_dir)
    db_path = data_dir / "sql" / "db.sqlite"
    if not db_path.is_file():
        sys.exit(f"No database at {db_path}")

    print(f"Data directory: {data_dir}")
    key = load_key(data_dir, args)
    conn = open_db(db_path, key)
    print("Database unlocked.")

    convos = load_conversations(conn)
    attachments = {} if args.no_attachments else load_attachments(conn)

    aci_to_name = {
        c["serviceId"]: c["title"] for c in convos.values() if c.get("serviceId")
    }

    our_aci = load_our_aci(conn)

    def name_for_aci(aci):
        if not aci:
            return "Unknown"
        if our_aci and aci == our_aci:
            return "You"
        return aci_to_name.get(aci, aci)

    out_dir = Path(args.out).expanduser()
    (out_dir / "chats").mkdir(parents=True, exist_ok=True)
    (out_dir / "assets").mkdir(exist_ok=True)
    (out_dir / "assets" / "style.css").write_text(CSS)

    att_root = data_dir / "attachments.noindex"
    exported, failed, skipped_empty = 0, 0, 0
    summaries = []

    for pos, convo in enumerate(convos.values(), 1):
        log.info("[%d/%d] %s", pos, len(convos), convo["title"])
        rows = load_messages(conn, convo["id"], args.limit)
        if not rows:
            log.info("    nothing to render, skipped")
            skipped_empty += 1
            continue

        slug = f"{safe_name(convo['title'])}-{convo['id'][:8]}"
        att_dir = out_dir / "chats" / f"{slug}_files"

        if not args.no_attachments:
            for row in rows:
                for att in attachments.get(row["id"], []):
                    src = att_root / att["path"]
                    if not src.is_file():
                        att["_error"] = "file missing on disk"
                        failed += 1
                        continue
                    try:
                        raw = src.read_bytes()
                        blob = (decrypt_attachment(raw, att["localKey"], att["size"])
                                if att.get("localKey") else raw)
                    except Exception as exc:  # noqa: BLE001 - report and continue
                        att["_error"] = str(exc)
                        failed += 1
                        continue
                    att_dir.mkdir(parents=True, exist_ok=True)
                    base = safe_name(att.get("fileName") or "")
                    if not base or "." not in base:
                        ext = (att.get("contentType") or "").split("/")[-1][:8] or "bin"
                        base = f"{att['path'].replace('/', '_')}.{ext}"
                    dest = att_dir / base
                    n = 1
                    while dest.exists():
                        dest = att_dir / f"{dest.stem}_{n}{dest.suffix}"
                        n += 1
                    dest.write_bytes(blob)
                    att["_exported"] = dest.name
                    exported += 1

        content, rendered = render_conversation(convo, rows, attachments,
                                                name_for_aci, f"{slug}_files")
        if not rendered:
            log.info("    nothing to render, skipped")
            skipped_empty += 1
            continue
        log.info("    %d entries", rendered)
        (out_dir / "chats" / f"{slug}.html").write_text(
            PAGE.format(title=esc(convo["title"]), css="../assets/style.css",
                        content=content)
        )
        summaries.append((convo["title"], f"chats/{slug}.html", rendered,
                          rows[-1]["sent_at"]))

    summaries.sort(key=lambda s: s[3] or 0, reverse=True)
    items = "\n".join(
        f'<li><a href="{esc(link)}"><span class="convo-name">{esc(title)}</span>'
        f'<span class="convo-meta">{count} msgs &middot; {esc(fmt_time(last))}</span>'
        f"</a></li>"
        for title, link, count, last in summaries
    )
    index = (
        f"<h1>Signal export</h1>"
        f'<div class="sub">{len(summaries)} conversations &middot; '
        f"generated {esc(datetime.now().strftime('%Y-%m-%d %H:%M'))}</div>"
        f'<ul class="convo-list">{items}</ul>'
    )
    (out_dir / "index.html").write_text(
        PAGE.format(title="Signal export", css="assets/style.css", content=index)
    )

    conn.close()
    print(f"Wrote {len(summaries)} conversations to {out_dir}/index.html")
    if skipped_empty:
        print(f"Skipped {skipped_empty} conversations with no messages.")
    if not args.no_attachments:
        print(f"Attachments: {exported} exported, {failed} failed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
