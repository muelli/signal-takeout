#!/usr/bin/env -S uv run --script
# SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
# /// script
# requires-python = ">=3.9"
# dependencies = ["sqlcipher3-binary", "cryptography", "tqdm"]
# ///
"""Export a local Signal Desktop database to static HTML.

Reads ~/.var/app/org.signal.Signal/config/Signal (or the native equivalent),
decrypts db.sqlite with the key Signal stores in config.json, and writes one
HTML file per conversation plus an index with offline search.

This only ever reads your own local Signal installation. Nothing is uploaded.
"""

from __future__ import annotations

import argparse
import atexit
import base64
import binascii
import contextlib
import hashlib
import hmac
import html
import json
import logging
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from itertools import groupby
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

log = logging.getLogger("signal_takeout")

try:
    from sqlcipher3 import dbapi2 as sqlcipher
except ImportError:  # pragma: no cover - dependency check
    sys.exit(
        "Missing sqlcipher3. Run with uv:\n"
        "  uv run signal_takeout.py\n"
        "or install with:\n"
        "  python3 -m venv .venv && .venv/bin/pip install sqlcipher3-binary cryptography tqdm"
    )

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover - dependency check
    sys.exit("Missing cryptography. Run with uv (uv run signal_takeout.py) or pip install cryptography")


try:
    from tqdm import tqdm
    from tqdm.contrib.logging import logging_redirect_tqdm
except ImportError:  # progress bars are optional
    tqdm = None


def progress(iterable, **kwargs):
    # disable=None turns the bar off when stderr is not a terminal
    return iterable if tqdm is None else tqdm(iterable, disable=None, **kwargs)


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
    try:
        try:
            return _try_open(db_path, key, "mode=ro")
        except sqlcipher.OperationalError as error:
            return _open_read_only_snapshot(db_path, key, error)
    except sqlcipher.DatabaseError as e:
        if "not a database" in str(e):
            sys.exit("Could not decrypt the database - wrong key.")
        sys.exit(f"Could not open the database: {e}")


def _open_read_only_snapshot(db_path: Path, key: str, error):
    # Read-only WAL needs a -shm file it can create, so read-only snapshots
    # fail. With an empty WAL, immutable is safe; otherwise use a copy.
    wal = db_path.with_name(db_path.name + "-wal")
    if not wal.exists() or wal.stat().st_size == 0:
        log.info("Cannot open database read-only (%s), opening immutable", error)
        return _try_open(db_path, key, "immutable=1")
    tmp = Path(tempfile.mkdtemp(prefix="signal-takeout-"))
    atexit.register(shutil.rmtree, tmp, ignore_errors=True)
    log.info("Cannot open database read-only (%s), copying it to %s", error, tmp)
    shutil.copy2(db_path, tmp / db_path.name)
    shutil.copy2(wal, tmp / wal.name)
    return _try_open(tmp / db_path.name, key, "mode=ro")


def _try_open(db_path: Path, key: str, flags: str):
    conn = sqlcipher.connect(f"file:{db_path}?{flags}", uri=True)
    conn.row_factory = sqlcipher.Row
    # Raw-key mode: no KDF is applied, matching Signal's keyDatabase().
    conn.execute(f"PRAGMA key = \"x'{key}'\"")
    try:
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except sqlcipher.DatabaseError:
        conn.close()
        raise
    return conn


# --------------------------------------------------------------------------
# Attachments: IV(16) || AES-256-CBC ciphertext || HMAC-SHA256(32),
# keyed by the per-file base64 'localKey' (32 bytes AES + 32 bytes MAC).
# --------------------------------------------------------------------------


CHUNK = 1 << 20


def iter_stored_file(src: Path, entry: dict):
    """Yield plaintext chunks. The MAC is verified before the last chunk is
    yielded, so callers must discard everything if this raises."""
    if not entry.get("localKey"):
        with src.open("rb") as f:
            while chunk := f.read(CHUNK):
                yield chunk
        return

    keys = base64.b64decode(entry["localKey"])
    if len(keys) != 64:
        raise ValueError(f"localKey should be 64 bytes, got {len(keys)}")
    total = src.stat().st_size
    if total < 48:
        raise ValueError("attachment too short to contain IV and MAC")

    size = entry.get("size")
    limit = size if isinstance(size, int) and size >= 0 else None
    mac = hmac.new(keys[32:], digestmod=hashlib.sha256)
    held = b""
    emitted = 0
    with src.open("rb") as f:
        iv = f.read(16)
        mac.update(iv)
        decryptor = Cipher(algorithms.AES(keys[:32]), modes.CBC(iv)).decryptor()
        left = total - 48
        while left:
            block = f.read(min(CHUNK, left))
            if not block:
                raise ValueError("attachment truncated")
            left -= len(block)
            mac.update(block)
            held += decryptor.update(block)
            ready, held = held[:-16], held[-16:]
            if limit is not None:
                ready = ready[:limit - emitted]
            if ready:
                emitted += len(ready)
                yield ready
        held += decryptor.finalize()
        if not hmac.compare_digest(mac.digest(), f.read(32)):
            raise ValueError("MAC mismatch - file corrupt or wrong key")

    if limit is not None and emitted + len(held) >= limit:
        held = held[:limit - emitted]
    else:
        pad = held[-1] if held else 0
        held = held[:-pad] if 1 <= pad <= 16 else held
    if held:
        yield held


def read_stored_file(src: Path, entry: dict) -> bytes:
    return b"".join(iter_stored_file(src, entry))


def copy_stored_file(src: Path, entry: dict, dest: Path) -> None:
    part = dest.with_name(dest.name + ".part")
    try:
        with part.open("wb") as out:
            for chunk in iter_stored_file(src, entry):
                out.write(chunk)
        part.replace(dest)
    finally:
        part.unlink(missing_ok=True)


def image_ext(blob: bytes) -> str:
    for magic, ext in ((b"\x89PNG", "png"), (b"\xff\xd8", "jpg"), (b"GIF8", "gif")):
        if blob.startswith(magic):
            return ext
    return "webp" if blob[:4] == b"RIFF" and blob[8:12] == b"WEBP" else "img"


def export_avatar(convo, att_root: Path, avatar_dir: Path, slug: str) -> str | None:
    for entry in convo["avatars"]:
        try:
            blob = read_stored_file(att_root / entry["path"].replace("\\", "/"), entry)
        except (OSError, ValueError) as exc:
            log.debug("    avatar %s unusable: %s", entry["path"], exc)
            continue
        avatar_dir.mkdir(parents=True, exist_ok=True)
        dest = avatar_dir / f"{slug}.{image_ext(blob)}"
        dest.write_bytes(blob)
        log.debug("    avatar %s -> %s", entry["path"], dest.name)
        return dest.name
    return None


def safe_name(name: str, unicode: bool = False) -> str:
    cleaned = re.sub(r"[^\w.-]+" if unicode else r"[^A-Za-z0-9._-]+", "_", name).strip("._")
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
            "names": conversation_names(data),
            "avatars": [a for a in (data.get("avatar"), data.get("profileAvatar"))
                        if isinstance(a, dict) and a.get("path")],
            "color": {k: data.get(k) for k in ("conversationColor", "customColor", "customColorId")},
        }
    return convos


FLAT_COLORS = {
    "blue": "#336ba3", "burlap": "#6f6a58", "crimson": "#cf163e", "forest": "#3b7845",
    "indigo": "#6058ca", "plum": "#aa377a", "steel": "#71717f", "taupe": "#8f616a",
    "teal": "#077d92", "vermilion": "#c73f0a", "violet": "#9932c8", "wintergreen": "#1d8663",
}
GRADIENT_COLORS = {
    "ultramarine": (180, "#0552f0", "#2c6bed"), "basil": (180, "#2f9373", "#077343"),
    "ember": (168, "#e57c00", "#5e0000"), "fluorescent": (192, "#ec13dd", "#1b36c6"),
    "infrared": (192, "#f65560", "#442ced"), "lagoon": (180, "#004066", "#32867d"),
    "midnight": (180, "#2c2c3a", "#787891"), "sea": (180, "#498fd4", "#2c66a0"),
    "sublime": (180, "#6281d5", "#974460"), "tangerine": (192, "#db7133", "#911231"),
}
LIGHTNESS_AT_HUE = {0: 45, 60: 30, 180: 30, 240: 50, 300: 40, 360: 45}


def default_lightness(hue: float) -> float:
    lo, hi = next(((a, b) for a, b in ((0, 60), (60, 180), (180, 240), (240, 300))
                   if hue < b), (300, 360))
    return LIGHTNESS_AT_HUE[lo] + (hue - lo) * (LIGHTNESS_AT_HUE[hi] - LIGHTNESS_AT_HUE[lo]) / (hi - lo)


def hsl_css(color: dict) -> str:
    hue = color.get("hue", 0)
    lightness = color.get("lightness")
    lightness = default_lightness(hue) if lightness is None else lightness * 100
    return f"hsl({hue:g}, {color.get('saturation', 0):g}%, {lightness:g}%)"


def chat_color_css(color: dict, defaults: dict) -> str | None:
    """CSS background for our outgoing bubbles, resolved like Signal does:
    the chat's own colour, else the account default."""
    name = color.get("conversationColor") or defaults.get("color") or "ultramarine"
    if name in FLAT_COLORS:
        return FLAT_COLORS[name]
    if name in GRADIENT_COLORS:
        deg, start, end = GRADIENT_COLORS[name]
        return f"linear-gradient({deg}deg, {start}, {end})"
    if name != "custom":
        return None
    default_data = defaults.get("customColorData") or {}
    custom = (color.get("customColor")
              or (defaults.get("customColors") or {}).get(color.get("customColorId"))
              or default_data.get("value"))
    if not isinstance(custom, dict) or not isinstance(custom.get("start"), dict):
        return None
    if not isinstance(custom.get("end"), dict):
        return hsl_css(custom["start"])
    return (f"linear-gradient({270 - (custom.get('deg') or 0):g}deg, "
            f"{hsl_css(custom['start'])}, {hsl_css(custom['end'])})")


def load_chat_color_defaults(conn) -> dict:
    """Account-wide default chat colour and the custom colour list, from items."""
    out = {}
    if not table_exists(conn, "items"):
        return out
    for key in ("defaultConversationColor", "customColors"):
        row = conn.execute("SELECT json FROM items WHERE id = ?", (key,)).fetchone()
        try:
            value = json.loads(row["json"]).get("value") if row and row["json"] else None
        except (json.JSONDecodeError, AttributeError):
            value = None
        if not isinstance(value, dict):
            continue
        if key == "customColors":
            out["customColors"] = value.get("colors") or {}
        else:
            out.update(color=value.get("color"), customColorData=value.get("customColorData"))
    return out


def conversation_names(data: dict) -> list[str]:
    """Every name a conversation is known by, for --export-only matching."""
    names = [data.get("name")]
    for given, family in (("systemGivenName", "systemFamilyName"),
                          ("profileName", "profileFamilyName")):
        names += [data.get(given), data.get(family),
                  " ".join(p for p in (data.get(given), data.get(family)) if p)]
    return [n for n in names if isinstance(n, str) and n]


def load_attachments(conn) -> dict:
    """messageId -> list of attachment rows, ordered as they appear in the message."""
    if not table_exists(conn, "message_attachments"):
        return {}
    by_message = defaultdict(list)
    rows = conn.execute(
        """
        SELECT messageId, attachmentType, orderInMessage, size, contentType,
               path, localKey, fileName, width, height, caption, flags,
               screenshotPath, screenshotLocalKey, screenshotSize,
               screenshotContentType, wasTooBig, pending, error, isCorrupted
        FROM message_attachments
        WHERE attachmentType IN ('attachment', 'long-message', 'quote', 'preview', 'sticker')
          AND editHistoryIndex = -1
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


def parse_day(text: str) -> datetime:
    try:
        return datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a date like 2026-03-31")


@dataclass(frozen=True)
class Window:
    """Which messages to read: sent_at from start (inclusive) to end (exclusive),
    and received_at from cutoff on."""
    start: int = 0
    end: int | None = None
    cutoff: int | None = None

    def sql(self) -> tuple[str, list]:
        clause = "received_at >= ?"
        params = [self.cutoff or 0]
        if self.start:
            clause += " AND sent_at >= ?"
            params.append(self.start)
        if self.end is not None:
            clause += " AND sent_at < ?"
            params.append(self.end)
        return clause, params


def newest_cutoff(conn, conversation_ids, limit: int, window: Window = Window()) -> int | None:
    """received_at of the limit-th newest message in these conversations, if there are that many."""
    wanted = set(conversation_ids)
    clause, params = window.sql()
    seen = 0
    for row in conn.execute(f"SELECT conversationId, received_at FROM messages WHERE {clause}"
                            " ORDER BY received_at DESC", params):
        if row["conversationId"] in wanted:
            seen += 1
            if seen >= limit:
                return row["received_at"]
    return None


def count_messages(conn, conversation_id: str, window: Window = Window()) -> int:
    clause, params = window.sql()
    return conn.execute(f"SELECT count(*) FROM messages WHERE conversationId = ? AND {clause}",
                        [conversation_id, *params]).fetchone()[0]


def load_messages(conn, conversation_id: str, window: Window = Window()):
    clause, params = window.sql()
    return conn.execute(
        f"""
        SELECT id, json, body, type, sent_at, received_at, sourceServiceId, isErased
        FROM messages
        WHERE conversationId = ? AND {clause}
        ORDER BY received_at ASC, sent_at ASC
        """,
        [conversation_id, *params],
    )


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
.convo-id { display:flex; align-items:center; gap:.75rem; min-width:0; }
.avatar { width:2.5rem; height:2.5rem; border-radius:50%; object-fit:cover;
  flex:none; }
.avatar.ph { display:flex; align-items:center; justify-content:center;
  background:var(--in); color:var(--muted); font-weight:600; }
.chat-head { display:flex; align-items:center; gap:.75rem; padding-top:.5rem; }
.chat-head .avatar { width:2.5rem; height:2.5rem; }
.chat-head h1 { font-size:1.1rem; line-height:1.2; margin:0; }
.chat-head .sub { margin-bottom:0; font-size:.8rem; }
.tabs { display:flex; flex-wrap:wrap; gap:1rem; margin:1rem 0 .5rem; }
h2 { font-size:1.1rem; margin:1.5rem 0 .25rem; }
h3.month { font-size:.8rem; font-weight:600; color:var(--muted); margin:1rem 0 .4rem; }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(7.5rem,1fr)); gap:.3rem;
  content-visibility:auto; contain-intrinsic-size:auto 8rem; }
.tile { position:relative; aspect-ratio:1; background:var(--in); border-radius:6px;
  overflow:hidden; }
.tile .thumb { display:block; width:100%; height:100%; text-decoration:none; }
.tile img { width:100%; height:100%; object-fit:cover; display:block; }
.tile .novideo { display:flex; align-items:flex-end; width:100%;
  height:100%; padding:.5rem; background:#222; color:#ccc; font-size:.7rem;
  overflow:hidden; word-break:break-all; }
.play { position:absolute; left:50%; top:50%; transform:translate(-50%,-50%);
  width:2.2rem; height:2.2rem; line-height:2.2rem; text-align:center; border-radius:50%;
  background:rgba(0,0,0,.55); color:#fff; font-size:.9rem; pointer-events:none; }
.goto { position:absolute; right:.25rem; bottom:.25rem; padding:0 .4rem; border-radius:6px;
  background:rgba(0,0,0,.65); color:#fff; font-size:.7rem; text-decoration:none;
  opacity:0; }
.tile:hover .goto, .goto:focus-visible { opacity:1; }
.rows { list-style:none; padding:0; margin:0; }
.rows li { display:flex; flex-wrap:wrap; align-items:center; gap:.25rem .75rem;
  padding:.5rem 0; border-bottom:1px solid var(--line); }
.rows .goto { position:static; background:none; color:var(--muted); opacity:1;
  text-decoration:underline; }
.rows .time { color:var(--muted); font-size:.75rem; margin:0 0 0 auto; opacity:1; }
.convo-name { font-weight:600; }
.convo-meta { color:var(--muted); font-size:.8rem; white-space:nowrap; }
.day { text-align:center; color:var(--muted); font-size:.78rem;
  margin:1.5rem 0 .75rem; }
.msg { display:flex; margin:.2rem 0; }
.msg.out { justify-content:flex-end; }
.bubble { max-width:78%; padding:.5rem .75rem; border-radius:14px;
  background:var(--in); position:relative; }
.copy { opacity:0; visibility:hidden; transition:opacity .3s .5s, visibility 0s .8s;
  position:absolute; top:50%; left:100%; transform:translateY(-50%);
  padding:.15rem .5rem; border:1px solid var(--line); border-radius:8px;
  background:var(--card); color:var(--muted); font:inherit; font-size:.75rem;
  cursor:pointer; white-space:nowrap; }
.msg.out .copy { left:auto; right:100%; }
.bubble:hover .copy, .copy:focus-visible { opacity:1; visibility:visible; transition:opacity .1s; }
.msg.out .bubble { background:var(--out); color:var(--out-fg); }
.author { font-size:.75rem; font-weight:600; margin-bottom:.15rem;
  color:hsl(var(--h, 0) 60% 38%); }
@media (prefers-color-scheme: dark) { .author { color:hsl(var(--h, 0) 70% 72%); } }
.msg > .avatar { width:1.75rem; height:1.75rem; margin-right:.4rem;
  align-self:flex-end; font-size:.8rem; }
.body { white-space:pre-wrap; overflow-wrap:anywhere; }
.msg.out .bubble a { color:inherit; }
.time { font-size:.7rem; opacity:.6; margin-top:.25rem; text-align:right; }
.system { text-align:center; color:var(--muted); font-size:.8rem;
  margin:.6rem 0; font-style:italic; }
.deleted { font-style:italic; opacity:.7; }
.quote { border-left:3px solid currentColor; opacity:.75; padding-left:.5rem;
  margin-bottom:.35rem; font-size:.85rem; }
.edits { margin-top:.3rem; font-size:.8rem; opacity:.8; }
.edits summary { cursor:pointer; }
.edit { margin-top:.2rem; white-space:pre-wrap; overflow-wrap:anywhere; }
.edit .time { display:inline; margin:0; }
.reactions { display:flex; flex-wrap:wrap; gap:.25rem; margin-top:.3rem; }
.reaction { display:inline-flex; align-items:center; gap:.25rem; padding:0 .5rem;
  border-radius:999px; font-size:.85rem; line-height:1.5;
  background:rgba(127,127,127,.18); border:1px solid rgba(127,127,127,.35); }
.rcount { font-size:.75rem; opacity:.8; }
.att img, .att video { max-width:100%; height:auto; border-radius:8px; margin-top:.35rem;
  display:block; }
.att video { max-height:70vh; }
.att-file { display:inline-block; margin-top:.35rem; font-size:.85rem; }
.att-size, .att-label { opacity:.7; font-size:.8rem; }
.caption { margin-top:.35rem; }
.att img.sticker { max-width:8rem; }
.qthumb { float:right; width:2.5rem; height:2.5rem; object-fit:cover;
  border-radius:4px; margin-left:.5rem; }
.preview { display:block; margin-top:.35rem; padding:.5rem; border-radius:8px;
  border:1px solid currentColor; color:inherit; text-decoration:none;
  overflow-wrap:anywhere; }
.preview img { max-width:100%; height:auto; border-radius:6px; display:block; margin-bottom:.35rem; }
.ptitle { font-weight:600; }
.pdesc, .purl { font-size:.8rem; opacity:.75; }
.contact { margin-top:.35rem; }
.missing { font-size:.8rem; opacity:.7; font-style:italic; }
[hidden] { display:none !important; }
.jserror { background:#b3261e; color:#fff; padding:.5rem 1rem; font-size:.85rem; }
mark { background:#ffd54a; color:#000; border-radius:2px; }
.tools, .findbar { display:flex; gap:.5rem; align-items:center; }
.tools { margin-bottom:1rem; }
.stickybar { position:sticky; top:0; z-index:1; background:var(--bg); }
.findbar { padding:.5rem 0; background:var(--bg); }
.dayfloat { position:absolute; top:100%; left:50%; transform:translateX(-50%);
  margin-top:.25rem; padding:.15rem .8rem; border-radius:999px; white-space:nowrap;
  background:var(--card); border:1px solid var(--line); color:var(--muted);
  font-size:.75rem; box-shadow:0 1px 4px rgba(0,0,0,.15); pointer-events:none; }
.tools input, .findbar input { flex:1; min-width:0; padding:.45rem .7rem;
  border:1px solid var(--line); border-radius:8px; background:var(--card);
  color:var(--fg); font:inherit; }
.tools select, .findbar select, .findbar button { padding:.4rem .6rem; border:1px solid var(--line);
  border-radius:8px; background:var(--card); color:var(--fg); font:inherit; }
.find-count { color:var(--muted); font-size:.8rem; white-space:nowrap; }
.msg { scroll-margin-top:7rem; }
.msg.cur .bubble, .msg.jump .bubble { outline:2px solid #f5a623; }
#timeline { overflow-anchor:none; padding-top:1.5rem; }
.chunk { display:flow-root; scroll-margin-top:7rem; }
.chunk-label { text-align:center; color:var(--muted); font-size:.85rem;
  padding:1rem 0; font-style:italic; }
.findbar select { max-width:11rem; }
.section { color:var(--muted); font-size:.8rem; text-transform:uppercase;
  letter-spacing:.04em; margin:1rem 0 .4rem; }
.convo-list li.hit a { display:block; }
.hit-head { display:flex; justify-content:space-between; gap:1rem; }
.snip { color:var(--muted); font-size:.85rem; margin-top:.15rem;
  overflow-wrap:anywhere; }
.none { color:var(--muted); font-style:italic; }
"""

PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><link rel="stylesheet" href="{css}"></head>
<body><div class="wrap">{content}</div>{scripts}</body></html>
"""

JS = r"""(() => {
const $ = (id) => document.getElementById(id);
const norm = (s) => s.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
const tokens = (q) => norm(q).split(/\s+/).filter(Boolean);

function normMap(s) {
  let n = "";
  const map = [];
  for (let i = 0; i < s.length; i++) {
    const c = norm(s[i]);
    for (let k = 0; k < c.length; k++) { n += c[k]; map.push(i); }
  }
  return { n, map };
}

function ranges(text, toks) {
  const { n, map } = normMap(text);
  const found = [];
  for (const t of toks) {
    for (let i = n.indexOf(t); i !== -1; i = n.indexOf(t, i + t.length)) {
      found.push([map[i], map[i + t.length - 1] + 1]);
    }
  }
  found.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const r of found) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]);
    else merged.push(r);
  }
  return merged;
}

function highlight(text, rs, from = 0, to = text.length) {
  const out = document.createDocumentFragment();
  let pos = from;
  for (const [a, b] of rs) {
    const s = Math.max(a, pos), e = Math.min(b, to);
    if (e <= s) continue;
    out.append(text.slice(pos, s));
    const m = document.createElement("mark");
    m.textContent = text.slice(s, e);
    out.append(m);
    pos = e;
  }
  out.append(text.slice(pos, to));
  return out;
}

function snippet(text, rs) {
  const from = Math.max(0, rs[0][0] - 40);
  const to = Math.min(text.length, from + 160);
  const el = document.createElement("div");
  el.className = "snip";
  if (from > 0) el.append("...");
  el.append(highlight(text, rs, from, to));
  if (to < text.length) el.append("...");
  return el;
}

const pad = (n) => String(n).padStart(2, "0");
function fmt(ms) {
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function el(tag, cls, ...kids) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  e.append(...kids);
  return e;
}

function avatar(c) {
  if (c.a) {
    const img = el("img", "avatar");
    img.src = c.a;
    img.alt = "";
    return img;
  }
  const initial = [...c.t].find((ch) => /[\p{L}\p{N}]/u.test(ch)) || "#";
  return el("span", "avatar ph", initial.toUpperCase());
}

function reportErrors() {
  const show = (msg) => {
    let b = $("jserror");
    if (!b) {
      b = el("div", "jserror");
      b.id = "jserror";
      document.body.prepend(b);
    }
    b.textContent = msg;
  };
  addEventListener("error", (e) => show(`Script error: ${e.message} (${(e.filename || "").split("/").pop()}:${e.lineno})`));
  addEventListener("unhandledrejection", (e) => show(`Script error: ${e.reason}`));
}

function initIndex() {
  const q = $("q");
  if (!q) return;
  const list = $("list"), results = $("results"), sort = $("sort");
  const data = window.SEARCH_INDEX || { convos: [], msgs: [] };
  let prepared = false;

  function sortList() {
    const items = [...list.children];
    items.sort(sort.value === "name"
      ? (a, b) => a.dataset.name.localeCompare(b.dataset.name, undefined, { sensitivity: "base" })
      : (a, b) => b.dataset.last - a.dataset.last);
    list.append(...items);
  }

  function prepare() {
    if (prepared) return;
    prepared = true;
    for (const c of data.convos) c.n = norm(c.t);
    for (const m of data.msgs) m.push(norm(m[3]));
  }

  function nameScore(n, toks) {
    let score = 0;
    for (const t of toks) {
      const i = n.indexOf(t);
      if (i < 0) return 0;
      score += i === 0 ? 3 : n[i - 1] === " " ? 2 : 1;
    }
    return n === toks.join(" ") ? score + 5 : score;
  }

  function search() {
    const toks = tokens(q.value);
    list.hidden = toks.length > 0;
    results.hidden = toks.length === 0;
    if (!toks.length) return;
    prepare();

    const names = data.convos
      .map((c) => ({ c, score: nameScore(c.n, toks) }))
      .filter((h) => h.score > 0)
      .sort((a, b) => b.score - a.score || b.c.l - a.c.l);
    const msgs = data.msgs
      .filter((m) => toks.every((t) => m[4].includes(t)))
      .sort((a, b) => b[2] - a[2]);

    const out = [];
    if (names.length) {
      out.push(el("div", "section", `Conversations (${names.length})`));
      out.push(el("ul", "convo-list", ...names.map(({ c }) => {
        const a = el("a", "",
                     el("span", "convo-id", avatar(c),
                        el("span", "convo-name", highlight(c.t, ranges(c.t, toks)))),
                     el("span", "convo-meta", fmt(c.l)));
        a.href = c.u;
        return el("li", "", a);
      })));
    }
    if (msgs.length) {
      const shown = msgs.slice(0, 100);
      const suffix = msgs.length > shown.length ? `, showing ${shown.length}` : "";
      out.push(el("div", "section", `Messages (${msgs.length}${suffix})`));
      out.push(el("ul", "convo-list", ...shown.map((m) => {
        const c = data.convos[m[0]];
        const a = el("a", "", el("div", "hit-head", el("span", "convo-name", c.t),
                                 el("span", "convo-meta", fmt(m[2]))),
                     snippet(m[3], ranges(m[3], toks)));
        a.href = `${c.u}#m${m[1]}`;
        return el("li", "hit", a);
      })));
    }
    if (!out.length) out.push(el("div", "none", "No matches."));
    results.replaceChildren(...out);
  }

  let timer;
  q.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(search, 120); });
  sort.addEventListener("change", sortList);
  sortList();
  search();
}

function initFind(chat) {
  const input = $("find"), timeline = $("timeline");
  if (!input || !timeline) return;
  const count = $("find-count");
  const MARKED = ".msg .body:not(.deleted), .msg .caption";
  let data = null, loading = null, toks = [], matches = [], cur = -1, gen = 0;
  let marked = [], curEl = null;

  function loadData() {
    if (!loading) {
      loading = new Promise((resolve) => {
        window.__find = (list) => {
          for (const m of list) m.push(norm(m[1]));
          data = list;
          resolve();
        };
        const tag = document.createElement("script");
        tag.charset = "utf-8";
        tag.onload = () => tag.remove();
        tag.onerror = () => { tag.remove(); data = []; count.textContent = "Search data missing"; resolve(); };
        tag.src = timeline.dataset.find;
        document.head.append(tag);
      });
    }
    return loading;
  }

  function markIn(root) {
    if (!toks.length) return;
    for (const e of root.querySelectorAll(MARKED)) {
      const rs = ranges(e.textContent, toks);
      if (!rs.length) continue;
      e._c = e.cloneNode(true);
      const walk = document.createTreeWalker(e, NodeFilter.SHOW_TEXT), texts = [];
      while (walk.nextNode()) texts.push(walk.currentNode);
      let off = 0;
      for (const n of texts) {
        const t = n.data;
        n.replaceWith(highlight(t, rs.map(([a, b]) => [a - off, b - off])));
        off += t.length;
      }
      marked.push(e);
    }
  }

  function clearMarks() {
    for (const e of marked) if (e.isConnected) e.replaceChildren(...e._c.childNodes);
    marked = [];
    if (curEl) curEl.classList.remove("cur");
    curEl = null;
  }

  function show(i) {
    if (!matches.length) { count.textContent = input.value.trim() ? "0 / 0" : ""; return; }
    cur = (i + matches.length) % matches.length;
    count.textContent = `${cur + 1} / ${matches.length}`;
    const mine = ++gen;
    chat.reveal(matches[cur]).then((e) => {
      if (mine !== gen || !e) return;
      if (curEl) curEl.classList.remove("cur");
      curEl = e;
      e.classList.add("cur");
      e.scrollIntoView({ block: "center" });
    });
  }

  function run() {
    clearMarks();
    toks = tokens(input.value);
    matches = toks.length ? data.filter((m) => toks.every((t) => m[2].includes(t))).map((m) => m[0]) : [];
    markIn(timeline);
    cur = -1;
    count.textContent = "";
    show(0);
  }

  chat.onLoad(markIn);
  let timer;
  input.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => loadData().then(run), 120);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); show(cur + (e.shiftKey ? -1 : 1)); }
    else if (e.key === "Escape" && input.value) {
      e.preventDefault();
      input.value = "";
      loadData().then(run);
    }
  });
  $("find-next").addEventListener("click", () => show(cur + 1));
  $("find-prev").addEventListener("click", () => show(cur - 1));
}

function initKeys() {
  const back = $("back"), input = $("find");
  if (!back) return;
  document.addEventListener("keydown", (e) => {
    if (e.defaultPrevented || e.altKey) return;
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
    if (input && (e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
      e.preventDefault();
      input.focus();
      input.select();
    } else if (input && e.key === "/" && !typing && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      input.focus();
    } else if (e.key === "Escape" && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
      location.href = back.href;
    }
  });
}

function initCopy() {
  const timeline = $("timeline");
  if (!timeline) return;
  const btn = el("button", "copy", "Copy");
  btn.type = "button";
  btn.title = "Copy message text";
  const textOf = (bubble) => [...bubble.querySelectorAll(".body:not(.deleted), .caption")]
    .map((e) => e.textContent).join("\n");

  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const t = document.createElement("textarea");
      t.value = text;
      t.style.cssText = "position:fixed;opacity:0";
      document.body.append(t);
      t.select();
      document.execCommand("copy");
      t.remove();
    }
  }

  timeline.addEventListener("mouseover", (e) => {
    const bubble = e.target.closest(".bubble");
    if (!bubble || bubble === btn.parentElement) return;
    if (textOf(bubble)) bubble.append(btn); else btn.remove();
  });
  let timer;
  btn.addEventListener("click", async () => {
    await copy(textOf(btn.parentElement));
    btn.textContent = "Copied";
    clearTimeout(timer);
    timer = setTimeout(() => { btn.textContent = "Copy"; }, 1200);
  });
}

function initChat() {
  const pill = $("dayfloat"), timeline = $("timeline");
  if (!pill || !timeline) return null;
  const hooks = [];
  const secs = [...timeline.children].filter((e) => e.classList.contains("chunk"));
  const bar = pill.parentElement, jump = $("jump");
  const pending = new Map();
  let queued = false, pinned = null;
  for (const s of secs) { s._ph = s.firstElementChild; s._label = s._ph.textContent; }

  window.__chunk = (id, html) => {
    const done = pending.get(id);
    if (done) { pending.delete(id); done(html); }
  };

  function fetchChunk(s) {
    return new Promise((resolve, reject) => {
      const id = s.dataset.id;
      const tag = document.createElement("script");
      tag.charset = "utf-8";
      pending.set(id, resolve);
      tag.onload = () => tag.remove();
      tag.onerror = () => { pending.delete(id); tag.remove(); reject(new Error(s.dataset.src)); };
      tag.src = s.dataset.src;
      document.head.append(tag);
    });
  }

  function stuck(s, why) {
    s._ph.textContent = `${s.dataset.label}: ${why} (${s.dataset.src})`;
    console.error(`chunk ${s.dataset.id}: ${why}`);
  }

  function load(s) {
    if (s._p) return s._p;
    const wait = setTimeout(() => stuck(s, "no response after 15 s"), 15000);
    s._p = fetchChunk(s).then((html) => {
      clearTimeout(wait);
      const before = s.getBoundingClientRect();
      s.innerHTML = html;
      s.style.height = "";
      s._loaded = true;
      for (const h of hooks) h(s);
      const after = s.getBoundingClientRect();
      if (before.bottom <= 0) scrollBy(0, after.height - before.height);
      return s;
    }).catch((err) => {
      clearTimeout(wait);
      if (s._loaded) throw err;
      stuck(s, `could not load, ${err && err.message}`);
    });
    return s._p;
  }

  function unload(s) {
    s.style.height = `${s.getBoundingClientRect().height}px`;
    s._ph.textContent = s._label;
    s.replaceChildren(s._ph);
    s._loaded = false;
    s._p = null;
  }

  function update() {
    queued = false;
    const edge = bar.getBoundingClientRect().bottom, vh = innerHeight;
    let cur = -1;
    secs.forEach((s, i) => {
      const r = s.getBoundingClientRect();
      if (r.top <= edge) cur = i;
      if (r.bottom > -1.5 * vh && r.top < 2.5 * vh) load(s);
      else if (s._loaded && s !== pinned && (r.bottom < -3 * vh || r.top > 4 * vh)) unload(s);
    });
    pill.hidden = cur < 0;
    if (cur < 0) return;
    const s = secs[cur];
    if (jump) jump.value = s.dataset.id;
    const days = s.getElementsByClassName("day");
    let lo = 0, hi = days.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (days[mid].getBoundingClientRect().top <= edge) lo = mid + 1; else hi = mid;
    }
    pill.textContent = lo ? days[lo - 1].textContent : s.dataset.label;
  }

  const schedule = () => { if (!queued) { queued = true; requestAnimationFrame(update); } };

  function reveal(n) {
    const have = $(`m${n}`);
    if (have) return Promise.resolve(have);
    const s = secs.find((x) => +x.dataset.first <= n && n <= +x.dataset.last);
    if (!s) return Promise.resolve(null);
    pinned = s;
    s.scrollIntoView({ block: "start" });
    return load(s).then(() => $(`m${n}`));
  }

  function goto(hash) {
    const m = /^#m(\d+)$/.exec(hash);
    if (!m) return;
    reveal(+m[1]).then((e) => {
      if (!e) return;
      for (const x of document.querySelectorAll(".msg.jump")) x.classList.remove("jump");
      e.classList.add("jump");
      e.scrollIntoView({ block: "center" });
      schedule();
    });
  }

  const MEDIA_ERRORS = ["", "aborted", "network error", "decode error", "format not supported"];
  timeline.addEventListener("error", (e) => {
    const m = e.target;
    if (!(m instanceof HTMLMediaElement) || m._noted) return;
    m._noted = true;
    const a = el("a", "", "open the file");
    a.href = m.getAttribute("src");
    const why = MEDIA_ERRORS[m.error ? m.error.code : 0] || "unknown error";
    m.after(el("div", "missing", `This browser could not play it (${why}); `, a,
               " to use another player."));
  }, true);

  addEventListener("scroll", schedule, { passive: true });
  addEventListener("resize", schedule);
  addEventListener("hashchange", () => goto(location.hash));
  if (jump) {
    jump.addEventListener("change", () => {
      const s = secs.find((x) => x.dataset.id === jump.value);
      s.scrollIntoView({ block: "start" });
      schedule();
    });
  }
  if (/^#m\d+$/.test(location.hash)) goto(location.hash); else update();
  return { reveal, onLoad: (h) => hooks.push(h) };
}

reportErrors();
initIndex();
const chat = initChat();
if (chat) initFind(chat);
initKeys();
initCopy();
})();
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


def month_of(ms) -> tuple[str, str]:
    if not ms:
        return "unknown", "Unknown date"
    d = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).astimezone()
    return d.strftime("%Y-%m"), d.strftime("%B %Y")


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


VOICE_MESSAGE, GIF = 1, 8


def human_size(n) -> str:
    if not isinstance(n, (int, float)) or n <= 0:
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def missing_reason(att: dict) -> str:
    for column, reason in (("wasTooBig", "too large to download"),
                           ("isCorrupted", "corrupted"),
                           ("pending", "download pending"),
                           ("error", "download failed")):
        if att.get(column):
            return reason
    return "not downloaded"


URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
HOST_RE = re.compile(r"[\w-]+(\.[\w-]+)*\.?")
CLOSERS = {")": "(", "]": "[", "}": "{"}


def trim_url(url: str) -> str:
    """Drop trailing punctuation that belongs to the sentence, not the URL."""
    while url and url[-1] in ".,;:!?'\")]}":
        opener = CLOSERS.get(url[-1])
        if opener and url.count(opener) >= url.count(url[-1]):
            break
        url = url[:-1]
    return url


def valid_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        parts.port
    except ValueError:
        return False
    host = parts.hostname or ""
    return ":" in host or bool(HOST_RE.fullmatch(host))


def linkify(text) -> str:
    """Escape text and turn http(s) URLs in it into links."""
    text = str(text if text is not None else "")
    out, pos = [], 0
    for m in URL_RE.finditer(text):
        url = trim_url(m.group())
        if not valid_url(url):
            continue
        out.append(esc(text[pos:m.start()]))
        out.append(f'<a href="{esc(url)}" target="_blank" rel="noopener noreferrer">{esc(url)}</a>')
        pos = m.start() + len(url)
    out.append(esc(text[pos:]))
    return "".join(out)


def att_href(rel_dir: str, name: str) -> str:
    return esc(f"{rel_dir}/{quote(name)}")


def dims(att: dict | None) -> str:
    """width/height attributes, so the browser reserves the box before loading."""
    w, h = (att or {}).get("width"), (att or {}).get("height")
    if isinstance(w, int) and isinstance(h, int) and w > 0 and h > 0:
        return f' width="{w}" height="{h}"'
    return ""


def render_attachment(att: dict, rel_dir: str) -> str:
    name = att.get("fileName") or ""
    label = esc(name or att.get("contentType") or "attachment")
    size = human_size(att.get("size"))
    caption = f'<div class="caption">{linkify(att["caption"])}</div>' if att.get("caption") else ""
    if not att.get("_exported"):
        reason = att.get("_error") or "not exported"
        detail = f" ({size})" if size else ""
        return f'<div class="missing">[attachment {label}{detail}: {esc(reason)}]</div>' + caption

    href = att_href(rel_dir, att["_exported"])
    ctype = att.get("contentType") or ""
    flags = att.get("flags") or 0
    if ctype.startswith("image/"):
        media = f'<a href="{href}"><img loading="lazy"{dims(att)} src="{href}" alt="{label}"></a>'
    elif ctype.startswith("video/") and flags & GIF:
        media = f'<video{dims(att)} src="{href}" autoplay loop muted playsinline></video>'
    elif ctype.startswith("video/"):
        poster = f' poster="{att_href(rel_dir, att["_poster"])}"' if att.get("_poster") else ""
        preload = "none" if poster else "metadata"
        media = f'<video controls preload="{preload}"{dims(att)}{poster} src="{href}"></video>'
    elif ctype.startswith("audio/"):
        tag = "Voice message" if flags & VOICE_MESSAGE else label
        media = f'<div class="att-label">{tag}</div><audio controls preload="none" src="{href}"></audio>'
    else:
        download = f' download="{esc(name)}"' if name else " download"
        detail = f' <span class="att-size">({size})</span>' if size else ""
        return (f'<a class="att-file" href="{href}"{download}>\U0001F4CE {label}{detail}</a>'
                + caption)
    return f'<div class="att">{media}</div>' + caption


def quote_label(quote_atts) -> str:
    first = quote_atts[0] if quote_atts else {}
    kind = (first.get("contentType") or "").split("/")[0]
    named = {"image": "Photo", "video": "Video", "audio": "Audio"}.get(kind)
    return first.get("fileName") or named or "Attachment"


def render_quote(quote_data: dict, thumbs: list, author: str, rel_dir: str) -> str:
    text = quote_data.get("text") or quote_label(quote_data.get("attachments") or [])
    thumb = next((t for t in thumbs if t.get("_exported")), None)
    img = (f'<img class="qthumb" loading="lazy" alt="" '
           f'src="{att_href(rel_dir, thumb["_exported"])}">' if thumb else "")
    return f'<div class="quote">{img}<b>{esc(author)}</b><br>{esc(text)}</div>'


def render_preview(preview: dict, image: dict | None, rel_dir: str) -> str:
    url = preview.get("url") or ""
    img = (f'<img loading="lazy"{dims(image)} alt="" src="{att_href(rel_dir, image["_exported"])}">'
           if image and image.get("_exported") else "")
    title = esc(preview.get("title") or url)
    desc = f'<div class="pdesc">{esc(preview["description"])}</div>' if preview.get("description") else ""
    inner = f'{img}<div class="ptitle">{title}</div>{desc}<div class="purl">{esc(url)}</div>'
    if url.startswith(("http://", "https://")):
        return (f'<a class="preview" href="{esc(url)}" target="_blank" '
                f'rel="noopener noreferrer">{inner}</a>')
    return f'<div class="preview">{inner}</div>'


def render_sticker(sticker: dict, att: dict | None, rel_dir: str) -> str:
    emoji = esc(sticker.get("emoji") or "")
    if att and att.get("_exported"):
        return (f'<div class="att"><img class="sticker" loading="lazy"{dims(att)} alt="{emoji}" '
                f'src="{att_href(rel_dir, att["_exported"])}"></div>')
    return f'<div class="missing">[sticker {emoji}]</div>'


def render_contact(contact: dict) -> str:
    name = contact.get("name") or {}
    label = (name.get("displayName")
             or " ".join(p for p in (name.get("givenName"), name.get("familyName")) if p)
             or name.get("organization") or "Contact")
    numbers = [n.get("value") for n in contact.get("number") or [] if isinstance(n, dict)]
    detail = ", ".join(n for n in numbers if n)
    return f'<div class="contact">Contact: {esc(label)}{esc(" (" + detail + ")") if detail else ""}</div>'


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


class AttachmentDir:
    """Decrypts a conversation's attachments into att_dir, reusing files that an
    earlier run produced from the same source file."""

    MANIFEST = ".manifest.json"

    def __init__(self, att_root: Path, att_dir: Path, stats: dict):
        self.att_root, self.att_dir, self.stats = att_root, att_dir, stats
        self.old: dict = {}
        try:
            self.old = json.loads((att_dir / self.MANIFEST).read_text())
        except (OSError, ValueError):
            pass
        self.new: dict = {}
        self.taken = {e["name"] for e in self.old.values()} | {
            e["poster"] for e in self.old.values() if e.get("poster")}

    def fingerprint(self, src: Path) -> list:
        st = src.stat()
        return [st.st_size, st.st_mtime_ns]

    def reusable(self, att, src: Path):
        prev = self.old.get(att["path"])
        if not prev or prev.get("src") != self.fingerprint(src):
            return None
        dest = self.att_dir / prev["name"]
        try:
            if dest.stat().st_size != prev["size"]:
                return None
            if prev.get("poster") and not (self.att_dir / prev["poster"]).is_file():
                return None
        except OSError:
            return None
        return prev

    def fresh_name(self, base: str) -> str:
        name, stem, suffix, n = base, Path(base).stem, Path(base).suffix, 1
        while name in self.taken:
            name = f"{stem}_{n}{suffix}"
            n += 1
        self.taken.add(name)
        return name

    def export(self, atts) -> None:
        stats = self.stats

        def fail(att, reason):
            att["_error"] = reason
            stats["failed"] += 1
            stats["reasons"][reason] += 1
            log.warning("    attachment failed (%s): %s %s (%s, message %s)", reason,
                        att.get("fileName") or "", att["path"], att.get("contentType"),
                        att.get("messageId"))

        for att in atts:
            if not att.get("path"):
                att["_error"] = missing_reason(att)
                continue
            src = self.att_root / att["path"]
            if att["attachmentType"] == "long-message" and not src.is_file():
                log.debug("    long message file %s is gone, body already holds the text",
                          att["path"])
                continue
            if not src.is_file():
                fail(att, "file missing on disk")
                continue
            if att["attachmentType"] == "long-message":
                try:
                    att["_text"] = read_stored_file(src, att).decode("utf-8")
                except (OSError, ValueError) as exc:
                    log.debug("    long message %s unusable: %s", att["path"], exc)
                continue
            self.att_dir.mkdir(parents=True, exist_ok=True)

            prev = self.new.get(att["path"]) or self.reusable(att, src)
            if prev:
                self.new[att["path"]] = prev
                att["_exported"] = prev["name"]
                if prev.get("poster"):
                    att["_poster"] = prev["poster"]
                stats["exported"] += 1
                stats["reused"] += 1
                log.debug("    attachment %s reused as %s", att["path"], prev["name"])
                continue

            base = safe_name(att["fileName"], unicode=True) if att.get("fileName") else ""
            if not base or "." not in base:
                ctype = (att.get("contentType") or "").split(";")[0].strip()
                base = (base or att["path"].replace("/", "_")) + (
                    mimetypes.guess_extension(ctype) or ".bin")
            was = self.old.get(att["path"]) or {}
            dest = self.att_dir / (was.get("name") or self.fresh_name(base))
            try:
                copy_stored_file(src, att, dest)
            except Exception as exc:  # noqa: BLE001 - report and continue
                fail(att, str(exc))
                continue
            att["_exported"] = dest.name
            stats["exported"] += 1
            entry = {"name": dest.name, "size": dest.stat().st_size,
                     "src": self.fingerprint(src)}
            if att.get("screenshotPath"):
                poster = self.att_dir / (was.get("poster") or self.fresh_name(
                    dest.stem + ".poster" + (
                        mimetypes.guess_extension(att.get("screenshotContentType") or "")
                        or ".jpg")))
                try:
                    copy_stored_file(self.att_root / att["screenshotPath"], {
                        "localKey": att.get("screenshotLocalKey"),
                        "size": att.get("screenshotSize")}, poster)
                    att["_poster"] = poster.name
                    entry["poster"] = poster.name
                except (OSError, ValueError) as exc:
                    log.debug("    poster %s unusable: %s", att["screenshotPath"], exc)
            self.new[att["path"]] = entry
            log.debug("    attachment %s -> %s", att["path"], dest.name)

    def finish(self) -> None:
        """Drop files no longer referenced and remember what is here for next time."""
        if not self.att_dir.is_dir():
            return
        keep = {self.MANIFEST}
        for entry in self.new.values():
            keep.add(entry["name"])
            if entry.get("poster"):
                keep.add(entry["poster"])
        for f in self.att_dir.iterdir():
            if f.name not in keep:
                f.unlink() if f.is_file() or f.is_symlink() else shutil.rmtree(f, ignore_errors=True)
        (self.att_dir / self.MANIFEST).write_text(json.dumps(self.new))


CHUNK_CAP = 2000
ROW_ESTIMATE_PX = 64


class Chunker:
    """Groups rendered entries into month chunks and hands each finished chunk to emit."""

    def __init__(self, emit):
        self.emit = emit
        self.chunks = []
        self.parts = []
        self.meta = None
        self.last_day = None
        self.ids = set()

    def add(self, ts, html: str, n: int) -> None:
        day = fmt_day(ts)
        if day != self.last_day:
            month, label = month_of(ts)
            if (self.meta is None or month != self.meta["month"]
                    or n - self.meta["first"] >= CHUNK_CAP):
                self.close(n - 1)
                self.open(month, label, n)
            self.parts.append(f'<div class="day">{esc(day)}</div>')
            self.last_day = day
        self.parts.append(html)

    def open(self, month: str, label: str, first: int) -> None:
        chunk_id, k = month, 1
        while chunk_id in self.ids:
            k += 1
            chunk_id = f"{month}-{k}"
        self.ids.add(chunk_id)
        self.meta = {"id": chunk_id, "month": month, "first": first,
                     "label": label if k == 1 else f"{label} (part {k})"}

    def close(self, last: int) -> None:
        if self.meta is None:
            return
        self.meta["last"] = last
        self.meta["count"] = last - self.meta["first"] + 1
        self.emit(self.meta, "\n".join(self.parts))
        self.chunks.append(self.meta)
        self.parts, self.meta = [], None


@dataclass
class Rendered:
    chunks: list
    count: int
    last_ts: int | None
    hits: list = field(default_factory=list)
    media: list = field(default_factory=list)
    links: list = field(default_factory=list)


def reactor_title(reactions, emoji, name_for_cid) -> str:
    if not name_for_cid:
        return ""
    names = [name_for_cid(r.get("fromId")) for r in reactions
             if isinstance(r, dict) and r.get("emoji") == emoji]
    names = [n for n in names if n]
    return f' title="{esc(", ".join(names))}"' if names else ""


def render_conversation(convo, rows, attachments, name_for_aci, att_rel_dir,
                        export_att, emit_chunk, name_for_cid=None,
                        sender_avatar=None) -> Rendered:
    chunker = Chunker(emit_chunk)
    hits = []
    media = []
    links = []
    rendered = 0
    last_ts = None
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
        by_type = defaultdict(list)
        for att in atts:
            by_type[att["attachmentType"]].append(att)
        quote = data.get("quote") if isinstance(data.get("quote"), dict) else None
        sticker = data.get("sticker") if isinstance(data.get("sticker"), dict) else None
        previews = [p for p in data.get("preview") or [] if isinstance(p, dict)]
        contacts = [c for c in data.get("contact") or [] if isinstance(c, dict)]
        has_content = bool(
            body or by_type["attachment"] or quote or sticker or contacts
            or data.get("deletedForEveryone")
        )

        # Anything with no renderable content is either a system event (group
        # update, timer change, call) or nothing worth a bubble.
        if msg_type not in ("incoming", "outgoing") or not has_content:
            text = describe_system(data) or describe_system({"type": msg_type})
            if text:
                rendered += 1
                chunker.add(row["sent_at"], f'<div class="system">{esc(text)}</div>', rendered)
                last_ts = row["sent_at"]
                log.debug("    #%d system: %s", rendered, text)
            continue

        outgoing = msg_type == "outgoing"
        rendered += 1
        last_ts = row["sent_at"]
        log.debug("    #%d %s %s", rendered, msg_type, fmt_time(row["sent_at"]))
        export_att(atts)
        full_text = next((a["_text"] for a in by_type["long-message"] if a.get("_text")), None)
        if full_text and not data.get("deletedForEveryone"):
            body = apply_mentions(full_text, data.get("bodyRanges"), name_for_aci)
        inner = []

        sender_html = ""
        if convo["type"] == "group" and not outgoing:
            who = name_for_aci(row["sourceServiceId"])
            hue = zlib.crc32((row["sourceServiceId"] or who).encode()) % 360
            inner.append(f'<div class="author" style="--h:{hue}">{esc(who)}</div>')
            avatar = sender_avatar(row["sourceServiceId"]) if sender_avatar else None
            sender_html = avatar_html(avatar, who)

        if quote:
            inner.append(render_quote(quote, by_type["quote"],
                                      name_for_aci(quote.get("authorAci")), att_rel_dir))

        if data.get("deletedForEveryone"):
            inner.append('<div class="body deleted">This message was deleted.</div>')
        else:
            if body:
                inner.append(f'<div class="body">{linkify(body)}</div>')
            for att in by_type["attachment"]:
                inner.append(render_attachment(att, att_rel_dir))
                if att.get("_exported"):
                    media.append({"n": rendered, "ts": row["sent_at"], "name": att["_exported"],
                                  "poster": att.get("_poster"), "type": att.get("contentType") or "",
                                  "label": att.get("fileName") or "", "size": att.get("size"),
                                  "flags": att.get("flags") or 0})
            if sticker:
                inner.append(render_sticker(sticker, next(iter(by_type["sticker"]), None),
                                            att_rel_dir))
            for idx, preview in enumerate(previews):
                image = next((a for a in by_type["preview"] if a["orderInMessage"] == idx), None)
                inner.append(render_preview(preview, image, att_rel_dir))
                if (preview.get("url") or "").startswith(("http://", "https://")):
                    links.append({"n": rendered, "ts": row["sent_at"], "url": preview["url"],
                                  "title": preview.get("title") or preview["url"]})
            inner.extend(render_contact(c) for c in contacts)
            searchable = " ".join(t for t in (
                [body] + [a.get("caption") for a in by_type["attachment"]]
                + [p.get("title") for p in previews]) if t)
            if searchable:
                hits.append((rendered, row["sent_at"] or 0, searchable))

        reactions = data.get("reactions") or []
        if reactions:
            tally = Counter(r["emoji"] for r in reactions
                            if isinstance(r, dict) and r.get("emoji"))
            pills = "".join(
                f'<span class="reaction"{reactor_title(reactions, emoji, name_for_cid)}>{esc(emoji)}'
                + (f'<span class="rcount">{n}</span>' if n > 1 else "") + "</span>"
                for emoji, n in tally.items())
            if pills:
                inner.append(f'<div class="reactions">{pills}</div>')

        edits = [e for e in data.get("editHistory") or [] if isinstance(e, dict)][1:]
        if edits and not data.get("deletedForEveryone"):
            versions = "".join(
                f'<div class="edit"><span class="time">{esc(fmt_time(e.get("timestamp")))}</span> '
                f'{linkify(apply_mentions(e.get("body") or "", e.get("bodyRanges"), name_for_aci))}</div>'
                for e in reversed(edits))
            inner.append(f'<details class="edits"><summary>Edited ({len(edits)} earlier '
                         f'{"version" if len(edits) == 1 else "versions"})</summary>{versions}</details>')

        inner.append(f'<div class="time">{esc(fmt_time(row["sent_at"]))}</div>')
        css_class = "msg out" if outgoing else "msg"
        chunker.add(row["sent_at"], f'<div class="{css_class}" id="m{rendered}">'
                    f'{sender_html}<div class="bubble">{"".join(inner)}</div></div>', rendered)

    chunker.close(rendered)
    return Rendered(chunker.chunks, rendered, last_ts, hits, media, links)


def avatar_html(src: str | None, title: str) -> str:
    if src:
        return f'<img class="avatar" src="{esc(src)}" alt="">'
    initial = next((ch for ch in title if ch.isalnum()), "#").upper()
    return f'<span class="avatar ph" aria-hidden="true">{esc(initial)}</span>'


def chat_header(convo, count: int, avatar_src: str | None, chunks, media_link: str = "") -> str:
    jump = "".join(f'<option value="{esc(c["id"])}">{esc(c["label"])} ({c["count"]})</option>'
                   for c in chunks)
    return (
        '<div class="stickybar">'
        f'<div class="chat-head">{avatar_html(avatar_src, convo["title"])}<div>'
        f"<h1>{esc(convo['title'])}</h1>"
        f'<div class="sub">{count} entries &middot; '
        f'{media_link}<a id="back" href="../index.html">back to index</a></div></div></div>'
        '<div class="findbar">'
        '<input id="find" type="search" autocomplete="off" '
        'placeholder="Search this conversation">'
        '<span class="find-count" id="find-count"></span>'
        '<button id="find-prev" type="button" aria-label="Previous match">&uarr;</button>'
        '<button id="find-next" type="button" aria-label="Next match">&darr;</button>'
        f'<select id="jump" aria-label="Jump to month">{jump}</select></div>'
        '<div class="dayfloat" id="dayfloat" hidden></div></div>'
    )


def media_kind(item: dict) -> str:
    if item["type"].startswith(("image/", "video/")):
        return "media"
    return "audio" if item["type"].startswith("audio/") else "files"


def media_goto(chat_href: str, n: int) -> str:
    return f'<a class="goto" href="{esc(chat_href)}#m{n}" title="Show in chat">in chat</a>'


def media_tile(item: dict, rel_dir: str, chat_href: str) -> str:
    href = att_href(rel_dir, item["name"])
    label = esc(item["label"] or item["type"])
    if item["type"].startswith("image/"):
        thumb = f'<img loading="lazy" decoding="async" src="{href}" alt="{label}">'
    elif item["poster"]:
        thumb = (f'<img loading="lazy" decoding="async" src="{att_href(rel_dir, item["poster"])}" '
                 f'alt="{label}"><span class="play">&#9654;</span>')
    else:
        thumb = f'<span class="novideo">{label}</span><span class="play">&#9654;</span>'
    return (f'<div class="tile"><a class="thumb" href="{href}">{thumb}</a>'
            f'{media_goto(chat_href, item["n"])}</div>')


def media_row(item: dict, rel_dir: str, chat_href: str) -> str:
    href = att_href(rel_dir, item["name"])
    when = f'<span class="time">{esc(fmt_time(item["ts"]))}</span>'
    if media_kind(item) == "audio":
        tag = "Voice message" if item["flags"] & VOICE_MESSAGE else esc(item["label"] or "Audio")
        body = (f'<div class="att-label">{tag}</div>'
                f'<audio controls preload="none" src="{href}"></audio>')
    else:
        size = human_size(item["size"])
        detail = f' <span class="att-size">({size})</span>' if size else ""
        name = esc(item["label"] or item["name"])
        body = f'<a class="att-file" href="{href}" download="{esc(item["name"])}">\U0001F4CE {name}{detail}</a>'
    return f'<li>{body}{when}{media_goto(chat_href, item["n"])}</li>'


def render_media_page(convo, media: list, links: list, avatar_src, rel_dir: str,
                      chat_href: str) -> str:
    groups = {"media": [], "audio": [], "files": []}
    for item in reversed(media):
        groups[media_kind(item)].append(item)
    sections = []
    tabs = []

    def add(key, title, count, body):
        if count:
            tabs.append(f'<a href="#{key}">{title} ({count})</a>')
            sections.append(f'<section id="{key}"><h2>{title}</h2>{body}</section>')

    grid = "".join(
        f'<h3 class="month">{esc(label)}</h3><div class="grid">'
        + "".join(media_tile(i, rel_dir, chat_href) for i in items) + "</div>"
        for (_, label), items in ((k, list(g)) for k, g in groupby(
            groups["media"], key=lambda i: month_of(i["ts"]))))
    add("media", "Photos and videos", len(groups["media"]), grid)
    for key, title in (("audio", "Audio"), ("files", "Files")):
        add(key, title, len(groups[key]), '<ul class="rows">' + "".join(
            media_row(i, rel_dir, chat_href) for i in groups[key]) + "</ul>")
    link_rows = "".join(
        f'<li><a href="{esc(l["url"])}" target="_blank" rel="noopener noreferrer">'
        f'{esc(l["title"])}</a><div class="purl">{esc(l["url"])}</div>'
        f'<span class="time">{esc(fmt_time(l["ts"]))}</span>{media_goto(chat_href, l["n"])}</li>'
        for l in reversed(links))
    add("links", "Links", len(links), f'<ul class="rows">{link_rows}</ul>')
    return (f'<div class="chat-head">{avatar_html(avatar_src, convo["title"])}<div>'
            f'<h1>{esc(convo["title"])}: media</h1><div class="sub">'
            f'<a id="back" href="{esc(chat_href)}">back to chat</a></div></div></div>'
            f'<nav class="tabs">{"".join(tabs)}</nav>{"".join(sections)}')


def chat_timeline(chunks, months_rel: str, build: str, out_color: str | None = None) -> str:
    sections = "".join(
        f'<section class="chunk" data-id="{esc(c["id"])}" '
        f'data-src="{esc(months_rel)}/{esc(c["id"])}.js?v={build}" data-first="{c["first"]}" '
        f'data-last="{c["last"]}" data-label="{esc(c["label"])}" '
        f'style="height:{c["count"] * ROW_ESTIMATE_PX}px">'
        f'<div class="chunk-label">{esc(c["label"])} &middot; {c["count"]} entries</div></section>'
        for c in chunks
    )
    style = f' style="--out:{esc(out_color)}"' if out_color else ""
    return (f'<div id="timeline"{style} data-find="{esc(months_rel)}/find.js?v={build}">{sections}</div>'
            '<noscript><p class="missing">Messages are loaded in month chunks by '
            'JavaScript. Enable it to read this conversation.</p></noscript>')


def render_index(summaries, sort: str) -> str:
    key = ((lambda s: s["title"].casefold()) if sort == "name"
           else (lambda s: -(s["last"] or 0)))
    items = "\n".join(
        f'<li data-last="{s["last"] or 0}" data-name="{esc(s["title"])}">'
        f'<a href="{esc(s["link"])}"><span class="convo-id">'
        f'{avatar_html(s["avatar"], s["title"])}'
        f'<span class="convo-name">{esc(s["title"])}</span></span>'
        f'<span class="convo-meta">{s["count"]} msgs &middot; {esc(fmt_time(s["last"]))}</span>'
        f"</a></li>"
        for s in sorted(summaries, key=key)
    )
    options = "".join(
        f'<option value="{value}"{" selected" if value == sort else ""}>{label}</option>'
        for value, label in (("recent", "Last message"), ("name", "Name"))
    )
    return (
        f"<h1>Signal export</h1>"
        f'<div class="sub">{len(summaries)} conversations &middot; '
        f"generated {esc(datetime.now().strftime('%Y-%m-%d %H:%M'))}</div>"
        '<div class="tools"><input id="q" type="search" autocomplete="off" '
        'placeholder="Search names and messages">'
        f'<label>Sort <select id="sort">{options}</select></label></div>'
        f'<ul class="convo-list" id="list">{items}</ul>'
        '<div id="results" hidden></div>'
    )


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(prog="signal_takeout.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", help="Signal data directory (auto-detected by default)")
    ap.add_argument("-o", "--out", default="signal-export", help="output directory")
    ap.add_argument("--key", help="64-char hex SQLCipher key, bypassing config.json")
    ap.add_argument("--safe-storage-password",
                    help="keyring secret protecting 'encryptedKey'")
    ap.add_argument("--no-attachments", action="store_true",
                    help="skip decrypting and copying attachment files")
    ap.add_argument("--export-only", metavar="NAME",
                    help="only export conversations with NAME somewhere in a contact or "
                         "group name (case insensitive)")
    ap.add_argument("--limit", type=int,
                    help="only the N newest messages across all conversations (for testing)")
    ap.add_argument("--since", type=parse_day, metavar="YYYY-MM-DD",
                    help="only messages sent on or after this day (local time)")
    ap.add_argument("--until", type=parse_day, metavar="YYYY-MM-DD",
                    help="only messages sent on or before this day (local time)")
    ap.add_argument("--sort", choices=("recent", "name"), default="recent",
                    help="initial order of the index: last message or name (default: recent)")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="log progress per conversation; repeat (-vv) for every message")
    args = ap.parse_args()
    logging.basicConfig(
        level=(logging.WARNING, logging.INFO, logging.DEBUG)[min(args.verbose, 2)],
        format="%(message)s", stream=sys.stderr,
    )

    if tqdm is None and sys.stderr.isatty():
        print("Tip: pip install tqdm (or use uv run) for progress bars.", file=sys.stderr)

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
    color_defaults = load_chat_color_defaults(conn)
    cid_to_name = {cid: c["title"] for cid, c in convos.items()}
    all_convos = dict(convos)

    def name_for_aci(aci):
        if not aci:
            return "Unknown"
        if our_aci and aci == our_aci:
            return "You"
        return aci_to_name.get(aci, aci)

    if args.export_only:
        needle = args.export_only.casefold()
        matching = {cid: c for cid, c in convos.items()
                    if any(needle in n.casefold() for n in c["names"])}
        if not matching:
            sys.exit(f"No conversation has {args.export_only!r} in its name.")
        print(f"--export-only {args.export_only!r}: {len(matching)} of "
              f"{len(convos)} conversations match.")
        convos = matching

    out_dir = Path(args.out).expanduser()
    build = str(int(time.time()))
    (out_dir / "chats").mkdir(parents=True, exist_ok=True)
    (out_dir / "assets").mkdir(exist_ok=True)
    (out_dir / "assets" / "style.css").write_text(CSS)
    (out_dir / "assets" / "takeout.js").write_text(JS, encoding="utf-8")

    att_root = data_dir / "attachments.noindex"
    avatar_dir = out_dir / "assets" / "avatars"
    aci_to_convo = {c["serviceId"]: c for c in all_convos.values() if c.get("serviceId")}
    sender_cache: dict = {}

    def sender_avatar(aci):
        convo = aci_to_convo.get(aci)
        if not convo:
            return None
        if aci not in sender_cache:
            name = export_avatar(convo, att_root, avatar_dir,
                                 f"{safe_name(convo['title'])}-{convo['id'][:8]}")
            sender_cache[aci] = f"../assets/avatars/{name}" if name else None
        return sender_cache[aci]

    def name_for_cid(cid):
        return cid_to_name.get(cid)

    stats = {"exported": 0, "reused": 0, "failed": 0, "reasons": Counter()}
    skipped_empty = 0
    window = Window(
        start=int(args.since.timestamp() * 1000) if args.since else 0,
        end=int((args.until + timedelta(days=1)).timestamp() * 1000) if args.until else None,
    )
    if args.limit:
        window = replace(window, cutoff=newest_cutoff(conn, convos, args.limit, window))
    cutoff = window.cutoff
    filtered = bool(args.since or args.until or args.limit)
    summaries, search_msgs = [], []

    chats = progress(convos.values(), desc="Conversations", unit="chat", position=0)
    with contextlib.nullcontext() if tqdm is None else logging_redirect_tqdm():
        for pos, convo in enumerate(chats, 1):
            if tqdm is not None:
                chats.set_postfix(files=stats["exported"], refresh=False)
            if filtered and not count_messages(conn, convo["id"], window):
                log.info("[%d/%d] %s: no messages in the selected range",
                         pos, len(convos), convo["title"])
                continue

            slug = f"{safe_name(convo['title'])}-{convo['id'][:8]}"
            att_dir = out_dir / "chats" / f"{slug}_files"
            log.info("[%d/%d] %s", pos, len(convos), convo["title"])
            store = AttachmentDir(att_root, att_dir, stats)

            months_rel = f"{slug}_months"
            months_dir = out_dir / "chats" / months_rel
            shutil.rmtree(months_dir, ignore_errors=True)

            def emit_chunk(meta, html, months_dir=months_dir):
                months_dir.mkdir(exist_ok=True)
                (months_dir / f"{meta['id']}.js").write_text(
                    f"window.__chunk({json.dumps(meta['id'])},"
                    f"{json.dumps(html, ensure_ascii=False)});", encoding="utf-8")

            result = render_conversation(
                convo,
                progress(load_messages(conn, convo["id"], window),
                         total=count_messages(conn, convo["id"], window),
                         desc=convo["title"][:30], unit="msg", leave=False, position=1),
                attachments, name_for_aci,
                f"{slug}_files",
                store.export,
                emit_chunk,
                name_for_cid, sender_avatar,
            )
            if not result.count:
                shutil.rmtree(att_dir, ignore_errors=True)
                log.info("    nothing to render, skipped")
                skipped_empty += 1
                continue
            store.finish()
            log.info("    %d entries, last message %s", result.count, fmt_time(result.last_ts))

            (months_dir / "find.js").write_text(
                "window.__find(" + json.dumps([[n, text] for n, _, text in result.hits],
                                             ensure_ascii=False) + ");", encoding="utf-8")

            link = f"chats/{slug}.html"
            avatar = export_avatar(convo, att_root, out_dir / "assets" / "avatars", slug)
            avatar_src = f"assets/avatars/{avatar}" if avatar else None
            media_link = ""
            if result.media or result.links:
                (out_dir / "chats" / f"{slug}_media.html").write_text(PAGE.format(
                    title=esc(f"{convo['title']}: media"), css=f"../assets/style.css?v={build}",
                    content=render_media_page(convo, result.media, result.links,
                                              f"../{avatar_src}" if avatar_src else None,
                                              f"{slug}_files", f"{slug}.html"),
                    scripts=f'<script src="../assets/takeout.js?v={build}"></script>'))
                media_link = (f'<a href="{esc(slug)}_media.html">Media ('
                              f'{len(result.media) + len(result.links)})</a> &middot; ')
            (out_dir / "chats" / f"{slug}.html").write_text(
                PAGE.format(title=esc(convo["title"]), css=f"../assets/style.css?v={build}",
                            content=(chat_header(convo, result.count,
                                                 f"../{avatar_src}" if avatar_src else None,
                                                 result.chunks, media_link)
                                     + chat_timeline(result.chunks, months_rel, build,
                                                     chat_color_css(convo["color"], color_defaults))),
                            scripts=f'<script src="../assets/takeout.js?v={build}"></script>')
            )
            search_msgs.extend([len(summaries), n, ts, text] for n, ts, text in result.hits)
            summaries.append({"title": convo["title"], "link": link,
                              "count": result.count, "last": result.last_ts,
                              "avatar": avatar_src})
    if tqdm is not None:
        chats.close()

    search_index = {
        "convos": [{"t": s["title"], "u": s["link"], "l": s["last"] or 0, "a": s["avatar"]}
                   for s in summaries],
        "msgs": search_msgs,
    }
    (out_dir / "assets" / "search-index.js").write_text(
        "window.SEARCH_INDEX=" + json.dumps(search_index, ensure_ascii=False,
                                            separators=(",", ":")) + ";",
        encoding="utf-8",
    )
    (out_dir / "index.html").write_text(
        PAGE.format(title="Signal export", css=f"assets/style.css?v={build}",
                    content=render_index(summaries, args.sort),
                    scripts=f'<script src="assets/search-index.js?v={build}" charset="utf-8"></script>'
                            f'<script src="assets/takeout.js?v={build}"></script>')
    )

    conn.close()
    print(f"Wrote {len(summaries)} conversations to {out_dir}/index.html")
    if skipped_empty:
        print(f"Skipped {skipped_empty} conversations with no messages.")
    if cutoff is not None:
        print(f"--limit {args.limit}: exported only the newest messages.")
    if args.since or args.until:
        print(f"Date range: {args.since:%Y-%m-%d}" if args.since else "Date range: start",
              f"to {args.until:%Y-%m-%d}" if args.until else "to now")
    if not args.no_attachments:
        reused = f" ({stats['reused']} reused from an earlier run)" if stats["reused"] else ""
        print(f"Attachments: {stats['exported']} exported{reused}, {stats['failed']} failed.")
        for reason, n in stats["reasons"].most_common():
            print(f"  {n:5d}  {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
