#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["sqlcipher3-binary", "cryptography"]
# ///
"""Export a local Signal Desktop database to static HTML.

Reads ~/.var/app/org.signal.Signal/config/Signal (or the native equivalent),
decrypts db.sqlite with the key Signal stores in config.json, and writes one
HTML file per conversation plus an index with offline search.

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
from dataclasses import dataclass, field
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


def load_messages(conn, conversation_id: str):
    return conn.execute(
        """
        SELECT id, json, body, type, sent_at, received_at, sourceServiceId, isErased
        FROM messages
        WHERE conversationId = ?
        ORDER BY received_at ASC, sent_at ASC
        """,
        (conversation_id,),
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
[hidden] { display:none !important; }
mark { background:#ffd54a; color:#000; border-radius:2px; }
.tools { display:flex; gap:.5rem; align-items:center; margin-bottom:1rem; }
.tools input { flex:1; min-width:0; padding:.45rem .7rem;
  border:1px solid var(--line); border-radius:8px; background:var(--card);
  color:var(--fg); font:inherit; }
.tools select { padding:.4rem .6rem; border:1px solid var(--line);
  border-radius:8px; background:var(--card); color:var(--fg); font:inherit; }
.msg { scroll-margin-top:4rem; }
.msg:target .bubble { outline:2px solid #f5a623; }
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
        const a = el("a", "", el("span", "convo-name", highlight(c.t, ranges(c.t, toks))),
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

initIndex();
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


def export_attachments(atts, att_root: Path, att_dir: Path, stats: dict) -> None:
    for att in atts:
        src = att_root / att["path"]
        if not src.is_file():
            att["_error"] = "file missing on disk"
            stats["failed"] += 1
            continue
        try:
            raw = src.read_bytes()
            blob = (decrypt_attachment(raw, att["localKey"], att["size"])
                    if att.get("localKey") else raw)
        except Exception as exc:  # noqa: BLE001 - report and continue
            att["_error"] = str(exc)
            stats["failed"] += 1
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
        stats["exported"] += 1
        log.debug("    attachment %s -> %s", att["path"], dest.name)


@dataclass
class Rendered:
    html: str
    count: int
    last_ts: int | None
    hits: list = field(default_factory=list)


def render_conversation(convo, rows, attachments, name_for_aci, att_rel_dir,
                        export_att, budget=None) -> Rendered:
    parts = []
    hits = []
    rendered = 0
    last_ts = None
    last_day = None
    for seen, row in enumerate(rows, 1):
        if budget is not None and rendered >= budget:
            break
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
                last_ts = row["sent_at"]
                log.debug("    #%d system: %s", rendered, text)
            continue

        day = fmt_day(row["sent_at"])
        if day != last_day:
            parts.append(f'<div class="day">{esc(day)}</div>')
            last_day = day

        outgoing = msg_type == "outgoing"
        rendered += 1
        last_ts = row["sent_at"]
        log.debug("    #%d %s %s", rendered, msg_type, fmt_time(row["sent_at"]))
        export_att(atts)
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
                hits.append((rendered, row["sent_at"] or 0, body))
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
        parts.append(f'<div class="{css_class}" id="m{rendered}">'
                     f'<div class="bubble">{"".join(inner)}</div></div>')

    header = (
        f"<h1>{esc(convo['title'])}</h1>"
        f'<div class="sub">{rendered} entries &middot; '
        f'<a href="../index.html">back to index</a></div>'
    )
    return Rendered(header + "\n".join(parts), rendered, last_ts, hits)


def render_index(summaries, sort: str) -> str:
    key = ((lambda s: s["title"].casefold()) if sort == "name"
           else (lambda s: -(s["last"] or 0)))
    items = "\n".join(
        f'<li data-last="{s["last"] or 0}" data-name="{esc(s["title"])}">'
        f'<a href="{esc(s["link"])}"><span class="convo-name">{esc(s["title"])}</span>'
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
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", help="Signal data directory (auto-detected by default)")
    ap.add_argument("-o", "--out", default="signal-export", help="output directory")
    ap.add_argument("--key", help="64-char hex SQLCipher key, bypassing config.json")
    ap.add_argument("--safe-storage-password",
                    help="keyring secret protecting 'encryptedKey'")
    ap.add_argument("--no-attachments", action="store_true",
                    help="skip decrypting and copying attachment files")
    ap.add_argument("--limit", type=int,
                    help="stop after N rendered messages across all conversations (for testing)")
    ap.add_argument("--sort", choices=("recent", "name"), default="recent",
                    help="initial order of the index: last message or name (default: recent)")
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
    (out_dir / "assets" / "takeout.js").write_text(JS, encoding="utf-8")

    att_root = data_dir / "attachments.noindex"
    stats = {"exported": 0, "failed": 0}
    skipped_empty = 0
    remaining = args.limit
    summaries, search_msgs = [], []

    for pos, convo in enumerate(convos.values(), 1):
        if remaining is not None and remaining <= 0:
            log.info("Limit of %d messages reached, %d conversations not visited",
                     args.limit, len(convos) - pos + 1)
            break

        slug = f"{safe_name(convo['title'])}-{convo['id'][:8]}"
        att_dir = out_dir / "chats" / f"{slug}_files"
        log.info("[%d/%d] %s", pos, len(convos), convo["title"])

        result = render_conversation(
            convo, load_messages(conn, convo["id"]), attachments, name_for_aci,
            f"{slug}_files",
            lambda atts, att_dir=att_dir: export_attachments(atts, att_root, att_dir, stats),
            remaining,
        )
        if not result.count:
            log.info("    nothing to render, skipped")
            skipped_empty += 1
            continue
        if remaining is not None:
            remaining -= result.count
        log.info("    %d entries, last message %s", result.count, fmt_time(result.last_ts))

        link = f"chats/{slug}.html"
        (out_dir / "chats" / f"{slug}.html").write_text(
            PAGE.format(title=esc(convo["title"]), css="../assets/style.css",
                        content=result.html, scripts="")
        )
        search_msgs.extend([len(summaries), n, ts, text] for n, ts, text in result.hits)
        summaries.append({"title": convo["title"], "link": link,
                          "count": result.count, "last": result.last_ts})

    search_index = {
        "convos": [{"t": s["title"], "u": s["link"], "l": s["last"] or 0} for s in summaries],
        "msgs": search_msgs,
    }
    (out_dir / "assets" / "search-index.js").write_text(
        "window.SEARCH_INDEX=" + json.dumps(search_index, ensure_ascii=False,
                                            separators=(",", ":")) + ";",
        encoding="utf-8",
    )
    (out_dir / "index.html").write_text(
        PAGE.format(title="Signal export", css="assets/style.css",
                    content=render_index(summaries, args.sort),
                    scripts='<script src="assets/search-index.js" charset="utf-8"></script>'
                            '<script src="assets/takeout.js"></script>')
    )

    conn.close()
    print(f"Wrote {len(summaries)} conversations to {out_dir}/index.html")
    if skipped_empty:
        print(f"Skipped {skipped_empty} conversations with no messages.")
    if remaining is not None and remaining <= 0:
        print(f"Stopped after --limit {args.limit} rendered messages.")
    if not args.no_attachments:
        print(f"Attachments: {stats['exported']} exported, {stats['failed']} failed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
