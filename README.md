# signal-takeout

Exports a local Signal Desktop database to static HTML — one page per
conversation plus an index, with attachments decrypted alongside.

Reads only your own installation. Nothing leaves the machine.

## Use

With [uv](https://docs.astral.sh/uv/), dependencies are declared in the script
header and installed on demand:

```sh
uv run signal_takeout.py -o ~/signal-export
xdg-open ~/signal-export/index.html
```

Without uv:

```sh
python3 -m venv .venv
.venv/bin/pip install sqlcipher3-binary cryptography
.venv/bin/python signal_takeout.py -o ~/signal-export
```

**Close Signal first.** The database is opened read-only, but Signal writes
through a WAL; exporting while it runs can miss recent messages.

Useful flags:

| Flag | Purpose |
| --- | --- |
| `--data-dir DIR` | Point at a specific profile (auto-detected otherwise) |
| `--key HEX` | Supply the 64-char SQLCipher key directly |
| `--safe-storage-password P` | Keyring secret, when the key is sealed |
| `--no-attachments` | Text only; much faster |
| `--limit N` | Stop after N rendered messages across all conversations, for testing |
| `--sort recent\|name` | Initial index order: last message (default) or name |
| `-v`, `--verbose` | Log each conversation as it renders; `-vv` logs every message |

## Browsing

The index lists conversations by last message and can be re-sorted by name from
the page.

## How it gets in

Signal keeps the SQLCipher key in `config.json` next to the database, in one
of two forms:

- **`key`** — plaintext hex. This is what you get with
  `SIGNAL_PASSWORD_STORE=basic`, the default for the Flathub build. Nothing to
  decrypt.
- **`encryptedKey`** — hex of a Chromium `os_crypt` blob sealed by
  Electron's `safeStorage`. On Linux that's AES-128-CBC with a PBKDF2-SHA1
  key (salt `saltysalt`, 1 iteration, IV of 16 spaces). `v10` blobs use the
  hardcoded password `peanuts`; `v11` blobs use a secret from the desktop
  keyring, which the tool tries to read via `secret-tool`, or you pass with
  `--safe-storage-password`. macOS is read from the Keychain via `security`.
  Windows DPAPI is not implemented — use `--key` there.

The database itself is opened in SQLCipher **raw key mode**
(`PRAGMA key = "x'<hex>'"`), no KDF, matching `keyDatabase()` in
`ts/sql/Server.node.ts`.

## Where the data lives

- `conversations.json` — contact and group metadata; titles come from
  `systemGivenName`, else profile name, else phone number.
- `messages` — `body` and `type` are columns; `reactions`, `quote`,
  `bodyRanges` and the rest live in the `json` blob.
- `message_attachments` — attachments were moved out of the message JSON in
  schema 1360, so they are read from this table.

Local attachment files under `attachments.noindex/` are individually
encrypted as `IV(16) || AES-256-CBC || HMAC-SHA256(32)`, keyed by the
per-file base64 `localKey` (32 bytes AES + 32 bytes MAC). The MAC is verified
before writing anything out; failures are reported inline in the HTML rather
than aborting the export.

## What it renders

Text, attachments (images, video and audio inline; everything else as a
link), reactions, quoted replies, @-mentions resolved to names, and
delete-for-everyone tombstones. Group updates, timer changes and calls become
one-line system entries. Edit history is not rendered — only the current
version of an edited message.

## Testing without real data

`make_fixture.py` builds a synthetic data directory with the same schema,
including a genuinely encrypted attachment:

```sh
uv run make_fixture.py /tmp/fake-signal
uv run signal_takeout.py --data-dir /tmp/fake-signal -o /tmp/sig-export -v
```
