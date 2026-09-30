# signal-takeout

Exports a local Signal Desktop database to static HTML: one page per
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
.venv/bin/pip install sqlcipher3-binary cryptography tqdm
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
| `--no-attachments` | Text only; much faster (profile pictures are still exported, long messages stay cut off) |
| `--export-only NAME` | Only conversations with NAME in a contact or group name, case insensitive (profile names count too) |
| `--limit N` | Only the N newest messages across all conversations, for testing |
| `--sort recent\|name` | Initial index order: last message (default) or name |
| `-v`, `--verbose` | Log each conversation as it renders; `-vv` logs every message |

tqdm is optional. With it installed you get a progress bar over conversations and
one over the messages of the current one; the bars switch themselves off when
stderr is not a terminal, and without tqdm the export just runs quietly.

## Browsing

The index lists conversations by last message and can be re-sorted by name from
the page. The search box works offline and matches every word you type.
Conversation names rank above message text, and message hits link straight to
the message. Each conversation page also has its own search box with
previous and next buttons (Enter and Shift+Enter work too). Matching ignores
case and accents. While you scroll a conversation, the current date floats
below its search box.

In a conversation, Ctrl+F (or `/`) jumps to its search box and Escape clears
the search, then goes back to the index.

Long conversations are split into one file per month (or per 2000 entries in
a busy month) under `chats/<name>_months/`. The page loads a month when you
scroll near it and drops it again when you are far away, so the browser never
holds the whole history. A month menu next to the search box jumps around, and
in-page search covers every month. This works from `file://` because chunks
are loaded as scripts, not with `fetch`.

The search data lives in `assets/search-index.js` and the per-conversation
`_months/` folders next to the pages, so keep the export folder together. The
index search still loads all message text for every conversation at once.

## How it gets in

Signal keeps the SQLCipher key in `config.json` next to the database, in one
of two forms:

- **`key`**: plaintext hex. This is what you get with
  `SIGNAL_PASSWORD_STORE=basic`, the default for the Flathub build. Nothing to
  decrypt.
- **`encryptedKey`**: hex of a Chromium `os_crypt` blob sealed by
  Electron's `safeStorage`. On Linux that's AES-128-CBC with a PBKDF2-SHA1
  key (salt `saltysalt`, 1 iteration, IV of 16 spaces). `v10` blobs use the
  hardcoded password `peanuts`; `v11` blobs use a secret from the desktop
  keyring, which the tool tries to read via `secret-tool`, or you pass with
  `--safe-storage-password`. macOS is read from the Keychain via `security`.
  Windows DPAPI is not implemented; use `--key` there.

The database itself is opened in SQLCipher **raw key mode**
(`PRAGMA key = "x'<hex>'"`), no KDF, matching `keyDatabase()` in
`ts/sql/Server.node.ts`.

## Where the data lives

- `conversations.json`: contact and group metadata; titles come from
  `systemGivenName`, else profile name, else phone number.
- `messages`: `body` and `type` are columns; `reactions`, `quote`,
  `bodyRanges` and the rest live in the `json` blob.
- `avatar` and `profileAvatar` in each conversation's JSON point at picture files
  in `attachments.noindex/`, encrypted like attachments (older data is plain).
  The contact or group avatar is preferred, as in Signal, then the profile
  picture.
- `message_attachments`: attachments were moved out of the message JSON in
  schema 1360, so they are read from this table.

Local attachment files under `attachments.noindex/` are individually
encrypted as `IV(16) || AES-256-CBC || HMAC-SHA256(32)`, keyed by the
per-file base64 `localKey` (32 bytes AES + 32 bytes MAC). Files are decrypted
in a stream, so large videos do not need to fit in memory. The output is
written to a temporary file and only renamed into place once the MAC checks
out; failures are reported inline in the HTML and logged with their reason, and the
end of the run summarizes them, rather than aborting the export.

## What it renders

Text, reactions, quoted replies, @-mentions resolved to names, and
delete-for-everyone tombstones. Contact and group pictures show next to names
in the index, in search results and on each conversation page; conversations
without a picture get a letter placeholder. Group updates, timer changes and
calls become one-line system entries. Edit history is not rendered; only the
current version of an edited message.

### Attachments

- Images show inline. Videos get a player with Signal's stored poster frame,
  and videos Signal flagged as GIFs loop silently. Voice notes and other audio
  get a player; anything else is a download link with the original filename
  and size. Captions are shown and searchable.
- An attachment that was never downloaded (too large, pending, failed) shows
  a placeholder with the reason instead of disappearing.
- Long messages are cut off in the database; the full text sits in a separate
  attachment and is what gets rendered and searched.
- Quotes show the thumbnail of the quoted media, link previews show as cards
  (only `http` and `https` links are clickable), stickers show as images, and
  shared contacts show their name and numbers.
- Files keep their original name (non-ASCII characters included) and get their
  extension from the MIME type when the name has none. Exporting again into the
  same folder replaces a conversation's attachment folder instead of adding
  duplicates.

## Testing without real data

`make_fixture.py` builds a synthetic data directory with the same schema,
including genuinely encrypted attachments (video, PDF, voice note, GIF, a long
message, previews and more, all in one conversation called Carol):

```sh
uv run make_fixture.py /tmp/fake-signal
uv run signal_takeout.py --data-dir /tmp/fake-signal -o /tmp/sig-export -v
```

## License

AGPL-3.0-or-later, REUSE compliant. See `LICENSES/`.
