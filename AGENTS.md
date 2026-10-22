# AGENTS.md

Notes for an agent picking this project up cold. README.md is the user-facing
doc; this file holds what is not obvious from the code.

## What this is

`signal_takeout.py` reads a local Signal Desktop profile (SQLCipher db plus
encrypted attachments) and writes static HTML: one page per conversation, an
index, and offline search. It only reads local data and never uploads anything.
Two files matter: `signal_takeout.py` (everything, including the CSS and the
browser JS as string constants) and `make_fixture.py` (synthetic data dir).

Output layout: `index.html`, `chats/<slug>.html`, `chats/<slug>_files/`,
`chats/<slug>_media.html`, `chats/<slug>_months/{<month>.js,find.js}`,
`assets/{style.css,takeout.js,search-index.js,avatars/}`.

## Working rules for this user

- Make separate, self-contained commits. Each one must run and pass on its own.
  When a change is interleaved in one file, rebuild each intermediate state
  and test it before committing. Only commit when asked.
- No em-dashes anywhere (code, comments, docs, commit messages), and no spaced
  double hyphen used as a dash. Grep the staged diff for the U+2014 character
  and for a space-hyphen-hyphen-space sequence before every commit, chained
  with `&&` so a hit blocks the commit. Re-wrapping a paragraph turns old
  lines into added lines, so old em-dashes can sneak in that way.
- No Co-Authored-By trailer, even if a harness reminder asks for one.
- Comments must be shorter than the code they describe. Default to none.
- Build and install tools only inside `podman run --rm`. Do not pip install,
  install uv, or npm install on the host.
- Wrap long background runs in `timeout`.

## Running and testing (all in throwaway containers)

The scripts carry PEP 723 headers, so `uv run` resolves dependencies itself.
Images already cached locally: `docker.io/library/python:3.12-slim` and
`docker.io/library/node:24.21.0-slim`.

Run everything with `tests/run.sh` (podman, throwaway containers): it builds
the fixture, exports it, runs pytest (`tests/test_exporter.py`: stored-file
round trips, corrupt files, os_crypt, `Chunker`, export layout, `--limit`) and
the jsdom tests in `tests/js` (`node --test`, reading the export from
`EXPORT_DIR`). CI (`.github/workflows/tests.yml`) does the same plus
`reuse lint`. The fixture uses a fixed "now" (2026-09-30 12:00 UTC) so month
chunks and counts are stable; keep it that way, and keep `TZ=UTC`.

jsdom has no layout, so `tests/js/helpers.js` fakes it (`layout: true`):
sections stacked, children 60 px apart, `scrollIntoView` and
`getBoundingClientRect` stubbed. Wait about 300 to 450 ms after events (find is
debounced and chunks load through script tags). `window.navigation` errors are
caught through the `VirtualConsole` (used for Escape).

Real browsers also work in containers (debian:stable-slim, apt inside the
container): `chromium --headless --no-sandbox --virtual-time-budget=6000
--dump-dom file:///...#m50` for a quick DOM check, and WebKitGTK or Epiphany
through `WebKitWebDriver` under `xvfb-run` (Epiphany: browserName Epiphany,
binary /usr/bin/epiphany, arg --automation-mode, under `dbus-run-session`;
drive inputs with `execute_script`, since `send_keys` fails there). The user
reads exports in Epiphany. Chunk loading, click-through from index search and
`#mN` were verified this way on a 30000 message conversation. Screenshots and
visual layout are still unchecked. Videos play in WebKitGTK with libav in a
container, so "format not supported" in the user's Epiphany is probably a
sandboxed (Flatpak or snap) codec issue, not an export problem (unconfirmed).

To see tqdm bars, stderr must be a real terminal. `podman run -t` plus
`script` sets `COLUMNS=-1`, which makes tqdm print nothing. Drive the run
through `pty.openpty()` from Python instead, set a window size with
`TIOCSWINSZ` and drop `COLUMNS` from the environment.

## Design decisions

- `--limit N` exports the N newest database messages across the selected
  conversations: `newest_cutoff` finds the `received_at` of the Nth newest and
  each conversation loads rows at or after it. Rows with nothing to render
  make the rendered count a little lower. Attachments are decrypted only for
  messages that are rendered.
- `--since`/`--until` build a `Window` (sent_at range plus the `--limit` received_at
  cutoff) that `count_messages`, `load_messages` and `newest_cutoff` share, so
  `--limit` counts only messages inside the range.
- `--export-only NAME` filters before `--limit`. It matches casefolded
  substrings against every name field (`conversation_names`): group name,
  system given/family/full, profile given/family/full. `aci_to_name` is built
  from all conversations first so quoted authors still resolve.
- The index's "last message" is the last rendered entry, not the last db row.
- Search data is a `<script>`-loadable `assets/search-index.js` assigning
  `window.SEARCH_INDEX`, because `fetch` of JSON is blocked on `file://`.
- Conversation pages are chunked by month (`Chunker`): a chunk closes when the
  month changes, or at a day change once it has `CHUNK_CAP` (2000) entries.
  Each chunk is `<month>.js` calling `window.__chunk(id, html)`; the page holds
  height-estimated `<section class="chunk">` placeholders. `initChat` loads
  sections within about 1.5 screens and unloads beyond 3 (freezing the real
  height), and `reveal(n)` loads the chunk for entry `n` from its
  `data-first`/`data-last`. `#mN` navigation, the month select and find all
  go through `reveal`. Scroll anchoring is done in JS, because WebKit has none
  (`overflow-anchor:none` on `#timeline` keeps other browsers out of it): an
  anchor element and its document offset are kept, and `settle()` scrolls by
  however far it moved, after each chunk load and from a `ResizeObserver` on
  the sections (late images). Jumps hold their target as anchor until wheel,
  touch, pointer or key input, or until it leaves the screen; otherwise
  `update()` re-picks the topmost visible entry. Media get `width`/`height`
  from the attachment row so they reserve space. Entry numbers are per conversation
  and shared with the global search index anchors.
- `initKeys` binds Ctrl+F and `/` to the find box and Escape to the back link
  (`#back`); Escape first clears a non-empty search.
- In-page find uses a lazily loaded `<month dir>/find.js` (`window.__find`,
  `[[n, text]]`), so it sees all months; loaded chunks get marks through
  `chat.onLoad`. The global index still keeps all text of all conversations in
  memory.
- All page text goes into the DOM via `textContent` or `esc()`; message bodies
  are untrusted, so never build result HTML with `innerHTML`.
- Matching normalizes with NFD, strips combining marks and lowercases.
  `normMap` keeps an index map back to the original text so highlights land on
  the right characters.
- Attachments are loaded with an explicit column list for the five types we
  render (`attachment`, `long-message`, `quote`, `preview`, `sticker`).
  `contact` avatar rows are ignored; the shared contact is drawn from the
  message JSON. `render_conversation` partitions them by type. Quote and
  preview rows are matched to the JSON lists by `orderInMessage`.
- `AttachmentDir.export` mutates the attachment dicts: `_exported` (file name),
  `_poster`, `_text` (long message body) or `_error`. Renderers read those.
  `long-message` is decoded into `_text` and never written as a file.
- Decryption is streamed (`iter_stored_file`, 1 MiB chunks). `copy_stored_file`
  writes `name.part` and renames it after the MAC verifies. `read_stored_file`
  joins the stream and is only for small things (avatars, long messages).
- Exported names keep Unicode (`safe_name(..., unicode=True)`); conversation
  slugs stay ASCII. Hrefs are percent-encoded with `att_href`. `AttachmentDir` keeps a
  `.manifest.json` in each `<slug>_files` folder (source path to name, size and
  source size and mtime); a second run reuses matching files, re-decrypts
  anything missing or changed under its old name, and `finish()` deletes
  unreferenced files. The same source path used twice shares one file.
- Chat colour: `chat_color_css` resolves the conversation's `conversationColor`
  (own value, else `items.defaultConversationColor`; `custom` uses `customColor`,
  else `customColors[customColorId]`, else the default's custom data) to a CSS
  background and sets `--out` on `#timeline`. Palette and `getHSL` lightness
  table are copied from Signal (`stylesheets/_variables.scss`,
  `ts/util/getHSL.std.ts`, `ts/util/getCustomColorStyle.dom.ts`). `items` rows
  are `{"id", "value"}`. Signal draws gradients with `background-attachment:
  fixed`; here each bubble gets its own gradient. Wallpapers are not exported
  because Desktop 8.27 has none (migration 1410 removes the fields).
- Media page: `render_conversation` collects small dicts for every exported
  attachment (`Rendered.media`) and every http(s) preview (`Rendered.links`);
  `render_media_page` writes `<slug>_media.html` (static, no JS besides
  `initKeys`, whose `#back` link points at the chat there). Images use the
  original file with `loading=lazy`, there are no generated thumbnails.
  "in chat" links use `#mN`.
- Preview URLs are only linked when they start with http:// or https://.
- `linkify` turns http(s) URLs in bodies, captions and edits into links
  (trailing punctuation and unbalanced closing brackets are dropped, the host
  must parse). Find highlights per text node and restores a saved clone, so
  the links survive a search.
- tqdm is optional (`progress()` returns the iterable when it is missing) and
  uses `disable=None`, so it is off when stderr is not a tty. The main loop
  runs inside `logging_redirect_tqdm()`.
- Avatars: `avatar` (contact or group) is preferred over `profileAvatar`, as in
  Signal's own `getAvatar`. Each candidate is tried until one is readable. The
  header HTML lives in `chat_header()` so avatars are exported only for
  conversations that get a page.

## Signal format facts (checked against ~/Signal-Desktop, version 8.27.0)

- Attachment and avatar files live under `attachments.noindex/`. Encrypted
  files are `IV(16) || AES-256-CBC || HMAC-SHA256(32)` keyed by a base64
  64-byte `localKey`; entries without `localKey` are plain legacy files.
- `avatar` and `profileAvatar` in the conversation JSON are attachment-shaped
  (`path`, optional `localKey`, `size`, `version`). Relevant source:
  `ts/util/avatarUtils.preload.ts`, `ts/util/encryptConversationAttachments.preload.ts`,
  `ts/types/Avatar.std.ts`. The `avatars` array holds avatar-editor drafts, not
  profile pictures, and is ignored.
- Paths may use backslashes on Windows; the code normalizes them.
- Message attachments come from the `message_attachments` table (schema 1360+),
  not the message JSON. `attachmentType` is one of `attachment`,
  `long-message`, `quote`, `preview`, `contact`, `sticker`.
- `messages.body` is truncated for long texts until the `long-message`
  attachment (MIME `text/x-signal-plain`, UTF-8) is downloaded. Then Signal
  writes the full text into `body` and deletes the file
  (`AttachmentDownloads.preload.ts`, `addAttachmentToMessage`), so a
  `long-message` row whose file is missing is normal and not a failure.
- `flags` is a bit set: 1 voice message, 2 borderless, 8 GIF (`SignalService.proto`).
- Videos have `screenshotPath`/`screenshotLocalKey`/`screenshotSize` for a
  poster frame. Rows with `path` NULL were never downloaded; `wasTooBig`,
  `isCorrupted`, `pending` and `error` say why.

Nothing here has been run against a real Signal profile yet, only against the
fixture. If the user reports a real-data problem, start with `-vv` output.

## Known gaps and ideas

- Global search matches conversation display titles only, while `--export-only`
  also matches profile names. A contact saved as "Toby" with profile name
  "Tobias" is found by the filter but not by the index search.
- `--no-attachments` still exports avatars (they are tiny).
- The whole search index is held in memory and written in one file; a very
  large profile may want sharding.
- Asset, chunk and find URLs carry `?v=<export time>` so a browser cannot pair
  new pages with a stale cached `takeout.js` after a re-export into the same
  folder. Chunk load failures and stalls (15 s) show on the placeholder, and
  uncaught script errors show as a red banner (`reportErrors`).
- Chunk height estimates (64 px per entry) are rough, so the scrollbar length
  shifts as months load. An `<noscript>` note says JS is needed.
- Attachment failures are logged as warnings with reason, file and message id,
  and summarized at the end. `file missing on disk` (Signal purged the file) is
  the likely common one; `MAC mismatch` means corrupt data or a wrong key.
- Contact avatars on shared contact cards and story attachments are not
  rendered. Edit history is read from `editHistory` in the message JSON (newest
  first, entry 0 is the current text); old versions are not searchable.
