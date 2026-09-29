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
`chats/<slug>_months/{<month>.js,find.js}`,
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

Exporter against the fixture:

```sh
podman run --rm -v "$PWD":/work:ro -v /tmp/out:/out -w /tmp docker.io/library/python:3.12-slim sh -c 'pip install -q uv && uv run /work/make_fixture.py /out/fake && uv run /work/signal_takeout.py --data-dir /out/fake -o /out/export -vv'
```

The fixture has Dave, a conversation over four months, for the chunk tests.
The browser JS has no committed tests. To check it, install `jsdom` inside the
node image, load `export/index.html` with `JSDOM.fromFile(..., { runScripts:
"dangerously", resources: "usable" })`, wait for `load`, stub
`Element.prototype.scrollIntoView` (jsdom lacks it), set an input's `value`,
dispatch an `input` event and wait about 200 ms (search is debounced 120 ms).
Things worth asserting: sort order, name hits before message hits, accent
insensitive matching, anchors like `chats/x.html#m2`, find count and next/prev,
avatar `src` files exist. Remember the export dir must come from a run without
`--limit`, or the pages will have too few conversations.

jsdom has no layout, so chunk tests fake it: give `.stickybar`, `.chunk`,
`.day` and `.msg` a `getBoundingClientRect` computed from a virtual scrollY
(sections stacked, loaded ones taller than placeholders), stub `scrollIntoView`
to set that scrollY, set `innerHeight`, and open pages with `#mN` in the `url`
option to test goto. Assert which `.chunk` elements are loaded (`_loaded`)
after scrolling, that `#mN` gets the `jump` class, and find counts
("1 / 60", prev wraps to the newest). Wait about 300 to 450 ms after events
(find is debounced and chunks load through script tags).
`Chunker` can be unit tested by importing the module with a small `CHUNK_CAP`.
No real browser has been used yet, so CSS, sticky positioning and scroll
compensation are unseen.

To see tqdm bars, stderr must be a real terminal. `podman run -t` plus
`script` sets `COLUMNS=-1`, which makes tqdm print nothing. Drive the run
through `pty.openpty()` from Python instead, set a window size with
`TIOCSWINSZ` and drop `COLUMNS` from the environment.

Streaming decryption is worth re-testing after any change to
`iter_stored_file`: round trips at sizes 0, 1, 15, 16, 17, 1 MiB minus 1,
1 MiB and above, with size given, missing, too large and zero-padded, plus a
flipped byte, a truncated file and a tiny file, which must all raise
`ValueError` and leave no `.part` file.

## Design decisions

- `--limit N` exports the N newest database messages across the selected
  conversations: `newest_cutoff` finds the `received_at` of the Nth newest and
  each conversation loads rows at or after it. Rows with nothing to render
  make the rendered count a little lower. Attachments are decrypted only for
  messages that are rendered.
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
  height), compensates `scrollBy` when a loaded section is above the viewport
  (`overflow-anchor:none` on `#timeline`), and `reveal(n)` loads the chunk for
  entry `n` from its `data-first`/`data-last`. `#mN` navigation, the month
  select and find all go through `reveal`. Entry numbers are per conversation
  and shared with the global search index anchors.
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
- `export_attachments` mutates the attachment dicts: `_exported` (file name),
  `_poster`, `_text` (long message body) or `_error`. Renderers read those.
  `long-message` is decoded into `_text` and never written as a file.
- Decryption is streamed (`iter_stored_file`, 1 MiB chunks). `copy_stored_file`
  writes `name.part` and renames it after the MAC verifies. `read_stored_file`
  joins the stream and is only for small things (avatars, long messages).
- Exported names keep Unicode (`safe_name(..., unicode=True)`); conversation
  slugs stay ASCII. Hrefs are percent-encoded with `att_href`. A conversation's
  `<slug>_files` folder is deleted before it is exported again.
- Preview URLs are only linked when they start with http:// or https://.
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
- No per-message avatars next to incoming messages in group chats.
- `--no-attachments` still exports avatars (they are tiny).
- The whole search index is held in memory and written in one file; a very
  large profile may want sharding.
- Chunk height estimates (64 px per entry) are rough, so the scrollbar length
  shifts as months load. An `<noscript>` note says JS is needed.
- Attachment failures are logged as warnings with reason, file and message id,
  and summarized at the end. `file missing on disk` (Signal purged the file) is
  the likely common one; `MAC mismatch` means corrupt data or a wrong key.
- Contact avatars on shared contact cards, edit history and story attachments
  are not rendered.
- There is no committed test suite; the fixture plus manual runs above are it.
