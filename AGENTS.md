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

The browser JS has no committed tests. To check it, install `jsdom` inside the
node image, load `export/index.html` with `JSDOM.fromFile(..., { runScripts:
"dangerously", resources: "usable" })`, wait for `load`, stub
`Element.prototype.scrollIntoView` (jsdom lacks it), set an input's `value`,
dispatch an `input` event and wait about 200 ms (search is debounced 120 ms).
Things worth asserting: sort order, name hits before message hits, accent
insensitive matching, anchors like `chats/x.html#m2`, find count and next/prev,
avatar `src` files exist. Remember the export dir must come from a run without
`--limit`, or the pages will have too few conversations.

## Design decisions

- `--limit N` is an overall budget of rendered entries across all conversations
  (system entries count). Messages are read lazily from a cursor; attachments
  are decrypted only for messages that are actually rendered.
- `--export-only NAME` filters before `--limit`. It matches casefolded
  substrings against every name field (`conversation_names`): group name,
  system given/family/full, profile given/family/full. `aci_to_name` is built
  from all conversations first so quoted authors still resolve.
- The index's "last message" is the last rendered entry, not the last db row.
- Search data is a `<script>`-loadable `assets/search-index.js` assigning
  `window.SEARCH_INDEX`, because `fetch` of JSON is blocked on `file://`.
  Conversation pages search their own DOM and need no index.
- All page text goes into the DOM via `textContent` or `esc()`; message bodies
  are untrusted, so never build result HTML with `innerHTML`.
- Matching normalizes with NFD, strips combining marks and lowercases.
  `normMap` keeps an index map back to the original text so highlights land on
  the right characters.
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
  not the message JSON.

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
- README.md still has several em-dashes from the initial commit.
- There is no committed test suite; the fixture plus manual runs above are it.
