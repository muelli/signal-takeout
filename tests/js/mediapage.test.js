// SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
// SPDX-License-Identifier: AGPL-3.0-or-later
const test = require("node:test");
const assert = require("assert");
const fs = require("fs");
const { chats, chatFile, openPage, sleep } = require("./helpers");

test("media page has tiles, and Escape goes back to the chat", async () => {
  const file = fs.readdirSync(chats).find((f) => f.startsWith("Carol") && f.endsWith("_media.html"));
  let nav = 0;
  const { w, d } = await openPage(chats + file, { onError: (e) => { if (/navigation/i.test(e.message)) nav++; } });
  assert(d.querySelectorAll(".tile").length >= 2);
  assert(d.getElementById("back").href.endsWith(chatFile("Carol")));
  d.body.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
  await sleep(50);
  assert.strictEqual(nav, 1);
  w.close();
});
