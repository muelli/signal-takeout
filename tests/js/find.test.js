// SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
// SPDX-License-Identifier: AGPL-3.0-or-later
const { test } = require("node:test");
const assert = require("assert");
const { sleep, openChat, loaded, type } = require("./helpers");

test("find covers unloaded months and wraps", async () => {
  const { w, d } = await openChat("Dave", { layout: true });
  await sleep(300);
  assert.strictEqual(await type(w, d, "archive-needle"), "1 / 1");
  let cur = d.querySelector(".msg.cur");
  assert(cur && cur.querySelector("mark"), "hit is marked and current");

  assert.strictEqual(await type(w, d, "message 55"), "1 / 1");
  cur = d.querySelector(".msg.cur");
  assert(cur.textContent.includes("Dave message 55") && loaded(d).includes("2026-08"));
  assert.strictEqual(d.querySelectorAll(".msg.cur").length, 1);

  assert.strictEqual(await type(w, d, "dave"), "1 / 60");
  d.getElementById("find-prev").click(); await sleep(300);
  assert.strictEqual(d.getElementById("find-count").textContent, "60 / 60");
  assert(d.querySelector(".msg.cur").textContent.includes("Dave message 59"));

  assert.strictEqual(await type(w, d, "zzzz"), "0 / 0");
  assert.strictEqual(await type(w, d, ""), "");
  assert(!d.querySelector("mark") && !d.querySelector(".msg.cur"));
  w.close();
});

test("find sees long messages, captions and previews", async () => {
  const { w, d } = await openChat("Carol", { layout: true });
  await sleep(300);
  assert.strictEqual(await type(w, d, "needle-in-the-long-text"), "1 / 1");
  assert.strictEqual(await type(w, d, "dog beach"), "1 / 1");
  assert(d.querySelector(".msg.cur .caption mark"), "caption highlighted");
  assert.strictEqual(await type(w, d, "example domain"), "1 / 1");
  w.close();
});

test("find marks inside links and keeps them", async () => {
  const { w, d } = await openChat("Carol", { layout: true });
  await sleep(300);
  assert.strictEqual(await type(w, d, "example.com"), "1 / 1");
  const a = d.querySelector(".msg.cur .body a");
  assert(a && a.querySelector("mark"), "link text highlighted");
  assert.strictEqual(a.textContent, "https://example.com/a");
  await type(w, d, "");
  const back = d.querySelector(".body a[href='https://example.com/a']");
  assert(back && !back.querySelector("mark"));
  w.close();
});

test("find sees poll questions and options", async () => {
  const { w, d } = await openChat("Weekend", { layout: true });
  await sleep(300);
  assert.strictEqual(await type(w, d, "saturday sunday"), "1 / 1");
  assert(d.querySelector(".msg.cur .poll-q mark") && d.querySelector(".msg.cur .popt mark"));
  w.close();
});
