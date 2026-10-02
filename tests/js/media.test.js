// SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
// SPDX-License-Identifier: AGPL-3.0-or-later
const { test } = require("node:test");
const assert = require("assert");
const { sleep, openChat } = require("./helpers");

test("a video that cannot play gets one explanatory note", async () => {
  const { w, d } = await openChat("Carol");
  await sleep(300);
  const v = d.querySelector("video[controls]");
  assert(v);
  Object.defineProperty(v, "error", { value: { code: 4 } });
  v.dispatchEvent(new w.Event("error"));
  v.dispatchEvent(new w.Event("error"));
  const mine = [...d.querySelectorAll(".missing")].filter((n) => n.textContent.includes("could not play"));
  assert.strictEqual(mine.length, 1);
  assert(mine[0].textContent.includes("format not supported"));
  assert.strictEqual(mine[0].querySelector("a").getAttribute("href"), v.getAttribute("src"));
  w.close();
});
