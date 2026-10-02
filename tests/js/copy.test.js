// SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
// SPDX-License-Identifier: AGPL-3.0-or-later
const { test } = require("node:test");
const assert = require("assert");
const { sleep, openChat } = require("./helpers");

test("copy button joins body and caption, skips media-only bubbles", async () => {
  const { w, d } = await openChat("Carol");
  let copied = null;
  Object.defineProperty(w.navigator, "clipboard", { value: { writeText: async (t) => { copied = t; } } });
  await sleep(300);
  const over = (el) => el.dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  const bubble = d.querySelector("#m1 .bubble");
  over(bubble.querySelector(".body") || bubble);
  const btn = d.querySelector(".copy");
  assert(btn && btn.parentElement === bubble);
  btn.click(); await sleep(20);
  assert.strictEqual(copied, "Look at this\nDog at the beach");
  assert.strictEqual(btn.textContent, "Copied");

  over(d.querySelector("#m2 .bubble"));
  assert(!d.querySelector(".copy"), "no text, no button");
  over(d.querySelector("#m6 .bubble"));
  d.querySelector(".copy").click(); await sleep(20);
  assert(copied.includes("needle-in-the-long-text"), "long message copied in full");
  w.close();
});
