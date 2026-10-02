// SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
// SPDX-License-Identifier: AGPL-3.0-or-later
const { test } = require("node:test");
const assert = require("assert");
const { sleep, openChat, type } = require("./helpers");

test("Ctrl+F and slash focus the search, Escape clears then leaves", async () => {
  let nav = 0;
  const { w, d } = await openChat("Dave", { onError: (e) => { if (/navigation/i.test(e.message)) nav++; } });
  await sleep(300);
  const key = (target, k, o = {}) => {
    const e = new w.KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true, ...o });
    target.dispatchEvent(e);
    return e;
  };
  const input = d.getElementById("find");
  let e = key(d.body, "f", { ctrlKey: true });
  assert(e.defaultPrevented && d.activeElement === input);
  input.blur();
  e = key(d.body, "/");
  assert(e.defaultPrevented && d.activeElement === input);

  await type(w, d, "archive");
  key(input, "/");
  assert.strictEqual(nav, 0, "slash inside the box is just a character");
  key(input, "Escape"); await sleep(400);
  assert.strictEqual(input.value, "");
  assert.strictEqual(nav, 0, "first Escape only clears");
  key(input, "Escape"); await sleep(50);
  assert.strictEqual(nav, 1, "Escape on an empty box goes to the index");
  key(d.body, "Escape"); await sleep(50);
  assert.strictEqual(nav, 2);
  w.close();
});
