// SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
// SPDX-License-Identifier: AGPL-3.0-or-later
const { test } = require("node:test");
const assert = require("assert");
const { sleep, openChat } = require("./helpers");

test("reactions are grouped into pills with counts", async () => {
  const { w, d } = await openChat("Alice");
  await sleep(300);
  const pills = [...d.querySelectorAll("#m1 .reactions .reaction")];
  assert.strictEqual(pills.length, 2);
  assert.strictEqual(pills[0].querySelector(".rcount").textContent, "2");
  assert(!pills[1].querySelector(".rcount"));
  w.close();
});

test("the day pill follows the scroll position", async () => {
  const { w, d } = await openChat("Dave");
  await sleep(300);
  const pill = d.getElementById("dayfloat");
  const secs = [...d.querySelectorAll(".chunk")];
  const sec = secs[0];
  const days = [...sec.querySelectorAll(".day")];
  assert(days.length >= 3);
  d.querySelector(".stickybar").getBoundingClientRect = () => ({ bottom: 50, top: 0 });
  const scroll = async (secTop, tops) => {
    secs.forEach((x, i) => {
      const top = secTop + 100000 * i;
      x.getBoundingClientRect = () => ({ top, bottom: top + 3000, height: 3000 });
    });
    days.forEach((el, i) => { el.getBoundingClientRect = () => ({ top: tops[i] }); });
    w.dispatchEvent(new w.Event("scroll"));
    await sleep(60);
  };
  await scroll(100, days.map((_, i) => 100 + 400 * i));
  assert(pill.hidden, "hidden above the first chunk");
  await scroll(0, days.map((_, i) => 100 + 400 * i));
  assert.strictEqual(pill.textContent, sec.dataset.label, "month label before the first divider");
  await scroll(-200, days.map((_, i) => -200 + 600 * i));
  assert(!pill.hidden && pill.textContent === days[0].textContent);
  await scroll(-800, days.map((_, i) => -800 + 500 * i));
  assert.strictEqual(pill.textContent, days[1].textContent);
  await scroll(-1000, days.map((_, i) => (i === days.length - 1 ? 51 : -1000 + i)));
  assert.strictEqual(pill.textContent, days[days.length - 2].textContent);
  await scroll(-1000, days.map((_, i) => (i === days.length - 1 ? 40 : -1000 + i)));
  assert.strictEqual(pill.textContent, days[days.length - 1].textContent);
  w.close();
});
