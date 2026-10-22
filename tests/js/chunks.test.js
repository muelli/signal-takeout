// SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
// SPDX-License-Identifier: AGPL-3.0-or-later
const { test } = require("node:test");
const assert = require("assert");
const { sleep, openChat, loaded } = require("./helpers");

test("chunks load near the viewport and unload far away", async () => {
  const { w, d } = await openChat("Dave", { layout: true });
  await sleep(300);
  assert(loaded(d).includes("2026-05") && !loaded(d).includes("2026-08"), loaded(d).join());
  assert(d.querySelectorAll(".msg").length > 0);
  assert.strictEqual(d.getElementById("jump").options.length, 4);

  w.scrollY = 9000; w.dispatchEvent(new w.Event("scroll")); await sleep(300);
  const first = d.querySelector('.chunk[data-id="2026-05"]');
  assert(!first._loaded && first.style.height && first.querySelector(".chunk-label"));
  assert(!d.getElementById("m1"), "message DOM dropped");

  w.scrollY = 0; w.dispatchEvent(new w.Event("scroll")); await sleep(300);
  assert(d.getElementById("m1"), "reloaded");
  w.close();
});

test("#mN opens the right chunk and highlights the message", async () => {
  const { w, d } = await openChat("Dave", { layout: true, hash: "#m50" });
  await sleep(400);
  const e = d.getElementById("m50");
  assert(e && e.classList.contains("jump") && w._scrolled === e);
  assert(loaded(d).includes("2026-08"));
  assert(d.getElementById("dayfloat").textContent.length > 0);

  w.location.hash = "#m3"; await sleep(400);
  assert.deepStrictEqual([...d.querySelectorAll(".msg.jump")].map((x) => x.id), ["m3"]);

  d.getElementById("jump").value = "2026-07";
  d.getElementById("jump").dispatchEvent(new w.Event("change")); await sleep(300);
  assert(loaded(d).includes("2026-07"), "month select loads that month");
  w.close();
});

test("a jump stays put when the month above loads later", async () => {
  const { w, d } = await openChat("Dave", { layout: true });
  await sleep(300);
  const append = d.head.append.bind(d.head);
  d.head.append = (t) => (/2026-07/.test(t.src) ? setTimeout(() => append(t), 200) : append(t));
  const n = d.querySelector('.chunk[data-id="2026-08"]').dataset.first;
  w.location.hash = `#m${n}`; await sleep(100);
  const e = d.getElementById(`m${n}`);
  assert(e && !loaded(d).includes("2026-07"));
  const top = e.getBoundingClientRect().top;
  assert(top > 0 && top < 800);
  await sleep(400);
  assert(loaded(d).includes("2026-07"));
  assert.strictEqual(e.getBoundingClientRect().top, top);
  w.close();
});
