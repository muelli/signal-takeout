// SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
// SPDX-License-Identifier: AGPL-3.0-or-later
const { test } = require("node:test");
const assert = require("assert");
const { sleep, root, openPage } = require("./helpers");

async function search(w, d, value) {
  const q = d.getElementById("q");
  q.value = value;
  q.dispatchEvent(new w.Event("input"));
  await sleep(300);
  return d.getElementById("results");
}

test("index lists conversations and sorts by name", async () => {
  const { w, d } = await openPage(root + "/index.html");
  await sleep(200);
  const names = () => [...d.querySelectorAll("#list li")].map((li) => li.dataset.name);
  assert(names().length >= 4);
  const sort = d.getElementById("sort");
  sort.value = "name"; sort.dispatchEvent(new w.Event("change"));
  const sorted = names();
  assert.deepStrictEqual(sorted, [...sorted].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" })));
  w.close();
});

test("message hits link to the entry and are not lost in old months", async () => {
  const { w, d } = await openPage(root + "/index.html");
  await sleep(200);
  const res = await search(w, d, "archive-needle");
  assert(!res.hidden && d.getElementById("list").hidden);
  const a = res.querySelector("a[href*='#m']");
  assert(a && /Dave.*\.html#m\d+$/.test(a.getAttribute("href")), a && a.getAttribute("href"));
  assert(res.querySelector("mark"));
  w.close();
});

test("names rank above message text", async () => {
  const { w, d } = await openPage(root + "/index.html");
  await sleep(200);
  const res = await search(w, d, "alice");
  assert(/^Conversations/.test(res.firstElementChild.textContent), res.firstElementChild.textContent);
  w.close();
});
