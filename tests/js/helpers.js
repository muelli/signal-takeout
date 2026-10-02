// SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
// SPDX-License-Identifier: AGPL-3.0-or-later
const { JSDOM, VirtualConsole } = require("jsdom");
const fs = require("fs");
const path = require("path");

const root = process.env.EXPORT_DIR || "/out/export";
const chats = path.join(root, "chats") + path.sep;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function chatFile(prefix) {
  return fs.readdirSync(chats).find((f) => f.startsWith(prefix) && f.endsWith(".html"));
}

async function openPage(file, { hash = "", layout = false, onError } = {}) {
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => { if (onError) onError(e); });
  const dom = await JSDOM.fromFile(file, {
    runScripts: "dangerously", resources: "usable", pretendToBeVisual: true,
    url: "file://" + path.resolve(file) + hash, virtualConsole: vc,
    beforeParse(w) {
      w.innerHeight = 800;
      w.scrollBy = (x, y) => { w.scrollY += y; };
      w.Element.prototype.scrollIntoView = function (o) {
        w._scrolled = this;
        if (layout) {
          w.scrollY = w._top(this) - (o && o.block === "center" ? 400 : 0);
          w.dispatchEvent(new w.Event("scroll"));
        }
      };
    },
  });
  const w = dom.window, d = w.document;
  if (layout) fakeLayout(w, d);
  await new Promise((r) => w.addEventListener("load", r));
  return { dom, w, d };
}

async function openChat(prefix, opts) {
  return openPage(chats + chatFile(prefix), opts);
}

// jsdom has no layout: sections are stacked, children are 60px apart.
function fakeLayout(w, d) {
  w.scrollY = 0;
  w._sec = () => [...d.querySelectorAll(".chunk")];
  w._h = (s) => (s._loaded ? 3000 : parseFloat(s.style.height) || 100);
  w._secTop = (s) => {
    let t = 100;
    for (const x of w._sec()) { if (x === s) return t; t += w._h(x); }
  };
  w._top = (e) => {
    const s = e.closest(".chunk") || e;
    if (e === s) return w._secTop(s);
    const kids = [...s.querySelectorAll(".day, .msg")];
    return w._secTop(s) + 60 * (kids.indexOf(e.closest(".msg, .day")) + 1);
  };
  w.Element.prototype.getBoundingClientRect = function () {
    if (this.classList.contains("stickybar")) return { top: 0, bottom: 50, height: 50 };
    if (this.classList.contains("chunk")) {
      const t = w._secTop(this) - w.scrollY;
      return { top: t, bottom: t + w._h(this), height: w._h(this) };
    }
    const t = w._top(this) - w.scrollY;
    return { top: t, bottom: t + 40, height: 40 };
  };
}

const loaded = (d) => [...d.querySelectorAll(".chunk")].filter((s) => s._loaded).map((s) => s.dataset.id);

async function type(w, d, value) {
  const i = d.getElementById("find");
  i.value = value;
  i.dispatchEvent(new w.Event("input"));
  await sleep(450);
  return d.getElementById("find-count").textContent;
}

module.exports = { root, chats, sleep, chatFile, openPage, openChat, loaded, type };
