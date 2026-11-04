# SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import hashlib
import hmac
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import signal_takeout as st  # noqa: E402

MIB = 1 << 20


def encrypt(plain: bytes, zeros: int = 0):
    keys = secrets.token_bytes(64)
    iv = secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(keys[:32]), modes.CBC(iv)).encryptor()
    body = iv + enc.update(padder.update(plain + b"\0" * zeros) + padder.finalize()) + enc.finalize()
    mac = hmac.new(keys[32:], body, hashlib.sha256).digest()
    return body + mac, base64.b64encode(keys).decode()


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 31, 32, MIB - 1, MIB, MIB + 5])
@pytest.mark.parametrize("zeros", [0, 40])
def test_stored_file_round_trip(tmp_path, n, zeros):
    data = secrets.token_bytes(n)
    blob, key = encrypt(data, zeros)
    f = tmp_path / "f"
    f.write_bytes(blob)
    assert st.read_stored_file(f, {"localKey": key, "size": n}) == data
    if not zeros:
        assert st.read_stored_file(f, {"localKey": key}) == data
        assert st.read_stored_file(f, {"localKey": key, "size": n + 999}) == data


def test_legacy_plain_file(tmp_path):
    f = tmp_path / "plain"
    f.write_bytes(b"legacy")
    assert st.read_stored_file(f, {}) == b"legacy"


@pytest.mark.parametrize("damage", ["flip", "truncate", "tiny"])
def test_corrupt_file_is_rejected_cleanly(tmp_path, damage):
    blob, key = encrypt(secrets.token_bytes(5000))
    bad = {
        "flip": blob[:100] + bytes([blob[100] ^ 1]) + blob[101:],
        "truncate": blob[:-40],
        "tiny": blob[:20],
    }[damage]
    src, dest = tmp_path / "bad", tmp_path / "dest"
    src.write_bytes(bad)
    with pytest.raises(ValueError):
        st.copy_stored_file(src, {"localKey": key, "size": 5000}, dest)
    assert not dest.exists() and not list(tmp_path.glob("*.part"))


def test_oscrypt_round_trip():
    import hashlib as h
    key = h.pbkdf2_hmac("sha1", b"hunter2", b"saltysalt", 1, 16)
    padder = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).encryptor()
    blob = b"v11" + enc.update(padder.update(b"ab" * 32) + padder.finalize()) + enc.finalize()
    assert st.oscrypt_decrypt(blob, b"hunter2") == "ab" * 32
    with pytest.raises(ValueError):
        st.oscrypt_decrypt(blob, b"wrong")


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the read-only bit")
@pytest.mark.parametrize("leave_wal", [False, True])
def test_wal_db_opens_from_read_only_dir(tmp_path, leave_wal):
    key = "c" * 64
    db = tmp_path / "db.sqlite"
    # os._exit skips the close, so the WAL keeps the table uncheckpointed.
    subprocess.run([sys.executable, "-c", f"""
import os
from sqlcipher3 import dbapi2 as s
c = s.connect({str(db)!r})
c.execute("PRAGMA key = \\"x'{key}'\\"")
c.execute("PRAGMA journal_mode=WAL")
c.execute("PRAGMA wal_autocheckpoint=0")
c.execute("CREATE TABLE t(x)")
c.commit()
if {leave_wal}:
    os._exit(0)
c.close()
"""], check=True)
    (tmp_path / "db.sqlite-shm").unlink(missing_ok=True)
    assert (tmp_path / "db.sqlite-wal").exists() == leave_wal
    tmp_path.chmod(0o555)
    try:
        conn = st.open_db(db, key)
        assert conn.execute("SELECT name FROM sqlite_master").fetchone()[0] == "t"
        conn.close()
        with pytest.raises(SystemExit, match="wrong key"):
            st.open_db(db, "d" * 64)
    finally:
        tmp_path.chmod(0o755)


def test_chunker_splits_by_month_and_cap(monkeypatch):
    monkeypatch.setattr(st, "CHUNK_CAP", 5)
    out = []
    c = st.Chunker(lambda meta, html: out.append(dict(meta)))
    day, base, n = 86400000, 1_750_000_000_000, 0
    for d in range(12):
        for k in range(3):
            n += 1
            c.add(base + d * day + k * 1000, f"<m{n}>", n)
    c.close(n)
    assert sum(m["count"] for m in out) == n
    assert all(m["last"] - m["first"] + 1 == m["count"] for m in out)
    assert len({m["id"] for m in out}) == len(out)


@pytest.fixture(scope="module")
def export(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("export")
    run = lambda *a: subprocess.run([sys.executable, *map(str, a)], check=True,
                                    capture_output=True, text=True)
    run(ROOT / "make_fixture.py", tmp / "fake")
    res = run(ROOT / "signal_takeout.py", "--data-dir", tmp / "fake", "-o", tmp / "out")
    return tmp / "out", res


def test_export_layout(export):
    out, res = export
    assert "0 failed" in res.stdout
    assert (out / "index.html").is_file()
    assert (out / "assets" / "takeout.js").is_file()
    assert (out / "assets" / "search-index.js").is_file()
    pages = list((out / "chats").glob("*.html"))
    assert len(pages) >= 4
    dave = chat_page(out, "Dave")
    months = sorted(f.stem for f in (out / "chats" / (dave.stem + "_months")).glob("2026-*.js"))
    assert months == ["2026-05", "2026-06", "2026-07", "2026-08"]


def test_limit_keeps_the_newest(tmp_path):
    run = lambda *a: subprocess.run([sys.executable, *map(str, a)], check=True,
                                    capture_output=True, text=True)
    run(ROOT / "make_fixture.py", tmp_path / "fake")
    run(ROOT / "signal_takeout.py", "--data-dir", tmp_path / "fake", "-o", tmp_path / "out",
        "--export-only", "Dave", "--limit", "5", "--no-attachments")
    text = "".join(f.read_text() for f in (tmp_path / "out" / "chats").rglob("*.js"))
    text += "".join(f.read_text() for f in (tmp_path / "out" / "chats").glob("*.html"))
    assert "Dave message 59" in text and "Dave message 54" not in text


def chunks_text(out, prefix):
    return "".join(f.read_text() for f in out.glob(f"chats/{prefix}*_months/*.js")
                   if f.name != "find.js")


def test_group_senders_have_avatar_color_and_reactions_name_people(export):
    out, _ = export
    group = chunks_text(out, "Weekend")
    assert 'class=\\"author\\" style=\\"--h:' in group
    assert '<img class=\\"avatar\\" src=\\"../assets/avatars/Alice' in group
    alice = chunks_text(out, "Alice")
    assert 'title=\\"Bob, Toby\\"' in alice


def test_edit_history_lists_earlier_versions_oldest_first(export):
    out, _ = export
    text = next(out.glob("chats/Alice*_months/2026-09.js")).read_text()
    assert "Edited (2 earlier versions)" in text
    assert text.index("Frday at 7 works") < text.index("Friday at 7 works")


def run_export(tmp_path, *extra):
    run = lambda *a: subprocess.run([sys.executable, *map(str, a)], check=True,
                                    capture_output=True, text=True)
    run(ROOT / "make_fixture.py", tmp_path / "fake")
    res = run(ROOT / "signal_takeout.py", "--data-dir", tmp_path / "fake", "-o", tmp_path / "out",
              "--no-attachments", *extra)
    return tmp_path / "out", res


def test_since_and_until_select_whole_days(tmp_path):
    out, _ = run_export(tmp_path, "--export-only", "Dave", "--since", "2026-07-01",
                        "--until", "2026-07-31")
    months = [f.stem for f in out.glob("chats/Dave*_months/2026-*.js")]
    assert months == ["2026-07"]


def test_limit_applies_inside_the_range(tmp_path):
    out, _ = run_export(tmp_path, "--export-only", "Dave", "--until", "2026-07-31", "--limit", "3")
    text = "".join(f.read_text() for f in out.glob("chats/Dave*_months/2026-*.js"))
    assert text.count("Dave message") == 3
    assert [f.stem for f in out.glob("chats/Dave*_months/2026-*.js")] == ["2026-07"]


def test_bad_date_is_rejected(tmp_path):
    res = subprocess.run([sys.executable, str(ROOT / "signal_takeout.py"), "--since", "yesterday"],
                         capture_output=True, text=True)
    assert res.returncode == 2 and "not a date" in res.stderr


def test_second_run_reuses_attachments_and_drops_stale_ones(tmp_path):
    def run(*extra):
        return subprocess.run([sys.executable, str(ROOT / "signal_takeout.py"), "--data-dir",
                               str(tmp_path / "fake"), "-o", str(tmp_path / "out"), *extra],
                              check=True, capture_output=True, text=True).stdout
    subprocess.run([sys.executable, str(ROOT / "make_fixture.py"), str(tmp_path / "fake")],
                   check=True, capture_output=True)
    first = run()
    files = tmp_path / "out" / "chats"
    carol = next(files.glob("Carol*_files"))
    before = {f.name: f.stat().st_mtime_ns for f in carol.iterdir() if f.is_file() and f.name[0] != "."}
    assert "reused" not in first and len(before) > 5

    second = run()
    assert "reused from an earlier run" in second and "0 failed" in second
    assert {f.name: f.stat().st_mtime_ns for f in carol.iterdir() if f.is_file() and f.name[0] != "."} == before

    victim = next(f for f in carol.iterdir() if f.suffix == ".pdf")
    victim.unlink()
    (carol / "stale.bin").write_bytes(b"x")
    (carol / "partial.mp4").write_bytes(b"truncated")
    third = run()
    assert victim.is_file() and victim.stat().st_size > 100
    assert not (carol / "stale.bin").exists()
    assert "reused from an earlier run" in third


def chat_page(out, prefix):
    return next(p for p in out.glob(f"chats/{prefix}*.html") if not p.name.endswith("_media.html"))


def timeline_style(out, prefix):
    page = chat_page(out, prefix).read_text()
    return re.search(r'<div id="timeline" style="--out:([^"]*)"', page).group(1)


def test_chat_colours_follow_signal_rules(export):
    out, _ = export
    assert timeline_style(out, "Alice") == "#cf163e"
    assert timeline_style(out, "Weekend") == "linear-gradient(168deg, #e57c00, #5e0000)"
    assert timeline_style(out, "Bob") == "hsl(120, 80%, 30%)"
    assert timeline_style(out, "Dave") == ("linear-gradient(180deg, hsl(300, 90%, 50%), "
                                           "hsl(240, 70%, 50%))")
    assert timeline_style(out, "Toby") == "#077d92"


@pytest.mark.parametrize("hue,expected", [(0, 45), (30, 37.5), (100, 30), (210, 40), (270, 45), (330, 42.5)])
def test_default_lightness_matches_signal(hue, expected):
    assert st.default_lightness(hue) == expected


def test_unknown_colour_is_left_to_the_stylesheet():
    assert st.chat_color_css({"conversationColor": "nonsense"}, {}) is None
    assert st.chat_color_css({"conversationColor": "custom"}, {}) is None


def media_page(out, prefix):
    return next(out.glob(f"chats/{prefix}*_media.html")).read_text()


def test_media_page_groups_by_kind_and_links_back_into_the_chat(export):
    out, _ = export
    page = media_page(out, "Carol")
    for section in ("media", "audio", "files", "links"):
        assert f'<section id="{section}">' in page
    assert "beach.mp4" in page and "Quarterly Report" in page
    assert "Voice message" in page and "https://example.com/a" in page
    assert "huge.zip" not in page
    chat = chat_page(out, "Carol")
    assert f'href="{chat.name[:-5]}.html#m1"' in page
    assert f'href="{chat.name[:-5]}_media.html">Media (5)</a>' in chat.read_text()
    assert 'id="back" href="' + chat.name in page


def test_media_page_shows_posters_and_placeholders(export):
    out, _ = export
    page = media_page(out, "Carol")
    assert page.count('class="play"') == 2
    assert page.count('class="novideo"') == 1 and "<img" in page
    alice = media_page(out, "Alice")
    assert "map.png" in alice and '<section id="audio">' not in alice


def test_chats_without_media_have_no_media_page(export):
    out, _ = export
    assert not list(out.glob("chats/Dave*_media.html"))
    assert "_media.html" not in chat_page(out, "Dave").read_text()


@pytest.mark.parametrize("text, url", [
    ("see https://example.com/a.", "https://example.com/a"),
    ("(at https://en.wikipedia.org/wiki/Foo_(bar))", "https://en.wikipedia.org/wiki/Foo_(bar)"),
    ("HTTP://Example.com:8080/x?y=1&z=2!", "HTTP://Example.com:8080/x?y=1&z=2"),
    ("http://[::1]/", "http://[::1]/"),
    ("https://bücher.de, ok", "https://bücher.de"),
])
def test_linkify_finds_urls(text, url):
    html = st.linkify(text)
    assert f'<a href="{st.esc(url)}" target="_blank" rel="noopener noreferrer">{st.esc(url)}</a>' in html
    assert re.sub(r"<[^>]+>", "", html) == st.esc(text)


@pytest.mark.parametrize("text", [
    "https://", "http://:80/", "https://%zz/", "https://a..b/", "http://host:99999/",
    "ftp://example.com", "javascript:alert(1)", "example.com", "<b>https://\"x</b>",
])
def test_linkify_leaves_other_text_alone(text):
    assert st.linkify(text) == st.esc(text)


def test_message_urls_are_links(export):
    out, _ = export
    text = chunks_text(out, "Carol")
    assert ('<div class=\\"body\\"><a href=\\"https://example.com/a\\" target=\\"_blank\\" '
            'rel=\\"noopener noreferrer\\">https://example.com/a</a></div>') in text


def test_media_reserves_its_size(export):
    out, _ = export
    alice, carol = chunks_text(out, "Alice"), chunks_text(out, "Carol")
    assert '<img loading=\\"lazy\\" width=\\"1\\" height=\\"1\\" src=' in alice
    assert '<video controls preload=\\"none\\" width=\\"640\\" height=\\"360\\" poster=' in carol
    assert st.dims({"width": 0, "height": 5}) == st.dims({"width": "3", "height": 4}) == ""


def test_erased_view_once_media_leaves_a_note(export):
    out, _ = export
    bob = chunks_text(out, "Bob")
    for note in ("viewed", "expired", "deleted after sending", "could not be shown"):
        assert f'<div class=\\"deleted\\">View-once media, {note}</div>' in bob
    viewed = bob[bob.index("View-once media, viewed"):bob.index("View-once media, expired")]
    assert 'class=\\"reaction\\"' in viewed


def test_unopened_view_once_media_is_covered(export):
    out, _ = export
    bob = chunks_text(out, "Bob")
    cover = re.search(r'<div class=\\"viewonce\\"><input type=\\"checkbox\\" class=\\"vo-seen\\" '
                      r'id=\\"(vo[0-9a-f]{8})\\"><div class=\\"att\\"><a href=.*?</div>'
                      r'<label class=\\"vo-cover\\" for=\\"\1\\">View-once photo'
                      r'<span>click to show</span></label></div>', bob)
    assert cover and bob.count('class=\\"viewonce\\"') == 1
    assert re.search(r'<div class="tile"><div class="viewonce"><input type="checkbox" class="vo-seen" '
                     r'id="(vo[0-9a-f]{8})"><a class="thumb".*?<label class="vo-cover" for="\1">',
                     media_page(out, "Bob"))


def test_polls_count_each_voter_once(export):
    out, _ = export
    group = chunks_text(out, "Weekend")
    assert ('<div class=\\"poll-q\\">Saturday or Sunday?</div><div class=\\"poll-sub\\">'
            'Poll &middot; Final results</div>') in group
    assert ('<li style=\\"--p:33%\\" title=\\"Alice Anderson\\"><span class=\\"popt\\">Saturday'
            '</span><span class=\\"pcount\\">1</span></li>') in group
    assert ('<li style=\\"--p:67%\\" title=\\"Bob, Toby\\"><span class=\\"popt\\">Sunday'
            '</span><span class=\\"pcount\\">2</span></li>') in group
    assert '<div class=\\"system\\">Alice Anderson ended the poll: Saturday or Sunday?</div>' in group
    flip = re.search(r'<input type=\\"checkbox\\" class=\\"poll-flip\\" id=\\"(pv[0-9a-f]{8})\\">'
                     r'<div class=\\"poll-face poll-front\\"><label class=\\"poll-pill\\" for=\\"\1\\">'
                     r'Votes</label>.*?<label class=\\"poll-pill\\" for=\\"\1\\">Back</label>', group)
    assert flip
    assert ('<ul class=\\"poll-who\\"><li>Saturday<span class=\\"pvoters\\">Alice Anderson</span></li>'
            '<li>Sunday<span class=\\"pvoters\\">Bob, Toby</span></li></ul>') in group
    assert "poll-flip" not in st.render_poll({"question": "Q", "options": ["a"]}, lambda c: c)
    assert st.render_poll({"question": "Q", "options": ["a"], "allowMultiple": True}).count(
        "Select one or more") == 1


def test_unsupported_messages_say_what_they_needed(export):
    out, _ = export
    bob = chunks_text(out, "Bob")
    assert '<div class=\\"deleted\\">Unsupported message, it needs a newer Signal (polls)</div>' in bob
    assert '<div class=\\"deleted\\">Unsupported message</div>' in bob
    assert st.unsupported_note({"requiredProtocolVersion": 42}).endswith("(protocol version 42)")


def test_stories_show_with_their_replies(export):
    out, _ = export
    alice = chunks_text(out, "Alice")
    story = re.search(r'<div class=\\"msg story\\" id=\\"m(\d+)\\"><div class=\\"bubble\\">'
                      r'<div class=\\"story-tag\\">Story</div><div class=\\"att\\">.*?'
                      r'<div class=\\"caption\\">Sunset at the lake</div>', alice)
    assert story
    link = f'<a href=\\"#m{story.group(1)}\\">Photo</a>'
    assert f"<b>Replied to Alice Anderson&#x27;s story</b><br>{link}</div>" in alice
    assert f"<b>Reacted \U0001F60D to Alice Anderson&#x27;s story</b><br>{link}</div>" in alice
    assert ('<b>Replied to your story</b><br><span class=\\"deleted\\">No longer available</span>'
            in alice)
    assert '<span class="tile-tag">Story</span>' in media_page(out, "Alice")


def test_group_story_replies_live_in_the_story_thread(export):
    out, _ = export
    group = chunks_text(out, "Weekend")
    assert ('<div class=\\"text-story ts3\\" style=\\"background:linear-gradient(180deg, '
            '#5b6bef 0%, #ee5b8e 100%)\\"><span style=\\"color:#ffffff\\">Mondays.</span></div>'
            '<details class=\\"story-replies\\"><summary>3 replies</summary>') in group
    assert "<b>Toby</b> reacted \U0001F525" in group and "<b>You</b> Me too" in group
    thread = group[group.index("story-replies"):]
    thread = thread[:thread.index("</details>")]
    assert "Haha, so true" in thread and group.count("Haha, so true") == 1


def test_story_backgrounds_follow_signal():
    assert st.story_background({}) == "#fbfbfb"
    assert st.story_background({"color": 0xFF112233}) == "#112233"
    assert st.story_background({"gradient": {"angle": 90, "startColor": 0xFF000000,
                                             "endColor": 0xFFFFFFFF}}) == (
        "linear-gradient(90deg, #000000, #ffffff)")
