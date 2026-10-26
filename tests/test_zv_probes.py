"""Independent verifier probes (read-only verification session).

Spec-derived from odd/tasks/entry-bullet-edit-confirm.md: S1-S4 incl. S4.1-S4.7.
Driven at the flow level like tests/test_bot_flow.py (no aiogram objects, no
network). These are regression probes for the parent to hand to the writer.
"""
from __future__ import annotations

import hashlib
from typing import Any

import pytest

from app.bot import handlers
from app.bot.flow import ConfirmKB, PREVIEW, UNKNOWN_CALLBACK
import test_bot_flow
from app.bot.keyboards import confirm_kb
from app.db.repository import get_resource, set_resource_state
from app.services.github import DuplicateError, build_entry_line, parse_entry_line

from test_bot_flow import (
    CHOSEN,
    GITHUB_URL,
    USER,
    VALID_PAT,
    _active_id,
    _audit,
    _to_confirming,
    _to_placement,
)

h = test_bot_flow.h  # reuse the suite's AppDeps fixture in this module

REVIEWED = GITHUB_URL  # https://github.com/OtherOrg/awesome-tool


def _bullet(name: str, desc: str, tags: str = "`type:tool` `free` `linux`", url: str = REVIEWED) -> str:
    return f"- [{name}]({url}) — {desc}. {tags}"


async def _entry_line(h: dict, rid: int) -> str:
    return (await get_resource(h["conn"], rid)).entry_line


async def _row_digest(h: dict, rid: int) -> str:
    async with h["conn"].execute(
        "SELECT state, entry_line, folder, url FROM resources WHERE id = ?", (rid,)
    ) as cur:
        row = await cur.fetchone()
    return hashlib.sha256(repr(tuple(row)).encode()).hexdigest()


# ---------------------------------------------------------------- S1 / S4.1


def test_s1_confirm_keyboard_has_three_rows_edit_payload_e() -> None:
    rows = [[(b.text, b.callback_data) for b in r] for r in confirm_kb(CHOSEN).inline_keyboard]
    assert rows[0] == [(f"✅ Commit to {CHOSEN}", "✅")]
    assert rows[1] == [("❌ Cancel", "❌")]
    assert rows[2] == [("✏️ Edit", "e")]
    assert len(rows) == 3
    for row in rows:
        for _, data in row:
            assert len(data.encode("utf-8")) <= 64  # Telegram callback_data budget
            assert "/" not in data


# ---------------------------------------------------------------- S1 / S4.2


async def test_s1_edit_keypress_returns_stored_bullet_verbatim_in_code_block(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    stored = await _entry_line(h, rid)

    result = await flow.handle_callback(USER, "jonan", "e")

    assert result.new_message is True  # a NEW message, ✅/❌ bubble untouched
    assert result.parse_mode == "HTML"
    assert result.keyboard is None
    assert len(result.replies) == 2
    assert result.replies[1] == f"<pre>{stored}</pre>"  # verbatim, copyable block
    assert result.replies[1].removeprefix("<pre>").removesuffix("</pre>") == stored
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"
    assert await _entry_line(h, rid) == stored
    assert await _audit(h, "entry_edit_requested")


async def test_s1_edit_replay_can_be_repeated_and_stays_identical(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    first = await flow.handle_callback(USER, "jonan", "e")
    second = await flow.handle_callback(USER, "jonan", "e")
    assert first.replies == second.replies
    assert await _entry_line(h, rid) == await _entry_line(h, rid)


async def test_s1_edit_keypress_escapes_html_markup_in_stored_bullet(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    # hand-edited DB row is realistic input; markup must be escaped in the block
    await set_resource_state(
        h["conn"], rid, "CONFIRMING",
        entry_line=_bullet("<b>&amp;</b>", "</pre><script>alert(1)</script>"),
    )
    result = await flow.handle_callback(USER, "jonan", "e")
    assert "&lt;b&gt;&amp;amp;&lt;/b&gt;" in result.replies[1]
    assert "<script>" not in result.replies[1]
    assert "</pre>" not in result.replies[1].removeprefix("<pre>").removesuffix("</pre>").replace("&lt;/pre&gt;", "")


class _Rec:
    def __init__(self) -> None:
        self.items: list[tuple] = []

    async def __call__(self, *a: Any, **k: Any) -> None:
        self.items.append((a, k))


class _User:
    def __init__(self, i: int, u: str) -> None:
        self.id, self.username = i, u


class _Callback:
    def __init__(self, i: int, u: str, d: str) -> None:
        self.from_user = _User(i, u)
        self.data = d
        self.answer = _Rec()
        self.message = type("M", (), {})()
        self.message.answer = _Rec()
        self.message.edit_text = _Rec()


async def test_s1_handler_level_edit_answers_new_message_bubble_intact(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    stored = await _entry_line(h, rid)
    cb = _Callback(USER, "jonan", "e")
    await handlers.on_callback(cb, h["deps"], flow)
    assert cb.message.edit_text.items == []  # ✅/❌ bubble NOT edited
    assert len(cb.message.answer.items) == 2  # instruction + code block, new messages
    code_args, code_kwargs = cb.message.answer.items[1]
    assert code_args[0] == f"<pre>{stored}</pre>"
    assert code_kwargs.get("parse_mode") == "HTML"
    assert code_kwargs.get("reply_markup") is None
    assert len(cb.answer.items) == 1
    assert await _entry_line(h, rid) == stored


async def test_s1_edit_keypress_in_other_states_is_unknown_callback_audited(h: dict) -> None:
    flow = await _to_placement(h)  # AWAITING_PLACEMENT
    result = await flow.handle_callback(USER, "jonan", "e")
    assert result.replies == (UNKNOWN_CALLBACK,)
    assert result.keyboard is None
    rows = await _audit(h, "callback_ignored")
    assert rows and rows[-1]["detail"] == "data=e"

    await flow.handle_folder_choice(USER, CHOSEN)  # AWAITING_ENTRY_INFO
    result = await flow.handle_callback(USER, "jonan", "e")
    assert result.replies == (UNKNOWN_CALLBACK,)
    assert (await get_resource(h["conn"], await _active_id(h))).state == "AWAITING_ENTRY_INFO"


async def test_s1_unauthorized_edit_keypress_is_silent(h: dict) -> None:
    from test_bot_flow import INTRUDER

    cb = _Callback(INTRUDER, "sneaky", "e")
    await handlers.on_callback(cb, h["deps"], h["flow"])
    assert cb.message.edit_text.items == [] and cb.message.answer.items == []
    assert cb.answer.items == [((), {})]  # empty ack only
    assert any(r["tg_user_id"] == INTRUDER for r in await _audit(h, "unauthorized_ignored"))


# ---------------------------------------------------------------- S2 / S4.3


async def test_s2_valid_paste_rebuilds_canonical_and_persists(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    paste = _bullet(
        "renamed-tool", "A sharpened recon suite",
        "`type:docs` `paid` `windows` `macos`",
    )

    result = await flow.handle_text(USER, "jonan", paste)

    expected = build_entry_line(
        "renamed-tool", REVIEWED, "A sharpened recon suite", "docs", "paid", ["windows", "macos"]
    )
    assert await _entry_line(h, rid) == expected  # canonical format re-applied
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"
    assert result.replies == (f"{PREVIEW}\n{expected}",)
    assert isinstance(result.keyboard, ConfirmKB) and result.keyboard.folder == CHOSEN
    assert result.parse_mode is None
    assert result.new_message is False
    assert await _audit(h, "entry_edited")
    # persisted in the SQLite row itself
    async with h["conn"].execute("SELECT entry_line FROM resources WHERE id = ?", (rid,)) as cur:
        row = await cur.fetchone()
    assert row["entry_line"] == expected


async def test_s2_parse_rebuild_roundtrip_matches_builder(h: dict) -> None:
    line = build_entry_line("Nmap", "https://nmap.org", "Port scanner.", "tool", "free", ["linux"])
    parsed = parse_entry_line(line)
    assert build_entry_line(parsed.name, parsed.url, parsed.description, "tool", "free", ["linux"]) == line


# ---------------------------------------------------------------- S3


async def test_s3_different_url_rejected_row_byte_identical(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    before = await _row_digest(h, rid)
    stored = await _entry_line(h, rid)

    result = await flow.handle_text(
        USER, "jonan", _bullet("awesome-tool", "A tool for things", url="https://github.com/EvilOrg/awesome-tool")
    )

    assert len(result.replies) == 2
    assert "must stay" in result.replies[0]  # one specific URL-lock error
    assert result.replies[1] == f"<pre>{stored}</pre>"  # retry bullet re-offered
    assert result.keyboard is None
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"
    assert await _row_digest(h, rid) == before  # byte-identical row, nothing persisted
    rows = await _audit(h, "entry_edit_rejected")
    assert any("url-changed" in r["detail"] for r in rows)


async def test_s3_canonical_equivalent_url_variants_accepted(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    for variant in ("https://GITHUB.COM/OtherOrg/awesome-tool/", f"{REVIEWED}/"):
        result = await flow.handle_text(USER, "jonan", _bullet("v", "Variant desc", url=variant))
        assert isinstance(result.keyboard, ConfirmKB), variant
        assert await _entry_line(h, rid) == build_entry_line("v", REVIEWED, "Variant desc", "tool", "free", ["linux"])


async def test_s3_rebuild_always_carries_the_reviewed_url_not_the_pasted_spelling(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_text(
        USER, "jonan", _bullet("v", "Desc", url="https://GITHUB.COM/OtherOrg/awesome-tool/")
    )
    line = await _entry_line(h, rid)
    assert f"]({REVIEWED})" in line  # reviewed spelling, not the pasted variant


# ---------------------------------------------------------------- S4.4


async def test_s44_garbage_pastes_each_specific_error_retry_and_no_change(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    stored = await _entry_line(h, rid)
    before = await _row_digest(h, rid)

    cases = {
        "just prose, not a bullet": "missing leading dash",
        "- no link here": "missing link",
        f"- [N]({REVIEWED}) no separator": "missing description separator",
        f"- [{'n' * 121}]({REVIEWED}) — d. `type:tool`": "120 character limit",
        f"- [N]({REVIEWED}) — {'d' * 501}. `type:tool`": "500 character limit",
        f"- [N]({REVIEWED}) — d.": "type tag",  # tagless paste: parses, cannot rebuild
        f"- [N]({REVIEWED}) — d. `type:banana`": "type tag",
        f"- [N]({REVIEWED}) — d. `type:tool` `{'t' * 41}`": "40 character limit",
        f"- [N]({REVIEWED}) — d. `type:tool` `ba|d`": "invalid platform tag",
        "- [N](HTTPS://github.com/OtherOrg/awesome-tool) — d. `type:tool`": "https://",
    }
    for paste, needle in cases.items():
        result = await flow.handle_text(USER, "jonan", paste)
        assert len(result.replies) == 2, paste
        assert needle in result.replies[0], (paste, result.replies[0])
        assert result.replies[1] == f"<pre>{stored}</pre>", paste  # retry re-offered
        assert result.keyboard is None
        assert (await get_resource(h["conn"], rid)).state == "CONFIRMING", paste
        assert await _row_digest(h, rid) == before, paste


async def test_s44_retry_still_works_after_rejections_then_accepts(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_text(USER, "jonan", "garbage")
    await flow.handle_text(USER, "jonan", f"- [N](https://evil.example/x) — d. `type:tool`")
    ok = await flow.handle_text(USER, "jonan", _bullet("fixed", "Now correct"))
    assert isinstance(ok.keyboard, ConfirmKB)
    assert await _entry_line(h, rid) == build_entry_line("fixed", REVIEWED, "Now correct", "tool", "free", ["linux"])


# ---------------------------------------------------------------- S4.5


async def test_s45_confirm_after_edit_commits_the_edited_bullet_verbatim(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    edited = build_entry_line("edited-name", REVIEWED, "Edited description", "lab", "paid", ["docker"])
    await flow.handle_text(USER, "jonan", f"- [edited-name]({REVIEWED}) — Edited description. `type:lab` `paid` `docker`")

    await flow.handle_confirm(USER)

    commit_call = [c for c in h["gh"].calls if c[0] == "commit_entry"][-1]
    assert commit_call[1] == f"{CHOSEN}/README.md"
    assert commit_call[2] == edited  # the EDITED bullet, verbatim
    assert (await get_resource(h["conn"], rid)).state == "COMMITTED"


# ---------------------------------------------------------------- S4.6


async def test_s46_duplicate_check_fires_on_edited_line(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_text(USER, "jonan", _bullet("dup", "Duplicating entry"))
    h["gh"].commit_error = DuplicateError(
        f"That link is already listed in {CHOSEN}/README.md — nothing was committed."
    )
    result = await flow.handle_confirm(USER)
    assert "already" in "\n".join(result.replies).lower()
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"
    assert await _audit(h, "commit_duplicate")


async def test_s46_folder_validation_still_fires_after_edit(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_text(USER, "jonan", _bullet("t", "Tamper test"))
    await set_resource_state(h["conn"], rid, "CONFIRMING", folder="../../etc")
    calls_before = len(h["gh"].calls)
    result = await flow.handle_confirm(USER)
    assert "nothing was committed" in "\n".join(result.replies).lower()
    assert len(h["gh"].calls) == calls_before  # no GitHub call at all
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"
    assert await _audit(h, "commit_rejected")


# ---------------------------------------------------------------- safety probes (item-1 risk)


async def test_safety_markup_paste_no_crash_and_only_canonical_persisted(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    paste = _bullet("<b>bold&amp;</b>", "Uses </pre><script>alert(1)</script> `backtick` ok")
    result = await flow.handle_text(USER, "jonan", paste)
    parsed = parse_entry_line(paste)
    expected = build_entry_line(
        parsed.name, REVIEWED, parsed.description, "tool", "free", ["linux"]
    )
    assert await _entry_line(h, rid) == expected  # canonical builder output only
    assert "<script>" not in result.replies[0].replace("<script>alert(1)</script>", "")
    await flow.handle_confirm(USER)
    commit_call = [c for c in h["gh"].calls if c[0] == "commit_entry"][-1]
    assert commit_call[2] == expected


async def test_safety_huge_inputs_no_unhandled_exception(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    stored = await _entry_line(h, rid)
    for huge in ("x" * 100_000, f"- [{'n' * 100_000}]({REVIEWED}) — d. `type:tool`",
                 "-" + " `tag`" * 20_000):
        result = await flow.handle_text(USER, "jonan", huge)
        assert len(result.replies) == 2
        assert len(result.replies[0]) <= 300  # bounded, user-safe
        assert result.replies[1] == f"<pre>{stored}</pre>"
    assert await _row_digest(h, rid) is not None
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"


async def test_safety_newline_and_control_chars_do_not_leak_into_replies(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    stored = await _entry_line(h, rid)
    paste = "- [N](https://e\x0cxample.com/a) — d. `type:tool`"
    result = await flow.handle_text(USER, "jonan", paste)
    assert "\x0c" not in result.replies[0]
    assert result.replies[1] == f"<pre>{stored}</pre>"
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"


async def test_safety_multiline_paste_is_rejected_whole_not_silently_truncated(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    stored = await _entry_line(h, rid)
    before = await _row_digest(h, rid)
    paste = _bullet("m", "First line only") + "\n- [Second](https://evil.example/) — extra line"
    result = await flow.handle_text(USER, "jonan", paste)
    assert "missing link" in result.replies[0]  # whole-message grammar, no silent drop
    assert result.replies[1] == f"<pre>{stored}</pre>"
    assert await _row_digest(h, rid) == before
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"


