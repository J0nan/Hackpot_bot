"""Independent verifier probes (read-only verification session).

Spec-derived from odd/tasks/entry-bullet-edit-confirm.md. T4 repoint: probes
that pinned the removed whole-bullet paste UX (S1-S4.4) now drive the two
field-edit buttons (S5, S6.1-S6.7); probes for surviving plumbing
(parse/build round-trip) are unchanged. Driven at the flow level like
tests/test_bot_flow.py (no aiogram objects, no network). These are regression
probes for the parent to hand to the writer.
"""
from __future__ import annotations

import hashlib
from typing import Any

import pytest

from app.bot import handlers, pending_edits
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

# T4 repoint: presses ride a tracked card so delete ids are observable.
CHAT = 77001
CARD = 90042


@pytest.fixture(autouse=True)
def _no_stale_markers():
    """Markers are process-global; tmp DBs reuse resource ids across tests."""
    pending_edits.clear_all()
    yield
    pending_edits.clear_all()


async def _press(flow, data: str, message_id: int = CARD):
    """Press a confirmation-card edit button (S6.2) on the tracked card."""
    return await flow.handle_callback(USER, "jonan", data, chat_id=CHAT, message_id=message_id)


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


# ---------------------------------------------------------------- S6.1 / S1


def test_s1_confirm_keyboard_has_field_edit_row() -> None:
    """S6.1 (T4 repoint): third row = ✏️ Description + 🏷️ Tags; the "e" row is gone."""
    rows = [[(b.text, b.callback_data) for b in r] for r in confirm_kb(CHOSEN).inline_keyboard]
    assert rows[0] == [(f"✅ Commit to {CHOSEN}", "✅")]
    assert rows[1] == [("❌ Cancel", "❌")]
    assert rows[2] == [("✏️ Description", "d"), ("🏷️ Tags", "t")]
    assert len(rows) == 3
    for row in rows:
        for _, data in row:
            assert len(data.encode("utf-8")) <= 64  # Telegram callback_data budget
            assert "/" not in data
            assert data != "e"  # S6.7: whole-bullet payload removed → unknown-callback tail


# ---------------------------------------------------------------- S6.2


async def test_s1_description_keypress_returns_current_description_in_code_block(h: dict) -> None:
    """T4 repoint: "d" answers with the CURRENT description extracted from the bullet."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    stored = await _entry_line(h, rid)
    current = parse_entry_line(stored).description

    result = await _press(flow, "d")

    assert result.new_message is True  # a NEW message, ✅/❌ bubble untouched
    assert result.parse_mode == "HTML"
    assert result.keyboard is None
    assert len(result.replies) == 2
    assert result.replies[1] == f"<pre>{current}</pre>"  # copyable, field-scoped
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"
    assert await _entry_line(h, rid) == stored
    assert await _audit(h, "entry_edit_requested")
    marker = pending_edits.get_marker(rid)
    assert marker is not None and marker.mode == "description"
    assert (marker.chat_id, marker.message_id) == (CHAT, CARD)


async def test_s1_edit_replay_can_be_repeated_and_stays_identical(h: dict) -> None:
    """S6.6: presses repeat freely and persist nothing; prompts track the current value."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    before = await _row_digest(h, rid)  # pre-captured (fixes L7 finding R2-6)
    first = await _press(flow, "d")
    second = await _press(flow, "d")
    assert first.replies == second.replies
    assert await _row_digest(h, rid) == before
    await flow.handle_text(USER, "jonan", "Round two description")
    third = await _press(flow, "d", message_id=CARD + 2)
    assert third.replies[1] == "<pre>Round two description</pre>"  # CURRENT value


async def test_s1_edit_keypress_escapes_html_markup_in_stored_bullet(h: dict) -> None:
    """Markup in the stored description stays escaped inside the copy block."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    # hand-edited DB row is realistic input; markup must be escaped in the block
    await set_resource_state(
        h["conn"], rid, "CONFIRMING",
        entry_line=_bullet("<b>&amp;</b>", "</pre><script>alert(1)</script>"),
    )
    result = await _press(flow, "d")
    assert "&lt;/pre&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in result.replies[1]
    assert "<script>" not in result.replies[1]
    assert result.replies[1] == (
        "<pre>&lt;/pre&gt;&lt;script&gt;alert(1)&lt;/script&gt;</pre>"
    )
    tag_result = await _press(flow, "t")
    assert tag_result.replies[1] == "<pre>`type:tool` `free` `linux`</pre>"


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
    current = parse_entry_line(stored).description
    cb = _Callback(USER, "jonan", "d")
    await handlers.on_callback(cb, h["deps"], flow)
    assert cb.message.edit_text.items == []  # ✅/❌ bubble NOT edited
    assert len(cb.message.answer.items) == 2  # instruction + code block, new messages
    code_args, code_kwargs = cb.message.answer.items[1]
    assert code_args[0] == f"<pre>{current}</pre>"
    assert code_kwargs.get("parse_mode") == "HTML"
    assert code_kwargs.get("reply_markup") is None
    assert len(cb.answer.items) == 1
    assert await _entry_line(h, rid) == stored


async def test_s1_edit_keypress_in_other_states_is_unknown_callback_audited(h: dict) -> None:
    flow = await _to_placement(h)  # AWAITING_PLACEMENT
    result = await flow.handle_callback(USER, "jonan", "d")
    assert result.replies == (UNKNOWN_CALLBACK,)
    assert result.keyboard is None
    rows = await _audit(h, "callback_ignored")
    assert rows and rows[-1]["detail"] == "data=d"

    await flow.handle_folder_choice(USER, CHOSEN)  # AWAITING_ENTRY_INFO
    result = await flow.handle_callback(USER, "jonan", "t")
    assert result.replies == (UNKNOWN_CALLBACK,)
    assert (await get_resource(h["conn"], await _active_id(h))).state == "AWAITING_ENTRY_INFO"

    # S6.1/S6.7: the removed "e" payload now lands in the same tail while CONFIRMING.
    await flow.handle_callback(USER, "jonan", "tool")
    await flow.handle_text(USER, "jonan", "linux")  # -> CONFIRMING
    result = await flow.handle_callback(USER, "jonan", "e")
    assert result.replies == (UNKNOWN_CALLBACK,)
    assert (await get_resource(h["conn"], await _active_id(h))).state == "CONFIRMING"


async def test_s1_unauthorized_edit_keypress_is_silent(h: dict) -> None:
    from test_bot_flow import INTRUDER

    cb = _Callback(INTRUDER, "sneaky", "d")
    await handlers.on_callback(cb, h["deps"], h["flow"])
    assert cb.message.edit_text.items == [] and cb.message.answer.items == []
    assert cb.answer.items == [((), {})]  # empty ack only
    assert any(r["tg_user_id"] == INTRUDER for r in await _audit(h, "unauthorized_ignored"))


# ---------------------------------------------------------------- S6.3 / S2


async def test_s2_description_paste_rebuilds_canonical_and_persists(h: dict) -> None:
    """T4 repoint: description paste → build_entry_line canonical rebuild."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    parsed = parse_entry_line(await _entry_line(h, rid))

    await _press(flow, "d")
    result = await flow.handle_text(USER, "jonan", "A sharpened recon suite")

    expected = build_entry_line(
        parsed.name, REVIEWED, "A sharpened recon suite", "tool", "free", ["linux"]
    )
    assert await _entry_line(h, rid) == expected  # canonical format re-applied
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"
    assert result.replies == (f"{PREVIEW}\n{expected}",)
    assert isinstance(result.keyboard, ConfirmKB) and result.keyboard.folder == CHOSEN
    assert result.parse_mode is None
    assert result.new_message is False
    assert result.delete_outgoing == ((CHAT, CARD),)  # S6.3: previous card tracked
    assert await _audit(h, "entry_edited")
    # persisted in the SQLite row itself
    async with h["conn"].execute("SELECT entry_line FROM resources WHERE id = ?", (rid,)) as cur:
        row = await cur.fetchone()
    assert row["entry_line"] == expected


async def test_s2_tags_paste_rebuilds_canonical_and_persists(h: dict) -> None:
    """S6.4: tags paste keeps name/url/description and re-applies canonical tags."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    parsed = parse_entry_line(await _entry_line(h, rid))

    await _press(flow, "t")
    result = await flow.handle_text(USER, "jonan", "`type:docs` `paid` `windows` `macos`")

    expected = build_entry_line(
        parsed.name, REVIEWED, parsed.description, "docs", "paid", ["windows", "macos"]
    )
    assert await _entry_line(h, rid) == expected
    assert result.replies == (f"{PREVIEW}\n{expected}",)
    assert result.delete_outgoing == ((CHAT, CARD),)
    assert pending_edits.get_marker(rid) is None  # marker cleared after a completed edit


async def test_s2_parse_rebuild_roundtrip_matches_builder(h: dict) -> None:
    line = build_entry_line("Nmap", "https://nmap.org", "Port scanner.", "tool", "free", ["linux"])
    parsed = parse_entry_line(line)
    assert build_entry_line(parsed.name, parsed.url, parsed.description, "tool", "free", ["linux"]) == line


# ---------------------------------------------------------------- S3 / S6.3


async def test_s3_paste_can_never_reach_the_link_slot(h: dict) -> None:
    """T4 repoint: the URL lock is now structural.

    Markdown-link syntax cannot enter the description (bracket guard) and a
    colon-bearing tag is refused, so the reviewed link stays the only link.
    """
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    before = await _row_digest(h, rid)
    stored = await _entry_line(h, rid)
    current = parse_entry_line(stored).description

    await _press(flow, "d")
    result = await flow.handle_text(
        USER, "jonan", "evil [X](https://github.com/EvilOrg/awesome-tool)"
    )
    assert "can't contain" in result.replies[0]  # the interview bracket guard, reused
    assert result.replies[-1] == f"<pre>{current}</pre>"  # prompt re-offered
    assert result.keyboard is None
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"
    assert await _row_digest(h, rid) == before  # byte-identical row, nothing persisted
    rows = await _audit(h, "entry_edit_rejected")
    assert rows

    await _press(flow, "t")
    result = await flow.handle_text(USER, "jonan", "type:tool https://evil.example/x")
    assert "cost" in result.replies[0]  # the colon-shaped tag is named and refused
    assert await _row_digest(h, rid) == before


async def test_s3_editing_never_touches_the_stored_link_spelling(h: dict) -> None:
    """S6.3/S6.4: every successful rebuild carries the reviewed URL verbatim."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await _press(flow, "d")
    await flow.handle_text(USER, "jonan", "Plain new text mentioning https://GITHUB.COM/x")
    line = await _entry_line(h, rid)
    assert f"]({REVIEWED})" in line  # reviewed spelling, never the pasted words
    assert "mentioning https://GITHUB.COM/x" in line  # only inside the description
    await _press(flow, "t")
    await flow.handle_text(USER, "jonan", "type:tool free docker")
    line = await _entry_line(h, rid)
    assert f"]({REVIEWED})" in line


# ---------------------------------------------------------------- S6.6 / S4.4


async def test_s44_rejected_edits_each_specific_error_retry_and_no_change(h: dict) -> None:
    """T4 repoint: marker-driven rejection tables, row byte-identical, marker kept."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    stored = await _entry_line(h, rid)
    before = await _row_digest(h, rid)
    current_desc = parse_entry_line(stored).description

    desc_cases = {
        "bad [bracket] name": "can't contain",
        "evil `tick`": "backticks",
        "two\nlines": "one line",
        "x" * 501: "500",
        "   ": "empty",
    }
    await _press(flow, "d")
    for paste, needle in desc_cases.items():
        result = await flow.handle_text(USER, "jonan", paste)
        assert len(result.replies) == 3, paste  # error, instruction, copyable value
        assert needle in result.replies[0], (paste, result.replies[0])
        assert result.replies[-1] == f"<pre>{current_desc}</pre>", paste  # prompt re-offered
        assert result.keyboard is None
        assert result.delete_outgoing == (), paste
        assert (await get_resource(h["conn"], rid)).state == "CONFIRMING", paste
        assert await _row_digest(h, rid) == before, paste
        assert pending_edits.get_marker(rid) is not None, paste

    tag_cases = {
        "free linux": "Missing type tag",
        "type:banana": "type tag must be one of",
        "type:tool cost:nope": "cost",
        "type:tool `ba|d`": "invalid platform tag",
        f"type:tool {'t' * 41}": "40 character limit",
    }
    await _press(flow, "t")
    for paste, needle in tag_cases.items():
        result = await flow.handle_text(USER, "jonan", paste)
        assert needle in result.replies[0], (paste, result.replies[0])
        assert result.delete_outgoing == (), paste
        assert await _row_digest(h, rid) == before, paste
        assert pending_edits.get_marker(rid).mode == "tags", paste


async def test_s44_retry_still_works_after_rejections_then_accepts(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    parsed = parse_entry_line(await _entry_line(h, rid))
    await _press(flow, "d")
    await flow.handle_text(USER, "jonan", "garbage with a [bracket]")
    await flow.handle_text(USER, "jonan", "")
    ok = await flow.handle_text(USER, "jonan", "Now correct")
    assert isinstance(ok.keyboard, ConfirmKB)
    expected = build_entry_line(parsed.name, REVIEWED, "Now correct", "tool", "free", ["linux"])
    assert await _entry_line(h, rid) == expected
    assert ok.delete_outgoing == ((CHAT, CARD),)
    assert pending_edits.get_marker(rid) is None


# ---------------------------------------------------------------- S4.5


async def test_s45_confirm_after_edit_commits_the_edited_bullet_verbatim(h: dict) -> None:
    """S4.5 (T4 repoint): field edits then ✅ commits the stored line verbatim."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    parsed = parse_entry_line(await _entry_line(h, rid))
    await _press(flow, "d")
    await flow.handle_text(USER, "jonan", "Edited description")
    await _press(flow, "t", message_id=CARD + 1)
    await flow.handle_text(USER, "jonan", "type:lab paid docker")

    edited = build_entry_line(parsed.name, REVIEWED, "Edited description", "lab", "paid", ["docker"])
    await flow.handle_confirm(USER)

    commit_call = [c for c in h["gh"].calls if c[0] == "commit_entry"][-1]
    assert commit_call[1] == f"{CHOSEN}/README.md"
    assert commit_call[2] == edited  # the EDITED bullet, verbatim
    assert (await get_resource(h["conn"], rid)).state == "COMMITTED"


# ---------------------------------------------------------------- S4.6


async def test_s46_duplicate_check_fires_on_edited_line(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await _press(flow, "d")
    await flow.handle_text(USER, "jonan", "Duplicating entry")
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
    await _press(flow, "d")
    await flow.handle_text(USER, "jonan", "Tamper test")
    await set_resource_state(h["conn"], rid, "CONFIRMING", folder="../../etc")
    calls_before = len(h["gh"].calls)
    result = await flow.handle_confirm(USER)
    assert "nothing was committed" in "\n".join(result.replies).lower()
    assert len(h["gh"].calls) == calls_before  # no GitHub call at all
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"
    assert await _audit(h, "commit_rejected")


# ---------------------------------------------------------------- safety probes (item-1 risk)


async def test_safety_markup_paste_is_refused_and_nothing_persists(h: dict) -> None:
    """T4: the bracket guard now rejects markup-carrying descriptions outright —
    no canonical persistence needed because nothing unsafe is ever stored."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    before = await _row_digest(h, rid)
    await _press(flow, "d")
    result = await flow.handle_text(
        USER, "jonan", "Uses </pre><script>alert(1)</script> `backtick` ok"
    )
    assert "can't contain" in result.replies[0]
    assert "<script>" not in result.replies[0]  # static error, no payload echo
    assert await _row_digest(h, rid) == before
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"
    # ✅ stays usable right after the refusal (S6.6)
    await flow.handle_confirm(USER)
    commit_call = [c for c in h["gh"].calls if c[0] == "commit_entry"][-1]
    assert commit_call[2] == await _entry_line(h, rid)


async def test_safety_huge_inputs_no_unhandled_exception(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    stored = await _entry_line(h, rid)
    parsed = parse_entry_line(stored)
    current_desc = f"<pre>{parsed.description}</pre>"
    await _press(flow, "d")
    for huge in ("x" * 100_000, "\u00e9" * 501, "  \n  "):
        result = await flow.handle_text(USER, "jonan", huge)
        assert len(result.replies) == 3
        assert len(result.replies[0]) <= 300  # bounded, user-safe
        assert result.replies[-1] == current_desc
    await _press(flow, "t")
    result = await flow.handle_text(USER, "jonan", "type:tool " + "y" * 100_000)
    assert "40 character limit" in result.replies[0]
    assert await _entry_line(h, rid) == stored  # never persisted
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"


async def test_safety_newline_and_control_chars_do_not_leak_into_replies(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    parsed = parse_entry_line(await _entry_line(h, rid))
    await _press(flow, "d")
    result = await flow.handle_text(USER, "jonan", "ok\n\x0cmore")
    assert "\x0c" not in result.replies[0]
    assert "\n" not in result.replies[0]
    assert result.replies[-1] == f"<pre>{parsed.description}</pre>"
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"


async def test_safety_multiline_paste_is_rejected_whole_not_silently_truncated(h: dict) -> None:
    """A multi-line description paste is refused whole (one-line rule)."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    parsed = parse_entry_line(await _entry_line(h, rid))
    before = await _row_digest(h, rid)
    await _press(flow, "d")
    result = await flow.handle_text(USER, "jonan", "First line\n- [Second](https://evil.example/)")
    assert "one line" in result.replies[0]  # whole-message rejection, no silent drop
    assert result.replies[-1] == f"<pre>{parsed.description}</pre>"
    assert await _row_digest(h, rid) == before
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"


