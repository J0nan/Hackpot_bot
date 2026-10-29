"""Independent T4 verifier probes (S5/S6): field-scoped edit buttons.

Spec-derived from odd/tasks/entry-bullet-edit-confirm.md (S6.1-S6.6, S4.5,
S4.6, L7-R1 analogue). Written independently of the shipped writer tests:
own harness, own ids, own crafted canonical rows. Flow-level like
tests/test_bot_flow.py plus duck-typed handler probes. No network, no
live Telegram.
"""
from __future__ import annotations

import hashlib
from typing import Any

import httpx
import pytest
from aiogram.exceptions import TelegramAPIError
from cryptography.fernet import Fernet

from app.bot import handlers, pending_edits
from app.bot.flow import (
    ASK_DESCRIPTION,
    CONFIRMING_HINT,
    EDIT_UNAVAILABLE,
    PREVIEW,
    UNKNOWN_CALLBACK,
    AppDeps,
    ConfirmKB,
    FlowResult,
    ResourceFlow,
)
from app.bot.keyboards import confirm_kb
from app.config import Settings
from app.db.database import open_db
from app.db.repository import get_resource, set_resource_state
from app.security.rate_limit import RateLimiter
from app.services.decision import ClassificationResult, FolderCandidate
from app.services.github import DuplicateError, build_entry_line, parse_entry_line

USER = 200
INTRUDER = 777
URL = "https://github.com/VerifyOrg/probe-repo"
VALID_PAT = "ghp_" + "ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210"
CATS = {
    "01_Recon/OSINT": "recon",
    "02_Web_Application/Vulnerability_Specific": "web",
}
FOLDERS = sorted(CATS)
CHOSEN = FOLDERS[1]

CHAT = 555001
CARD = 666001

UNI_NAME = "\u00dcn\u00efcode T\u00f6\u00f6l"
UNI_DESC = "d\u00e9scription with \u2014 em-dash and \u00fcnicode"
HYPHEN_DESC = "dash - inside - the description"


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "telegram_bot_token": "123456:TEST-BOT-TOKEN",
        "AUTHORIZED_USERS": frozenset({USER}),
        "CATEGORIES_JSON": dict(CATS),
        "QWEN_API_URL": "https://qwen.example.invalid/x",
        "qwen_api_key": "qwen-test-key",
        "SECRETS_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


class FakeGitHub:
    def __init__(self) -> None:
        self.meta = {"description": "A tool for things", "default_branch": "main", "homepage": "", "stars": 7}
        self.readme_text = "# Probe\n\nbody"
        self.calls: list[tuple] = []
        self.commit_error: Exception | None = None

    async def repo_meta(self, owner, repo):
        self.calls.append(("repo_meta", owner, repo))
        return dict(self.meta)

    async def readme(self, owner, repo):
        self.calls.append(("readme", owner, repo))
        return self.readme_text

    async def commit_entry(self, path, entry_line, branch, leaf_title, leaf_description):
        self.calls.append(("commit_entry", path, entry_line, branch, leaf_title, leaf_description))
        if self.commit_error:
            raise self.commit_error
        return ("https://github.com/J0nan/Hackpot/commit/cafef00d", "inserted")


class FakeDecision:
    def __init__(self) -> None:
        self.result = ClassificationResult(
            candidates=[FolderCandidate(CHOSEN, 0.9, True), FolderCandidate(FOLDERS[0], 0.1, False)],
            needs_admin=0.9,
            request_id="req-9",
            raw={},
        )

    async def classify(self, *a, **k):
        return self.result


@pytest.fixture()
async def h(tmp_path):
    settings = make_settings(db_path=tmp_path / "data" / "probe.sqlite3")
    conn = await open_db(settings.db_path)
    http = httpx.AsyncClient()
    gh = FakeGitHub()
    deps = AppDeps(
        settings=settings,
        conn=conn,
        limiter=RateLimiter(1000),
        http=http,
        make_github=lambda token: gh,
        make_decision=lambda: FakeDecision(),
    )
    try:
        yield {"settings": settings, "conn": conn, "deps": deps, "gh": gh, "flow": ResourceFlow(deps)}
    finally:
        await http.aclose()
        await conn.close()


@pytest.fixture(autouse=True)
def _no_stale_markers():
    pending_edits.clear_all()
    yield
    pending_edits.clear_all()


async def _audit(h, action):
    async with h["conn"].execute(
        "SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,)
    ) as cur:
        return [dict(r) for r in await cur.fetchall()]


async def _rid(h):
    async with h["conn"].execute(
        "SELECT id FROM resources WHERE tg_user_id = ? ORDER BY id DESC LIMIT 1", (USER,)
    ) as cur:
        return (await cur.fetchone())[0]


async def _row(h, rid):
    return await get_resource(h["conn"], rid)


async def _line(h, rid):
    return (await _row(h, rid)).entry_line


async def _digest(h, rid):
    async with h["conn"].execute(
        "SELECT state, entry_line, folder, url, context, kind FROM resources WHERE id = ?", (rid,)
    ) as cur:
        r = await cur.fetchone()
    return hashlib.sha256(repr(tuple(r)).encode()).hexdigest()


async def _to_confirming(h, url: str = URL):
    flow = h["flow"]
    await flow.handle_start(USER, "verifier")
    await flow.handle_text(USER, "verifier", VALID_PAT)
    await flow.handle_text(USER, "verifier", url)
    await flow.handle_folder_choice(USER, CHOSEN)
    await flow.handle_callback(USER, "verifier", "tool")
    await flow.handle_text(USER, "verifier", "linux")
    return await _rid(h)


async def _press(h, data, chat_id=CHAT, message_id=CARD):
    return await h["flow"].handle_callback(
        USER, "verifier", data, chat_id=chat_id, message_id=message_id
    )


async def _craft(h, rid, name=UNI_NAME, desc=UNI_DESC, platforms=("linux",)):
    await set_resource_state(
        h["conn"], rid, "CONFIRMING",
        entry_line=build_entry_line(name, URL, desc, "tool", list(platforms)),
    )


class _Rec:
    def __init__(self):
        self.items = []

    async def __call__(self, *a, **k):
        self.items.append((a, k))


class _User:
    def __init__(self, i, u):
        self.id, self.username = i, u


def _duck_message(user_id=USER, username="verifier", chat_id=CHAT, message_id=CARD):
    m = type("M", (), {})()
    m.from_user = _User(user_id, username)
    m.text = "card"
    m.chat = type("C", (), {})()
    m.chat.id = chat_id
    m.message_id = message_id
    m.answer = _Rec()
    m.edit_text = _Rec()
    m.delete = _Rec()
    m.bot = type("B", (), {})()
    m.bot.delete_message = _Rec()
    return m


def _duck_callback(user_id=USER, username="verifier", data="d"):
    c = type("C", (), {})()
    c.from_user = _User(user_id, username)
    c.data = data
    c.answer = _Rec()
    c.message = _duck_message(user_id, username)
    return c


class _BoomBot:
    def __init__(self):
        self.calls = []

    async def delete_message(self, chat_id, message_id):
        self.calls.append((chat_id, message_id))
        raise TelegramAPIError(method=None, message="boom")


def _duck_text_message(text):
    m = _duck_message()
    m.text = text
    m.bot = _BoomBot()

    async def _delete():
        raise TelegramAPIError(method=None, message="boom")

    m.delete = _delete
    return m


# ---------------------------------------------------------------- V1 (S6.1)


def test_v1_confirm_keyboard_exact_rows_and_payloads():
    rows = [[(b.text, b.callback_data) for b in r] for r in confirm_kb(CHOSEN).inline_keyboard]
    assert rows == [
        [("\u2705 Commit to " + CHOSEN, "\u2705")],
        [("\u274c Cancel", "\u274c")],
        [("\u270f\ufe0f Description", "d"), ("\U0001f3f7\ufe0f Tags", "t")],
    ]
    for row in rows:
        for _, data in row:
            assert len(data.encode("utf-8")) <= 64
            assert "/" not in data


async def test_v1_removed_e_payload_hits_unknown_tail_with_audit(h):
    rid = await _to_confirming(h)
    result = await h["flow"].handle_callback(USER, "verifier", "e", chat_id=CHAT, message_id=CARD)
    assert result.replies == (UNKNOWN_CALLBACK,)
    assert result.keyboard is None
    rows = await _audit(h, "callback_ignored")
    assert rows[-1]["detail"] == "data=e"
    assert (await _row(h, rid)).state == "CONFIRMING"
    assert pending_edits.get_marker(rid) is None


# ---------------------------------------------------------------- V2 (S6.2)


async def test_v2_press_gated_to_confirming_authorized_sender(h):
    rid = await _to_confirming(h)
    result = await _press(h, "d")
    assert result.new_message is True and result.parse_mode == "HTML"
    assert result.keyboard is None
    assert result.delete_message is False and result.delete_outgoing == ()
    assert len(result.replies) == 2
    assert "escription" in result.replies[0]
    marker = pending_edits.get_marker(rid)
    assert marker is not None and marker.mode == "description"
    assert (marker.chat_id, marker.message_id) == (CHAT, CARD)
    assert (await _row(h, rid)).state == "CONFIRMING"  # the press persisted nothing
    assert await _audit(h, "entry_edit_requested")


async def test_v2_press_in_other_states_is_unknown_tail(h):
    flow = h["flow"]
    r_none = await flow.handle_callback(USER, "verifier", "d", chat_id=CHAT, message_id=CARD)
    assert r_none.replies == (UNKNOWN_CALLBACK,)
    await flow.handle_start(USER, "verifier")
    await flow.handle_text(USER, "verifier", VALID_PAT)
    await flow.handle_text(USER, "verifier", URL)  # AWAITING_PLACEMENT
    r_place = await flow.handle_callback(USER, "verifier", "t", chat_id=CHAT, message_id=CARD)
    assert r_place.replies == (UNKNOWN_CALLBACK,)
    await flow.handle_folder_choice(USER, CHOSEN)  # AWAITING_ENTRY_INFO
    r_entry = await flow.handle_callback(USER, "verifier", "d", chat_id=CHAT, message_id=CARD)
    assert r_entry.replies == (UNKNOWN_CALLBACK,)
    details = [r["detail"] for r in await _audit(h, "callback_ignored")]
    assert details.count("data=d") == 2 and details.count("data=t") == 1
    rid = await _rid(h)
    assert pending_edits.get_marker(rid) is None  # never armed outside CONFIRMING
    assert (await _row(h, rid)).state == "AWAITING_ENTRY_INFO"


async def test_v2_unauthorized_press_silent_and_audited(h):
    cb = _duck_callback(INTRUDER, "sneaky", "d")
    await handlers.on_callback(cb, h["deps"], h["flow"])
    assert cb.message.answer.items == [] and cb.message.edit_text.items == []
    assert cb.message.bot.delete_message.items == []
    assert cb.answer.items == [((), {})]  # empty ack, nothing shown to the sender
    rows = await _audit(h, "unauthorized_ignored")
    assert rows and rows[-1]["tg_user_id"] == INTRUDER


async def test_v2_handler_renders_press_as_new_messages_bubble_untouched(h):
    rid = await _to_confirming(h)
    stored = await _line(h, rid)
    cb = _duck_callback(USER, "verifier", "d")
    await handlers.on_callback(cb, h["deps"], h["flow"])
    assert cb.message.edit_text.items == []  # prior card bubble never edited
    assert len(cb.message.answer.items) == 2  # instruction + code block as NEW messages
    (instr, _), (block, kw) = cb.message.answer.items
    assert "escription" in instr[0]
    assert block[0].startswith("<pre>") and block[0].endswith("</pre>")
    assert kw.get("parse_mode") == "HTML"
    assert kw.get("reply_markup") is None  # the keyboard stays on the old bubble
    assert len(cb.answer.items) == 1  # callback acknowledged once
    assert cb.message.bot.delete_message.items == []  # a press deletes nothing
    assert await _line(h, rid) == stored


# ------------------------------------------------- V3 (S6.3/S6.4 extraction)


async def test_v3_code_block_shows_current_description_and_tags_exactly(h):
    rid = await _to_confirming(h)
    await _craft(h, rid)
    d = await _press(h, "d")
    assert d.replies[1] == f"<pre>{UNI_DESC}</pre>"
    t = await _press(h, "t")
    assert t.replies[1] == "<pre>`type:tool` `linux`</pre>"


async def test_v3_extraction_survives_hyphens_inside_description(h):
    rid = await _to_confirming(h)
    await _craft(h, rid, desc=HYPHEN_DESC)
    d = await _press(h, "d")
    assert d.replies[1] == f"<pre>{HYPHEN_DESC}</pre>"


async def test_v3_unparseable_row_degrades_gracefully(h):
    rid = await _to_confirming(h)
    await set_resource_state(h["conn"], rid, "CONFIRMING", entry_line="not a bullet")
    for data in ("d", "t"):
        result = await _press(h, data)
        assert result.replies == (EDIT_UNAVAILABLE,)
        assert pending_edits.get_marker(rid) is None
    result = await h["flow"].handle_text(USER, "verifier", "anything")
    assert result.replies == (CONFIRMING_HINT,)


# ------------------------------------------ V4 (byte-faithful edit pipeline)


async def test_v4_description_edit_rebuild_is_canonical_and_byte_faithful(h):
    rid = await _to_confirming(h)
    await _craft(h, rid)
    await _press(h, "d")
    result = await h["flow"].handle_text(USER, "verifier", "A sharpened probe description")
    expected = build_entry_line(UNI_NAME, URL, "A sharpened probe description", "tool", ["linux"])
    assert await _line(h, rid) == expected  # persisted == independent rebuild
    assert result.replies == (f"{PREVIEW}\n{expected}",)  # confirmation re-sent
    assert isinstance(result.keyboard, ConfirmKB) and result.keyboard.folder == CHOSEN
    assert result.parse_mode is None and result.new_message is False
    assert (await _row(h, rid)).state == "CONFIRMING"


async def test_v4_repasting_current_description_is_byte_identical(h):
    rid = await _to_confirming(h)
    stored = await _line(h, rid)
    parsed = parse_entry_line(stored)
    await _press(h, "d")
    result = await h["flow"].handle_text(USER, "verifier", parsed.description)
    assert await _line(h, rid) == stored  # idempotent no-op edit
    assert result.replies == (f"{PREVIEW}\n{stored}",)


async def test_v4_url_in_description_stays_out_of_the_link_slot(h):
    rid = await _to_confirming(h)
    stored = await _line(h, rid)
    parsed = parse_entry_line(stored)
    paste = "see https://GITHUB.COM/VerifyOrg/probe-repo for the upstream"
    await _press(h, "d")
    await h["flow"].handle_text(USER, "verifier", paste)
    line = await _line(h, rid)
    expected = build_entry_line(parsed.name, URL, paste, "tool", ["linux"])
    assert line == expected  # link slot = reviewed resource.url, paste only in text
    assert f"]({URL})" in line


async def test_v4_tags_edit_keeps_name_url_description(h):
    rid = await _to_confirming(h)
    await _craft(h, rid)
    await _press(h, "t")
    result = await h["flow"].handle_text(USER, "verifier", "type:lab paid docker")
    # S4: the pasted legacy `paid` word is dropped; the edit keeps name/url/desc.
    expected = build_entry_line(UNI_NAME, URL, UNI_DESC, "lab", ["docker"])
    assert await _line(h, rid) == expected
    assert result.replies == (f"{PREVIEW}\n{expected}",)
    assert isinstance(result.keyboard, ConfirmKB)


# ------------------------------------------------ V5 (previous-card deletion)


async def test_v5_success_deletes_exactly_the_pressed_card_once(h):
    await _to_confirming(h)
    await _press(h, "d", chat_id=111, message_id=222)
    result = await h["flow"].handle_text(USER, "verifier", "New value one")
    assert result.delete_outgoing == ((111, 222),)  # exactly one, captured at the press
    await _press(h, "t", chat_id=333, message_id=444)
    result = await h["flow"].handle_text(USER, "verifier", "type:tool free linux")
    assert result.delete_outgoing == ((333, 444),)


async def test_v5_rejection_and_missing_ids_delete_nothing(h):
    await _to_confirming(h)
    await _press(h, "t", chat_id=111, message_id=222)
    rejected = await h["flow"].handle_text(USER, "verifier", "free linux")
    assert rejected.delete_outgoing == ()
    # press with no captured ids: a successful edit must not fabricate a target
    await h["flow"].handle_callback(USER, "verifier", "d")
    ok = await h["flow"].handle_text(USER, "verifier", "No ids captured")
    assert ok.delete_outgoing == ()
    assert ok.keyboard is not None  # the edit itself still succeeded


async def test_v5_confirm_and_cancel_delete_nothing(h):
    rid = await _to_confirming(h)
    await _press(h, "d")
    await h["flow"].handle_text(USER, "verifier", "Edited then confirmed")
    confirmed = await h["flow"].handle_confirm(USER)
    assert confirmed.delete_outgoing == ()
    assert (await _row(h, rid)).state == "COMMITTED"
    # Distinct link: the second submission must not hit the intake duplicate gate.
    rid2 = await _to_confirming(h, "https://github.com/VerifyOrg/probe-repo-2")
    await _press(h, "t")
    cancelled = await h["flow"].handle_cancel(USER)
    assert cancelled.delete_outgoing == ()
    assert (await _row(h, rid2)).state == "CANCELLED"


async def test_v5_marker_replacement_tracks_only_the_latest_card(h):
    await _to_confirming(h)
    await _press(h, "d", chat_id=111, message_id=1)
    await _press(h, "t", chat_id=222, message_id=2)  # replaces the marker
    result = await h["flow"].handle_text(USER, "verifier", "type:tool free linux")
    assert result.delete_outgoing == ((222, 2),)  # never both, never anything else


async def test_v5_telegram_delete_failure_is_best_effort(h):
    msg = _duck_text_message("paste")
    result = FlowResult(("one", "two"), delete_outgoing=((CHAT, CARD),))
    await handlers._send(msg, h["deps"], result)  # must not raise
    assert [a[0][0] for a in msg.answer.items] == ["one", "two"]  # replies still sent
    assert msg.bot.calls == [(CHAT, CARD)]  # deletion attempted exactly once


async def test_v5_delete_failure_does_not_break_the_edit_flow(h):
    rid = await _to_confirming(h)
    await _press(h, "d")
    msg = _duck_text_message("Survives an API failure")
    await handlers.on_text(msg, h["deps"], h["flow"])  # must not raise
    texts = [a[0][0] for a in msg.answer.items]
    assert any(t.startswith(PREVIEW) for t in texts)  # the new card still went out
    assert "Survives an API failure" in await _line(h, rid)  # the edit still persisted
    assert (await _row(h, rid)).state == "CONFIRMING"
    assert msg.bot.calls == [(CHAT, CARD)]


# ------------------------------------------------------ V6 (marker lifecycle)


async def test_v6_text_without_marker_restores_hint_row_untouched(h):
    rid = await _to_confirming(h)
    before = await _digest(h, rid)
    whole_bullet = "- [X](https://x.example/) - pasted bullet. `type:tool` `free`"
    result = await h["flow"].handle_text(USER, "verifier", whole_bullet)
    assert result.replies == (CONFIRMING_HINT,)
    assert result.keyboard is None
    assert await _digest(h, rid) == before  # whole-bullet paste is NOT intercepted


async def test_v6_restart_loses_marker_and_falls_back(h):
    rid = await _to_confirming(h)
    before = await _digest(h, rid)
    await _press(h, "d")
    assert pending_edits.get_marker(rid) is not None
    pending_edits.clear_all()  # simulates the process restart (S6.5)
    result = await h["flow"].handle_text(USER, "verifier", "late paste after restart")
    assert result.replies == (CONFIRMING_HINT,)
    assert await _digest(h, rid) == before


async def test_v6_marker_cleared_by_confirm_and_cancel(h):
    rid = await _to_confirming(h)
    await _press(h, "d")
    await h["flow"].handle_confirm(USER)
    assert pending_edits.get_marker(rid) is None
    rid2 = await _to_confirming(h)
    await _press(h, "t")
    await h["flow"].handle_cancel(USER)
    assert pending_edits.get_marker(rid2) is None


async def test_v6_d_then_t_sequence_round_trips(h):
    rid = await _to_confirming(h)
    await _press(h, "d", chat_id=111, message_id=10)
    first = await h["flow"].handle_text(USER, "verifier", "Round one description")
    assert first.delete_outgoing == ((111, 10),)
    await _press(h, "t", chat_id=111, message_id=11)
    assert pending_edits.get_marker(rid).mode == "tags"
    second = await h["flow"].handle_text(USER, "verifier", "type:tool paid docker")
    assert second.delete_outgoing == ((111, 11),)
    line = await _line(h, rid)
    assert "Round one description" in line
    assert "`type:tool` `docker`" in line  # S4: pasted `paid` is a legacy word, dropped


async def test_v6_repeated_edits_delete_exactly_one_card_each(h):
    await _to_confirming(h)
    deletes = []
    for i in range(3):
        await _press(h, "d", chat_id=111, message_id=100 + i)
        result = await h["flow"].handle_text(USER, "verifier", f"Round {i} description")
        deletes.append(result.delete_outgoing)
    assert deletes == [((111, 100),), ((111, 101),), ((111, 102),)]


# ------------------------------------------------------- V7 (rejection table)


async def test_v7_description_rejections_specific_retry_byte_identical(h):
    rid = await _to_confirming(h)
    await _craft(h, rid)
    before = await _digest(h, rid)
    await _press(h, "d")
    cases = {
        "line one\nline two": "one line",
        "   ": "empty",
        "x" * 501: "500",
        "has [brackets]": "can't contain",
        "has `backtick`": "backticks",
        "[link](https://evil.example/)": "can't contain",
    }
    for paste, needle in cases.items():
        result = await h["flow"].handle_text(USER, "verifier", paste)
        assert len(result.replies) == 3, paste  # one specific error + instruction + value
        assert needle in result.replies[0], (paste, result.replies[0])
        assert result.replies[-1] == f"<pre>{UNI_DESC}</pre>", paste  # prompt re-offered
        assert result.delete_outgoing == (), paste
        assert result.keyboard is None, paste
        assert (await _row(h, rid)).state == "CONFIRMING", paste
        assert await _digest(h, rid) == before, paste  # row byte-identical
        marker = pending_edits.get_marker(rid)
        assert marker is not None and marker.mode == "description", paste


async def test_v7_tags_rejections_specific_retry_byte_identical(h):
    rid = await _to_confirming(h)
    await _craft(h, rid)
    before = await _digest(h, rid)
    await _press(h, "t")
    cases = {
        "free linux": "Missing type tag",
        "type:banana": "must be one of",
        "type:tool cost:premium": "plain words",
        "type:tool " + "a" * 41: "40 character limit",
        "type:tool ba|d": "invalid platform tag",
        "": "Missing type tag",
    }
    for paste, needle in cases.items():
        result = await h["flow"].handle_text(USER, "verifier", paste)
        assert len(result.replies) == 3, paste
        assert needle in result.replies[0], (paste, result.replies[0])
        assert result.replies[-1] == "<pre>`type:tool` `linux`</pre>", paste
        assert result.delete_outgoing == (), paste
        assert result.keyboard is None, paste
        assert await _digest(h, rid) == before, paste  # row byte-identical
        marker = pending_edits.get_marker(rid)
        assert marker is not None and marker.mode == "tags", paste
        assert (await _row(h, rid)).state == "CONFIRMING", paste


async def test_v7_boundary_values_accepted(h):
    rid = await _to_confirming(h)
    await _press(h, "d")
    exact = "y" * 500
    result = await h["flow"].handle_text(USER, "verifier", exact)
    assert isinstance(result.keyboard, ConfirmKB), result.replies[:1]
    assert parse_entry_line(await _line(h, rid)).description == exact
    await _press(h, "t")
    tag40 = "t" * 40
    result = await h["flow"].handle_text(USER, "verifier", f"type:tool free {tag40}")
    assert isinstance(result.keyboard, ConfirmKB), result.replies[:1]
    assert f"`{tag40}`" in await _line(h, rid)


async def test_v7_duplicate_tags_are_deduped_and_accepted(h):
    rid = await _to_confirming(h)
    stored = await _line(h, rid)
    parsed = parse_entry_line(stored)
    await _press(h, "t")
    result = await h["flow"].handle_text(USER, "verifier", "type:tool free linux linux linux")
    expected = build_entry_line(parsed.name, URL, parsed.description, "tool", ["linux"])
    assert await _line(h, rid) == expected  # byte-identical rebuild (S6.4 dedupe)
    assert result.replies == (f"{PREVIEW}\n{expected}",)
    assert result.delete_outgoing == ((CHAT, CARD),)


# ------------------------------------------- V8 (S4.5/S4.6/S6.7 preservation)


async def test_v8_edited_entry_committed_verbatim(h):
    rid = await _to_confirming(h)
    await _craft(h, rid)
    await _press(h, "d")
    await h["flow"].handle_text(USER, "verifier", "Final edited description")
    await _press(h, "t")
    await h["flow"].handle_text(USER, "verifier", "type:lab paid docker")
    expected = build_entry_line(UNI_NAME, URL, "Final edited description", "lab", ["docker"])
    assert await _line(h, rid) == expected
    await h["flow"].handle_confirm(USER)
    call = [c for c in h["gh"].calls if c[0] == "commit_entry"][-1]
    assert call[1] == f"{CHOSEN}/README.md"
    assert call[2] == expected  # S4.5: the edited line, verbatim
    assert (await _row(h, rid)).state == "COMMITTED"


async def test_v8_duplicate_link_detection_fires_after_edit(h):
    rid = await _to_confirming(h)
    await _press(h, "d")
    await h["flow"].handle_text(USER, "verifier", "Duplicated entry")
    h["gh"].commit_error = DuplicateError(
        "That link is already listed in " + CHOSEN + "/README.md - nothing was committed."
    )
    result = await h["flow"].handle_confirm(USER)
    assert "already" in "\n".join(result.replies).lower()
    assert (await _row(h, rid)).state == "CONFIRMING"
    assert await _audit(h, "commit_duplicate")


async def test_v8_tampered_folder_rejected_after_edit(h):
    rid = await _to_confirming(h)
    await _press(h, "d")
    await h["flow"].handle_text(USER, "verifier", "Tamper case")
    await h["conn"].execute("UPDATE resources SET folder = ? WHERE id = ?", ("../../etc", rid))
    await h["conn"].commit()
    calls_before = len(h["gh"].calls)
    result = await h["flow"].handle_confirm(USER)
    assert "nothing was committed" in "\n".join(result.replies).lower()
    assert len(h["gh"].calls) == calls_before  # GitHub never called
    assert (await _row(h, rid)).state == "CONFIRMING"
    assert await _audit(h, "commit_rejected")


# ------------------------------------------- V10 (L7-R1 analogue on the guard)


async def test_v10_no_edit_path_persists_a_bracket_bearing_description(h):
    rid = await _to_confirming(h)
    before = await _digest(h, rid)
    await _press(h, "d")
    for paste in ("[a](https://evil.example/)", "b [x] c", "d `e` f"):
        result = await h["flow"].handle_text(USER, "verifier", paste)
        assert "can't contain" in result.replies[0], paste
        assert await _digest(h, rid) == before, paste
    # the tags field can never smuggle a description either
    await _press(h, "t")
    result = await h["flow"].handle_text(USER, "verifier", "type:tool free linux")
    line = await _line(h, rid)
    assert line.count("[") == 1 and line.count("]") == 1  # only the canonical name link


async def test_v10_repo_meta_bracket_advisory(h):
    """ADVISORY reproduction (pre-existing at baseline 723881c, unchanged by
    T4): a GitHub repo description carrying markdown-link syntax pre-fills
    the bullet description without the bracket guard (flow.py:633/732-734,
    both untouched hunks). T4 hardened only the paste path (S6.3).
    Admin-only, previewed before the irreversible commit - same framing as
    the baseline L7-R1 finding."""
    flow = h["flow"]
    await flow.handle_start(USER, "verifier")
    await flow.handle_text(USER, "verifier", VALID_PAT)
    h["gh"].meta["description"] = "repo desc with [markdown](https://evil.example/) link"
    await flow.handle_text(USER, "verifier", URL)
    await flow.handle_folder_choice(USER, CHOSEN)
    await flow.handle_callback(USER, "verifier", "tool")
    await flow.handle_text(USER, "verifier", "linux")
    rid = await _rid(h)
    line = await _line(h, rid)
    assert "[markdown](https://evil.example/)" in line  # ADVISORY: pre-existing
