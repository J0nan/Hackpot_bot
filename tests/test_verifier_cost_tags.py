"""Independent verifier probes for remove-cost-tag (S1-S5): emitted lines,
interview order, unknown cost callbacks, decision request shape, legacy
rebuild drops, tags grammar, /stats boards."""
from __future__ import annotations

import dataclasses
import hashlib
import inspect
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet

import app.bot.keyboards as kb_mod
from app.bot.flow import UNKNOWN_CALLBACK, AppDeps, ResourceFlow
from app.config import Settings
from app.db.database import open_db
from app.db.repository import get_resource, set_resource_state
from app.security.rate_limit import RateLimiter
from app.services.decision import ClassificationResult, DecisionClient, FolderCandidate, build_request
from app.services.github import build_entry_line, parse_entry_line

USER, URL, PAT = 100, "https://github.com/OtherOrg/awesome-tool", "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
CATS = {"02_Web_Application/Vulnerability_Specific": "web", "01_Recon/OSINT": "recon", "03_Mobile/Android": "mob"}
CHOSEN = "02_Web_Application/Vulnerability_Specific"
CHAT, CARD = 77001, 90042


def _settings(db: Path) -> Settings:
    return Settings(_env_file=None, **{  # type: ignore[arg-type]
        "telegram_bot_token": "t", "AUTHORIZED_USERS": frozenset({USER}), "CATEGORIES_JSON": dict(CATS),
        "QWEN_API_URL": "https://qwen.example.invalid/x", "qwen_api_key": "k",
        "SECRETS_ENCRYPTION_KEY": Fernet.generate_key().decode(), "db_path": db})


class _GH:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    async def repo_meta(self, o, r):
        return {"description": "A tool for things", "default_branch": "main", "homepage": "", "stars": 1}

    async def readme(self, o, r):
        return "# A\n\nbody"

    async def commit_entry(self, path, entry_line, branch, t, d):
        self.calls.append(("commit_entry", path, entry_line, branch))
        return ("https://c", "inserted")


class _Dec:
    def __init__(self) -> None:
        self.result = ClassificationResult(
            candidates=[FolderCandidate(CHOSEN, 0.75, True)], needs_admin=0.75, request_id="r", raw={}
        )

    async def classify(self, *a, **k):
        return self.result


@pytest.fixture()
async def h(tmp_path: Path):
    conn = await open_db(tmp_path / "data" / "hackpot.sqlite3")
    http, gh = httpx.AsyncClient(), _GH()
    deps = AppDeps(settings=_settings(tmp_path / "data" / "hackpot.sqlite3"), conn=conn,
                   limiter=RateLimiter(1000), http=http, make_github=lambda t: gh, make_decision=lambda: _Dec())
    try:
        yield {"conn": conn, "gh": gh, "flow": ResourceFlow(deps)}
    finally:
        await http.aclose()
        await conn.close()


async def _to_confirming(h, platforms: str = "linux") -> int:
    flow = h["flow"]
    await flow.handle_start(USER, "jonan")
    await flow.handle_text(USER, "jonan", PAT)
    await flow.handle_text(USER, "jonan", URL)
    await flow.handle_folder_choice(USER, CHOSEN)
    await flow.handle_callback(USER, "jonan", "tool")
    await flow.handle_text(USER, "jonan", platforms)
    async with h["conn"].execute("SELECT id FROM resources ORDER BY id DESC LIMIT 1") as c:
        return (await c.fetchone())["id"]


async def _row(h, rid) -> str:
    r = await get_resource(h["conn"], rid)
    return hashlib.sha256(repr((r.state, r.entry_line, r.folder, r.updated_at)).encode()).hexdigest()


# S1
def test_s1_no_cost_param_and_legacy_words_dropped() -> None:
    assert "cost_tag" not in inspect.signature(build_entry_line).parameters
    assert build_entry_line("N", "https://n.dev", "D", "tool", ["free", "paid", "freemium", "linux"]) == (
        "- [N](https://n.dev) \u2014 D. `type:tool` `linux`")


def test_s4_legacy_bullet_still_parses() -> None:
    assert parse_entry_line("- [N](https://n.dev) \u2014 D. `type:tool` `free` `linux`").tags == (
        "type:tool", "free", "linux")


# S3
def test_s3_request_shape_and_result_fields() -> None:
    assert set(build_request("m", "T-1", "c", CATS)["questions"]) == {"folder", "needs_admin"}
    assert "cost" not in [f.name for f in dataclasses.fields(ClassificationResult)]


async def test_s3_legacy_cost_answer_ignored() -> None:
    canned = {"request_id": "req-9", "answers": {
        "folder": {"choice": CHOSEN, "probabilities": {CHOSEN: 0.8}},
        "needs_admin": {"noul": 0.1}, "cost": {"choice": "freemium"}}}
    client = DecisionClient(api_url="https://qwen.example.invalid/x", api_key="k", model="m",
                            client=httpx.AsyncClient(transport=httpx.MockTransport(
                                lambda r: httpx.Response(200, json=canned))), sleep=lambda s: None)
    res = await client.classify("T-1", "c", CATS, 0.5, 5)
    assert not hasattr(res, "cost") and res.request_id == "req-9"


async def test_s3_new_decision_rows_store_empty_cost_choice(h) -> None:
    await _to_confirming(h)
    async with h["conn"].execute("SELECT cost_choice FROM decisions ORDER BY id DESC LIMIT 1") as c:
        assert (await c.fetchone())["cost_choice"] == ""


# S2
async def test_s2_interview_order_and_cost_callbacks_unknown(h) -> None:
    flow = h["flow"]
    await flow.handle_start(USER, "jonan")
    await flow.handle_text(USER, "jonan", PAT)
    await flow.handle_text(USER, "jonan", URL)
    placed = await flow.handle_folder_choice(USER, CHOSEN)
    assert "Pick the type tag:" in "\n".join(placed.replies)
    after_type = await flow.handle_callback(USER, "jonan", "tool")
    assert after_type.replies == (
        "Optional platform/tech tags, space-separated (e.g. linux docker), or send \"none\".",
    )
    for data in ("free", "paid", "freemium"):
        assert (await flow.handle_callback(USER, "jonan", data)).replies == (UNKNOWN_CALLBACK,)
    async with h["conn"].execute(
        "SELECT detail FROM audit_log WHERE action='callback_ignored' ORDER BY id DESC LIMIT 1"
    ) as c:
        assert (await c.fetchone())["detail"] == "data=freemium"
    assert not hasattr(kb_mod, "cost_kb")


# S4
async def test_s4_legacy_row_edits_drop_cost_word(h) -> None:
    flow = h["flow"]
    rid = await _to_confirming(h)
    legacy = f"- [awesome-tool]({URL}) \u2014 A tool for things. `type:tool` `free` `linux`"
    await set_resource_state(h["conn"], rid, "CONFIRMING", entry_line=legacy)
    await flow.handle_callback(USER, "jonan", "d", chat_id=CHAT, message_id=CARD)
    before = await _row(h, rid)
    rejected = await flow.handle_text(USER, "jonan", "bad [bracket] desc")
    assert any("can't contain" in x for x in rejected.replies) and await _row(h, rid) == before
    await flow.handle_text(USER, "jonan", "Fresh new description")
    assert (await get_resource(h["conn"], rid)).entry_line == (
        f"- [awesome-tool]({URL}) \u2014 Fresh new description. `type:tool` `linux`")
    await flow.handle_callback(USER, "jonan", "t", chat_id=CHAT, message_id=CARD + 1)
    before = await _row(h, rid)
    bad = await flow.handle_text(USER, "jonan", "type:tool cost:premium")
    assert any("plain words" in x for x in bad.replies) and await _row(h, rid) == before
    await flow.handle_text(USER, "jonan", "type:tool free linux")
    assert (await get_resource(h["conn"], rid)).entry_line == (
        f"- [awesome-tool]({URL}) \u2014 Fresh new description. `type:tool` `linux`")


# S5
async def test_s5_stats_boards_and_clean_commit_wire(h) -> None:
    flow = h["flow"]
    rid = await _to_confirming(h)
    await flow.handle_callback(USER, "jonan", "t", chat_id=CHAT, message_id=CARD)
    await flow.handle_text(USER, "jonan", "type:tool free linux")
    await flow.handle_confirm(USER)
    wire = [c for c in h["gh"].calls if c[0] == "commit_entry"][-1][2]
    assert "`free`" not in wire and wire.endswith("`type:tool` `linux`")
    st = await flow.handle_stats(USER, "jonan")
    assert st.replies[0].startswith("\U0001F3C6 Committed links \u2014 per curator")
    assert st.replies[1].startswith("\U0001F3F7\uFE0F Top tags \u2014 across committed links")
    assert "free" not in st.replies[1].casefold()
