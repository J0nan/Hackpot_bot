"""Security/regression probes for the T6 bot layer (commit 552ef21).

Each test mirrors an independent-verification probe: authorization gate on
both paths (S9/S17), PAT never at rest (S8/S12), injection guard (L7-1),
folder-index safety (S13/S16), commit target/path discipline (S16/S4),
and mid-interview resume (S10).
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from app.bot import handlers
from app.bot.flow import (ASK_COST, INVALID_FIELD, UNKNOWN_FOLDER,
                          AppDeps, ResourceFlow, make_github_factory)
from app.config import Settings
from app.db.database import open_db
from app.db.repository import (create_resource, get_active_resource_for_user,
                               get_github_token, get_resource, save_github_token,
                               set_resource_state, upsert_user)
from app.security.rate_limit import RateLimiter
from app.security.token_store import decrypt_pat, encrypt_pat

UID, UNAME, EVIL_ID = 1001, "alice", 666
TOKEN = "ghp_ZZZVERIFYPATTOKEN1234567890abcdefXYZ"
LEAF = "02_Web_Application/Vulnerability_Specific"
BULLET = "- [X](https://example.com/x) — d. `type:tool` `free`"

CATEGORIES = {"01_Recon/Tools": "recon", LEAF: "web", "03_Crypto/Wordlists": "crypto"}


class FakeUser:
    def __init__(self, i, u):
        self.id, self.username = i, u


class Rec:
    def __init__(self):
        self.items = []

    async def __call__(self, *a, **k):
        self.items.append((a, k))


class FakeMessage:
    def __init__(self, i, u, t):
        self.from_user = FakeUser(i, u) if i is not None else None
        self.text = t
        self.answer, self.delete = Rec(), Rec()


class FakeCallback:
    def __init__(self, i, u, d):
        self.from_user = FakeUser(i, u) if i is not None else None
        self.data = d
        self.answer = Rec()
        self.message = FakeMessage(i, u, "orig")
        self.message.edit_text = Rec()


def _no_http(request):
    raise AssertionError(f"unexpected HTTP {request.url}")


@pytest.fixture
async def env(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:TEST")
    monkeypatch.setenv("AUTHORIZED_USERS", str(UID))
    monkeypatch.setenv("CATEGORIES_JSON", json.dumps(CATEGORIES))
    monkeypatch.setenv("QWEN_API_URL", "https://qwen.example.test/x")
    monkeypatch.setenv("QWEN_API_KEY", "k")
    monkeypatch.setenv("SECRETS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("DB_PATH", str(tmp_path / "bot.sqlite3"))
    settings = Settings()
    http = httpx.AsyncClient(transport=httpx.MockTransport(_no_http), timeout=30.0)
    conn = await open_db(Path(settings.db_path))
    deps = AppDeps(
        settings=settings,
        conn=conn,
        limiter=RateLimiter(1000),
        http=http,
        make_github=lambda t: (_ for _ in ()).throw(AssertionError("github")),
        make_decision=lambda: (_ for _ in ()).throw(AssertionError("decision")),
    )
    flow = ResourceFlow(deps)
    yield deps, flow
    await conn.close()
    await http.aclose()


async def _audit(conn):
    async with conn.execute("SELECT tg_user_id, action, detail FROM audit_log") as cur:
        return [tuple(r) for r in await cur.fetchall()]


async def test_unauthorized_text_is_silent_and_audited(env):  # S9/S17
    deps, flow = env
    m = FakeMessage(EVIL_ID, "intruder", "https://github.com/evil/repo")
    await handlers.on_text(m, deps, flow)
    assert m.answer.items == [] and m.delete.items == []
    rows = [r for r in await _audit(deps.conn) if r[1] == "unauthorized_ignored"]
    assert rows and rows[0][0] == EVIL_ID and "intruder" in rows[0][2]


async def test_unauthorized_callback_is_silent_and_audited(env):  # S9/S17
    deps, flow = env
    c = FakeCallback(EVIL_ID, "intruder", "c:0")
    await handlers.on_callback(c, deps, flow)
    assert c.message.edit_text.items == [] and c.message.answer.items == []
    assert c.answer.items == [((), {})]  # empty ack, nothing shown
    assert any(r[1] == "unauthorized_ignored" and r[0] == EVIL_ID for r in await _audit(deps.conn))


async def test_pat_never_stored_or_echoed_in_plaintext(env):  # S8/S12
    deps, flow = env
    await upsert_user(deps.conn, UID, UNAME)
    m = FakeMessage(UID, UNAME, TOKEN)
    await handlers.on_text(m, deps, flow)
    stored = await get_github_token(deps.conn, UID)
    assert stored and stored.enc_token != TOKEN
    assert decrypt_pat(deps.settings, stored.enc_token) == TOKEN
    assert len(m.delete.items) == 1  # capture message deleted (S8)
    assert TOKEN not in " ".join(t for a, _ in m.answer.items for t in a)
    for p in [Path(deps.settings.db_path)] + [Path(str(deps.settings.db_path) + s) for s in ("-wal", "-shm")]:
        if p.exists():
            assert TOKEN.encode() not in p.read_bytes()


async def test_injection_guard_rejects_markup_in_name(env):  # L7-1
    deps, flow = env
    await upsert_user(deps.conn, UID, UNAME)
    r = await create_resource(deps.conn, UID, "https://example.com/t", "other")
    await set_resource_state(deps.conn, r, "AWAITING_ENTRY_INFO",
                             folder="01_Recon/Tools", context="c", entry_line="{}")
    res = await flow.handle_text(UID, UNAME, "Evil](https://evil)")
    assert res.replies == (INVALID_FIELD.format(label="Name"),)
    assert (await get_resource(deps.conn, r)).entry_line == "{}"
    assert ("entry_rejected", "field=name") in [(a, d) for _, a, d in await _audit(deps.conn)]


async def test_folder_indices_and_raw_paths_rejected(env):  # S13/S16
    deps, flow = env
    await upsert_user(deps.conn, UID, UNAME)
    r = await create_resource(deps.conn, UID, "https://example.com/t", "other")
    await set_resource_state(deps.conn, r, "AWAITING_PLACEMENT", context="c")
    for data in ("c:999", "c:-1", "f:../../etc", "c:abc", "c:1/../../etc"):
        assert (await flow.handle_callback(UID, UNAME, data)).replies == (UNKNOWN_FOLDER,)
    row = await get_resource(deps.conn, r)
    assert row.state == "AWAITING_PLACEMENT" and row.folder == ""
    for raw in ("../../etc", LEAF):
        assert "no longer available" in (await flow.handle_callback(UID, UNAME, raw)).replies[0]


async def test_commit_wire_targets_only_readme_path(env):  # S16/S4/S8
    deps, flow = env
    seen = []

    def transport(request):
        seen.append((request.method, str(request.url)))
        if request.method == "PUT":
            return httpx.Response(200, json={"content": {"commit": {"html_url": "https://github.com/J0nan/Hackpot/commit/ff"}}})
        return httpx.Response(404, json={"message": "nf"})

    http = httpx.AsyncClient(transport=httpx.MockTransport(transport), timeout=30.0)
    deps.http = http
    deps.make_github = make_github_factory(deps.settings, http)
    await upsert_user(deps.conn, UID, UNAME)
    await save_github_token(deps.conn, UID, encrypt_pat(deps.settings, TOKEN))
    r = await create_resource(deps.conn, UID, "https://example.com/t", "other")
    await set_resource_state(deps.conn, r, "CONFIRMING", folder=LEAF,
                             context="c", entry_line=BULLET)
    await ResourceFlow(deps).handle_confirm(UID)
    row = await get_resource(deps.conn, r)
    assert row.state == "COMMITTED" and row.commit_url.endswith("/commit/ff")
    assert [u for _, u in seen] == [
        f"https://api.github.com/repos/J0nan/Hackpot/contents/{LEAF}/README.md?ref=main",
        f"https://api.github.com/repos/J0nan/Hackpot/contents/{LEAF}/README.md"]
    await http.aclose()


async def test_tampered_folder_never_commits(env):  # S13/S12 (L11-b: safe reject)
    deps, flow = env
    await upsert_user(deps.conn, UID, UNAME)
    await save_github_token(deps.conn, UID, encrypt_pat(deps.settings, TOKEN))
    r = await create_resource(deps.conn, UID, "https://example.com/t", "other")
    await set_resource_state(deps.conn, r, "CONFIRMING", folder="../../etc", entry_line=BULLET)
    # T7/L11-b: handle_confirm now catches the traversal gate's ValueError instead
    # of raising. The gate itself is unchanged — deps.make_github still explodes if
    # any client is built, so reaching GitHub would fail this test loudly.
    result = await flow.handle_confirm(UID)
    assert "nothing was committed" in "\n".join(result.replies).lower()
    assert "../../etc" not in "\n".join(result.replies)
    assert (await get_resource(deps.conn, r)).state == "CONFIRMING"
    assert "commit_rejected" in [action for _, action, _ in await _audit(deps.conn)]


async def test_resume_mid_interview_on_fresh_flow(env):  # S10
    deps, flow = env
    await upsert_user(deps.conn, UID, UNAME)
    r = await create_resource(deps.conn, UID, "https://example.com/t", "other")
    await set_resource_state(deps.conn, r, "AWAITING_ENTRY_INFO", folder=LEAF, context="c",
                             entry_line=json.dumps({"name": "n", "description": "d"}, sort_keys=True))
    fresh = ResourceFlow(deps)  # simulate a restarted process
    assert (await fresh.handle_text(UID, UNAME, "tool")).replies == (ASK_COST,)
    assert json.loads((await get_resource(deps.conn, r)).entry_line)["type"] == "tool"


async def test_active_resource_excludes_final_states(env):  # S10
    deps, flow = env
    await upsert_user(deps.conn, UID, UNAME)
    for state in ("COMMITTED", "FAILED", "CANCELLED"):
        r = await create_resource(deps.conn, UID, "https://example.com/t", "other")
        await set_resource_state(deps.conn, r, state)
        assert await get_active_resource_for_user(deps.conn, UID) is None
