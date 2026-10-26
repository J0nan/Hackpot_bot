"""Tests for the SQLite persistence layer (T2; Specs S10, S16, S17).

Covers schema bootstrap and pragmas, the typed repository functions, the
resume query, decision JSON round-trips, audit rows, timestamp shape, and
injection-hostile strings stored verbatim through parameterized queries only.
Every database file lives under pytest's tmp_path; no live data is touched.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path

import aiosqlite
import pytest

from app.db.database import RESOURCE_STATES, open_db, utc_now
from app.db.models import AuditEvent, Decision, GithubToken, Resource, User
from app.db.repository import (
    audit,
    create_resource,
    delete_github_token,
    get_active_resource_for_user,
    get_github_token,
    get_resource,
    list_resources_by_states,
    record_decision,
    save_github_token,
    set_resource_state,
    upsert_user,
)

TABLES = {"users", "github_tokens", "resources", "decisions", "audit_log"}


@pytest.fixture()
async def db(tmp_path: Path) -> AsyncIterator[aiosqlite.Connection]:
    """Connection to a fresh database inside a not-yet-existing directory."""
    conn = await open_db(tmp_path / "data" / "hackpot.sqlite3")
    try:
        yield conn
    finally:
        await conn.close()


async def _fetch_one(
    conn: aiosqlite.Connection, sql: str, params: tuple[object, ...] = ()
) -> sqlite3.Row | None:
    async with conn.execute(sql, params) as cursor:
        return await cursor.fetchone()


async def _table_names(conn: aiosqlite.Connection) -> set[str]:
    async with conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'") as cursor:
        return {row["name"] for row in await cursor.fetchall()}


async def _get_user(conn: aiosqlite.Connection, tg_user_id: int) -> User:
    row = await _fetch_one(conn, "SELECT * FROM users WHERE tg_user_id = ?", (tg_user_id,))
    assert row is not None
    return User.from_row(row)


# ---------------------------------------------------------------- timestamps

def test_utc_now_is_iso8601_with_z_suffix() -> None:
    stamp = utc_now()
    assert stamp.endswith("Z")
    # Must be parseable ISO-8601 in UTC.
    parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None


# ---------------------------------------------------------------- open_db

async def test_open_db_creates_parent_dirs(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "deeper" / "hackpot.sqlite3"
    assert not path.parent.exists()
    conn = await open_db(path)
    try:
        assert path.exists()
    finally:
        await conn.close()


async def test_open_db_schema_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "data" / "hackpot.sqlite3"
    first = await open_db(path)
    await upsert_user(first, 1, "alice")
    await first.close()

    # Reopening re-runs SCHEMA over existing data without error or loss (S10).
    second = await open_db(path)
    try:
        assert await _table_names(second) >= TABLES
        user = await _get_user(second, 1)
        assert user.username == "alice"
    finally:
        await second.close()


async def test_pragmas_wal_foreign_keys_busy_timeout(db: aiosqlite.Connection) -> None:
    journal = await _fetch_one(db, "PRAGMA journal_mode")
    assert journal is not None and str(journal[0]).lower() == "wal"
    fks = await _fetch_one(db, "PRAGMA foreign_keys")
    assert fks is not None and fks[0] == 1
    timeout = await _fetch_one(db, "PRAGMA busy_timeout")
    assert timeout is not None and timeout[0] == 5000


# ---------------------------------------------------------------- users

async def test_upsert_user_keeps_first_seen_and_refreshes_username(
    db: aiosqlite.Connection,
) -> None:
    await upsert_user(db, 101, "alice")
    before = await _get_user(db, 101)
    await asyncio.sleep(0.001)
    await upsert_user(db, 101, "alice-renamed")
    after = await _get_user(db, 101)

    assert after.first_seen == before.first_seen  # first_seen stays stable
    assert after.username == "alice-renamed"
    assert after.last_seen != before.last_seen
    assert after.first_seen.endswith("Z") and after.last_seen.endswith("Z")


async def test_upsert_user_creates_distinct_rows(db: aiosqlite.Connection) -> None:
    await upsert_user(db, 1, "alice")
    await upsert_user(db, 2, "bob")
    assert (await _get_user(db, 1)).tg_user_id == 1
    assert (await _get_user(db, 2)).username == "bob"


# ---------------------------------------------------------------- github tokens

async def test_github_token_crud_roundtrip(db: aiosqlite.Connection) -> None:
    await upsert_user(db, 1, "alice")
    assert await get_github_token(db, 1) is None

    await save_github_token(db, 1, "gAAAAAB-fake-ciphertext-one")
    stored = await get_github_token(db, 1)
    assert isinstance(stored, GithubToken)
    assert stored.enc_token == "gAAAAAB-fake-ciphertext-one"
    assert stored.created_at.endswith("Z") and stored.updated_at.endswith("Z")

    await asyncio.sleep(0.001)
    await save_github_token(db, 1, "gAAAAAB-fake-ciphertext-two")
    rotated = await get_github_token(db, 1)
    assert rotated is not None and stored is not None
    assert rotated.enc_token == "gAAAAAB-fake-ciphertext-two"
    assert rotated.created_at == stored.created_at  # created_at stays stable
    assert rotated.updated_at != stored.updated_at

    await delete_github_token(db, 1)
    assert await get_github_token(db, 1) is None


async def test_github_token_foreign_key_enforced(db: aiosqlite.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        await save_github_token(db, 999, "orphan-ciphertext")


# ---------------------------------------------------------------- resources

async def test_create_resource_returns_id_with_new_defaults(
    db: aiosqlite.Connection,
) -> None:
    await upsert_user(db, 7, "bob")
    resource_id = await create_resource(db, 7, "https://github.com/owner/repo", "github")
    assert isinstance(resource_id, int) and resource_id > 0

    resource = await get_resource(db, resource_id)
    assert isinstance(resource, Resource)
    assert resource.state == "NEW"
    assert resource.kind == "github"
    assert resource.context == "" and resource.folder == ""
    assert resource.entry_line == "" and resource.commit_url == "" and resource.error == ""
    assert resource.created_at.endswith("Z") and resource.updated_at.endswith("Z")

    assert await get_resource(db, 123456) is None


async def test_create_resource_rejects_unknown_kind(db: aiosqlite.Connection) -> None:
    await upsert_user(db, 7, "bob")
    with pytest.raises(ValueError):
        await create_resource(db, 7, "https://example.com", "gitlab")


async def test_create_resource_foreign_key_enforced(db: aiosqlite.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        await create_resource(db, 999, "https://example.com", "other")


async def test_set_resource_state_updates_whitelisted_columns(
    db: aiosqlite.Connection,
) -> None:
    await upsert_user(db, 7, "bob")
    resource_id = await create_resource(db, 7, "https://example.com", "other")
    before = await get_resource(db, resource_id)
    assert before is not None

    await set_resource_state(
        db, resource_id, "NEED_SUMMARY", context="a summary", folder="02_Web/SQLi"
    )
    after = await get_resource(db, resource_id)
    assert after is not None
    assert after.state == "NEED_SUMMARY"
    assert after.context == "a summary"
    assert after.folder == "02_Web/SQLi"
    assert after.created_at == before.created_at  # created_at never rewritten
    assert after.updated_at.endswith("Z") and after.updated_at >= before.updated_at


async def test_every_schema_state_is_settable(db: aiosqlite.Connection) -> None:
    await upsert_user(db, 7, "bob")
    resource_id = await create_resource(db, 7, "https://example.com", "github")
    for state in sorted(RESOURCE_STATES):
        await set_resource_state(db, resource_id, state)
    final = await get_resource(db, resource_id)
    assert final is not None and final.state == max(sorted(RESOURCE_STATES))


async def test_set_resource_state_rejects_invalid_state_and_unknown_column(
    db: aiosqlite.Connection,
) -> None:
    await upsert_user(db, 7, "bob")
    resource_id = await create_resource(db, 7, "https://example.com", "github")

    with pytest.raises(ValueError):
        await set_resource_state(db, resource_id, "NOT_A_STATE")
    with pytest.raises(ValueError):  # typo of COMMITTED, outside the CHECK list
        await set_resource_state(db, resource_id, "COMMITED")
    with pytest.raises(ValueError):
        await set_resource_state(db, resource_id, "NEW", bogus_column="x")
    with pytest.raises(ValueError):  # kind/url/id/tg_user_id are not updatable
        await set_resource_state(db, resource_id, "NEW", kind="other")
    with pytest.raises(ValueError):
        await set_resource_state(db, resource_id, "NEW", updated_at="2020-01-01T00:00:00Z")

    untouched = await get_resource(db, resource_id)
    assert untouched is not None and untouched.state == "NEW"


# ---------------------------------------------------------------- resume

async def test_resume_returns_only_non_final_states_newest_first(
    db: aiosqlite.Connection,
) -> None:
    await upsert_user(db, 5, "carol")
    await upsert_user(db, 6, "dave")
    r1 = await create_resource(db, 5, "https://a.example/1", "other")
    r2 = await create_resource(db, 5, "https://a.example/2", "github")
    r3 = await create_resource(db, 5, "https://a.example/3", "other")
    other = await create_resource(db, 6, "https://b.example/1", "github")

    # All NEW: the newest one wins, and only the requesting user's rows.
    active = await get_active_resource_for_user(db, 5)
    assert active is not None and active.id == r3
    assert (await get_active_resource_for_user(db, 6)) is not None
    assert (await get_active_resource_for_user(db, 404)) is None

    # Each final state (COMMITTED/FAILED/CANCELLED) drops the resource.
    await set_resource_state(db, r3, "COMMITTED")
    assert (await get_active_resource_for_user(db, 5)).id == r2  # type: ignore[union-attr]
    await set_resource_state(db, r2, "CANCELLED")
    assert (await get_active_resource_for_user(db, 5)).id == r1  # type: ignore[union-attr]
    await set_resource_state(db, r1, "FAILED")
    assert await get_active_resource_for_user(db, 5) is None

    # The other user's flow is untouched by user 5 draining its states.
    resumed_other = await get_active_resource_for_user(db, 6)
    assert resumed_other is not None and resumed_other.id == other


# ---------------------------------------------------------------- decisions

async def test_record_decision_json_roundtrip(db: aiosqlite.Connection) -> None:
    await upsert_user(db, 1, "alice")
    resource_id = await create_resource(db, 1, "https://github.com/a/b", "github")

    probabilities = {"01_Recon/Passive": 0.62, "02_Web/SQLi": 0.21, "03_Wireless/Drone": 0.17}
    raw = {"answers": {"folder": {"confidence": 0.62, "probabilities": probabilities}}}
    decision_id = await record_decision(
        db,
        resource_id,
        request_id="req-1",
        folder_choice="01_Recon/Passive",
        confidence=0.62,
        probabilities=probabilities,
        needs_admin=0.02,
        cost_choice="free",
        raw_json=raw,
    )
    assert isinstance(decision_id, int) and decision_id > 0

    row = await _fetch_one(db, "SELECT * FROM decisions WHERE id = ?", (decision_id,))
    assert row is not None
    decision = Decision.from_row(row)
    assert decision.resource_id == resource_id
    assert decision.request_id == "req-1"
    assert decision.folder_choice == "01_Recon/Passive"
    assert decision.confidence == 0.62
    assert decision.needs_admin == 0.02
    assert decision.cost_choice == "free"
    assert json.loads(decision.probabilities_json) == probabilities
    assert json.loads(decision.raw_json) == raw
    assert decision.created_at.endswith("Z")


async def test_record_decision_defaults_and_unknown_field(
    db: aiosqlite.Connection,
) -> None:
    await upsert_user(db, 1, "alice")
    resource_id = await create_resource(db, 1, "https://example.com", "other")

    decision_id = await record_decision(db, resource_id, folder_choice="05_x/Y")
    row = await _fetch_one(db, "SELECT * FROM decisions WHERE id = ?", (decision_id,))
    assert row is not None
    decision = Decision.from_row(row)
    assert decision.probabilities_json == "{}"
    assert decision.needs_admin is None  # REAL column stays NULL when unset

    with pytest.raises(ValueError):
        await record_decision(db, resource_id, bogus_field="x")


# ---------------------------------------------------------------- audit

async def test_audit_insert_with_null_resource_and_user(
    db: aiosqlite.Connection,
) -> None:
    first_id = await audit(db, "unauthorized_message")
    assert isinstance(first_id, int) and first_id > 0

    row = await _fetch_one(db, "SELECT * FROM audit_log WHERE id = ?", (first_id,))
    assert row is not None
    event = AuditEvent.from_row(row)
    assert event.tg_user_id is None
    assert event.resource_id is None  # NULL resource id is legal
    assert event.action == "unauthorized_message"
    assert event.detail == ""
    assert event.created_at.endswith("Z")

    second_id = await audit(
        db, "commit_done", tg_user_id=1, resource_id=2, detail="sha:abcd"
    )
    assert second_id > first_id
    row2 = await _fetch_one(db, "SELECT * FROM audit_log WHERE id = ?", (second_id,))
    assert row2 is not None
    event2 = AuditEvent.from_row(row2)
    assert event2.tg_user_id == 1 and event2.resource_id == 2
    assert event2.detail == "sha:abcd"


# ---------------------------------------------------------------- injection hostility

async def test_hostile_strings_stored_and_retrieved_verbatim(
    db: aiosqlite.Connection,
) -> None:
    """Queries are fully parameterized: hostile payloads are inert data."""
    hostile_username = "Rob'); DROP TABLE users;--"
    hostile_url = "https://evil.example/../../etc/passwd?x=' OR 1=1--"
    hostile_context = "'; DELETE FROM resources;--\n'quote'\t"
    hostile_folder = "../../../windows/system32/README.md"
    hostile_detail = "%s %? AND sleep(30000)"

    await upsert_user(db, 42, hostile_username)
    resource_id = await create_resource(db, 42, hostile_url, "other")
    await set_resource_state(
        db,
        resource_id,
        "AWAITING_PLACEMENT",
        context=hostile_context,
        folder=hostile_folder,
        entry_line=hostile_detail,
        commit_url=hostile_url,
        error=hostile_context,
    )
    audit_id = await audit(
        db, hostile_username, tg_user_id=42, resource_id=resource_id, detail=hostile_detail
    )

    assert (await _get_user(db, 42)).username == hostile_username
    resource = await get_resource(db, resource_id)
    assert resource is not None
    assert resource.url == hostile_url
    assert resource.context == hostile_context
    assert resource.folder == hostile_folder
    assert resource.entry_line == hostile_detail
    assert resource.commit_url == hostile_url
    assert resource.error == hostile_context

    row = await _fetch_one(db, "SELECT action, detail FROM audit_log WHERE id = ?", (audit_id,))
    assert row is not None
    assert row["action"] == hostile_username and row["detail"] == hostile_detail

    # Nothing was executed: every table is still present and readable.
    assert await _table_names(db) >= TABLES
    assert await get_active_resource_for_user(db, 42) is not None


# ------------------------------------------------- duplicate-check listings

async def test_list_resources_by_states_committed_first_then_newest(
    db: aiosqlite.Connection,
) -> None:
    await upsert_user(db, 7, "bob")
    a = await create_resource(db, 7, "https://a.example/1", "other")
    b = await create_resource(db, 7, "https://a.example/2", "other")
    c = await create_resource(db, 7, "https://a.example/3", "other")
    d = await create_resource(db, 7, "https://a.example/4", "github")
    e = await create_resource(db, 7, "https://a.example/5", "github")

    await set_resource_state(db, a, "FAILED")
    await set_resource_state(db, b, "CANCELLED")
    await set_resource_state(db, c, "NEW")
    await set_resource_state(db, d, "COMMITTED", folder="01_Recon/OSINT")
    await set_resource_state(db, e, "AWAITING_PLACEMENT")

    rows = await list_resources_by_states(db, ("NEW", "AWAITING_PLACEMENT", "COMMITTED"))
    assert [r.id for r in rows] == [d, e, c]  # COMMITTED first, then newest
    assert rows[0].folder == "01_Recon/OSINT"

    # Unrequested states stay out; empty input never builds invalid SQL.
    ids = {r.id for r in rows}
    assert a not in ids and b not in ids
    assert await list_resources_by_states(db, ()) == []
