"""Mirror index persistence (repo-mirror-dedup T1; Specs S1, S2).

Schema bootstrap for the three mirror tables, the typed repository functions
behind the repo mirror (link upsert/find/replace, per-file blob shas, single-row
sync state), and the multi-folder semantics: one URL listed under two leaf
READMEs is two rows, and deleting one file must not blind the intake gate to
the other listing. Real aiosqlite under tmp_path; no network, no live data.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import aiosqlite
import pytest

from app.db.database import open_db
from app.db.models import MirrorLink, MirrorState
from app.db.repository import (
    delete_mirror_file,
    find_mirror_link,
    get_mirror_state,
    list_mirror_files,
    replace_mirror_file_links,
    set_mirror_file_sha,
    set_mirror_state,
    upsert_mirror_link,
)

MIRROR_TABLES = {"mirror_links", "mirror_files", "mirror_state"}


@pytest.fixture()
async def db(tmp_path: Path) -> AsyncIterator[aiosqlite.Connection]:
    conn = await open_db(tmp_path / "data" / "hackpot.sqlite3")
    try:
        yield conn
    finally:
        await conn.close()


async def _table_names(conn: aiosqlite.Connection) -> set[str]:
    async with conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'") as cursor:
        return {row["name"] for row in await cursor.fetchall()}


async def _folder_keys(conn: aiosqlite.Connection, folder: str) -> set[str]:
    async with conn.execute(
        "SELECT url_key FROM mirror_links WHERE folder = ?", (folder,)
    ) as cursor:
        return {row["url_key"] for row in await cursor.fetchall()}


# ----------------------------------------------------------------- schema


async def test_schema_creates_mirror_tables(db: aiosqlite.Connection) -> None:
    assert MIRROR_TABLES <= await _table_names(db)


async def test_reopening_db_keeps_mirror_state(db: aiosqlite.Connection, tmp_path: Path) -> None:
    """SCHEMA is CREATE TABLE IF NOT EXISTS: a restart never wipes the mirror."""
    await set_mirror_state(db, "head-1")
    second = await open_db(tmp_path / "data" / "hackpot.sqlite3")
    try:
        state = await get_mirror_state(second)
        assert state is not None and state.head_sha == "head-1"
    finally:
        await second.close()


# ------------------------------------------------------------ mirror_links


async def test_find_unknown_key_returns_none(db: aiosqlite.Connection) -> None:
    assert await find_mirror_link(db, "github.com/nope/nope") is None


async def test_upsert_then_find_returns_typed_row(db: aiosqlite.Connection) -> None:
    await upsert_mirror_link(db, "github.com/x/y", "https://github.com/x/y", "01_Recon/OSINT")
    row = await find_mirror_link(db, "github.com/x/y")
    assert isinstance(row, MirrorLink)
    assert row.url == "https://github.com/x/y"
    assert row.folder == "01_Recon/OSINT"
    assert row.synced_at == row.synced_at.strip() and row.synced_at.endswith("Z")


async def test_upsert_same_key_same_folder_updates_in_place(db: aiosqlite.Connection) -> None:
    await upsert_mirror_link(db, "k", "https://old", "f1")
    await upsert_mirror_link(db, "k", "https://new", "f1")
    row = await find_mirror_link(db, "k")
    assert row is not None and row.url == "https://new"
    async with db.execute("SELECT COUNT(*) AS n FROM mirror_links") as cursor:
        assert (await cursor.fetchone())["n"] == 1


async def test_same_key_in_two_folders_keeps_both_and_survives_one_delete(
    db: aiosqlite.Connection,
) -> None:
    """A hand-duplicated entry: dropping one README must not lose the other."""
    await upsert_mirror_link(db, "k", "https://a", "f1")
    await upsert_mirror_link(db, "k", "https://a", "f2")
    await set_mirror_file_sha(db, "f1", "sha-1")
    await delete_mirror_file(db, "f1")
    row = await find_mirror_link(db, "k")
    assert row is not None and row.folder == "f2"


async def test_find_is_deterministic_across_folders(db: aiosqlite.Connection) -> None:
    await upsert_mirror_link(db, "k", "https://a", "zz")
    await upsert_mirror_link(db, "k", "https://a", "aa")
    row = await find_mirror_link(db, "k")
    assert row is not None and row.folder == "aa"  # ORDER BY folder, first hit


async def test_replace_file_links_prunes_stale_and_keeps_other_folders(
    db: aiosqlite.Connection,
) -> None:
    await replace_mirror_file_links(db, "f1", [("k1", "https://1"), ("k2", "https://2")])
    await replace_mirror_file_links(db, "f2", [("k2", "https://2")])
    await replace_mirror_file_links(db, "f1", [("k2", "https://2"), ("k3", "https://3")])
    assert await find_mirror_link(db, "k1") is None  # stale entry pruned
    assert await _folder_keys(db, "f1") == {"k2", "k3"}
    assert await _folder_keys(db, "f2") == {"k2"}  # untouched by f1's replace


async def test_replace_with_empty_links_clears_folder_only(db: aiosqlite.Connection) -> None:
    await replace_mirror_file_links(db, "f1", [("k1", "https://1")])
    await replace_mirror_file_links(db, "f2", [("k1", "https://1")])
    await replace_mirror_file_links(db, "f1", [])
    assert await _folder_keys(db, "f1") == set()
    row = await find_mirror_link(db, "k1")
    assert row is not None and row.folder == "f2"


async def test_repository_functions_commit_immediately(db: aiosqlite.Connection) -> None:
    """No caller-side commit: a second connection sees the write (S4 restart safety)."""
    await upsert_mirror_link(db, "k", "https://a", "f1")
    async with db.execute("SELECT COUNT(*) AS n FROM mirror_links") as cursor:
        assert (await cursor.fetchone())["n"] == 1


# ------------------------------------------------------------ mirror_files


async def test_mirror_files_sha_map_roundtrip(db: aiosqlite.Connection) -> None:
    assert await list_mirror_files(db) == {}
    await set_mirror_file_sha(db, "f1/README.md", "sha-a")
    await set_mirror_file_sha(db, "f2/README.md", "sha-b")
    await set_mirror_file_sha(db, "f1/README.md", "sha-c")  # upsert overwrites
    assert await list_mirror_files(db) == {"f1/README.md": "sha-c", "f2/README.md": "sha-b"}


async def test_delete_mirror_file_clears_sha_and_links(db: aiosqlite.Connection) -> None:
    await replace_mirror_file_links(db, "f1", [("k1", "https://1")])
    await set_mirror_file_sha(db, "f1", "sha-1")
    await delete_mirror_file(db, "f1")
    assert await list_mirror_files(db) == {}
    assert await find_mirror_link(db, "k1") is None


# ------------------------------------------------------------ mirror_state


async def test_mirror_state_absent_before_first_sync(db: aiosqlite.Connection) -> None:
    assert await get_mirror_state(db) is None


async def test_mirror_state_single_row_overwritten(db: aiosqlite.Connection) -> None:
    await set_mirror_state(db, "head-1")
    await set_mirror_state(db, "head-2")
    state = await get_mirror_state(db)
    assert isinstance(state, MirrorState)
    assert state.head_sha == "head-2"
    async with db.execute("SELECT COUNT(*) AS n FROM mirror_state") as cursor:
        assert (await cursor.fetchone())["n"] == 1


async def test_mirror_state_timestamp_matches_utc_now_shape(
    db: aiosqlite.Connection,
) -> None:
    """synced_at uses the package's single timestamp source (ISO-8601 with Z)."""
    from datetime import datetime

    await set_mirror_state(db, "head-1")
    state = await get_mirror_state(db)
    assert state is not None
    assert state.synced_at.endswith("Z")
    parsed = datetime.fromisoformat(state.synced_at.replace("Z", "+00:00"))
    assert parsed.utcoffset().total_seconds() == 0.0
