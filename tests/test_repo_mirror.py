"""Repo mirror sync service.

Covers README link extraction and the incremental sync contract: one tree
call and a head-sha short-circuit when the repo did not move, the startup and
interval loop, and the failure policy: a broken fetch never deletes known
links, and the state only pins to a head sha after a clean pass so the next
tick retries exactly the files that failed. All network is injected; no live
GitHub calls."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import aiosqlite
import pytest

from app.db.database import open_db
from app.db.repository import (
    find_mirror_link,
    get_mirror_state,
    list_mirror_files,
)
from app.services.github import canonical_url_key
from app.services.repo_mirror import (
    MirrorSyncError,
    extract_readme_links,
    mirror_sync_loop,
    parse_tree_response,
    sync_mirror_once,
)

OSINT = "01_Recon/OSINT"
WEB = "02_Web/Tools"
OSINT_URL = "https://github.com/x/y"
WEB_URL = "https://example.com/tool"

OSINT_README = (
    f"# OSINT\n\nIntro text with a [paragraph link](https://paragraph.test) here.\n\n"
    "## Resources\n\n"
    f"- [Tool Y]({OSINT_URL}) — a tool. `type:tool`\n"
    f"- [Tool Y again]({OSINT_URL}) — duplicate line in the same file\n"
    "+ [Legacy](https://legacy.test) — star/plus bullets too\n"
    "* [Star](https://star.test) — bullet\n"
    "- Contact: mailto:a@b.test and an [anchor](#resources) and a [relative](/docs.md)\n"
)
WEB_README = f"# Tools\n\n## Resources\n\n- [Example]({WEB_URL}) — the web tool\n"


def tree_entries(*pairs: tuple[str, str]) -> list[dict[str, Any]]:
    return [
        {"path": f"{folder}/README.md", "type": "blob", "sha": sha}
        for folder, sha in pairs
    ] + [{"path": "LICENSE", "type": "blob", "sha": "lic"}]


def make_stub(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "target_repo": "HackPot-HQ/Hackpot",
        "target_branch": "main",
        "github_token": None,
        "mirror_sync_interval_hours": 1.0,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.fixture()
async def db(tmp_path: Path) -> AsyncIterator[aiosqlite.Connection]:
    conn = await open_db(tmp_path / "data" / "hackpot.sqlite3")
    try:
        yield conn
    finally:
        await conn.close()


class FakeNet:
    """Injectable fetch_tree/fetch_raw recording every call; programmable content."""

    def __init__(self, head: str, tree: list[dict[str, Any]], contents: dict[str, str] | None = None) -> None:
        self.head = head
        self.tree = tree
        self.contents = contents or {}
        self.tree_calls = 0
        self.raw_calls: list[str] = []
        self.tree_error: Exception | None = None

    def set_repo(self, head: str, tree: list[dict[str, Any]], contents: dict[str, str] | None = None) -> None:
        self.head, self.tree = head, tree
        if contents is not None:
            self.contents = contents

    def fetch_tree(self, repo: str, branch: str, token: str | None):
        self.tree_calls += 1
        if self.tree_error is not None:
            raise self.tree_error
        return self.head, self.tree

    def fetch_raw(self, url: str, token: str | None):
        self.raw_calls.append(url)
        for path, text in self.contents.items():
            if url.endswith(path):
                return text
        return None


def test_extract_reads_bullets_and_canonicalizes() -> None:
    links = extract_readme_links(OSINT_README)
    keys = [key for key, _ in links]
    assert canonical_url_key(OSINT_URL) in keys
    assert canonical_url_key("https://legacy.test") in keys
    assert canonical_url_key("https://star.test") in keys


def test_extract_ignores_paragraph_and_non_http_links() -> None:
    keys = [key for key, _ in extract_readme_links(OSINT_README)]
    assert canonical_url_key("https://paragraph.test") not in keys
    assert not any("mailto" in key or "#" in key or key.startswith("/") for key in keys)
    assert canonical_url_key("https://docs.md") not in keys


def test_extract_dedupes_same_key_within_file() -> None:
    links = extract_readme_links(OSINT_README)
    osint_keys = [key for key, _ in links if key == canonical_url_key(OSINT_URL)]
    assert len(osint_keys) == 1


def test_extract_tolerant_of_empty_or_comment_only() -> None:
    assert extract_readme_links("") == []
    assert extract_readme_links("<!-- - [fake](https://x.test) -->") == []


async def test_first_full_sync_indexes_all_readmes(db: aiosqlite.Connection) -> None:
    net = FakeNet(
        "head-1",
        tree_entries((OSINT, "a1"), (WEB, "b1")),
        {f"{OSINT}/README.md": OSINT_README, f"{WEB}/README.md": WEB_README},
    )
    result = await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    assert result["status"] == "synced"
    row = await find_mirror_link(db, canonical_url_key(OSINT_URL))
    assert row is not None and row.folder == OSINT
    row = await find_mirror_link(db, canonical_url_key(WEB_URL))
    assert row is not None and row.folder == WEB
    assert await list_mirror_files(db) == {OSINT: "a1", WEB: "b1"}
    state = await get_mirror_state(db)
    assert state is not None and state.head_sha == "head-1"


async def test_sync_indexes_root_readme_with_empty_folder(db: aiosqlite.Connection) -> None:
    net = FakeNet(
        "head-1",
        [{"path": "README.md", "type": "blob", "sha": "r1"}],
        {"README.md": "- [Site](https://site.test) — root listing\n"},
    )
    await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    row = await find_mirror_link(db, canonical_url_key("https://site.test"))
    assert row is not None and row.folder == ""


async def test_unchanged_head_costs_one_tree_call_and_zero_raw_fetches(
    db: aiosqlite.Connection,
) -> None:
    net = FakeNet(
        "head-1",
        tree_entries((OSINT, "a1")),
        {f"{OSINT}/README.md": OSINT_README},
    )
    await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    net.raw_calls.clear()
    result = await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    assert result["status"] == "unchanged"
    assert net.tree_calls == 2
    assert net.raw_calls == []


async def test_incremental_fetches_only_changed_blob(db: aiosqlite.Connection) -> None:
    contents = {f"{OSINT}/README.md": OSINT_README, f"{WEB}/README.md": WEB_README}
    net = FakeNet("head-1", tree_entries((OSINT, "a1"), (WEB, "b1")), contents)
    await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    net.raw_calls.clear()
    new_osint = OSINT_README + "- [Fresh](https://fresh.test) — new\n"
    net.set_repo(
        "head-2",
        tree_entries((OSINT, "a2"), (WEB, "b1")),
        {**contents, f"{OSINT}/README.md": new_osint},
    )
    result = await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    assert result["status"] == "synced"
    assert len(net.raw_calls) == 1 and net.raw_calls[0].endswith(f"{OSINT}/README.md")
    assert await find_mirror_link(db, canonical_url_key("https://fresh.test")) is not None
    assert (await list_mirror_files(db))[OSINT] == "a2"
    state = await get_mirror_state(db)
    assert state is not None and state.head_sha == "head-2"


async def test_removed_readme_prunes_only_its_own_rows(db: aiosqlite.Connection) -> None:
    contents = {f"{OSINT}/README.md": OSINT_README, f"{WEB}/README.md": WEB_README}
    net = FakeNet("head-1", tree_entries((OSINT, "a1"), (WEB, "b1")), contents)
    await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    net.set_repo("head-2", tree_entries((OSINT, "a1")), contents)
    result = await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    assert result["removed"] == [WEB]
    assert await find_mirror_link(db, canonical_url_key(WEB_URL)) is None
    assert await find_mirror_link(db, canonical_url_key(OSINT_URL)) is not None
    assert (await list_mirror_files(db)).get(WEB) is None


async def test_failed_readme_fetch_keeps_old_rows_and_forces_retry(
    db: aiosqlite.Connection,
) -> None:
    contents = {f"{OSINT}/README.md": OSINT_README}
    net = FakeNet("head-1", tree_entries((OSINT, "a1")), contents)
    await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    net.set_repo("head-2", tree_entries((OSINT, "a2")), {})
    result = await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    assert result["failed"] == 1
    assert await find_mirror_link(db, canonical_url_key(OSINT_URL)) is not None
    state = await get_mirror_state(db)
    assert state is not None and state.head_sha == "head-1"
    assert (await list_mirror_files(db))[OSINT] == "a1"
    net.contents = {f"{OSINT}/README.md": "## Resources\n\n- [Only](https://only.test) — replaced\n"}
    result = await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    assert result["status"] == "synced"
    assert await find_mirror_link(db, canonical_url_key("https://only.test")) is not None
    assert await find_mirror_link(db, canonical_url_key(OSINT_URL)) is None
    state = await get_mirror_state(db)
    assert state is not None and state.head_sha == "head-2"


async def test_tree_failure_raises_and_leaves_mirror_intact(db: aiosqlite.Connection) -> None:
    net = FakeNet("head-1", tree_entries((OSINT, "a1")), {f"{OSINT}/README.md": OSINT_README})
    await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    net.tree_error = MirrorSyncError("GitHub returned HTTP 500")
    with pytest.raises(MirrorSyncError):
        await sync_mirror_once(make_stub(), db, fetch_tree=net.fetch_tree, fetch_raw=net.fetch_raw)
    assert await find_mirror_link(db, canonical_url_key(OSINT_URL)) is not None


async def test_truncated_tree_is_refused(db: aiosqlite.Connection) -> None:
    with pytest.raises(MirrorSyncError):
        parse_tree_response({"sha": "s", "tree": [{"path": "x"}], "truncated": True})


async def test_loop_syncs_at_startup_then_every_interval(db: aiosqlite.Connection) -> None:
    calls: list[int] = []
    slept: list[float] = []

    async def fake_sync(settings: Any, conn: Any) -> dict[str, Any]:
        calls.append(len(calls) + 1)
        return {"status": "synced"}

    async def fake_sleep(delay: float) -> None:
        if len(calls) >= 3:
            raise asyncio.CancelledError
        slept.append(delay)

    stub = make_stub(mirror_sync_interval_hours=1.0)
    with pytest.raises(asyncio.CancelledError):
        await mirror_sync_loop(stub, db, sleep=fake_sleep, sync=fake_sync)
    assert calls == [1, 2, 3]
    assert slept == [3600.0, 3600.0]


async def test_loop_survives_sync_failure_and_retries_next_tick(db: aiosqlite.Connection) -> None:
    calls: list[int] = []

    async def flaky_sync(settings: Any, conn: Any) -> dict[str, Any]:
        calls.append(len(calls) + 1)
        if len(calls) == 1:
            raise RuntimeError("boom")
        return {"status": "synced"}

    async def fake_sleep(delay: float) -> None:
        if len(calls) >= 2:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await mirror_sync_loop(make_stub(), db, sleep=fake_sleep, sync=flaky_sync)
    assert calls == [1, 2]
