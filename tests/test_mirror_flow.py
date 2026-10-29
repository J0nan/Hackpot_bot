"""Flow integration of the repo mirror (repo-mirror-dedup T3; Specs S1, S6).

The intake gate must refuse a link that exists only in the repo mirror —
nothing is created, one ``duplicate_mirror`` audit row is kept, the reply
names the folder — while DB-row matches keep their exact existing replies
(in-progress wins over mirror because it is checked first), and a successful
commit refreshes the mirror immediately (S6). Real aiosqlite + real Settings +
hand-rolled fakes, same harness style as tests/test_bot_flow.py. No network.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.fernet import Fernet

from app.bot import pending_edits
from app.bot.flow import (
    ALREADY_COMMITTED,
    ALREADY_COMMITTED_OUTSIDE,
    ALREADY_IN_PROGRESS,
    AppDeps,
    STATS_EMPTY,
    ResourceFlow,
)
from app.config import Settings
from app.db.database import open_db
from app.db.repository import (
    create_resource,
    find_mirror_link,
    set_resource_state,
    upsert_mirror_link,
    upsert_user,
)
from app.security.rate_limit import RateLimiter
from app.services.decision import ClassificationResult, FolderCandidate
from app.services.github import DuplicateError, canonical_url_key

USER = 100
GITHUB_URL = "https://github.com/OtherOrg/awesome-tool"
VALID_PAT = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz012345"

CATEGORIES = {
    "02_Web_Application/Vulnerability_Specific": "web vulnerability tooling",
    "01_Recon/OSINT": "recon and OSINT resources",
    "03_Mobile/Android": "android security resources",
}
FOLDERS = sorted(CATEGORIES)
CHOSEN = FOLDERS[1]


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "telegram_bot_token": "123456:TEST-BOT-TOKEN",
        "AUTHORIZED_USERS": frozenset({USER}),
        "CATEGORIES_JSON": dict(CATEGORIES),
        "QWEN_API_URL": "https://qwen.example.invalid/compatible-mode/v1/systemone",
        "qwen_api_key": "qwen-test-key",
        "SECRETS_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


class FakeGitHub:
    def __init__(self) -> None:
        self.meta = {"description": "A tool", "default_branch": "main", "homepage": "", "stars": 42}
        self.readme_text = "# Awesome\n\nBody for the model."
        self.calls: list[tuple] = []
        self.commit_error: Exception | None = None
        self.commit_result = ("https://github.com/J0nan/Hackpot/commit/deadbeef", "inserted")

    async def repo_meta(self, owner: str, repo: str) -> dict[str, Any]:
        return dict(self.meta)

    async def readme(self, owner: str, repo: str) -> str:
        return self.readme_text

    async def commit_entry(self, path, entry_line, branch, leaf_title, leaf_description):
        self.calls.append(("commit_entry", path, entry_line))
        if self.commit_error:
            raise self.commit_error
        return self.commit_result


class FakeDecision:
    def __init__(self) -> None:
        self.result = ClassificationResult(
            candidates=[FolderCandidate(CHOSEN, 0.75, True), FolderCandidate(FOLDERS[0], 0.2, False)],
            needs_admin=0.75,
            request_id="req-1",
            raw={},
        )

    async def classify(self, ticket_id, content, categories, threshold, max_candidates):
        return self.result


@pytest.fixture()
async def h(tmp_path: Path) -> AsyncIterator[dict[str, Any]]:
    settings = make_settings(db_path=tmp_path / "data" / "hackpot.sqlite3")
    conn = await open_db(settings.db_path)
    http = httpx.AsyncClient()
    gh = FakeGitHub()
    decision = FakeDecision()
    deps = AppDeps(
        settings=settings,
        conn=conn,
        limiter=RateLimiter(1000),
        http=http,
        make_github=lambda token: gh,
        make_decision=lambda: decision,
    )
    try:
        yield {"settings": settings, "conn": conn, "deps": deps, "gh": gh, "flow": ResourceFlow(deps)}
    finally:
        await http.aclose()
        await conn.close()


@pytest.fixture(autouse=True)
def _no_stale_edit_markers() -> AsyncIterator[None]:
    pending_edits.clear_all()
    yield
    pending_edits.clear_all()


async def _audit(h: dict, action: str) -> list[dict[str, Any]]:
    async with h["conn"].execute(
        "SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,)
    ) as cursor:
        return [dict(row) for row in await cursor.fetchall()]


async def _resource_count(h: dict) -> int:
    async with h["conn"].execute("SELECT COUNT(*) AS n FROM resources") as cursor:
        return (await cursor.fetchone())["n"]


async def _capture_token(h: dict) -> None:
    flow = h["flow"]
    await flow.handle_start(USER, "jonan")
    await flow.handle_text(USER, "jonan", VALID_PAT)


async def _to_confirming(h: dict) -> ResourceFlow:
    flow = await _to_placement(h)
    await flow.handle_folder_choice(USER, CHOSEN)
    await flow.handle_callback(USER, "jonan", "tool")
    await flow.handle_text(USER, "jonan", "linux")
    return flow


async def _to_placement(h: dict) -> ResourceFlow:
    await _capture_token(h)
    result = await h["flow"].handle_text(USER, "jonan", GITHUB_URL)
    assert result.keyboard is not None
    return h["flow"]


# ------------------------------------------------------------- S1: intake gate


async def test_mirror_only_link_is_refused_and_nothing_is_created(h: dict) -> None:
    await upsert_mirror_link(h["conn"], canonical_url_key(GITHUB_URL), GITHUB_URL, "01_Recon/OSINT")
    await h["flow"].handle_start(USER, "jonan")
    result = await h["flow"].handle_text(USER, "jonan", GITHUB_URL)
    assert result.replies == (ALREADY_COMMITTED_OUTSIDE.format(folder="01_Recon/OSINT"),)
    assert result.keyboard is None
    assert await _resource_count(h) == 0  # no resource row, no flow started
    rows = await _audit(h, "duplicate_mirror")
    assert len(rows) == 1 and "01_Recon/OSINT" in rows[0]["detail"]


async def test_mirror_match_uses_canonical_identity(h: dict) -> None:
    """Trailing slash / scheme-insensitive key: the mirror catches the same URL."""
    await upsert_mirror_link(h["conn"], canonical_url_key("https://example.com/a"), "https://example.com/a", "f")
    await h["flow"].handle_start(USER, "jonan")
    result = await h["flow"].handle_text(USER, "jonan", "https://example.com/a/")
    assert result.replies and "already listed" in result.replies[0]
    assert await _resource_count(h) == 0


async def test_root_readme_hit_names_the_repo_root(h: dict) -> None:
    await upsert_mirror_link(h["conn"], canonical_url_key(GITHUB_URL), GITHUB_URL, "")
    await h["flow"].handle_start(USER, "jonan")
    result = await h["flow"].handle_text(USER, "jonan", GITHUB_URL)
    assert result.replies == (ALREADY_COMMITTED_OUTSIDE.format(folder="the repo root"),)


async def test_db_in_progress_row_wins_over_mirror(h: dict) -> None:
    """Ordering pin: a live resource (bot-known) keeps the ALREADY_IN_PROGRESS reply.

    The duplicate gate is global (all users), so the live row belongs to
    another user: this exercises the gate itself, not flow resumption.
    """
    other = 999
    await upsert_user(h["conn"], other, "someone-else")
    resource_id = await create_resource(h["conn"], other, GITHUB_URL, "github")
    await upsert_mirror_link(h["conn"], canonical_url_key(GITHUB_URL), GITHUB_URL, "01_Recon/OSINT")
    await h["flow"].handle_start(USER, "jonan")
    result = await h["flow"].handle_text(USER, "jonan", GITHUB_URL)
    assert result.replies and "being processed" in result.replies[0]
    assert str(resource_id) in result.replies[0]
    assert ALREADY_COMMITTED_OUTSIDE not in result.replies


async def test_committed_db_row_keeps_existing_reply(h: dict) -> None:
    """Regression: DB COMMITTED rows still answer with ALREADY_COMMITTED, unchanged."""
    await upsert_user(h["conn"], USER, "jonan")
    resource_id = await create_resource(h["conn"], USER, GITHUB_URL, "github")
    await set_resource_state(h["conn"], resource_id, "COMMITTED", folder=CHOSEN)
    await h["flow"].handle_start(USER, "jonan")
    result = await h["flow"].handle_text(USER, "jonan", GITHUB_URL)
    assert result.replies[0] == ALREADY_COMMITTED.format(folder=CHOSEN)
    assert ALREADY_COMMITTED_OUTSIDE not in result.replies


async def test_stats_unaffected_by_mirror_rows(h: dict) -> None:
    """S2 acceptance: the mirror never leaks into the curator leaderboards."""
    await upsert_mirror_link(h["conn"], "a.test", "https://a.test", "f")
    await upsert_mirror_link(h["conn"], "b.test", "https://b.test", "f")
    await h["flow"].handle_start(USER, "jonan")
    result = await h["flow"].handle_stats(USER, "jonan")
    assert result.replies[0] == STATS_EMPTY


# ------------------------------------------------------------- S6: commit refresh


async def test_successful_commit_upserts_mirror(h: dict) -> None:
    flow = await _to_confirming(h)
    result = await flow.handle_confirm(USER)
    assert any("✅" in reply for reply in result.replies)
    row = await find_mirror_link(h["conn"], canonical_url_key(GITHUB_URL))
    assert row is not None and row.folder == CHOSEN


async def test_failed_commit_does_not_touch_mirror(h: dict) -> None:
    flow = await _to_confirming(h)
    h["gh"].commit_error = DuplicateError("dup")
    result = await flow.handle_confirm(USER)
    assert result.replies == ("dup",)
    assert await find_mirror_link(h["conn"], canonical_url_key(GITHUB_URL)) is None
