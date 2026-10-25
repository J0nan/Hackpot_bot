"""Tests for the bot orchestration flow (T6; Specs S1-S9, S14; ODD L7 follow-ups).

Real aiosqlite (tmp_path) + real Settings built from a fake env (never the
machine env), with hand-rolled GitHub/Decision fakes injected through the
AppDeps factories. No network, no aiogram objects: flow.py must stay
framework-free. Every assertion goes through observable effects: returned
FlowResults, stored rows, and audit entries. (T7 adds the L11-a/b/c + L7-4
hardening pins here; the one handler-wiring probe uses a duck-typed Message,
same style as tests/test_bot_gate_regression.py.)
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.fernet import Fernet

from app.bot import handlers
from app.bot.flow import (
    AppDeps,
    CandidatesKB,
    ConfirmKB,
    CostKB,
    FoldersKB,
    ResourceFlow,
    SLOW_DOWN,
    TypeKB,
    UNKNOWN_FOLDER,
    make_github_factory,
)
from app.bot.handlers import precheck
from app.config import Settings
from app.db.database import open_db
from app.db.repository import (
    create_resource,
    get_active_resource_for_user,
    get_github_token,
    get_resource,
    set_resource_state,
    upsert_user,
)
from app.security.rate_limit import RateLimiter
from app.security.sanitizers import sanitize_line
from app.security.token_store import decrypt_pat
from app.services.decision import ClassificationResult, DecisionError, FolderCandidate
from app.services.github import DuplicateError, FetchError

USER = 100
INTRUDER = 999
GITHUB_URL = "https://github.com/OtherOrg/awesome-tool"
VALID_PAT = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz012345"

CATEGORIES = {
    "02_Web_Application/Vulnerability_Specific": "web vulnerability tooling",
    "01_Recon/OSINT": "recon and OSINT resources",
    "03_Mobile/Android": "android security resources",
}
FOLDERS = sorted(CATEGORIES)  # ["01_Recon/OSINT", "02_...", "03_Mobile/Android"]
CHOSEN = FOLDERS[1]  # 02_Web_Application/Vulnerability_Specific


def make_settings(**overrides: Any) -> Settings:
    """Validated Settings from test-only values (never reads the real env)."""
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
    """Stand-in for GitHubClient: records calls, raises programmed failures."""

    def __init__(self) -> None:
        self.meta: dict[str, Any] = {
            "description": "A tool for things",
            "default_branch": "main",
            "homepage": "",
            "stars": 42,
        }
        self.readme_text = "# Awesome\n\nReadme magic body that must reach the model."
        self.calls: list[tuple] = []
        self.read_error: Exception | None = None
        self.commit_error: Exception | None = None
        self.commit_result = ("https://github.com/J0nan/Hackpot/commit/deadbeef", "inserted")

    async def repo_meta(self, owner: str, repo: str) -> dict[str, Any]:
        self.calls.append(("repo_meta", owner, repo))
        return dict(self.meta)

    async def readme(self, owner: str, repo: str) -> str:
        self.calls.append(("readme", owner, repo))
        if self.read_error:
            raise self.read_error
        return self.readme_text

    async def commit_entry(self, path, entry_line, branch, leaf_title, leaf_description):
        self.calls.append(("commit_entry", path, entry_line, branch, leaf_title, leaf_description))
        if self.commit_error:
            raise self.commit_error
        return self.commit_result


class FakeDecision:
    """Stand-in for DecisionClient.classify with recorded kwargs."""

    def __init__(self) -> None:
        self.result = ClassificationResult(
            candidates=[
                FolderCandidate(CHOSEN, 0.75, True),
                FolderCandidate(FOLDERS[0], 0.2, False),
            ],
            needs_admin=0.75,
            cost="free",
            request_id="req-1",
            raw={"answers": {"folder": {"choice": CHOSEN}}},
        )
        self.error: Exception | None = None
        self.calls: list[dict[str, Any]] = []

    async def classify(self, ticket_id, content, categories, threshold, max_candidates):
        self.calls.append(
            {
                "ticket_id": ticket_id,
                "content": content,
                "categories": categories,
                "threshold": threshold,
                "max_candidates": max_candidates,
            }
        )
        if self.error:
            raise self.error
        return self.result


@pytest.fixture()
async def h(tmp_path: Path) -> AsyncIterator[dict[str, Any]]:
    """AppDeps wired to a real sqlite DB, real Settings, fake seams."""
    settings = make_settings(db_path=tmp_path / "data" / "hackpot.sqlite3")
    conn = await open_db(settings.db_path)
    http = httpx.AsyncClient()
    gh = FakeGitHub()
    decision = FakeDecision()
    github_tokens: list[str | None] = []

    def make_github(token: str | None) -> FakeGitHub:
        github_tokens.append(token)
        return gh

    deps = AppDeps(
        settings=settings,
        conn=conn,
        limiter=RateLimiter(1000),
        http=http,
        make_github=make_github,
        make_decision=lambda: decision,
    )
    try:
        yield {
            "settings": settings,
            "conn": conn,
            "deps": deps,
            "gh": gh,
            "decision": decision,
            "github_tokens": github_tokens,
            "flow": ResourceFlow(deps),
        }
    finally:
        await http.aclose()
        await conn.close()


async def _audit(h: dict, action: str) -> list[dict[str, Any]]:
    async with h["conn"].execute(
        "SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,)
    ) as cursor:
        return [dict(row) for row in await cursor.fetchall()]


async def _capture_token(h: dict) -> None:
    flow = h["flow"]
    await flow.handle_start(USER, "jonan")
    result = await flow.handle_text(USER, "jonan", VALID_PAT)
    assert result.delete_message is True


async def _to_placement(h: dict) -> ResourceFlow:
    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_text(USER, "jonan", GITHUB_URL)
    assert result.keyboard is not None
    return flow


async def _to_confirming(h: dict) -> tuple[ResourceFlow, Any]:
    flow = await _to_placement(h)
    await flow.handle_folder_choice(USER, CHOSEN)
    # github kind pre-fills name/description from repo meta, cost from decision
    await flow.handle_callback(USER, "jonan", "tool")  # type step
    result = await flow.handle_text(USER, "jonan", "linux")  # platforms -> preview
    return flow, result


# ----------------------------------------------------------------- S9 gate


async def test_unauthorized_is_silent_and_audited(h: dict) -> None:
    result = await h["flow"].handle_unauthorized(INTRUDER, "sneaky")
    assert result.replies == ()
    assert result.keyboard is None
    rows = await _audit(h, "unauthorized_ignored")
    assert len(rows) == 1
    assert rows[0]["tg_user_id"] == INTRUDER
    assert "sneaky" in rows[0]["detail"]


def test_precheck_rejects_unknown_user(h: dict) -> None:
    assert precheck(h["deps"], INTRUDER) == "unauthorized"
    assert precheck(h["deps"], None) == "unauthorized"


def test_precheck_unauthorized_never_consumes_rate_budget(h: dict) -> None:
    for _ in range(20):
        assert precheck(h["deps"], INTRUDER) == "unauthorized"
    assert precheck(h["deps"], USER) == "ok"


def test_precheck_rate_limits_after_window_budget(h: dict) -> None:
    deps = h["deps"]
    deps.limiter = RateLimiter(2)
    assert precheck(deps, USER) == "ok"
    assert precheck(deps, USER) == "ok"
    assert precheck(deps, USER) == "rate_limited"
    assert precheck(deps, USER) == "rate_limited"
    assert SLOW_DOWN  # handlers reply exactly once with this wording


# ---------------------------------------------------------------- PAT store


async def test_pat_capture_encrypts_stores_and_deletes(h: dict) -> None:
    flow = h["flow"]
    await flow.handle_start(USER, "jonan")
    result = await flow.handle_text(USER, "jonan", VALID_PAT)
    assert result.delete_message is True
    assert result.replies  # confirmation reply exists
    assert all(VALID_PAT not in r for r in result.replies)

    stored = await get_github_token(h["conn"], USER)
    assert stored is not None
    assert stored.enc_token != VALID_PAT  # ciphertext at rest
    assert decrypt_pat(h["settings"], stored.enc_token) == VALID_PAT
    assert await _audit(h, "pat_captured")


async def test_start_asks_pat_when_missing_offers_link_when_present(h: dict) -> None:
    flow = h["flow"]
    result = await flow.handle_start(USER, "jonan")
    text = "\n".join(result.replies)
    assert "token" in text.lower()
    assert "personal-access-tokens" in text.lower()  # start prompt offers the PAT creation link

    await _capture_token(h)
    result = await flow.handle_start(USER, "jonan")
    assert "link" in "\n".join(result.replies).lower()
    assert "github personal access" not in "\n".join(result.replies).lower()


async def test_forget_deletes_stored_pat(h: dict) -> None:
    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_forget(USER)
    assert "token" in "\n".join(result.replies).lower()
    assert await get_github_token(h["conn"], USER) is None
    assert await _audit(h, "pat_forgotten")


async def test_link_before_token_parks_resource_then_resumes_after_capture(h: dict) -> None:
    flow = h["flow"]
    await flow.handle_start(USER, "jonan")
    result = await flow.handle_text(USER, "jonan", GITHUB_URL)
    active = await get_active_resource_for_user(h["conn"], USER)
    assert active is not None and active.state == "NEED_TOKEN" and active.kind == "github"

    result = await flow.handle_text(USER, "jonan", "I do not have one yet")
    assert "token" in "\n".join(result.replies).lower()
    active = await get_active_resource_for_user(h["conn"], USER)
    assert active.state == "NEED_TOKEN"

    result = await flow.handle_text(USER, "jonan", VALID_PAT)
    assert result.delete_message is True
    assert h["github_tokens"][0] == VALID_PAT  # fetch used the sender's own PAT
    active = await get_active_resource_for_user(h["conn"], USER)
    assert active.state == "AWAITING_PLACEMENT"


# ---------------------------------------------------------------- link intake


async def test_zero_or_multiple_urls_gives_usage_hint(h: dict) -> None:
    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_text(USER, "jonan", "just some prose")
    assert result.replies and "link" in "\n".join(result.replies).lower()
    result = await flow.handle_text(
        USER, "jonan", f"see {GITHUB_URL} and https://example.com/other too"
    )
    assert "\n".join(result.replies).lower().count("one") >= 1
    assert await get_active_resource_for_user(h["conn"], USER) is None  # nothing created


async def test_github_url_fetches_readme_then_classifies_into_candidates(h: dict) -> None:
    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_text(USER, "jonan", GITHUB_URL)

    assert ("repo_meta", "OtherOrg", "awesome-tool") in h["gh"].calls
    assert ("readme", "OtherOrg", "awesome-tool") in h["gh"].calls
    call = h["decision"].calls[-1]
    resource = await get_active_resource_for_user(h["conn"], USER)
    assert call["ticket_id"] == f"T-{resource.id}"
    assert call["content"].startswith(GITHUB_URL)
    assert "Readme magic body" in call["content"]
    assert call["categories"] == dict(CATEGORIES)
    assert call["threshold"] == h["settings"].confidence_threshold
    assert call["max_candidates"] == h["settings"].max_candidates_shown

    assert resource.state == "AWAITING_PLACEMENT"
    assert isinstance(result.keyboard, CandidatesKB)
    assert [c.folder for c in result.keyboard.candidates] == [CHOSEN, FOLDERS[0]]

    async with h["conn"].execute("SELECT * FROM decisions WHERE resource_id = ?", (resource.id,)) as cur:
        row = dict(await cur.fetchone())
    assert json.loads(row["probabilities_json"]) == {CHOSEN: 0.75, FOLDERS[0]: 0.2}
    assert row["needs_admin"] == 0.75
    assert row["cost_choice"] == "free"
    assert row["request_id"] == "req-1"
    assert row["folder_choice"] == CHOSEN
    assert json.loads(row["raw_json"]) == {"answers": {"folder": {"choice": CHOSEN}}}
    assert await _audit(h, "decision_recorded")


async def test_readme_excerpt_is_capped_near_6000_chars(h: dict) -> None:
    h["gh"].readme_text = "lead para\n\n" + ("x" * 20_000)
    flow = h["flow"]
    await _capture_token(h)
    await flow.handle_text(USER, "jonan", GITHUB_URL)
    content = h["decision"].calls[-1]["content"]
    assert content.count("x") <= 6000  # L7-2
    assert "lead para" in content


async def test_github_fetch_failure_asks_summary_with_public_reminder(h: dict) -> None:
    h["gh"].read_error = FetchError("GitHub is unreachable right now. (HTTP 404)", public_hint=True)
    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_text(USER, "jonan", GITHUB_URL)
    resource = await get_active_resource_for_user(h["conn"], USER)
    assert resource.state == "NEED_SUMMARY"
    text = "\n".join(result.replies).lower()
    assert "summary" in text and "public" in text
    rows = await _audit(h, "fetch_failed")
    assert "404" in rows[-1]["detail"]  # L7-5: status lands in audit, not chat


async def test_summary_path_records_context_then_classifies(h: dict) -> None:
    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_text(USER, "jonan", "https://cool-labs.io/tool")
    assert result.replies
    assert (await get_active_resource_for_user(h["conn"], USER)).state == "NEED_SUMMARY"

    await flow.handle_text(USER, "jonan", "An offline wordlist generator for fuzzing.")
    call = h["decision"].calls[-1]
    assert "https://cool-labs.io/tool" in call["content"]
    assert "wordlist generator" in call["content"]
    resource = await get_active_resource_for_user(h["conn"], USER)
    assert resource.kind == "other"
    assert resource.state == "AWAITING_PLACEMENT"


async def test_decision_failure_fails_resource_and_audits_without_leaks(h: dict) -> None:
    h["decision"].error = DecisionError(
        "decision API rejected the request after 3 attempt(s) with HTTP 503: backend busy"
    )
    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_text(USER, "jonan", GITHUB_URL)
    text = "\n".join(result.replies)
    assert "503" not in text and "HTTP" not in text  # no internal detail to user
    created = h["conn"].execute("SELECT * FROM resources ORDER BY id DESC LIMIT 1")
    async with created as cursor:
        row = await cursor.fetchone()
    assert row["state"] == "FAILED"
    assert "503" in row["error"]
    rows = await _audit(h, "decision_failed")
    assert "503" in rows[-1]["detail"]
    assert await get_active_resource_for_user(h["conn"], USER) is None  # FAILED is final


# ---------------------------------------------------------------- placement


async def test_folder_choice_by_callback_index_round_trip(h: dict) -> None:
    flow = await _to_placement(h)
    index = FOLDERS.index(CHOSEN)
    result = await flow.handle_callback(USER, "jonan", f"c:{index}")
    resource = await get_active_resource_for_user(h["conn"], USER)
    assert resource.state == "AWAITING_ENTRY_INFO"
    assert resource.folder == CHOSEN
    assert "double-check" in "\n".join(result.replies).lower()  # S7 needs_admin >= 0.5
    assert await _audit(h, "placement_chosen")


async def test_folder_choice_without_needs_admin_note(h: dict) -> None:
    h["decision"].result = ClassificationResult(
        candidates=[FolderCandidate(CHOSEN, 0.75, True)],
        needs_admin=0.2,
        cost="free",
        request_id="req-2",
        raw={},
    )
    flow = await _to_placement(h)
    result = await flow.handle_folder_choice(USER, CHOSEN)
    assert "double-check" not in "\n".join(result.replies).lower()


async def test_folder_choice_rejects_invalid_callback_index(h: dict) -> None:
    flow = await _to_placement(h)
    result = await flow.handle_callback(USER, "jonan", "c:99")
    resource = await get_active_resource_for_user(h["conn"], USER)
    assert resource.state == "AWAITING_PLACEMENT"  # unchanged
    assert result.replies

    result = await flow.handle_callback(USER, "jonan", "c:notanint")
    assert result.replies


async def test_other_folders_pages(h: dict) -> None:
    flow = await _to_placement(h)
    result = await flow.handle_callback(USER, "jonan", "o")
    assert isinstance(result.keyboard, FoldersKB) and result.keyboard.page == 0
    result = await flow.handle_callback(USER, "jonan", "p:1")
    assert isinstance(result.keyboard, FoldersKB) and result.keyboard.page == 1
    result = await flow.handle_callback(USER, "jonan", f"f:{FOLDERS.index(FOLDERS[2])}")
    resource = await get_active_resource_for_user(h["conn"], USER)
    assert resource.folder == FOLDERS[2]


# ---------------------------------------------------------------- interview


async def _to_interview(h: dict) -> ResourceFlow:
    """Mid-interview 'other' resource with NO pre-fills (exercises derivation)."""
    conn = h["conn"]
    await upsert_user(conn, USER, "jonan")
    await _capture_token(h)  # keep confirm path realistic; not asserted here
    rid = await create_resource(conn, USER, "https://cool-labs.io/tool", "other")
    await set_resource_state(
        conn, rid, "AWAITING_ENTRY_INFO", folder=CHOSEN, context="A summary exists", entry_line="{}"
    )
    return ResourceFlow(h["deps"])  # fresh instance == resume


async def test_interview_step_derivation_and_bracket_rejection(h: dict) -> None:
    flow = await _to_interview(h)

    # First empty field is name: a bracketed name must be refused, storing nothing.
    result = await flow.handle_text(USER, "jonan", "Bad]Name")
    assert "[" in result.replies[0] or "]" in result.replies[0] or "bracket" in result.replies[0].lower()
    resource = await get_resource(h["conn"], await _active_id(h))
    assert json.loads(resource.entry_line) == {}  # rejected input stored nothing
    assert await _audit(h, "entry_rejected")

    result = await flow.handle_text(USER, "jonan", "SQLMap")
    assert "description" in "\n".join(result.replies).lower()

    result = await flow.handle_text(USER, "jonan", "evil `backtick` thing")
    assert "backtick" in "\n".join(result.replies).lower() or "`" in result.replies[0]

    await flow.handle_text(USER, "jonan", "Dumps database banners")
    result = await flow.handle_text(USER, "jonan", "banana")  # invalid type
    assert isinstance(result.keyboard, TypeKB)

    await flow.handle_callback(USER, "jonan", "tool")
    result = await flow.handle_callback(USER, "jonan", "freemium")
    assert isinstance(result.keyboard, CostKB) or "platform" in "\n".join(result.replies).lower()

    result = await flow.handle_text(USER, "jonan", "linux")
    assert isinstance(result.keyboard, ConfirmKB)
    resource = await get_resource(h["conn"], await _active_id(h))
    assert resource.state == "CONFIRMING"
    assert resource.entry_line == (
        "- [SQLMap](https://cool-labs.io/tool) \u2014 Dumps database banners. "
        "`type:tool` `freemium` `linux`"
    )


async def _active_id(h: dict) -> int:
    active = await get_active_resource_for_user(h["conn"], USER)
    assert active is not None
    return active.id


async def test_interview_control_chars_are_sanitized(h: dict) -> None:
    flow = await _to_interview(h)
    await flow.handle_text(USER, "jonan", "Nor\x00mal Name")
    resource = await get_resource(h["conn"], await _active_id(h))
    iv = json.loads(resource.entry_line)
    assert iv["name"] == "Normal Name"  # control chars dropped by sanitize_line


async def test_platforms_none_accepts_empty_optional(h: dict) -> None:
    flow = await _to_interview(h)
    await flow.handle_text(USER, "jonan", "Name")
    await flow.handle_text(USER, "jonan", "Description")
    await flow.handle_callback(USER, "jonan", "docs")
    await flow.handle_callback(USER, "jonan", "paid")
    result = await flow.handle_text(USER, "jonan", "none")
    resource = await get_resource(h["conn"], await _active_id(h))
    assert resource.state == "CONFIRMING"
    assert "none" not in resource.entry_line.split("`")


async def test_platforms_reject_backtick_tokens(h: dict) -> None:
    flow = await _to_interview(h)
    await flow.handle_text(USER, "jonan", "Name")
    await flow.handle_text(USER, "jonan", "Description")
    await flow.handle_callback(USER, "jonan", "lab")
    await flow.handle_callback(USER, "jonan", "free")
    result = await flow.handle_text(USER, "jonan", "linux `evil`")
    resource = await get_resource(h["conn"], await _active_id(h))
    assert resource.state == "AWAITING_ENTRY_INFO"  # refused, still asking platforms
    assert result.replies


async def test_resume_finds_mid_interview_resource(h: dict) -> None:
    flow1 = await _to_interview(h)
    await flow1.handle_text(USER, "jonan", "SQLMap")  # answers name step

    flow2 = ResourceFlow(h["deps"])  # brand-new instance, same db == restart
    result = await flow2.handle_text(USER, "jonan", "Dumps database banners")
    assert "type" in "\n".join(result.replies).lower() or isinstance(result.keyboard, TypeKB)


async def test_cancel_clears_active_resource(h: dict) -> None:
    flow = await _to_placement(h)
    result = await flow.handle_cancel(USER)
    assert await get_active_resource_for_user(h["conn"], USER) is None
    assert "cancel" in "\n".join(result.replies).lower()
    assert await _audit(h, "cancelled")


# ---------------------------------------------------------------- confirm


async def test_confirm_commits_with_sender_pat_and_stores_commit_url(h: dict) -> None:
    flow, preview = await _to_confirming(h)
    assert isinstance(preview.keyboard, ConfirmKB)
    assert preview.keyboard.folder == CHOSEN
    assert "linux" in "\n".join(preview.replies)  # preview shows the bullet
    rid = await _active_id(h)  # COMMITTED is a final state; remember the id

    result = await flow.handle_confirm(USER)
    commit_call = [c for c in h["gh"].calls if c[0] == "commit_entry"][-1]
    assert h["github_tokens"][-1] == VALID_PAT  # decrypted sender PAT used
    assert commit_call[1] == f"{CHOSEN}/README.md"  # settings.readme_path(folder)
    assert commit_call[3] == "main"  # settings.target_branch
    assert commit_call[4] == "Vulnerability Specific"  # leaf_title_from_path
    assert commit_call[5] == "A tool for things"  # first paragraph of context
    assert commit_call[2].startswith("- [awesome-tool](")

    resource = await get_resource(h["conn"], rid)
    assert resource.state == "COMMITTED"
    assert resource.commit_url == h["gh"].commit_result[0]
    assert h["gh"].commit_result[0] in "\n".join(result.replies)
    assert await _audit(h, "committed")
    assert await get_active_resource_for_user(h["conn"], USER) is None


async def test_duplicate_error_notifies_without_recommit(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    h["gh"].commit_error = DuplicateError(
        f"That link is already listed in {CHOSEN}/README.md — nothing was committed."
    )
    before = len([c for c in h["gh"].calls if c[0] == "commit_entry"])
    result = await flow.handle_confirm(USER)
    assert "already" in "\n".join(result.replies).lower()
    after = len([c for c in h["gh"].calls if c[0] == "commit_entry"])
    assert after == before + 1  # exactly one attempt; the flow never re-commits
    resource = await get_resource(h["conn"], await _active_id(h))
    assert resource.state == "CONFIRMING"
    assert await _audit(h, "commit_duplicate")


async def test_commit_fetch_error_surfaces_public_hint_and_keeps_confirming(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    h["gh"].commit_error = FetchError("GitHub is unreachable right now.", public_hint=True)
    result = await flow.handle_confirm(USER)
    assert "public" in "\n".join(result.replies).lower() or "unreachable" in "\n".join(result.replies).lower()
    resource = await get_resource(h["conn"], await _active_id(h))
    assert resource.state == "CONFIRMING"  # retryable
    assert await _audit(h, "commit_failed")


async def test_confirm_without_pat_asks_for_token(h: dict) -> None:
    flow, _ = await _to_confirming(h)
    from app.db.repository import delete_github_token

    await delete_github_token(h["conn"], USER)
    result = await flow.handle_confirm(USER)
    assert "token" in "\n".join(result.replies).lower()
    assert (await get_active_resource_for_user(h["conn"], USER)).state == "CONFIRMING"


# ---------------------------------------------------------------- factories


def test_github_factory_always_pins_settings_target_repo(tmp_path: Path) -> None:
    """L7-3: never rely on the GitHubClient module default."""
    settings = make_settings(TARGET_REPO="Some/OtherRepo")
    factory = make_github_factory(settings, httpx.AsyncClient())
    client = factory(None)
    assert client.target_repo == "Some/OtherRepo"


def test_github_factory_default_target_repo(h: dict) -> None:
    factory = make_github_factory(h["settings"], httpx.AsyncClient())
    assert factory("tok").target_repo == "J0nan/Hackpot"


# ------------------------------------------------- L11 hardening pins (T7)


ANALYZING_TEXT = "🤔 Analyzing… send /cancel anytime"


async def test_folder_index_must_be_strict_digits(h: dict) -> None:
    """L11-a: ``c: 1`` / ``c:+1`` / ``c:01`` are rejected exactly like ``c:abc``."""
    flow = await _to_placement(h)
    index = FOLDERS.index(CHOSEN)
    rejected = [
        f"c: {index}",
        "c:+1",
        "c:01",
        "c:1_0",
        "c:١",  # Arabic-Indic digit: int() accepts it, a folder index must not
        "f: 1",
        "f:+2",
        "f:00",
    ]
    for data in rejected:
        result = await flow.handle_callback(USER, "jonan", data)
        assert result.replies == (UNKNOWN_FOLDER,), data
        assert result.keyboard is None, data

    active = await get_active_resource_for_user(h["conn"], USER)
    assert active.state == "AWAITING_PLACEMENT"  # rejected input placed nothing
    assert active.folder == ""
    rows = await _audit(h, "placement_rejected")
    assert [row["detail"] for row in rows] == [f"data={data}" for data in rejected]

    # PRESERVE: the honest index still resolves after the hostile ones were refused.
    await flow.handle_callback(USER, "jonan", f"c:{index}")
    active = await get_active_resource_for_user(h["conn"], USER)
    assert active.state == "AWAITING_ENTRY_INFO"
    assert active.folder == CHOSEN


async def test_folder_page_index_must_be_strict_digits(h: dict) -> None:
    """L11-a: ``p:<i>`` navigation is strict too; a bad page falls back to page 0."""
    flow = await _to_placement(h)
    for data in ("p:01", "p:+1", "p: 1", "p:1_0"):
        result = await flow.handle_callback(USER, "jonan", data)
        assert isinstance(result.keyboard, FoldersKB), data
        assert result.keyboard.page == 0, data

    # PRESERVE: real payloads behave exactly as before.
    result = await flow.handle_callback(USER, "jonan", "p:1")
    assert isinstance(result.keyboard, FoldersKB) and result.keyboard.page == 1
    result = await flow.handle_callback(USER, "jonan", "o")
    assert isinstance(result.keyboard, FoldersKB) and result.keyboard.page == 0
    result = await flow.handle_callback(USER, "jonan", f"f:{FOLDERS.index(CHOSEN)}")
    assert (await get_active_resource_for_user(h["conn"], USER)).folder == CHOSEN


async def test_confirm_with_tampered_folder_rejects_safely(h: dict) -> None:
    """L11-b: a stored folder outside CATEGORIES_JSON must not raise nor commit."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    tampered = "01_Recon/../../etc\nsecret-marker"
    await set_resource_state(h["conn"], rid, "CONFIRMING", folder=tampered)

    commits_before = len([c for c in h["gh"].calls if c[0] == "commit_entry"])
    clients_before = len(h["github_tokens"])
    result = await flow.handle_confirm(USER)

    assert len([c for c in h["gh"].calls if c[0] == "commit_entry"]) == commits_before
    assert len(h["github_tokens"]) == clients_before  # no client, so no HTTP at all
    assert (await get_resource(h["conn"], rid)).state == "CONFIRMING"  # not lost, retryable
    text = "\n".join(result.replies)
    assert result.replies and "nothing was committed" in text.lower()
    assert "/cancel" in text  # actionable wording, no internals
    assert "secret-marker" not in text and "../../etc" not in text  # value never echoed
    assert result.keyboard is None

    rows = await _audit(h, "commit_rejected")
    assert len(rows) == 1
    assert rows[0]["resource_id"] == rid
    assert rows[0]["detail"] == sanitize_line(f"folder={tampered}")
    assert "\n" not in rows[0]["detail"]  # the smuggled newline is gone


async def test_analyzing_progress_reply_precedes_the_decision_call(h: dict) -> None:
    """L7-4/L11-c: the slow classify is announced before any retry budget is spent."""
    flow = h["flow"]
    await _capture_token(h)
    order: list[str] = []
    decision = h["decision"]
    inner = decision.classify

    async def timed_classify(*args: Any, **kwargs: Any) -> Any:
        order.append("classify")
        return await inner(*args, **kwargs)

    decision.classify = timed_classify

    async def sink(text: str) -> None:
        order.append(f"progress::{text}")

    result = await flow.handle_text(USER, "jonan", GITHUB_URL, progress=sink)

    assert order == [f"progress::{ANALYZING_TEXT}", "classify"]
    assert isinstance(result.keyboard, CandidatesKB)  # the real answer still arrives


async def test_analyzing_progress_is_sent_once_per_decision_call(h: dict) -> None:
    """One extra reply per classify (summary path included), never an edit pipeline."""
    flow = h["flow"]
    await _capture_token(h)
    sent: list[str] = []

    async def sink(text: str) -> None:
        sent.append(text)

    # PRESERVE: progress is optional — existing callers keep working untouched.
    await flow.handle_text(USER, "jonan", "https://cool-labs.io/tool")
    assert sent == []

    result = await flow.handle_text(USER, "jonan", "Fuzzing wordlist generator.", progress=sink)
    assert sent == [ANALYZING_TEXT]
    assert isinstance(result.keyboard, CandidatesKB)


async def test_failing_progress_sink_never_breaks_the_decision(h: dict) -> None:
    """Progress feedback is best-effort: a refused send must not abort the flow."""

    async def broken_sink(text: str) -> None:
        raise RuntimeError("telegram is down")

    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_text(USER, "jonan", GITHUB_URL, progress=broken_sink)
    assert isinstance(result.keyboard, CandidatesKB)
    assert (await get_active_resource_for_user(h["conn"], USER)).state == "AWAITING_PLACEMENT"


class FakeUser:
    def __init__(self, user_id: int, username: str) -> None:
        self.id = user_id
        self.username = username


class FakeMessage:
    """Duck-typed aiogram Message: records the replies the handler sends."""

    def __init__(self, user_id: int, username: str, text: str) -> None:
        self.from_user = FakeUser(user_id, username)
        self.text = text
        self.answers: list[str] = []

    async def answer(self, text: str, reply_markup: Any = None) -> None:
        self.answers.append(text)

    async def delete(self) -> None:
        pass


async def test_handler_sends_the_analyzing_reply_first(h: dict) -> None:
    """The rendering side actually wires the progress sink (L7-4)."""
    await _capture_token(h)
    message = FakeMessage(USER, "jonan", GITHUB_URL)
    await handlers.on_text(message, h["deps"], h["flow"])
    assert message.answers[0] == ANALYZING_TEXT
    assert any("folder" in text.lower() for text in message.answers[1:])
