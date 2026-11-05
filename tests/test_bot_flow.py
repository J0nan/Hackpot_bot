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

from app.bot import handlers, manual_placement, pending_edits, rearm
from app.bot.flow import (
    ASK_PLATFORMS,
    ASK_SUMMARY,
    AppDeps,
    CANCELLED_MSG,
    CONFIRMING_HINT,
    CandidatesKB,
    ConfirmKB,
    FLOW_INTERRUPTED,
    FlowResult,
    FoldersKB,
    GREETING_READY,
    NOTHING_PENDING,
    PREVIEW,
    ResourceFlow,
    ResumeKB,
    SLOW_DOWN,
    STATS_EMPTY,
    STATS_NO_COMMITS,
    STATS_TAGS_EMPTY,
    TypeKB,
    UNKNOWN_CALLBACK,
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
from app.services.github import DuplicateError, FetchError, build_entry_line

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
        self.commit_result = ("https://github.com/HackPot-HQ/Hackpot/commit/deadbeef", "inserted")

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


@pytest.fixture(autouse=True)
def _no_stale_edit_markers() -> AsyncIterator[None]:
    """Markers are process-global and tmp DBs reuse resource ids across tests."""
    pending_edits.clear_all()
    rearm.clear_all()
    manual_placement.clear_all()
    yield
    pending_edits.clear_all()
    rearm.clear_all()
    manual_placement.clear_all()


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


async def _answer(flow: ResourceFlow, text: str, **kw: Any) -> Any:
    """S4 (revised): text at a text-driven step is its answer — no Continue needed."""
    return await flow.handle_text(USER, "jonan", text, **kw)


async def _to_placement(h: dict) -> ResourceFlow:
    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_text(USER, "jonan", GITHUB_URL)
    assert result.keyboard is not None
    return flow


async def _to_confirming(h: dict) -> tuple[ResourceFlow, Any]:
    flow = await _to_placement(h)
    await flow.handle_folder_choice(USER, CHOSEN)
    # github kind pre-fills name/description from repo meta (no cost step: S2)
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
    assert "public" in text.lower()  # S15: the public-links reminder is pinned, not replaced

    await _capture_token(h)
    result = await flow.handle_start(USER, "jonan")
    assert "link" in "\n".join(result.replies).lower()
    assert "github personal access" not in "\n".join(result.replies).lower()
    assert "public" in "\n".join(result.replies).lower()  # S15 pinned in the returning-admin greeting too


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

    result = await _answer(flow, "I do not have one yet")  # NEED_TOKEN is a text step
    assert "token" in "\n".join(result.replies).lower()
    active = await get_active_resource_for_user(h["conn"], USER)
    assert active.state == "NEED_TOKEN"

    # the step still wants text, so the PAT lands with no Continue press (S4).
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
    # Keycap'd caption (Option B) carries the readable names and percents.
    assert result.parse_mode == "HTML"
    caption = result.replies[-1]
    assert "1\uFE0F\u20E3 Vulnerability Specific" in caption
    assert "02 · Web Application" in caption and "75%" in caption
    assert "2\uFE0F\u20E3 OSINT" in caption and "20%" in caption
    assert "Other folder" in caption

    async with h["conn"].execute("SELECT * FROM decisions WHERE resource_id = ?", (resource.id,)) as cur:
        row = dict(await cur.fetchone())
    assert json.loads(row["probabilities_json"]) == {CHOSEN: 0.75, FOLDERS[0]: 0.2}
    assert row["needs_admin"] == 0.75
    assert row["cost_choice"] == ""  # S3: cost is never written to new decisions
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

    await _answer(flow, "An offline wordlist generator for fuzzing.")  # direct (S4)
    call = h["decision"].calls[-1]
    assert "https://cool-labs.io/tool" in call["content"]
    assert "wordlist generator" in call["content"]
    resource = await get_active_resource_for_user(h["conn"], USER)
    assert resource.kind == "other"
    assert resource.state == "AWAITING_PLACEMENT"


async def test_decision_hard_failure_offers_folders_and_context_retry(h: dict) -> None:
    h["decision"].error = DecisionError(
        "decision API rejected the request after 3 attempt(s) with HTTP 503: backend busy"
    )
    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_text(USER, "jonan", GITHUB_URL)
    text = "\n".join(result.replies)
    assert "503" not in text and "HTTP" not in text  # no internal detail to user
    assert "reliable" in text.lower()  # the model's failure is stated plainly
    assert isinstance(result.keyboard, FoldersKB)  # every folder shown right away

    resource = await get_active_resource_for_user(h["conn"], USER)
    assert resource is not None and resource.state == "AWAITING_PLACEMENT"  # flow survives
    assert "503" in resource.error  # the detail stays in the DB row
    rows = await _audit(h, "decision_failed")
    assert "503" in rows[-1]["detail"]
    async with h["conn"].execute(
        "SELECT folder_choice, raw_json FROM decisions WHERE resource_id = ?", (resource.id,)
    ) as cur:
        row = dict(await cur.fetchone())
    assert row["folder_choice"] == ""  # the empty row drives the retry gating
    assert "503" in row["raw_json"]

    # sending context re-runs the classification; a healthy answer resumes the card
    h["decision"].error = None
    result = await flow.handle_text(USER, "jonan", "A tool that dumps Windows credentials")
    assert isinstance(result.keyboard, CandidatesKB)
    content = h["decision"].calls[-1]["content"]
    assert "A tool that dumps Windows credentials" in content
    assert "Readme magic body" in content  # original context kept


# ------------------------------------------------- unreliable decision retry


def _empty_decision() -> ClassificationResult:
    """Model answered, but no folder cleared the confidence bar."""
    return ClassificationResult(
        candidates=[], needs_admin=None, request_id="req-empty", raw={"answers": {}}
    )


async def test_decision_without_value_shows_all_folders_and_asks_context(h: dict) -> None:
    h["decision"].result = _empty_decision()
    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_text(USER, "jonan", GITHUB_URL)

    resource = await get_active_resource_for_user(h["conn"], USER)
    assert resource.state == "AWAITING_PLACEMENT"
    assert isinstance(result.keyboard, FoldersKB)  # every folder, not "go press Other folder…"
    assert result.parse_mode == "HTML"
    lowered = "\n".join(result.replies).lower()
    assert "reliable" in lowered  # the model told them so plainly
    assert "context" in lowered  # and the text-retry invite is visible
    caption = result.replies[-1]
    assert "Choose destination folder" in caption
    for folder in FOLDERS:  # all configured leaves are on the card
        assert folder.partition("/")[2].replace("_", " ") in caption

    async with h["conn"].execute(
        "SELECT folder_choice, confidence FROM decisions WHERE resource_id = ?", (resource.id,)
    ) as cur:
        row = dict(await cur.fetchone())
    assert row["folder_choice"] == "" and row["confidence"] == 0.0  # audit keeps the empty answer


async def test_added_context_text_reclassifies_and_resumes_candidates(h: dict) -> None:
    h["decision"].result = _empty_decision()
    flow = h["flow"]
    await _capture_token(h)
    await flow.handle_text(USER, "jonan", GITHUB_URL)

    # The ask is armed: the next text is extra context — no keep press needed.
    h["decision"].result = FakeDecision().result
    result = await flow.handle_text(USER, "jonan", "It fuzzes GraphQL APIs for auth bypass")
    assert isinstance(result.keyboard, CandidatesKB)  # back to the normal decision card

    content = h["decision"].calls[-1]["content"]
    assert content.startswith(GITHUB_URL)
    assert "Readme magic body" in content  # the original context is kept
    assert "It fuzzes GraphQL APIs for auth bypass" in content  # the added text is used
    resource = await get_active_resource_for_user(h["conn"], USER)
    assert resource.state == "AWAITING_PLACEMENT"
    assert "It fuzzes GraphQL" in resource.context  # and persisted for later steps
    rows = await _audit(h, "context_retry")
    assert rows and rows[-1]["resource_id"] == resource.id


async def test_context_retry_still_unreliable_re_offers_folders_armed(h: dict) -> None:
    h["decision"].result = _empty_decision()
    flow = h["flow"]
    await _capture_token(h)
    await flow.handle_text(USER, "jonan", GITHUB_URL)

    result = await flow.handle_text(USER, "jonan", "first extra note")
    assert isinstance(result.keyboard, FoldersKB)  # still nothing reliable: folders again
    result = await flow.handle_text(USER, "jonan", "   ")  # empty context re-asks, no call spent
    assert isinstance(result.keyboard, FoldersKB)
    assert len(h["decision"].calls) == 2  # whitespace did not hit the model again

    result = await flow.handle_text(USER, "jonan", "second extra note")
    assert isinstance(result.keyboard, FoldersKB)
    content = h["decision"].calls[-1]["content"]
    assert "first extra note" in content and "second extra note" in content
    assert len(h["decision"].calls) == 3


async def test_continue_re_offers_unreliable_step_and_arms_retry(h: dict) -> None:
    h["decision"].result = _empty_decision()
    flow = h["flow"]
    await _capture_token(h)
    await flow.handle_text(USER, "jonan", GITHUB_URL)
    await flow.handle_callback(USER, "jonan", "o")  # browsing the picker drops the arm

    result = await flow.handle_text(USER, "jonan", "context after guard")
    assert result.replies == (FLOW_INTERRUPTED,)
    assert isinstance(result.keyboard, ResumeKB)

    resumed = await flow.handle_callback(USER, "jonan", "keep")
    assert isinstance(resumed.keyboard, FoldersKB)
    assert "reliable" in "\n".join(resumed.replies).lower()  # the step as first shown, invite and all

    await flow.handle_text(USER, "jonan", "context after guard")  # now consumed as retry
    assert "context after guard" in h["decision"].calls[-1]["content"]


async def test_manual_classify_ends_the_context_invite(h: dict) -> None:
    h["decision"].result = _empty_decision()
    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_text(USER, "jonan", GITHUB_URL)
    assert result.keyboard.manual is True  # the ask offers the manual route and cancel

    result = await flow.handle_callback(USER, "jonan", "m")
    assert isinstance(result.keyboard, FoldersKB)
    assert result.keyboard.manual is False  # plain picker from here on
    assert "manual" in "\n".join(result.replies).lower()

    calls = len(h["decision"].calls)
    result = await flow.handle_text(USER, "jonan", "a few words")  # NOT context any more
    assert result.replies == (FLOW_INTERRUPTED,)
    assert isinstance(result.keyboard, ResumeKB)
    assert len(h["decision"].calls) == calls  # the model was not consulted

    resumed = await flow.handle_callback(USER, "jonan", "keep")  # step stays button-driven
    assert isinstance(resumed.keyboard, FoldersKB)
    assert not resumed.keyboard.manual
    again = await flow.handle_text(USER, "jonan", "still not context")
    assert again.replies == (FLOW_INTERRUPTED,)

    placed = await flow.handle_callback(USER, "jonan", f"f:{FOLDERS.index(CHOSEN)}")
    assert placed.replies  # normal placement continues into the interview
    resource = await get_active_resource_for_user(h["conn"], USER)
    assert resource.state == "AWAITING_ENTRY_INFO" and resource.folder == CHOSEN
    assert await _audit(h, "manual_placement")


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
    def KC(n: int) -> str:
        return f"{n}\uFE0F\u20E3"

    flow = await _to_placement(h)
    result = await flow.handle_callback(USER, "jonan", "o")
    assert isinstance(result.keyboard, FoldersKB) and result.keyboard.page == 0
    # Option B: the full paths ride in an HTML caption, keycap'd numbers that
    # match the caption lines one-to-one on the keyboard.
    assert result.parse_mode == "HTML"
    text = result.replies[0]
    assert "Page 1 of 1" in text
    for number, folder in zip([KC(1), KC(2), KC(3)], FOLDERS):
        assert number in text
        assert folder.split("/")[1].replace("_", " ") in text
    result = await flow.handle_callback(USER, "jonan", "p:1")
    assert isinstance(result.keyboard, FoldersKB) and result.keyboard.page == 1
    assert "Page 1 of 1" in result.replies[0]  # 3 folders fit one page: clamped
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
    result = await _answer(flow, "Bad]Name")  # name is a text step (S4)
    assert "[" in result.replies[0] or "]" in result.replies[0] or "bracket" in result.replies[0].lower()
    resource = await get_resource(h["conn"], await _active_id(h))
    assert json.loads(resource.entry_line) == {}  # rejected input stored nothing
    assert await _audit(h, "entry_rejected")

    result = await flow.handle_text(USER, "jonan", "SQLMap")  # the step keeps taking text
    assert "description" in "\n".join(result.replies).lower()

    result = await _answer(flow, "evil `backtick` thing")  # description step, direct
    assert "backtick" in "\n".join(result.replies).lower() or "`" in result.replies[0]

    await flow.handle_text(USER, "jonan", "Dumps database banners")  # still a text step
    result = await _answer(flow, "banana")  # invalid type at the type step
    assert isinstance(result.keyboard, TypeKB)

    await flow.handle_callback(USER, "jonan", "tool")
    result = await flow.handle_callback(USER, "jonan", "freemium")  # cost button gone (S2)
    assert result.replies == (UNKNOWN_CALLBACK,)  # ignored, audited, not an error state
    assert await _audit(h, "callback_ignored")

    result = await _answer(flow, "linux")  # platforms is a text step too (S4)
    assert isinstance(result.keyboard, ConfirmKB)
    resource = await get_resource(h["conn"], await _active_id(h))
    assert resource.state == "CONFIRMING"
    assert resource.entry_line == (
        "- [SQLMap](https://cool-labs.io/tool) — Dumps database banners. "
        "`type:tool` `linux`"
    )


async def _active_id(h: dict) -> int:
    active = await get_active_resource_for_user(h["conn"], USER)
    assert active is not None
    return active.id


async def test_interview_control_chars_are_sanitized(h: dict) -> None:
    flow = await _to_interview(h)
    await _answer(flow, "Nor\x00mal Name")
    resource = await get_resource(h["conn"], await _active_id(h))
    iv = json.loads(resource.entry_line)
    assert iv["name"] == "Normal Name"  # control chars dropped by sanitize_line


async def test_platforms_none_accepts_empty_optional(h: dict) -> None:
    flow = await _to_interview(h)
    await _answer(flow, "Name")
    await _answer(flow, "Description")
    await flow.handle_callback(USER, "jonan", "docs")
    await flow.handle_callback(USER, "jonan", "paid")
    result = await _answer(flow, "none")
    resource = await get_resource(h["conn"], await _active_id(h))
    assert resource.state == "CONFIRMING"
    assert "none" not in resource.entry_line.split("`")


async def test_platforms_reject_backtick_tokens(h: dict) -> None:
    flow = await _to_interview(h)
    await _answer(flow, "Name")
    await _answer(flow, "Description")
    await flow.handle_callback(USER, "jonan", "lab")
    await flow.handle_callback(USER, "jonan", "free")
    result = await _answer(flow, "linux `evil`")
    resource = await get_resource(h["conn"], await _active_id(h))
    assert resource.state == "AWAITING_ENTRY_INFO"  # refused, still asking platforms
    assert result.replies == (ASK_PLATFORMS,)  # rejection just re-asks the step (S4)


async def test_resume_finds_mid_interview_resource(h: dict) -> None:
    flow1 = await _to_interview(h)
    await _answer(flow1, "SQLMap")  # answers name step

    flow2 = ResourceFlow(h["deps"])  # brand-new instance, same db == restart
    result = await _answer(flow2, "Dumps database banners")
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


# ------------------------------------------------------- field edits (T4)

CHAT_ID = 77001
CARD_MSG_ID = 90042


def _current_bullet(
    desc: str = "A tool for things", tags: str = "`type:tool` `linux`"
) -> str:
    return f"- [awesome-tool]({GITHUB_URL}) — {desc}. {tags}"


async def test_description_press_replies_current_description_in_code_block(h: dict) -> None:
    """S6.2/S6.3: "d" answers with the CURRENT description as a copyable block."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)

    result = await flow.handle_callback(
        USER, "jonan", "d", chat_id=CHAT_ID, message_id=CARD_MSG_ID
    )

    assert len(result.replies) == 2
    assert "copy" in result.replies[0].lower() and "description" in result.replies[0].lower()
    assert result.replies[1] == "<pre>A tool for things</pre>"
    assert result.new_message is True and result.parse_mode == "HTML"
    assert result.keyboard is None
    assert result.delete_outgoing == ()
    resource = await get_resource(h["conn"], rid)
    assert resource.state == "CONFIRMING" and resource.entry_line == _current_bullet()
    assert await _audit(h, "entry_edit_requested")
    marker = pending_edits.get_marker(rid)
    assert marker is not None and marker.mode == "description"
    assert (marker.chat_id, marker.message_id) == (CHAT_ID, CARD_MSG_ID)


async def test_tags_press_replies_current_tags_and_replaces_the_marker(h: dict) -> None:
    """S6.2: "t" shows the current tag line; another field press replaces it."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_callback(USER, "jonan", "d", chat_id=CHAT_ID, message_id=CARD_MSG_ID)

    result = await flow.handle_callback(
        USER, "jonan", "t", chat_id=CHAT_ID, message_id=CARD_MSG_ID + 7
    )

    assert result.replies[1] == "<pre>`type:tool` `linux`</pre>"
    assert "tags" in result.replies[0].lower()
    marker = pending_edits.get_marker(rid)
    assert marker is not None and marker.mode == "tags"
    assert (marker.chat_id, marker.message_id) == (CHAT_ID, CARD_MSG_ID + 7)


async def test_field_presses_outside_confirming_are_unknown_callbacks(h: dict) -> None:
    """S6.2: "d"/"t" are only CONFIRMING actions; elsewhere the audited unknown tail."""
    flow = await _to_placement(h)
    for data in ("d", "t"):
        result = await flow.handle_callback(USER, "jonan", data)
        assert result.replies == (UNKNOWN_CALLBACK,), data
        assert result.keyboard is None, data
    rows = await _audit(h, "callback_ignored")
    assert rows[-1]["detail"] == "data=t"


async def test_removed_bullet_edit_payload_is_unknown_in_confirming(h: dict) -> None:
    """S6.1/S6.7: the whole-bullet "e" payload is gone → audit + UNKNOWN_CALLBACK."""
    flow, _ = await _to_confirming(h)
    result = await flow.handle_callback(
        USER, "jonan", "e", chat_id=CHAT_ID, message_id=CARD_MSG_ID
    )
    assert result.replies == (UNKNOWN_CALLBACK,)
    assert pending_edits.get_marker(await _active_id(h)) is None


async def test_confirming_text_without_marker_gets_the_interrupt_prompt(h: dict) -> None:
    """S6.5 + flow-interrupt-rearm S1: plain CONFIRMING text asks Continue/Cancel."""
    flow, _ = await _to_confirming(h)
    result = await flow.handle_text(USER, "jonan", _current_bullet("Rewritten by hand"))
    assert result.replies == (FLOW_INTERRUPTED,)
    assert isinstance(result.keyboard, ResumeKB)
    resource = await get_resource(h["conn"], await _active_id(h))
    assert resource.entry_line == _current_bullet()  # never applied


async def test_description_paste_rebuilds_bullet_keeping_name_url_tags(h: dict) -> None:
    """S6.3: same name, reviewed url, same tags — only the description changes."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_callback(USER, "jonan", "d", chat_id=CHAT_ID, message_id=CARD_MSG_ID)

    result = await flow.handle_text(USER, "jonan", "A superb recon tool")

    expected = _current_bullet("A superb recon tool")
    resource = await get_resource(h["conn"], rid)
    assert resource.state == "CONFIRMING" and resource.entry_line == expected
    assert result.replies == (f"{PREVIEW}\n{expected}",)
    assert isinstance(result.keyboard, ConfirmKB) and result.keyboard.folder == CHOSEN
    assert result.parse_mode is None and result.new_message is False
    assert result.delete_outgoing == ((CHAT_ID, CARD_MSG_ID),)  # S6.3 previous card
    assert pending_edits.get_marker(rid) is None
    assert await _audit(h, "entry_edited")


async def test_tags_paste_rebuilds_keeping_name_url_description(h: dict) -> None:
    """S6.4: same name, url and description — only the tags change."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_callback(USER, "jonan", "t", chat_id=CHAT_ID, message_id=CARD_MSG_ID)

    result = await flow.handle_text(USER, "jonan", "`type:docs` `paid` `windows` `macos`")

    # S4: the pasted legacy `paid` word is dropped; the rebuild is cost-free.
    expected = _current_bullet(tags="`type:docs` `windows` `macos`")
    assert (await get_resource(h["conn"], rid)).entry_line == expected
    assert result.replies == (f"{PREVIEW}\n{expected}",)
    assert result.delete_outgoing == ((CHAT_ID, CARD_MSG_ID),)
    assert await _audit(h, "entry_edited")


DESCRIPTION_REJECTIONS: list[tuple[str, str]] = [
    ("bad [bracket] name", "can't contain"),
    ("evil `ticks` here", "backticks"),
    ("first line\nsecond line", "one line"),
    ("d" * 501, "500"),
    ("   ", "empty"),
]

TAGS_REJECTIONS: list[tuple[str, str]] = [
    ("free linux", "Missing type tag"),
    ("type:banana free", "type tag must be one of"),
    ("type:tool cost:premium linux", "plain words"),
    ("type:tool `ba|d`", "invalid platform tag"),
    ("type:tool " + "t" * 41, "40 character limit"),
]


@pytest.mark.parametrize("paste,needle", DESCRIPTION_REJECTIONS)
async def test_description_rejections_answer_one_error_and_persist_nothing(
    h: dict, paste: str, needle: str
) -> None:
    """S6.3/S6.6: one specific error, prompt re-offered, row unchanged, marker kept."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_callback(USER, "jonan", "d", chat_id=CHAT_ID, message_id=CARD_MSG_ID)

    result = await flow.handle_text(USER, "jonan", paste)

    assert len(result.replies) == 3  # error, instruction, copyable current value
    assert needle in result.replies[0], result.replies[0]
    assert result.replies[-1] == "<pre>A tool for things</pre>"
    assert result.keyboard is None and result.delete_outgoing == ()
    resource = await get_resource(h["conn"], rid)
    assert resource.state == "CONFIRMING" and resource.entry_line == _current_bullet()
    assert pending_edits.get_marker(rid) is not None  # retry stays open
    assert await _audit(h, "entry_edit_rejected")


@pytest.mark.parametrize("paste,needle", TAGS_REJECTIONS)
async def test_tags_rejections_answer_one_error_and_persist_nothing(
    h: dict, paste: str, needle: str
) -> None:
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_callback(USER, "jonan", "t", chat_id=CHAT_ID, message_id=CARD_MSG_ID)

    result = await flow.handle_text(USER, "jonan", paste)

    assert len(result.replies) == 3
    assert needle in result.replies[0], result.replies[0]
    assert result.replies[-1] == "<pre>`type:tool` `linux`</pre>"
    assert result.delete_outgoing == ()
    resource = await get_resource(h["conn"], rid)
    assert resource.state == "CONFIRMING" and resource.entry_line == _current_bullet()
    assert pending_edits.get_marker(rid) is not None
    assert await _audit(h, "entry_edit_rejected")


async def test_tags_paste_duplicate_tags_are_deduped_by_the_existing_rule(h: dict) -> None:
    """S6.4: duplicates stay a dedupe (existing tag rules), never a crash."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_callback(USER, "jonan", "t", chat_id=CHAT_ID, message_id=CARD_MSG_ID)

    result = await flow.handle_text(USER, "jonan", "type:tool free linux linux")

    # S4: the legacy `free` word is dropped, linux dedupes, no error.
    assert (await get_resource(h["conn"], rid)).entry_line == _current_bullet()
    assert result.replies == (f"{PREVIEW}\n{_current_bullet()}",)
    assert result.delete_outgoing == ((CHAT_ID, CARD_MSG_ID),)
    assert pending_edits.get_marker(rid) is None


async def test_paste_routes_per_marker_not_per_content(h: dict) -> None:
    """The marker decides the field: a tag-shaped line edits the DESCRIPTION."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_callback(USER, "jonan", "d", chat_id=CHAT_ID, message_id=CARD_MSG_ID)

    result = await flow.handle_text(USER, "jonan", "type:docs paid windows")

    assert (await get_resource(h["conn"], rid)).entry_line == _current_bullet(
        desc="type:docs paid windows"
    )
    assert isinstance(result.keyboard, ConfirmKB)


async def test_description_then_tags_then_confirm_commits_edited_bullet(h: dict) -> None:
    """S4.5/S6.6: edits loop freely; ✅ commits the last entry_line verbatim."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_callback(USER, "jonan", "d", chat_id=CHAT_ID, message_id=CARD_MSG_ID)
    await flow.handle_text(USER, "jonan", "Edited description")
    await flow.handle_callback(USER, "jonan", "t", chat_id=CHAT_ID, message_id=CARD_MSG_ID + 1)
    await flow.handle_text(USER, "jonan", "type:lab paid docker")

    # S4: `paid` is a legacy word and never survives into the rebuilt bullet.
    expected = _current_bullet("Edited description", tags="`type:lab` `docker`")
    assert (await get_resource(h["conn"], rid)).entry_line == expected

    await flow.handle_confirm(USER)
    commit_call = [c for c in h["gh"].calls if c[0] == "commit_entry"][-1]
    assert commit_call[1] == f"{CHOSEN}/README.md"
    assert commit_call[2] == expected  # verbatim (S4.5)
    assert pending_edits.get_marker(rid) is None  # ✅ ends the edit loop (S6.2)


async def test_marker_cleared_after_cancel(h: dict) -> None:
    """S6.2: ❌ / /cancel clear the pending-edit marker."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    await flow.handle_callback(USER, "jonan", "d", chat_id=CHAT_ID, message_id=CARD_MSG_ID)
    await flow.handle_cancel(USER)
    assert pending_edits.get_marker(rid) is None


async def test_description_edit_preserves_unicode_and_em_dash_name(h: dict) -> None:
    """Name/description round-trip is byte-faithful across unicode and '—' in the name."""
    flow, _ = await _to_confirming(h)
    rid = await _active_id(h)
    bullet = (
        "- [Ñom — Special](https://github.com/OtherOrg/awesome-tool) — "
        "Descripción con ñ. `type:tool` `free`"
    )
    await set_resource_state(h["conn"], rid, "CONFIRMING", entry_line=bullet)

    result = await flow.handle_callback(USER, "jonan", "d", chat_id=CHAT_ID, message_id=CARD_MSG_ID)
    assert result.replies[1] == "<pre>Descripción con ñ</pre>"

    await flow.handle_text(USER, "jonan", "Nueva descripción")
    # S4: the LEGACY `free` word stored in the old bullet is dropped on rebuild.
    assert (await get_resource(h["conn"], rid)).entry_line == (
        "- [Ñom — Special](https://github.com/OtherOrg/awesome-tool) — "
        "Nueva descripción. `type:tool`"
    )


# ---------------------------------------------------------------- factories


def test_github_factory_always_pins_settings_target_repo(tmp_path: Path) -> None:
    """L7-3: never rely on the GitHubClient module default."""
    settings = make_settings(TARGET_REPO="Some/OtherRepo")
    factory = make_github_factory(settings, httpx.AsyncClient())
    client = factory(None)
    assert client.target_repo == "Some/OtherRepo"


def test_github_factory_default_target_repo(h: dict) -> None:
    factory = make_github_factory(h["settings"], httpx.AsyncClient())
    assert factory("tok").target_repo == "HackPot-HQ/Hackpot"


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
    await flow.handle_text(USER, "jonan", "https://cool-labs.io/tool")  # intake -> ASK_SUMMARY
    assert sent == []

    # the summary is a NEED_SUMMARY step answer: it lands directly (S4)
    result = await _answer(flow, "Fuzzing wordlist generator.", progress=sink)
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


class FakeChat:
    def __init__(self, chat_id: int) -> None:
        self.id = chat_id


class FakeBot:
    """Records delete_message calls (the S6.3 previous-card deletion pin)."""

    def __init__(self) -> None:
        self.deleted: list[tuple[int, int]] = []

    async def delete_message(self, chat_id: int = None, message_id: int = None) -> None:
        self.deleted.append((chat_id, message_id))


class FakeMessage:
    """Duck-typed aiogram Message: records the replies the handler sends."""

    def __init__(
        self,
        user_id: int,
        username: str,
        text: str,
        chat_id: int | None = None,
        message_id: int | None = None,
    ) -> None:
        self.from_user = FakeUser(user_id, username)
        self.text = text
        self.answers: list[str] = []
        self.parse_modes: list[object] = []
        self.chat = FakeChat(chat_id) if chat_id is not None else None
        self.message_id = message_id
        self.bot = FakeBot()

    async def answer(self, text: str, reply_markup: Any = None, parse_mode: Any = None) -> None:
        self.answers.append(text)
        self.parse_modes.append(parse_mode)

    async def delete(self) -> None:
        pass


class FakeCallback:
    """Duck-typed CallbackQuery riding on the confirmation card message."""

    def __init__(
        self,
        user_id: int,
        username: str,
        data: str,
        chat_id: int = CHAT_ID,
        message_id: int = CARD_MSG_ID,
    ) -> None:
        self.from_user = FakeUser(user_id, username)
        self.data = data
        self.acks: list[tuple] = []
        self.message = FakeMessage(
            user_id, username, "card", chat_id=chat_id, message_id=message_id
        )

    async def answer(self, *args: Any, **kwargs: Any) -> None:
        self.acks.append((args, kwargs))


async def test_handler_sends_the_analyzing_reply_first(h: dict) -> None:
    """The rendering side actually wires the progress sink (L7-4)."""
    await _capture_token(h)
    message = FakeMessage(USER, "jonan", GITHUB_URL)
    await handlers.on_text(message, h["deps"], h["flow"])
    assert message.answers[0] == ANALYZING_TEXT
    assert any("folder" in text.lower() for text in message.answers[1:])
    # PRESERVE: the early progress sink keeps the bot default (no parse mode).
    assert message.parse_modes[0] is None
    # The decision card now opts into HTML per-result (Option B numbered caption).
    assert all(mode == "HTML" for mode in message.parse_modes[1:])


async def test_handler_text_without_marker_asks_continue_or_cancel(h: dict) -> None:
    """S6.5 + flow-interrupt-rearm through the renderer: CONFIRMING text = prompt."""
    flow, _ = await _to_confirming(h)
    message = FakeMessage(USER, "jonan", "A tool for things")
    await handlers.on_text(message, h["deps"], flow)
    assert message.answers == [FLOW_INTERRUPTED]
    assert message.parse_modes == [None]


async def test_handler_deletes_previous_card_once_after_successful_edit(h: dict) -> None:
    """S6.3: the new delete_outgoing mechanism deletes ONLY the tracked card, once."""
    flow, _ = await _to_confirming(h)
    cb = FakeCallback(USER, "jonan", "d")
    await handlers.on_callback(cb, h["deps"], flow)
    assert len(cb.message.answers) == 2  # prompt as new messages, ✅/❌ bubble intact
    assert cb.message.bot.deleted == []  # pressing a button never deletes

    paste = FakeMessage(USER, "jonan", "A superb recon tool")
    await handlers.on_text(paste, h["deps"], flow)
    assert paste.bot.deleted == [(CHAT_ID, CARD_MSG_ID)]  # exactly once, captured ids
    assert paste.answers[-1].startswith(PREVIEW)  # the fresh confirmation card arrived


async def test_handler_deletes_nothing_on_rejected_edit(h: dict) -> None:
    """S6.6: a rejected paste re-offers the prompt (HTML) and deletes nothing."""
    flow, _ = await _to_confirming(h)
    cb = FakeCallback(USER, "jonan", "t")
    await handlers.on_callback(cb, h["deps"], flow)
    paste = FakeMessage(USER, "jonan", "free linux")
    await handlers.on_text(paste, h["deps"], flow)
    assert paste.bot.deleted == []
    assert paste.answers[-1] == "<pre>`type:tool` `linux`</pre>"
    assert paste.parse_modes[-1] == "HTML"  # renders as a copyable code block
    assert len(paste.answers) == 3  # exactly one error, then the re-offered prompt


# ------------------------------------------------- intake duplicate gate (L12)


SECOND_USER = 555  # someone else's submission: the check is global
COMMIT_URL = "https://github.com/HackPot-HQ/Hackpot/commit/deadbeef"
OTHER_URL = "https://cool-labs.io/tool"


async def _count_resources(h: dict) -> int:
    async with h["conn"].execute("SELECT COUNT(*) AS n FROM resources") as cursor:
        row = await cursor.fetchone()
    return int(row["n"])


async def _seed(h: dict, url: str, kind: str, state: str, folder: str = "") -> int:
    """Another user's resource in *state*; committed rows carry the commit link."""
    conn = h["conn"]
    await upsert_user(conn, SECOND_USER, "someone-else")
    rid = await create_resource(conn, SECOND_USER, url, kind)
    updates: dict[str, str] = {"folder": folder}
    if state == "COMMITTED":
        updates["commit_url"] = COMMIT_URL
    await set_resource_state(conn, rid, state, **updates)
    return rid


async def test_committed_duplicate_names_folder_and_skips_decision(h: dict) -> None:
    """The gate fires before create_resource and before the decision model."""
    flow = h["flow"]
    await _capture_token(h)
    await _seed(h, GITHUB_URL, "github", "COMMITTED", folder=CHOSEN)
    before = await _count_resources(h)

    result = await flow.handle_text(USER, "jonan", GITHUB_URL)

    assert any(CHOSEN in text for text in result.replies)
    assert any(COMMIT_URL in text for text in result.replies)
    assert h["decision"].calls == []
    assert await _count_resources(h) == before  # no new row
    rows = await _audit(h, "duplicate_link")
    assert len(rows) == 1


async def test_committed_duplicate_detected_across_github_url_variants(h: dict) -> None:
    """Case, trailing slash, .git, /tree/… and www all collapse to one repo."""
    flow = h["flow"]
    await _capture_token(h)
    await _seed(h, GITHUB_URL, "github", "COMMITTED", folder=CHOSEN)
    variants = [
        "https://github.com/OtherOrg/awesome-tool/",
        "https://github.com/otherorg/Awesome-Tool",
        "https://github.com/OtherOrg/awesome-tool.git",
        "https://github.com/OtherOrg/awesome-tool/tree/main",
        "https://www.github.com/otherorg/awesome-tool/issues/3",
    ]
    for variant in variants:
        result = await flow.handle_text(USER, "jonan", variant)
        assert any(CHOSEN in text for text in result.replies), variant
    assert h["decision"].calls == []


async def test_in_progress_duplicate_is_reported_as_pending(h: dict) -> None:
    """No PAT needed for the gate to fire, and pending rows are named honestly."""
    flow = h["flow"]
    rid = await _seed(h, GITHUB_URL, "github", "NEED_SUMMARY")
    placed = await _seed(h, OTHER_URL, "other", "AWAITING_ENTRY_INFO", folder=FOLDERS[0])
    before = await _count_resources(h)

    result = await flow.handle_text(USER, "jonan", GITHUB_URL)
    assert await _count_resources(h) == before
    assert h["decision"].calls == []
    assert "already being processed" in result.replies[0].lower()
    assert str(rid) in result.replies[0]

    result = await flow.handle_text(USER, "jonan", OTHER_URL)
    assert FOLDERS[0] in result.replies[0]  # folder shown when one was already chosen


@pytest.mark.parametrize("state", ["CANCELLED", "FAILED"])
async def test_dead_submissions_stay_resubmittable(h: dict, state: str) -> None:
    flow = h["flow"]
    await _capture_token(h)
    await _seed(h, GITHUB_URL, "github", state)
    before = await _count_resources(h)

    await flow.handle_text(USER, "jonan", GITHUB_URL)

    assert await _count_resources(h) == before + 1  # normal intake proceeded
    assert len(h["decision"].calls) == 1


async def test_non_github_duplicate_matches_canonical_form(h: dict) -> None:
    flow = h["flow"]
    await _seed(h, "https://example.com/tool", "other", "COMMITTED", folder=FOLDERS[0])
    before = await _count_resources(h)

    result = await flow.handle_text(USER, "jonan", "https://example.com/tool/")

    assert any(FOLDERS[0] in text for text in result.replies)
    assert h["decision"].calls == []
    assert await _count_resources(h) == before


async def test_distinct_link_is_not_a_duplicate(h: dict) -> None:
    """PRESERVE: everything that is not a repeat keeps the old intake behavior."""
    flow = h["flow"]
    await _capture_token(h)
    await _seed(h, GITHUB_URL, "github", "COMMITTED", folder=CHOSEN)

    result = await flow.handle_text(USER, "jonan", "https://github.com/OtherOrg/different-repo")

    assert isinstance(result.keyboard, CandidatesKB)
    assert len(h["decision"].calls) == 1


# ---------------------------------------------------------------- /stats


async def _seed_for(h: dict, user_id: int, username: str, url: str, state: str = "NEW", entry_line: str = "") -> int:
    """One link owned by *user_id* in *state* (leaderboard fixture)."""
    conn = h["conn"]
    await upsert_user(conn, user_id, username)
    rid = await create_resource(conn, user_id, url, "other")
    updates: dict[str, str] = {"entry_line": entry_line} if entry_line else {}
    await set_resource_state(conn, rid, state, **updates)
    return rid


async def test_stats_empty_boards_answer_two_messages(h: dict) -> None:
    result = await h["flow"].handle_stats(USER, "jonan")
    assert result.replies == (STATS_EMPTY, STATS_TAGS_EMPTY)
    assert result.keyboard is None
    assert len(await _audit(h, "stats")) == 1


async def test_stats_counts_only_committed_links(h: dict) -> None:
    await _seed_for(h, 200, "ana", "https://b.example/one", "COMMITTED")
    await _seed_for(h, 200, "ana", "https://b.example/two", "CANCELLED")  # not counted
    await _seed_for(h, USER, "jonan", GITHUB_URL, "NEW")  # in flight, not counted

    text = (await h["flow"].handle_stats(USER, "jonan")).replies[0]
    assert "🥇 @ana — 1 link" in text
    assert "@jonan" not in text  # caller only has an in-flight link
    assert text.endswith(STATS_NO_COMMITS)


async def test_stats_orders_users_by_committed_links(h: dict) -> None:
    await _seed_for(h, 200, "ana", "https://b.example/one", "COMMITTED")
    await _seed_for(h, 200, "ana", "https://b.example/two", "COMMITTED")
    await _seed_for(h, USER, "jonan", GITHUB_URL, "COMMITTED")

    text = (await h["flow"].handle_stats(USER, "jonan")).replies[0]
    assert "🏆" in text
    assert "🥇 @ana — 2 links" in text
    assert "🥈 @jonan — 1 link" in text
    assert text.index("@ana") < text.index("@jonan")


async def test_stats_notes_caller_without_commits(h: dict) -> None:
    await _seed_for(h, 200, "ana", "https://b.example/one", "COMMITTED")

    text = (await h["flow"].handle_stats(300, "ghost")).replies[0]
    assert "🥇 @ana — 1 link" in text
    assert text.endswith(STATS_NO_COMMITS)


async def test_stats_cuts_board_at_ten_and_shows_caller_rank(h: dict) -> None:
    for i in range(1, 11):
        await _seed_for(h, 200 + i, f"user{i}", f"https://b.example/{i}", "COMMITTED")
    await _seed_for(h, USER, "jonan", GITHUB_URL, "COMMITTED")  # 11th curator

    text = (await h["flow"].handle_stats(USER, "jonan")).replies[0]
    assert text.count("@user") == 10  # only the top ten rows are rendered
    assert "@jonan" not in text
    assert "You are #11 — 1 link" in text


async def test_stats_tag_board_counts_committed_tags(h: dict) -> None:
    line_a = build_entry_line("Tool A", "https://t.example/1", "does things", "tool", ["linux", "web"])
    line_b = build_entry_line("Tool B", "https://t.example/2", "does more", "tool", ["web"])
    # a LEGACY cost word pasted as a platform tag is dropped by the builder (S1)
    line_c = build_entry_line("Tool C", "https://t.example/3", "more still", "tool", ["free", "Linux"])
    await _seed_for(h, 200, "ana", "https://t.example/1", "COMMITTED", entry_line=line_a)
    await _seed_for(h, 300, "bob", "https://t.example/2", "COMMITTED", entry_line=line_b)
    await _seed_for(h, 400, "cid", "https://t.example/3", "COMMITTED", entry_line=line_c)
    await _seed_for(h, 500, "dee", "https://t.example/4", "NEW", entry_line=line_a)  # not counted

    text = (await h["flow"].handle_stats(USER, "jonan")).replies[1]
    assert "🏷️" in text
    # type tags count too; ties break alphabetically; case-insensitive dedupe
    assert "🥇 type:tool — 3 links" in text
    assert "🥈 linux — 2 links" in text  # "Linux" folded into "linux"
    assert "🥉 web — 2 links" in text
    assert "free" not in text and "Linux" not in text  # legacy cost never emitted, one spelling
    assert text.index("linux") < text.index("web")  # l < w


async def test_stats_tag_board_survives_a_tampered_entry_line(h: dict) -> None:
    await _seed_for(h, 200, "ana", "https://t.example/1", "COMMITTED", entry_line="not a bullet at all")

    result = await h["flow"].handle_stats(USER, "jonan")
    assert result.replies[1] == STATS_TAGS_EMPTY  # skipped, no crash, nothing counted


async def test_stats_does_not_disturb_the_active_flow(h: dict) -> None:
    """Mid-interview /stats is read-only: the pending resource stays put."""
    flow = h["flow"]
    await _capture_token(h)
    await flow.handle_text(USER, "jonan", GITHUB_URL)

    result = await flow.handle_stats(USER, "jonan")

    assert result.replies == (STATS_EMPTY, STATS_TAGS_EMPTY)  # in-flight links are not on it
    active = await get_active_resource_for_user(h["conn"], USER)
    assert active is not None


async def test_cmd_stats_handler_sends_both_boards(h: dict) -> None:
    line = build_entry_line("Tool A", GITHUB_URL, "does things", "tool", ["linux"])
    await _seed_for(h, USER, "jonan", GITHUB_URL, "COMMITTED", entry_line=line)
    message = FakeMessage(USER, "jonan", "/stats")

    await handlers.cmd_stats(message, h["deps"], h["flow"])

    assert len(message.answers) == 2  # one message per board (S: different messages)
    assert "🥇 @jonan — 1 link" in message.answers[0]
    assert message.answers[1].startswith("🏷️") and "linux — 1 link" in message.answers[1]


# ----------------------------------------------- flow-interrupt-rearm (S1, S2, S4)


async def _to_summary(h: dict) -> ResourceFlow:
    """A non-GitHub resource parked in NEED_SUMMARY, waiting for its text answer."""
    flow = h["flow"]
    await _capture_token(h)
    result = await flow.handle_text(USER, "jonan", OTHER_URL)
    assert result.replies == (ASK_SUMMARY,)
    return flow


async def test_text_at_a_text_step_is_the_answer_directly(h: dict) -> None:
    """S4: a text-driven step (summary here) takes the message — NO Continue press."""
    flow = await _to_summary(h)
    result = await flow.handle_text(USER, "jonan", "An offline wordlist generator.")
    assert "folder(s)" in result.replies[0]  # the decision ran immediately
    assert not await _audit(h, "flow_interrupted")


async def test_optional_tags_are_accepted_without_the_prompt(h: dict) -> None:
    """S4 user-report pin: platform tags typed at their step just land."""
    flow = await _to_interview(h)
    await flow.handle_text(USER, "jonan", "Name")
    await flow.handle_text(USER, "jonan", "Description")
    await flow.handle_callback(USER, "jonan", "tool")  # type step by button
    result = await flow.handle_text(USER, "jonan", "linux docker")
    assert isinstance(result.keyboard, ConfirmKB)  # straight to the preview
    assert not await _audit(h, "flow_interrupted")


async def test_text_during_button_step_asks_continue_or_cancel(h: dict) -> None:
    """S1 + S4: a text the current step cannot use gets the prompt, unprocessed."""
    flow = await _to_placement(h)  # AWAITING_PLACEMENT (candidates card)
    result = await flow.handle_text(USER, "jonan", "just text")
    assert result.replies == (FLOW_INTERRUPTED,)
    assert isinstance(result.keyboard, ResumeKB)
    resource = await get_resource(h["conn"], await _active_id(h))
    assert resource.state == "AWAITING_PLACEMENT" and not resource.folder
    assert await _audit(h, "flow_interrupted")


async def test_continue_resends_the_current_step_message(h: dict) -> None:
    """S2: Continue re-sends the step message; a button step stays button-driven."""
    flow = await _to_placement(h)
    await flow.handle_text(USER, "jonan", "noise")  # -> prompt
    resumed = await flow.handle_callback(USER, "jonan", "keep")
    assert isinstance(resumed.keyboard, FoldersKB)  # placement step re-sent
    assert await _audit(h, "flow_resumed")
    again = await flow.handle_text(USER, "jonan", "more text")
    assert again.replies == (FLOW_INTERRUPTED,)


async def test_continue_at_a_text_step_re_asks_it_and_text_still_lands(h: dict) -> None:
    """S2 + S4: Continue also re-sends a text ask; answers work with or without it."""
    flow = await _to_summary(h)
    resumed = await flow.handle_callback(USER, "jonan", "keep")
    assert resumed.replies == (ASK_SUMMARY,)
    result = await flow.handle_text(USER, "jonan", "An offline wordlist generator.")
    assert "folder(s)" in result.replies[0]


async def test_cancel_from_the_prompt_drops_the_resource(h: dict) -> None:
    """S1: the ❌ button on the prompt is the cancel choice."""
    flow = await _to_placement(h)
    await flow.handle_text(USER, "jonan", "noise")
    result = await flow.handle_callback(USER, "jonan", "❌")
    assert result.replies == (CANCELLED_MSG,)
    assert await get_active_resource_for_user(h["conn"], USER) is None


async def test_start_with_active_flow_offers_the_buttons(h: dict) -> None:
    """S1 on the /start path: pending flow answers with the prompt + ResumeKB."""
    flow = await _to_summary(h)
    result = await flow.handle_start(USER, "jonan")
    assert result.replies[-1] == FLOW_INTERRUPTED
    assert isinstance(result.keyboard, ResumeKB)

    await flow.handle_cancel(USER)  # no flow: the plain greeting contract stays
    plain = await flow.handle_start(USER, "jonan")
    assert plain.replies == (GREETING_READY,)
    assert plain.keyboard is None


async def test_rejected_answer_just_reasks_without_the_prompt(h: dict) -> None:
    """S4: a rejection re-asks its own step; the retry lands directly."""
    flow = await _to_interview(h)  # name step, no pre-fills
    result = await flow.handle_text(USER, "jonan", "Bad]Name")
    assert "[" in result.replies[0] or "]" in result.replies[0]  # INVALID_FIELD
    result = await flow.handle_text(USER, "jonan", "SQLMap")  # retry, straight through
    assert "description" in "\n".join(result.replies).lower()


async def test_confirming_paste_back_after_the_marker_press(h: dict) -> None:
    """The ✏️/🏷️ ask takes its paste; only stray CONFIRMING text is guarded."""
    flow, _ = await _to_confirming(h)
    stray = await flow.handle_text(USER, "jonan", "stray text")
    assert stray.replies == (FLOW_INTERRUPTED,)  # no marker -> button step
    await flow.handle_callback(USER, "jonan", "d")  # the edit ask takes the next text
    result = await flow.handle_text(USER, "jonan", "A superb recon tool")
    assert result.replies[0].startswith(PREVIEW)  # accepted directly


async def test_keep_without_active_flow_says_nothing_pending(h: dict) -> None:
    result = await h["flow"].handle_callback(USER, "jonan", "keep")
    assert result.replies == (NOTHING_PENDING,)


async def test_resume_kb_renders_continue_and_cancel(h: dict) -> None:
    """S1: the keyboard rides the prompt — ▶️ keep first, ❌ cancel second."""
    markup = handlers.render_keyboard(h["deps"], FlowResult(("x",), ResumeKB()))
    assert markup is not None
    rows = markup.inline_keyboard
    assert rows[0][0].callback_data == "keep"
    assert rows[1][0].callback_data == "❌"
