"""Leveled logging with secret redaction (feature hackpot-logging; Specs S2-S6).

The point of this file is S4: a credential must never reach the log stream.
That guarantee lives on the *handler filter*, so redaction is proven through
the real configured handler and captured ``stdout`` (``capsys``) — never
through ``caplog``, whose own handler bypasses the handler we install.

Wiring seams (decision / github / flow) are exercised against their real
functions so a log line that exists in the module is pinned, while the
existing behaviour (return values, raised errors) stays untouched (S6).
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.bot.flow import AppDeps, ResourceFlow
from app.config import Settings
from app.db.database import open_db
from app.logging_config import LEVELS, RedactionFilter, get_logger, setup_logging
from app.security.rate_limit import RateLimiter
from app.services.decision import DecisionClient
from app.services.github import FetchError, GitHubClient

# Credentials used as *shapes* the filter must catch even when they are not
# configured as literals, plus literals passed to setup_logging.
FAKE_BOT_TOKEN = "123456:FAKEBOTTOKENabcdefghijkl"
FAKE_SK_KEY = "sk-FAKEQWENKEY0123456789abcdef"
FAKE_GHP = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
FAKE_PAT = "github_pat_11ABCDEFGH_zyxwvutsrqponmlkjihgfedcba9876543210"

API_URL = "https://decision.test/compatible-mode/v1/systemone"
MODEL = "decision-model-preview"
CATEGORIES = {"02_Web_Application/Vulnerability_Specific": "web vulnerability tooling"}
CHOSEN = "02_Web_Application/Vulnerability_Specific"


# --------------------------------------------------------------------------- #
# fixtures / helpers
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def _clean_root_logging() -> Iterator[None]:
    """Detach the hackpot handler and restore the root level after each test."""
    yield
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_hackpot_logging", False):
            root.removeHandler(handler)
            handler.close()
    root.setLevel(logging.NOTSET)


def make_settings(**overrides: Any) -> Settings:
    """Validated Settings from test-only values (never reads the real env)."""
    values: dict[str, Any] = {
        "telegram_bot_token": FAKE_BOT_TOKEN,
        "AUTHORIZED_USERS": frozenset({100}),
        "CATEGORIES_JSON": dict(CATEGORIES),
        "QWEN_API_URL": API_URL,
        "qwen_api_key": FAKE_SK_KEY,
        "SECRETS_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


class Scripted:
    """MockTransport handler that replays scripted responses and absorbs sleeps."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self.responses = list(responses)
        self.calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        response = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return response

    async def sleep(self, delay: float) -> None:  # pragma: no cover - trivial
        return None


# --------------------------------------------------------------------------- #
# S4 — redaction through the REAL handler / captured stdout
# --------------------------------------------------------------------------- #
def test_redaction_scrubles_all_shapes_through_handler(capsys: pytest.CaptureFixture[str]) -> None:
    setup_logging("DEBUG", secrets=(FAKE_BOT_TOKEN, FAKE_SK_KEY))
    logger = get_logger("hackpot.redaction")

    logger.info(
        "leak attempt bot=%s pat=%s github=%s key=%s header Authorization: Bearer %s",
        FAKE_BOT_TOKEN,
        FAKE_GHP,
        FAKE_PAT,
        FAKE_SK_KEY,
        FAKE_BOT_TOKEN,
    )

    out = capsys.readouterr().out
    assert "***" in out
    for secret in (FAKE_BOT_TOKEN, FAKE_GHP, FAKE_PAT, FAKE_SK_KEY):
        assert secret not in out, f"plaintext credential leaked: {secret!r}"
    assert "Authorization:" not in out


def test_redaction_scrubles_formatted_exception(capsys: pytest.CaptureFixture[str]) -> None:
    setup_logging("DEBUG", secrets=(FAKE_SK_KEY,))
    logger = get_logger("hackpot.exception")

    try:
        raise RuntimeError(f"decision blew up with key {FAKE_SK_KEY}")
    except RuntimeError:
        logger.error("decision failed", exc_info=True)

    out = capsys.readouterr().out
    assert "Traceback" in out, "formatted exception body must still be present"
    assert "***" in out
    assert FAKE_SK_KEY not in out, "the key leaked through the exception text"


def test_redaction_filter_is_idempotent_and_keeps_safe_text() -> None:
    filt = RedactionFilter(secrets=(FAKE_SK_KEY,))
    record = logging.LogRecord(
        "hackpot.x", logging.INFO, "f.py", 1,
        "safe line about %s", ("folders",), None,
    )
    assert filt.filter(record) is True
    # The message is rendered onto record.msg so downstream handlers see scrubbed text.
    assert record.getMessage() == "safe line about folders"


# --------------------------------------------------------------------------- #
# S2 — setup idempotence, default INFO suppression, get_logger
# --------------------------------------------------------------------------- #
def test_setup_logging_is_idempotent(capsys: pytest.CaptureFixture[str]) -> None:
    setup_logging("DEBUG", secrets=())
    setup_logging("DEBUG", secrets=())  # a second call must not stack a handler
    logger = get_logger("hackpot.idempotent")
    logger.info("only-once-marker")

    out = capsys.readouterr().out
    assert out.count("only-once-marker") == 1


def test_default_level_info_suppresses_debug(capsys: pytest.CaptureFixture[str]) -> None:
    setup_logging("INFO")
    logger = get_logger("hackpot.levels")
    logger.debug("debug-hidden-marker")
    logger.info("info-shown-marker")

    out = capsys.readouterr().out
    assert "info-shown-marker" in out
    assert "debug-hidden-marker" not in out


def test_levels_constant() -> None:
    assert LEVELS == ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def test_get_logger_returns_named_propagating_logger() -> None:
    logger = get_logger("hackpot.config")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "hackpot.config"
    assert logger is logging.getLogger("hackpot.config")
    assert logger.propagate is True


# --------------------------------------------------------------------------- #
# S2 — LOG_LEVEL validator on Settings
# --------------------------------------------------------------------------- #
def test_log_level_defaults_to_info() -> None:
    assert make_settings().log_level == "INFO"


def test_log_level_accepts_case_insensitive_value() -> None:
    assert make_settings(LOG_LEVEL="debug").log_level == "DEBUG"
    assert make_settings(LOG_LEVEL="  WaRnInG ").log_level == "WARNING"


def test_log_level_rejects_invalid_with_helpful_error() -> None:
    with pytest.raises(ValidationError) as excinfo:
        make_settings(LOG_LEVEL="VERBOSE")
    message = str(excinfo.value)
    assert "VERBOSE" in message
    for level in LEVELS:
        assert level in message


# --------------------------------------------------------------------------- #
# S5 wiring — decision retry WARNING + success INFO, through the real handler
# --------------------------------------------------------------------------- #
async def test_decision_retry_warning_and_success_info(
    capsys: pytest.CaptureFixture[str],
) -> None:
    setup_logging("DEBUG", secrets=(FAKE_SK_KEY,))
    success = httpx.Response(
        200,
        json={
            "request_id": "req-smoke-42",
            "answers": {
                "folder": {"choice": CHOSEN, "probabilities": {CHOSEN: 0.9}},
                "cost": {"choice": "free"},
                "needs_admin": {"noul": 0.05},
            },
        },
    )
    scripted = Scripted([httpx.Response(500, text=f"server {FAKE_SK_KEY}"), httpx.Response(500, text="x"), success])
    client = httpx.AsyncClient(transport=httpx.MockTransport(scripted))
    try:
        dc = DecisionClient(
            api_url=API_URL, api_key=FAKE_SK_KEY, model=MODEL, client=client, sleep=scripted.sleep
        )
        await dc.classify("T-1", "https://example.invalid", CATEGORIES, 0.15, 3)
    finally:
        await client.aclose()

    out = capsys.readouterr().out
    assert "attempt 1/3" in out and "attempt 2/3" in out, "each retry attempt must be logged"
    assert "[app.services.decision]" in out, "the retry lines must come from the decision logger"
    assert "req-smoke-42" in out, "success INFO must carry the request id"
    assert FAKE_SK_KEY not in out


# --------------------------------------------------------------------------- #
# S5 wiring — github DEBUG request line + INFO commit + WARNING on error
# --------------------------------------------------------------------------- #
async def test_github_logs_commit_without_token(capsys: pytest.CaptureFixture[str]) -> None:
    setup_logging("DEBUG", secrets=(FAKE_GHP,))
    commit_url = "https://github.com/HackPot-HQ/Hackpot/commit/deadbeef"
    scripted = Scripted([httpx.Response(200, json={"content": {"commit": {"html_url": commit_url}}})])
    client = httpx.AsyncClient(transport=httpx.MockTransport(scripted))
    try:
        gh = GitHubClient(FAKE_GHP, client, "HackPot-HQ/Hackpot")
        url = await gh.put_file("02_Web_Application/Vulnerability_Specific/README.md", "text", "sha1", "msg", "main")
    finally:
        await client.aclose()

    assert url == commit_url
    out = capsys.readouterr().out
    assert "[app.services.github]" in out, "github seams log through the github logger"
    assert "PUT" in out and "main" in out  # DEBUG request summary carries method + branch
    assert "github commit ok" in out, "successful commit INFO must be logged"
    assert commit_url in out, "successful commit INFO must carry the commit url"
    assert FAKE_GHP not in out, "the PAT must never reach the log stream"


async def test_github_warns_on_read_error(capsys: pytest.CaptureFixture[str]) -> None:
    setup_logging("DEBUG", secrets=(FAKE_GHP,))
    scripted = Scripted([httpx.Response(403, json={"message": "forbidden"})])
    client = httpx.AsyncClient(transport=httpx.MockTransport(scripted))
    try:
        gh = GitHubClient(FAKE_GHP, client, "HackPot-HQ/Hackpot")
        with pytest.raises(FetchError):
            await gh.repo_meta("owner", "repo")
    finally:
        await client.aclose()

    out = capsys.readouterr().out
    # Prove it is OUR github WARNING (status only), not httpx's log; the misleading
    # fake-correlation token must be gone (review R2-1).
    assert "[app.services.github]" in out
    assert "WARNING" in out
    assert "HTTP 403" in out
    assert "res=unknown-ok" not in out
    assert FAKE_GHP not in out


# --------------------------------------------------------------------------- #
# S5 wiring — flow logs the unauthorized WARNING (id + username only)
# --------------------------------------------------------------------------- #
async def test_flow_logs_unauthorized(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    setup_logging("DEBUG", secrets=(FAKE_BOT_TOKEN,))
    settings = make_settings(db_path=tmp_path / "hackpot.sqlite3")
    conn = await open_db(settings.db_path)
    try:
        deps = AppDeps(
            settings=settings,
            conn=conn,
            limiter=RateLimiter(1000),
            http=httpx.AsyncClient(),
            make_github=lambda token: None,
            make_decision=lambda: None,
        )
        flow = ResourceFlow(deps)
        await flow.handle_unauthorized(987654, "intruder")
    finally:
        await deps.http.aclose()
        await conn.close()

    out = capsys.readouterr().out
    assert "unauthorized_ignored" in out
    assert "[app.bot.flow]" in out and "WARNING" in out, "unauthorized events are a flow WARNING"
    assert "987654" in out and "intruder" in out
