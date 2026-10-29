"""Settings and startup wiring for the mirror loop (repo-mirror-dedup T4; S3, S4).

Bounds on the new optional Settings fields (defaults keep every existing
construction green), and one integration pin on ``app.main``: with the switch
on, ``mirror_sync_loop`` is launched as a task on the shared DB connection and
cancelled on shutdown; with the switch off, it is never launched. aiogram's
Bot/Dispatcher are stubbed — no network, no real polling.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.config import Settings

USER = 100


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "telegram_bot_token": "123456:TEST-BOT-TOKEN",
        "AUTHORIZED_USERS": frozenset({USER}),
        "CATEGORIES_JSON": {"01_Recon/OSINT": "recon resources"},
        "QWEN_API_URL": "https://qwen.example.invalid/compatible-mode/v1/systemone",
        "qwen_api_key": "qwen-test-key",
        "SECRETS_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


# ----------------------------------------------------------------- settings


def test_mirror_settings_defaults_keep_constructions_green() -> None:
    s = make_settings()
    assert s.mirror_sync_enabled is True
    assert s.mirror_sync_interval_hours == 1.0  # S3: hourly by default


def test_mirror_sync_can_be_disabled() -> None:
    assert make_settings(mirror_sync_enabled=False).mirror_sync_enabled is False


@pytest.mark.parametrize("hours", [0.0, -1.0, 24.5, 100.0])
def test_mirror_interval_bounds_rejected(hours: float) -> None:
    with pytest.raises(ValidationError):
        make_settings(mirror_sync_interval_hours=hours)


@pytest.mark.parametrize("hours", [0.25, 1.0, 24.0])
def test_mirror_interval_bounds_accepted(hours: float) -> None:
    assert make_settings(mirror_sync_interval_hours=hours).mirror_sync_interval_hours == hours


# ------------------------------------------------------------------- wiring


class _DummyBot:
    def __init__(self, token: str) -> None:
        self.token = token


class _DummyDispatcher:
    """Yields once inside start_polling so scheduled tasks get their first tick."""

    def __init__(self, **kwargs: Any) -> None:
        self.polled = False

    def include_router(self, router: Any) -> None:  # noqa: D102
        return None

    async def start_polling(self, bot: Any, allowed_updates: Any = None) -> None:
        self.polled = True
        await asyncio.sleep(0)  # let the mirror task start its body


@pytest.fixture()
def wired(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    import app.main as m

    monkeypatch.setattr(m, "Bot", _DummyBot)
    dispatched: list[_DummyDispatcher] = []

    class DispatcherPatch(_DummyDispatcher):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            dispatched.append(self)

    monkeypatch.setattr(m, "Dispatcher", DispatcherPatch)

    mirror_calls: list[tuple[Any, Any]] = []

    async def fake_loop(settings: Any, conn: Any) -> None:
        mirror_calls.append((settings, conn))
        await asyncio.sleep(3600)  # cancelled by main's shutdown path

    monkeypatch.setattr(m, "mirror_sync_loop", fake_loop)

    env = {
        "TELEGRAM_BOT_TOKEN": "123456:TEST-BOT-TOKEN",
        "AUTHORIZED_USERS": str(USER),
        "CATEGORIES_JSON": '{"01_Recon/OSINT": "recon resources"}',
        "QWEN_API_URL": "https://qwen.example.invalid/compatible-mode/v1/systemone",
        "QWEN_API_KEY": "qwen-test-key",
        "SECRETS_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
        "DB_PATH": str(tmp_path / "data" / "hackpot.sqlite3"),
        "CATEGORY_SYNC_ENABLED": "false",
        "LOG_LEVEL": "CRITICAL",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("MIRROR_SYNC_ENABLED", raising=False)
    monkeypatch.delenv("MIRROR_SYNC_INTERVAL_HOURS", raising=False)

    return {"main": m, "mirror_calls": mirror_calls, "dispatched": dispatched}


async def test_main_launches_mirror_task_and_cancels_on_shutdown(wired: dict) -> None:
    """S4: the loop runs at startup for the life of the process (cancel at exit)."""
    await wired["main"].main()
    assert len(wired["mirror_calls"]) == 1
    settings, conn = wired["mirror_calls"][0]
    assert settings.mirror_sync_enabled is True
    assert settings.mirror_sync_interval_hours == 1.0
    assert conn is not None  # launched on the shared DB connection
    assert wired["dispatched"][0].polled is True


async def test_main_never_launches_mirror_when_disabled(wired: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRROR_SYNC_ENABLED", "false")
    await wired["main"].main()
    assert wired["mirror_calls"] == []
