"""Tests for the in-app daily category sync (app/services/category_sync.py).

Specs: refresh CATEGORIES_JSON from the Hackpot repo every day at 00:00 and
hot-swap ``settings.categories`` so the running bot and decision model see the
latest leaves without a restart. The script CLI behavior must stay identical
after the refactor (differential tests pin its stdout and .env rewrite).
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
from datetime import datetime
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.config import Settings
from app.services import category_sync as cs

REPO = "J0nan/Hackpot"
BRANCH = "main"


def _tree(*paths: tuple[str, str]) -> list[dict]:
    return [{"path": p, "type": t} for p, t in paths]


BASE_TREE = _tree(
    ("01_Recon_and_OSINT", "tree"),
    ("01_Recon_and_OSINT/OSINT", "tree"),
    ("01_Recon_and_OSINT/OSINT/README.md", "blob"),
    ("02_Web_Application", "tree"),
    ("02_Web_Application/Proxies_and_Scanners", "tree"),
    ("02_Web_Application/Proxies_and_Scanners/README.md", "blob"),
    ("README.md", "blob"),
)

LEAVES = [
    "01_Recon_and_OSINT/OSINT",
    "02_Web_Application/Proxies_and_Scanners",
]


def make_settings(**overrides) -> Settings:
    """Validated Settings from test-only values (never reads the real env)."""
    values: dict = {
        "telegram_bot_token": "123456:TEST-BOT-TOKEN",
        "AUTHORIZED_USERS": frozenset({123}),
        "CATEGORIES_JSON": {"01_Recon_and_OSINT/OSINT": "old curated"},
        "QWEN_API_URL": "https://qwen.example.invalid/compatible-mode/v1/systemone",
        "qwen_api_key": "qwen-test-key",
        "SECRETS_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


def fake_fetch_tree(tree: list[dict]):
    def _fetched(repo: str, branch: str, token: str | None) -> list[dict]:
        assert repo == REPO and branch == BRANCH
        return tree

    return _fetched


def fake_readmes(descriptions: dict[str, str]):
    def _fetch(repo: str, branch: str, leaves: list[str], token: str | None, workers: int = 8):
        return {leaf: descriptions[leaf] for leaf in leaves if leaf in descriptions}

    return _fetch


class TestSecondsUntilNext:
    def test_nightly_slot_two_hours_away(self):
        now = datetime(2026, 10, 26, 22, 0, 0)
        assert cs.seconds_until_next(now, "00:00") == 2 * 3600

    def test_exactly_at_the_slot_waits_a_full_day(self):
        now = datetime(2026, 10, 26, 0, 0, 0)
        assert cs.seconds_until_next(now, "00:00") == 24 * 3600

    def test_crosses_into_tomorrow(self):
        now = datetime(2026, 10, 26, 12, 34, 0)
        assert cs.seconds_until_next(now, "06:30") == 17 * 3600 + 56 * 60

    def test_accepts_unpadded_times(self):
        now = datetime(2026, 10, 26, 8, 0, 0)
        assert cs.seconds_until_next(now, "9:05") == 65 * 60


class TestApplyRefresh:
    def test_hot_swaps_settings_categories_from_repo(self, monkeypatch):
        monkeypatch.setattr(cs, "fetch_tree", fake_fetch_tree(BASE_TREE))
        monkeypatch.setattr(
            cs,
            "fetch_readme_descriptions",
            fake_readmes({p: f"desc for {p}" for p in LEAVES}),
        )
        settings = make_settings()
        merged = cs.apply_refresh(settings, env_file=None)
        # Repo README intros are the source of truth; the removed leaf is gone.
        assert merged == {p: f"desc for {p}" for p in LEAVES}
        assert settings.categories == merged

    def test_keep_curated_preserves_hand_tuned_criteria(self, monkeypatch):
        monkeypatch.setattr(cs, "fetch_tree", fake_fetch_tree(BASE_TREE))
        monkeypatch.setattr(
            cs, "fetch_readme_descriptions", fake_readmes({p: "readme text" for p in LEAVES})
        )
        settings = make_settings(category_sync_keep_curated=True)
        merged = cs.apply_refresh(settings, env_file=None)
        assert merged["01_Recon_and_OSINT/OSINT"] == "old curated"
        assert merged["02_Web_Application/Proxies_and_Scanners"] == "readme text"

    def test_empty_tree_is_refused_and_current_categories_survive(self, monkeypatch):
        monkeypatch.setattr(cs, "fetch_tree", fake_fetch_tree(_tree(("docs", "tree"))))
        settings = make_settings()
        with pytest.raises(RuntimeError, match="refusing"):
            cs.apply_refresh(settings, env_file=None)
        assert settings.categories == {"01_Recon_and_OSINT/OSINT": "old curated"}

    def test_unreadme_leaf_gets_placeholder_not_blank(self, monkeypatch):
        monkeypatch.setattr(cs, "fetch_tree", fake_fetch_tree(BASE_TREE))
        monkeypatch.setattr(cs, "fetch_readme_descriptions", fake_readmes({}))
        settings = make_settings()
        merged = cs.apply_refresh(settings, env_file=None)
        assert all(v.strip() for v in merged.values())

    def test_updates_env_file_with_rolling_backup(self, monkeypatch, tmp_path):
        monkeypatch.setattr(cs, "fetch_tree", fake_fetch_tree(BASE_TREE))
        monkeypatch.setattr(
            cs,
            "fetch_readme_descriptions",
            fake_readmes({p: "fresh" for p in LEAVES}),
        )
        env = tmp_path / ".env"
        env.write_text(
            "# keep me\nTARGET_REPO=J0nan/Hackpot\n"
            'CATEGORIES_JSON={"01_Recon_and_OSINT/OSINT":"old curated"}\n',
            encoding="utf-8",
        )
        settings = make_settings()
        cs.apply_refresh(settings, env_file=env)
        text = env.read_text(encoding="utf-8")
        line = next(l for l in text.splitlines() if l.startswith("CATEGORIES_JSON="))
        assert json.loads(line.split("=", 1)[1]) == {p: "fresh" for p in LEAVES}
        assert "# keep me" in text and "TARGET_REPO=J0nan/Hackpot" in text
        backup = tmp_path / ".env.bak"
        assert "old curated" in backup.read_text(encoding="utf-8")

    def test_missing_env_file_never_breaks_the_sync(self, monkeypatch, tmp_path):
        monkeypatch.setattr(cs, "fetch_tree", fake_fetch_tree(BASE_TREE))
        monkeypatch.setattr(cs, "fetch_readme_descriptions", fake_readmes({}))
        settings = make_settings()
        merged = cs.apply_refresh(settings, env_file=tmp_path / "absent.env")
        assert settings.categories == merged


class TestCategoryRefreshLoop:
    async def test_refreshes_at_startup_then_sleeps_until_slot(self):
        now = datetime(2026, 10, 26, 22, 0, 0)
        delays: list[float] = []
        refreshed: list[Settings] = []

        async def sleep(seconds: float) -> None:
            delays.append(seconds)
            raise asyncio.CancelledError  # shutdown before the midnight wake

        async def to_thread(fn, *args):
            refreshed.append(args[0])

        settings = make_settings()
        with pytest.raises(asyncio.CancelledError):
            await cs.category_refresh_loop(
                settings, sleep=sleep, to_thread=to_thread,
                refresh=lambda s: dict(s.categories), now=lambda: now,
            )
        # The refresh ran immediately at startup, then the loop armed the slot.
        assert refreshed == [settings]
        assert delays == [2 * 3600]

    async def test_startup_failure_still_schedules_the_slot(self):
        slept: list[float] = []

        async def sleep(seconds: float) -> None:
            slept.append(seconds)
            raise asyncio.CancelledError

        settings = make_settings()

        def boom(_settings):
            raise RuntimeError("GitHub request failed")

        with pytest.raises(asyncio.CancelledError):
            await cs.category_refresh_loop(
                settings, sleep=sleep, refresh=boom,
                now=lambda: datetime(2026, 10, 26, 22, 0, 0),
            )
        # A dead startup sync is logged, not fatal: the nightly slot is armed
        # and the current categories survive.
        assert len(slept) == 1
        assert settings.categories == {"01_Recon_and_OSINT/OSINT": "old curated"}

    async def test_refresh_failure_keeps_the_loop_alive(self):
        slept: list[float] = []

        async def sleep(seconds: float) -> None:
            slept.append(seconds)
            if len(slept) > 1:
                raise asyncio.CancelledError

        calls: list[int] = []

        async def to_thread(fn, *args):
            calls.append(1)
            raise RuntimeError("GitHub request failed")

        settings = make_settings()
        with pytest.raises(asyncio.CancelledError):
            await cs.category_refresh_loop(
                settings, sleep=sleep, to_thread=to_thread,
                refresh=None, now=lambda: datetime(2026, 10, 26, 22, 0, 0),
            )
        # The failure was logged, not fatal: the loop scheduled the next slot.
        assert len(slept) == 2

    async def test_default_refresh_is_apply(self, monkeypatch):
        called: list = []
        monkeypatch.setattr(cs, "apply_refresh", lambda s: called.append(s))

        async def sleep(seconds: float) -> None:
            raise asyncio.CancelledError

        st = make_settings()
        with pytest.raises(asyncio.CancelledError):
            await cs.category_refresh_loop(
                st, sleep=sleep,
                now=lambda: datetime(2026, 10, 26, 22, 0, 0),
            )
        assert called == [st]  # startup run fires before the first sleep


class TestSettingsFields:
    def test_defaults(self):
        settings = make_settings()
        assert settings.category_sync_enabled is True
        assert settings.category_sync_time == "00:00"
        assert settings.category_sync_keep_curated is False
        assert settings.github_token is None

    def test_github_token_is_a_secret(self):
        settings = make_settings(github_token="ghp_secret")
        assert settings.github_token.get_secret_value() == "ghp_secret"

    def test_time_is_normalized(self):
        assert make_settings(category_sync_time="9:05").category_sync_time == "09:05"

    @pytest.mark.parametrize("bad", ["24:00", "12:60", "0000", "nightly", "1:5"])
    def test_bad_time_rejected(self, bad):
        with pytest.raises(ValidationError):
            make_settings(category_sync_time=bad)


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sync_categories.py"


@pytest.fixture(scope="module")
def script_mod():
    spec = importlib.util.spec_from_file_location("sync_categories", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestScriptCliUnchanged:
    """Differential pins: the refactored CLI keeps its stdout, .env rewrite and backup."""

    def test_main_updates_env_and_prints_the_same_progress(self, script_mod, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(cs, "fetch_tree", fake_fetch_tree(BASE_TREE))
        monkeypatch.setattr(
            cs,
            "fetch_readme_descriptions",
            fake_readmes({p: "readme text" for p in LEAVES}),
        )
        env = tmp_path / ".env"
        env.write_text(
            'TARGET_REPO=J0nan/Hackpot\nTARGET_BRANCH=main\n'
            'CATEGORIES_JSON={"01_Recon_and_OSINT/OSINT":"old curated"}\n',
            encoding="utf-8",
        )
        assert script_mod.main(["--env", str(env)]) == 0
        out = capsys.readouterr().out
        assert f"Fetching {REPO}@{BRANCH} tree from GitHub ..." in out
        assert "Fetching 2 leaf README description(s) from raw.githubusercontent ..." in out
        assert "  2 README intro(s) found." in out
        line = next(l for l in env.read_text(encoding="utf-8").splitlines()
                    if l.startswith("CATEGORIES_JSON="))
        assert json.loads(line.split("=", 1)[1]) == {p: "readme text" for p in LEAVES}
        assert list(tmp_path.glob(".env.bak.*"))  # timestamped backup, as before

    def test_dry_run_writes_nothing(self, script_mod, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(cs, "fetch_tree", fake_fetch_tree(BASE_TREE))
        monkeypatch.setattr(cs, "fetch_readme_descriptions", fake_readmes({}))
        env = tmp_path / ".env"
        before = 'TARGET_REPO=J0nan/Hackpot\nTARGET_BRANCH=main\nCATEGORIES_JSON={}\n'
        env.write_text(before, encoding="utf-8")
        assert script_mod.main(["--env", str(env), "--dry-run"]) == 0
        assert env.read_text(encoding="utf-8") == before
        assert "--dry-run: .env not modified." in capsys.readouterr().out
