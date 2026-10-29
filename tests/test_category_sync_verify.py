"""Regression pins from the independent verification of the daily category sync.

Probes exercised V1 loop math, V2 keep-curated merge, V3 refusal + loop
survival under SystemExit, V4 hot-swap snapshot isolation, V5 .env rewrite
edge cases (unchanged map, directory-as-env), and V6 CLI parity gaps
(CRLF env, missing env without flags).
"""

from __future__ import annotations

import asyncio
import importlib.util
from datetime import datetime
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app.config import Settings
from app.services import category_sync as cs

TREE = [
    {"path": "01_Recon_and_OSINT/OSINT", "type": "tree"},
    {"path": "01_Recon_and_OSINT/OSINT/README.md", "type": "blob"},
    {"path": "02_Web_Application/Proxies_and_Scanners", "type": "tree"},
    {"path": "02_Web_Application/Proxies_and_Scanners/README.md", "type": "blob"},
    {"path": "03_Network_and_Infrastructure/Wireless_and_Radio", "type": "tree"},
]
LEAVES = ["01_Recon_and_OSINT/OSINT", "02_Web_Application/Proxies_and_Scanners"]


def make_settings(**over) -> Settings:
    values: dict = {
        "telegram_bot_token": "123456:TEST-BOT-TOKEN",
        "AUTHORIZED_USERS": frozenset({123}),
        "CATEGORIES_JSON": {"01_Recon_and_OSINT/OSINT": "old curated"},
        "QWEN_API_URL": "https://qwen.example.invalid/v1",
        "qwen_api_key": "k",
        "SECRETS_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
    }
    values.update(over)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


@pytest.mark.parametrize("now,t,expected", [
    (datetime(2026, 10, 26, 22, 0), "00:00", 7200.0),
    (datetime(2026, 10, 26, 0, 0), "00:00", 86400.0),
    (datetime(2026, 10, 26, 0, 0, 0, 1), "00:00", 86399.999999),
    (datetime(2026, 10, 26, 23, 59), "00:00", 60.0),
    (datetime(2026, 10, 26, 8, 0), "9:05", 3900.0),
])
def test_seconds_until_next(now, t, expected):
    assert cs.seconds_until_next(now, t) == pytest.approx(expected)


def test_keep_curated_fills_placeholder_leaf(monkeypatch):
    monkeypatch.setattr(cs, "fetch_tree", lambda *a: TREE)
    monkeypatch.setattr(cs, "fetch_readme_descriptions", lambda *a, **k: {
        "01_Recon_and_OSINT/OSINT": "fresh readme",
        "02_Web_Application/Proxies_and_Scanners": "ph filled"})
    st = make_settings(category_sync_keep_curated=True, CATEGORIES_JSON={
        "01_Recon_and_OSINT/OSINT": "hand tuned",
        "02_Web_Application/Proxies_and_Scanners":
            cs.placeholder_criteria("02_Web_Application/Proxies_and_Scanners")})
    merged = cs.apply_refresh(st, env_file=None)
    assert merged["01_Recon_and_OSINT/OSINT"] == "hand tuned"
    assert merged["02_Web_Application/Proxies_and_Scanners"] == "ph filled"


def test_refusal_keeps_same_dict_object(monkeypatch):
    monkeypatch.setattr(cs, "fetch_tree", lambda *a: [])
    monkeypatch.setattr(cs, "fetch_readme_descriptions", lambda *a, **k: {})
    st = make_settings()
    ref = st.categories
    with pytest.raises(RuntimeError, match="refus"):
        cs.apply_refresh(st, env_file=None)
    assert st.categories is ref
    assert st.categories == {"01_Recon_and_OSINT/OSINT": "old curated"}


async def test_loop_survives_system_exit_from_fetch(monkeypatch):
    def boom(*a):
        raise SystemExit("no leaf categories found")

    monkeypatch.setattr(cs, "fetch_tree", boom)
    slept: list[float] = []

    async def sleep(sec: float) -> None:
        slept.append(sec)
        if len(slept) > 1:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await cs.category_refresh_loop(
            make_settings(), sleep=sleep,
            now=lambda: datetime(2026, 10, 26, 22, 0))
    assert len(slept) == 2  # failed refresh did not kill the loop


def test_hot_swap_never_mutates_old_snapshot(monkeypatch):
    monkeypatch.setattr(cs, "fetch_tree", lambda *a: TREE)
    monkeypatch.setattr(cs, "fetch_readme_descriptions", lambda *a, **k: {
        p: f"desc {p}" for p in LEAVES})
    st = make_settings()
    old = st.categories
    cs.apply_refresh(st, env_file=None)
    assert old == {"01_Recon_and_OSINT/OSINT": "old curated"}
    assert st.categories == {p: f"desc {p}" for p in LEAVES}


def test_unchanged_map_no_backup_churn(monkeypatch, tmp_path):
    monkeypatch.setattr(cs, "fetch_tree", lambda *a: TREE)
    monkeypatch.setattr(cs, "fetch_readme_descriptions", lambda *a, **k: {
        p: "stable" for p in LEAVES})
    env = tmp_path / ".env"
    env.write_text('CATEGORIES_JSON={"01_Recon_and_OSINT/OSINT":"stable"}\n', encoding="utf-8")
    st = make_settings(CATEGORIES_JSON={"01_Recon_and_OSINT/OSINT": "stable",
                                        "02_Web_Application/Proxies_and_Scanners": "stable"})
    cs.apply_refresh(st, env_file=env)
    cs.apply_refresh(st, env_file=env)
    # The in-memory map never changed; the .env gained the second leaf once and
    # the second refresh was a no-op — one rolling backup, no timestamp churn.
    assert len(list(tmp_path.glob(".env.bak*"))) == 1


def test_env_write_error_never_breaks_sync(monkeypatch, tmp_path):
    monkeypatch.setattr(cs, "fetch_tree", lambda *a: TREE)
    monkeypatch.setattr(cs, "fetch_readme_descriptions", lambda *a, **k: {
        p: "x" for p in LEAVES})
    d = tmp_path / "direnv"
    d.mkdir()
    st = make_settings()
    assert cs.apply_refresh(st, env_file=d) == st.categories


async def test_cli_crlf_and_missing_env(monkeypatch, tmp_path, capsys):
    script = Path(__file__).resolve().parents[1] / "scripts" / "sync_categories.py"
    spec = importlib.util.spec_from_file_location("sync_cli_verify", script)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(cs, "fetch_tree", lambda *a: TREE)
    monkeypatch.setattr(cs, "fetch_readme_descriptions", lambda *a, **k: {})

    env = tmp_path / ".env"
    original = b"TARGET_REPO=HackPot-HQ/Hackpot\r\nCATEGORIES_JSON={}\r\n"
    env.write_bytes(original)
    assert mod.main(["--env", str(env), "--dry-run"]) == 0
    # dry-run: no write at all, CRLF bytes intact
    assert env.read_bytes() == original

    missing = tmp_path / "absent.env"
    with pytest.raises(SystemExit, match="env file not found"):
        mod.main(["--env", str(missing)])
