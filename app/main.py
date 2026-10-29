"""Entrypoint (T6; Specs S10, S11).

Wires the seams: fail-fast Settings, the SQLite bootstrap, one shared
httpx client (30 s timeouts per the Security section), the rate limiter, and
the aiogram dispatcher with the bot Router. Both polling and this module do
no network at construction time; on shutdown the shared httpx client and the
database connection are always closed (L7-6) — the Bot session is closed by
``start_polling(close_bot_session=True)``.
"""

from __future__ import annotations

import asyncio
import contextlib

import httpx
from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage

from app.bot.flow import AppDeps, ResourceFlow, make_decision_factory, make_github_factory
from app.bot.handlers import router
from app.config import Settings
from app.db.database import open_db
from app.logging_config import get_logger, setup_logging
from app.security.rate_limit import RateLimiter
from app.services.category_sync import category_refresh_loop
from app.services.repo_mirror import mirror_sync_loop

ALLOWED_UPDATES = ["message", "callback_query"]

logger = get_logger(__name__)


async def main() -> None:
    settings = Settings()  # fail-fast: invalid env stops before any I/O
    # Configure logging first (S2/S4): the bot token and Qwen key are handed to
    # the redaction filter so no credential can ever reach the stream.
    secrets = (
        settings.telegram_bot_token.get_secret_value(),
        settings.qwen_api_key.get_secret_value(),
        settings.fernet_key.get_secret_value(),
    )
    if settings.github_token is not None:
        secrets += (settings.github_token.get_secret_value(),)
    setup_logging(settings.log_level, secrets=secrets)
    logger.info("hackpot bot starting repo=%s level=%s", settings.target_repo, settings.log_level)
    conn = await open_db(settings.db_path)
    http = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
    sync_task: asyncio.Task | None = None
    mirror_task: asyncio.Task | None = None
    try:
        deps = AppDeps(
            settings=settings,
            conn=conn,
            limiter=RateLimiter(settings.rate_limit_per_min),
            http=http,
            make_github=make_github_factory(settings, http),
            make_decision=make_decision_factory(settings, http),
        )
        flow = ResourceFlow(deps)
        bot = Bot(token=settings.telegram_bot_token.get_secret_value())
        dp = Dispatcher(storage=MemoryStorage(), deps=deps, flow=flow)
        dp.include_router(router)
        # Daily category refresh: syncs once at startup, then wakes at
        # CATEGORY_SYNC_TIME and hot-swaps settings.categories. No network at
        # construction time (the first fetch runs inside the task).
        if settings.category_sync_enabled:
            sync_task = asyncio.create_task(category_refresh_loop(settings))
        # Repo mirror (S4): syncs the README link index once at startup, then
        # every settings.mirror_sync_interval_hours, on the shared DB conn.
        if settings.mirror_sync_enabled:
            mirror_task = asyncio.create_task(mirror_sync_loop(settings, conn))
        logger.info("starting Telegram polling")
        await dp.start_polling(bot, allowed_updates=ALLOWED_UPDATES)
    except Exception:  # noqa: BLE001 - log the traceback, then let it propagate unchanged
        logger.error("unexpected error during polling", exc_info=True)
        raise
    finally:
        if sync_task is not None:
            sync_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sync_task
        if mirror_task is not None:
            mirror_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await mirror_task
        await http.aclose()
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
