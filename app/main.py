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

import httpx
from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage

from app.bot.flow import AppDeps, ResourceFlow, make_decision_factory, make_github_factory
from app.bot.handlers import router
from app.config import Settings
from app.db.database import open_db
from app.logging_config import get_logger, setup_logging
from app.security.rate_limit import RateLimiter

ALLOWED_UPDATES = ["message", "callback_query"]

logger = get_logger(__name__)


async def main() -> None:
    settings = Settings()  # fail-fast: invalid env stops before any I/O
    # Configure logging first (S2/S4): the bot token and Qwen key are handed to
    # the redaction filter so no credential can ever reach the stream.
    setup_logging(
        settings.log_level,
        secrets=(
            settings.telegram_bot_token.get_secret_value(),
            settings.qwen_api_key.get_secret_value(),
        ),
    )
    logger.info("hackpot bot starting repo=%s level=%s", settings.target_repo, settings.log_level)
    conn = await open_db(settings.db_path)
    http = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
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
        logger.info("starting Telegram polling")
        await dp.start_polling(bot, allowed_updates=ALLOWED_UPDATES)
    except Exception:  # noqa: BLE001 - log the traceback, then let it propagate unchanged
        logger.error("unexpected error during polling", exc_info=True)
        raise
    finally:
        await http.aclose()
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
