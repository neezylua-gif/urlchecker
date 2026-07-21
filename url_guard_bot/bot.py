from __future__ import annotations

import asyncio
import logging

from aiogram import Bot, Dispatcher

from .config import Config
from .handlers import router
from .rate_limiter import UserRateLimiter
from .url_checker import URLAnalyzer


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


async def main() -> None:
    configure_logging()
    config = Config.from_env()

    bot = Bot(token=config.bot_token)
    dispatcher = Dispatcher()
    dispatcher.include_router(router)

    rate_limiter = UserRateLimiter(
        limit=config.rate_limit_requests,
        window_seconds=config.rate_limit_window_seconds,
        max_keys=config.rate_limit_max_users,
    )

    try:
        async with URLAnalyzer(config) as analyzer:
            dispatcher["analyzer"] = analyzer
            dispatcher["rate_limiter"] = rate_limiter

            await bot.delete_webhook(drop_pending_updates=True)
            await dispatcher.start_polling(
                bot,
                allowed_updates=dispatcher.resolve_used_update_types(),
                tasks_concurrency_limit=config.update_concurrency_limit,
                close_bot_session=False,
            )
    finally:
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
