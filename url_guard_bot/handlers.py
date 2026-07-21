from __future__ import annotations

import logging
import re

from aiogram import F, Router
from aiogram.enums import MessageEntityType
from aiogram.filters import Command, CommandStart
from aiogram.types import LinkPreviewOptions, Message
from aiogram.utils.chat_action import ChatActionSender

from .models import AnalysisResult, Severity, Verdict
from .rate_limiter import UserRateLimiter
from .url_checker import URLAnalyzer

logger = logging.getLogger(__name__)

router = Router(name="url_guard")

URL_RE = re.compile(r"(?i)(?<![\w@])(?:https?://|www\.)[^\s<>\[\]{}\"']+")
TRAILING_PUNCTUATION = ".,!?;:)]}>»”’"


def extract_url(message: Message) -> str | None:
    text = message.text or message.caption or ""
    entities = message.entities or message.caption_entities or []

    for entity in entities:
        if entity.type == MessageEntityType.TEXT_LINK and entity.url:
            return entity.url.strip()

    match = URL_RE.search(text)
    if match:
        return match.group(0).rstrip(TRAILING_PUNCTUATION)

    # A plain domain without a scheme is accepted when the whole message is it.
    candidate = text.strip().rstrip(TRAILING_PUNCTUATION)
    if re.fullmatch(r"(?i)(?:[a-z0-9-]+\.)+[a-z]{2,63}(?:/[^\s]*)?", candidate):
        return candidate
    return None


def format_result(result: AnalysisResult) -> str:
    verdicts = {
        Verdict.LOW_RISK: "✅ Явных признаков угрозы не обнаружено",
        Verdict.SUSPICIOUS: "⚠️ Обнаружены подозрительные признаки",
        Verdict.DANGEROUS: "🚫 Ссылка потенциально опасна",
        Verdict.UNKNOWN: "❔ Не удалось надёжно завершить проверку",
    }
    severity_icons = {
        Severity.INFO: "ℹ️",
        Severity.WARNING: "⚠️",
        Severity.DANGER: "🚫",
        Severity.ERROR: "❔",
    }

    lines = [verdicts[result.verdict], "", f"🔗 URL: {result.display_url}"]
    if result.final_url and result.final_url != result.normalized_url:
        from .url_checker import redact_url

        lines.append(f"🏁 Итоговый URL: {redact_url(result.final_url)}")
    if result.status_code is not None:
        lines.append(f"🌐 HTTP-статус: {result.status_code}")
    if result.redirects:
        lines.append(f"↪️ Редиректов: {len(result.redirects)}")

    visible_findings = [
        item for item in result.findings if item.severity is not Severity.INFO
    ]
    info_findings = [item for item in result.findings if item.severity is Severity.INFO]
    ordered = visible_findings + info_findings

    lines.extend(["", "📋 Результаты:"])
    if ordered:
        for finding in ordered[:12]:
            lines.append(f"{severity_icons[finding.severity]} {finding.message}")
    else:
        lines.append("ℹ️ Дополнительных замечаний нет.")

    lines.extend(
        [
            "",
            f"⏱ Проверка: {result.elapsed_ms} мс",
            "Бот оценивает технические признаки и не гарантирует абсолютную безопасность сайта.",
        ]
    )
    return "\n".join(lines)


@router.message(CommandStart())
async def cmd_start(message: Message) -> None:
    await message.answer(
        "Отправьте HTTP/HTTPS-ссылку — я проверю редиректы, TLS, домен и технические признаки риска.\n\n"
        "Внутренние адреса, локальные сети и опасные порты блокируются до выполнения запроса."
    )


@router.message(Command("help"))
async def cmd_help(message: Message) -> None:
    await message.answer(
        "Пример: https://example.com\n\n"
        "Проверка не заменяет антивирус, песочницу и репутационные базы. Не вводите пароли и платёжные данные на подозрительных сайтах."
    )


@router.message(F.text | F.caption)
async def handle_message(
    message: Message,
    analyzer: URLAnalyzer,
    rate_limiter: UserRateLimiter,
) -> None:
    url = extract_url(message)
    if not url:
        await message.reply("❌ Не нашёл HTTP/HTTPS-ссылку в сообщении.")
        return

    user_key = message.from_user.id if message.from_user else message.chat.id
    allowed, retry_after = await rate_limiter.check(user_key)
    if not allowed:
        await message.reply(
            f"⏳ Слишком много проверок. Повторите примерно через {retry_after} сек."
        )
        return

    try:
        async with ChatActionSender.typing(bot=message.bot, chat_id=message.chat.id):
            result = await analyzer.analyze(url)
    except Exception:
        # The analyzer already handles expected network errors. This boundary
        # prevents an unexpected bug from terminating an update task.
        logger.exception("Unhandled URL handler failure")
        await message.reply("❔ Внутренняя ошибка. Ссылка не была полностью проверена.")
        return

    await message.reply(
        format_result(result),
        link_preview_options=LinkPreviewOptions(is_disabled=True),
    )
