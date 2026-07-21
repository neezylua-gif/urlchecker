from __future__ import annotations

from types import SimpleNamespace

import pytest
from aiogram.enums import MessageEntityType

from url_guard_bot.handlers import extract_url, format_result
from url_guard_bot.models import AnalysisResult, Finding, Severity


def message(text: str = "", *, entities=None):
    return SimpleNamespace(
        text=text, caption=None, entities=entities or [], caption_entities=[]
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("https://example.com", "https://example.com"),
        ("ссылка: https://example.com/a).", "https://example.com/a"),
        ("www.example.com/test", "www.example.com/test"),
        ("example.com/path", "example.com/path"),
        ("not a link", None),
    ],
)
def test_extract_url_from_text(text: str, expected: str | None) -> None:
    assert extract_url(message(text)) == expected


def test_extract_text_link_entity() -> None:
    entity = SimpleNamespace(
        type=MessageEntityType.TEXT_LINK, url=" https://example.com/x "
    )
    assert extract_url(message("click", entities=[entity])) == "https://example.com/x"


def test_format_result_hides_query() -> None:
    result = AnalysisResult(
        "https://example.com/?token=x",
        "https://example.com/?<скрыто>",
        normalized_url="https://example.com/?token=x",
        final_url="https://other.example/path?secret=x",
        status_code=200,
        findings=[Finding("w", Severity.WARNING, "warning")],
        elapsed_ms=12,
    )
    text = format_result(result)
    assert "token=x" not in text
    assert "secret=x" not in text
    assert "<скрыто>" in text
