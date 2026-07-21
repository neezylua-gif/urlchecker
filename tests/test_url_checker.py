from __future__ import annotations

import pytest

from url_guard_bot.config import Config
from url_guard_bot.url_checker import (
    InvalidURL,
    UnsafeTargetError,
    extract_meta_refresh_target,
    has_sensitive_query,
    heuristic_findings,
    normalize_url,
    redact_url,
    registrable_domain,
)


@pytest.fixture()
def config() -> Config:
    return Config(bot_token="123456:TEST_TOKEN_FOR_UNIT_TESTS")


@pytest.mark.parametrize(
    "raw_url, expected",
    [
        ("example.com", "https://example.com/"),
        ("HTTPS://Example.COM/path?A=1#fragment", "https://example.com/path?A=1"),
        ("http://example.com:80", "http://example.com/"),
    ],
)
def test_normalize_url_canonicalizes_safe_urls(
    config: Config,
    raw_url: str,
    expected: str,
) -> None:
    assert normalize_url(raw_url, config) == expected


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/",
        "https://example.com/%zz",
        "https://example.com/\\admin",
    ],
)
def test_normalize_url_rejects_invalid_urls(config: Config, url: str) -> None:
    with pytest.raises(InvalidURL):
        normalize_url(url, config)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
        "http://service.internal/",
        "https://user:pass@example.com/",
    ],
)
def test_normalize_url_blocks_unsafe_targets(config: Config, url: str) -> None:
    with pytest.raises(UnsafeTargetError):
        normalize_url(url, config)


def test_redact_url_hides_query_values() -> None:
    assert redact_url("https://example.com/reset?token=secret") == (
        "https://example.com/reset?<скрыто>"
    )


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://example.com/reset?token=secret", True),
        ("https://example.com/callback?Code=abc", True),
        ("https://example.com/?page=1", False),
    ],
)
def test_has_sensitive_query(url: str, expected: bool) -> None:
    assert has_sensitive_query(url) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("https://login.example.co.uk/path", "example.co.uk"),
        ("sub.example.com", "example.com"),
        ("8.8.8.8", "8.8.8.8"),
    ],
)
def test_registrable_domain(value: str, expected: str) -> None:
    assert registrable_domain(value) == expected


def test_extract_meta_refresh_target_from_html_prefix() -> None:
    html = (
        b'<html><head><meta http-equiv="refresh" content="0; url=/next"></head></html>'
    )
    assert extract_meta_refresh_target(html, "text/html; charset=utf-8") == "/next"


def test_extract_meta_refresh_target_ignores_non_html() -> None:
    assert (
        extract_meta_refresh_target(
            b'<meta http-equiv="refresh" content="0; url=/next">', "text/plain"
        )
        is None
    )


def test_heuristic_findings_reports_plain_http_and_ip_literal() -> None:
    codes = {finding.code for finding in heuristic_findings("http://8.8.8.8/")}
    assert {"plain_http", "ip_literal"}.issubset(codes)
