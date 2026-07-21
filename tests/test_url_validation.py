from __future__ import annotations

import pytest

from url_guard_bot.config import Config
from url_guard_bot.url_checker import (
    InvalidURL,
    UnsafeTargetError,
    ensure_global_ip,
    ensure_safe_hostname,
    has_sensitive_query,
    normalize_url,
    redact_url,
    registrable_domain,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com/"),
        ("https://example.com", "https://example.com/"),
        ("http://example.com/a", "http://example.com/a"),
        (" HTTPS://EXAMPLE.COM/a?x=1#frag ", "https://example.com/a?x=1"),
        ("https://пример.рф/путь", "https://xn--e1afmkfd.xn--p1ai/путь"),
        ("https://example.com:443/a", "https://example.com/a"),
        ("http://example.com:80/a", "http://example.com/a"),
    ],
)
def test_normalize_valid(config: Config, raw: str, expected: str) -> None:
    assert normalize_url(raw, config) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        " ",
        "ftp://example.com/file",
        "file:///etc/passwd",
        "data:text/plain,hello",
        "gopher://example.com/",
        "https://",
        "https://-bad.example/",
        "https://bad-.example/",
        "https://bad..example/",
        "https://user@example.com/",
        "https://user:pass@example.com/",
        "https://example.com:abc/",
        "https://example.com:99999/",
        "https://example.com/%0d%0aX-Test:1",
        "https://example.com/%250d%250aX-Test:1",
        "https://example.com/%",
        "https://example.com/\\evil",
        "https://example.com/\u200bhidden",
        "https://exa mple.com/",
        "https://[::1]/",
        "https://[::ffff:127.0.0.1]/",
    ],
)
def test_normalize_rejects_invalid_or_unsafe(config: Config, raw: str) -> None:
    with pytest.raises((InvalidURL, UnsafeTargetError)):
        normalize_url(raw, config)


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "localhost.localdomain",
        "service.local",
        "service.internal",
        "router.lan",
        "hidden.onion",
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::1",
        "fe80::1",
    ],
)
def test_hostname_rejects_local_targets(host: str) -> None:
    with pytest.raises(UnsafeTargetError):
        ensure_safe_hostname(host)


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.31.255.255",
        "192.168.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "::ffff:127.0.0.1",
    ],
)
def test_ensure_global_ip_rejects_special(ip: str) -> None:
    with pytest.raises(UnsafeTargetError):
        ensure_global_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_ensure_global_ip_accepts_public(ip: str) -> None:
    ensure_global_ip(ip)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/?token=abc", True),
        ("https://example.com/?TOKEN=abc", True),
        ("https://example.com/?api_key=abc", True),
        ("https://example.com/?password=abc", True),
        ("https://example.com/?q=token", False),
        ("https://example.com/?page=1", False),
    ],
)
def test_sensitive_query(url: str, expected: bool) -> None:
    assert has_sensitive_query(url) is expected


def test_redact_url_hides_credentials_and_query() -> None:
    assert redact_url("https://user:pass@example.com/a?token=secret#x") == (
        "https://example.com/a?<скрыто>"
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://www.example.com/a", "example.com"),
        ("sub.example.co.uk", "example.co.uk"),
        ("8.8.8.8", "8.8.8.8"),
        ("", ""),
    ],
)
def test_registrable_domain(value: str, expected: str) -> None:
    assert registrable_domain(value) == expected
