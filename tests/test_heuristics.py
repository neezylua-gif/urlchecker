from __future__ import annotations

import pytest

from url_guard_bot.url_checker import extract_meta_refresh_target, heuristic_findings


def codes(url: str) -> set[str]:
    return {finding.code for finding in heuristic_findings(url)}


@pytest.mark.parametrize(
    ("url", "expected_code"),
    [
        ("http://example.com/", "plain_http"),
        ("https://8.8.8.8/", "ip_literal"),
        ("https://xn--e1afmkfd.xn--p1ai/", "punycode"),
        ("https://" + "a" * 61 + ".com/", "long_host"),
        ("https://a-b-c-d-e-f.example.com/", "many_hyphens"),
        ("https://a.b.c.d.e.f.example.com/", "many_subdomains"),
        ("https://paypal.com.evil.example/", "brand_in_subdomain"),
        ("https://paypa1.com/", "possible_typosquat"),
    ],
)
def test_heuristic_flags(url: str, expected_code: str) -> None:
    assert expected_code in codes(url)


def test_popular_domain_not_flagged() -> None:
    assert "possible_typosquat" not in codes("https://paypal.com/")


@pytest.mark.parametrize(
    ("body", "content_type", "expected"),
    [
        (b'<meta http-equiv="refresh" content="0;url=/next">', "text/html", "/next"),
        (
            b"<META HTTP-EQUIV='refresh' CONTENT='1; URL=https://example.com'>",
            "text/html",
            "https://example.com",
        ),
        (b"<html></html>", "text/html", None),
        (b'<meta http-equiv="refresh" content="0;url=/next">', "text/plain", None),
        (b"", "text/html", None),
    ],
)
def test_meta_refresh(body: bytes, content_type: str, expected: str | None) -> None:
    assert extract_meta_refresh_target(body, content_type) == expected
