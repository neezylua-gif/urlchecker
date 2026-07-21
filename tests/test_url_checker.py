from __future__ import annotations

import socket

import pytest
from aiohttp.abc import AbstractResolver

from url_guard_bot.config import Config
from url_guard_bot.models import AnalysisResult, Finding, Severity, Verdict
from url_guard_bot.url_checker import (
    InvalidURL,
    ProbeResponse,
    PublicOnlyResolver,
    URLAnalyzer,
    UnsafeTargetError,
    ensure_global_ip,
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
    "url",
    [
        "http://127.0.0.1",
        "http://10.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://localhost/",
        "http://service.internal/",
        "http://printer.local/",
    ],
)
def test_normalize_blocks_ssrf_targets(config: Config, url: str) -> None:
    with pytest.raises(UnsafeTargetError):
        normalize_url(url, config)


def test_normalize_rejects_credentials(config: Config) -> None:
    with pytest.raises(UnsafeTargetError):
        normalize_url("https://user:password@example.com/", config)


def test_normalize_rejects_non_http_scheme(config: Config) -> None:
    with pytest.raises(InvalidURL):
        normalize_url("file:///etc/passwd", config)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:8443/",
        "http://example.com:443/",
        "https://example.com:80/",
    ],
)
def test_normalize_blocks_nonstandard_or_mismatched_port(
    config: Config, url: str
) -> None:
    with pytest.raises(UnsafeTargetError):
        normalize_url(url, config)


def test_normalize_adds_https(config: Config) -> None:
    assert normalize_url("example.com/path", config) == "https://example.com/path"


@pytest.mark.parametrize(
    ("raw_url", "expected"),
    [
        ("example.com", "https://example.com/"),
        ("HTTPS://Example.COM:443/a#fragment", "https://example.com/a"),
        ("http://Example.COM:80", "http://example.com/"),
        ("https://8.8.8.8", "https://8.8.8.8/"),
        ("https://пример.рф/путь", "https://xn--e1afmkfd.xn--p1ai/путь"),
    ],
)
def test_normalize_url_edge_cases(
    config: Config,
    raw_url: str,
    expected: str,
) -> None:
    assert normalize_url(raw_url, config) == expected


@pytest.mark.parametrize(
    "encoded_value",
    ["%00", "%01", "%09", "%0a", "%1f", "%7f", "%250d"],
)
def test_normalize_rejects_all_encoded_control_ranges(
    config: Config,
    encoded_value: str,
) -> None:
    with pytest.raises(InvalidURL):
        normalize_url(f"https://example.com/{encoded_value}evil", config)


@pytest.mark.parametrize("encoded_value", ["%5c", "%E2%80%AE"])
def test_normalize_rejects_encoded_hidden_or_path_confusion_characters(
    config: Config,
    encoded_value: str,
) -> None:
    with pytest.raises(InvalidURL):
        normalize_url(f"https://example.com/{encoded_value}evil", config)


def test_normalize_rejects_malformed_percent_encoding(config: Config) -> None:
    with pytest.raises(InvalidURL):
        normalize_url("https://example.com/%0G", config)


def test_redact_url_hides_query_and_credentials() -> None:
    assert redact_url("https://user:pass@example.com/reset?token=secret") == (
        "https://example.com/reset?<скрыто>"
    )


def test_http_is_suspicious(config: Config) -> None:
    url = normalize_url("http://example.com", config)
    assert any(item.code == "plain_http" for item in heuristic_findings(url))


def test_brand_in_subdomain_is_dangerous(config: Config) -> None:
    url = normalize_url("https://paypal.com.attacker.net/login", config)
    findings = heuristic_findings(url)
    assert any(
        item.code == "brand_in_subdomain" and item.severity is Severity.DANGER
        for item in findings
    )


def test_typosquatting_is_detected(config: Config) -> None:
    url = normalize_url("https://paypa1.com/login", config)
    assert any(item.code == "possible_typosquat" for item in heuristic_findings(url))


def test_long_domain_is_detected(config: Config) -> None:
    url = normalize_url(f"https://{'a' * 60}.com/", config)
    assert any(item.code == "long_host" for item in heuristic_findings(url))


def test_registrable_domain_falls_back_when_tldextract_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_extract(_host: str):
        raise OSError("cache unavailable")

    monkeypatch.setattr("url_guard_bot.url_checker.EXTRACT_DOMAIN", fail_extract)
    assert registrable_domain("login.example.com") == "example.com"
    assert isinstance(heuristic_findings("https://login.example.com/"), list)


def test_verdict_priority() -> None:
    result = AnalysisResult("x", "x")
    assert result.verdict is Verdict.LOW_RISK
    result.findings.append(Finding("warning", Severity.WARNING, "warning"))
    assert result.verdict is Verdict.SUSPICIOUS
    result.findings.append(Finding("error", Severity.ERROR, "error"))
    assert result.verdict is Verdict.UNKNOWN
    result.findings.append(Finding("danger", Severity.DANGER, "danger"))
    assert result.verdict is Verdict.DANGEROUS


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "ff02::1"],
)
def test_ensure_global_ip_blocks_special_ranges(address: str) -> None:
    with pytest.raises(UnsafeTargetError):
        ensure_global_ip(address)


class FakeResolver(AbstractResolver):
    def __init__(self, address: str) -> None:
        self.address = address
        self.closed = False

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_UNSPEC):
        return [
            {
                "hostname": host,
                "host": self.address,
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": 0,
            }
        ]

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_resolver_blocks_dns_to_loopback() -> None:
    resolver = PublicOnlyResolver(FakeResolver("127.0.0.1"))
    with pytest.raises(UnsafeTargetError):
        await resolver.resolve("attacker.example.org", 80)
    await resolver.close()


@pytest.mark.asyncio
async def test_resolver_allows_public_address() -> None:
    resolver = PublicOnlyResolver(FakeResolver("93.184.216.34"))
    records = await resolver.resolve("example.org", 443)
    assert records[0]["host"] == "93.184.216.34"
    await resolver.close()


class MultiAddressResolver(AbstractResolver):
    def __init__(self, addresses: list[str]) -> None:
        self.addresses = addresses
        self.closed = False

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_UNSPEC):
        return [
            {
                "hostname": host,
                "host": address,
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": 0,
            }
            for address in self.addresses
        ]

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_resolver_rejects_answer_set_with_one_private_address() -> None:
    delegate = MultiAddressResolver(["93.184.216.34", "10.0.0.5"])
    resolver = PublicOnlyResolver(delegate)
    with pytest.raises(UnsafeTargetError):
        await resolver.resolve("example.org", 443)
    await resolver.close()
    assert delegate.closed is True


class EmptyResolver(AbstractResolver):
    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_UNSPEC):
        return []

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_resolver_rejects_empty_dns_answer() -> None:
    resolver = PublicOnlyResolver(EmptyResolver())
    with pytest.raises(OSError, match="DNS returned no addresses"):
        await resolver.resolve("example.org", 443)


@pytest.mark.asyncio
async def test_analyzer_blocks_dns_rebinding_before_connection(config: Config) -> None:
    # The fake DNS answer points a public-looking host at loopback. The analyzer
    # must return a dangerous SSRF finding without opening a TCP connection.
    resolver = PublicOnlyResolver(FakeResolver("127.0.0.1"))
    from url_guard_bot.url_checker import URLAnalyzer

    async with URLAnalyzer(config, resolver=resolver) as analyzer:
        result = await analyzer.analyze("http://attacker.example.org/")

    assert result.verdict is Verdict.DANGEROUS
    assert any(item.code == "dns_ssrf_blocked" for item in result.findings)


def test_normalize_rejects_unicode_format_char(config: Config) -> None:
    with pytest.raises(InvalidURL):
        normalize_url("https://example.com/\u202eevil", config)


def test_normalize_rejects_encoded_crlf(config: Config) -> None:
    with pytest.raises(InvalidURL):
        normalize_url("https://example.com/%0d%0aheader", config)


def test_sensitive_query_detection() -> None:
    assert has_sensitive_query("https://example.com/?token=secret") is True
    assert has_sensitive_query("https://example.com/?page=2") is False


class ScriptedAnalyzer:
    """Minimal URLAnalyzer-compatible harness for redirect policy tests."""

    def __init__(self, config: Config, responses: dict[str, object]) -> None:
        from url_guard_bot.url_checker import URLAnalyzer

        class Impl(URLAnalyzer):
            async def _probe(inner_self, url: str):
                inner_self.called.append(url)
                response = responses[url]
                if isinstance(response, BaseException):
                    raise response
                return response

        self.impl = Impl(config)
        self.impl.called = []


@pytest.mark.asyncio
async def test_redirect_to_loopback_is_blocked_before_second_request(
    config: Config,
) -> None:
    from url_guard_bot.url_checker import ProbeResponse

    start = "https://example.com/start"
    harness = ScriptedAnalyzer(
        config,
        {
            start: ProbeResponse(
                status=302,
                headers={"Location": "http://127.0.0.1/admin"},
                method="HEAD",
            )
        },
    )
    result = await harness.impl.analyze(start)
    assert harness.impl.called == [start]
    assert result.verdict is Verdict.DANGEROUS
    assert any(item.code == "unsafe_redirect" for item in result.findings)


@pytest.mark.asyncio
async def test_https_downgrade_is_not_followed(config: Config) -> None:
    from url_guard_bot.url_checker import ProbeResponse

    start = "https://example.com/start"
    harness = ScriptedAnalyzer(
        config,
        {
            start: ProbeResponse(
                status=302,
                headers={"Location": "http://example.com/plain"},
                method="HEAD",
            )
        },
    )
    result = await harness.impl.analyze(start)
    assert harness.impl.called == [start]
    assert any(item.code == "https_downgrade" for item in result.findings)


@pytest.mark.asyncio
async def test_sensitive_cross_domain_redirect_is_not_followed(config: Config) -> None:
    from url_guard_bot.url_checker import ProbeResponse

    start = "https://example.com/reset?token=secret"
    harness = ScriptedAnalyzer(
        config,
        {
            start: ProbeResponse(
                status=302,
                headers={"Location": "https://example.net/continue"},
                method="HEAD",
            )
        },
    )
    result = await harness.impl.analyze(start)
    assert harness.impl.called == [start]
    assert any(
        item.code == "sensitive_cross_domain_redirect" for item in result.findings
    )


@pytest.mark.asyncio
async def test_redirect_loop_is_detected_without_repeating_request(
    config: Config,
) -> None:
    from url_guard_bot.url_checker import ProbeResponse

    start = "https://example.com/start"
    second = "https://example.com/second"
    harness = ScriptedAnalyzer(
        config,
        {
            start: ProbeResponse(
                status=302, headers={"Location": second}, method="HEAD"
            ),
            second: ProbeResponse(
                status=302, headers={"Location": start}, method="HEAD"
            ),
        },
    )
    result = await harness.impl.analyze(start)
    assert harness.impl.called == [start, second]
    assert any(item.code == "redirect_loop" for item in result.findings)


@pytest.mark.asyncio
async def test_cross_domain_redirect_is_followed_and_warned(config: Config) -> None:
    start = "https://example.com/start"
    target = "https://example.net/final"
    harness = ScriptedAnalyzer(
        config,
        {
            start: ProbeResponse(
                status=302,
                headers={"Location": target},
                method="HEAD",
            ),
            target: ProbeResponse(
                status=200,
                headers={"Content-Type": "text/plain"},
                method="HEAD",
            ),
        },
    )
    result = await harness.impl.analyze(start)
    assert harness.impl.called == [start, target]
    assert result.final_url == target
    assert any(item.code == "cross_domain_redirect" for item in result.findings)


@pytest.mark.asyncio
async def test_too_many_redirects_is_detected(config: Config) -> None:
    limited = Config(
        bot_token=config.bot_token,
        max_redirects=1,
    )
    start = "https://example.com/start"
    second = "https://example.com/second"
    third = "https://example.com/third"
    harness = ScriptedAnalyzer(
        limited,
        {
            start: ProbeResponse(
                status=302,
                headers={"Location": second},
                method="HEAD",
            ),
            second: ProbeResponse(
                status=302,
                headers={"Location": third},
                method="HEAD",
            ),
        },
    )
    result = await harness.impl.analyze(start)
    assert harness.impl.called == [start, second]
    assert any(item.code == "too_many_redirects" for item in result.findings)


@pytest.mark.parametrize(
    ("html", "expected"),
    [
        (
            b'<html><head><meta http-equiv="refresh" content="0; url=/next"></head>',
            "/next",
        ),
        (
            b"<META CONTENT='5;URL=https://example.net/' HTTP-EQUIV='REFRESH'>",
            "https://example.net/",
        ),
        (b'<meta http-equiv="refresh" content="broken">', None),
    ],
)
def test_extract_meta_refresh_target(html: bytes, expected: str | None) -> None:
    assert extract_meta_refresh_target(html, "text/html; charset=utf-8") == expected


def test_meta_refresh_is_not_parsed_for_non_html() -> None:
    html = b'<meta http-equiv="refresh" content="0;url=https://example.net/">'
    assert extract_meta_refresh_target(html, "text/plain") is None


@pytest.mark.asyncio
async def test_meta_refresh_is_followed_with_same_safety_policy(config: Config) -> None:
    start = "https://example.com/start"
    target = "https://example.com/next"
    html = b'<meta http-equiv="refresh" content="0; url=/next">'
    harness = ScriptedAnalyzer(
        config,
        {
            start: ProbeResponse(
                status=200,
                headers={"Content-Type": "text/html"},
                method="GET",
                body_prefix=html,
            ),
            target: ProbeResponse(
                status=200,
                headers={"Content-Type": "text/plain"},
                method="HEAD",
            ),
        },
    )
    result = await harness.impl.analyze(start)
    assert harness.impl.called == [start, target]
    assert result.redirects[0].kind == "meta"
    assert any(item.code == "meta_refresh_redirect" for item in result.findings)


@pytest.mark.asyncio
async def test_meta_refresh_to_loopback_is_blocked_before_request(
    config: Config,
) -> None:
    start = "https://example.com/start"
    html = b'<meta http-equiv="refresh" content="0; url=http://127.0.0.1/admin">'
    harness = ScriptedAnalyzer(
        config,
        {
            start: ProbeResponse(
                status=200,
                headers={"Content-Type": "text/html"},
                method="GET",
                body_prefix=html,
            )
        },
    )
    result = await harness.impl.analyze(start)
    assert harness.impl.called == [start]
    assert any(item.code == "unsafe_redirect" for item in result.findings)


@pytest.mark.asyncio
async def test_meta_refresh_https_downgrade_is_blocked(config: Config) -> None:
    start = "https://example.com/start"
    html = b'<meta http-equiv="refresh" content="0; url=http://example.com/plain">'
    harness = ScriptedAnalyzer(
        config,
        {
            start: ProbeResponse(
                status=200,
                headers={"Content-Type": "text/html"},
                method="GET",
                body_prefix=html,
            )
        },
    )
    result = await harness.impl.analyze(start)
    assert harness.impl.called == [start]
    assert any(item.code == "https_downgrade" for item in result.findings)


@pytest.mark.asyncio
async def test_meta_refresh_can_be_disabled(config: Config) -> None:
    disabled = Config(bot_token=config.bot_token, check_meta_refresh=False)
    start = "https://example.com/start"
    html = b'<meta http-equiv="refresh" content="0; url=/next">'
    harness = ScriptedAnalyzer(
        disabled,
        {
            start: ProbeResponse(
                status=200,
                headers={"Content-Type": "text/html"},
                method="GET",
                body_prefix=html,
            )
        },
    )
    result = await harness.impl.analyze(start)
    assert harness.impl.called == [start]
    assert result.final_url == start
    assert not any(item.code == "meta_refresh_redirect" for item in result.findings)


@pytest.mark.asyncio
async def test_analyze_converts_unexpected_probe_exception_to_finding(
    config: Config,
) -> None:
    start = "https://example.com/start"
    harness = ScriptedAnalyzer(config, {start: RuntimeError("unexpected")})
    result = await harness.impl.analyze(start)
    assert any(item.code == "internal_error" for item in result.findings)


@pytest.mark.asyncio
async def test_analyze_handles_unexpected_heuristic_exception(
    config: Config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_heuristics(_url: str):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(
        "url_guard_bot.url_checker.heuristic_findings",
        fail_heuristics,
    )
    async with URLAnalyzer(config) as analyzer:
        result = await analyzer.analyze("https://example.com/")
    assert any(item.code == "internal_error" for item in result.findings)


@pytest.mark.asyncio
async def test_meta_refresh_sensitive_cross_domain_is_blocked(config: Config) -> None:
    start = "https://example.com/reset?token=secret"
    html = b'<meta http-equiv="refresh" content="0; url=https://example.net/continue">'
    harness = ScriptedAnalyzer(
        config,
        {
            start: ProbeResponse(
                status=200,
                headers={"Content-Type": "text/html"},
                method="GET",
                body_prefix=html,
            )
        },
    )
    result = await harness.impl.analyze(start)
    assert harness.impl.called == [start]
    assert any(
        item.code == "sensitive_cross_domain_redirect" for item in result.findings
    )


@pytest.mark.asyncio
async def test_meta_refresh_loop_is_detected(config: Config) -> None:
    start = "https://example.com/start"
    second = "https://example.com/second"
    harness = ScriptedAnalyzer(
        config,
        {
            start: ProbeResponse(
                status=200,
                headers={"Content-Type": "text/html"},
                method="GET",
                body_prefix=(b'<meta http-equiv="refresh" content="0; url=/second">'),
            ),
            second: ProbeResponse(
                status=200,
                headers={"Content-Type": "text/html"},
                method="GET",
                body_prefix=(b'<meta http-equiv="refresh" content="0; url=/start">'),
            ),
        },
    )
    result = await harness.impl.analyze(start)
    assert harness.impl.called == [start, second]
    assert any(item.code == "redirect_loop" for item in result.findings)
