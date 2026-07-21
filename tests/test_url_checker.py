from __future__ import annotations

import socket

import pytest
from aiohttp.abc import AbstractResolver

from url_guard_bot.config import Config
from url_guard_bot.models import AnalysisResult, Finding, Severity, Verdict
from url_guard_bot.url_checker import (
    InvalidURL,
    ProbeResponse,
    PublicOnlyResolver,UnsafeTargetError,
    URLAnalyzer,
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
@@ -348,54 +348,52 @@ async def test_https_downgrade_is_not_followed(config: Config) -> None:
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
    result = await harness.impl.analyze(start) assert harness.impl.called == []
    assert any(item.code == "sensitive_query_not_requested" for item in result.findings)


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

@@ -589,54 +587,52 @@ async def test_analyze_handles_unexpected_heuristic_exception(
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
    result = await harness.impl.analyze(start)assert harness.impl.called == []
    assert any(item.code == "sensitive_query_not_requested" for item in result.findings)


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
