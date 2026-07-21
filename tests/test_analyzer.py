from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from url_guard_bot.models import Severity
from url_guard_bot.url_checker import (
    ProbeResponse,
    PublicOnlyResolver,
    UnsafeTargetError,
    URLAnalyzer,
)


class EmptyThreatList:
    async def match(self, normalized_url: str) -> None:
        return None


class MatchThreatList:
    async def match(self, normalized_url: str) -> object:
        return object()


class FakeResolver:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self.records = records
        self.closed = False

    async def resolve(self, host: str, port: int, family: int) -> list[dict[str, Any]]:
        return self.records

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_sensitive_query_does_not_probe(config) -> None:
    analyzer = URLAnalyzer(config, threat_list=EmptyThreatList())

    async def forbidden_probe(url: str) -> ProbeResponse:
        raise AssertionError("network probe must not run")

    analyzer._probe = forbidden_probe  # type: ignore[method-assign]
    result = await analyzer.analyze("https://example.com/?token=secret")
    assert "sensitive_query_not_requested" in {x.code for x in result.findings}
    assert result.status_code is None


@pytest.mark.asyncio
async def test_blacklist_does_not_probe(config) -> None:
    analyzer = URLAnalyzer(config, threat_list=MatchThreatList())

    async def forbidden_probe(url: str) -> ProbeResponse:
        raise AssertionError("network probe must not run")

    analyzer._probe = forbidden_probe  # type: ignore[method-assign]
    result = await analyzer.analyze("https://example.com/")
    assert any(x.code == "local_scam_list" for x in result.findings)


@pytest.mark.asyncio
async def test_successful_https_probe(config) -> None:
    analyzer = URLAnalyzer(config, threat_list=EmptyThreatList())

    async def probe(url: str) -> ProbeResponse:
        return ProbeResponse(200, {"Content-Type": "text/html"}, "HEAD")

    analyzer._probe = probe  # type: ignore[method-assign]
    result = await analyzer.analyze("https://example.com/")
    assert result.status_code == 200
    assert result.final_url == "https://example.com/"
    assert any(x.code == "tls_verified" for x in result.findings)


@pytest.mark.asyncio
async def test_redirect_loop_blocked(config) -> None:
    analyzer = URLAnalyzer(config, threat_list=EmptyThreatList())

    async def probe(url: str) -> ProbeResponse:
        return ProbeResponse(302, {"Location": "/"}, "HEAD")

    analyzer._probe = probe  # type: ignore[method-assign]
    result = await analyzer.analyze("https://example.com/")
    assert any(x.code == "redirect_loop" for x in result.findings)


@pytest.mark.asyncio
async def test_https_downgrade_blocked(config) -> None:
    analyzer = URLAnalyzer(config, threat_list=EmptyThreatList())

    async def probe(url: str) -> ProbeResponse:
        return ProbeResponse(302, {"Location": "http://example.com/"}, "HEAD")

    analyzer._probe = probe  # type: ignore[method-assign]
    result = await analyzer.analyze("https://example.com/")
    assert any(x.code == "https_downgrade" for x in result.findings)


@pytest.mark.asyncio
async def test_redirect_to_localhost_blocked(config) -> None:
    analyzer = URLAnalyzer(config, threat_list=EmptyThreatList())

    async def probe(url: str) -> ProbeResponse:
        return ProbeResponse(302, {"Location": "http://127.0.0.1/"}, "HEAD")

    analyzer._probe = probe  # type: ignore[method-assign]
    result = await analyzer.analyze("http://example.com/")
    assert any(x.code == "unsafe_redirect" for x in result.findings)


@pytest.mark.asyncio
async def test_meta_refresh_redirect(config) -> None:
    analyzer = URLAnalyzer(config, threat_list=EmptyThreatList())
    calls = []

    async def probe(url: str) -> ProbeResponse:
        calls.append(url)
        if len(calls) == 1:
            return ProbeResponse(
                200,
                {"Content-Type": "text/html"},
                "GET",
                b'<meta http-equiv="refresh" content="0;url=/next">',
            )
        return ProbeResponse(200, {"Content-Type": "text/html"}, "HEAD")

    analyzer._probe = probe  # type: ignore[method-assign]
    result = await analyzer.analyze("https://example.com/")
    assert result.final_url == "https://example.com/next"
    assert any(x.code == "meta_refresh_redirect" for x in result.findings)


@pytest.mark.asyncio
async def test_executable_mime_is_danger(config) -> None:
    analyzer = URLAnalyzer(config, threat_list=EmptyThreatList())

    async def probe(url: str) -> ProbeResponse:
        return ProbeResponse(200, {"Content-Type": "application/x-msdownload"}, "HEAD")

    analyzer._probe = probe  # type: ignore[method-assign]
    result = await analyzer.analyze("https://example.com/file")
    finding = next(x for x in result.findings if x.code == "executable_download")
    assert finding.severity is Severity.DANGER


@pytest.mark.asyncio
async def test_public_only_resolver_accepts_all_public() -> None:
    delegate = FakeResolver(
        [
            {"host": "8.8.8.8", "port": 443},
            {"host": "1.1.1.1", "port": 443},
        ]
    )
    resolver = PublicOnlyResolver(delegate)  # type: ignore[arg-type]
    records = await resolver.resolve("example.com", 443)
    assert len(records) == 2
    await resolver.close()
    assert delegate.closed is True


@pytest.mark.asyncio
async def test_public_only_resolver_rejects_mixed_dns() -> None:
    delegate = FakeResolver(
        [
            {"host": "8.8.8.8", "port": 443},
            {"host": "127.0.0.1", "port": 443},
        ]
    )
    resolver = PublicOnlyResolver(delegate)  # type: ignore[arg-type]
    with pytest.raises(UnsafeTargetError):
        await resolver.resolve("example.com", 443)


@pytest.mark.asyncio
async def test_sensitive_query_can_be_enabled(config) -> None:
    relaxed = replace(config, block_sensitive_query_requests=False)
    analyzer = URLAnalyzer(relaxed, threat_list=EmptyThreatList())

    async def probe(url: str) -> ProbeResponse:
        return ProbeResponse(200, {"Content-Type": "text/plain"}, "HEAD")

    analyzer._probe = probe  # type: ignore[method-assign]
    result = await analyzer.analyze("https://example.com/?token=secret")
    assert result.status_code == 200
