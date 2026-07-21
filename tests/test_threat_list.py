from __future__ import annotations

from pathlib import Path

import pytest

from url_guard_bot.config import Config
from url_guard_bot.threat_list import ScamLinkDatabase
from url_guard_bot.url_checker import ensure_safe_hostname, normalize_url


def make_db(path: Path, config: Config, max_bytes: int = 1_048_576) -> ScamLinkDatabase:
    return ScamLinkDatabase(
        path,
        normalize_url=lambda value: normalize_url(value, config),
        normalize_host=ensure_safe_hostname,
        max_bytes=max_bytes,
    )


@pytest.mark.asyncio
async def test_missing_file_is_empty(tmp_path: Path, config: Config) -> None:
    db = make_db(tmp_path / "missing.txt", config)
    assert await db.match("https://example.com/") is None


@pytest.mark.asyncio
async def test_domain_and_subdomain_match(tmp_path: Path, config: Config) -> None:
    path = tmp_path / "list.txt"
    path.write_text("bad-domain.com\n")
    db = make_db(path, config)
    assert (await db.match("https://bad-domain.com/")) is not None
    assert (await db.match("https://login.bad-domain.com/a")) is not None


@pytest.mark.asyncio
async def test_exact_and_queryless_url_match(tmp_path: Path, config: Config) -> None:
    path = tmp_path / "list.txt"
    path.write_text("https://example.com/bad\nurl:https://example.com/exact?id=1\n")
    db = make_db(path, config)
    assert (await db.match("https://example.com/bad?x=2")) is not None
    assert (await db.match("https://example.com/exact?id=1")) is not None
    assert await db.match("https://example.com/exact?id=2") is None


@pytest.mark.asyncio
async def test_prefix_match(tmp_path: Path, config: Config) -> None:
    path = tmp_path / "list.txt"
    path.write_text("prefix:https://example.com/malware/*\n")
    db = make_db(path, config)
    assert (await db.match("https://example.com/malware/file.exe")) is not None


@pytest.mark.asyncio
async def test_comments_duplicates_and_invalid_lines(
    tmp_path: Path, config: Config
) -> None:
    path = tmp_path / "list.txt"
    path.write_text("# c\n; c\nbad-domain.com\nbad-domain.com\ndomain:bad/path\n")
    db = make_db(path, config)
    assert await db.force_reload() == 1


@pytest.mark.asyncio
async def test_hot_reload(tmp_path: Path, config: Config) -> None:
    path = tmp_path / "list.txt"
    path.write_text("one-domain.com\n")
    db = make_db(path, config)
    assert (await db.match("https://one-domain.com/")) is not None
    path.write_text("two-domain.com\n")
    assert (await db.match("https://two-domain.com/")) is not None
    assert await db.match("https://one-domain.com/") is None


@pytest.mark.asyncio
async def test_oversized_file_rejected(tmp_path: Path, config: Config) -> None:
    path = tmp_path / "list.txt"
    path.write_text("a" * 100)
    db = make_db(path, config, max_bytes=10)
    with pytest.raises(ValueError):
        await db.force_reload()
