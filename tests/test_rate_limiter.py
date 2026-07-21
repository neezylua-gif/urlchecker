from __future__ import annotations

import pytest

from url_guard_bot import rate_limiter as module
from url_guard_bot.rate_limiter import UserRateLimiter


@pytest.mark.asyncio
async def test_allows_until_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 100.0
    monkeypatch.setattr(module.time, "monotonic", lambda: now)
    limiter = UserRateLimiter(2, 60)
    assert await limiter.check(1) == (True, 0)
    assert await limiter.check(1) == (True, 0)
    allowed, retry = await limiter.check(1)
    assert allowed is False
    assert retry == 61


@pytest.mark.asyncio
async def test_window_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    limiter = UserRateLimiter(1, 10)
    assert (await limiter.check(1))[0] is True
    clock[0] = 111.0
    assert (await limiter.check(1))[0] is True


@pytest.mark.asyncio
async def test_keys_are_independent() -> None:
    limiter = UserRateLimiter(1, 60)
    assert (await limiter.check(1))[0] is True
    assert (await limiter.check(2))[0] is True


@pytest.mark.asyncio
async def test_cardinality_limit_fails_closed() -> None:
    limiter = UserRateLimiter(1, 60, max_keys=2)
    assert (await limiter.check(1))[0] is True
    assert (await limiter.check(2))[0] is True
    allowed, retry = await limiter.check(3)
    assert allowed is False
    assert retry == 60


@pytest.mark.parametrize("args", [(0, 1, 1), (1, 0, 1), (1, 1, 0)])
def test_invalid_constructor(args: tuple[int, int, int]) -> None:
    with pytest.raises(ValueError):
        UserRateLimiter(*args)
