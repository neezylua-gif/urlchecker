from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from typing import Any

import pytest

from url_guard_bot.config import Config


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "asyncio: run async test functions")


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem: pytest.Function) -> bool | None:
    test_function = pyfuncitem.obj
    if not inspect.iscoroutinefunction(test_function):
        return None

    fixture_args: dict[str, Any] = {
        name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames
    }
    asyncio.run(test_function(**fixture_args))
    return True


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        bot_token="test-token",
        scam_links_file=tmp_path / "scam_links.txt",
        analysis_timeout=2.0,
        request_timeout=1.0,
        connect_timeout=0.5,
        read_timeout=0.5,
    )
