from __future__ import annotations

from pathlib import Path

import pytest

from url_guard_bot.config import Config


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
