from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def _positive_int(
    name: str,
    default: int,
    *,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise RuntimeError(f"{name} must be <= {maximum}")
    return value


def _positive_float(name: str, default: float, *, minimum: float = 0.1) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a number") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}")
    return value


def _boolean(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be a boolean")


def _ports(name: str, default: frozenset[int]) -> frozenset[int]:
    raw = os.getenv(name)
    if not raw:
        return default

    result: set[int] = set()
    for item in raw.split(","):
        try:
            port = int(item.strip())
        except ValueError as exc:
            raise RuntimeError(f"{name} contains a non-integer port") from exc
        if not 1 <= port <= 65535:
            raise RuntimeError(f"{name} contains an invalid port: {port}")
        result.add(port)
    return frozenset(result)


@dataclass(frozen=True, slots=True)
class Config:
    bot_token: str
    max_url_length: int = 2048
    max_redirects: int = 5
    analysis_timeout: float = 20.0
    request_timeout: float = 8.0
    connect_timeout: float = 4.0
    read_timeout: float = 5.0
    max_concurrent_analyses: int = 12
    update_concurrency_limit: int = 40
    rate_limit_requests: int = 5
    rate_limit_window_seconds: int = 60
    rate_limit_max_users: int = 10_000
    check_meta_refresh: bool = True
    block_sensitive_query_requests: bool = True
    meta_refresh_max_bytes: int = 2048
    allowed_http_ports: frozenset[int] = frozenset({80})
    allowed_https_ports: frozenset[int] = frozenset({443})
    scam_links_file: Path = Path("scam_links.txt")
    scam_links_max_bytes: int = 1_048_576

    @classmethod
    def from_env(cls) -> Config:
        load_dotenv()
        token = (os.getenv("BOT_TOKEN") or "").strip()
        if not token:
            raise RuntimeError(
                "BOT_TOKEN is not configured. Copy .env.example to .env and add the token."
            )

        return cls(
            bot_token=token,
            max_url_length=_positive_int(
                "MAX_URL_LENGTH", 2048, minimum=128, maximum=16384
            ),
            max_redirects=_positive_int("MAX_REDIRECTS", 5, maximum=20),
            analysis_timeout=_positive_float("ANALYSIS_TIMEOUT", 20.0),
            request_timeout=_positive_float("REQUEST_TIMEOUT", 8.0),
            connect_timeout=_positive_float("CONNECT_TIMEOUT", 4.0),
            read_timeout=_positive_float("READ_TIMEOUT", 5.0),
            max_concurrent_analyses=_positive_int(
                "MAX_CONCURRENT_ANALYSES", 12, maximum=256
            ),
            update_concurrency_limit=_positive_int(
                "UPDATE_CONCURRENCY_LIMIT", 40, maximum=1024
            ),
            rate_limit_requests=_positive_int("RATE_LIMIT_REQUESTS", 5, maximum=1000),
            rate_limit_window_seconds=_positive_int(
                "RATE_LIMIT_WINDOW_SECONDS", 60, maximum=86400
            ),
            rate_limit_max_users=_positive_int(
                "RATE_LIMIT_MAX_USERS", 10_000, maximum=1_000_000
            ),
            check_meta_refresh=_boolean("CHECK_META_REFRESH", True),
            block_sensitive_query_requests=_boolean(
                "BLOCK_SENSITIVE_QUERY_REQUESTS", True
            ),
            meta_refresh_max_bytes=_positive_int(
                "META_REFRESH_MAX_BYTES", 2048, minimum=512
            ),
            allowed_http_ports=_ports("ALLOWED_HTTP_PORTS", frozenset({80})),
            allowed_https_ports=_ports("ALLOWED_HTTPS_PORTS", frozenset({443})),
            scam_links_file=Path(
                os.getenv("SCAM_LINKS_FILE", "scam_links.txt")
            ).expanduser(),
            scam_links_max_bytes=_positive_int(
                "SCAM_LINKS_MAX_BYTES", 1_048_576, minimum=1024
            ),
        )
