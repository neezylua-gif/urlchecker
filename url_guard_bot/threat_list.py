from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ThreatListMatch:
    rule_type: str
    source: str


@dataclass(frozen=True, slots=True)
class _Snapshot:
    domains: frozenset[str] = frozenset()
    exact_urls: frozenset[str] = frozenset()
    queryless_urls: frozenset[str] = frozenset()
    prefixes: tuple[str, ...] = ()
    loaded_entries: int = 0


class ScamLinkDatabase:
    """Hot-reloadable local list of known malicious domains and URLs.

    Supported line formats:
      - example.com                     (domain and all subdomains)
      - domain:example.com              (same, explicit form)
      - https://example.com/login       (exact URL; query ignored if omitted)
      - url:https://example.com/login   (same, explicit form)
      - prefix:https://example.com/bad/ (all URLs beginning with the prefix)

    Empty lines and lines beginning with ``#`` or ``;`` are ignored.
    """

    def __init__(
        self,
        path: Path,
        *,
        normalize_url: Callable[[str], str],
        normalize_host: Callable[[str], str],
        max_bytes: int = 1_048_576,
    ) -> None:
        self._path = path
        self._normalize_url = normalize_url
        self._normalize_host = normalize_host
        self._max_bytes = max_bytes
        self._snapshot = _Snapshot()
        self._signature: tuple[int, int, str] | None = None
        self._failed_signature: tuple[int, int, str] | None = None
        self._retry_after = 0.0
        self._lock = asyncio.Lock()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def loaded_entries(self) -> int:
        return self._snapshot.loaded_entries

    async def match(self, normalized_url: str) -> ThreatListMatch | None:
        await self._refresh_if_needed()
        snapshot = self._snapshot

        parsed = urlsplit(normalized_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if host in snapshot.domains:
            return ThreatListMatch("domain", host)
        labels = host.split(".")
        for index in range(1, len(labels)):
            candidate = ".".join(labels[index:])
            if candidate in snapshot.domains:
                return ThreatListMatch("domain", candidate)

        if normalized_url in snapshot.exact_urls:
            return ThreatListMatch("url", normalized_url)

        queryless = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        if queryless in snapshot.queryless_urls:
            return ThreatListMatch("url", queryless)

        for prefix in snapshot.prefixes:
            if normalized_url.startswith(prefix):
                return ThreatListMatch("prefix", prefix)

        return None

    async def force_reload(self) -> int:
        """Reload now and return the number of valid entries."""
        async with self._lock:
            signature = await asyncio.to_thread(self._file_signature)
            snapshot = await asyncio.to_thread(self._load_snapshot)
            self._snapshot = snapshot
            self._signature = signature
            self._failed_signature = None
            self._retry_after = 0.0
            return snapshot.loaded_entries

    async def _refresh_if_needed(self) -> None:
        signature = await asyncio.to_thread(self._file_signature)
        if signature == self._signature:
            return

        now = time.monotonic()
        if signature == self._failed_signature and now < self._retry_after:
            return

        async with self._lock:
            signature = await asyncio.to_thread(self._file_signature)
            if signature == self._signature:
                return
            now = time.monotonic()
            if signature == self._failed_signature and now < self._retry_after:
                return

            try:
                snapshot = await asyncio.to_thread(self._load_snapshot)
            except Exception:
                # Keep the last known-good snapshot. A damaged local list must
                # not crash URL analysis or erase previously loaded rules.
                self._failed_signature = signature
                self._retry_after = time.monotonic() + 5.0
                logger.exception("Failed to reload scam link database: %s", self._path)
                return

            self._snapshot = snapshot
            self._signature = signature
            self._failed_signature = None
            self._retry_after = 0.0
            logger.info(
                "Loaded %d scam-link rules from %s",
                snapshot.loaded_entries,
                self._path,
            )

    def _file_signature(self) -> tuple[int, int, str] | None:
        try:
            stat = self._path.stat()
        except FileNotFoundError:
            return None

        if stat.st_size > self._max_bytes:
            return stat.st_mtime_ns, stat.st_size, "<oversized>"

        digest = hashlib.blake2b(digest_size=16)
        with self._path.open("rb") as file:
            for chunk in iter(lambda: file.read(65536), b""):
                digest.update(chunk)
        return stat.st_mtime_ns, stat.st_size, digest.hexdigest()

    def _load_snapshot(self) -> _Snapshot:
        try:
            stat = self._path.stat()
        except FileNotFoundError:
            return _Snapshot()

        if stat.st_size > self._max_bytes:
            raise ValueError(
                f"Scam-link database exceeds the {self._max_bytes}-byte limit"
            )

        text = self._path.read_text(encoding="utf-8-sig", errors="strict")
        domains: set[str] = set()
        exact_urls: set[str] = set()
        queryless_urls: set[str] = set()
        prefixes: set[str] = set()
        seen: set[tuple[str, str]] = set()

        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue

            try:
                rule_type, value = self._parse_line(line)
            except Exception as exc:
                logger.warning(
                    "Skipped invalid scam-list entry at %s:%d: %s",
                    self._path,
                    line_number,
                    exc,
                )
                continue

            key = (rule_type, value)
            if key in seen:
                continue
            seen.add(key)
            if rule_type == "domain":
                domains.add(value)
            elif rule_type == "url":
                parsed = urlsplit(value)
                if parsed.query:
                    exact_urls.add(value)
                else:
                    queryless_urls.add(value)
            else:
                prefixes.add(value)

        return _Snapshot(
            domains=frozenset(domains),
            exact_urls=frozenset(exact_urls),
            queryless_urls=frozenset(queryless_urls),
            prefixes=tuple(sorted(prefixes, key=len, reverse=True)),
            loaded_entries=len(seen),
        )

    def _parse_line(self, line: str) -> tuple[str, str]:
        lowered = line.casefold()
        if lowered.startswith("domain:"):
            return "domain", self._parse_domain(line[7:])
        if lowered.startswith("url:"):
            return "url", self._normalize_url(line[4:].strip())
        if lowered.startswith("prefix:"):
            value = line[7:].strip()
            if value.endswith("*"):
                value = value[:-1]
            if not value:
                raise ValueError("empty prefix")
            return "prefix", self._normalize_url(value)

        if line.startswith("*."):
            return "domain", self._parse_domain(line[2:])
        if "://" in line or "/" in line:
            return "url", self._normalize_url(line)
        return "domain", self._parse_domain(line)

    def _parse_domain(self, value: str) -> str:
        candidate = value.strip().rstrip(".")
        if not candidate:
            raise ValueError("empty domain")
        if any(char in candidate for char in "/?#@") or "://" in candidate:
            raise ValueError("domain rule contains URL components")
        return self._normalize_host(candidate)
