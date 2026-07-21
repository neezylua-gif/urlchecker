from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
import time
import unicodedata
from dataclasses import dataclass
from difflib import SequenceMatcher
from html.parser import HTMLParser
from ipaddress import IPv4Address, IPv6Address, ip_address
from types import TracebackType
from typing import Any
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit, urlunsplit

import aiohttp
import idna
import tldextract
from aiohttp.abc import AbstractResolver
from aiohttp.resolver import DefaultResolver

from .config import Config
from .models import AnalysisResult, Finding, RedirectStep, Severity
from .threat_list import ScamLinkDatabase

logger = logging.getLogger(__name__)

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
FALLBACK_GET_STATUSES = frozenset({405, 501})
BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".lan",
    ".home",
    ".internal",
    ".intranet",
    ".test",
    ".invalid",
    ".example",
    ".onion",
)
BLOCKED_HOSTS = frozenset({"localhost", "localhost.localdomain", "broadcasthost"})
POPULAR_DOMAINS = (
    "google.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "telegram.org",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "github.com",
    "discord.com",
    "netflix.com",
    "linkedin.com",
)
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
MALFORMED_PERCENT_RE = re.compile(r"%(?![0-9a-fA-F]{2})")
META_REFRESH_CONTENT_RE = re.compile(
    r"^\s*\d+(?:\.\d+)?\s*;\s*url\s*=\s*(.+?)\s*$",
    re.IGNORECASE | re.DOTALL,
)
SENSITIVE_QUERY_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "code",
        "confirm",
        "jwt",
        "key",
        "pass",
        "password",
        "reset",
        "secret",
        "session",
        "sessionid",
        "sig",
        "signature",
        "token",
    }
)

EXTRACT_DOMAIN = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
    cache_dir=None,
)


class InvalidURL(ValueError):
    pass


class UnsafeTargetError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProbeResponse:
    status: int
    headers: dict[str, str]
    method: str
    body_prefix: bytes = b""


class _MetaRefreshParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.target: str | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self._handle_tag(tag, attrs)

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self._handle_tag(tag, attrs)

    def _handle_tag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if self.target is not None or tag.lower() != "meta":
            return

        values = {
            key.lower(): value for key, value in attrs if key and value is not None
        }
        if values.get("http-equiv", "").strip().lower() != "refresh":
            return

        content = values.get("content", "")
        match = META_REFRESH_CONTENT_RE.match(content)
        if not match:
            return

        target = match.group(1).strip().strip("\"'")
        if target:
            self.target = target


def _normalise_ip(value: IPv4Address | IPv6Address) -> IPv4Address | IPv6Address:
    if isinstance(value, IPv6Address) and value.ipv4_mapped is not None:
        return value.ipv4_mapped
    return value


def ensure_global_ip(value: str) -> None:
    try:
        address = _normalise_ip(ip_address(value))
    except ValueError as exc:
        raise UnsafeTargetError("DNS вернул некорректный IP-адрес") from exc

    # Python's classification has edge cases across versions (for example,
    # multicast may still report is_global=True), so dangerous categories are
    # rejected explicitly in addition to the is_global check.
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise UnsafeTargetError("Адрес ведёт во внутреннюю или специальную сеть")


def is_ip_literal(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def ensure_safe_hostname(host: str) -> str:
    cleaned = host.strip().rstrip(".").lower()
    if not cleaned:
        raise InvalidURL("В URL отсутствует домен")
    if cleaned in BLOCKED_HOSTS or cleaned.endswith(BLOCKED_HOST_SUFFIXES):
        raise UnsafeTargetError("Локальные и специальные доменные имена запрещены")

    if is_ip_literal(cleaned):
        ensure_global_ip(cleaned)
        return cleaned

    try:
        ascii_host = idna.encode(cleaned, uts46=True, std3_rules=True).decode("ascii")
    except idna.IDNAError as exc:
        raise InvalidURL("Домен содержит некорректные международные символы") from exc

    if len(ascii_host) > 253:
        raise InvalidURL("Доменное имя слишком длинное")
    labels = ascii_host.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise InvalidURL("Некорректное доменное имя")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise InvalidURL("Домен содержит некорректную часть")
    if any(not re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
        raise InvalidURL("Домен содержит запрещённые символы")
    return ascii_host


def _validate_percent_decoding(candidate: str) -> None:
    if MALFORMED_PERCENT_RE.search(candidate):
        raise InvalidURL("URL содержит некорректное percent-кодирование")

    decoded = candidate
    # A small bounded loop also catches double-encoded controls such as %250d.
    for _ in range(3):
        if CONTROL_CHAR_RE.search(decoded):
            raise InvalidURL("Управляющие символы в URL запрещены")
        if any(unicodedata.category(char) == "Cf" for char in decoded):
            raise InvalidURL("Скрытые Unicode-символы в URL запрещены")
        if "\\" in decoded:
            raise InvalidURL("Обратные слеши в URL запрещены")
        try:
            next_value = unquote(decoded, errors="strict")
        except UnicodeDecodeError as exc:
            raise InvalidURL("URL содержит некорректное percent-кодирование") from exc
        if next_value == decoded:
            return
        decoded = next_value

    if CONTROL_CHAR_RE.search(decoded):
        raise InvalidURL("Управляющие символы в URL запрещены")
    if any(unicodedata.category(char) == "Cf" for char in decoded):
        raise InvalidURL("Скрытые Unicode-символы в URL запрещены")
    if "\\" in decoded:
        raise InvalidURL("Обратные слеши в URL запрещены")


def normalize_url(raw_url: str, config: Config) -> str:
    candidate = raw_url.strip().strip("<>\"'")
    if not candidate:
        raise InvalidURL("Пустой URL")
    if len(candidate) > config.max_url_length:
        raise InvalidURL("URL слишком длинный")
    if CONTROL_CHAR_RE.search(candidate):
        raise InvalidURL("Управляющие символы в URL запрещены")
    _validate_percent_decoding(candidate)
    if any(unicodedata.category(char) == "Cf" for char in candidate):
        raise InvalidURL("Скрытые Unicode-символы в URL запрещены")
    if "\\" in candidate:
        raise InvalidURL("Обратные слеши в URL запрещены")

    if "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise InvalidURL("URL содержит некорректный порт или домен") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InvalidURL("Поддерживаются только HTTP и HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeTargetError("URL с логином или паролем запрещены")
    if not parsed.hostname:
        raise InvalidURL("В URL отсутствует домен")

    host = ensure_safe_hostname(parsed.hostname)
    effective_port = port or (443 if scheme == "https" else 80)
    allowed_ports = (
        config.allowed_https_ports if scheme == "https" else config.allowed_http_ports
    )
    if effective_port not in allowed_ports:
        raise UnsafeTargetError("Порт запрещён для этой схемы URL")

    host_for_netloc = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    netloc = (
        host_for_netloc
        if effective_port == default_port
        else f"{host_for_netloc}:{effective_port}"
    )
    path = parsed.path or "/"

    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def redact_url(url: str | None) -> str:
    if not url:
        return "—"
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return "<некорректный URL>"

    netloc = parsed.netloc
    if parsed.hostname:
        host = parsed.hostname
        host_for_netloc = f"[{host}]" if ":" in host else host
        netloc = host_for_netloc if port is None else f"{host_for_netloc}:{port}"

    query = "<скрыто>" if parsed.query else ""
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))


def has_sensitive_query(url: str) -> bool:
    try:
        query_items = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return True
    return any(key.lower() in SENSITIVE_QUERY_KEYS for key, _ in query_items)


def registrable_domain(url_or_host: str) -> str:
    try:
        host = urlsplit(url_or_host).hostname if "://" in url_or_host else url_or_host
    except ValueError:
        return ""
    if not host:
        return ""

    clean_host = host.lower().rstrip(".")
    if is_ip_literal(clean_host):
        return clean_host

    try:
        result = EXTRACT_DOMAIN(clean_host)
        return result.top_domain_under_public_suffix or _basic_domain(clean_host)
    except Exception:
        logger.warning("tldextract failed for host %r", clean_host, exc_info=True)
        return _basic_domain(clean_host)


def _basic_domain(host: str) -> str:
    labels = [label for label in host.lower().rstrip(".").split(".") if label]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return labels[0] if labels else ""


def extract_meta_refresh_target(body_prefix: bytes, content_type: str) -> str | None:
    if not body_prefix or "html" not in content_type.lower():
        return None

    # Meta refresh syntax is ASCII-compatible. UTF-8 with ignored invalid bytes
    # is enough for the bounded prefix and avoids trusting an arbitrary codec.
    text = body_prefix.decode("utf-8", errors="ignore")
    parser = _MetaRefreshParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        logger.debug("Failed to parse HTML prefix for meta refresh", exc_info=True)
        return None
    return parser.target


def _edit_distance(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[j] + 1,
                    previous[j - 1] + (char_a != char_b),
                )
            )
        previous = current
    return previous[-1]


def heuristic_findings(url: str) -> list[Finding]:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    findings: list[Finding] = []

    if parsed.scheme == "http":
        findings.append(
            Finding("plain_http", Severity.WARNING, "Соединение не защищено HTTPS.")
        )
    if is_ip_literal(host):
        findings.append(
            Finding(
                "ip_literal", Severity.WARNING, "Вместо домена используется IP-адрес."
            )
        )
    if "xn--" in host:
        findings.append(
            Finding(
                "punycode",
                Severity.WARNING,
                "Домен использует Punycode; возможна визуальная подмена символов.",
            )
        )
    if len(host) > 60:
        findings.append(
            Finding("long_host", Severity.WARNING, "Необычно длинное доменное имя.")
        )
    if host.count("-") > 4:
        findings.append(
            Finding(
                "many_hyphens", Severity.WARNING, "В домене необычно много дефисов."
            )
        )
    if host.count(".") > 4:
        findings.append(
            Finding(
                "many_subdomains",
                Severity.WARNING,
                "В ссылке много уровней поддоменов.",
            )
        )

    domain = registrable_domain(host)
    if domain and not is_ip_literal(domain):
        for popular in POPULAR_DOMAINS:
            if domain == popular:
                continue
            if popular in host and not host.endswith("." + popular):
                findings.append(
                    Finding(
                        "brand_in_subdomain",
                        Severity.DANGER,
                        f"Название известного сервиса ({popular}) находится внутри чужого домена.",
                    )
                )
                break
            distance = _edit_distance(domain, popular)
            ratio = SequenceMatcher(None, domain, popular).ratio()
            if distance == 1 or (distance <= 2 and ratio >= 0.86):
                findings.append(
                    Finding(
                        "possible_typosquat",
                        Severity.WARNING,
                        f"Домен похож на {popular}; возможен тайпсквоттинг.",
                    )
                )
                break

    return findings


class PublicOnlyResolver(AbstractResolver):
    """Resolver that rejects every non-global address before aiohttp connects."""

    def __init__(self, delegate: AbstractResolver | None = None) -> None:
        self._delegate = delegate or DefaultResolver()

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: int = socket.AF_UNSPEC,
    ) -> list[dict[str, Any]]:
        safe_host = ensure_safe_hostname(host)
        if is_ip_literal(safe_host):
            ensure_global_ip(safe_host)

        records = await self._delegate.resolve(safe_host, port, family)
        if not records:
            raise OSError("DNS returned no addresses")

        for record in records:
            ensure_global_ip(str(record["host"]))
        return records

    async def close(self) -> None:
        await self._delegate.close()


class URLAnalyzer:
    def __init__(
        self,
        config: Config,
        *,
        resolver: AbstractResolver | None = None,
        threat_list: ScamLinkDatabase | None = None,
    ) -> None:
        self._config = config
        self._resolver = resolver
        self._session: aiohttp.ClientSession | None = None
        self._semaphore = asyncio.Semaphore(config.max_concurrent_analyses)
        self._threat_list = threat_list or ScamLinkDatabase(
            config.scam_links_file,
            normalize_url=lambda value: normalize_url(value, config),
            normalize_host=ensure_safe_hostname,
            max_bytes=config.scam_links_max_bytes,
        )

    async def __aenter__(self) -> URLAnalyzer:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def start(self) -> None:
        if self._session and not self._session.closed:
            return

        ssl_context = ssl.create_default_context()
        connector = aiohttp.TCPConnector(
            resolver=self._resolver or PublicOnlyResolver(),
            use_dns_cache=False,
            ssl=ssl_context,
            limit=max(20, self._config.max_concurrent_analyses * 2),
            limit_per_host=2,
        )
        timeout = aiohttp.ClientTimeout(
            total=self._config.request_timeout,
            connect=self._config.connect_timeout,
            sock_connect=self._config.connect_timeout,
            sock_read=self._config.read_timeout,
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            cookie_jar=aiohttp.DummyCookieJar(),
            auto_decompress=False,
            trust_env=False,
            headers={
                "User-Agent": "URLGuardBot/1.2.1 (+security URL checker)",
                "Accept": "text/html,application/xhtml+xml;q=0.8,*/*;q=0.1",
            },
            skip_auto_headers={"Accept-Encoding"},
        )

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    async def _probe(self, url: str) -> ProbeResponse:
        if self._session is None or self._session.closed:
            raise RuntimeError("URLAnalyzer.start() was not called")

        async with self._session.head(url, allow_redirects=False) as response:
            status = response.status
            headers = {key: value for key, value in response.headers.items()}

        content_type = headers.get("Content-Type", "")
        should_read_html_prefix = (
            self._config.check_meta_refresh
            and 200 <= status < 300
            and "html" in content_type.lower()
        )
        if status not in FALLBACK_GET_STATUSES and not should_read_html_prefix:
            return ProbeResponse(status=status, headers=headers, method="HEAD")

        # Some servers do not implement HEAD. The same bounded GET is also used
        # when meta-refresh inspection is enabled for an HTML response.
        max_bytes = self._config.meta_refresh_max_bytes
        async with self._session.get(
            url,
            allow_redirects=False,
            headers={"Range": f"bytes=0-{max_bytes - 1}"},
        ) as response:
            body_prefix = await response.content.read(max_bytes)
            return ProbeResponse(
                status=response.status,
                headers={key: value for key, value in response.headers.items()},
                method="GET",
                body_prefix=body_prefix,
            )

    async def analyze(self, raw_url: str) -> AnalysisResult:
        started = time.monotonic()
        result = AnalysisResult(
            requested_url=raw_url,
            display_url=redact_url(raw_url),
        )

        try:
            normalized = normalize_url(raw_url, self._config)
            result.normalized_url = normalized
            result.display_url = redact_url(normalized)
        except UnsafeTargetError as exc:
            result.findings.append(Finding("blocked_target", Severity.DANGER, str(exc)))
            result.elapsed_ms = int((time.monotonic() - started) * 1000)
            return result
        except InvalidURL as exc:
            result.findings.append(Finding("invalid_url", Severity.ERROR, str(exc)))
            result.elapsed_ms = int((time.monotonic() - started) * 1000)
            return result
        except Exception:
            logger.exception("Unexpected URL normalization failure")
            result.findings.append(
                Finding(
                    "internal_error",
                    Severity.ERROR,
                    "Внутренняя ошибка анализатора.",
                )
            )
            result.elapsed_ms = int((time.monotonic() - started) * 1000)
            return result

        try:
            blacklist_match = await self._threat_list.match(normalized)
            if blacklist_match is not None:
                result.final_url = normalized
                result.findings.append(
                    Finding(
                        "local_scam_list",
                        Severity.DANGER,
                        "Ссылка найдена в локальной базе известных вредоносных адресов.",
                    )
                )
                result.elapsed_ms = int((time.monotonic() - started) * 1000)
                return result

            result.findings.extend(heuristic_findings(normalized))
            if self._config.block_sensitive_query_requests and has_sensitive_query(
                normalized
            ):
                result.final_url = normalized
                result.findings.append(
                    Finding(
                        "sensitive_query_not_requested",
                        Severity.WARNING,
                        "URL содержит чувствительные параметры; сетевой запрос не выполнялся.",
                    )
                )
                result.elapsed_ms = int((time.monotonic() - started) * 1000)
                return result

            current_url = normalized
            initial_domain = registrable_domain(current_url)
        except Exception:
            logger.exception("Unexpected heuristic analysis failure")
            result.findings.append(
                Finding(
                    "internal_error",
                    Severity.ERROR,
                    "Внутренняя ошибка анализатора.",
                )
            )
            result.elapsed_ms = int((time.monotonic() - started) * 1000)
            return result

        seen_urls = {current_url}
        deadline = time.monotonic() + self._config.analysis_timeout

        async with self._semaphore:
            try:
                for step in range(self._config.max_redirects + 1):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    response = await asyncio.wait_for(
                        self._probe(current_url), timeout=remaining
                    )
                    result.status_code = response.status

                    location = response.headers.get("Location")
                    redirect_kind = "http"
                    redirect_target = (
                        location
                        if response.status in REDIRECT_STATUSES and location
                        else None
                    )
                    if redirect_target is None and self._config.check_meta_refresh:
                        redirect_target = extract_meta_refresh_target(
                            response.body_prefix,
                            response.headers.get("Content-Type", ""),
                        )
                        if redirect_target is not None:
                            redirect_kind = "meta"

                    if redirect_target is not None:
                        if step >= self._config.max_redirects:
                            result.findings.append(
                                Finding(
                                    "too_many_redirects",
                                    Severity.DANGER,
                                    f"Превышен лимит редиректов ({self._config.max_redirects}).",
                                )
                            )
                            break

                        if redirect_kind == "meta":
                            result.findings.append(
                                Finding(
                                    "meta_refresh_redirect",
                                    Severity.WARNING,
                                    "Обнаружен HTML meta-refresh редирект.",
                                )
                            )

                        joined = urljoin(current_url, redirect_target)
                        try:
                            next_url = normalize_url(joined, self._config)
                        except (InvalidURL, UnsafeTargetError) as exc:
                            result.findings.append(
                                Finding(
                                    "unsafe_redirect",
                                    Severity.DANGER,
                                    f"Опасный редирект заблокирован: {exc}",
                                )
                            )
                            break

                        blacklist_match = await self._threat_list.match(next_url)
                        if blacklist_match is not None:
                            result.redirects.append(
                                RedirectStep(
                                    source_url=redact_url(current_url),
                                    target_url=redact_url(next_url),
                                    status_code=response.status,
                                    kind=redirect_kind,
                                )
                            )
                            result.findings.append(
                                Finding(
                                    "local_scam_list_redirect",
                                    Severity.DANGER,
                                    "Редирект ведёт на адрес из локальной базы вредоносных ссылок; переход заблокирован.",
                                )
                            )
                            break

                        if next_url in seen_urls:
                            result.findings.append(
                                Finding(
                                    "redirect_loop",
                                    Severity.DANGER,
                                    "Обнаружен циклический редирект.",
                                )
                            )
                            break
                        seen_urls.add(next_url)

                        result.redirects.append(
                            RedirectStep(
                                source_url=redact_url(current_url),
                                target_url=redact_url(next_url),
                                status_code=response.status,
                                kind=redirect_kind,
                            )
                        )

                        if (
                            urlsplit(current_url).scheme == "https"
                            and urlsplit(next_url).scheme == "http"
                        ):
                            result.findings.append(
                                Finding(
                                    "https_downgrade",
                                    Severity.DANGER,
                                    "Редирект на HTTP заблокирован: защищённое соединение понижалось.",
                                )
                            )
                            break

                        old_domain = registrable_domain(current_url)
                        new_domain = registrable_domain(next_url)
                        if (
                            old_domain
                            and new_domain
                            and old_domain != new_domain
                            and (
                                has_sensitive_query(current_url)
                                or has_sensitive_query(next_url)
                            )
                        ):
                            result.findings.append(
                                Finding(
                                    "sensitive_cross_domain_redirect",
                                    Severity.DANGER,
                                    "Междоменный редирект с чувствительными параметрами заблокирован.",
                                )
                            )
                            break

                        for redirect_finding in heuristic_findings(next_url):
                            if not any(
                                existing.code == redirect_finding.code
                                and existing.message == redirect_finding.message
                                for existing in result.findings
                            ):
                                result.findings.append(redirect_finding)

                        if old_domain and new_domain and old_domain != new_domain:
                            result.findings.append(
                                Finding(
                                    "cross_domain_redirect",
                                    Severity.WARNING,
                                    f"Редирект меняет домен: {old_domain} → {new_domain}.",
                                )
                            )
                        current_url = next_url
                        continue

                    result.final_url = current_url
                    final_domain = registrable_domain(current_url)
                    if (
                        initial_domain
                        and final_domain
                        and initial_domain != final_domain
                    ):
                        # The per-step warning is useful, but this summary remains
                        # meaningful if multiple redirects were involved.
                        if not any(
                            item.code == "cross_domain_redirect"
                            for item in result.findings
                        ):
                            result.findings.append(
                                Finding(
                                    "final_domain_changed",
                                    Severity.WARNING,
                                    f"Итоговый домен отличается: {initial_domain} → {final_domain}.",
                                )
                            )

                    if response.status >= 500:
                        result.findings.append(
                            Finding(
                                "server_error",
                                Severity.ERROR,
                                f"Сайт ответил серверной ошибкой HTTP {response.status}.",
                            )
                        )
                    elif response.status in {401, 403, 407, 429}:
                        result.findings.append(
                            Finding(
                                "access_limited",
                                Severity.ERROR,
                                f"Сайт ограничил автоматическую проверку: HTTP {response.status}.",
                            )
                        )
                    elif response.status in REDIRECT_STATUSES and not location:
                        result.findings.append(
                            Finding(
                                "redirect_without_location",
                                Severity.WARNING,
                                "Сайт вернул редирект без корректного заголовка Location.",
                            )
                        )
                    elif response.status >= 400:
                        result.findings.append(
                            Finding(
                                "client_error",
                                Severity.WARNING,
                                f"Сайт ответил HTTP {response.status}.",
                            )
                        )

                    content_type = response.headers.get("Content-Type", "").lower()
                    content_disposition = response.headers.get(
                        "Content-Disposition", ""
                    ).lower()
                    dangerous_types = (
                        "application/x-msdownload",
                        "application/x-msdos-program",
                        "application/vnd.microsoft.portable-executable",
                    )
                    if any(item in content_type for item in dangerous_types):
                        result.findings.append(
                            Finding(
                                "executable_download",
                                Severity.DANGER,
                                "Ссылка ведёт на исполняемый файл.",
                            )
                        )
                    elif "attachment" in content_disposition:
                        result.findings.append(
                            Finding(
                                "file_download",
                                Severity.WARNING,
                                "Ссылка инициирует скачивание файла.",
                            )
                        )

                    if urlsplit(current_url).scheme == "https":
                        result.findings.append(
                            Finding(
                                "tls_verified",
                                Severity.INFO,
                                "TLS-сертификат успешно проверен.",
                            )
                        )
                    break

            except UnsafeTargetError:
                result.findings.append(
                    Finding(
                        "dns_ssrf_blocked",
                        Severity.DANGER,
                        "DNS указывает на внутренний или специальный IP-адрес; запрос заблокирован.",
                    )
                )
            except aiohttp.ClientConnectorCertificateError:
                result.findings.append(
                    Finding(
                        "invalid_certificate",
                        Severity.DANGER,
                        "TLS-сертификат сайта недействителен или не соответствует домену.",
                    )
                )
            except aiohttp.ClientSSLError:
                result.findings.append(
                    Finding(
                        "tls_error",
                        Severity.DANGER,
                        "Не удалось безопасно установить TLS-соединение.",
                    )
                )
            except TimeoutError:
                result.findings.append(
                    Finding(
                        "timeout",
                        Severity.ERROR,
                        "Сайт не ответил за установленное время.",
                    )
                )
            except aiohttp.InvalidURL:
                result.findings.append(
                    Finding(
                        "aiohttp_invalid_url",
                        Severity.ERROR,
                        "HTTP-клиент отклонил URL.",
                    )
                )
            except aiohttp.ClientConnectorError:
                result.findings.append(
                    Finding(
                        "connection_error",
                        Severity.ERROR,
                        "Не удалось подключиться к сайту.",
                    )
                )
            except aiohttp.ClientError:
                result.findings.append(
                    Finding(
                        "http_error",
                        Severity.ERROR,
                        "Ошибка при безопасной HTTP-проверке.",
                    )
                )
            except OSError:
                result.findings.append(
                    Finding(
                        "dns_error",
                        Severity.ERROR,
                        "Не удалось разрешить доменное имя.",
                    )
                )
            except Exception:
                logger.exception("Unexpected URL analysis failure")
                result.findings.append(
                    Finding(
                        "internal_error",
                        Severity.ERROR,
                        "Внутренняя ошибка анализатора.",
                    )
                )

        result.elapsed_ms = int((time.monotonic() - started) * 1000)
        return result
