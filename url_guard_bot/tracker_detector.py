from __future__ import annotations␊
␊
from dataclasses import dataclass␊
from urllib.parse import urlsplit␊
␊
␊
@dataclass(frozen=True, slots=True)␊
class TrackerMatch:␊
    name: str␊
    domain: str␊
␊
␊
# Сервисы, которые используются для логирования переходов␊
TRACKING_DOMAINS = {␊
    "iplogger.com": "IPLogger",␊
    "iplogger.org": "IPLogger",␊
    "grabify.link": "Grabify",␊
    "blasze.com": "Blasze tracker",␊
    "2no.co": "IP tracker",␊
    "yip.su": "YIP tracker",␊
}␊
␊
␊
def detect_tracker(url: str) -> TrackerMatch | None:␊
    """␊
    Проверка URL на сервисы отслеживания переходов.␊
    """␊
␊
    parsed = urlsplit(url)␊
␊
    host = (parsed.hostname or "").lower().rstrip(".")␊
␊
    if not host:␊
        return None␊
␊
    # Проверяем сам домен и поддомены␊
    for domain, name in TRACKING_DOMAINS.items():␊
        if host == domain or host.endswith("." + domain):␊
            return TrackerMatch(␊
                name=name,␊
                domain=domain,␊
            )␊
␊
    return None
