# Changelog

## 1.2.1 — 2026-07-21

- Собрана полная структура Python-пакета `url_guard_bot`.
- Добавлены `.env.example`, Dockerfile, Docker Compose, тесты и скрипты проверки.
- Rate limiter получил ограничение количества одновременно отслеживаемых пользователей.
- URL с чувствительными query-параметрами по умолчанию не запрашиваются по сети.
- Добавлены безопасный in-process stress test и loopback-only nmap/tcpdump lab.
- Добавлены Bandit, Ruff, pytest и pip-audit в воспроизводимый security workflow.
