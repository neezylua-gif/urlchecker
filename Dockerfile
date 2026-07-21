FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system app && useradd --system --gid app --home-dir /app app
WORKDIR /app

COPY requirements.lock.txt ./
RUN python -m pip install --upgrade pip && \
    python -m pip install --requirement requirements.lock.txt

COPY --chown=app:app url_guard_bot ./url_guard_bot
COPY --chown=app:app scam_links.txt ./scam_links.txt

USER app
ENTRYPOINT ["python", "-m", "url_guard_bot"]
