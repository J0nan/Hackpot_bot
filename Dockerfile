FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Host folder ownership decides write access for the ./data bind mount;
# default matches the host uid/gid this bot runs under (override: --build-arg).
ARG BOT_UID=568
ARG BOT_GID=568

RUN groupadd --gid ${BOT_GID} hackpot \
    && useradd --uid ${BOT_UID} --gid hackpot --home-dir /app --shell /usr/sbin/nologin hackpot

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --no-cache-dir . \
    && rm -rf /app/*.egg-info \
    && mkdir -p /app/data \
    && chown -R hackpot:hackpot /app/data

USER ${BOT_UID}:${BOT_GID}

# SQLite + encrypted token store live here; bind-mount the host ./data there.
ENV DB_PATH=/app/data/hackpot.sqlite3
VOLUME ["/app/data"]

ENTRYPOINT ["python", "-m", "app.main"]
