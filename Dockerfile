FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10001 hackpot \
    && useradd --uid 10001 --gid hackpot --home-dir /app --shell /usr/sbin/nologin hackpot

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --no-cache-dir . \
    && rm -rf /app/*.egg-info \
    && mkdir -p /app/data \
    && chown -R hackpot:hackpot /app/data

USER 10001:10001

# SQLite + encrypted token store live here; mount as a named volume.
ENV DB_PATH=/app/data/hackpot.sqlite3
VOLUME ["/app/data"]

ENTRYPOINT ["python", "-m", "app.main"]
