"""SQLite persistence layer (Spec S10): connection bootstrap and schema.

`open_db` is the single entry point. It creates the database file and any
missing parent directories, applies the PRAGMAs every other component
depends on (WAL, foreign keys, busy timeout), initializes the schema
idempotently, and commits — so the bot survives updates and restarts with
pending flows intact.

The `enc_token` column stores opaque ciphertext blobs produced by
app/security; this layer never performs cryptography itself.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

# All resource states; mirrors the resources.state CHECK constraint exactly.
RESOURCE_STATES: frozenset[str] = frozenset(
    {
        "NEW",
        "NEED_TOKEN",
        "NEED_SUMMARY",
        "AWAITING_PLACEMENT",
        "AWAITING_ENTRY_INFO",
        "CONFIRMING",
        "COMMITTED",
        "FAILED",
        "CANCELLED",
    }
)

# Final states end a resource's life. Resume after restart (S10) only looks
# at the remaining, non-final states; the tuple order is stable for SQL.
FINAL_STATES: frozenset[str] = frozenset({"COMMITTED", "FAILED", "CANCELLED"})
ACTIVE_STATES: tuple[str, ...] = tuple(sorted(RESOURCE_STATES - FINAL_STATES))

# Resource source kinds; mirrors the resources.kind CHECK constraint.
RESOURCE_KINDS: frozenset[str] = frozenset({"github", "other"})

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    tg_user_id  INTEGER PRIMARY KEY,
    username    TEXT NOT NULL DEFAULT '',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS github_tokens (
    tg_user_id  INTEGER PRIMARY KEY REFERENCES users(tg_user_id),
    enc_token   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_user_id  INTEGER NOT NULL REFERENCES users(tg_user_id),
    url         TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('github', 'other')),
    context     TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL CHECK (
                    state IN ('NEW', 'NEED_TOKEN', 'NEED_SUMMARY',
                              'AWAITING_PLACEMENT', 'AWAITING_ENTRY_INFO',
                              'CONFIRMING', 'COMMITTED', 'FAILED', 'CANCELLED')
                ),
    folder      TEXT NOT NULL DEFAULT '',
    entry_line  TEXT NOT NULL DEFAULT '',
    commit_url  TEXT NOT NULL DEFAULT '',
    error       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id        INTEGER NOT NULL REFERENCES resources(id),
    request_id         TEXT NOT NULL DEFAULT '',
    folder_choice      TEXT NOT NULL DEFAULT '',
    confidence         REAL NOT NULL DEFAULT 0,
    probabilities_json TEXT NOT NULL DEFAULT '{}',
    needs_admin        REAL,
    cost_choice        TEXT NOT NULL DEFAULT '',
    raw_json           TEXT NOT NULL DEFAULT '{}',
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_user_id  INTEGER,
    resource_id INTEGER,
    action      TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

-- Repo mirror (repo-mirror-dedup S1/S2): every link currently listed in a
-- README of the target repo, including links added outside the bot. One row
-- per (folder, url_key): a hand-duplicated entry stays visible from each
-- README that lists it, and deleting one file cannot blind the intake gate.
CREATE TABLE IF NOT EXISTS mirror_links (
    folder    TEXT NOT NULL,
    url_key   TEXT NOT NULL,
    url       TEXT NOT NULL,
    synced_at TEXT NOT NULL,
    PRIMARY KEY (folder, url_key)
);
CREATE INDEX IF NOT EXISTS idx_mirror_links_key ON mirror_links(url_key);

-- Per-file bookkeeping for the incremental sync: the blob sha each README had
-- at the last successful fetch. A file whose sha is unchanged is never refetched.
CREATE TABLE IF NOT EXISTS mirror_files (
    path      TEXT PRIMARY KEY,
    blob_sha  TEXT NOT NULL,
    synced_at TEXT NOT NULL
);

-- Single-row sync state (id is pinned to 1). head_sha is the git tree object
-- sha of the branch tip: equal shas mean the repo did not move at all.
CREATE TABLE IF NOT EXISTS mirror_state (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    head_sha  TEXT NOT NULL DEFAULT '',
    synced_at TEXT NOT NULL DEFAULT ''
);
"""


def utc_now() -> str:
    """Current UTC time as ISO-8601 with a 'Z' suffix (microseconds kept).

    Single source of truth for timestamps: every writer in this package uses
    it, so ordering by created_at/updated_at stays reliable.
    """
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


async def init_schema(conn: aiosqlite.Connection) -> None:
    """Apply SCHEMA. Every statement is CREATE TABLE IF NOT EXISTS (idempotent)."""
    await conn.executescript(SCHEMA)


async def open_db(path: Path) -> aiosqlite.Connection:
    """Open (creating if needed) the SQLite database at *path*.

    Sets WAL, foreign keys, and a 5 s busy timeout, runs init_schema, and
    commits. Rows come back as sqlite3.Row so models can read columns by
    name. The caller owns the connection and must close it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA foreign_keys=ON")
    await conn.execute("PRAGMA busy_timeout=5000")
    await init_schema(conn)
    await conn.commit()
    return conn
