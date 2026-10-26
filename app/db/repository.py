"""Typed data-access functions over an aiosqlite connection (Spec S10, S17).

Every query is fully parameterized. The only SQL text built at runtime is
assembled from hard-coded identifier whitelists — never from caller data —
so hostile strings can only ever be stored as inert values. Each mutating
function commits, keeping the file durable across restarts.
"""

from __future__ import annotations

import json
from typing import Any

import aiosqlite

from app.db.database import (
    ACTIVE_STATES,
    RESOURCE_KINDS,
    RESOURCE_STATES,
    utc_now,
)
from app.db.models import GithubToken, Resource

# Columns of `resources` a caller may update alongside a state change.
# `state` is the positional argument; id/tg_user_id/url/kind/created_at are
# immutable, and updated_at is always written from utc_now().
RESOURCE_UPDATE_COLUMNS: frozenset[str] = frozenset(
    {"context", "folder", "entry_line", "commit_url", "error"}
)

# Columns of `decisions` accepted by record_decision. `probabilities` is an
# alias for probabilities_json; dict values for JSON columns are serialized.
DECISION_COLUMNS: frozenset[str] = frozenset(
    {
        "request_id",
        "folder_choice",
        "confidence",
        "probabilities_json",
        "needs_admin",
        "cost_choice",
        "raw_json",
    }
)
_DECISION_JSON_COLUMNS: frozenset[str] = frozenset({"probabilities_json", "raw_json"})


async def upsert_user(
    conn: aiosqlite.Connection, tg_user_id: int, username: str
) -> None:
    """Insert a user or refresh username/last_seen; first_seen stays stable (S17)."""
    now = utc_now()
    await conn.execute(
        """
        INSERT INTO users (tg_user_id, username, first_seen, last_seen)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(tg_user_id) DO UPDATE SET
            username = excluded.username,
            last_seen = excluded.last_seen
        """,
        (tg_user_id, username, now, now),
    )
    await conn.commit()


async def save_github_token(
    conn: aiosqlite.Connection, tg_user_id: int, enc_token: str
) -> None:
    """Store or rotate the encrypted PAT blob; created_at stays, updated_at refreshes."""
    now = utc_now()
    await conn.execute(
        """
        INSERT INTO github_tokens (tg_user_id, enc_token, created_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(tg_user_id) DO UPDATE SET
            enc_token = excluded.enc_token,
            updated_at = excluded.updated_at
        """,
        (tg_user_id, enc_token, now, now),
    )
    await conn.commit()


async def get_github_token(
    conn: aiosqlite.Connection, tg_user_id: int
) -> GithubToken | None:
    """Return the stored encrypted token row, or None when the user has none."""
    async with conn.execute(
        "SELECT * FROM github_tokens WHERE tg_user_id = ?", (tg_user_id,)
    ) as cursor:
        row = await cursor.fetchone()
    return GithubToken.from_row(row) if row is not None else None


async def delete_github_token(conn: aiosqlite.Connection, tg_user_id: int) -> None:
    """Forget the stored token (e.g. after the admin revokes the PAT)."""
    await conn.execute("DELETE FROM github_tokens WHERE tg_user_id = ?", (tg_user_id,))
    await conn.commit()


async def create_resource(
    conn: aiosqlite.Connection, tg_user_id: int, url: str, kind: str
) -> int:
    """Insert a resource in state NEW and return its row id."""
    if kind not in RESOURCE_KINDS:
        raise ValueError(f"unknown resource kind: {kind!r}")
    now = utc_now()
    cursor = await conn.execute(
        """
        INSERT INTO resources
            (tg_user_id, url, kind, state, created_at, updated_at)
        VALUES (?, ?, ?, 'NEW', ?, ?)
        """,
        (tg_user_id, url, kind, now, now),
    )
    await conn.commit()
    return cursor.lastrowid


async def set_resource_state(
    conn: aiosqlite.Connection, resource_id: int, state: str, **updates: Any
) -> None:
    """Move a resource to *state*, optionally updating whitelisted columns.

    Raises ValueError for states outside the schema CHECK list and for any
    column name not in RESOURCE_UPDATE_COLUMNS (identifiers are taken from
    the whitelist only, so the f-string never sees user input).
    """
    if state not in RESOURCE_STATES:
        raise ValueError(f"unknown resource state: {state!r}")
    unknown = sorted(set(updates) - RESOURCE_UPDATE_COLUMNS)
    if unknown:
        raise ValueError(f"unknown resource column(s): {', '.join(unknown)}")

    assignments = ["state = ?", "updated_at = ?"]
    params: list[Any] = [state, utc_now()]
    for column in sorted(updates):  # stable order, whitelisted identifiers only
        assignments.append(f"{column} = ?")
        params.append(updates[column])
    params.append(resource_id)

    sql = f"UPDATE resources SET {', '.join(assignments)} WHERE id = ?"
    await conn.execute(sql, params)
    await conn.commit()


async def get_resource(conn: aiosqlite.Connection, resource_id: int) -> Resource | None:
    """Return one resource by id, or None when it does not exist."""
    async with conn.execute(
        "SELECT * FROM resources WHERE id = ?", (resource_id,)
    ) as cursor:
        row = await cursor.fetchone()
    return Resource.from_row(row) if row is not None else None


async def get_active_resource_for_user(
    conn: aiosqlite.Connection, tg_user_id: int
) -> Resource | None:
    """Newest resource of *tg_user_id* still in a non-final state (resume, S10)."""
    placeholders = ", ".join("?" for _ in ACTIVE_STATES)
    async with conn.execute(
        f"SELECT * FROM resources "
        f"WHERE tg_user_id = ? AND state IN ({placeholders}) "
        f"ORDER BY created_at DESC, id DESC LIMIT 1",
        (tg_user_id, *ACTIVE_STATES),
    ) as cursor:
        row = await cursor.fetchone()
    return Resource.from_row(row) if row is not None else None


async def list_resources_by_states(
    conn: aiosqlite.Connection, states: tuple[str, ...]
) -> list[Resource]:
    """Every resource whose state is in *states*, across all users.

    Order: COMMITTED first, then newest (created_at, id). Duplicate checks
    rely on it to prefer a placed, committed match over an in-flight one.
    """
    if not states:
        return []
    placeholders = ", ".join("?" for _ in states)
    async with conn.execute(
        f"SELECT * FROM resources WHERE state IN ({placeholders}) "
        "ORDER BY state = 'COMMITTED' DESC, created_at DESC, id DESC",
        states,
    ) as cursor:
        rows = await cursor.fetchall()
    return [Resource.from_row(row) for row in rows]


async def record_decision(
    conn: aiosqlite.Connection, resource_id: int, **fields: Any
) -> int:
    """Insert a decision row and return its id.

    Keys must be DECISION_COLUMNS names or the `probabilities` alias for
    probabilities_json; dict values for the JSON columns are serialized.
    Unknown keys raise ValueError.
    """
    values: dict[str, Any] = {}
    for key, value in fields.items():
        column = "probabilities_json" if key == "probabilities" else key
        if column not in DECISION_COLUMNS:
            raise ValueError(f"unknown decision field: {key!r}")
        if column in _DECISION_JSON_COLUMNS and isinstance(value, dict):
            value = json.dumps(value)
        values[column] = value

    columns = ["resource_id", *sorted(values), "created_at"]
    params = [resource_id, *(values[name] for name in sorted(values)), utc_now()]
    placeholders = ", ".join("?" for _ in columns)
    sql = f"INSERT INTO decisions ({', '.join(columns)}) VALUES ({placeholders})"
    cursor = await conn.execute(sql, params)
    await conn.commit()
    return cursor.lastrowid


async def audit(
    conn: aiosqlite.Connection,
    action: str,
    tg_user_id: int | None = None,
    resource_id: int | None = None,
    detail: str = "",
) -> int:
    """Append an audit trail row (user IDs plus usernames kept for audit, S17)."""
    cursor = await conn.execute(
        """
        INSERT INTO audit_log (tg_user_id, resource_id, action, detail, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (tg_user_id, resource_id, action, detail, utc_now()),
    )
    await conn.commit()
    return cursor.lastrowid
