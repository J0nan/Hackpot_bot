"""Frozen row models mirroring the SCHEMA columns of app/db/database.py.

Repository functions return these instead of raw rows. `from_row` expects a
sqlite3.Row (row_factory is set by `open_db`) so columns are read by name.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Self


@dataclass(frozen=True)
class User:
    """One `users` row: numeric Telegram ID primary, username kept for audit (S17)."""

    tg_user_id: int
    username: str
    first_seen: str
    last_seen: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Self:
        return cls(
            tg_user_id=row["tg_user_id"],
            username=row["username"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )


@dataclass(frozen=True)
class GithubToken:
    """One `github_tokens` row. enc_token is opaque ciphertext from app/security."""

    tg_user_id: int
    enc_token: str
    created_at: str
    updated_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Self:
        return cls(
            tg_user_id=row["tg_user_id"],
            enc_token=row["enc_token"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


@dataclass(frozen=True)
class Resource:
    """One `resources` row: the unit that flows through the bot FSM (S10)."""

    id: int
    tg_user_id: int
    url: str
    kind: str
    context: str
    state: str
    folder: str
    entry_line: str
    commit_url: str
    error: str
    created_at: str
    updated_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Self:
        return cls(
            id=row["id"],
            tg_user_id=row["tg_user_id"],
            url=row["url"],
            kind=row["kind"],
            context=row["context"],
            state=row["state"],
            folder=row["folder"],
            entry_line=row["entry_line"],
            commit_url=row["commit_url"],
            error=row["error"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


@dataclass(frozen=True)
class Decision:
    """One `decisions` row: the Qwen placement answer kept for audit (S7/S16)."""

    id: int
    resource_id: int
    request_id: str
    folder_choice: str
    confidence: float
    probabilities_json: str
    needs_admin: float | None
    cost_choice: str
    raw_json: str
    created_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Self:
        return cls(
            id=row["id"],
            resource_id=row["resource_id"],
            request_id=row["request_id"],
            folder_choice=row["folder_choice"],
            confidence=row["confidence"],
            probabilities_json=row["probabilities_json"],
            needs_admin=row["needs_admin"],
            cost_choice=row["cost_choice"],
            raw_json=row["raw_json"],
            created_at=row["created_at"],
        )


@dataclass(frozen=True)
class AuditEvent:
    """One `audit_log` row. User/resource references are nullable by design."""

    id: int
    tg_user_id: int | None
    resource_id: int | None
    action: str
    detail: str
    created_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Self:
        return cls(
            id=row["id"],
            tg_user_id=row["tg_user_id"],
            resource_id=row["resource_id"],
            action=row["action"],
            detail=row["detail"],
            created_at=row["created_at"],
        )
