"""Authorization gate for the bot (Spec S2, S9, S17).

Access is decided exclusively by the numeric Telegram user ID configured in
``AUTHORIZED_USERS`` (docker compose). Usernames are never an authorization
input — they are only stored for audit by the persistence layer.
"""

from __future__ import annotations

from app.config import Settings


def is_authorized(settings: Settings, user_id: int | None) -> bool:
    """Return True only when ``user_id`` is an int present in the allowlist.

    ``None`` means the update carries no sender (channel posts, service
    messages, anonymous admins) and is never authorized.

    The ``isinstance`` gate is load-bearing, not cosmetic: ``frozenset[int]``
    membership would also accept ``123456789.0`` (a float hashes equal to the
    int), and ``True``/``False`` would match user IDs ``1``/``0`` because
    ``bool`` is an int subclass. Unhashable payloads (list/dict) would raise
    ``TypeError`` on membership testing, so they are rejected before the check.
    """
    if user_id is None or isinstance(user_id, bool) or not isinstance(user_id, int):
        return False
    return user_id in settings.authorized_user_ids
