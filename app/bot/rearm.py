"""Process-local re-arm markers.

While a resource flow is in progress every text update is guarded: the flow
(app/bot/flow.py) answers the Continue/Cancel prompt and does NOT process the
text. Pressing ▶️ Continue re-sends the current step's message and ARMS the
user so exactly the next text update is consumed by the normal per-state
dispatch; any other button press drops the arm (the press itself replaced the
answer). Like ``pending_edits``, the store is deliberately process-local: no
DB schema change, no new FSM state — a restart drops the arms and the guarded
prompt simply returns (silent, safe degradation).

Keyed by Telegram user id: one active resource per user drives the guard, and
every arm is consumed by the next text, cleared by a button press or by
/cancel, so a finished or redirected flow never leaves one behind.
``clear_all`` exists for test isolation (in-process runs reuse user ids)."""

from __future__ import annotations

_arms: set[int] = set()


def arm(user_id: int) -> None:
    """The next text update from this user answers the current step."""
    _arms.add(user_id)


def disarm(user_id: int) -> None:
    _arms.discard(user_id)


def is_armed(user_id: int) -> bool:
    return user_id in _arms


def clear_all() -> None:
    """Drop every arm (test isolation hook; a restart does the same)."""
    _arms.clear()
