"""Process-local in-flight commit guard.

When the user presses ``✅ Commit`` the flow awaits a slow GitHub round-trip
before the resource's state flips to ``COMMITTED``. aiogram dispatches every
callback in its own task, so rapid presses all read ``CONFIRMING`` before the
first commit lands — the companion press then hits GitHub's dedup and the user
sees "that link is already listed" right next to the success message.

The guard closes that window: ``begin()`` claims the commit for a user and any
concurrent press is refused without reaching GitHub. Like ``rearm``,
``pending_edits`` and ``manual_placement`` the store is deliberately
process-local: no DB schema change, no new FSM state. The single event loop
makes the check-and-add atomic (no await between), and ``handle_confirm``
releases the claim in a ``finally``, so a failed commit leaves ✅ pressable
again. A restart drops the claims with the process. If the restart landed
*between* GitHub accepting and the DB flipping to COMMITTED, the row still
reads CONFIRMING, so a re-press honestly answers with GitHub's "already
listed" warning — the DuplicateError fallback in ``flow_confirm`` converts
the warning to success only once the stored state is COMMITTED.

Keyed by user id: a user always acts on their single active resource, so one
claim per user is exactly the protected window."""

from __future__ import annotations

_in_flight: set[int] = set()


def begin(user_id: int) -> bool:
    """Claim the commit for this user. False when a commit is already running."""
    if user_id in _in_flight:
        return False
    _in_flight.add(user_id)
    return True


def release(user_id: int) -> None:
    _in_flight.discard(user_id)


def is_in_flight(user_id: int) -> bool:
    return user_id in _in_flight


def clear_all() -> None:
    """Drop every claim (test isolation hook; a restart does the same)."""
    _in_flight.clear()
