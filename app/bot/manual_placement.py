"""Process-local manual-placement marks.

When the user presses ``🛠️ Manual classify`` on the unreliable-decision step
they take over folder placement: the text-context invite is ended for that
resource, so any later text is a stray message the Continue/Cancel gate guards
(Continue/Cancel) instead of classification context.

Like ``rearm`` and ``pending_edits`` the store is deliberately process-local:
no DB schema change, no new FSM state — a restart drops the marks and the
Continue re-offer falls back to the armed invite (silent, safe degradation).

Keyed by resource id: choosing a folder or cancelling clears the mark, and a
new link starts a fresh resource whose invite is available again."""

from __future__ import annotations

_marked: set[int] = set()


def mark(resource_id: int) -> None:
    """This resource is being classified by hand: no text-context invite."""
    _marked.add(resource_id)


def clear(resource_id: int) -> None:
    _marked.discard(resource_id)


def is_marked(resource_id: int) -> bool:
    return resource_id in _marked


def clear_all() -> None:
    """Drop every mark (test isolation hook; a restart does the same)."""
    _marked.clear()
