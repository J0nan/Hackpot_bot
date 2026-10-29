"""Process-local pending-edit markers (T4; entry-bullet-edit-confirm S6.2/S6.5).

Pressing ✏️ Description / 🏷️ Tags on the confirmation card records one marker
per resource so the next CONFIRMING text update knows (a) which field is being
edited and (b) which confirmation message to delete once the new value lands.
The card ids come ONLY from the user's own callback message (never from text
input), and the store is deliberately process-local: no DB schema change, no
new FSM state. A restart drops the markers, and plain text during CONFIRMING
falls back to ``CONFIRMING_HINT`` — silent degradation is the approved design
(S6.5 [assumption]).

Keyed by resource id: an id is unique per resource, and terminal paths
(✅ / ❌ / /cancel) clear the marker, so a finished flow never leaves one
behind. ``clear_all`` exists for test isolation (in-process test runs reuse
resource ids across fresh databases).
"""

from __future__ import annotations

from dataclasses import dataclass

#: Marker modes: which field the pending paste-back edits.
DESCRIPTION = "description"
TAGS = "tags"


@dataclass(frozen=True)
class PendingEdit:
    """Field being edited plus the confirmation card to replace."""

    mode: str
    chat_id: int | None
    message_id: int | None


_markers: dict[int, PendingEdit] = {}


def set_marker(resource_id: int, mode: str, chat_id: int | None, message_id: int | None) -> None:
    """Record (or replace, when the other field button was pressed) the marker."""
    _markers[resource_id] = PendingEdit(mode, chat_id, message_id)


def get_marker(resource_id: int) -> PendingEdit | None:
    return _markers.get(resource_id)


def clear_marker(resource_id: int) -> None:
    _markers.pop(resource_id, None)


def clear_all() -> None:
    """Drop every marker (test isolation hook; a restart does the same)."""
    _markers.clear()
