"""Flow result actions and keyboard specs shared by the flow modules."""

from __future__ import annotations

from dataclasses import dataclass

from app.services.decision import FolderCandidate


@dataclass(frozen=True)
class CandidatesKB:
    candidates: tuple[FolderCandidate, ...]


@dataclass(frozen=True)
class FoldersKB:
    page: int = 0


@dataclass(frozen=True)
class ManualKB:
    """Unreliable-decision ask: 🛠️ Manual classify / ❌ Cancel, no folders yet."""


@dataclass(frozen=True)
class TypeKB:
    pass


@dataclass(frozen=True)
class ConfirmKB:
    folder: str


@dataclass(frozen=True)
class ResumeKB:
    """▶️ Continue / ❌ Cancel under the prompt."""

    pass


@dataclass(frozen=True)
class FlowResult:
    """Actions for the handler: reply texts, one keyboard, delete this message.

    ``new_message`` asks a callback answer to go out as fresh message(s) instead
    of editing the button bubble — the ✏️ Description / 🏷️ Tags reply must
    leave the ✅/❌ confirmation usable. ``parse_mode`` (e.g. ``"HTML"``) is
    handed to every send of this result, so the flow can ship pre-escaped code
    blocks without changing the bot-wide default (none): the flow owns the
    escaping, the handler only renders. ``delete_outgoing`` names
    ``(chat_id, message_id)`` pairs the renderer must delete after sending —
    only ever the card ids captured from the user's OWN button press, never
    caller-supplied values."""

    replies: tuple[str, ...] = ()
    keyboard: CandidatesKB | FoldersKB | ManualKB | TypeKB | ConfirmKB | ResumeKB | None = None
    delete_message: bool = False
    new_message: bool = False
    parse_mode: str | None = None
    delete_outgoing: tuple[tuple[int, int], ...] = ()