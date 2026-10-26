"""Pure inline-keyboard builders for the bot (T6; Specs S7, S13, S14).

No I/O and no flow logic: each builder turns already-validated data into an
aiogram InlineKeyboardMarkup deterministically. Callback payloads are small
and carry only indices into ``sorted(settings.categories)`` (``c:<i>`` /
``f:<i>``), list navigation (``o``, ``p:<i>``), plain allowed tags for the
interview, ``✅`` / ``❌`` and the confirmation-row field edits
``✏️ Description`` (``d``) / ``🏷️ Tags`` (``t``) — and — never raw folder
paths (Telegram caps callback_data at 64 bytes, and indices kill the
path-injection surface).
"""

from __future__ import annotations

from collections.abc import Sequence

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from app.services.decision import FolderCandidate
from app.services.github import COST_TAGS, ENTRY_TYPES

OTHER_FOLDERS_LABEL = "📂 Other folder…"
BACK_LABEL = "⬅️ Back"
NEXT_LABEL = "Next ➡️"
PAGE_SIZE = 10
FOLDERS_PER_ROW = 2

HELP_TEXT = (
    "Hackpot resource bot — index a public resource into the right leaf category.\n"
    "\n"
    "/start — begin (asks for your GitHub token the first time)\n"
    "/help — this message\n"
    "/cancel — drop the current resource, nothing gets committed\n"
    "/forget — delete my stored GitHub token\n"
    "\n"
    "Send one https link. GitHub repos are read automatically; otherwise I ask "
    "for a summary. Then pick a folder (my suggestions or 📂 Other folder…), "
    "answer the entry questions, and confirm the commit — made under your own "
    "account, to the configured branch.\n"
    "\n"
    "Remember: all repos and resources must be public."
)


def _button(text: str, data: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(text=text, callback_data=data)


def candidates_kb(
    candidates: Sequence[FolderCandidate], folders_sorted: Sequence[str]
) -> InlineKeyboardMarkup:
    """One button per ranked candidate (S7) plus the full-list override."""
    rows: list[list[InlineKeyboardButton]] = []
    for candidate in candidates:
        if candidate.folder not in folders_sorted:
            continue  # only configured leaves can ever be buttoned
        percent = int(candidate.probability * 100)
        index = folders_sorted.index(candidate.folder)
        rows.append([_button(f"📁 {candidate.folder} ({percent}%)", f"c:{index}")])
    rows.append([_button(OTHER_FOLDERS_LABEL, "o")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def folders_kb(
    folders_sorted: Sequence[str], page: int = 0, size: int = PAGE_SIZE
) -> InlineKeyboardMarkup:
    """Paged override list: every button is an index into the sorted leaves."""
    page = max(0, int(page))
    start = page * size
    chunk = list(folders_sorted[start : start + size])
    rows: list[list[InlineKeyboardButton]] = []
    for offset in range(0, len(chunk), FOLDERS_PER_ROW):
        rows.append(
            [
                _button(f"📂 {folder}", f"f:{start + offset + i}")
                for i, folder in enumerate(chunk[offset : offset + FOLDERS_PER_ROW])
            ]
        )
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(_button(BACK_LABEL, f"p:{page - 1}"))
    if start + size < len(folders_sorted):
        nav.append(_button(NEXT_LABEL, f"p:{page + 1}"))
    if nav:
        rows.append(nav)
    if not rows:  # empty category list can never happen (Settings validates), but stay safe
        rows.append([_button(OTHER_FOLDERS_LABEL, "o")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def type_kb() -> InlineKeyboardMarkup:
    """Allowed S13 type tags only — the callback value IS the tag."""
    rows = [
        [_button(tag, tag) for tag in ENTRY_TYPES[offset : offset + 3]]
        for offset in range(0, len(ENTRY_TYPES), 3)
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def cost_kb() -> InlineKeyboardMarkup:
    rows = [[_button(tag, tag) for tag in COST_TAGS]]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def confirm_kb(folder: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [_button(f"✅ Commit to {folder}", "✅")],
            [_button("❌ Cancel", "❌")],
            # S6.1 (T4): one row, two field-edit buttons — payloads "d"/"t",
            # valid only while CONFIRMING. The whole-bullet "e" row is removed.
            [_button("✏️ Description", "d"), _button("🏷️ Tags", "t")],
        ]
    )
