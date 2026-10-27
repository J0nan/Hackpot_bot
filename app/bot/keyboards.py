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

from app.bot.folder_picker import PAGE_SIZE, count_pages, keycap, page_slice
from app.services.decision import FolderCandidate
from app.services.github import COST_TAGS, ENTRY_TYPES

OTHER_FOLDERS_LABEL = "📂 Other folder…"
BACK_LABEL = "⬅️ Back"
NEXT_LABEL = "Next ➡️"
BUTTONS_PER_ROW = 5
TG_BUTTON_TEXT_LIMIT = 64  # Telegram caps button text at 64 UTF-16 code units

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
    "If a link is already on file I say so — with the folder it lives in — "
    "before doing anything else.\n"
    "\n"
    "Remember: all repos and resources must be public."
)


def _button(text: str, data: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(text=text, callback_data=data)


def _utf16_len(text: str) -> int:
    """Telegram measures button text in UTF-16 code units (emoji = 2)."""
    return len(text.encode("utf-16-le")) // 2


def _fit_folder_button(prefix: str, folder: str, suffix: str = "") -> str:
    """Assemble ``prefix + folder + suffix`` within the 64-unit button cap.

    Labels that fit are returned byte-for-byte unchanged; only an overflowing
    folder part is middle-elided, keeping the leaf tail (the identifying part)
    and the full suffix (percentages, punctuation).
    """
    label = f"{prefix}{folder}{suffix}"
    if _utf16_len(label) <= TG_BUTTON_TEXT_LIMIT:
        return label
    room = TG_BUTTON_TEXT_LIMIT - _utf16_len(prefix + suffix) - 1  # 1 for "…"
    if room <= 0:
        return f"{prefix}…"
    return f"{prefix}…{folder[-room:]}{suffix}"


def candidates_kb(
    candidates: Sequence[FolderCandidate], folders_sorted: Sequence[str]
) -> InlineKeyboardMarkup:
    """Number buttons (1..N in rank order) for the candidates_list_html caption.

    The full path and confidence percent moved to the HTML message so phones
    show them whole; payloads stay global ``c:<i>`` indices (S7), and the
    full-list override button is unchanged.
    """
    buttoned = [c for c in candidates if c.folder in folders_sorted]
    rows: list[list[InlineKeyboardButton]] = []
    for offset in range(0, len(buttoned), BUTTONS_PER_ROW):
        rows.append(
            [
                _button(keycap(offset + i + 1), f"c:{folders_sorted.index(c.folder)}")
                for i, c in enumerate(buttoned[offset : offset + BUTTONS_PER_ROW])
            ]
        )
    rows.append([_button(OTHER_FOLDERS_LABEL, "o")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def folders_kb(
    folders_sorted: Sequence[str], page: int = 0, size: int = PAGE_SIZE
) -> InlineKeyboardMarkup:
    """Number buttons (1..N, page-local) for the folders_list_html caption.

    Long leaf paths were unreadable on phones, so the full names moved to the
    HTML message (app/bot/folder_picker.py); the keyboard carries just the
    matching numbers, still resolving to global ``f:<i>`` index payloads.
    """
    page, start, chunk = page_slice(folders_sorted, page, size)
    rows: list[list[InlineKeyboardButton]] = []
    for offset in range(0, len(chunk), BUTTONS_PER_ROW):
        rows.append(
            [
                _button(keycap(offset + i + 1), f"f:{start + offset + i}")
                for i, _folder in enumerate(chunk[offset : offset + BUTTONS_PER_ROW])
            ]
        )
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(_button(BACK_LABEL, f"p:{page - 1}"))
    if page + 1 < count_pages(folders_sorted, size):
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
            [_button(_fit_folder_button("✅ Commit to ", folder), "✅")],
            [_button("❌ Cancel", "❌")],
            # S6.1 (T4): one row, two field-edit buttons — payloads "d"/"t",
            # valid only while CONFIRMING. The whole-bullet "e" row is removed.
            [_button("✏️ Description", "d"), _button("🏷️ Tags", "t")],
        ]
    )
