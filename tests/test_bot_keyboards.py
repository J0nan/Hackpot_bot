"""Deterministic tests for the pure keyboard builders (T6; Specs S7, S13, S14).

Labels and callback_data are pinned byte-for-byte: callback payloads carry
indices into ``sorted(settings.categories)`` only — never raw folder paths —
and every payload stays inside Telegram's 64-byte callback_data budget.
"""

from __future__ import annotations

import pytest

from app.bot.keyboards import (
    HELP_TEXT,
    candidates_kb,
    confirm_kb,
    cost_kb,
    folders_kb,
    type_kb,
)
from app.services.decision import FolderCandidate
from app.services.github import COST_TAGS, ENTRY_TYPES

FOLDERS = [
    "01_Recon/OSINT",
    "02_Web_Application/Vulnerability_Specific",
    "03_Mobile/Android",
]


def _cells(kb) -> list[list[tuple[str, str]]]:
    """[(text, callback_data), ...] per row of an InlineKeyboardMarkup."""
    return [[(b.text, b.callback_data) for b in row] for row in kb.inline_keyboard]


# ---------------------------------------------------------------- candidates


def test_candidates_kb_exact_labels_and_index_callbacks() -> None:
    candidates = [
        FolderCandidate("02_Web_Application/Vulnerability_Specific", 0.751, True),
        FolderCandidate("01_Recon/OSINT", 0.2, False),
    ]
    rows = _cells(candidates_kb(candidates, FOLDERS))
    assert rows[0][0] == (
        "📁 02_Web_Application/Vulnerability_Specific (75%)",
        "c:1",  # index into the sorted list, not the candidate order
    )
    assert rows[1][0] == ("📁 01_Recon/OSINT (20%)", "c:0")
    assert rows[-1][0] == ("📂 Other folder…", "o")
    assert len(rows) == 3


def test_candidates_kb_int_truncates_probability() -> None:
    rows = _cells(candidates_kb([FolderCandidate("01_Recon/OSINT", 0.1999, False)], FOLDERS))
    assert rows[0][0][0] == "📁 01_Recon/OSINT (19%)"


def test_candidates_kb_empty_falls_back_to_other_only() -> None:
    rows = _cells(candidates_kb([], FOLDERS))
    assert rows == [[("📂 Other folder…", "o")]]


def test_candidate_callbacks_never_carry_raw_paths_and_fit_64_bytes() -> None:
    candidates = [FolderCandidate(f, 0.5, False) for f in FOLDERS]
    rows = _cells(candidates_kb(candidates, FOLDERS))
    for row in rows:
        for _, data in row:
            assert "/" not in data
            assert len(data.encode("utf-8")) <= 64


# ---------------------------------------------------------------- full list


def _folders_12() -> list[str]:
    return [f"NN_Domain{i}/Sub{i:02d}" for i in range(12)]


def test_folders_kb_page_zero_first_10_with_next() -> None:
    folders = _folders_12()
    kb = folders_kb(folders, page=0, size=10)
    rows = _cells(kb)
    body = [cell for row in rows[:-1] for cell in row]
    assert len(body) == 10
    assert body[0] == (f"📂 {folders[0]}", "f:0")
    assert body[9] == (f"📂 {folders[9]}", "f:9")
    assert rows[-1] == [("Next ➡️", "p:1")]


def test_folders_kb_last_page_has_back_only() -> None:
    folders = _folders_12()
    kb = folders_kb(folders, page=1, size=10)
    rows = _cells(kb)
    body = [cell for row in rows[:-1] for cell in row]
    assert body == [(f"📂 {folders[10]}", "f:10"), (f"📂 {folders[11]}", "f:11")]
    assert rows[-1] == [("⬅️ Back", "p:0")]


def test_folders_kb_single_page_has_no_nav() -> None:
    kb = folders_kb(FOLDERS, page=0, size=10)
    rows = _cells(kb)
    assert rows[-1][0][1].startswith("f:")  # no Back/Next row
    assert len([c for r in rows for c in r]) == 3


def test_folders_kb_middle_page_has_both_nav_buttons() -> None:
    folders = _folders_12()
    kb = folders_kb(folders, page=1, size=4)  # pages of 4: 0:[0:4] 1:[4:8] 2:[8:12]
    rows = _cells(kb)
    body = [cell for row in rows[:-1] for cell in row]
    assert body == [(f"📂 {folders[i]}", f"f:{i}") for i in range(4, 8)]
    assert rows[-1] == [("⬅️ Back", "p:0"), ("Next ➡️", "p:2")]


def test_folders_kb_clamps_negative_page() -> None:
    rows = _cells(folders_kb(_folders_12(), page=-3, size=10))
    assert rows[0][0] == (f"📂 {_folders_12()[0]}", "f:0")


# ---------------------------------------------------------------- interview


def test_type_kb_lists_allowed_types_only_as_direct_callbacks() -> None:
    cells = [c for row in _cells(type_kb()) for c in row]
    assert cells == [(tag, tag) for tag in ENTRY_TYPES]


def test_cost_kb_lists_allowed_costs_only() -> None:
    cells = [c for row in _cells(cost_kb()) for c in row]
    assert cells == [(tag, tag) for tag in COST_TAGS]


def test_confirm_kb_labels_destination_folder() -> None:
    rows = _cells(confirm_kb("02_Web_Application/Vulnerability_Specific"))
    assert rows[0][0] == ("✅ Commit to 02_Web_Application/Vulnerability_Specific", "✅")
    assert rows[1][0] == ("❌ Cancel", "❌")
    # S6.1 (T4): one row, two field-edit buttons — the "e" row is gone.
    assert rows[2] == [("✏️ Description", "d"), ("🏷️ Tags", "t")]
    assert len(rows) == 3


def test_confirm_kb_edit_payload_is_short_and_path_free() -> None:
    rows = _cells(confirm_kb("01_Recon/OSINT"))
    payloads = [data for row in rows for _, data in row]
    assert "e" not in payloads  # S6.7: the whole-bullet edit payload was removed
    for data in payloads:
        assert "/" not in data
        assert len(data.encode("utf-8")) <= 64  # Telegram callback_data budget


# ---------------------------------------------------------------- /help


def test_help_text_documents_commands_and_public_rule() -> None:
    assert isinstance(HELP_TEXT, str) and HELP_TEXT
    for token in ("/start", "/help", "/cancel", "/forget", "public"):
        assert token in HELP_TEXT
