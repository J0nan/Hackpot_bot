"""Deterministic tests for the pure keyboard builders (T6; Specs S7, S13, S14).

Labels and callback_data are pinned byte-for-byte: callback payloads carry
indices into ``sorted(settings.categories)`` only — never raw folder paths —
and every payload stays inside Telegram's 64-byte callback_data budget.
"""

from __future__ import annotations

import re

import pytest

from app.bot import folder_picker
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


def test_candidates_kb_number_buttons_match_rank_order() -> None:
    candidates = [
        FolderCandidate("02_Web_Application/Vulnerability_Specific", 0.751, True),
        FolderCandidate("01_Recon/OSINT", 0.2, False),
    ]
    rows = _cells(candidates_kb(candidates, FOLDERS))
    assert rows[0] == [
        (KC(1), "c:1"),  # c: stays an index into the sorted list, not candidate order
        (KC(2), "c:0"),
    ]
    assert rows[-1] == [("📂 Other folder…", "o")]
    assert len(rows) == 2


def test_candidates_list_html_carries_the_readable_names_and_percents() -> None:
    candidates = [
        FolderCandidate(LONG_FOLDER, 0.751, True),
        FolderCandidate("01_Recon/OSINT", 0.1999, False),
    ]
    text = folder_picker.candidates_list_html(candidates, sorted([c.folder for c in candidates]))
    numbers = KEYCAP_RE.findall(text)
    assert numbers == ["1", "2"]  # same rank order as the buttons
    assert "75%" in text  # int truncation kept from the old button labels
    assert "19%" in text
    # Picker layout: domain header flush left, keycap'd leaf indented below it.
    assert (
        f"🗂️ <b>15 · AI and Machine Learning</b>\n  {KC(1)} Adversarial ML and Model Security — <i>75%</i>"
        in text
    )
    assert f"🗂️ <b>01 · Recon</b>\n  {KC(2)} OSINT — <i>19%</i>" in text
    assert "Other folder" in text  # the full-list override stays discoverable


def test_candidates_list_html_groups_same_domain_under_one_header() -> None:
    candidates = [
        FolderCandidate("05_Exploitation_and_PrivEsc/Linux_PrivEsc", 0.4, True),
        FolderCandidate("05_Exploitation_and_PrivEsc/Windows_PrivEsc", 0.3, False),
    ]
    text = folder_picker.candidates_list_html(candidates, sorted([c.folder for c in candidates]))
    assert text.count("05 · Exploitation and PrivEsc") == 1
    assert f"{KC(1)} Linux PrivEsc" in text and f"{KC(2)} Windows PrivEsc" in text


def test_candidates_list_html_skips_unknown_folders_like_the_keyboard() -> None:
    candidates = [
        FolderCandidate("99_Boot/Legacy", 0.9, True),
        FolderCandidate("01_Recon/OSINT", 0.3, False),
    ]
    text = folder_picker.candidates_list_html(candidates, FOLDERS)
    assert "Legacy" not in text
    numbers = KEYCAP_RE.findall(text)
    button_labels = [
        label
        for row in _cells(candidates_kb(candidates, FOLDERS))
        for label, data in row
        if data.startswith("c:")
    ]
    assert numbers == ["1"]
    assert button_labels == [KC(1)]


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


GROUPED = [
    "03_Physical_Security/Surveillance_and_Countermeasures",
    "05_Exploitation_and_PrivEsc/CVE_PoCs_and_Exploit_Databases",
    "05_Exploitation_and_PrivEsc/Exploitation_Frameworks",
]


def _tg_len(text: str) -> int:
    """Telegram counts button text in UTF-16 code units (non-BMP chars = 2)."""
    return len(text.encode("utf-16-le")) // 2


def KC(n: int) -> str:
    """Expected keycap emoji: digits + VS16 + combining enclosing keycap."""
    return f"{n}\uFE0F\u20E3"


KEYCAP_RE = re.compile(r"(\d+)\uFE0F\u20E3")


def test_folders_kb_page_zero_number_buttons_with_next() -> None:
    folders = _folders_12()
    rows = _cells(folders_kb(folders, page=0, size=10))
    body = rows[:-1]
    assert [len(row) for row in body] == [5, 5]  # five number buttons per row
    assert [cell for row in body for cell in row] == [
        (KC(i + 1), f"f:{i}") for i in range(10)
    ]
    assert rows[-1] == [("Next ➡️", "p:1")]


def test_folders_kb_last_page_has_back_only() -> None:
    folders = _folders_12()
    rows = _cells(folders_kb(folders, page=1, size=10))
    assert [c for row in rows[:-1] for c in row] == [(KC(1), "f:10"), (KC(2), "f:11")]
    assert rows[-1] == [("⬅️ Back", "p:0")]


def test_folders_kb_single_page_has_no_nav() -> None:
    rows = _cells(folders_kb(FOLDERS, page=0, size=10))
    assert rows == [[(KC(1), "f:0"), (KC(2), "f:1"), (KC(3), "f:2")]]


def test_folders_kb_middle_page_has_both_nav_buttons() -> None:
    folders = _folders_12()
    rows = _cells(folders_kb(folders, page=1, size=4))  # 0:[0:4] 1:[4:8] 2:[8:12]
    body = [cell for row in rows[:-1] for cell in row]
    assert body == [(KC(i - 3), f"f:{i}") for i in range(4, 8)]
    assert rows[-1] == [("⬅️ Back", "p:0"), ("Next ➡️", "p:2")]


def test_folders_kb_clamps_negative_page() -> None:
    rows = _cells(folders_kb(_folders_12(), page=-3, size=10))
    assert rows[0][0] == (KC(1), "f:0")


# ------------------------------------------------------------ list caption


def test_folders_list_html_numbers_match_the_buttons() -> None:
    text = folder_picker.folders_list_html(GROUPED, page=0, size=10)
    numbers = KEYCAP_RE.findall(text)
    button_labels = [
        label
        for row in _cells(folders_kb(GROUPED, page=0, size=10))
        for label, data in row
        if data.startswith("f:")
    ]
    assert numbers == ["1", "2", "3"]
    assert button_labels == [KC(1), KC(2), KC(3)]
    # Every full path is readable: formatted leaf lines under a formatted
    # domain header, shown once per domain per page.
    assert "🗂️ <b>03 · Physical Security</b>" in text
    assert "🗂️ <b>05 · Exploitation and PrivEsc</b>" in text
    assert text.count("05 · Exploitation and PrivEsc") == 1
    assert f"  {KC(1)} Surveillance and Countermeasures" in text
    assert f"  {KC(2)} CVE PoCs and Exploit Databases" in text
    assert f"  {KC(3)} Exploitation Frameworks" in text
    assert "Page 1 of 1" in text


def test_folders_list_html_paginates_like_the_keyboard() -> None:
    folders = _folders_12()
    text = folder_picker.folders_list_html(folders, page=1, size=5)
    assert "Page 2 of 3" in text
    assert f"{KC(1)} Sub05" in text  # page-local numbering restarts
    assert "Sub00" not in text


def test_folders_list_html_beyond_last_page_clamps_to_last() -> None:
    text = folder_picker.folders_list_html(GROUPED, page=5, size=10)
    assert "Page 1 of 1" in text
    assert f"{KC(1)} Surveillance and Countermeasures" in text


def test_folders_list_html_escapes_untrusted_names() -> None:
    # LEAF_PATH_RE forbids these, but the builder must never emit raw markup.
    text = folder_picker.folders_list_html(["01_A<b>C/D<b>E"], page=0, size=10)
    assert "A<b>C" not in text
    assert "D<b>E" not in text
    assert "A&lt;b&gt;C" in text


# ------------------------------------------------------- 64-char button cap


LONG_FOLDER = "15_AI_and_Machine_Learning/Adversarial_ML_and_Model_Security"  # 60 chars


def test_confirm_kb_long_folder_label_fits_telegram_limit() -> None:
    rows = _cells(confirm_kb(LONG_FOLDER))
    label, data = rows[0][0]
    assert _tg_len(label) <= 64
    assert label.startswith("✅ Commit to ")
    assert label.endswith(LONG_FOLDER[-20:])
    assert data == "✅"


def test_every_button_label_fits_telegram_limit() -> None:
    keyboards = [
        candidates_kb([FolderCandidate(LONG_FOLDER, 0.9, True)], [LONG_FOLDER]),
        confirm_kb(LONG_FOLDER),
        folders_kb([LONG_FOLDER] * 10, page=0, size=10),
    ]
    for kb in keyboards:
        for row in _cells(kb):
            for label, _ in row:
                assert _tg_len(label) <= 64, label


# ------------------------------------------------- domain-aligned page windows


PACK = [
    "01_Recon/OSINT",
    "01_Recon/Subdomains",
    "02_Web/Injection",
    "02_Web/XSS",
    "03_Mobile/Android",
    "03_Mobile/iOS",
    "04_Cloud/AWS",
    "04_Cloud/Azure",
]


def test_page_windows_never_split_a_domain() -> None:
    windows = folder_picker.page_windows(PACK, size=3)
    assert [chunk for _start, chunk in windows] == [PACK[0:2], PACK[2:4], PACK[4:6], PACK[6:8]]
    assert [start for start, _chunk in windows] == [0, 2, 4, 6]


def test_page_windows_pack_domains_into_a_full_page() -> None:
    windows = folder_picker.page_windows(PACK, size=4)
    assert [chunk for _start, chunk in windows] == [PACK[0:4], PACK[4:8]]


def test_oversized_domain_spans_whole_pages_of_itself() -> None:
    big = [f"01_Big/Leaf{i:02d}" for i in range(7)] + ["02_Small/Only"]
    windows = folder_picker.page_windows(big, size=5)
    # page 1: only the big domain; page 2: its remainder, then packing continues
    assert windows == [(0, big[0:5]), (5, big[5:8])]


def test_page_slice_and_count_pages_agree() -> None:
    windows = folder_picker.page_windows(PACK, size=3)
    assert folder_picker.count_pages(PACK, size=3) == len(windows) == 4
    page, start, chunk = folder_picker.page_slice(PACK, 9, size=3)  # clamped to last
    assert (page, start, chunk) == (3, 6, PACK[6:8])


def test_folders_list_html_aligned_page_shows_group_and_count() -> None:
    text = folder_picker.folders_list_html(PACK, page=1, size=3)
    assert "Page 2 of 4" in text
    assert "🗂️ <b>02 · Web</b>" in text
    assert f"{KC(1)} Injection" in text and f"{KC(2)} XSS" in text


def test_folders_kb_next_disappears_on_last_aligned_page() -> None:
    rows = _cells(folders_kb(PACK, page=3, size=3))
    assert rows[0] == [(KC(1), "f:6"), (KC(2), "f:7")]
    assert rows[-1] == [("⬅️ Back", "p:2")]


def test_folders_kb_clamps_stale_page_after_sync() -> None:
    # Categories shrink between presses: an out-of-range page shows the last window.
    rows = _cells(folders_kb(PACK, page=99, size=3))
    assert rows[0] == [(KC(1), "f:6"), (KC(2), "f:7")]
    assert rows[-1] == [("⬅️ Back", "p:2")]


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
