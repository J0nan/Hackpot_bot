"""Pure page-window and caption builders for the numbered folder pickers.

Telegram phones truncate long inline-keyboard labels (and cap button text at
64 characters), so the full ``NN_Domain/Sub_Leaf`` paths live in these HTML
captions instead: every leaf is a readable line under its domain header, and
the keyboard buttons only carry page-local numbers ``1..N`` mapped to
``sorted(categories)`` indices (``f:<i>`` / ``c:<i>`` payloads stay the
contract).

Page windows are domain-aligned: a domain's leaves are never split across
pages (a domain larger than one page gets whole pages of its own). Flow and
keyboards share this single page-window owner, so caption text and buttons
can never disagree about pagination.

This module is deliberately aiogram-free: app/bot/flow.py builds the captions
from here and app/bot/keyboards.py slices pages through here.
"""

from __future__ import annotations

import html
from collections.abc import Sequence

from app.services.decision import FolderCandidate

PAGE_SIZE = 10  # nominal leaves per page; domains are kept whole (see page_windows)


def keycap(number: int) -> str:
    """Emoji keycap label (``3`` -> ``3️⃣``) shared by captions and buttons.

    Digits + VS16 + combining enclosing keycap: the caption line and its
    keyboard button carry the identical glyph, so the correlation is visual
    even on a small phone screen.
    """
    return f"{int(number)}\uFE0F\u20E3"


def group_domains(folders_sorted: Sequence[str]) -> list[tuple[str, list[str]]]:
    """Contiguous ``(domain, folders)`` groups, input order preserved.

    Leaves stay as full ``domain/leaf`` paths so callers keep global-index
    fidelity; caption builders partition for display.
    """
    groups: list[tuple[str, list[str]]] = []
    for folder in folders_sorted:
        domain, _, _leaf = folder.partition("/")
        if not groups or groups[-1][0] != domain:
            groups.append((domain, []))
        groups[-1][1].append(folder)
    return groups


def page_windows(
    folders_sorted: Sequence[str], size: int = PAGE_SIZE
) -> list[tuple[int, list[str]]]:
    """``(global start index, chunk)`` per page; domains are never split.

    Domains pack greedily into pages of ``size``. A domain larger than one
    page consumes whole pages on its own, and packing of following domains
    resumes in the last of those pages.
    """
    size = max(1, int(size))
    windows: list[tuple[int, list[str]]] = []
    start = 0
    for _domain, folders in group_domains(folders_sorted):
        offset = 0
        while offset < len(folders):
            if windows and len(windows[-1][1]) + len(folders) - offset <= size:
                windows[-1][1].extend(folders[offset:])  # pack into the open page
                break
            take = min(size, len(folders) - offset)
            windows.append((start + offset, list(folders[offset : offset + take])))
            offset += take
        start += len(folders)
    return windows


def count_pages(folders_sorted: Sequence[str], size: int = PAGE_SIZE) -> int:
    """Total aligned pages (always at least 1, even for an empty list)."""
    return max(1, len(page_windows(folders_sorted, size)))


def page_slice(
    folders_sorted: Sequence[str], page: int, size: int = PAGE_SIZE
) -> tuple[int, int, list[str]]:
    """Return ``(clamped page, global start index, chunk)`` for one picker page.

    Pages beyond the last one clamp back (the daily category sync can shrink
    the list under a stale button card).
    """
    page = max(0, int(page))
    windows = page_windows(folders_sorted, size)
    if not windows:
        return 0, 0, []
    page = min(page, len(windows) - 1)
    start, chunk = windows[page]
    return page, start, chunk


def pretty_domain(domain: str) -> str:
    """``05_Exploitation_and_PrivEsc`` -> ``05 · Exploitation and PrivEsc``."""
    number, sep, rest = domain.partition("_")
    if not sep:
        return domain.replace("_", " ")
    return f"{number} · {rest.replace('_', ' ')}"


def pretty_leaf(leaf: str) -> str:
    """``CVE_PoCs_and_Exploit_Databases`` -> ``CVE PoCs and Exploit Databases``."""
    return leaf.replace("_", " ")


def _caption_header(title: str, subtitle: str) -> list[str]:
    return [f"📂 <b>{title}</b>", f"<i>{subtitle}</i>", ""]


def folders_list_html(
    folders_sorted: Sequence[str], page: int = 0, size: int = PAGE_SIZE
) -> str:
    """Numbered, domain-grouped HTML caption for one folder-picker page.

    Line numbers are page-local (``1..len(chunk)``) and match the keyboard
    buttons one-to-one; folder text is HTML-escaped even though the config
    validator forbids markup characters.
    """
    page, _start, chunk = page_slice(folders_sorted, page, size)
    total_pages = count_pages(folders_sorted, size)
    lines = _caption_header(
        "Choose destination folder",
        f"Page {page + 1} of {total_pages} · press the number below",
    )
    last_domain: str | None = None
    for offset, folder in enumerate(chunk):
        domain, _, leaf = folder.partition("/")
        if domain != last_domain:
            lines.append(f"🗂️ <b>{html.escape(pretty_domain(domain))}</b>")
            last_domain = domain
        lines.append(f"  {keycap(offset + 1)} {html.escape(pretty_leaf(leaf))}")
    return "\n".join(lines)


def candidates_list_html(
    candidates: Sequence[FolderCandidate], folders_sorted: Sequence[str]
) -> str:
    """Numbered HTML caption for the decision model's ranked suggestions.

    Same layout as ``folders_list_html``: domain header flush left, numbered
    leaves indented below it with their confidence — but the rank order is
    kept (no regrouping), so the numbers always match the buttons. Candidates
    that are not configured leaves are skipped exactly like
    ``candidates_kb``; a domain header repeats only if ranking jumps back to
    a domain a later candidate belongs to again.
    """
    lines = _caption_header(
        "Suggested folders",
        "press the matching number · 📂 Other folder… lists them all",
    )
    number = 0
    last_domain: str | None = None
    for candidate in candidates:
        if candidate.folder not in folders_sorted:
            continue
        number += 1
        domain, _, leaf = candidate.folder.partition("/")
        percent = int(candidate.probability * 100)
        if domain != last_domain:
            lines.append(f"🗂️ <b>{html.escape(pretty_domain(domain))}</b>")
            last_domain = domain
        lines.append(
            f"  {keycap(number)} {html.escape(pretty_leaf(leaf))} — <i>{percent}%</i>"
        )
    return "\n".join(lines)
