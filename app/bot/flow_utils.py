"""Small helpers shared by the flow modules."""

from __future__ import annotations

import json
from typing import Any

from app.bot.flow_messages import _DESC_MAX
from app.logging_config import get_logger
from app.security.sanitizers import sanitize_line

logger = get_logger(__name__)


def _transition(resource_id: Any, old: str, new: str) -> None:
    """DEBUG state transition with the ``res=<id>`` correlation token."""
    logger.debug("state res=%s %s->%s", resource_id, old, new)


def _dump_iv(iv: dict[str, Any]) -> str:
    return json.dumps(iv, sort_keys=True)


def _load_iv(entry_line: str) -> dict[str, Any]:
    """Partial interview answers ride in the whitelisted ``entry_line`` column
    as JSON until the final bullet replaces them."""
    if not entry_line:
        return {}
    try:
        data = json.loads(entry_line)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _first_paragraph(text: str) -> str:
    para = (text or "").strip().split("\n\n", 1)[0].strip()
    return sanitize_line(para, _DESC_MAX)


PARSE_HTML = "HTML"


def _html_escape(text: str) -> str:
    """Telegram HTML-entity escape: only ``&``, ``<`` and ``>`` are special."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _code_block(text: str) -> str:
    """One <pre> block: renders monospace, and copying it yields the value
    verbatim. Escaped here so no payload can break markup."""
    return f"<pre>{_html_escape(text)}</pre>"

