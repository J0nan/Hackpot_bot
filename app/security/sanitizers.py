"""Input sanitizers used on every untrusted bot input (Spec S12, S13, S15).

Three gates:
  * :func:`sanitize_url` — resource links (https-only, no credentials, bounded).
  * :func:`sanitize_line` — one-line text that becomes a README bullet or a DB
    detail column, so it cannot smuggle newlines or HTML comments.
  * :func:`check_folder` — the commit destination must be an exact configured
    leaf category, never a user-built path (path traversal gate).

Error messages are short and static: they must not echo attacker-controlled
input into logs or back into chat.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit

from app.config import Settings

MAX_URL_LENGTH = 2000
DEFAULT_LINE_LENGTH = 500
URL_REJECTION_PREFIX = "URL rejected"

# Characters that mean "line break" and therefore collapse to a single space.
_LINE_BREAK_CHARS = "\t\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029"
_COMMENT_SPAN_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_COMMENT_MARKERS = ("<!--", "-->")
_SPACE_RUN_RE = re.compile(r"\s+")


def sanitize_url(raw: str) -> str:
    """Validate and normalize a resource URL; return the https URL to store.

    Rules: https only, host must be a dotted fully-qualified name, no userinfo
    credentials, printable ASCII only, no internal whitespace, length <= 2000.
    Path, query, and fragment are preserved verbatim (GitHub URLs legitimately
    use both ``?`` and ``#``).
    """
    if not isinstance(raw, str):
        raise ValueError(f"{URL_REJECTION_PREFIX}: must be text")
    value = raw.strip()
    if not value:
        raise ValueError(f"{URL_REJECTION_PREFIX}: empty")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"{URL_REJECTION_PREFIX}: longer than {MAX_URL_LENGTH} characters")
    if any(not 0x20 <= ord(character) <= 0x7E for character in value):
        raise ValueError(f"{URL_REJECTION_PREFIX}: non-printable or non-ASCII character")
    if any(character.isspace() for character in value):
        raise ValueError(f"{URL_REJECTION_PREFIX}: whitespace inside the URL")

    try:
        parts = urlsplit(value)
        # username/password/hostname can raise on malformed hosts (bad IPv6, bad port).
        host = parts.hostname or ""
        has_credentials = bool(parts.username or parts.password) or "@" in parts.netloc
    except ValueError:
        raise ValueError(f"{URL_REJECTION_PREFIX}: malformed URL") from None

    if parts.scheme != "https":
        raise ValueError(f"{URL_REJECTION_PREFIX}: only https is allowed")
    if not parts.netloc:
        raise ValueError(f"{URL_REJECTION_PREFIX}: missing host")
    if has_credentials:
        raise ValueError(f"{URL_REJECTION_PREFIX}: credentials in the URL are not allowed")
    if "." not in host or host.startswith(".") or host.endswith("."):
        raise ValueError(f"{URL_REJECTION_PREFIX}: host must be a fully qualified domain name")
    return value


def sanitize_line(text: str, max_len: int = DEFAULT_LINE_LENGTH) -> str:
    """Reduce arbitrary user text to one safe line for bullets and DB details.

    Whole ``<!-- ... -->`` comment spans are removed (their content too), then any
    leftover comment markers; line breaks become spaces; every other control or
    format character (including zero-width and bidi-override characters) is
    dropped; runs of spaces collapse; the result is capped at ``max_len``.
    """
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    if isinstance(max_len, bool) or not isinstance(max_len, int) or max_len < 1:
        raise ValueError("max_len must be a positive integer")

    value = _COMMENT_SPAN_RE.sub(" ", text)
    for marker in _COMMENT_MARKERS:
        value = value.replace(marker, " ")

    kept: list[str] = []
    for character in value:
        if character in _LINE_BREAK_CHARS:
            kept.append(" ")
        elif unicodedata.category(character).startswith("C"):
            continue
        else:
            kept.append(character)
    return _SPACE_RUN_RE.sub(" ", "".join(kept)).strip()[:max_len]


def check_folder(settings: Settings, folder: str) -> str:
    """Return ``folder`` only if it is an exact configured leaf category.

    This is the traversal gate for the commit path: the repository path is built
    from ``settings.categories`` keys, so ``../`` segments, extra depth, case
    variants, or whitespace-padded names are all rejected by the shared config
    validator. The caller must handle ValueError and show its own safe message.
    """
    if not isinstance(folder, str):
        raise ValueError("category must be a string")
    return settings.folder_or_reject(folder)
