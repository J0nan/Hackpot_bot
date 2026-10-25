"""Leveled logging with secret redaction (feature hackpot-logging; Specs S2-S5).

Stdlib ``logging`` only — no new dependencies. Three concerns live here:

* :func:`setup_logging` installs **one** ``StreamHandler`` on the root logger
  that writes to **stdout** (S3 — Docker captures it, ``docker compose logs -f
  bot`` is the operator interface). It is idempotent: a second call replaces
  its own handler instead of stacking a duplicate.
* :class:`RedactionFilter` is attached to that handler (S4). It scrubs every
  configured secret literal and every credential *shape* out of the rendered
  message AND the formatted exception text, so a log line can never carry a
  plaintext credential — including logs emitted by third-party loggers
  (aiogram) that propagate through the root.
* :func:`get_logger` is the single import point for module loggers.

Logger-name convention: every module calls ``get_logger(__name__)``, so logger
names are the dotted module path (``app.main``, ``app.services.decision``,
``app.bot.flow``) and the whole tree is configured by the one root handler.
There is a single sink (stdout) and a single redaction layer (the filter).
"""

from __future__ import annotations

import logging
import re
import sys
import traceback

#: Levels accepted by ``LOG_LEVEL`` (S2). Also surfaced in the config validator.
LEVELS: tuple[str, ...] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

#: Single line format: ``timestamp LEVEL [logger] message`` (S5).
_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"

#: The replacement token written wherever a credential was scrubbed (S4).
REDACTED = "***"

# Credential shapes that must never reach the stream, independent of which
# secrets were configured (S4). Compiled once at import so the hot path is a
# cheap substring test plus, at worst, a handful of ``.sub()`` calls.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,255}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{16,255}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"Authorization:\s*\S+"),
)

# Cheap pre-filter: a message that contains none of these fragments cannot
# match any shape pattern, so the regex pass is skipped entirely. Each hint is
# a literal substring the corresponding pattern requires (note ``github_pat_``
# spells "gh" separately, hence its own hint) — over-triggering is safe, an
# under-trigger would leak, so these are deliberate supersets.
_SHAPE_HINTS: tuple[str, ...] = ("gh", "github_pat_", "sk-", "Authorization")


def _scrub(text: str, secrets: tuple[str, ...]) -> str:
    """Replace every configured secret literal then every credential shape."""
    if not text:
        return text
    for secret in secrets:  # pre-sorted longest-first by RedactionFilter
        if secret and secret in text:
            text = text.replace(secret, REDACTED)
    if any(hint in text for hint in _SHAPE_HINTS):
        for pattern in _SECRET_PATTERNS:
            text = pattern.sub(REDACTED, text)
    return text


class RedactionFilter(logging.Filter):
    """Scrub credentials from the record text and the formatted exception (S4).

    Attached to the handler, so it also covers records produced by third-party
    loggers that propagate to the root. ``filter`` mutates the record in place
    (rendered message + ``exc_text``) so every downstream handler sees only
    scrubbed text, then returns ``True`` (it never suppresses a record).
    """

    def __init__(self, secrets: tuple[str, ...] = ()) -> None:
        super().__init__()
        # Longest-first so a secret that contains another is fully replaced.
        self._secrets = tuple(sorted({s for s in secrets if s}, key=len, reverse=True))

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _scrub(record.getMessage(), self._secrets)
        record.args = ()  # message already rendered onto record.msg

        exc_text = record.exc_text
        if exc_text is None and record.exc_info is not None:
            exc_text = "".join(traceback.format_exception(*record.exc_info))
        if exc_text:
            record.exc_text = _scrub(exc_text, self._secrets)
            record.exc_info = None  # keep the formatter from re-rendering raw text
        return True


def setup_logging(level: str, *, secrets: tuple[str, ...] = ()) -> None:
    """Configure root stdout logging at ``level`` with the redaction filter.

    Idempotent: any handler previously installed by this function is replaced,
    never duplicated. Foreign handlers (e.g. pytest's capture handler) are left
    untouched.
    """
    root = logging.getLogger()
    resolved = getattr(logging, level.strip().upper(), logging.INFO)
    root.setLevel(resolved)

    for handler in list(root.handlers):
        if getattr(handler, "_hackpot_logging", False):
            root.removeHandler(handler)
            handler.close()

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(resolved)
    handler.setFormatter(logging.Formatter(_FORMAT))
    handler.addFilter(RedactionFilter(secrets=secrets))
    handler._hackpot_logging = True  # type: ignore[attr-defined]
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return the named logger; every module imports loggers from here."""
    return logging.getLogger(name)
