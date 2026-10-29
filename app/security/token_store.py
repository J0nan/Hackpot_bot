"""GitHub PAT capture, validation, encryption at rest, and masking (Spec S8, S12).

A PAT is treated as a secret everywhere: it is validated before storage, stored
only as a Fernet token, and every failure path returns a generic message that
never echoes the token. Callers log with :func:`mask`, never the plaintext.
"""

from __future__ import annotations

import re
import unicodedata

from cryptography.fernet import Fernet

from app.config import Settings

# Accepted token shapes. Classic GitHub tokens use these five prefixes;
# fine-grained tokens use a longer prefix and may contain underscores.
CLASSIC_PREFIXES: tuple[str, ...] = ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")
FINE_GRAINED_PREFIX = "github_pat_"
_TOKEN_BODY_MIN = 16
_TOKEN_BODY_MAX = 255
MAX_TOKEN_LENGTH = 400

_CLASSIC_RE = re.compile(
    "(?:" + "|".join(re.escape(prefix) for prefix in CLASSIC_PREFIXES) + r")[A-Za-z0-9]{16,255}"
)
_FINE_GRAINED_RE = re.compile(r"github_pat_[A-Za-z0-9_]{16,255}")

# Generic, echo-free messages: nothing that reaches a log may contain the secret.
INVALID_TOKEN_MESSAGE = "GitHub token is not valid"
DECRYPT_FAILED_MESSAGE = "Stored GitHub token could not be decrypted"

# Masking: keep the public format prefix and the last four characters only.
MASK_SEPARATOR = "…"
MASK_FALLBACK = "***"
_MIN_MASKABLE_LENGTH = 12
_MAX_MASK_PREFIX = len(FINE_GRAINED_PREFIX)  # longest prefix we are willing to echo
_MIN_HIDDEN_CHARS = 8


def _is_clean_candidate(token: str) -> bool:
    """Reject whitespace, control/format characters, and oversize input early.

    The format regexes already exclude these characters; the explicit check keeps
    the rules readable and enforces the total-length budget independently.
    """
    if not token or len(token) > MAX_TOKEN_LENGTH:
        return False
    return not any(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in token
    )


def validate_pat_format(token: str) -> bool:
    """Return True for a well-formed classic or fine-grained GitHub PAT.

    Never raises: the caller forwards arbitrary chat text here, and a False
    result must not leak the attempted value through an exception message.
    Non-string input is rejected defensively even though the signature is typed.
    """
    if not isinstance(token, str) or not _is_clean_candidate(token):
        return False
    return bool(
        _CLASSIC_RE.fullmatch(token) or _FINE_GRAINED_RE.fullmatch(token)
    )


def looks_like_token(text: str) -> bool:
    """True when a Telegram message body is a single-line bare PAT.

    Used by the capture flow (S8): only a whole message that is exactly one
    token is treated as a token, so prose containing a token is not stored and
    multi-line pastes are not silently truncated.
    """
    if not isinstance(text, str) or not text:
        return False
    if any(character in text for character in ("\r", "\n", "\v", "\f", "\x85", "\u2028", "\u2029")):
        return False
    # Surrounding spaces from a manual paste are tolerated; inner whitespace is not.
    return validate_pat_format(text.strip())


def _fernet(settings: Settings) -> Fernet:
    """Fernet built from the already-validated compose key (never logged)."""
    return Fernet(settings.fernet_key.get_secret_value().encode("utf-8"))


def encrypt_pat(settings: Settings, token: str) -> str:
    """Encrypt a PAT for storage; the plaintext is never returned or echoed.

    Raises ValueError with a generic message when the token is not a valid
    GitHub PAT, so a malformed value can never reach the database.
    """
    if not validate_pat_format(token):
        raise ValueError(INVALID_TOKEN_MESSAGE)
    encrypted = _fernet(settings).encrypt(token.encode("utf-8"))
    return encrypted.decode("ascii")


def decrypt_pat(settings: Settings, enc: str) -> str:
    """Decrypt a stored PAT.

    Any failure (tampered ciphertext, truncated base64, wrong key, non-string
    input, non-UTF-8 payload, or a payload that is not a valid PAT) raises
    ValueError with the same generic message. Fernet's ``InvalidToken`` carries
    no message, so chaining it cannot leak the secret either.
    """
    if not isinstance(enc, str) or not enc.strip():
        raise ValueError(DECRYPT_FAILED_MESSAGE)
    try:
        payload = _fernet(settings).decrypt(enc.encode("ascii"))
        token = payload.decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - one safe outcome for every failure mode
        raise ValueError(DECRYPT_FAILED_MESSAGE) from exc
    if not validate_pat_format(token):
        raise ValueError(DECRYPT_FAILED_MESSAGE)
    return token


def _public_prefix(token: str) -> str:
    """The fixed, non-secret prefix of the token format, or "" if unrecognised.

    A known format prefix is matched first so fine-grained tokens mask as
    ``github_pat_…wxyz`` instead of being cut at their first underscore.
    """
    for known in (*CLASSIC_PREFIXES, FINE_GRAINED_PREFIX):
        if token.startswith(known):
            return known
    separator_index = token.find("_")
    if 0 < separator_index <= _MAX_MASK_PREFIX - 1:
        return token[: separator_index + 1]
    return ""


def mask(token: str) -> str:
    """Render a token for logs/UI as ``ghp_…wxyz`` — public prefix plus 4 chars.

    Tokens that are empty, malformed, or short enough that prefix + suffix would
    expose most of the secret become the constant ``***``.
    """
    if not isinstance(token, str) or len(token) < _MIN_MASKABLE_LENGTH:
        return MASK_FALLBACK
    prefix = _public_prefix(token)
    if len(token) - len(prefix) - 4 < _MIN_HIDDEN_CHARS:
        return MASK_FALLBACK
    return f"{prefix}{MASK_SEPARATOR}{token[-4:]}"
