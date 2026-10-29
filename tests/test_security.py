"""Tests for the T3 security core (Spec S2, S8, S9, S12, S17).

Covers: numeric-ID authorization, the Fernet-encrypted GitHub PAT store, input
sanitizers (URL / single-line text / category path), and the per-user sliding
window rate limiter. No network, no real secrets: Fernet keys are generated per
test and every URL host uses the reserved ``.invalid`` TLD.
"""

from __future__ import annotations

import traceback
from collections.abc import Iterable

import pytest
from cryptography.fernet import Fernet

from app.config import Settings
from app.security.authz import is_authorized
from app.security.rate_limit import RateLimiter
from app.security.sanitizers import check_folder, sanitize_line, sanitize_url
from app.security.token_store import (
    decrypt_pat,
    encrypt_pat,
    looks_like_token,
    mask,
    validate_pat_format,
)

# --------------------------------------------------------------------------- helpers

ALLOWED_IDS = (123456789, 987654321)
CATEGORIES = {
    "01_Recon/OSINT": "reconnaissance and OSINT tooling",
    "02_Web_Application/Vulnerability_Specific": "web app vulnerability resources",
}
ELLIPSIS = "…"  # the single separator mask() must use

# Distinct characters everywhere, so any extra leak inside a masked value shows up.
VALID_CLASSIC = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
VALID_FINE_GRAINED = "github_pat_11ABCDEFG0zY8xW7vU6tS5rQ4pO3nM2lK1jI0hG7fE6dC4bA9zX"


def make_settings(
    user_ids: Iterable[int] = ALLOWED_IDS,
    fernet_key: str | None = None,
    rate_limit_per_min: int | None = None,
) -> Settings:
    """Build validated Settings from test-only values (never reads the real env)."""
    values: dict[str, object] = {
        "telegram_bot_token": "123456:TEST-BOT-TOKEN",
        "AUTHORIZED_USERS": frozenset(user_ids),
        "CATEGORIES_JSON": dict(CATEGORIES),
        "QWEN_API_URL": "https://qwen.example.invalid/compatible-mode/v1/systemone",
        "qwen_api_key": "qwen-test-key",
        "SECRETS_ENCRYPTION_KEY": fernet_key or Fernet.generate_key().decode("ascii"),
    }
    if rate_limit_per_min is not None:
        values["RATE_LIMIT_PER_MIN"] = rate_limit_per_min
    return Settings(**values)  # type: ignore[arg-type]


@pytest.fixture
def settings() -> Settings:
    return make_settings()


class FakeClock:
    """Deterministic stand-in for time.monotonic."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def error_text(exc: BaseException) -> str:
    """Everything a logger could emit for an exception: message, repr, traceback."""
    return " ".join(
        [
            str(exc),
            repr(exc),
            repr(exc.args),
            "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
        ]
    )


# ---------------------------------------------------------------------- authz (S2/S9/S17)


def test_is_authorized_true_for_configured_ids(settings: Settings) -> None:
    assert is_authorized(settings, ALLOWED_IDS[0]) is True
    assert is_authorized(settings, ALLOWED_IDS[1]) is True


def test_is_authorized_false_for_unknown_id(settings: Settings) -> None:
    assert is_authorized(settings, 424242) is False


def test_is_authorized_false_for_none(settings: Settings) -> None:
    """Updates without a from_user (channel posts, synthetic updates) are not authorized."""
    assert is_authorized(settings, None) is False


def test_is_authorized_false_for_string_that_looks_like_allowed_id(settings: Settings) -> None:
    assert is_authorized(settings, str(ALLOWED_IDS[0])) is False


def test_is_authorized_rejects_non_int_values(settings: Settings) -> None:
    """Membership alone is not enough: 123456789.0 == 123456789, lists are unhashable."""
    for value in (float(ALLOWED_IDS[0]), [ALLOWED_IDS[0]], (ALLOWED_IDS[0],), {"id": 1}):
        assert is_authorized(settings, value) is False  # type: ignore[arg-type]


def test_is_authorized_rejects_booleans(settings: Settings) -> None:
    """bool is an int subclass; True must never impersonate a Telegram ID."""
    assert is_authorized(make_settings([1]), True) is False
    assert is_authorized(make_settings([1]), False) is False


def test_is_authorized_rejects_zero_and_negative_ids(settings: Settings) -> None:
    assert is_authorized(settings, 0) is False
    assert is_authorized(settings, -ALLOWED_IDS[0]) is False


# ---------------------------------------------------------- PAT format + capture (S8/S12)


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(VALID_CLASSIC, id="classic-40"),
        pytest.param("ghp_" + "A" * 16, id="classic-min-length"),
        pytest.param("ghp_" + "A" * 255, id="classic-max-length"),
        pytest.param("gho_" + "x1" * 8, id="gho"),
        pytest.param("ghu_" + "Z9" * 20, id="ghu"),
        pytest.param("ghs_" + "aB3" * 11, id="ghs"),
        pytest.param("ghr_" + "q" * 40, id="ghr"),
        pytest.param(VALID_FINE_GRAINED, id="fine-grained"),
        pytest.param("github_pat_" + "A" * 16, id="fine-grained-min-length"),
        pytest.param("github_pat_11ABCDEFG0" + "A" * 30 + "_extra_suffix", id="fine-grained-underscores"),
    ],
)
def test_validate_pat_format_accepts(token: str) -> None:
    assert validate_pat_format(token) is True


@pytest.mark.parametrize(
    "token",
    [
        pytest.param("", id="empty"),
        pytest.param("ghp_", id="prefix-only"),
        pytest.param("ghp_" + "A" * 15, id="classic-too-short"),
        pytest.param("ghp_" + "A" * 256, id="classic-too-long"),
        pytest.param("github_pat_" + "A" * 15, id="fine-grained-too-short"),
        pytest.param("github_pat_" + "A" * 256, id="fine-grained-too-long"),
        pytest.param("ghx_" + "A" * 40, id="wrong-prefix"),
        pytest.param("GHP_" + "A" * 40, id="uppercase-prefix"),
        pytest.param("token_" + "A" * 40, id="no-github-prefix"),
        pytest.param("gh.p_" + "A" * 40, id="dotted-prefix"),
        pytest.param("A" * 500, id="oversize-500-chars"),
        pytest.param("ghp_" + "A" * 450, id="oversize-classic-454-chars"),
        pytest.param(" ghp_" + "A" * 40, id="leading-space"),
        pytest.param(VALID_CLASSIC + " ", id="trailing-space"),
        pytest.param("ghp_" + "A" * 20 + " " + "B" * 16, id="internal-space"),
        pytest.param("ghp_" + "A" * 20 + "\t" + "B" * 16, id="internal-tab"),
        pytest.param(VALID_CLASSIC + "\n", id="trailing-newline"),
        pytest.param("ghp_" + "ÁÉÍ" * 8, id="unicode-letters"),
        pytest.param("ghp_" + "Ａ" * 36, id="fullwidth-letter"),
        pytest.param("ghp_" + "A" * 18 + "\u200b", id="zero-width-space"),
        pytest.param("ghp_" + "A" * 17 + "\x1b", id="escape-control-char"),
        pytest.param("ghp_" + "*"*40, id="base64-punctuation"),
        pytest.param(None, id="non-string-none"),
        pytest.param(12345, id="non-string-int"),
    ],
)
def test_validate_pat_format_rejects(token: object) -> None:
    assert validate_pat_format(token) is False  # type: ignore[arg-type]


def test_looks_like_token_accepts_bare_message() -> None:
    assert looks_like_token(VALID_CLASSIC) is True
    assert looks_like_token(VALID_FINE_GRAINED) is True
    assert looks_like_token(f"  {VALID_CLASSIC}  ") is True


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("", id="empty"),
        pytest.param("hello there", id="prose"),
        pytest.param(f"here is my token:\n{VALID_CLASSIC}", id="labelled-multiline"),
        pytest.param(f"{VALID_CLASSIC}\n{VALID_FINE_GRAINED}", id="two-lines"),
        pytest.param(f"please use {VALID_CLASSIC} thanks", id="embedded-in-sentence"),
        pytest.param("ghp_" + "A" * 40 + "\r", id="carriage-return"),
        pytest.param("https://github.com/J0nan/Hackpot", id="url"),
        pytest.param(None, id="non-string"),
    ],
)
def test_looks_like_token_rejects(text: object) -> None:
    assert looks_like_token(text) is False  # type: ignore[arg-type]


# --------------------------------------------------------------- encrypt / decrypt (S8/S12)


def test_encrypt_then_decrypt_roundtrip(settings: Settings) -> None:
    for token in (VALID_CLASSIC, VALID_FINE_GRAINED):
        enc = encrypt_pat(settings, token)
        assert isinstance(enc, str) and enc
        assert enc != token
        assert token not in enc
        assert decrypt_pat(settings, enc) == token


def test_encrypt_is_non_deterministic(settings: Settings) -> None:
    assert encrypt_pat(settings, VALID_CLASSIC) != encrypt_pat(settings, VALID_CLASSIC)


def test_ciphertext_is_ascii_without_whitespace(settings: Settings) -> None:
    enc = encrypt_pat(settings, VALID_CLASSIC)
    assert enc.isascii()
    assert not any(ch.isspace() for ch in enc)


def test_ciphertext_uses_the_configured_fernet_key(settings: Settings) -> None:
    enc = encrypt_pat(settings, VALID_CLASSIC)
    raw = Fernet(settings.fernet_key.get_secret_value().encode("ascii"))
    assert raw.decrypt(enc.encode("ascii")).decode("utf-8") == VALID_CLASSIC


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("not-a-token", id="garbage"),
        pytest.param("", id="empty"),
        pytest.param("   ", id="whitespace"),
        pytest.param("YWJj", id="base64-without-parts"),
        pytest.param(VALID_CLASSIC, id="plaintext-not-a-token"),
        pytest.param("ghp_.../..", id="path-like-garbage"),
    ],
)
def test_decrypt_garbage_raises_safe_value_error(settings: Settings, bad: str) -> None:
    with pytest.raises(ValueError) as info:
        decrypt_pat(settings, bad)
    assert str(info.value)
    assert "ghp_" not in str(info.value)
    assert "github_pat" not in str(info.value)


def test_decrypt_with_non_string_input_raises_value_error(settings: Settings) -> None:
    enc = encrypt_pat(settings, VALID_CLASSIC)
    for bad in (None, enc.encode("ascii"), 123):
        with pytest.raises(ValueError):
            decrypt_pat(settings, bad)  # type: ignore[arg-type]


def test_decrypt_after_key_rotation_fails_without_leaking_plaintext() -> None:
    old_key = Fernet.generate_key().decode("ascii")
    new_key = Fernet.generate_key().decode("ascii")
    enc = encrypt_pat(make_settings(fernet_key=old_key), VALID_FINE_GRAINED)
    assert decrypt_pat(make_settings(fernet_key=old_key), enc) == VALID_FINE_GRAINED
    with pytest.raises(ValueError) as info:
        decrypt_pat(make_settings(fernet_key=new_key), enc)
    assert VALID_FINE_GRAINED not in error_text(info.value)


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("", id="empty"),
        pytest.param("hunter2", id="not-a-github-token"),
        pytest.param("ghp_" + "A" * 10, id="truncated"),
        pytest.param(f"prefix {VALID_CLASSIC}", id="whitespace"),
        pytest.param(VALID_CLASSIC + "\n", id="trailing-newline"),
        pytest.param(None, id="non-string"),
    ],
)
def test_encrypt_pat_rejects_malformed_token_without_echoing_it(bad: object) -> None:
    with pytest.raises(ValueError) as info:
        encrypt_pat(make_settings(), bad)  # type: ignore[arg-type]
    assert str(info.value)
    if isinstance(bad, str) and bad:
        assert bad not in error_text(info.value)


def test_plaintext_never_appears_in_exception_strings(settings: Settings) -> None:
    secret = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz999999"
    for bad in ("ghp_" + "✖" * 40, secret + "\n", "x" * 5000):
        with pytest.raises(ValueError) as info:
            encrypt_pat(settings, bad)
        text = error_text(info.value)
        assert "✖" not in text
        assert secret not in text
        assert "x" * 100 not in text
    with pytest.raises(ValueError) as info:
        decrypt_pat(settings, "garbage")
    assert secret not in error_text(info.value)


# ------------------------------------------------------------------------- mask (S12)


def test_mask_keeps_only_prefix_and_last_four() -> None:
    assert mask(VALID_CLASSIC) == f"ghp_{ELLIPSIS}{VALID_CLASSIC[-4:]}"
    assert mask(VALID_FINE_GRAINED) == f"github_pat_{ELLIPSIS}{VALID_FINE_GRAINED[-4:]}"


def test_mask_leaks_at_most_four_trailing_chars() -> None:
    token = "ghp_" + "".join(chr(ord("A") + i % 26) for i in range(36))
    masked = mask(token)
    body = token[len("ghp_") :]
    assert masked.split(ELLIPSIS)[-1] == body[-4:]
    assert body[-5] not in masked
    assert body[4:-4] not in masked
    assert len(masked) <= len("ghp_") + len(ELLIPSIS) + 4
    assert token not in masked


@pytest.mark.parametrize(
    "token",
    [
        pytest.param("", id="empty"),
        pytest.param("x", id="single-char"),
        pytest.param("ghp_", id="prefix-only"),
        pytest.param("ghp_AAAA", id="prefix-plus-four"),
        pytest.param("AbCdEfGh123", id="no-prefix-too-short"),
        pytest.param("\u0000\u0001", id="control-chars"),
        pytest.param(None, id="non-string"),
    ],
)
def test_mask_masks_short_or_unusable_tokens(token: object) -> None:
    assert mask(token) == "***"  # type: ignore[arg-type]


def test_mask_never_contains_the_secret_body() -> None:
    assert VALID_CLASSIC[4:] not in mask(VALID_CLASSIC)
    assert VALID_FINE_GRAINED[11:] not in mask(VALID_FINE_GRAINED)


# --------------------------------------------------------------------- sanitize_url (S12/S15)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://github.com/J0nan/Hackpot", "https://github.com/J0nan/Hackpot"),
        ("  https://github.com/J0nan/Hackpot  ", "https://github.com/J0nan/Hackpot"),
        ("https://github.com/a/b?x=1&y=2#readme", "https://github.com/a/b?x=1&y=2#readme"),
        ("https://example.com/Path/To?q=a%20b#frag", "https://example.com/Path/To?q=a%20b#frag"),
        ("https://tool.example.co.uk/", "https://tool.example.co.uk/"),
        # A dotted host with no path still satisfies the https + FQDN rules.
        ("https://github.com", "https://github.com"),
        ("https://github.com/Owner/Repo/tree/main?tab=readme#section-2",
         "https://github.com/Owner/Repo/tree/main?tab=readme#section-2"),
        # urlsplit normalises the scheme, so an uppercase scheme is tolerated as
        # long as it is https; the rest of the value is returned verbatim.
        ("HTTPS://Example.COM/a", "HTTPS://Example.COM/a"),
    ],
)
def test_sanitize_url_accepts_https(raw: str, expected: str) -> None:
    assert sanitize_url(raw) == expected


def test_sanitize_url_accepts_exactly_the_length_limit() -> None:
    url = "https://example.com/" + "a" * (2000 - len("https://example.com/"))
    assert len(url) == 2000
    assert sanitize_url(url) == url


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("http://github.com/J0nan/Hackpot", id="not-https"),
        pytest.param("ftp://example.com/tool", id="ftp"),
        pytest.param("file:///etc/passwd", id="file-scheme"),
        pytest.param("javascript:alert(1)", id="javascript-scheme"),
        pytest.param("github.com/J0nan/Hackpot", id="no-scheme"),
        pytest.param("//example.com/x", id="protocol-relative"),
        pytest.param("https://user:***@github.com/a/b", id="userinfo-credentials"),
        pytest.param("https:***@github.com/a", id="bearer-in-userinfo"),
        pytest.param("https://example", id="host-without-dot"),
        pytest.param("https://localhost:8080/x", id="localhost"),
        pytest.param("https://.example.com", id="empty-label"),
        pytest.param("https://example.com.", id="trailing-dot"),
        pytest.param("https://", id="no-host"),
        pytest.param("https:///path", id="empty-netloc"),
        pytest.param("", id="empty"),
        pytest.param("   ", id="whitespace-only"),
        pytest.param("https://example.com/\r\nX-Injected: 1", id="newline-smuggling"),
        pytest.param("https://example.com/a\tb", id="tab-in-url"),
        pytest.param("https://exa mple.com/a", id="space-in-host"),
        pytest.param("https://example.com/" + "b" * 2000, id="oversize"),
        pytest.param("https://example.com/👍", id="non-ascii"),
        pytest.param(None, id="non-string"),
    ],
)
def test_sanitize_url_rejects(raw: object) -> None:
    with pytest.raises(ValueError):
        sanitize_url(raw)  # type: ignore[arg-type]


def test_sanitize_url_errors_are_short_and_do_not_echo_input() -> None:
    oversized = "https://example.com/" + "a" * 2500
    with pytest.raises(ValueError) as info:
        sanitize_url(oversized)
    message = str(info.value)
    assert message
    assert "a" * 50 not in message
    assert oversized not in error_text(info.value)
    with pytest.raises(ValueError) as cred:
        sanitize_url("https://user:***@github.com/a")
    assert "s3cr3t" not in str(cred.value)


# --------------------------------------------------------------------- sanitize_line (S13)


def test_sanitize_line_collapses_newlines_to_spaces() -> None:
    out = sanitize_line("first line\nsecond line\r\nthird\rfour")
    assert "\n" not in out and "\r" not in out
    assert out == "first line second line third four"


def test_sanitize_line_strips_comment_smuggling() -> None:
    assert "<!--" not in sanitize_line("a<!--b hidden")
    assert "-->" not in sanitize_line("text --> more")
    assert sanitize_line("- [Tool](https://x.dev) <!-- private note -->") == (
        "- [Tool](https://x.dev)"
    )
    assert "<!--" not in sanitize_line("<!--<!--nested-->-->")
    assert "private note" not in sanitize_line("<!-- private note -->")


def test_sanitize_line_removes_control_and_format_chars() -> None:
    assert sanitize_line("a\x00b\x1fc\x7fd\u202ee\u200bf") == "abcdef"
    out = sanitize_line("keep  printable: [](){}<>`|~!@#$%^&*_-+=/\\?,.;:'\"")
    assert out == "keep  printable: [](){}<>`|~!@#$%^&*_-+=/\\?,.;:'\"".replace("  ", " ")


def test_sanitize_line_collapses_space_runs() -> None:
    assert sanitize_line("  many    spaces\t\there  ") == "many spaces here"
    assert sanitize_line("tab\tand\nnewline") == "tab and newline"
    assert sanitize_line("nbsp\u00a0here") == "nbsp here"


def test_sanitize_line_caps_length() -> None:
    assert len(sanitize_line("x" * 1000)) == 500
    assert sanitize_line("abcdefghij", max_len=4) == "abcd"
    assert sanitize_line("word " * 100, max_len=20) == ("word " * 100)[:20]


def test_sanitize_line_rejects_bad_arguments() -> None:
    with pytest.raises(ValueError):
        sanitize_line("x", max_len=0)
    with pytest.raises(ValueError):
        sanitize_line("x", max_len=-1)
    with pytest.raises(ValueError):
        sanitize_line(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        sanitize_line("x", max_len=1.5)  # type: ignore[arg-type]


def test_sanitize_line_keeps_plain_bullet_text_intact() -> None:
    line = "- [Burp Suite](https://portswigger.net/burp) — web proxy `tool` `free`"
    assert sanitize_line(line) == line


# ---------------------------------------------------------------------- check_folder (S12)


def test_check_folder_returns_exact_configured_leaf(settings: Settings) -> None:
    for leaf in CATEGORIES:
        assert check_folder(settings, leaf) == leaf


@pytest.mark.parametrize(
    "folder",
    [
        pytest.param("../../etc", id="traversal-etc"),
        pytest.param("../../../../etc/passwd", id="traversal-passwd"),
        pytest.param("..\\..\\windows\\system32", id="windows-traversal"),
        pytest.param("01_Recon/OSINT/../../01_Recon/OSINT", id="embedded-traversal"),
        pytest.param("01_Recon", id="domain-only"),
        pytest.param("01_Recon/OSINT/README.md", id="path-with-readme"),
        pytest.param("01_Recon/OSINT/../..", id="leaf-then-up"),
        pytest.param("./01_Recon/OSINT", id="dot-slash-prefix"),
        pytest.param(" 01_Recon/OSINT", id="leading-space"),
        pytest.param("01_Recon/OSINT ", id="trailing-space"),
        pytest.param("01_recon/osint", id="wrong-case"),
        pytest.param("", id="empty"),
        pytest.param("*", id="glob"),
        pytest.param("\x0001_Recon/OSINT", id="nul-prefix"),
        pytest.param(None, id="non-string"),
    ],
)
def test_check_folder_rejects_unconfigured_paths(settings: Settings, folder: object) -> None:
    with pytest.raises(ValueError):
        check_folder(settings, folder)  # type: ignore[arg-type]


def test_check_folder_error_message_is_safe(settings: Settings) -> None:
    with pytest.raises(ValueError) as info:
        check_folder(settings, "../../etc/passwd")
    assert str(info.value)
    # The rejection must never hand back a usable path.
    with pytest.raises(ValueError):
        check_folder(settings, "01_Recon/OSINT/../01_Recon/OSINT")


# ---------------------------------------------------------------------- RateLimiter (S12)


def test_rate_limiter_blocks_after_limit_within_window() -> None:
    clock = FakeClock()
    limiter = RateLimiter(limit_per_min=3, clock=clock)
    assert [limiter.allow(7) for _ in range(3)] == [True, True, True]
    assert limiter.allow(7) is False
    assert limiter.allow(7) is False


def test_rate_limiter_uses_the_configured_limit(settings: Settings) -> None:
    clock = FakeClock()
    limiter = RateLimiter(limit_per_min=settings.rate_limit_per_min, clock=clock)
    assert all(limiter.allow(1) for _ in range(settings.rate_limit_per_min))
    assert limiter.allow(1) is False


def test_rate_limiter_allows_again_after_full_window() -> None:
    clock = FakeClock()
    limiter = RateLimiter(limit_per_min=2, clock=clock)
    assert limiter.allow(5) and limiter.allow(5)
    assert limiter.allow(5) is False
    clock.advance(60.0)
    assert limiter.allow(5) is True


def test_rate_limiter_window_slides_per_message() -> None:
    clock = FakeClock()
    limiter = RateLimiter(limit_per_min=2, clock=clock)
    assert limiter.allow(9)  # t = 0
    clock.advance(30.0)
    assert limiter.allow(9)  # t = 30 -> window now full
    clock.advance(25.0)
    assert limiter.allow(9) is False  # t = 55: the t=0 hit has not expired yet
    clock.advance(5.0)
    assert limiter.allow(9) is True  # t = 60: the t=0 hit is out of the window
    assert limiter.allow(9) is False  # hits are now t=30 and t=60


def test_rate_limiter_does_not_refill_before_the_oldest_hit_expires() -> None:
    clock = FakeClock()
    limiter = RateLimiter(limit_per_min=3, clock=clock)
    for _ in range(3):
        assert limiter.allow(42)
    clock.advance(30.0)
    assert limiter.allow(42) is False
    clock.advance(30.0)
    assert limiter.allow(42) is True


def test_rate_limiter_users_are_independent() -> None:
    clock = FakeClock()
    limiter = RateLimiter(limit_per_min=1, clock=clock)
    assert limiter.allow(1) is True
    assert limiter.allow(1) is False
    assert limiter.allow(2) is True
    assert limiter.allow(2) is False
    clock.advance(61.0)
    assert limiter.allow(1) is True and limiter.allow(2) is True


def test_rate_limiter_prunes_old_users_and_keeps_working() -> None:
    clock = FakeClock()
    limiter = RateLimiter(limit_per_min=1, clock=clock)
    for user in range(200):
        assert limiter.allow(user)
    clock.advance(61.0)
    for user in range(0, 200, 40):
        assert limiter.allow(user) is True
        assert limiter.allow(user) is False


def test_rate_limiter_default_clock_is_monotonic() -> None:
    limiter = RateLimiter(limit_per_min=2)
    assert limiter.allow(1) and limiter.allow(1)
    assert limiter.allow(1) is False


@pytest.mark.parametrize("bad_limit", [0, -1, -100])
def test_rate_limiter_rejects_invalid_limit(bad_limit: int) -> None:
    with pytest.raises(ValueError):
        RateLimiter(limit_per_min=bad_limit, clock=FakeClock())
