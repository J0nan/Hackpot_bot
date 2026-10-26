"""Bot orchestration flow (T6; Specs S1-S9, S14) — deliberately aiogram-free.

Everything the Telegram layer does goes through :class:`ResourceFlow`: the
handlers in app/bot/handlers.py only translate Telegram objects into calls
here and render the returned :class:`FlowResult` actions (reply texts,
keyboard specs, message deletion). The FSM lives in the ``resources.state``
column (S10), so every method is resume-safe: a fresh process reads the
user's active resource and continues where it left off.

Design contracts (ODD L8 seam contract + L7 follow-ups honored here):
  * L7-1: entry name/description pass ``sanitize_line`` AND are refused when
    they contain ``[``, ``]`` or a backtick (bullet-injection guard).
  * L7-2: the README stored for classification is cut to the first
    ``README_EXCERPT_CHARS`` (6000) before reaching ``classify()``.
  * L7-3: real GitHub clients are built only via :func:`make_github_factory`,
    which always pins ``settings.target_repo`` — never the module default.
  * L7-4: :meth:`ResourceFlow.handle_decision` announces itself through the
    optional progress sink before the (worst-case ~93 s) classify retries run,
    so a slow decision never looks like a frozen bot. Best-effort only.
  * L7-5: FetchError/DecisionError land in audit rows with their status /
    request-id-bearing message; the user only ever sees the safe wording.
  * Callback payloads carry indices into ``sorted(settings.categories)``
    only (64-byte limit, no raw paths); the flow resolves them back.
  * T2 (entry-bullet-edit-confirm): the ✏️ Edit loop stays inside CONFIRMING.
    Pressing it answers as a NEW message (``FlowResult.new_message``) with the
    bullet in a pre-escaped HTML ``<pre>`` block (``FlowResult.parse_mode``), so
    the ✅/❌ bubble survives; a pasted line is re-parsed with
    ``parse_entry_line``, URL-locked via ``_canonical_url`` and rebuilt through
    ``build_entry_line`` — the L7-1 guard is deliberately never applied to
    pasted bullets (they legitimately carry brackets and backticked tags).

Hardening (T7; ODD L11 a/b/c), all pinned in tests/test_bot_flow.py:
  * L11-a: those indices are parsed strictly (``^\\d+$``, ASCII digits) — a
    padded, signed, zero-prefixed, underscored or non-ASCII-digit payload is
    rejected exactly like ``c:abc``.
  * L11-b: ``handle_confirm`` catches the traversal gate's ValueError from a
    tampered ``resources.folder``: it stays CONFIRMING, makes no HTTP call, and
    records a ``commit_rejected`` audit row with the sanitized folder.
  * L11-c: the "thinking…" reply above, delivered as one extra reply.

Secrets: PATs are validated, Fernet-encrypted and the capture message is
flagged for deletion; plaintext tokens never appear in replies or audit.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import aiosqlite
import httpx

from app.config import Settings
from app.db.repository import (
    audit,
    create_resource,
    delete_github_token,
    get_active_resource_for_user,
    get_github_token,
    get_resource,
    record_decision,
    save_github_token,
    set_resource_state,
    upsert_user,
)
from app.logging_config import get_logger
from app.security.rate_limit import RateLimiter
from app.security.sanitizers import sanitize_line, sanitize_url
from app.security.token_store import decrypt_pat, encrypt_pat, looks_like_token, mask
from app.services.decision import DecisionClient, DecisionError, FolderCandidate
from app.services.github import (
    COST_TAGS,
    ENTRY_TYPES,
    DuplicateError,
    EntryLineError,
    FetchError,
    GitHubClient,
    _canonical_url,
    build_entry_line,
    leaf_title_from_path,
    parse_entry_line,
    parse_repo_url,
)

README_EXCERPT_CHARS = 6000  # L7-2 excerpt cap handed to the decision model
SUMMARY_MAX_CHARS = 6000
_NAME_MAX = 120
_DESC_MAX = 500
IV_FIELDS: tuple[str, ...] = ("name", "description", "type", "cost", "platforms")
NEEDS_ADMIN_THRESHOLD = 0.5  # S7

URL_RE = re.compile(r"https?://\S+")
_TOKEN_SPLIT_RE = re.compile(r"[\s,;]+")
_PLATFORM_UNSAFE = set("`|'\"\\[](){}")
# L11-a: callback indices are ASCII digits only, in canonical spelling. int()
# alone would happily take " 1", "+1", "1_0" and even Arabic-Indic digits ("١"),
# and "^\d+$" alone would still take "01" — so the shape is matched first, then
# the round-trip. Keyboards only ever emit str(i), so any other spelling of the
# same index is a hand-made payload and is rejected like "c:abc".
_INDEX_RE = re.compile(r"^\d+$", re.ASCII)

ProgressSink = Callable[[str], Awaitable[None]]

logger = get_logger(__name__)


def _transition(resource_id: Any, old: str, new: str) -> None:
    """S5: DEBUG state transition with the ``res=<id>`` correlation token."""
    logger.debug("state res=%s %s->%s", resource_id, old, new)

# --- user-visible wording (short, safe, no internals, never a secret) -------- #
SLOW_DOWN = "You are sending too fast — please slow down and try again in a minute."
ASK_PAT_START = (
    "👋 Welcome, Hackpot curator! First, send me your GitHub Personal Access Token "
    "as one bare message. It is encrypted at rest, used only for commits under your "
    "account, and I delete your message right after capture. Tip: a fine-grained "
    "token with contents:write on the Hackpot repo only stays revocable.\n"
    "Here you can create one: https://github.com/settings/personal-access-tokens/new?name=Hackpot%20Bot\n"
    "Remember: all links must be public."
)
GREETING_READY = (
    "👋 Welcome back! Send the https link of the resource you want indexed. GitHub "
    "repo links are read automatically; for anything else I will ask you for a "
    "short summary.\nRemember: all links must be public."
)
PAT_SAVED = (
    "✅ Token stored (encrypted). Send the https link of the resource you want "
    "indexed. \nRemember: all links must be public."
)
PAT_STILL_NEEDED = (
    "I still need your GitHub token, send the bare token as one message "
    "(stored encrypted, never echoed back)."
)
NEED_TOKEN_FOR_LINK = (
    "Before I can index that link, send me your GitHub Personal Access Token as "
    "one bare message. It is stored encrypted and the commit will be made under "
    "your own account."
    "\nHere you can create one: https://github.com/settings/personal-access-tokens/new?name=Hackpot%20Bot\n"
)
USAGE_HINT = (
    "Send exactly one https link (for example https://github.com/owner/repo). For a "
    "non-GitHub resource, send just its link and I will ask for a summary. "
    "Remember: all links must be public."
)
ASK_SUMMARY = (
    "Send me a short summary of what that resource is about — remember: all "
    "links must be public."
)
ANALYZING = "🤔 Analyzing… send /cancel anytime"  # L7-4: shown before the slow call
DECISION_FAILED_USER = (
    "The decision model could not classify this resource just now. Nothing was "
    "committed — you can send the link again later or use /cancel."
)
PLACEMENT_HINT = (
    "Pick a destination folder from the buttons above (📂 Other folder… lists "
    "every category)."
)
UNKNOWN_FOLDER = "That folder is not in the configured category list."
ASK_NAME = "What display name should the entry use? (one line, no [ ] or backticks)"
ASK_DESCRIPTION = (
    "Now the description — one line: what it does and why it matters "
    "(no [ ] or backticks)."
)
ASK_TYPE = "Pick the type tag:"
ASK_COST = "Pick the cost tag:"
ASK_PLATFORMS = (
    "Optional platform/tech tags, space-separated (e.g. linux docker), "
    'or send "none".'
)
ASK_CONTEXT = (
    "Give me a one-line description of what this resource is — remember: all "
    "links must be public."
)
INVALID_FIELD = "{label} can't contain [ ] or backticks — please re-send without them."
INVALID_TYPE = f"Pick one of: {', '.join(ENTRY_TYPES)}."
INVALID_COST = f"Pick one of: {', '.join(COST_TAGS)}."
ENTRY_BUILD_FAILED = (
    "Some collected answers can't form a valid entry line — let's re-check them."
)
PLACED = "Placing in 📁 {folder}."
NEEDS_ADMIN_NOTE = (
    "⚠️ The model flags this as sensitive — please double-check the placement "
    "before committing."
)
PREVIEW = "Here is the entry bullet — confirm to commit:"
COMMITTED_REPLY = "✅ {status} → {url}"
COMMIT_REJECTED = (
    "⛔ That destination is not one of the configured categories — nothing was "
    "committed. Use /cancel, then send the link again."
)
CANCELLED_MSG = "🚫 Cancelled — nothing was uploaded. Send a new link any time."
NOTHING_PENDING = "There is nothing pending to cancel. /start to begin."
CONFIRMING_HINT = (
    "Use the ✅ Commit / ✏️ Edit / ❌ Cancel buttons above, send the edited "
    "bullet back, or /cancel to abort."
)
# T2 (entry-bullet-edit-confirm, S1-S4): ✏️ Edit loop wording, user-safe and
# static — the pasted bullet itself is never echoed beyond parse errors.
EDIT_BULLET_ASK = (
    "✏️ Copy the bullet below, edit the name, description or tags (keep the "
    "reviewed link and the leading `type:` tag), then send it back as one "
    "message. Nothing is committed until you press ✅ — the buttons above stay "
    "usable meanwhile."
)
EDIT_URL_LOCKED = (
    "Your edit changed the link — the URL must stay exactly the reviewed one. "
    "Edit only the name, description or tags, then send the bullet again."
)
EDIT_NO_TYPE_TAG = (
    "Missing type tag: the first tag must be one of "
    + ", ".join(f"`type:{tag}`" for tag in ENTRY_TYPES)
    + " — fix it and send the bullet again."
)
EDIT_FAILED = (
    "That edit can't be applied to the entry format — check the tag order and "
    "the length limits, then send the bullet again."
)
EDIT_RETRY_DETAIL_MAX = 200  # cap for a parse-error line echoed back for retry
FORGOTTEN = "🧹 Your stored GitHub token was deleted. /start to save a new one."
DECRYPT_FAILED = (
    "Your stored GitHub token could not be decrypted. Use /forget, then /start "
    "to save a new one."
)
UNKNOWN_CALLBACK = "That button is no longer available — /start or send the link again."
COMMIT_PUBLIC_REMINDER = " Remember: all links must be public."

# --- keyboard specs (plain data; handlers render them via app.bot.keyboards) - #


@dataclass(frozen=True)
class CandidatesKB:
    candidates: tuple[FolderCandidate, ...]


@dataclass(frozen=True)
class FoldersKB:
    page: int = 0


@dataclass(frozen=True)
class TypeKB:
    pass


@dataclass(frozen=True)
class CostKB:
    pass


@dataclass(frozen=True)
class ConfirmKB:
    folder: str


@dataclass(frozen=True)
class FlowResult:
    """Actions for the handler: reply texts, one keyboard, delete this message.

    ``new_message`` asks a callback answer to go out as fresh message(s) instead
    of editing the button bubble — the ✏️ Edit reply must leave the ✅/❌
    confirmation usable (T2, S4.2). ``parse_mode`` (e.g. ``"HTML"``) is handed
    to every send of this result, so the flow can ship pre-escaped code blocks
    without changing the bot-wide default (none): the flow owns the escaping,
    the handler only renders.
    """

    replies: tuple[str, ...] = ()
    keyboard: CandidatesKB | FoldersKB | TypeKB | CostKB | ConfirmKB | None = None
    delete_message: bool = False
    new_message: bool = False
    parse_mode: str | None = None


@dataclass
class AppDeps:
    """Everything the flow and handlers share, injectable for tests."""

    settings: Settings
    conn: aiosqlite.Connection
    limiter: RateLimiter
    http: httpx.AsyncClient
    make_github: Callable[[str | None], GitHubClient]
    make_decision: Callable[[], DecisionClient]


def make_github_factory(
    settings: Settings, http: httpx.AsyncClient
) -> Callable[[str | None], GitHubClient]:
    """L7-3: pin ``settings.target_repo`` on every GitHubClient we build."""

    def factory(token: str | None) -> GitHubClient:
        return GitHubClient(token, http, settings.target_repo)

    return factory


def make_decision_factory(
    settings: Settings, http: httpx.AsyncClient
) -> Callable[[], DecisionClient]:
    def factory() -> DecisionClient:
        return DecisionClient(
            api_url=settings.qwen_api_url,
            api_key=settings.qwen_api_key,
            model=settings.qwen_model,
            client=http,
        )

    return factory


# --- interview state helpers -------------------------------------------------- #


def _dump_iv(iv: dict[str, Any]) -> str:
    return json.dumps(iv, sort_keys=True)


def _load_iv(entry_line: str) -> dict[str, Any]:
    """Partial interview answers ride in the whitelisted ``entry_line`` column
    as JSON until the final S13 bullet replaces them."""
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


PARSE_HTML = "HTML"  # per-result parse mode (T2); the bot default stays unset


def _html_escape(text: str) -> str:
    """Telegram HTML-entity escape: only ``&``, ``<`` and ``>`` are special."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _code_block(text: str) -> str:
    """One <pre> block: renders monospace, and copying it yields the bullet
    verbatim (S4.2 copy fidelity). Escaped here so no payload can break markup."""
    return f"<pre>{_html_escape(text)}</pre>"


class ResourceFlow:
    """One instance per process; all state lives in SQLite (S10)."""

    def __init__(self, deps: AppDeps) -> None:
        self.deps = deps

    # -- primitives ----------------------------------------------------------- #

    async def _touch(self, user_id: int | None, username: str | None) -> None:
        if isinstance(user_id, int) and not isinstance(user_id, bool):
            await upsert_user(self.deps.conn, user_id, sanitize_line(username or "", 100))

    async def _active(self, user_id: int | None):
        if not isinstance(user_id, int) or isinstance(user_id, bool):
            return None
        return await get_active_resource_for_user(self.deps.conn, user_id)

    async def _log(
        self, action: str, user_id: int | None, resource_id: int | None = None, detail: str = ""
    ) -> None:
        await audit(
            self.deps.conn,
            action,
            tg_user_id=user_id if isinstance(user_id, int) and not isinstance(user_id, bool) else None,
            resource_id=resource_id,
            detail=sanitize_line(detail, 500),
        )

    async def _emit(self, progress: ProgressSink | None, text: str) -> None:
        """L7-4/L11-c: best-effort early feedback (a slow call must not look frozen).

        The sink is the caller's rendering concern; a refused send must never
        abort the flow or leak an internal error into chat, so failures here
        are swallowed after the audit-safe decision call proceeds anyway.
        """
        if progress is None:
            return
        try:
            await progress(text)
        except Exception:  # noqa: BLE001 - progress is optional UX, not a gate
            pass

    # -- entry points ---------------------------------------------------------- #

    async def handle_start(self, user_id: int, username: str) -> FlowResult:
        await self._touch(user_id, username)
        await self._log("start", user_id, detail=f"user={username or ''}")
        replies: list[str] = []
        stored = await get_github_token(self.deps.conn, user_id)
        replies.append(ASK_PAT_START if stored is None else GREETING_READY)
        active = await self._active(user_id)
        if active is not None:
            replies.append(
                f"You still have a pending resource ({active.url[:80]}) — just continue "
                "where you left off, or /cancel to drop it."
            )
        return FlowResult(tuple(replies))

    async def handle_text(
        self, user_id: int, username: str, text: str, progress: ProgressSink | None = None
    ) -> FlowResult:
        """One text update. ``progress`` is the L7-4 early-feedback sink."""
        await self._touch(user_id, username)
        text = text or ""
        active = await self._active(user_id)

        if active is None:
            if looks_like_token(text):
                return await self._capture_pat(user_id, text.strip(), resume=None, progress=progress)
            urls = URL_RE.findall(text)
            if len(urls) == 1:
                return await self._ingest_link(user_id, urls[0], progress)
            await self._log("usage_hint", user_id, detail=f"urls={len(urls)}")
            return FlowResult((USAGE_HINT,))

        state = active.state
        if state == "NEED_TOKEN":
            if looks_like_token(text):
                return await self._capture_pat(user_id, text.strip(), resume=active, progress=progress)
            await self._log("pat_reasked", user_id, active.id)
            return FlowResult((PAT_STILL_NEEDED,))
        if state == "NEED_SUMMARY":
            return await self._record_summary(user_id, active, text, progress)
        if state == "AWAITING_PLACEMENT":
            return FlowResult((PLACEMENT_HINT,))
        if state == "AWAITING_ENTRY_INFO":
            return await self._interview_text(user_id, active, text)
        if state == "CONFIRMING":
            # T2 (S4.3): plain text during CONFIRMING is a ✏️ Edit paste attempt.
            return await self._handle_confirming_text(user_id, active, text)
        # Anything unexpected: buttons drive the next step.
        return FlowResult((CONFIRMING_HINT,))

    async def handle_callback(self, user_id: int, username: str, data: str) -> FlowResult:
        await self._touch(user_id, username)
        data = (data or "").strip()
        folders = sorted(self.deps.settings.categories)

        if data.startswith(("c:", "f:")):
            folder = self._index_to_folder(data, folders)
            if folder is None:
                await self._log("placement_rejected", user_id, detail=f"data={data}")
                return FlowResult((UNKNOWN_FOLDER,))
            return await self.handle_folder_choice(user_id, folder)
        if data == "o":
            return await self.handle_more_folders(user_id, 0)
        if data.startswith("p:"):
            page = self._parse_index(data)
            return await self.handle_more_folders(user_id, page if page is not None else 0)
        if data == "✅":
            return await self.handle_confirm(user_id)
        if data == "❌":
            return await self.handle_cancel(user_id)
        if data == "e":
            # S4.1/S4.2: ✏️ Edit is only a CONFIRMING action; anywhere else the
            # tail below audits it as the unknown callback it is.
            confirming = await self._active(user_id)
            if confirming is not None and confirming.state == "CONFIRMING":
                await self._log("entry_edit_requested", user_id, confirming.id)
                return FlowResult(
                    (EDIT_BULLET_ASK, _code_block(confirming.entry_line)),
                    new_message=True,
                    parse_mode=PARSE_HTML,
                )

        active = await self._active(user_id)
        if active is not None and active.state == "AWAITING_ENTRY_INFO":
            iv = _load_iv(active.entry_line)
            step = self._derive_step(active, iv)
            if step == "type" and data in ENTRY_TYPES:
                return await self._answer_field(user_id, active, iv, "type", data)
            if step == "cost" and data in COST_TAGS:
                return await self._answer_field(user_id, active, iv, "cost", data)
        await self._log("callback_ignored", user_id, detail=f"data={data}")
        return FlowResult((UNKNOWN_CALLBACK,))

    @staticmethod
    def _parse_index(data: str) -> int | None:
        """Strict canonical ``^\\d+$`` payload index (L11-a).

        ``c: 1``, ``c:+1``, ``c:1_0`` and ``c:١`` fail the ASCII-digit match;
        ``c:01`` matches the shape but is not how an index is ever spelled, so
        the round-trip check rejects it too. Anything that is not exactly what
        :mod:`app.bot.keyboards` produces is treated as hostile, not as a near
        miss — the resolved value is always an in-range index, never a path.
        """
        _, separator, raw = data.partition(":")
        if not separator or not _INDEX_RE.match(raw):
            return None
        index = int(raw)
        if str(index) != raw:
            return None
        return index

    @classmethod
    def _index_to_folder(cls, data: str, folders: list[str]) -> str | None:
        """Resolve ``c:<i>``/``f:<i>`` against sorted(categories) — never raw paths."""
        index = cls._parse_index(data)
        if index is None:
            return None
        if 0 <= index < len(folders):
            return folders[index]
        return None

    # -- PAT capture (S8) ------------------------------------------------------- #

    async def _capture_pat(
        self, user_id: int, token: str, resume: Any, progress: ProgressSink | None = None
    ) -> FlowResult:
        try:
            enc = encrypt_pat(self.deps.settings, token)
        except ValueError:
            await self._log("pat_invalid", user_id)
            return FlowResult((PAT_STILL_NEEDED,))
        await save_github_token(self.deps.conn, user_id, enc)
        await self._log("pat_captured", user_id, detail=mask(token))
        logger.info("milestone=pat_captured user=%s", user_id)
        if resume is None:
            return FlowResult((PAT_SAVED,), delete_message=True)
        if resume.kind == "github":
            next_step = await self._fetch_and_decide(user_id, resume, token, progress)
        else:
            await set_resource_state(self.deps.conn, resume.id, "NEED_SUMMARY")
            _transition(resume.id, resume.state, "NEED_SUMMARY")
            await self._log("summary_requested", user_id, resume.id)
            next_step = FlowResult((ASK_SUMMARY,))
        # the PAT message is always deleted after capture (S8)
        return FlowResult(next_step.replies, next_step.keyboard, delete_message=True)

    # -- intake ----------------------------------------------------------------- #

    async def _ingest_link(
        self, user_id: int, raw_url: str, progress: ProgressSink | None
    ) -> FlowResult:
        try:
            url = sanitize_url(raw_url)
        except ValueError as exc:
            await self._log("url_rejected", user_id, detail=str(exc))
            return FlowResult((str(exc), USAGE_HINT))
        kind = "github" if parse_repo_url(url) else "other"
        stored = await get_github_token(self.deps.conn, user_id)
        if stored is None:
            resource_id = await create_resource(self.deps.conn, user_id, url, kind)
            await set_resource_state(self.deps.conn, resource_id, "NEED_TOKEN")
            _transition(resource_id, "NEW", "NEED_TOKEN")
            logger.info("milestone=resource_created res=%s kind=%s waiting=pat", resource_id, kind)
            await self._log(
                "resource_created", user_id, resource_id, detail=f"kind={kind}; waiting=pat"
            )
            return FlowResult((NEED_TOKEN_FOR_LINK,))
        resource_id = await create_resource(self.deps.conn, user_id, url, kind)
        logger.info("milestone=resource_created res=%s kind=%s", resource_id, kind)
        await self._log("resource_created", user_id, resource_id, detail=f"kind={kind}")
        resource = await get_resource(self.deps.conn, resource_id)
        if kind == "github":
            try:
                token = decrypt_pat(self.deps.settings, stored.enc_token)
            except ValueError:
                await self._log("pat_invalid", user_id, resource_id)
                await set_resource_state(self.deps.conn, resource_id, "NEED_TOKEN")
                _transition(resource_id, resource.state, "NEED_TOKEN")
                return FlowResult((PAT_STILL_NEEDED,))
            return await self._fetch_and_decide(user_id, resource, token, progress)
        await set_resource_state(self.deps.conn, resource_id, "NEED_SUMMARY")
        _transition(resource_id, resource.state, "NEED_SUMMARY")
        await self._log("summary_requested", user_id, resource_id)
        return FlowResult((ASK_SUMMARY,))

    async def _fetch_and_decide(
        self, user_id: int, resource: Any, token: str, progress: ProgressSink | None = None
    ) -> FlowResult:
        parsed = parse_repo_url(resource.url)
        if parsed is None:  # kind said github but URL no longer parses: treat as other
            await set_resource_state(self.deps.conn, resource.id, "NEED_SUMMARY")
            _transition(resource.id, resource.state, "NEED_SUMMARY")
            return FlowResult((ASK_SUMMARY,))
        owner, repo = parsed
        client = self.deps.make_github(token)
        try:
            meta = await client.repo_meta(owner, repo)
            readme = await client.readme(owner, repo)
        except FetchError as exc:  # L7-5: detail with status stays in the audit row
            safe = str(exc)
            await set_resource_state(self.deps.conn, resource.id, "NEED_SUMMARY", error=safe)
            _transition(resource.id, resource.state, "NEED_SUMMARY")
            logger.warning("fetch_failed res=%s: %s", resource.id, safe)
            await self._log("fetch_failed", user_id, resource.id, detail=safe)
            return FlowResult((safe, ASK_SUMMARY))
        await self._log("readme_fetched", user_id, resource.id, detail=f"repo={owner}/{repo}")
        logger.info("milestone=readme_fetched res=%s repo=%s/%s", resource.id, owner, repo)
        description = sanitize_line(str(meta.get("description") or ""), _DESC_MAX)
        excerpt = readme[:README_EXCERPT_CHARS]  # L7-2
        context = "\n\n".join(part for part in (description, excerpt) if part)
        await set_resource_state(self.deps.conn, resource.id, "NEW", context=context)
        _transition(resource.id, resource.state, "NEW")
        return await self.handle_decision(user_id, progress)

    async def _record_summary(
        self, user_id: int, resource: Any, text: str, progress: ProgressSink | None = None
    ) -> FlowResult:
        summary = sanitize_line(text, SUMMARY_MAX_CHARS)
        if not summary:
            return FlowResult((ASK_SUMMARY,))
        await set_resource_state(self.deps.conn, resource.id, "NEW", context=summary)
        await self._log("summary_stored", user_id, resource.id)
        return await self.handle_decision(user_id, progress)

    # -- decision (S5, S7) ------------------------------------------------------- #

    async def handle_decision(
        self, user_id: int, progress: ProgressSink | None = None
    ) -> FlowResult:
        resource = await self._active(user_id)
        if resource is None or not resource.context or resource.state not in ("NEW", "NEED_SUMMARY"):
            return FlowResult((UNKNOWN_CALLBACK,))
        excerpt = f"{resource.url}\n\n{resource.context}"
        settings = self.deps.settings
        client = self.deps.make_decision()
        await self._emit(progress, ANALYZING)  # L7-4: announced before the slow retries
        try:
            result = await client.classify(
                ticket_id=f"T-{resource.id}",
                content=excerpt,
                categories=settings.categories,
                threshold=settings.confidence_threshold,
                max_candidates=settings.max_candidates_shown,
            )
        except DecisionError as exc:  # L7-5: status/message audited, never shown raw
            safe = str(exc)
            await set_resource_state(self.deps.conn, resource.id, "FAILED", error=safe)
            _transition(resource.id, resource.state, "FAILED")
            logger.warning("decision_failed res=%s: %s", resource.id, safe)
            await self._log("decision_failed", user_id, resource.id, detail=safe)
            return FlowResult((DECISION_FAILED_USER,))

        top = result.candidates[0] if result.candidates else None
        await record_decision(
            self.deps.conn,
            resource.id,
            request_id=result.request_id,
            folder_choice=top.folder if top else "",
            confidence=top.probability if top else 0.0,
            probabilities={c.folder: c.probability for c in result.candidates},
            needs_admin=result.needs_admin,
            cost_choice=result.cost,
            raw_json=result.raw,
        )
        await set_resource_state(self.deps.conn, resource.id, "AWAITING_PLACEMENT")
        _transition(resource.id, resource.state, "AWAITING_PLACEMENT")
        logger.info(
            "milestone=decision_recorded res=%s request_id=%s candidates=%d",
            resource.id,
            result.request_id,
            len(result.candidates),
        )
        await self._log(
            "decision_recorded",
            user_id,
            resource.id,
            detail=f"request_id={result.request_id}; candidates={len(result.candidates)}",
        )
        replies = [f"Done thinking — {len(result.candidates)} folder(s) cleared the bar."]
        if not result.candidates:
            replies.append("No folder reached the confidence threshold — pick one via 📂 Other folder…")
        return FlowResult(tuple(replies), keyboard=CandidatesKB(tuple(result.candidates)))

    # -- placement ---------------------------------------------------------------- #

    async def handle_more_folders(self, user_id: int, page: int = 0) -> FlowResult:
        return FlowResult(("Pick the destination folder:",), keyboard=FoldersKB(page=max(0, int(page))))

    async def handle_folder_choice(self, user_id: int, folder: str) -> FlowResult:
        resource = await self._active(user_id)
        if resource is None:
            return FlowResult((NOTHING_PENDING,))
        if resource.state not in ("AWAITING_PLACEMENT", "AWAITING_ENTRY_INFO"):
            return FlowResult((CONFIRMING_HINT if resource.state == "CONFIRMING" else PLACEMENT_HINT,))
        try:
            self.deps.settings.folder_or_reject(folder)
        except ValueError:
            await self._log("placement_rejected", user_id, resource.id, detail=f"folder={folder!r}")
            return FlowResult((UNKNOWN_FOLDER,))

        decision = await self._latest_decision(resource.id)
        iv: dict[str, Any] = {}
        if resource.kind == "github":
            parsed = parse_repo_url(resource.url)
            if parsed:
                iv["name"] = sanitize_line(parsed[1], _NAME_MAX)
            lead = _first_paragraph(resource.context)
            if lead:
                iv["description"] = lead
        if decision and decision["cost_choice"] in COST_TAGS:
            iv["cost"] = decision["cost_choice"]

        await set_resource_state(
            self.deps.conn,
            resource.id,
            "AWAITING_ENTRY_INFO",
            folder=folder,
            entry_line=_dump_iv(iv),
        )
        _transition(resource.id, resource.state, "AWAITING_ENTRY_INFO")
        await self._log("placement_chosen", user_id, resource.id, detail=f"folder={folder}")

        replies: list[str] = []
        needs_admin = decision["needs_admin"] if decision else None
        if needs_admin is not None and needs_admin >= NEEDS_ADMIN_THRESHOLD:  # S7
            replies.append(NEEDS_ADMIN_NOTE)
        replies.append(PLACED.format(folder=folder))
        next_step = await self._advance(user_id, resource.id)
        return FlowResult((*replies, *next_step.replies), next_step.keyboard)

    async def _latest_decision(self, resource_id: int) -> dict[str, Any] | None:
        """Newest decision row for needs_admin/cost recall across steps."""
        async with self.deps.conn.execute(
            "SELECT needs_admin, cost_choice FROM decisions WHERE resource_id = ? ORDER BY id DESC LIMIT 1",
            (resource_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return {"needs_admin": row["needs_admin"], "cost_choice": row["cost_choice"]}

    # -- entry interview (S14, L7-1) ---------------------------------------------- #

    @staticmethod
    def _derive_step(resource: Any, iv: dict[str, Any]) -> str:
        if not resource.folder:
            return "folder"
        if not resource.context:
            return "context"
        for field_name in IV_FIELDS:
            if field_name not in iv:
                return field_name
        return "preview"

    _QUESTIONS: dict[str, tuple[str, Any]] = {
        "name": (ASK_NAME, None),
        "description": (ASK_DESCRIPTION, None),
        "type": (ASK_TYPE, TypeKB()),
        "cost": (ASK_COST, CostKB()),
        "platforms": (ASK_PLATFORMS, None),
        "folder": (PLACEMENT_HINT, None),
        "context": (ASK_CONTEXT, None),
    }

    async def _interview_text(self, user_id: int, resource: Any, text: str) -> FlowResult:
        iv = _load_iv(resource.entry_line)
        step = self._derive_step(resource, iv)
        raw = (text or "").strip()

        if step == "folder":
            return FlowResult((PLACEMENT_HINT,))
        if step == "context":
            value = sanitize_line(raw, SUMMARY_MAX_CHARS)
            if not value:
                return FlowResult((ASK_CONTEXT,))
            await set_resource_state(self.deps.conn, resource.id, "AWAITING_ENTRY_INFO", context=value)
            return await self._advance(user_id, resource.id)
        if step == "name":
            return await self._answer_line(user_id, resource, iv, "name", raw, _NAME_MAX)
        if step == "description":
            return await self._answer_line(user_id, resource, iv, "description", raw, _DESC_MAX)
        if step == "type":
            value = raw.lower()
            if value not in ENTRY_TYPES:
                await self._log("entry_rejected", user_id, resource.id, detail="field=type")
                return FlowResult((INVALID_TYPE,), TypeKB())
            return await self._answer_field(user_id, resource, iv, "type", value)
        if step == "cost":
            value = raw.lower()
            if value not in COST_TAGS:
                await self._log("entry_rejected", user_id, resource.id, detail="field=cost")
                return FlowResult((INVALID_COST,), CostKB())
            return await self._answer_field(user_id, resource, iv, "cost", value)
        if step == "platforms":
            tokens = [t for t in _TOKEN_SPLIT_RE.split(raw) if t]
            if not tokens or tokens == ["none"]:
                return await self._answer_field(user_id, resource, iv, "platforms", [])
            cleaned: list[str] = []
            for token in tokens:
                tag = sanitize_line(token, 40)
                if not tag or any(ch in _PLATFORM_UNSAFE for ch in tag):
                    await self._log("entry_rejected", user_id, resource.id, detail="field=platforms")
                    return FlowResult((ASK_PLATFORMS,))
                cleaned.append(tag.lower())
            return await self._answer_field(user_id, resource, iv, "platforms", cleaned)
        return await self._build_preview(user_id, resource)

    async def _answer_line(
        self, user_id: int, resource: Any, iv: dict[str, Any], field_name: str, raw: str, limit: int
    ) -> FlowResult:
        """L7-1 bullet-injection guard: sanitize, then reject brackets/backticks."""
        value = sanitize_line(raw, limit)
        if not value or any(ch in value for ch in ("[", "]", "`")):
            await self._log("entry_rejected", user_id, resource.id, detail=f"field={field_name}")
            return FlowResult((INVALID_FIELD.format(label=field_name.capitalize()),))
        return await self._answer_field(user_id, resource, iv, field_name, value)

    async def _answer_field(
        self, user_id: int, resource: Any, iv: dict[str, Any], field_name: str, value: Any
    ) -> FlowResult:
        iv[field_name] = value
        await set_resource_state(
            self.deps.conn, resource.id, "AWAITING_ENTRY_INFO", entry_line=_dump_iv(iv)
        )
        await self._log("entry_stored", user_id, resource.id, detail=f"field={field_name}")
        return await self._advance(user_id, resource.id)

    async def _advance(self, user_id: int, resource_id: int) -> FlowResult:
        resource = await get_resource(self.deps.conn, resource_id)
        iv = _load_iv(resource.entry_line)
        step = self._derive_step(resource, iv)
        if step == "preview":
            return await self._build_preview(user_id, resource)
        text, keyboard = self._QUESTIONS[step]
        return FlowResult((text,), keyboard)

    async def _build_preview(self, user_id: int, resource: Any) -> FlowResult:
        iv = _load_iv(resource.entry_line)
        try:
            line = build_entry_line(
                iv.get("name", ""),
                resource.url,
                iv.get("description", ""),
                iv.get("type", ""),
                iv.get("cost", ""),
                list(iv.get("platforms", [])),
            )
        except ValueError as exc:  # defensive: field names only, no echo of values
            await self._log("entry_build_failed", user_id, resource.id, detail=str(exc))
            iv = {k: v for k, v in iv.items() if k == "platforms"}
            await set_resource_state(
                self.deps.conn, resource.id, "AWAITING_ENTRY_INFO", entry_line=_dump_iv(iv)
            )
            _transition(resource.id, resource.state, "AWAITING_ENTRY_INFO")
            return await self._advance(user_id, resource.id)
        await set_resource_state(self.deps.conn, resource.id, "CONFIRMING", entry_line=line)
        _transition(resource.id, resource.state, "CONFIRMING")
        await self._log("entry_preview", user_id, resource.id, detail=f"folder={resource.folder}")
        return FlowResult((f"{PREVIEW}\n{line}",), keyboard=ConfirmKB(resource.folder))

    async def _handle_confirming_text(self, user_id: int, resource: Any, text: str) -> FlowResult:
        """T2 (S2-S4.3/S4.4): a pasted line while CONFIRMING is a bullet edit attempt.

        ``parse_entry_line`` → URL lock against the reviewed link (``_canonical_url``,
        S3) → rebuild through ``build_entry_line`` so the interview caps stay
        single-sourced → persist and re-send the very same confirmation as
        ``_build_preview`` does. Every rejection answers exactly one user-safe
        error naming the problem plus the copyable current bullet; state, bullet
        and the ✅/❌ bubble stay untouched, so the edit may be retried freely.
        The L7-1 bracket/backtick guard is deliberately NOT reused here — a
        bullet legitimately carries brackets and backticked tags (spec L5).
        """
        retry = _code_block(resource.entry_line)

        try:
            parsed = parse_entry_line(text)
        except EntryLineError as exc:  # T1 messages name one problem, payload-free
            await self._log("entry_edit_rejected", user_id, resource.id, detail=str(exc))
            error = _html_escape(sanitize_line(str(exc), EDIT_RETRY_DETAIL_MAX))
            return FlowResult((error, retry), parse_mode=PARSE_HTML)

        if _canonical_url(parsed.url) != _canonical_url(resource.url):
            await self._log("entry_edit_rejected", user_id, resource.id, detail="reason=url-changed")
            return FlowResult((EDIT_URL_LOCKED, retry), parse_mode=PARSE_HTML)

        # L5 rebuild mapping: tags[0] = "type:x", next only if a cost tag, rest
        # are platform tags. A tagless (or bad-type) paste parses but cannot be
        # rebuilt — surface S4.4, never crash.
        head = parsed.tags[0] if parsed.tags else ""
        type_tag = head[len("type:"):] if head.startswith("type:") else ""
        if type_tag not in ENTRY_TYPES:
            await self._log("entry_edit_rejected", user_id, resource.id, detail="reason=type-tag")
            return FlowResult((EDIT_NO_TYPE_TAG, retry), parse_mode=PARSE_HTML)
        platform_tags = list(parsed.tags[1:])
        cost_tag = ""
        if platform_tags and platform_tags[0] in COST_TAGS:
            cost_tag = platform_tags.pop(0)

        try:
            new_line = build_entry_line(
                parsed.name, resource.url, parsed.description, type_tag, cost_tag, platform_tags
            )
        except ValueError as exc:  # defensive: parse already enforced the caps
            await self._log("entry_edit_rejected", user_id, resource.id, detail=str(exc))
            return FlowResult((EDIT_FAILED, retry), parse_mode=PARSE_HTML)

        await set_resource_state(
            self.deps.conn, resource.id, "CONFIRMING", entry_line=new_line
        )
        await self._log("entry_edited", user_id, resource.id, detail=f"folder={resource.folder}")
        return FlowResult((f"{PREVIEW}\n{new_line}",), keyboard=ConfirmKB(resource.folder))

    # -- confirm / commit (S13, S16) ----------------------------------------------- #

    async def handle_confirm(self, user_id: int) -> FlowResult:
        resource = await self._active(user_id)
        if resource is None:
            return FlowResult((NOTHING_PENDING,))
        if resource.state != "CONFIRMING":
            return FlowResult((CONFIRMING_HINT,))
        stored = await get_github_token(self.deps.conn, user_id)
        if stored is None:
            await self._log("confirm_missing_pat", user_id, resource.id)
            return FlowResult((NEED_TOKEN_FOR_LINK,))
        try:
            token = decrypt_pat(self.deps.settings, stored.enc_token)
        except ValueError:
            await self._log("pat_invalid", user_id, resource.id)
            return FlowResult((DECRYPT_FAILED,))

        # L11-b: the traversal gate is the last word here. A folder that is not
        # a configured category (tampered/stale DB row) must never reach GitHub;
        # the resource stays CONFIRMING so /cancel works and the operator keeps
        # the audit trail instead of an unhandled traceback in the log.
        try:
            path = self.deps.settings.readme_path(resource.folder)
        except ValueError:
            await self._log(
                "commit_rejected",
                user_id,
                resource.id,
                detail=f"folder={sanitize_line(str(resource.folder or ''))}",
            )
            return FlowResult((COMMIT_REJECTED,))
        client = self.deps.make_github(token)
        try:
            commit_url, status = await client.commit_entry(
                path,
                resource.entry_line,
                self.deps.settings.target_branch,
                leaf_title_from_path(path),
                _first_paragraph(resource.context),
            )
        except DuplicateError as exc:
            logger.warning("commit_duplicate res=%s: %s", resource.id, str(exc))
            await self._log("commit_duplicate", user_id, resource.id, detail=str(exc))
            return FlowResult((str(exc),))
        except FetchError as exc:  # L7-5: audited verbatim, reminded publicly
            logger.warning("commit_failed res=%s: %s", resource.id, str(exc))
            await self._log("commit_failed", user_id, resource.id, detail=str(exc))
            return FlowResult((str(exc) + COMMIT_PUBLIC_REMINDER,))
        await set_resource_state(self.deps.conn, resource.id, "COMMITTED", commit_url=commit_url)
        _transition(resource.id, resource.state, "COMMITTED")
        logger.info("milestone=commit_done res=%s url=%s", resource.id, commit_url)
        await self._log("committed", user_id, resource.id, detail=commit_url)
        return FlowResult(
            (
                COMMITTED_REPLY.format(status=status, url=commit_url),
                f"Everything is on file in the audit trail (resource #{resource.id}).",
            )
        )

    async def handle_cancel(self, user_id: int) -> FlowResult:
        resource = await self._active(user_id)
        if resource is None:
            return FlowResult((NOTHING_PENDING,))
        await set_resource_state(self.deps.conn, resource.id, "CANCELLED")
        _transition(resource.id, resource.state, "CANCELLED")
        await self._log("cancelled", user_id, resource.id, detail=f"was={resource.state}")
        return FlowResult((CANCELLED_MSG,))

    async def handle_forget(self, user_id: int) -> FlowResult:
        await self._touch(user_id, None)
        await delete_github_token(self.deps.conn, user_id)
        await self._log("pat_forgotten", user_id)
        return FlowResult((FORGOTTEN,))

    async def handle_unauthorized(self, user_id: int | None, username: str | None) -> FlowResult:
        """S9: silent to the chat. The only user-facing effect is none; an audit
        row is written and an operator-facing WARNING records the ignored update
        (id + username only, no content)."""
        logger.warning("unauthorized_ignored res=unknown id=%s user=%s", user_id, username or "")
        await self._log("unauthorized_ignored", user_id, detail=f"user={username or ''}")
        return FlowResult()
