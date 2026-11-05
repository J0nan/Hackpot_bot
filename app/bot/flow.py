"""Bot orchestration flow — deliberately aiogram-free.

All Telegram-facing work goes through :class:`ResourceFlow`: the handlers in
app/bot/handlers.py translate Telegram objects into calls here and render the
returned :class:`FlowResult` actions. The FSM lives in the
``resources.state`` column, so every method is resume-safe.

Behavioral contracts:
  * entry name/description pass ``sanitize_line`` and are refused when they
    contain ``[``, ``]`` or a backtick (bullet-injection guard).
  * the README stored for classification is cut to ``README_EXCERPT_CHARS``
    before reaching ``classify``.
  * GitHub clients are built only via :func:`make_github_factory`, which pins
    ``settings.target_repo``.
  * :meth:`ResourceFlow.handle_decision` announces itself through the optional
    progress sink before the classify retries run.
  * FetchError/DecisionError land in audit rows; the user only sees safe text.
  * callback payloads carry indices into ``sorted(settings.categories)`` only.
  * the confirmation card carries the ``✏️ Description`` ("d") /
    ``🏷️ Tags`` ("t") row while CONFIRMING. A press answers as a new message
    with the current field in a pre-escaped ``<pre>`` block and records a
    process-local pending-edit marker. The next CONFIRMING text is the
    paste-back: rebuilt through ``build_entry_line``, persisted, re-previewed,
    and the previous card is deleted. Without a marker, CONFIRMING text only
    gets ``CONFIRMING_HINT``.
  * callback indices are parsed strictly as ASCII digits.
  * ``handle_confirm`` catches the traversal gate's ValueError from a tampered
    ``resources.folder``: it stays CONFIRMING, makes no HTTP call, and records
    a ``commit_rejected`` audit row.

Secrets: PATs are validated, Fernet-encrypted and the capture message is
flagged for deletion; plaintext tokens never appear in replies or audit.

The waiting step decides how a text update is read. Text-driven steps (PAT,
summary, interview answers, the field paste-back while its marker is set)
consume the next message directly. A text a button-driven step cannot use is
answered with the Continue/Cancel prompt (``FLOW_INTERRUPTED`` + ``ResumeKB``)
and never processed. Continue re-sends the current step's message; the
unreliable-placement context retry is button-gated too. /start during a flow
offers the same two buttons."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import aiosqlite
import httpx

from app.bot import folder_picker, manual_placement, pending_edits, rearm
from app.bot.flow_confirm import ConfirmMixin
from app.bot.flow_interview import InterviewMixin
from app.bot.flow_messages import (
    _DESC_MAX,
    _MAX_CONTEXT_CHARS,
    _NAME_MAX,
    ALREADY_COMMITTED,
    ALREADY_COMMITTED_OUTSIDE,
    ALREADY_IN_PROGRESS,
    ANALYZING,
    ASK_CONTEXT,
    ASK_DESCRIPTION,
    ASK_NAME,
    ASK_PAT_START,
    ASK_PLATFORMS,
    ASK_SUMMARY,
    ASK_TYPE,
    CANCELLED_MSG,
    COMMIT_PUBLIC_REMINDER,
    COMMIT_REJECTED,
    COMMITTED_REPLY,
    CONFIRMING_HINT,
    DECISION_UNRELIABLE_USER,
    DECRYPT_FAILED,
    EDIT_DESC_ASK,
    EDIT_DESC_EMPTY,
    EDIT_DESC_ONE_LINE,
    EDIT_DESC_TOO_LONG,
    EDIT_NO_TYPE_TAG,
    EDIT_RETRY_DETAIL_MAX,
    EDIT_TAGS_ASK,
    EDIT_TAGS_COLON,
    EDIT_TYPE_VALUE,
    EDIT_UNAVAILABLE,
    ENTRY_BUILD_FAILED,
    FLOW_INTERRUPTED,
    FORGOTTEN,
    GREETING_READY,
    INVALID_FIELD,
    INVALID_TYPE,
    MANUAL_PLACEMENT_NOTE,
    NEED_TOKEN_FOR_LINK,
    NEEDS_ADMIN_NOTE,
    NEEDS_ADMIN_THRESHOLD,
    NOTHING_PENDING,
    PAT_SAVED,
    PAT_STILL_NEEDED,
    PLACED,
    PLACEMENT_HINT,
    PREVIEW,
    README_EXCERPT_CHARS,
    SLOW_DOWN,
    STATS_EMPTY,
    STATS_NO_COMMITS,
    STATS_TAGS_EMPTY,
    SUMMARY_MAX_CHARS,
    UNKNOWN_CALLBACK,
    UNKNOWN_FOLDER,
    USAGE_HINT,
)
from app.bot.flow_stats import StatsMixin
from app.bot.flow_types import (
    CandidatesKB,
    ConfirmKB,
    FlowResult,
    FoldersKB,
    ManualKB,
    ResumeKB,
    TypeKB,
)
from app.bot.flow_utils import PARSE_HTML, _dump_iv, _first_paragraph, _load_iv, _transition
from app.config import Settings
from app.db.database import ACTIVE_STATES
from app.db.repository import (
    audit,
    create_resource,
    delete_github_token,
    find_mirror_link,
    get_active_resource_for_user,
    get_github_token,
    get_resource,
    list_resources_by_states,
    record_decision,
    save_github_token,
    set_resource_state,
    upsert_user,
)
from app.logging_config import get_logger
from app.security.rate_limit import RateLimiter
from app.security.sanitizers import sanitize_line, sanitize_url
from app.security.token_store import decrypt_pat, encrypt_pat, looks_like_token, mask
from app.services.decision import DecisionClient, DecisionError
from app.services.github import (
    ENTRY_TYPES,
    FetchError,
    GitHubClient,
    canonical_url_key,
    parse_repo_url,
)

URL_RE = re.compile(r"https?://\S+")
DUPLICATE_ELIGIBLE_STATES: tuple[str, ...] = ACTIVE_STATES + ("COMMITTED",)
_INDEX_RE = re.compile(r"^\d+$", re.ASCII)

ProgressSink = Callable[[str], Awaitable[None]]

logger = get_logger(__name__)

__all__ = [
    "ALREADY_COMMITTED",
    "ALREADY_COMMITTED_OUTSIDE",
    "ALREADY_IN_PROGRESS",
    "ANALYZING",
    "ASK_CONTEXT",
    "ASK_DESCRIPTION",
    "ASK_NAME",
    "ASK_PAT_START",
    "ASK_PLATFORMS",
    "ASK_SUMMARY",
    "ASK_TYPE",
    "CANCELLED_MSG",
    "COMMITTED_REPLY",
    "COMMIT_PUBLIC_REMINDER",
    "COMMIT_REJECTED",
    "CONFIRMING_HINT",
    "DECISION_UNRELIABLE_USER",
    "DECRYPT_FAILED",
    "EDIT_DESC_ASK",
    "EDIT_DESC_EMPTY",
    "EDIT_DESC_ONE_LINE",
    "EDIT_DESC_TOO_LONG",
    "EDIT_NO_TYPE_TAG",
    "EDIT_RETRY_DETAIL_MAX",
    "EDIT_TAGS_ASK",
    "EDIT_TAGS_COLON",
    "EDIT_TYPE_VALUE",
    "EDIT_UNAVAILABLE",
    "ENTRY_BUILD_FAILED",
    "FLOW_INTERRUPTED",
    "FORGOTTEN",
    "GREETING_READY",
    "INVALID_FIELD",
    "INVALID_TYPE",
    "MANUAL_PLACEMENT_NOTE",
    "NEEDS_ADMIN_NOTE",
    "NEED_TOKEN_FOR_LINK",
    "NOTHING_PENDING",
    "PAT_SAVED",
    "PAT_STILL_NEEDED",
    "PLACED",
    "PLACEMENT_HINT",
    "PREVIEW",
    "README_EXCERPT_CHARS",
    "SLOW_DOWN",
    "STATS_EMPTY",
    "STATS_NO_COMMITS",
    "STATS_TAGS_EMPTY",
    "SUMMARY_MAX_CHARS",
    "UNKNOWN_CALLBACK",
    "UNKNOWN_FOLDER",
    "USAGE_HINT",
    "AppDeps",
    "CandidatesKB",
    "ConfirmKB",
    "FlowResult",
    "FoldersKB",
    "ManualKB",
    "ResourceFlow",
    "ResumeKB",
    "TypeKB",
    "make_decision_factory",
    "make_github_factory",
]






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
    """Pin ``settings.target_repo`` on every GitHubClient we build."""

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














class ResourceFlow(InterviewMixin, ConfirmMixin, StatsMixin):
    """One instance per process; all state lives in SQLite."""

    def __init__(self, deps: AppDeps) -> None:
        self.deps = deps

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
        """Best-effort early feedback (a slow call must not look frozen).

        The sink is the caller's rendering concern; a refused send must never
        abort the flow or leak an internal error into chat, so failures here
        are swallowed after the audit-safe decision call proceeds anyway."""
        if progress is None:
            return
        try:
            await progress(text)
        except Exception:  # noqa: BLE001 - progress is optional UX, not a gate
            pass

    async def handle_start(self, user_id: int, username: str) -> FlowResult:
        await self._touch(user_id, username)
        await self._log("start", user_id, detail=f"user={username or ''}")
        replies: list[str] = []
        stored = await get_github_token(self.deps.conn, user_id)
        replies.append(ASK_PAT_START if stored is None else GREETING_READY)
        active = await self._active(user_id)
        if active is not None:
            replies.append(FLOW_INTERRUPTED)
            return FlowResult(tuple(replies), ResumeKB())
        return FlowResult(tuple(replies))

    async def handle_text(
        self, user_id: int, username: str, text: str, progress: ProgressSink | None = None
    ) -> FlowResult:
        """One text update. ``progress`` is the early-feedback sink."""
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
        if state == "CONFIRMING" and pending_edits.get_marker(active.id) is not None:
            return await self._handle_confirming_text(user_id, active, text)
        if not self._step_takes_text(active) and not rearm.is_armed(user_id):
            await self._log("flow_interrupted", user_id, active.id, detail=f"state={state}")
            return FlowResult((FLOW_INTERRUPTED,), ResumeKB())
        rearm.disarm(user_id)
        if state == "NEED_TOKEN":
            if looks_like_token(text):
                return await self._capture_pat(user_id, text.strip(), resume=active, progress=progress)
            await self._log("pat_reasked", user_id, active.id)
            return FlowResult((PAT_STILL_NEEDED,))
        if state == "NEED_SUMMARY":
            return await self._record_summary(user_id, active, text, progress)
        if state == "AWAITING_PLACEMENT":
            if await self._latest_decision_unreliable(active.id) and not (
                manual_placement.is_marked(active.id)
            ):
                return await self._retry_with_context(user_id, active, text, progress)
            return FlowResult((PLACEMENT_HINT,))
        if state == "AWAITING_ENTRY_INFO":
            return await self._interview_text(user_id, active, text)
        if state == "CONFIRMING":
            return await self._handle_confirming_text(user_id, active, text)
        return FlowResult((CONFIRMING_HINT,))

    def _step_takes_text(self, resource: Any) -> bool:
        """Does the waiting step take text?

        Text-driven steps — the PAT, the summary, every interview answer, and the
        ✏️/🏷️ paste-back while its marker is set — consume the next message as
        their answer directly: the Continue/Cancel prompt must NEVER interrupt
        them. Button-driven steps (the candidate/folder picker, the confirmation
        card without a pending edit, NEW) never guess: stray text there asks
        first. The unreliable-placement retry belongs to the second group: its
        invite is armed by ``_no_candidates_step`` and ends on any button press, so it flows through the arm gate."""
        state = resource.state
        if state in ("NEED_TOKEN", "NEED_SUMMARY"):
            return True
        if state == "AWAITING_ENTRY_INFO":
            return self._derive_step(resource, _load_iv(resource.entry_line)) != "folder"
        if state == "CONFIRMING":
            return pending_edits.get_marker(resource.id) is not None
        return False

    async def handle_callback(
        self,
        user_id: int,
        username: str,
        data: str,
        chat_id: int | None = None,
        message_id: int | None = None,
    ) -> FlowResult:
        """Button press. ``chat_id``/``message_id`` identify the card the press
        came from; the renderer passes them from the Telegram
        callback object itself — they are never derived from user text."""
        await self._touch(user_id, username)
        data = (data or "").strip()
        if isinstance(user_id, int) and not isinstance(user_id, bool):
            rearm.disarm(user_id)
        if data == "keep":
            return await self.handle_resume(user_id)
        folders = sorted(self.deps.settings.categories)

        if data.startswith(("c:", "f:")):
            folder = self._index_to_folder(data, folders)
            if folder is None:
                await self._log("placement_rejected", user_id, detail=f"data={data}")
                return FlowResult((UNKNOWN_FOLDER,))
            return await self.handle_folder_choice(user_id, folder)
        if data == "o":
            return await self.handle_more_folders(user_id, 0)
        if data == "m":
            return await self.handle_manual_classify(user_id)
        if data.startswith("p:"):
            page = self._parse_index(data)
            return await self.handle_more_folders(user_id, page if page is not None else 0)
        if data == "✅":
            return await self.handle_confirm(user_id)
        if data == "❌":
            return await self.handle_cancel(user_id)
        if data in ("d", "t"):
            confirming = await self._active(user_id)
            if confirming is not None and confirming.state == "CONFIRMING":
                mode = pending_edits.DESCRIPTION if data == "d" else pending_edits.TAGS
                return await self._start_field_edit(
                    user_id, confirming, mode, chat_id, message_id
                )

        active = await self._active(user_id)
        if active is not None and active.state == "AWAITING_ENTRY_INFO":
            iv = _load_iv(active.entry_line)
            step = self._derive_step(active, iv)
            if step == "type" and data in ENTRY_TYPES:
                return await self._answer_field(user_id, active, iv, "type", data)
        await self._log("callback_ignored", user_id, detail=f"data={data}")
        return FlowResult((UNKNOWN_CALLBACK,))

    @staticmethod
    def _parse_index(data: str) -> int | None:
        """Strict canonical ``^\\d+$`` payload index.

        ``c: 1``, ``c:+1``, ``c:1_0`` and ``c:١`` fail the ASCII-digit match;
        ``c:01`` matches the shape but is not how an index is ever spelled, so
        the round-trip check rejects it too. Anything that is not exactly what
        :mod:`app.bot.keyboards` produces is treated as hostile, not as a near
        miss — the resolved value is always an in-range index, never a path."""
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

    async def handle_resume(self, user_id: int) -> FlowResult:
        """▶️ Continue: re-send the current step's message.

        Text-driven steps need no arming — their next message is already the
        answer. Continue matters at button-driven steps: it re-shows the
        picker or card, and for the unreliable-placement ask it re-arms the
        context-retry invite through ``_no_candidates_step``. A stale
        press (no active resource) is audited."""
        resource = await self._active(user_id)
        if resource is None:
            await self._log("resume_stale", user_id)
            return FlowResult((NOTHING_PENDING,))
        await self._log("flow_resumed", user_id, resource.id, detail=f"state={resource.state}")
        return await self._current_step_message(user_id, resource)

    async def _current_step_message(self, user_id: int, resource: Any) -> FlowResult:
        """The message of the step the flow is waiting on, as first shown."""
        state = resource.state
        if state == "NEED_TOKEN":
            return FlowResult((PAT_STILL_NEEDED,))
        if state == "NEED_SUMMARY":
            return FlowResult((ASK_SUMMARY,))
        if state == "NEW":
            if resource.context:
                return await self.handle_decision(user_id)
            return FlowResult((USAGE_HINT,))
        if state == "AWAITING_PLACEMENT":
            if (
                await self._latest_decision_unreliable(resource.id)
                and not manual_placement.is_marked(resource.id)
            ):
                return await self._no_candidates_step(user_id, resource.id)
            return await self.handle_more_folders(user_id)
        if state == "AWAITING_ENTRY_INFO":
            iv = _load_iv(resource.entry_line)
            step = self._derive_step(resource, iv)
            if step == "preview":
                return await self._build_preview(user_id, resource)
            if step == "folder":
                return await self.handle_more_folders(user_id)
            text, keyboard = self._QUESTIONS[step]
            return FlowResult((text,), keyboard)
        if state == "CONFIRMING":
            marker = pending_edits.get_marker(resource.id)
            if marker is not None:
                parts = self._entry_parts(resource)
                if parts is not None:
                    return FlowResult(
                        self._edit_prompt(marker.mode, parts[0]), parse_mode=PARSE_HTML
                    )
            return FlowResult(
                (f"{PREVIEW}\n{resource.entry_line}",), keyboard=ConfirmKB(resource.folder)
            )
        return FlowResult((CONFIRMING_HINT,))

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
        return FlowResult(next_step.replies, next_step.keyboard, delete_message=True)

    async def _ingest_link(
        self, user_id: int, raw_url: str, progress: ProgressSink | None
    ) -> FlowResult:
        try:
            url = sanitize_url(raw_url)
        except ValueError as exc:
            await self._log("url_rejected", user_id, detail=str(exc))
            return FlowResult((str(exc), USAGE_HINT))
        kind = "github" if parse_repo_url(url) else "other"
        duplicate = await self._find_duplicate(url)
        if duplicate is not None:
            return await self._duplicate_result(user_id, duplicate)
        mirror = await find_mirror_link(self.deps.conn, canonical_url_key(url))
        if mirror is not None:
            await self._log("duplicate_mirror", user_id, detail=f"folder={mirror.folder}")
            folder_part = mirror.folder or "the repo root"
            return FlowResult((ALREADY_COMMITTED_OUTSIDE.format(folder=folder_part),))
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

    async def _find_duplicate(self, url: str) -> Any:
        """Global intake gate: canonical match against live or committed rows.

        FAILED/CANCELLED submissions are excluded, so dead rows stay
        re-submittable; list_resources_by_states orders COMMITTED first, so a
        placed match always wins over an in-flight one.
        """
        key = canonical_url_key(url)
        rows = await list_resources_by_states(self.deps.conn, DUPLICATE_ELIGIBLE_STATES)
        return next((r for r in rows if canonical_url_key(r.url) == key), None)

    async def _duplicate_result(self, user_id: int, match: Any) -> FlowResult:
        await self._log("duplicate_link", user_id, match.id, detail=f"state={match.state}")
        if match.state == "COMMITTED":
            replies = [ALREADY_COMMITTED.format(folder=match.folder or "the target repo")]
            if match.commit_url:
                replies.append(f"See {match.commit_url}.")
            return FlowResult(tuple(replies))
        folder_part = f", folder {match.folder}" if match.folder else ""
        return FlowResult(
            (ALREADY_IN_PROGRESS.format(resource_id=match.id, folder_part=folder_part),)
        )

    async def _fetch_and_decide(
        self, user_id: int, resource: Any, token: str, progress: ProgressSink | None = None
    ) -> FlowResult:
        parsed = parse_repo_url(resource.url)
        if parsed is None:
            await set_resource_state(self.deps.conn, resource.id, "NEED_SUMMARY")
            _transition(resource.id, resource.state, "NEED_SUMMARY")
            return FlowResult((ASK_SUMMARY,))
        owner, repo = parsed
        client = self.deps.make_github(token)
        try:
            meta = await client.repo_meta(owner, repo)
            readme = await client.readme(owner, repo)
        except FetchError as exc:
            safe = str(exc)
            await set_resource_state(self.deps.conn, resource.id, "NEED_SUMMARY", error=safe)
            _transition(resource.id, resource.state, "NEED_SUMMARY")
            logger.warning("fetch_failed res=%s: %s", resource.id, safe)
            await self._log("fetch_failed", user_id, resource.id, detail=safe)
            return FlowResult((safe, ASK_SUMMARY))
        await self._log("readme_fetched", user_id, resource.id, detail=f"repo={owner}/{repo}")
        logger.info("milestone=readme_fetched res=%s repo=%s/%s", resource.id, owner, repo)
        description = sanitize_line(str(meta.get("description") or ""), _DESC_MAX)
        excerpt = readme[:README_EXCERPT_CHARS]
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

    async def handle_decision(
        self, user_id: int, progress: ProgressSink | None = None
    ) -> FlowResult:
        resource = await self._active(user_id)
        if resource is None or not resource.context or resource.state not in ("NEW", "NEED_SUMMARY"):
            return FlowResult((UNKNOWN_CALLBACK,))
        excerpt = f"{resource.url}\n\n{resource.context}"
        settings = self.deps.settings
        client = self.deps.make_decision()
        await self._emit(progress, ANALYZING)
        try:
            result = await client.classify(
                ticket_id=f"T-{resource.id}",
                content=excerpt,
                categories=settings.categories,
                threshold=settings.confidence_threshold,
                max_candidates=settings.max_candidates_shown,
            )
        except DecisionError as exc:
            safe = str(exc)
            await record_decision(
                self.deps.conn,
                resource.id,
                request_id="",
                folder_choice="",
                confidence=0.0,
                probabilities={},
                needs_admin=None,
                raw_json={"error": safe},
            )
            await set_resource_state(
                self.deps.conn, resource.id, "AWAITING_PLACEMENT", error=safe
            )
            _transition(resource.id, resource.state, "AWAITING_PLACEMENT")
            logger.warning("decision_failed res=%s: %s", resource.id, safe)
            await self._log("decision_failed", user_id, resource.id, detail=safe)
            return await self._no_candidates_step(user_id, resource.id)

        top = result.candidates[0] if result.candidates else None
        await record_decision(
            self.deps.conn,
            resource.id,
            request_id=result.request_id,
            folder_choice=top.folder if top else "",
            confidence=top.probability if top else 0.0,
            probabilities={c.folder: c.probability for c in result.candidates},
            needs_admin=result.needs_admin,
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
            return await self._no_candidates_step(user_id, resource.id)
        replies.append(
            folder_picker.candidates_list_html(
                result.candidates, sorted(settings.categories)
            )
        )
        return FlowResult(
            tuple(replies),
            keyboard=CandidatesKB(tuple(result.candidates)),
            parse_mode=PARSE_HTML,
        )

    async def _no_candidates_step(self, user_id: int, resource_id: int) -> FlowResult:
        """The ask shown when the model produced no candidate.

        The message and the choice keyboard only — no folders yet: 🛠️ Manual
        classify opens the full picker, ❌ Cancel drops the resource. The
        user is armed so exactly the next text update re-runs the classification
        with extra context, any button press ends the invite, and ▶️ Continue re-offers this step armed
        again — unless manual placement was already chosen, which stays
        button-driven on the plain picker."""
        if not manual_placement.is_marked(resource_id):
            rearm.arm(user_id)
        return FlowResult((DECISION_UNRELIABLE_USER,), keyboard=ManualKB())

    async def _latest_decision_unreliable(self, resource_id: int) -> bool:
        """True when the newest decision row recorded no folder above threshold."""
        async with self.deps.conn.execute(
            "SELECT folder_choice FROM decisions WHERE resource_id = ? "
            "ORDER BY id DESC LIMIT 1",
            (resource_id,),
        ) as cursor:
            row = await cursor.fetchone()
        return row is not None and not row["folder_choice"]

    async def _retry_with_context(
        self, user_id: int, resource: Any, text: str, progress: ProgressSink | None = None
    ) -> FlowResult:
        """The armed text is extra context, not a command.

        The line is appended to the stored context (capped, newest kept) and
        the classification re-runs through :meth:`handle_decision`; if it is
        still unreliable the same step is re-offered, armed again for another
        try. Empty text re-asks without spending a model call."""
        extra = sanitize_line(text, SUMMARY_MAX_CHARS)
        if not extra:
            return await self._no_candidates_step(user_id, resource.id)
        base = resource.context or ""
        combined = f"{base}\n\n{extra}" if base else extra
        if len(combined) > _MAX_CONTEXT_CHARS:
            combined = combined[-_MAX_CONTEXT_CHARS:]
        await set_resource_state(self.deps.conn, resource.id, "NEW", context=combined)
        _transition(resource.id, resource.state, "NEW")
        await self._log(
            "context_retry", user_id, resource.id, detail=f"chars={len(extra)}"
        )
        return await self.handle_decision(user_id, progress)

    async def handle_more_folders(self, user_id: int, page: int = 0) -> FlowResult:
        """Numbered picker: full readable paths in an HTML caption, numbers as buttons."""
        page = max(0, int(page))
        folders = sorted(self.deps.settings.categories)
        return FlowResult(
            (folder_picker.folders_list_html(folders, page),),
            keyboard=FoldersKB(page=page),
            parse_mode=PARSE_HTML,
        )

    async def handle_manual_classify(self, user_id: int) -> FlowResult:
        """The user takes folder placement over.

        Marks the resource (process-local, app/bot/manual_placement.py) so the
        text-context invite is ended: later text is a stray message the
        flow-interrupt gate guards, never classification context. The full
        numbered picker opens here for the first time, and the press itself
        already disarmed any armed ask (handle_callback disarms every press).
        Valid only while placement is pending."""
        resource = await self._active(user_id)
        if resource is None:
            return FlowResult((NOTHING_PENDING,))
        if resource.state != "AWAITING_PLACEMENT":
            return FlowResult((PLACEMENT_HINT,))
        manual_placement.mark(resource.id)
        await self._log("manual_placement", user_id, resource.id)
        folders = sorted(self.deps.settings.categories)
        return FlowResult(
            (MANUAL_PLACEMENT_NOTE, folder_picker.folders_list_html(folders, 0)),
            keyboard=FoldersKB(page=0),
            parse_mode=PARSE_HTML,
        )

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
        manual_placement.clear(resource.id)

        needs_admin = await self._latest_needs_admin(resource.id)
        iv: dict[str, Any] = {}
        if resource.kind == "github":
            parsed = parse_repo_url(resource.url)
            if parsed:
                iv["name"] = sanitize_line(parsed[1], _NAME_MAX)
            lead = _first_paragraph(resource.context)
            if lead:
                iv["description"] = lead

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
        if needs_admin is not None and needs_admin >= NEEDS_ADMIN_THRESHOLD:
            replies.append(NEEDS_ADMIN_NOTE)
        replies.append(PLACED.format(folder=folder))
        next_step = await self._advance(user_id, resource.id)
        return FlowResult((*replies, *next_step.replies), next_step.keyboard)

    async def _latest_needs_admin(self, resource_id: int) -> float | None:
        """The needs_admin value of the newest decision row, shared across steps."""
        async with self.deps.conn.execute(
            "SELECT needs_admin FROM decisions WHERE resource_id = ? ORDER BY id DESC LIMIT 1",
            (resource_id,),
        ) as cursor:
            row = await cursor.fetchone()
        return None if row is None else row["needs_admin"]


    _QUESTIONS: dict[str, tuple[str, Any]] = {
        "name": (ASK_NAME, None),
        "description": (ASK_DESCRIPTION, None),
        "type": (ASK_TYPE, TypeKB()),
        "platforms": (ASK_PLATFORMS, None),
        "folder": (PLACEMENT_HINT, None),
        "context": (ASK_CONTEXT, None),
    }













    async def handle_cancel(self, user_id: int) -> FlowResult:
        resource = await self._active(user_id)
        if resource is None:
            return FlowResult((NOTHING_PENDING,))
        pending_edits.clear_marker(resource.id)
        rearm.disarm(user_id)
        manual_placement.clear(resource.id)
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
        """Silent to the chat. The only user-facing effect is none; an audit
        row is written and an operator-facing WARNING records the ignored update
        (id + username only, no content)."""
        logger.warning("unauthorized_ignored res=unknown id=%s user=%s", user_id, username or "")
        await self._log("unauthorized_ignored", user_id, detail=f"user={username or ''}")
        return FlowResult()
