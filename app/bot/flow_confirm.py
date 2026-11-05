"""Confirmation and field-edit handlers mixed into ResourceFlow."""

from __future__ import annotations

from typing import Any

from app.bot import pending_edits
from app.bot.flow_messages import (
    _DESC_MAX,
    COMMIT_PUBLIC_REMINDER,
    COMMIT_REJECTED,
    COMMITTED_REPLY,
    CONFIRMING_HINT,
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
    INVALID_FIELD,
    NEED_TOKEN_FOR_LINK,
    NOTHING_PENDING,
    PREVIEW,
)
from app.bot.flow_types import ConfirmKB, FlowResult
from app.bot.flow_utils import PARSE_HTML, _code_block, _first_paragraph, _html_escape, _transition
from app.db.repository import get_github_token, set_resource_state, upsert_mirror_link
from app.logging_config import get_logger
from app.security.sanitizers import sanitize_line
from app.security.token_store import decrypt_pat
from app.services.github import (
    ENTRY_TYPES,
    LEGACY_COST_TAGS,
    DuplicateError,
    EntryLineError,
    FetchError,
    build_entry_line,
    canonical_url_key,
    leaf_title_from_path,
    parse_entry_line,
)

logger = get_logger(__name__)


class ConfirmMixin:
    def _entry_parts(
        self, resource: Any
    ) -> tuple[Any, str, list[str]] | None:
        """Rebuild pieces of the stored bullet: parsed fields + type/tags.

        ``parse_entry_line`` stays as internal plumbing: it reads the
        current description and tags back out of the canonical ``entry_line``.
        LEGACY cost words inside the tag run are dropped here, so any rebuild
        emits a cost-free bullet. Returns None when the stored line
        cannot support an edit loop (a hand-corrupted row, never a
        builder-produced one)."""
        try:
            parsed = parse_entry_line(resource.entry_line)
        except EntryLineError:
            return None
        head = parsed.tags[0] if parsed.tags else ""
        kind, sep, type_tag = head.partition(":")
        if not sep or kind != "type" or type_tag not in ENTRY_TYPES:
            return None
        platform_tags = [t for t in parsed.tags[1:] if t not in LEGACY_COST_TAGS]
        return parsed, type_tag, platform_tags


    @staticmethod
    def _edit_prompt(mode: str, parsed: Any) -> tuple[str, str]:
        """Instruction + copyable code block of the CURRENT field value."""
        if mode == pending_edits.TAGS:
            rendered = " ".join(f"`{tag}`" for tag in parsed.tags)
            return (EDIT_TAGS_ASK, _code_block(rendered))
        return (EDIT_DESC_ASK, _code_block(parsed.description))


    async def _start_field_edit(
        self,
        user_id: int,
        resource: Any,
        mode: str,
        chat_id: int | None,
        message_id: int | None,
    ) -> FlowResult:
        """Answer a "d"/"t" press as NEW messages and arm the paste-back."""
        parts = self._entry_parts(resource)
        if parts is None:
            await self._log(
                "entry_edit_rejected", user_id, resource.id, detail="reason=unrebuildable-entry"
            )
            return FlowResult((EDIT_UNAVAILABLE,), new_message=True, parse_mode=PARSE_HTML)
        parsed = parts[0]
        pending_edits.set_marker(resource.id, mode, chat_id, message_id)
        await self._log("entry_edit_requested", user_id, resource.id, detail=f"field={mode}")
        return FlowResult(
            self._edit_prompt(mode, parsed), new_message=True, parse_mode=PARSE_HTML
        )


    def _rebuild_from_description(
        self, resource: Any, parsed: Any, type_tag: str, platform_tags: list[str], text: str
    ) -> tuple[str | None, str | None]:
        """The pasted line is a DESCRIPTION only (interview guard reused)."""
        stripped = (text or "").strip()
        if "\n" in stripped or "\r" in stripped:
            return None, EDIT_DESC_ONE_LINE
        value = sanitize_line(stripped, _DESC_MAX + 1)
        if not value:
            return None, EDIT_DESC_EMPTY
        if any(ch in value for ch in ("[", "]", "`")):
            return None, INVALID_FIELD.format(label="Description")
        if len(value) > _DESC_MAX:
            return None, EDIT_DESC_TOO_LONG
        try:
            new_line = build_entry_line(
                parsed.name, resource.url, value, type_tag, platform_tags
            )
        except ValueError as exc:
            return None, _html_escape(sanitize_line(str(exc), EDIT_RETRY_DETAIL_MAX))
        return new_line, None


    def _rebuild_from_tags(
        self, resource: Any, parsed: Any, text: str
    ) -> tuple[str | None, str | None]:
        """Whitespace tokens; backticks optional; existing tag rules via build."""
        tokens = (text or "").replace("`", " ").split()
        if not tokens:
            return None, EDIT_NO_TYPE_TAG
        kind, sep, type_tag = tokens[0].partition(":")
        if not sep or kind != "type":
            return None, EDIT_NO_TYPE_TAG
        if type_tag not in ENTRY_TYPES:
            return None, EDIT_TYPE_VALUE
        rest = tokens[1:]
        if any(":" in tag for tag in rest):
            return None, EDIT_TAGS_COLON
        try:
            new_line = build_entry_line(
                parsed.name, resource.url, parsed.description, type_tag, rest
            )
        except ValueError as exc:
            return None, _html_escape(sanitize_line(str(exc), EDIT_RETRY_DETAIL_MAX))
        return new_line, None


    async def _handle_confirming_text(self, user_id: int, resource: Any, text: str) -> FlowResult:
        """The pending-edit paste pipeline.

        CONFIRMING text edits anything only while a "d"/"t" marker is set —
        without one it falls back to ``CONFIRMING_HINT``. The paste rebuilds the bullet
        through ``build_entry_line`` (caps stay single-sourced), keeping every
        field the pressed button does not edit, persists it, re-sends exactly
        the confirmation ``_build_preview`` produces and hands the previous
        card's tracked ids to the renderer for best-effort deletion. One
        rejection answers one user-safe error plus the re-offered prompt;
        state, bullet and the ✅/❌ bubble stay untouched."""
        marker = pending_edits.get_marker(resource.id)
        if marker is None:
            return FlowResult((CONFIRMING_HINT,))
        parts = self._entry_parts(resource)
        if parts is None:
            pending_edits.clear_marker(resource.id)
            await self._log(
                "entry_edit_rejected", user_id, resource.id, detail="reason=unrebuildable-entry"
            )
            return FlowResult((EDIT_UNAVAILABLE,), parse_mode=PARSE_HTML)
        parsed, type_tag, platform_tags = parts
        if marker.mode == pending_edits.TAGS:
            new_line, error = self._rebuild_from_tags(resource, parsed, text)
        else:
            new_line, error = self._rebuild_from_description(
                resource, parsed, type_tag, platform_tags, text
            )
        if error is not None:
            await self._log(
                "entry_edit_rejected", user_id, resource.id, detail=f"field={marker.mode}"
            )
            return FlowResult(
                (error, *self._edit_prompt(marker.mode, parsed)), parse_mode=PARSE_HTML
            )

        await set_resource_state(
            self.deps.conn, resource.id, "CONFIRMING", entry_line=new_line
        )
        await self._log(
            "entry_edited", user_id, resource.id,
            detail=f"field={marker.mode}; folder={resource.folder}",
        )
        pending_edits.clear_marker(resource.id)
        deletes: tuple[tuple[int, int], ...] = ()
        if marker.chat_id is not None and marker.message_id is not None:
            deletes = ((marker.chat_id, marker.message_id),)
        return FlowResult(
            (f"{PREVIEW}\n{new_line}",),
            keyboard=ConfirmKB(resource.folder),
            delete_outgoing=deletes,
        )


    async def handle_confirm(self, user_id: int) -> FlowResult:
        resource = await self._active(user_id)
        if resource is None:
            return FlowResult((NOTHING_PENDING,))
        pending_edits.clear_marker(resource.id)
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
        except FetchError as exc:
            logger.warning("commit_failed res=%s: %s", resource.id, str(exc))
            await self._log("commit_failed", user_id, resource.id, detail=str(exc))
            return FlowResult((str(exc) + COMMIT_PUBLIC_REMINDER,))
        await set_resource_state(self.deps.conn, resource.id, "COMMITTED", commit_url=commit_url)
        _transition(resource.id, resource.state, "COMMITTED")
        await upsert_mirror_link(
            self.deps.conn, canonical_url_key(resource.url), resource.url, resource.folder
        )
        logger.info("milestone=commit_done res=%s url=%s", resource.id, commit_url)
        await self._log("committed", user_id, resource.id, detail=commit_url)
        return FlowResult(
            (
                COMMITTED_REPLY.format(status=status, url=commit_url),
                f"Everything is on file in the audit trail (resource #{resource.id}).",
            )
        )

