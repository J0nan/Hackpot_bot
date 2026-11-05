"""Interview step handlers mixed into ResourceFlow."""

from __future__ import annotations

import re
from typing import Any

from app.bot.flow_messages import (
    _DESC_MAX,
    _NAME_MAX,
    ASK_CONTEXT,
    ASK_PLATFORMS,
    INVALID_FIELD,
    INVALID_TYPE,
    PLACEMENT_HINT,
    PREVIEW,
    SUMMARY_MAX_CHARS,
)
from app.bot.flow_types import ConfirmKB, FlowResult, TypeKB
from app.bot.flow_utils import _dump_iv, _load_iv, _transition
from app.db.repository import get_resource, set_resource_state
from app.security.sanitizers import sanitize_line
from app.services.github import ENTRY_TYPES, build_entry_line

IV_FIELDS: tuple[str, ...] = ("name", "description", "type", "platforms")
_TOKEN_SPLIT_RE = re.compile(r"[\s,;]+")
_PLATFORM_UNSAFE = set("`|'\"\\[](){}")


class InterviewMixin:
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
            await set_resource_state(
                self.deps.conn, resource.id, "AWAITING_ENTRY_INFO", context=value
            )
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
        if step == "platforms":
            tokens = [t for t in _TOKEN_SPLIT_RE.split(raw) if t]
            if not tokens or tokens == ["none"]:
                return await self._answer_field(user_id, resource, iv, "platforms", [])
            cleaned: list[str] = []
            for token in tokens:
                tag = sanitize_line(token, 40)
                if not tag or any(ch in _PLATFORM_UNSAFE for ch in tag):
                    await self._log(
                        "entry_rejected", user_id, resource.id, detail="field=platforms"
                    )
                    return FlowResult((ASK_PLATFORMS,))
                cleaned.append(tag.lower())
            return await self._answer_field(user_id, resource, iv, "platforms", cleaned)
        return await self._build_preview(user_id, resource)

    async def _answer_line(
        self,
        user_id: int,
        resource: Any,
        iv: dict[str, Any],
        field_name: str,
        raw: str,
        limit: int,
    ) -> FlowResult:
        """Sanitize, then reject brackets/backticks."""
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
                list(iv.get("platforms", [])),
            )
        except ValueError as exc:
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