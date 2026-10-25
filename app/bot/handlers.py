"""Thin aiogram adapters (T6; Specs S2, S9, S12).

Every handler runs the same safety chain BEFORE any flow work:
  1. ``is_authorized`` — unauthorized chats are silently audited (S9);
  2. ``RateLimiter.allow`` — over-budget gets exactly one "slow down" reply;
  3. only then the update is translated into a ResourceFlow call and the
     returned FlowResult is rendered (replies, keyboard, deletion).

No business logic lives here; flow.py owns all of it. ``deps`` and ``flow``
arrive via Dispatcher workflow kwargs (see app/main.py).
"""

from __future__ import annotations

from aiogram import F, Router
from aiogram.exceptions import TelegramAPIError
from aiogram.filters import Command, CommandStart
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, Message

from app.bot import keyboards
from app.db.repository import audit
from app.bot.flow import (
    AppDeps,
    CandidatesKB,
    ConfirmKB,
    CostKB,
    FlowResult,
    FoldersKB,
    ResourceFlow,
    SLOW_DOWN,
    TypeKB,
)
from app.security.authz import is_authorized

router = Router()


def precheck(deps: AppDeps, user_id: int | None) -> str:
    """Safety chain verdict: 'ok' | 'unauthorized' | 'rate_limited'.

    Authorization is checked first and never consumes the rate-limit budget.
    """
    if not is_authorized(deps.settings, user_id):
        return "unauthorized"
    if not deps.limiter.allow(user_id):  # type: ignore[arg-type]
        return "rate_limited"
    return "ok"


def render_keyboard(deps: AppDeps, result: FlowResult) -> InlineKeyboardMarkup | None:
    spec = result.keyboard
    if spec is None:
        return None
    folders = sorted(deps.settings.categories)
    if isinstance(spec, CandidatesKB):
        return keyboards.candidates_kb(list(spec.candidates), folders)
    if isinstance(spec, FoldersKB):
        return keyboards.folders_kb(folders, page=spec.page)
    if isinstance(spec, TypeKB):
        return keyboards.type_kb()
    if isinstance(spec, CostKB):
        return keyboards.cost_kb()
    if isinstance(spec, ConfirmKB):
        return keyboards.confirm_kb(spec.folder)
    return None


async def _send(message: Message, deps: AppDeps, result: FlowResult) -> None:
    """Reply each text; the keyboard rides on the final reply."""
    last = len(result.replies) - 1
    for index, text in enumerate(result.replies):
        markup = render_keyboard(deps, result) if index == last else None
        await message.answer(text, reply_markup=markup)
    if result.delete_message:
        try:
            await message.delete()
        except TelegramAPIError:
            pass  # deletion is best-effort; capture already happened


async def _guard_message(
    message: Message, deps: AppDeps, flow: ResourceFlow
) -> tuple[bool, int | None, str]:
    """Returns (proceed, user_id, username). Side effects for blocked cases."""
    user_id = message.from_user.id if message.from_user else None
    username = (message.from_user.username or "") if message.from_user else ""
    verdict = precheck(deps, user_id)
    if verdict == "unauthorized":
        await flow.handle_unauthorized(user_id, username)  # silent, audit only
        return False, user_id, username
    if verdict == "rate_limited":
        await message.answer(SLOW_DOWN)  # the single allowed reply
        await audit(deps.conn, "rate_limited", tg_user_id=user_id)
        return False, user_id, username
    return True, user_id, username


# ------------------------------------------------------------------ commands


@router.message(CommandStart())
async def cmd_start(message: Message, deps: AppDeps, flow: ResourceFlow) -> None:
    proceed, user_id, username = await _guard_message(message, deps, flow)
    if not proceed:
        return
    await _send(message, deps, await flow.handle_start(user_id, username))


@router.message(Command("help"))
async def cmd_help(message: Message, deps: AppDeps, flow: ResourceFlow) -> None:
    proceed, _, _ = await _guard_message(message, deps, flow)
    if not proceed:
        return
    await message.answer(keyboards.HELP_TEXT)


@router.message(Command("cancel"))
async def cmd_cancel(message: Message, deps: AppDeps, flow: ResourceFlow) -> None:
    proceed, user_id, _ = await _guard_message(message, deps, flow)
    if not proceed:
        return
    await _send(message, deps, await flow.handle_cancel(user_id))


@router.message(Command("forget"))
async def cmd_forget(message: Message, deps: AppDeps, flow: ResourceFlow) -> None:
    proceed, user_id, _ = await _guard_message(message, deps, flow)
    if not proceed:
        return
    await _send(message, deps, await flow.handle_forget(user_id))


# --------------------------------------------------------------------- text


@router.message(F.text)
async def on_text(message: Message, deps: AppDeps, flow: ResourceFlow) -> None:
    proceed, user_id, username = await _guard_message(message, deps, flow)
    if not proceed:
        return

    async def progress(text: str) -> None:
        """L7-4: one fast reply before the flow starts the slow decision call."""
        await message.answer(text)

    result = await flow.handle_text(user_id, username, message.text or "", progress=progress)
    await _send(message, deps, result)


# ---------------------------------------------------------------- callbacks


@router.callback_query()
async def on_callback(callback: CallbackQuery, deps: AppDeps, flow: ResourceFlow) -> None:
    user_id = callback.from_user.id if callback.from_user else None
    username = (callback.from_user.username or "") if callback.from_user else ""
    verdict = precheck(deps, user_id)
    if verdict == "unauthorized":
        await flow.handle_unauthorized(user_id, username)
        await callback.answer()  # acknowledge, say nothing (S9)
        return
    if verdict == "rate_limited":
        await callback.answer(SLOW_DOWN)  # single toast, no message sent
        await audit(deps.conn, "rate_limited", tg_user_id=user_id)
        return

    result = await flow.handle_callback(user_id, username, callback.data or "")
    if result.replies and callback.message is not None:
        text = "\n\n".join(result.replies)
        markup = render_keyboard(deps, result)
        try:
            await callback.message.edit_text(text, reply_markup=markup)
        except TelegramAPIError:
            await callback.message.answer(text, reply_markup=markup)
    await callback.answer()
