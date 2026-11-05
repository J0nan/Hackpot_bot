"""Leaderboard handlers mixed into ResourceFlow."""

from __future__ import annotations

from typing import Any

from app.bot.flow_messages import (
    _STATS_DISPLAY_LIMIT,
    STATS_EMPTY,
    STATS_NO_COMMITS,
    STATS_TAGS_EMPTY,
)
from app.bot.flow_types import FlowResult
from app.db.repository import get_upload_leaderboard, list_resources_by_states
from app.services.github import EntryLineError, parse_entry_line


def _medal(rank: int) -> str:
    return {1: "🥇", 2: "🥈", 3: "🥉"}.get(rank, f"{rank}.")


def _links_noun(count: int) -> str:
    return f"{count} {'link' if count == 1 else 'links'}"


class StatsMixin:
    async def handle_stats(self, user_id: int, username: str | None) -> FlowResult:
        """Two read-only boards, one message each: committed links and top tags.

        Plain text (no parse mode) — usernames and tags arrive untrusted, and
        the bot-wide default of none keeps them inert.
        """
        await self._touch(user_id, username)
        await self._log("stats", user_id)
        rows = await get_upload_leaderboard(self.deps.conn)
        committed = await list_resources_by_states(self.deps.conn, ("COMMITTED",))
        return FlowResult((self._links_board(rows, user_id), self._tags_board(committed)))


    @staticmethod
    def _links_board(rows: list[Any], user_id: int) -> str:
        if not rows:
            return STATS_EMPTY
        lines = ["🏆 Committed links — per curator"]
        for rank, row in enumerate(rows[:_STATS_DISPLAY_LIMIT], start=1):
            name = f"@{row.username}" if row.username else "(no username)"
            lines.append(f"{_medal(rank)} {name} — {_links_noun(row.total)}")
        my_row = next((r for r in rows if r.tg_user_id == user_id), None)
        if my_row is None:
            lines.append(STATS_NO_COMMITS)
        elif len(rows) > _STATS_DISPLAY_LIMIT:
            rank = next(i for i, r in enumerate(rows, start=1) if r.tg_user_id == user_id)
            lines.append(f"You are #{rank} — {_links_noun(my_row.total)}")
        return "\n".join(lines)


    @staticmethod
    def _tags_board(committed: list[Any]) -> str:
        """Tag counts across COMMITTED entries, reusing the bullet parser.

        Tags are casefolded (one row per tag however it was spelled); ties
        break alphabetically so the order is stable. A tampered entry_line is
        skipped, never counted.
        """
        counts: dict[str, int] = {}
        for resource in committed:
            try:
                parsed = parse_entry_line(resource.entry_line)
            except EntryLineError:
                continue
            for tag in parsed.tags:
                key = tag.casefold()
                counts[key] = counts.get(key, 0) + 1
        if not counts:
            return STATS_TAGS_EMPTY
        lines = ["🏷️ Top tags — across committed links"]
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        for rank, (tag, n) in enumerate(ranked[:_STATS_DISPLAY_LIMIT], start=1):
            lines.append(f"{_medal(rank)} {tag} — {_links_noun(n)}")
        return "\n".join(lines)

