"""Repo mirror sync (repo-mirror-dedup T2; Specs S2, S3, S4, S7).

The target repo is the source of truth for what is already published: humans
edit leaf READMEs outside the bot, and its links must block intake anyway.
This service indexes every URL listed as a markdown bullet inside any
``README.md`` of ``settings.target_repo`` at ``settings.target_branch`` into
the ``mirror_links`` tables, incrementally:

* one recursive ``git/trees`` call per run gives the branch-tip tree sha plus
  every README blob sha (S3: a quiet repo costs exactly one API call);
* if the tree sha equals ``mirror_state.head_sha`` the repo did not move and
  the run short-circuits without any fetch;
* otherwise only READMEs whose blob sha changed are refetched, via the raw
  host (no API rate limit — same pattern as ``category_sync``);
* READMEs that vanished prune their rows; URLs that stay are refreshed.

Failure policy (S7): a README fetch that fails (non-200/transport error)
keeps that folder's previous rows and does NOT store the new blob sha, and
``mirror_state`` only pins to a head sha after a fully clean pass — so the
next tick re-derives exactly the failed files and retries them. A tree-call
failure raises :class:`MirrorSyncError` (never ``SystemExit``: this runs
inside the bot process) and leaves the whole mirror intact.

URL identity is :func:`app.services.github.canonical_url_key` — the single
canonicalization shared by intake and commit-time dedup; nothing here may
invent a second normalization.

:func:`mirror_sync_loop` is the long-lived task: one sync **immediately at
startup** (S4 — this also recovers a deleted DB or an offline gap, because
``mirror_state`` is then absent/stale), then one per
``settings.mirror_sync_interval_hours`` (S3, default hourly). The loop awaits
each pass sequentially, so passes can never overlap, and every error is
logged and retried at the next tick.
"""

from __future__ import annotations

import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable
from urllib.parse import quote

import httpx

from app.db.repository import (
    delete_mirror_file,
    get_mirror_state,
    list_mirror_files,
    replace_mirror_file_links,
    set_mirror_file_sha,
    set_mirror_state,
)
from app.logging_config import get_logger
from app.services.category_sync import API_ROOT, RAW_ROOT
from app.services.github import canonical_url_key

logger = get_logger(__name__)

USER_AGENT = "hackpot-bot-repo-mirror"
README_SUFFIX = "/README.md"

# GitHub's recursive tree for a curated docs repo is never expected anywhere
# near the 100k-entry truncation limit; if it ever is, refusing beats indexing
# a knowingly incomplete mirror (same rule category_sync applies to leaves).
_FETCH_WORKERS = 8


class MirrorSyncError(RuntimeError):
    """The mirror could not observe the repo state this pass (S7)."""


# --------------------------------------------------------------- extraction #

_BULLET_RE = re.compile(r"^\s*[-*+]\s")
_MD_LINK_RE = re.compile(r"\[[^\]]*\]\((https?://[^\s)]+)\)")


def extract_readme_links(text: str) -> list[tuple[str, str]]:
    """``[(url_key, url)]`` for every https link inside a bullet line.

    Entries — machine-written or hand-added — are bullets in this repo's
    format, so only bullet lines count: paragraph links (cross-references,
    prose) are deliberately ignored to avoid false "already committed" hits.
    mailto/anchor/relative links never match. Keys are canonical
    (:func:`canonical_url_key`); duplicates inside one file collapse to the
    first occurrence, preserving file order for stable debugging. HTML
    comments are skipped whole — the leaf template's format hint is a comment
    and must not index its example URL.
    """
    links: list[tuple[str, str]] = []
    seen: set[str] = set()
    in_comment = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if in_comment:
            if "-->" in line:
                in_comment = False
            continue
        if line.startswith("<!--"):
            if "-->" not in line:
                in_comment = True
            continue
        if not _BULLET_RE.match(raw):
            continue
        for url in _MD_LINK_RE.findall(raw):
            key = canonical_url_key(url)
            if key and key not in seen:
                seen.add(key)
                links.append((key, url))
    return links


# ------------------------------------------------------------------ network #


def folder_for_readme(path: str) -> str | None:
    """Mirror folder key for a blob path: README.md → its directory ('' = root).

    Only exact ``README.md`` blobs count; the repo is authored in that shape
    (the bot writes it, the contribution guide prescribes it).
    """
    if path == "README.md":
        return ""
    if path.endswith(README_SUFFIX):
        return path[: -len(README_SUFFIX)]
    return None


def raw_url(repo: str, branch: str, path: str) -> str:
    return f"{RAW_ROOT}/{repo}/{quote(branch, safe='')}/{quote(path, safe='/')}"


def parse_tree_response(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Validate a git/trees payload → (head tree sha, entries). Refuse truncation."""
    if data.get("truncated"):
        raise MirrorSyncError("GitHub truncated the tree (>100k entries) — mirror would be blind")
    sha = data.get("sha") or ""
    if not sha:
        raise MirrorSyncError("git/trees response carried no tree sha")
    return sha, data.get("tree") or []


def fetch_tree_with_sha(repo: str, branch: str, token: str | None) -> tuple[str, list[dict[str, Any]]]:
    """One recursive git/trees call → (tree sha, entries). Raises MirrorSyncError."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{API_ROOT}/repos/{repo}/git/trees/{quote(branch, safe='')}"
    try:
        resp = httpx.get(url, headers=headers, params={"recursive": "1"},
                         timeout=30.0, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise MirrorSyncError(f"GitHub tree request failed: {exc}") from exc
    if resp.status_code != 200:
        raise MirrorSyncError(f"GitHub tree call returned HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise MirrorSyncError("GitHub tree response was not JSON") from exc
    return parse_tree_response(data)


def fetch_raw_text(url: str, token: str | None) -> str | None:
    """Fetch one raw file; None on any transport failure or non-200 (S7 retry signal)."""
    headers = {"User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = httpx.get(url, headers=headers, timeout=30.0, follow_redirects=True)
    except httpx.HTTPError:
        return None
    return resp.text if resp.status_code == 200 else None


def _fetch_batch(
    urls: list[str], token: str | None, fetch_raw: Callable[[str, str | None], str | None],
    workers: int = _FETCH_WORKERS,
) -> dict[str, str | None]:
    """Fetch all urls in threads (sync httpx, off the event loop by the caller)."""
    if not urls:
        return {}
    with ThreadPoolExecutor(max_workers=min(workers, len(urls))) as pool:
        return dict(zip(urls, pool.map(lambda u: fetch_raw(u, token), urls)))


# -------------------------------------------------------------------- sync #

MirrorResult = dict[str, Any]


async def sync_mirror_once(
    settings: Any,
    conn: Any,
    *,
    fetch_tree: Callable[..., tuple[str, list[dict[str, Any]]]] = fetch_tree_with_sha,
    fetch_raw: Callable[[str, str | None], str | None] = fetch_raw_text,
    to_thread: Callable[..., Any] = asyncio.to_thread,
) -> MirrorResult:
    """One incremental mirror pass. Raises MirrorSyncError when the tree call fails.

    Returns ``{status, head_sha, fetched, removed, failed, links}`` where
    status is "unchanged" (head sha match, zero fetches — S3) or "synced".
    """
    token = None
    secret = getattr(settings, "github_token", None)
    if secret is not None:
        token = secret.get_secret_value() or None
    repo, branch = settings.target_repo, settings.target_branch

    head_sha, tree = await to_thread(fetch_tree, repo, branch, token)
    state = await get_mirror_state(conn)
    if state is not None and state.head_sha == head_sha:
        await set_mirror_state(conn, head_sha)  # refresh synced_at only
        logger.debug("mirror unchanged head=%s repo=%s@%s", head_sha, repo, branch)
        return {"status": "unchanged", "head_sha": head_sha, "fetched": 0,
                "removed": [], "failed": 0, "links": 0}

    live: dict[str, str] = {}  # folder -> blob sha
    for entry in tree:
        if entry.get("type") != "blob":
            continue
        folder = folder_for_readme(entry.get("path", ""))
        if folder is not None and entry.get("sha"):
            live[folder] = entry["sha"]

    stored = await list_mirror_files(conn)
    changed = sorted(folder for folder, sha in live.items() if stored.get(folder) != sha)
    removed = sorted(folder for folder in stored if folder not in live)
    for folder in removed:
        await delete_mirror_file(conn, folder)

    urls = [raw_url(repo, branch, f"{folder}{README_SUFFIX}" if folder else "README.md")
            for folder in changed]
    texts: dict[str, str | None] = {}
    if urls:
        texts = await to_thread(_fetch_batch, urls, token, fetch_raw)

    failed = 0
    links_total = 0
    for folder, url in zip(changed, urls):
        text = texts.get(url)
        if text is None:
            failed += 1  # S7: keep old rows, skip storing the sha, retry next tick
            continue
        links = extract_readme_links(text)
        await replace_mirror_file_links(conn, folder, links)
        await set_mirror_file_sha(conn, folder, live[folder])
        links_total += len(links)

    # Pin the head sha only after a fully clean pass: a pending failure keeps
    # the state stale on purpose so the next tick re-derives the changed set.
    if failed == 0:
        await set_mirror_state(conn, head_sha)
    else:
        logger.warning("mirror: %d README fetch(es) failed — retrying them next tick", failed)

    return {"status": "synced", "head_sha": head_sha, "fetched": len(changed),
            "removed": removed, "failed": failed, "links": links_total}


# --------------------------------------------------------------------- loop #


async def mirror_sync_loop(
    settings: Any,
    conn: Any,
    *,
    sleep: Callable[[float], Any] = asyncio.sleep,
    sync: Callable[..., Any] = sync_mirror_once,
) -> None:
    """Mirror sync for the life of the bot process (S4): once at startup, then
    every ``settings.mirror_sync_interval_hours``.

    The startup pass is also the recovery path: a deleted DB (no
    ``mirror_state`` row) or an offline gap (stale head sha) makes that first
    pass re-index what it cannot confirm. Passes run sequentially (no
    overlap), and every failure is logged and retried at the next tick — the
    loop exits only when cancelled by shutdown.
    """
    interval_hours = float(getattr(settings, "mirror_sync_interval_hours", 1.0))
    interval = interval_hours * 3600.0
    logger.info(
        "mirror sync: running now at startup, then every %.2f h (repo=%s@%s)",
        interval_hours, getattr(settings, "target_repo", "?"), getattr(settings, "target_branch", "?"),
    )
    while True:
        try:
            result = await sync(settings, conn)
            if result.get("status") == "synced":
                logger.info(
                    "mirror synced: head=%s refetched=%d removed=%d failed=%d links=%d",
                    result.get("head_sha", ""), result.get("fetched", 0),
                    len(result.get("removed", [])), result.get("failed", 0),
                    result.get("links", 0),
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("mirror sync failed — keeping the previous mirror state; retrying next tick")
        await sleep(interval)
