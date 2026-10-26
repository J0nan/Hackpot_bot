"""Daily Hackpot category sync — the shared contract for the CLI and the bot.

Moved verbatim from ``scripts/sync_categories.py`` (the script is now a thin
CLI over this module, so its stdout and .env rewrite are unchanged) and adds
the in-process pieces the running bot uses:

* :func:`apply_refresh` — fetch the live leaf map, validate it with the same
  contract as ``Settings._check_categories`` and hot-swap
  ``settings.categories`` so the next decision request and the next category
  keyboard already use the new leaves (no restart);
* :func:`category_refresh_loop` — an asyncio task that wakes every day at the
  configured local time (default ``00:00``, ``CATEGORY_SYNC_TIME``) and runs
  the refresh; a failed sync keeps the previous categories and is retried at
  the next slot.

The repo is the source of truth (same rules as the script): leaf README intro
> existing criteria > placeholder, removed leaves dropped. When a writable
``.env`` exists (local runs), the fresh map is persisted there with a rolling
``.env.bak``; under docker compose the container has no .env, and the
in-memory swap alone keeps the running bot current.

``seconds_until_next`` uses naive local wall-clock time: around a DST change
the wake-up may land up to an hour early/late on that single day, corrected
by the next recomputation.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

import httpx

from app.config import LEAF_PATH_RE, MAX_CATEGORIES
from app.logging_config import get_logger

logger = get_logger(__name__)

API_ROOT = "https://api.github.com"
RAW_ROOT = "https://raw.githubusercontent.com"
PREFIX = "CATEGORIES_JSON="

# A placeholder that is a sentence, never empty (Settings rejects blank criteria).
_PLACEHOLDER = "Tools and resources related to {sub} ({domain}) — refine this description."


def parse_env(text: str) -> dict[str, str]:
    """Minimal KEY=VALUE reader for the env file (splits on the first '=')."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value
    return values


def humanize(leaf_or_domain: str) -> str:
    """'01_Recon_and_OSINT' -> 'Recon and OSINT'; 'Port_Scanning' -> 'Port Scanning'."""
    return re.sub(r"^\d+_", "", leaf_or_domain).replace("_", " ")


def placeholder_criteria(path: str) -> str:
    domain, _, sub = path.partition("/")
    return _PLACEHOLDER.format(sub=humanize(sub), domain=humanize(domain))


def is_placeholder(text: str) -> bool:
    """True for blank text or criteria this script generated (never hand-written)."""
    text = (text or "").strip()
    return not text or text.endswith("— refine this description.")


def extract_readme_description(text: str) -> str:
    """The leaf README's intro: first paragraph after `# Title`, before `## Resources`.

    Mirrors `app.services.github.leaf_template` (title, blank, one-paragraph
    description, `## Resources`). HTML comments are skipped; multi-line
    paragraphs are joined with spaces. '' when there is no description.
    """
    desc: list[str] = []
    past_title = False
    in_comment = False
    for raw in text.splitlines():
        line = raw.strip()
        if in_comment:
            if "-->" in line:
                in_comment = False
            continue
        if line.startswith("<!--"):
            if "-->" not in line:
                in_comment = True
            continue
        if line.startswith("#"):
            if past_title or line.startswith("##"):
                break
            past_title = True
            continue
        if not line:
            if desc:
                break
            continue
        past_title = True
        desc.append(line)
    return " ".join(desc).strip()


def extract_leaf_paths(
    tree: list[dict[str, Any]], require_readme: bool = True
) -> tuple[list[str], list[str]]:
    """Leaf category dirs from recursive git-tree entries.

    Returns (leaves, leaves_without_readme). A leaf is a tree entry whose path
    fully matches LEAF_PATH_RE; with require_readme it must also contain
    README.md, the file the bot reads (Settings.readme_path).
    """
    dirs = [
        e["path"]
        for e in tree
        if e.get("type") == "tree" and LEAF_PATH_RE.match(e.get("path", ""))
    ]
    blobs = {e["path"] for e in tree if e.get("type") == "blob"}
    leaves: list[str] = []
    missing: list[str] = []
    for path in sorted(set(dirs)):
        if not require_readme or f"{path}/README.md" in blobs:
            leaves.append(path)
        else:
            missing.append(path)
    return leaves, missing


def merge_categories(
    existing: dict[str, str],
    live: Iterable[str],
    descriptions: dict[str, str] | None = None,
    overwrite: bool = True,
) -> tuple[dict[str, str], list[str], list[str]]:
    """Build the new map; priority README intro > existing value > placeholder.

    With `overwrite=True` (the default) every leaf whose README has an intro
    takes the README text — the repo is the source of truth. With
    `overwrite=False` only blank/placeholder criteria are replaced, and
    hand-tuned values survive. Leaves with no README intro always keep their
    existing non-empty criteria or fall back to the placeholder.
    """
    descriptions = descriptions or {}
    live_sorted = sorted(set(live))
    live_set = set(live_sorted)
    merged: dict[str, str] = {}
    for path in live_sorted:
        prev = (existing.get(path) or "").strip()
        readme = (descriptions.get(path) or "").strip()
        if readme and (overwrite or is_placeholder(prev)):
            merged[path] = readme
        else:
            merged[path] = prev or placeholder_criteria(path)
    added = [p for p in live_sorted if not (existing.get(p) or "").strip()]
    removed = sorted(p for p in existing if p not in live_set)
    return merged, added, removed


def validate(categories: dict[str, str]) -> None:
    """Same contract as app.config.Settings._check_categories, fail fast."""
    if not categories:
        raise SystemExit("no leaf categories found in the repo tree — refusing to write an empty map")
    if len(categories) > MAX_CATEGORIES:
        raise SystemExit(f"{len(categories)} categories exceed the {MAX_CATEGORIES}-option model limit")
    for path, criteria in categories.items():
        if not LEAF_PATH_RE.match(path):
            raise SystemExit(f"invalid leaf category path: {path!r}")
        if not isinstance(criteria, str) or not criteria.strip():
            raise SystemExit(f"missing decision criteria for category {path!r}")


def replace_in_env(text: str, categories: dict[str, str]) -> str:
    """Rewrite (or append) the CATEGORIES_JSON line, preserving everything else."""
    payload = json.dumps(categories, separators=(",", ":"), ensure_ascii=False)
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.lstrip().startswith(PREFIX):
            terminator = line[len(line.rstrip("\r\n")):] or "\n"
            lines[i] = f"{PREFIX}{payload}{terminator}"
            return "".join(lines)
    newline = "\r\n" if "\r\n" in text else "\n"
    if text and not text.endswith(("\n", "\r")):
        text += newline
    return text + f"{newline}{PREFIX}{payload}{newline}"


def readme_raw_url(repo: str, branch: str, leaf: str) -> str:
    return f"{RAW_ROOT}/{repo}/{quote(branch, safe='')}/{quote(leaf, safe='/')}/README.md"


def fetch_readme_descriptions(
    repo: str, branch: str, leaves: list[str], token: str | None, workers: int = 8
) -> dict[str, str]:
    """Fetch each leaf's README (raw host, no API rate limit) and extract its intro.

    Leaves that 404 or fail stay absent — the merge falls back to the
    placeholder for them; one bad README never aborts the sync.
    """
    if not leaves:
        return {}
    headers = {"User-Agent": "hackpot-bot-sync-categories"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    out: dict[str, str] = {}

    def one(leaf: str) -> tuple[str, str]:
        try:
            resp = httpx.get(readme_raw_url(repo, branch, leaf), headers=headers,
                             timeout=30.0, follow_redirects=True)
        except httpx.HTTPError:
            return leaf, ""
        if resp.status_code != 200:
            return leaf, ""
        return leaf, extract_readme_description(resp.text)

    with ThreadPoolExecutor(max_workers=min(workers, len(leaves))) as pool:
        for leaf, description in pool.map(one, leaves):
            if description:
                out[leaf] = description
    return out


def fetch_tree(repo: str, branch: str, token: str | None) -> list[dict[str, Any]]:
    """One recursive git/trees call; raises SystemExit with a safe message."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "hackpot-bot-sync-categories",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{API_ROOT}/repos/{repo}/git/trees/{quote(branch, safe='')}"
    try:
        resp = httpx.get(url, headers=headers, params={"recursive": "1"}, timeout=30.0, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise SystemExit(f"GitHub request failed: {exc}") from exc
    if resp.status_code in (403, 429) and not token:
        raise SystemExit(
            "GitHub rate limit hit (60 req/h unauthenticated) — set GITHUB_TOKEN and retry."
        )
    if resp.status_code == 404:
        raise SystemExit(f"not found (404): repo {repo!r} or branch {branch!r}")
    if resp.status_code != 200:
        raise SystemExit(f"GitHub returned HTTP {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    if data.get("truncated"):
        raise SystemExit("GitHub truncated the tree (>100k entries) — cannot trust the leaf list")
    return data.get("tree", [])


def sync_once(
    existing: dict[str, str],
    repo: str,
    branch: str,
    token: str | None = None,
    *,
    overwrite: bool = True,
    require_readme: bool = True,
    readmes: bool = True,
    log: Any = None,
) -> tuple[dict[str, str], list[str], list[str], list[str], dict[str, str]]:
    """Fetch the live tree (+ leaf README intros) and return the merged map.

    One GitHub tree call plus raw README fetches; raises SystemExit exactly
    like the original script (empty/truncated/failed tree, invalid map).
    `log` receives the progress lines the CLI prints. Returns
    ``(categories, added, removed, missing, descriptions)``.
    """
    say = log if callable(log) else (lambda _message: None)
    say(f"Fetching {repo}@{branch} tree from GitHub ...")
    tree = fetch_tree(repo, branch, token)
    leaves, missing = extract_leaf_paths(tree, require_readme=require_readme)

    # By default the repo is the source of truth: every leaf's README intro is
    # fetched. keep-curated only fetches leaves that are blank/placeholder;
    # readmes=False skips fetches entirely.
    descriptions: dict[str, str] = {}
    if readmes:
        needs = [
            p for p in leaves
            if overwrite
            or not (existing.get(p) or "").strip()
            or is_placeholder(existing.get(p))
        ]
        if needs:
            say(f"Fetching {len(needs)} leaf README description(s) from raw.githubusercontent ...")
            descriptions = fetch_readme_descriptions(repo, branch, needs, token)
            say(f"  {len(descriptions)} README intro(s) found.")

    categories, added, removed = merge_categories(
        existing, leaves, descriptions, overwrite=overwrite
    )
    validate(categories)
    return categories, added, removed, missing, descriptions


def apply_refresh(
    settings: Any, env_file: Path | None = Path(".env")
) -> dict[str, str]:
    """Refresh categories for a live Settings object; never apply a bad map.

    Validates with the same contract before touching `settings` — an empty or
    malformed tree raises (translated to RuntimeError for the async loop) and
    the current categories stay in force. When `env_file` exists it is
    rewritten with a rolling ``.env.bak`` (local runs); under docker compose
    the file is absent and only the in-memory swap happens.
    """
    token = None
    secret = getattr(settings, "github_token", None)
    if secret is not None:
        token = secret.get_secret_value() or None
    overwrite = not getattr(settings, "category_sync_keep_curated", False)
    try:
        categories, *_ = sync_once(
            dict(settings.categories), settings.target_repo,
            settings.target_branch, token, overwrite=overwrite,
        )
    except SystemExit as exc:
        raise RuntimeError(f"category sync refused: {exc}") from None

    if categories != dict(settings.categories):
        settings.categories = categories  # atomic reference swap; handlers
        # read the whole map per request, so no torn state is possible.
        logger.info("categories refreshed: %d live leaf(s)", len(categories))
    else:
        logger.info("categories unchanged (%d leaf(s))", len(categories))

    if env_file is not None and env_file.exists():
        try:
            text = env_file.read_text(encoding="utf-8-sig")
            new_text = replace_in_env(text, categories)
            if new_text != text:
                shutil.copy2(env_file, env_file.with_name(env_file.name + ".bak"))
                env_file.write_text(new_text, encoding="utf-8")
                logger.info("wrote refreshed CATEGORIES_JSON to %s", env_file)
        except OSError as exc:
            logger.warning("could not update %s: %s", env_file, exc)
    return categories


def seconds_until_next(now: datetime, time_of_day: str) -> float:
    """Seconds from `now` to the next local occurrence of 'HH:MM' (strictly future)."""
    hour, minute = (int(part) for part in time_of_day.split(":"))
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


async def category_refresh_loop(
    settings: Any,
    *,
    sleep: Any = asyncio.sleep,
    to_thread: Any = asyncio.to_thread,
    refresh: Any = None,
    now: Any = None,
) -> None:
    """Daily category sync for the whole life of the bot process.

    Sleeps until ``settings.category_sync_time`` (local wall clock), runs
    :func:`apply_refresh` off the event loop, and repeats. A failed refresh
    is logged and the previous categories survive; the loop only exits when
    cancelled (bot shutdown).
    """
    if refresh is None:
        refresh = apply_refresh
    now_fn = now if callable(now) else datetime.now
    logger.info(
        "daily category sync scheduled at %s local time (repo=%s@%s)",
        settings.category_sync_time, settings.target_repo, settings.target_branch,
    )
    while True:
        try:
            delay = seconds_until_next(now_fn(), settings.category_sync_time)
            await sleep(delay)
            # fetch_* are sync httpx calls; run them outside the event loop.
            await to_thread(refresh, settings)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("category sync failed — keeping the current categories")


def utc_stamp() -> str:
    """Timestamp for CLI backup filenames (matches the original script format)."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
