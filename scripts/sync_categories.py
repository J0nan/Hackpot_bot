#!/usr/bin/env python3
"""Sync Hackpot leaf categories from GitHub into .env's CATEGORIES_JSON.

Reads TARGET_REPO / TARGET_BRANCH / CATEGORIES_JSON from the env file, fetches
the repository tree in one GitHub API call, finds the live leaf directories
("NN_Domain/Sub_Category", README.md required by default), reads each leaf's
README.md intro paragraph (the one-line description under `# Title`), and
rewrites the CATEGORIES_JSON line so the bot follows Hackpot structure
changes. The repo is the source of truth:

* by default every leaf's criteria is OVERWRITTEN with its README intro
  (a leaf whose README has no intro keeps its previous value);
* new leaves without a README intro get a placeholder to refine;
* --keep-curated protects hand-tuned criteria (README fills only gaps);
* removed leaves are dropped (and reported).

Usage (from the repo root):
    python scripts/sync_categories.py                 # update .env (backs it up)
    python scripts/sync_categories.py --dry-run       # show the diff only
    python scripts/sync_categories.py --keep-curated  # never overwrite hand-tuned criteria
    python scripts/sync_categories.py --no-readme     # skip README fetches (fast, 1 API call)
    python scripts/sync_categories.py --json-out categories.json
    GITHUB_TOKEN=... python scripts/sync_categories.py  # raises the API rate limit

Only stdlib + httpx (already a project dependency) are used.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.config import LEAF_PATH_RE, MAX_CATEGORIES  # noqa: E402

API_ROOT = "https://api.github.com"
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


RAW_ROOT = "https://raw.githubusercontent.com"


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--env", default=".env", help="env file to read and update (default .env)")
    parser.add_argument("--repo", help="override TARGET_REPO (owner/name)")
    parser.add_argument("--branch", help="override TARGET_BRANCH")
    parser.add_argument("--dry-run", action="store_true", help="print the change, do not write .env")
    parser.add_argument("--json-out", metavar="FILE", help="also write the JSON map to FILE")
    parser.add_argument(
        "--allow-missing-readme",
        action="store_true",
        help="keep leaf dirs even without README.md (the bot reads <leaf>/README.md)",
    )
    parser.add_argument("--no-backup", action="store_true", help="do not write .env.bak before updating")
    parser.add_argument(
        "--keep-curated",
        action="store_true",
        help="do not overwrite hand-tuned criteria; README fills only blank/placeholder leaves",
    )
    parser.add_argument(
        "--no-readme",
        action="store_true",
        help="skip README fetches entirely; new leaves just get placeholders",
    )
    args = parser.parse_args(argv)

    env_path = Path(args.env)
    if env_path.exists():
        env_text = env_path.read_text(encoding="utf-8-sig")
    elif args.dry_run or args.repo:
        env_text = ""
    else:
        raise SystemExit(f"env file not found: {env_path} (use --repo/--dry-run to run without it)")
    values = parse_env(env_text)

    repo = args.repo or values.get("TARGET_REPO") or "J0nan/Hackpot"
    branch = args.branch or values.get("TARGET_BRANCH") or "main"
    token = os.environ.get("GITHUB_TOKEN") or values.get("GITHUB_TOKEN") or None

    try:
        existing = json.loads(values.get("CATEGORIES_JSON") or "{}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{env_path}: CATEGORIES_JSON is not valid JSON ({exc})") from exc
    if not isinstance(existing, dict):
        raise SystemExit(f"{env_path}: CATEGORIES_JSON must be a JSON object")

    print(f"Fetching {repo}@{branch} tree from GitHub ...")
    tree = fetch_tree(repo, branch, token)
    leaves, missing = extract_leaf_paths(tree, require_readme=not args.allow_missing_readme)

    # By default the repo is the source of truth: every leaf's README intro is
    # fetched. --keep-curated only fetches leaves that are blank/placeholder;
    # --no-readme skips fetches entirely.
    descriptions: dict[str, str] = {}
    if not args.no_readme:
        needs = [
            p for p in leaves
            if not args.keep_curated
            or not (existing.get(p) or "").strip()
            or is_placeholder(existing.get(p))
        ]
        if needs:
            print(f"Fetching {len(needs)} leaf README description(s) from raw.githubusercontent ...")
            descriptions = fetch_readme_descriptions(repo, branch, needs, token)
            print(f"  {len(descriptions)} README intro(s) found.")

    categories, added, removed = merge_categories(
        existing, leaves, descriptions, overwrite=not args.keep_curated
    )
    validate(categories)

    for path in missing:
        print(f"  ! {path}: no README.md, skipped (use --allow-missing-readme to keep it)")
    for path in added:
        tag = "criteria from README" if path in descriptions else "placeholder — refine it"
        print(f"  + {path}  ({tag})")
    for path in sorted(set(descriptions) - set(added)):
        prev = (existing.get(path) or "").strip()
        if not prev or is_placeholder(prev):
            print(f"  ~ {path}  (placeholder replaced by README intro)")
        elif descriptions[path] != prev:
            print(f"  ~ {path}  (README overwrote existing criteria)")
    for path in removed:
        print(f"  - {path}  (gone from the repo)")
    if not added and not removed and not missing and not descriptions:
        print("  = structure unchanged, criteria preserved")
    still_ph = sum(1 for v in categories.values() if is_placeholder(v))
    if still_ph:
        print(f"  {still_ph} leaf(s) still use placeholder criteria (no README intro found) — refine them.")
    print(f"{len(leaves)} live leaves, {len(categories)} categories in the JSON map.")

    if args.json_out:
        out = Path(args.json_out)
        out.write_text(json.dumps(categories, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Wrote {out}")

    new_text = replace_in_env(env_text, categories)
    if args.dry_run:
        print("--dry-run: .env not modified. New line preview:")
        line = next(l for l in new_text.splitlines() if l.startswith(PREFIX))
        print(line[:160] + ("..." if len(line) > 160 else ""))
        return 0

    if env_path.exists():
        if not args.no_backup:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup = env_path.with_name(f"{env_path.name}.bak.{stamp}")
            shutil.copy2(env_path, backup)
            print(f"Backed up to {backup.name}")
        if new_text != env_text:
            env_path.write_text(new_text, encoding="utf-8")
            print(f"Updated {env_path} — restart the bot to pick up the new categories")
        else:
            print(f"{env_path} already up to date")
    else:
        env_path.write_text(new_text, encoding="utf-8")
        print(f"Created {env_path} with CATEGORIES_JSON")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
