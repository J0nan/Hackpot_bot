#!/usr/bin/env python3
"""Sync Hackpot leaf categories from GitHub into .env's CATEGORIES_JSON.

Reads TARGET_REPO / TARGET_BRANCH / CATEGORIES_JSON from the env file, fetches
the repository tree in one GitHub API call, finds the live leaf directories
("NN_Domain/Sub_Category", README.md required by default), and rewrites the
CATEGORIES_JSON line so the bot follows Hackpot structure changes:

* leaves that still exist keep their refined decision criteria;
* new leaves get a placeholder criteria to improve before use;
* removed leaves are dropped (and reported).

Usage (from the repo root):
    python scripts/sync_categories.py                 # update .env (backs it up)
    python scripts/sync_categories.py --dry-run       # show the diff only
    python scripts/sync_categories.py --json-out categories.json
    GITHUB_TOKEN=... python scripts/sync_categories.py  # raises the rate limit

Only stdlib + httpx (already a project dependency) are used.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
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
    existing: dict[str, str], live: Iterable[str]
) -> tuple[dict[str, str], list[str], list[str]]:
    """Keep criteria for surviving leaves, placeholder new ones, drop removed."""
    live_sorted = sorted(set(live))
    live_set = set(live_sorted)
    merged = {path: existing.get(path) or placeholder_criteria(path) for path in live_sorted}
    added = [p for p in live_sorted if p not in existing]
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
    payload = json.dumps(categories, separators=(",", ":"))
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
    categories, added, removed = merge_categories(existing, leaves)
    validate(categories)

    for path in missing:
        print(f"  ! {path}: no README.md, skipped (use --allow-missing-readme to keep it)")
    for path in added:
        print(f"  + {path}  (placeholder criteria — refine it)")
    for path in removed:
        print(f"  - {path}  (gone from the repo)")
    if not added and not removed and not missing:
        print("  = structure unchanged, criteria preserved")
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
