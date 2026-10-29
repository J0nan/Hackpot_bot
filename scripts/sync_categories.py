#!/usr/bin/env python3
"""Sync Hackpot leaf categories from GitHub into .env's CATEGORIES_JSON.

Thin CLI over `app.services.category_sync` (the same logic the running bot
uses for its daily 00:00 refresh). Reads TARGET_REPO / TARGET_BRANCH /
CATEGORIES_JSON from the env file, fetches the repository tree in one GitHub
API call, finds the live leaf directories ("NN_Domain/Sub_Category", README.md
required by default), reads each leaf's README.md intro paragraph (the
one-line description under `# Title`), and rewrites the CATEGORIES_JSON line
so the bot follows Hackpot structure changes. The repo is the source of truth:

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
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.services.category_sync import (  # noqa: E402
    API_ROOT,
    PREFIX,
    RAW_ROOT,
    extract_leaf_paths,
    extract_readme_description,
    fetch_readme_descriptions,
    fetch_tree,
    humanize,
    is_placeholder,
    merge_categories,
    parse_env,
    placeholder_criteria,
    readme_raw_url,
    replace_in_env,
    sync_once,
    utc_stamp,
    validate,
)


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

    repo = args.repo or values.get("TARGET_REPO") or "HackPot-HQ/Hackpot"
    branch = args.branch or values.get("TARGET_BRANCH") or "main"
    token = os.environ.get("GITHUB_TOKEN") or values.get("GITHUB_TOKEN") or None

    try:
        existing = json.loads(values.get("CATEGORIES_JSON") or "{}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{env_path}: CATEGORIES_JSON is not valid JSON ({exc})") from exc
    if not isinstance(existing, dict):
        raise SystemExit(f"{env_path}: CATEGORIES_JSON must be a JSON object")

    categories, added, removed, missing, descriptions = sync_once(
        existing, repo, branch, token,
        overwrite=not args.keep_curated,
        require_readme=not args.allow_missing_readme,
        readmes=not args.no_readme,
        log=print,
    )

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
    print(f"{len(categories)} live leaves, {len(categories)} categories in the JSON map.")

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
            backup = env_path.with_name(f"{env_path.name}.bak.{utc_stamp()}")
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
