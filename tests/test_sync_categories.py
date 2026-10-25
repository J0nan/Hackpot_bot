"""Tests for scripts/sync_categories.py — leaf extraction, merge, .env rewrite.

The script is not a package, so it is loaded from its file path. Specs:
auto-retrieving the Hackpot leaf categories from GitHub and rewriting
CATEGORIES_JSON so .env follows repo-structure changes.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sync_categories.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("sync_categories", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tree(*paths: tuple[str, str]) -> list[dict]:
    return [{"path": p, "type": t} for p, t in paths]


BASE_TREE = _tree(
    ("01_Recon_and_OSINT", "tree"),
    ("01_Recon_and_OSINT/OSINT", "tree"),
    ("01_Recon_and_OSINT/OSINT/README.md", "blob"),
    ("02_Web_Application", "tree"),
    ("02_Web_Application/Proxies_and_Scanners", "tree"),
    ("02_Web_Application/Proxies_and_Scanners/README.md", "blob"),
    ("README.md", "blob"),
    ("LICENSE", "blob"),
)


class TestExtractLeaves:
    def test_finds_depth2_leaf_dirs_with_readme(self, mod):
        leaves, missing = mod.extract_leaf_paths(BASE_TREE, require_readme=True)
        assert sorted(leaves) == [
            "01_Recon_and_OSINT/OSINT",
            "02_Web_Application/Proxies_and_Scanners",
        ]
        assert missing == []

    def test_leaf_without_readme_is_reported_not_kept(self, mod):
        tree = BASE_TREE + _tree(("03_Network_and_Infrastructure/Wireless_and_Radio", "tree"))
        leaves, missing = mod.extract_leaf_paths(tree, require_readme=True)
        assert "03_Network_and_Infrastructure/Wireless_and_Radio" not in leaves
        assert missing == ["03_Network_and_Infrastructure/Wireless_and_Radio"]

    def test_non_matching_dirs_are_ignored(self, mod):
        tree = BASE_TREE + _tree(
            ("01_Recon_and_OSINT/OSINT/subdir", "tree"),  # too deep
            ("Tools/misc", "tree"),                        # no NN_ prefix
            ("Extra_Dir", "tree"),                         # domain only
        )
        leaves, _ = mod.extract_leaf_paths(tree, require_readme=True)
        assert sorted(leaves) == [
            "01_Recon_and_OSINT/OSINT",
            "02_Web_Application/Proxies_and_Scanners",
        ]

    def test_require_readme_false_keeps_every_leaf(self, mod):
        tree = BASE_TREE + _tree(("03_Network_and_Infrastructure/Wireless_and_Radio", "tree"))
        leaves, missing = mod.extract_leaf_paths(tree, require_readme=False)
        assert "03_Network_and_Infrastructure/Wireless_and_Radio" in leaves
        assert missing == []


class TestMergeCategories:
    def test_keeps_existing_criteria_drops_removed_adds_placeholders(self, mod):
        existing = {
            "01_Recon_and_OSINT/OSINT": "My refined description",
            "99_Deleted_Leaf/Gone": "should disappear",
        }
        live = ["02_Web_Application/Proxies_and_Scanners", "01_Recon_and_OSINT/OSINT"]
        merged, added, removed = mod.merge_categories(existing, live)
        assert merged["01_Recon_and_OSINT/OSINT"] == "My refined description"
        assert "99_Deleted_Leaf/Gone" not in merged
        assert added == ["02_Web_Application/Proxies_and_Scanners"]
        assert removed == ["99_Deleted_Leaf/Gone"]
        # New leaf gets a non-empty placeholder and keys stay sorted.
        assert merged["02_Web_Application/Proxies_and_Scanners"].strip()
        assert list(merged) == sorted(merged)

    def test_empty_existing_is_all_added(self, mod):
        merged, added, removed = mod.merge_categories({}, ["01_A/B"])
        assert added == ["01_A/B"]
        assert removed == []
        assert merged["01_A/B"]


class TestPlaceholderCriteria:
    def test_humanizes_domain_and_subcategory(self, mod):
        crit = mod.placeholder_criteria("01_Recon_and_OSINT/Port_Scanning")
        assert "Port Scanning" in crit
        assert "Recon and OSINT" in crit
        assert "01_" not in crit


ENV_TEXT = "\n".join(
    [
        "# comment",
        "TARGET_REPO=J0nan/Hackpot",
        'CATEGORIES_JSON={"01_Recon_and_OSINT/OSINT":"old"}',
        "QWEN_MODEL=decision-model-preview",
        "",
    ]
)


class TestReplaceInEnv:
    def test_replaces_only_the_categories_line(self, mod):
        cats = {"01_Recon_and_OSINT/OSINT": "new desc", "02_Web_Application/Proxies_and_Scanners": "p"}
        out = mod.replace_in_env(ENV_TEXT, cats)
        assert "# comment" in out
        assert "TARGET_REPO=J0nan/Hackpot" in out
        assert "QWEN_MODEL=decision-model-preview" in out
        assert "old" not in out
        line = next(l for l in out.splitlines() if l.startswith("CATEGORIES_JSON="))
        assert json.loads(line.split("=", 1)[1]) == cats

    def test_appends_when_line_missing(self, mod):
        cats = {"01_Recon_and_OSINT/OSINT": "desc"}
        out = mod.replace_in_env("TARGET_REPO=J0nan/Hackpot\n", cats)
        assert "CATEGORIES_JSON=" in out
        line = next(l for l in out.splitlines() if l.startswith("CATEGORIES_JSON="))
        assert json.loads(line.split("=", 1)[1]) == cats

    def test_round_trip_json_loads_with_unicode(self, mod):
        cats = {"01_Recon_and_OSINT/OSINT": "Tools — like nmap, masscan"}
        out = mod.replace_in_env(ENV_TEXT, cats)
        line = next(l for l in out.splitlines() if l.startswith("CATEGORIES_JSON="))
        assert json.loads(line.split("=", 1)[1])["01_Recon_and_OSINT/OSINT"] == (
            "Tools — like nmap, masscan"
        )


class TestParseEnvFile:
    def test_splits_first_equals_only(self, mod):
        values = mod.parse_env(ENV_TEXT)
        assert values["TARGET_REPO"] == "J0nan/Hackpot"
        assert json.loads(values["CATEGORIES_JSON"])["01_Recon_and_OSINT/OSINT"] == "old"

    def test_ignores_comments_and_blank_lines(self, mod):
        values = mod.parse_env("# a\n\n  # b\nKEY=value\n")
        assert values == {"KEY": "value"}
