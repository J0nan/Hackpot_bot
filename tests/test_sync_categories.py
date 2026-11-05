"""Tests for the shared category-sync logic — leaf extraction, merge, .env rewrite.

Covers retrieving the Hackpot leaf categories from GitHub and rewriting
CATEGORIES_JSON so .env follows repo-structure changes. The CLI wrapper itself
is pinned in tests/test_category_sync.py.
"""

from __future__ import annotations

import json

from app.services import category_sync as cs


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
    def test_finds_depth2_leaf_dirs_with_readme(self):
        leaves, missing = cs.extract_leaf_paths(BASE_TREE, require_readme=True)
        assert sorted(leaves) == [
            "01_Recon_and_OSINT/OSINT",
            "02_Web_Application/Proxies_and_Scanners",
        ]
        assert missing == []

    def test_leaf_without_readme_is_reported_not_kept(self):
        tree = BASE_TREE + _tree(("03_Network_and_Infrastructure/Wireless_and_Radio", "tree"))
        leaves, missing = cs.extract_leaf_paths(tree, require_readme=True)
        assert "03_Network_and_Infrastructure/Wireless_and_Radio" not in leaves
        assert missing == ["03_Network_and_Infrastructure/Wireless_and_Radio"]

    def test_non_matching_dirs_are_ignored(self):
        tree = BASE_TREE + _tree(
            ("01_Recon_and_OSINT/OSINT/subdir", "tree"),
            ("Tools/misc", "tree"),
            ("Extra_Dir", "tree"),
        )
        leaves, _ = cs.extract_leaf_paths(tree, require_readme=True)
        assert sorted(leaves) == [
            "01_Recon_and_OSINT/OSINT",
            "02_Web_Application/Proxies_and_Scanners",
        ]

    def test_require_readme_false_keeps_every_leaf(self):
        tree = BASE_TREE + _tree(("03_Network_and_Infrastructure/Wireless_and_Radio", "tree"))
        leaves, missing = cs.extract_leaf_paths(tree, require_readme=False)
        assert "03_Network_and_Infrastructure/Wireless_and_Radio" in leaves
        assert missing == []


class TestMergeCategories:
    def test_keeps_existing_criteria_drops_removed_adds_placeholders(self):
        existing = {
            "01_Recon_and_OSINT/OSINT": "My refined description",
            "99_Deleted_Leaf/Gone": "should disappear",
        }
        live = ["02_Web_Application/Proxies_and_Scanners", "01_Recon_and_OSINT/OSINT"]
        merged, added, removed = cs.merge_categories(existing, live)
        assert merged["01_Recon_and_OSINT/OSINT"] == "My refined description"
        assert "99_Deleted_Leaf/Gone" not in merged
        assert added == ["02_Web_Application/Proxies_and_Scanners"]
        assert removed == ["99_Deleted_Leaf/Gone"]
        assert merged["02_Web_Application/Proxies_and_Scanners"].strip()
        assert list(merged) == sorted(merged)

    def test_empty_existing_is_all_added(self):
        merged, added, removed = cs.merge_categories({}, ["01_A/B"])
        assert added == ["01_A/B"]
        assert removed == []
        assert merged["01_A/B"]

    def test_readme_descriptions_fill_new_and_placeholder_leaves(self):
        existing = {"02_Social_Engineering/Phishing": cs.placeholder_criteria(
            "02_Social_Engineering/Phishing")}
        live = ["02_Social_Engineering/Phishing", "09_Mobile/Android"]
        descs = {
            "02_Social_Engineering/Phishing": "Email phishing platforms and credential harvesting.",
            "09_Mobile/Android": "Android security tooling and labs.",
        }
        merged, _, _ = cs.merge_categories(existing, live, descs)
        assert merged["02_Social_Engineering/Phishing"] == (
            "Email phishing platforms and credential harvesting."
        )
        assert merged["09_Mobile/Android"] == "Android security tooling and labs."

    def test_default_overwrites_curated_with_readme(self):
        existing = {"01_Recon_and_OSINT/OSINT": "Hand-tuned criteria"}
        live = ["01_Recon_and_OSINT/OSINT"]
        merged, added, _ = cs.merge_categories(existing, live,
                                                {"01_Recon_and_OSINT/OSINT": "readme text"})
        assert merged["01_Recon_and_OSINT/OSINT"] == "readme text"
        assert added == []

    def test_keep_curated_preserves_hand_written_criteria(self):
        existing = {"01_Recon_and_OSINT/OSINT": "Hand-tuned criteria"}
        live = ["01_Recon_and_OSINT/OSINT"]
        merged, _, _ = cs.merge_categories(existing, live,
                                            {"01_Recon_and_OSINT/OSINT": "readme text"},
                                            overwrite=False)
        assert merged["01_Recon_and_OSINT/OSINT"] == "Hand-tuned criteria"

    def test_keep_curated_still_fills_placeholders(self):
        existing = {"02_Social_Engineering/Phishing": cs.placeholder_criteria(
            "02_Social_Engineering/Phishing")}
        merged, _, _ = cs.merge_categories(
            existing, ["02_Social_Engineering/Phishing"],
            {"02_Social_Engineering/Phishing": "Email phishing platforms."},
            overwrite=False)
        assert merged["02_Social_Engineering/Phishing"] == "Email phishing platforms."

    def test_overwrite_falls_back_to_existing_when_readme_missing(self):
        existing = {"08_Web_Application/APIs_and_Web_Services": "Hand-tuned criteria"}
        merged, _, _ = cs.merge_categories(existing, ["08_Web_Application/APIs_and_Web_Services"],
                                            {})
        assert merged["08_Web_Application/APIs_and_Web_Services"] == "Hand-tuned criteria"

    def test_missing_readme_description_falls_back_to_placeholder(self):
        merged, _, _ = cs.merge_categories({}, ["01_A/B"], {"01_A/B": ""})
        assert merged["01_A/B"] == cs.placeholder_criteria("01_A/B")


class TestIsPlaceholder:
    def test_true_for_empty_and_generated_text(self):
        assert cs.is_placeholder("")
        assert cs.is_placeholder("   ")
        assert cs.is_placeholder(cs.placeholder_criteria("01_Recon_and_OSINT/OSINT"))

    def test_false_for_curated_text(self):
        assert not cs.is_placeholder("Port scanners like nmap, masscan")


class TestExtractReadmeDescription:
    LEAF_README = (
        "# Phishing\n"
        "\n"
        "Email phishing platforms, campaign infrastructure, credential\n"
        "harvesting, and detection evasion.\n"
        "\n"
        "## Resources\n"
        "\n"
        "<!-- Format: - [Name](https://url) — what it does. -->\n"
        "\n"
        "- [GoPhish](https://gophish) — phishing platform. Tags: `type:tool` `free`\n"
    )

    def test_joins_the_first_paragraph_after_the_title(self):
        assert cs.extract_readme_description(self.LEAF_README) == (
            "Email phishing platforms, campaign infrastructure, credential "
            "harvesting, and detection evasion."
        )

    def test_stops_at_section_heading(self):
        text = "# Title\n\n## Resources\n\n- [x](https://x) — thing\n"
        assert cs.extract_readme_description(text) == ""

    def test_skips_html_comments(self):
        text = "# T\n\n<!-- note\nmulti-line\n-->\n\nReal description here.\n\n## Resources\n"
        assert cs.extract_readme_description(text) == "Real description here."

    def test_works_without_a_title_heading(self):
        assert cs.extract_readme_description("Just a paragraph.\n\n## X\n") == "Just a paragraph."

    def test_empty_input(self):
        assert cs.extract_readme_description("") == ""


class TestPlaceholderCriteria:
    def test_humanizes_domain_and_subcategory(self):
        crit = cs.placeholder_criteria("01_Recon_and_OSINT/Port_Scanning")
        assert "Port Scanning" in crit
        assert "Recon and OSINT" in crit
        assert "01_" not in crit


ENV_TEXT = "\n".join(
    [
        "# comment",
        "TARGET_REPO=HackPot-HQ/Hackpot",
        'CATEGORIES_JSON={"01_Recon_and_OSINT/OSINT":"old"}',
        "QWEN_MODEL=decision-model-preview",
        "",
    ]
)


class TestReplaceInEnv:
    def test_replaces_only_the_categories_line(self):
        cats = {"01_Recon_and_OSINT/OSINT": "new desc", "02_Web_Application/Proxies_and_Scanners": "p"}
        out = cs.replace_in_env(ENV_TEXT, cats)
        assert "# comment" in out
        assert "TARGET_REPO=HackPot-HQ/Hackpot" in out
        assert "QWEN_MODEL=decision-model-preview" in out
        assert "old" not in out
        line = next(candidate for candidate in out.splitlines() if candidate.startswith("CATEGORIES_JSON="))
        assert json.loads(line.split("=", 1)[1]) == cats

    def test_appends_when_line_missing(self):
        cats = {"01_Recon_and_OSINT/OSINT": "desc"}
        out = cs.replace_in_env("TARGET_REPO=HackPot-HQ/Hackpot\n", cats)
        assert "CATEGORIES_JSON=" in out
        line = next(candidate for candidate in out.splitlines() if candidate.startswith("CATEGORIES_JSON="))
        assert json.loads(line.split("=", 1)[1]) == cats

    def test_round_trip_json_loads_with_unicode(self):
        cats = {"01_Recon_and_OSINT/OSINT": "Tools — like nmap, masscan"}
        out = cs.replace_in_env(ENV_TEXT, cats)
        line = next(candidate for candidate in out.splitlines() if candidate.startswith("CATEGORIES_JSON="))
        assert json.loads(line.split("=", 1)[1])["01_Recon_and_OSINT/OSINT"] == (
            "Tools — like nmap, masscan"
        )


class TestParseEnvFile:
    def test_splits_first_equals_only(self):
        values = cs.parse_env(ENV_TEXT)
        assert values["TARGET_REPO"] == "HackPot-HQ/Hackpot"
        assert json.loads(values["CATEGORIES_JSON"])["01_Recon_and_OSINT/OSINT"] == "old"

    def test_ignores_comments_and_blank_lines(self):
        values = cs.parse_env("# a\n\n  # b\nKEY=value\n")
        assert values == {"KEY": "value"}
