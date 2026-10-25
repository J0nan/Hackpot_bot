"""Tests for the GitHub service: URL detection, S13 bullets, Contents API client.

All HTTP goes through httpx.MockTransport — no network, no secrets.
Covers specs S3, S4, S13, S15, S16 and assumption A1.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest

from app.services.github import (
    COST_TAGS,
    ENTRY_TYPES,
    ConflictError,
    DuplicateError,
    FetchError,
    GitHubClient,
    build_entry_line,
    insert_entry,
    leaf_template,
    leaf_title_from_path,
    parse_repo_url,
)

TARGET = "J0nan/Hackpot"
LEAF = "01_Recon_and_OSINT/OSINT/README.md"
TOKEN = "ghp_test-secret-value"


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


class Recorder:
    """MockTransport handler serving a scripted queue of responses per call."""

    def __init__(self, responses: list[tuple[int, Any]]) -> None:
        self.responses = responses
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, payload = self.responses[len(self.requests) - 1]
        if isinstance(payload, bytes):
            return httpx.Response(status, content=payload)
        if isinstance(payload, str):
            return httpx.Response(status, text=payload)
        return httpx.Response(status, json=payload)

    @property
    def paths(self) -> list[str]:
        return [str(r.url.copy_with(query=None)) for r in self.requests]


def client_for(recorder: Recorder, token: str | None = TOKEN) -> GitHubClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder.handler))
    return GitHubClient(token, http, target_repo=TARGET)


def body_of(recorder: Recorder, index: int) -> dict[str, Any]:
    return json.loads(recorder.requests[index].content.decode("utf-8"))


# --------------------------------------------------------------------------- #
# parse_repo_url (S3, S4)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/J0nan/Hackpot", ("J0nan", "Hackpot")),
        ("https://www.github.com/J0nan/Hackpot", ("J0nan", "Hackpot")),
        ("https://github.com/J0nan/Hackpot/", ("J0nan", "Hackpot")),
        ("https://github.com/J0nan/Hackpot.git", ("J0nan", "Hackpot")),
        ("https://github.com/J0nan/Hackpot/tree/main/01_Recon/README.md", ("J0nan", "Hackpot")),
        ("https://github.com/J0nan/Hackpot/blob/main/README.md#usage", ("J0nan", "Hackpot")),
        ("https://github.com/J0nan/Hackpot/issues/3", ("J0nan", "Hackpot")),
        ("https://github.com/J0nan/Hackpot?ref=1", ("J0nan", "Hackpot")),
        ("HTTPS://GitHub.COM/J0nan/Hackpot", ("J0nan", "Hackpot")),
        ("https://GitHub.com/MixedCase/RepoName", ("MixedCase", "RepoName")),
        ("https://github.com/a.b/c-d_e.git", ("a.b", "c-d_e")),
        ("https://www.GitHub.com/x/y/", ("x", "y")),
    ],
)
def test_parse_repo_url_accepts(url: str, expected: tuple[str, str]) -> None:
    assert parse_repo_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "",
        "owner/repo",
        "J0nan/Hackpot",
        "github.com/x/y",
        "https://evil.com/github.com/x/y",
        "https://github.com.evil.com/x/y",
        "http://github.com/x/y",
        "ftp://github.com/x/y",
        "git@github.com:x/y.git",
        "https://gitlab.com/x/y",
        "https://github.com/x",
        "https://github.com/x/",
        "https://github.com//y",
        "https://github.com/x/y!",
        "https://github.com/x/ space",
        "https://github.com/" + "o" * 40 + "/repo",
        "https://github.com/owner/" + "r" * 101,
        "not a url at all",
    ],
)
def test_parse_repo_url_rejects(url: str) -> None:
    assert parse_repo_url(url) is None


def test_parse_repo_url_accepts_boundary_lengths() -> None:
    assert parse_repo_url(f"https://github.com/{'o' * 39}/{'r' * 100}") == ("o" * 39, "r" * 100)


# --------------------------------------------------------------------------- #
# build_entry_line (S13)
# --------------------------------------------------------------------------- #

def test_build_entry_line_exact_output() -> None:
    line = build_entry_line(
        "Amass", "https://github.com/owasp-amass/amass", "Subdomain enumeration", "tool", "free", ["linux"]
    )
    assert line == (
        "- [Amass](https://github.com/owasp-amass/amass) — Subdomain enumeration. "
        "`type:tool` `free` `linux`"
    )


def test_build_entry_line_omits_cost_and_platforms() -> None:
    line = build_entry_line("Nmap", "https://nmap.org", "Port scanner", "tool", "")
    assert line == "- [Nmap](https://nmap.org) — Port scanner. `type:tool`"


def test_build_entry_line_type_always_required() -> None:
    assert "`type:video`" in build_entry_line("V", "https://v.dev", "Talk", "video", "paid")
    assert set(ENTRY_TYPES) == {"tool", "course", "docs", "wordlist", "lab", "article", "video"}
    assert set(COST_TAGS) == {"free", "paid", "freemium"}


@pytest.mark.parametrize("bad_type", ["toolkit", "Tool", "", "blog"])
def test_build_entry_line_rejects_bad_type(bad_type: str) -> None:
    with pytest.raises(ValueError):
        build_entry_line("N", "https://n.dev", "Desc", bad_type, "free")


@pytest.mark.parametrize("bad_cost", ["gratis", "Free", "open"])
def test_build_entry_line_rejects_bad_cost(bad_cost: str) -> None:
    with pytest.raises(ValueError):
        build_entry_line("N", "https://n.dev", "Desc", "tool", bad_cost)


@pytest.mark.parametrize("name,url", [("", "https://a.dev"), ("  ", "https://a.dev"), ("N", ""), ("N", "   ")])
def test_build_entry_line_rejects_empty_name_or_url(name: str, url: str) -> None:
    with pytest.raises(ValueError):
        build_entry_line(name, url, "Desc", "tool", "free")


def test_build_entry_line_requires_https_url() -> None:
    with pytest.raises(ValueError):
        build_entry_line("N", "http://a.dev", "Desc", "tool", "free")


def test_build_entry_line_rejects_raw_newlines() -> None:
    with pytest.raises(ValueError):
        build_entry_line("N\nx", "https://a.dev", "Desc", "tool", "free")
    with pytest.raises(ValueError):
        build_entry_line("N", "https://a.dev", "one\ntwo", "tool", "free")


def test_build_entry_line_strips_trailing_punctuation_and_adds_period() -> None:
    for desc in ("Fast scanner", "Fast scanner.", "Fast scanner!! ", "Fast scanner;"):
        assert build_entry_line("N", "https://a.dev", desc, "tool", "free").endswith(
            "Fast scanner. `type:tool` `free`"
        )


def test_build_entry_line_dedupes_platform_tags_keeping_order() -> None:
    line = build_entry_line(
        "N", "https://a.dev", "Desc", "docs", "freemium", ["linux", "Windows", "linux", "docker"]
    )
    assert line.endswith("Desc. `type:docs` `freemium` `linux` `Windows` `docker`")


# --------------------------------------------------------------------------- #
# insert_entry (S13)
# --------------------------------------------------------------------------- #

EXISTING = (
    "# Recon and OSINT\n"
    "\n"
    "Intro text.\n"
    "\n"
    "## Resources\n"
    "\n"
    "- [Aaa](https://example.com/aaa) — A. `type:tool` `free`\n"
    "- [Zzz](https://example.com/zzz) — Z. `type:docs` `paid`\n"
    "\n"
    "## Contributing\n"
    "\n"
    "Please keep it tidy.\n"
)

ENTRY_M = "- [Mmm](https://example.com/mmm) — M. `type:tool` `free`"
ENTRY_A0 = "- [Aa0](https://example.com/aaa0) — First. `type:lab` `free`"
ENTRY_Z9 = "- [Zzz9](https://example.com/zzz9) — Last. `type:lab` `free`"


def test_insert_entry_alphabetical_first() -> None:
    text, status = insert_entry(EXISTING, ENTRY_A0)
    assert status == "inserted"
    assert "- [Aa0](https://example.com/aaa0) — First. `type:lab` `free`\n" in text
    assert text.index("[Aa0]") < text.index("[Aaa]")


def test_insert_entry_alphabetical_middle() -> None:
    text, status = insert_entry(EXISTING, ENTRY_M)
    assert status == "inserted"
    assert text == (
        "# Recon and OSINT\n"
        "\n"
        "Intro text.\n"
        "\n"
        "## Resources\n"
        "\n"
        "- [Aaa](https://example.com/aaa) — A. `type:tool` `free`\n"
        "- [Mmm](https://example.com/mmm) — M. `type:tool` `free`\n"
        "- [Zzz](https://example.com/zzz) — Z. `type:docs` `paid`\n"
        "\n"
        "## Contributing\n"
        "\n"
        "Please keep it tidy.\n"
    )


def test_insert_entry_alphabetical_last() -> None:
    text, status = insert_entry(EXISTING, ENTRY_Z9)
    assert status == "inserted"
    assert text.index("[Zzz](") < text.index("[Zzz9]")
    assert text.endswith("## Contributing\n\nPlease keep it tidy.\n")


def test_insert_entry_is_case_insensitive_by_display_name() -> None:
    text, _ = insert_entry(EXISTING, "- [Bbb](https://example.com/b) — B. `type:tool` `free`")
    assert text.index("[Aaa]") < text.index("[Bbb]") < text.index("[Zzz]")


@pytest.mark.parametrize(
    "existing_url,new_url",
    [
        ("https://example.com/aaa", "https://example.com/aaa"),
        ("https://example.com/aaa", "http://example.com/aaa"),
        ("https://example.com/aaa/", "https://example.com/aaa"),
        ("https://example.com/aaa", "https://example.com/aaa/"),
        ("https://Example.COM/aaa", "https://example.com/aaa"),
    ],
)
def test_insert_entry_duplicate_canonical_url(existing_url: str, new_url: str) -> None:
    readme = f"## Resources\n\n- [Aaa]({existing_url}) — A. `type:tool` `free`\n"
    entry = f"- [Different Name]({new_url}) — Other. `type:tool` `free`"
    text, status = insert_entry(readme, entry)
    assert status == "duplicate"
    assert text == readme


def test_insert_entry_different_path_is_not_duplicate() -> None:
    readme = "## Resources\n\n- [Aaa](https://example.com/aaa) — A. `type:tool` `free`\n"
    entry = "- [Bbb](https://example.com/bbb) — B. `type:tool` `free`"
    text, status = insert_entry(readme, entry)
    assert status == "inserted"
    assert "[Bbb]" in text


def test_insert_entry_preserves_other_sections_byte_for_byte() -> None:
    prefix = EXISTING.split("## Resources")[0]
    suffix = "## Contributing\n\nPlease keep it tidy.\n"
    text, _ = insert_entry(EXISTING, ENTRY_M)
    assert text.startswith(prefix)
    assert text.endswith(suffix)


def test_insert_entry_without_resources_section_is_unchanged() -> None:
    readme = "# Title\n\n## Other\n\n- [Aaa](https://a.dev) — A.\n"
    text, status = insert_entry(readme, ENTRY_M)
    assert status == "no-section"
    assert text == readme


def test_insert_entry_keeps_missing_trailing_newline() -> None:
    readme = "## Resources\n\n- [Zzz](https://example.com/zzz) — Z."
    text, status = insert_entry(readme, ENTRY_M)
    assert status == "inserted"
    assert text == "## Resources\n\n- [Mmm](https://example.com/mmm) — M. `type:tool` `free`\n" \
                   "- [Zzz](https://example.com/zzz) — Z."


def test_insert_entry_preserves_crlf() -> None:
    readme = "## Resources\r\n\r\n- [Zzz](https://example.com/zzz) — Z.\r\n"
    text, status = insert_entry(readme, ENTRY_M)
    assert status == "inserted"
    assert text == (
        "## Resources\r\n\r\n- [Mmm](https://example.com/mmm) — M. `type:tool` `free`\r\n"
        "- [Zzz](https://example.com/zzz) — Z.\r\n"
    )


def test_insert_entry_rejects_malformed_entry_line() -> None:
    with pytest.raises(ValueError):
        insert_entry(EXISTING, "not a bullet")


def test_insert_entry_ignores_html_comment_hint() -> None:
    readme = (
        "## Resources\n"
        "\n"
        "<!-- Format: - [Name](https://url) — what it does and why it matters. -->\n"
        "- [Zzz](https://example.com/zzz) — Z.\n"
    )
    text, status = insert_entry(readme, ENTRY_M)
    assert status == "inserted"
    assert text.index("<!-- Format") < text.index("[Mmm]") < text.index("[Zzz]")


def test_insert_entry_subsection_heading_is_not_the_section_end() -> None:
    readme = "## Resources\n\n- [Zzz](https://example.com/zzz) — Z.\n\n### Tools\n\nbody\n"
    text, status = insert_entry(readme, ENTRY_M)
    assert status == "inserted"
    assert text.index("[Mmm]") < text.index("### Tools")


# --------------------------------------------------------------------------- #
# leaf_template (A1)
# --------------------------------------------------------------------------- #

def test_leaf_template_exact_text() -> None:
    assert leaf_template("OSINT", "Open source intelligence resources.") == (
        "# OSINT\n"
        "\n"
        "Open source intelligence resources.\n"
        "\n"
        "## Resources\n"
        "\n"
        "<!-- Format: - [Name](https://url) — what it does and why it matters. Tags: "
        "`type:tool|course|docs|wordlist|lab|article|video` `free|paid|freemium` "
        "`platform or tech` -->\n"
    )


def test_leaf_template_then_insert_resulting_exact_file_text() -> None:
    entry = build_entry_line(
        "Amass", "https://github.com/owasp-amass/amass", "Subdomain enumeration", "tool", "free", ["linux"]
    )
    text, status = insert_entry(leaf_template("OSINT", "Open source intelligence resources."), entry)
    assert status == "inserted"
    assert text == (
        "# OSINT\n"
        "\n"
        "Open source intelligence resources.\n"
        "\n"
        "## Resources\n"
        "\n"
        "<!-- Format: - [Name](https://url) — what it does and why it matters. Tags: "
        "`type:tool|course|docs|wordlist|lab|article|video` `free|paid|freemium` "
        "`platform or tech` -->\n"
        "- [Amass](https://github.com/owasp-amass/amass) — Subdomain enumeration. "
        "`type:tool` `free` `linux`\n"
    )


def test_leaf_title_from_path() -> None:
    assert leaf_title_from_path("01_Recon_and_OSINT/OSINT/README.md") == "OSINT"
    assert leaf_title_from_path("02_Web_Application/Injection/README.md") == "Injection"
    assert leaf_title_from_path("01_Recon_and_OSINT/Web2/README.md") == "Web2"


# --------------------------------------------------------------------------- #
# GitHubClient headers (S4, S8)
# --------------------------------------------------------------------------- #

async def test_headers_always_include_api_contract() -> None:
    recorder = Recorder([(200, {"full_name": TARGET})])
    client = client_for(recorder, token=None)
    await client.repo_meta("J0nan", "Hackpot")
    request = recorder.requests[0]
    assert request.headers["Accept"] == "application/vnd.github+json"
    assert request.headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert request.headers["User-Agent"] == "hackpot-bot"
    assert "authorization" not in request.headers


async def test_bearer_header_only_with_token() -> None:
    recorder = Recorder([(200, {}), (200, {})])
    client = client_for(recorder, token=TOKEN)
    await client.repo_meta("J0nan", "Hackpot")
    assert recorder.requests[0].headers["Authorization"] == f"Bearer {TOKEN}"
    no_token = client_for(Recorder([(200, {})]), token=None)
    await no_token.repo_meta("J0nan", "Hackpot")


async def test_default_target_is_hackpot() -> None:
    """Shared contract: GitHubClient(token, client) must work with the S4 default repo."""
    recorder = Recorder([(200, {"sha": "sha-1", "content": b64(LEAF_README)})])
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder.handler))
    client = GitHubClient(TOKEN, http)
    assert client.target_repo == TARGET
    text, sha = await client.get_file(LEAF, "main")
    assert (text, sha) == (LEAF_README, "sha-1")
    assert recorder.paths == [f"https://api.github.com/repos/{TARGET}/contents/{LEAF}"]
    await http.aclose()


def test_rejects_invalid_target_repo() -> None:
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    with pytest.raises(ValueError):
        GitHubClient(None, http, target_repo="not-a-repo")


# --------------------------------------------------------------------------- #
# repo_meta / readme (S3, S15)
# --------------------------------------------------------------------------- #

async def test_repo_meta_happy() -> None:
    recorder = Recorder(
        [
            (
                200,
                {
                    "description": "Pentest resources",
                    "default_branch": "main",
                    "homepage": "https://hackpot.dev",
                    "stargazers_count": 12,
                },
            )
        ]
    )
    client = client_for(recorder)
    meta = await client.repo_meta("J0nan", "Hackpot")
    assert recorder.paths == ["https://api.github.com/repos/J0nan/Hackpot"]
    assert meta == {
        "description": "Pentest resources",
        "default_branch": "main",
        "homepage": "https://hackpot.dev",
        "stars": 12,
    }


async def test_repo_meta_missing_fields_become_safe_defaults() -> None:
    recorder = Recorder([(200, {"description": None, "default_branch": "trunk"})])
    meta = await client_for(recorder).repo_meta("a", "b")
    assert meta == {"description": "", "default_branch": "trunk", "homepage": "", "stars": 0}


async def test_repo_meta_404_asks_user_and_reminds_public() -> None:
    recorder = Recorder([(404, {"message": "Not Found", "documentation_url": "https://docs.github.com"})])
    client = client_for(recorder)
    with pytest.raises(FetchError) as excinfo:
        await client.repo_meta("J0nan", "private-repo")
    message = str(excinfo.value)
    assert excinfo.value.public_hint is True
    assert "public" in message.lower()
    assert "summary" in message.lower()
    assert TOKEN not in message
    assert "documentation_url" not in message


async def test_readme_decodes_base64_unicode() -> None:
    body = "# Hackpot\n\nHerramientas de pentesting — éè ñ U+00E9 and emoji: \U0001f9ea\n"
    recorder = Recorder([(200, {"name": "README.md", "content": b64(body), "encoding": "base64"})])
    client = client_for(recorder)
    assert await client.readme("J0nan", "Hackpot") == body
    assert recorder.paths == ["https://api.github.com/repos/J0nan/Hackpot/readme"]


async def test_readme_error_is_fetch_error_with_public_hint() -> None:
    recorder = Recorder([(451, {"message": "Forbidden"})])
    client = client_for(recorder)
    with pytest.raises(FetchError) as excinfo:
        await client.readme("J0nan", "blocked")
    assert excinfo.value.public_hint is True
    assert "public" in str(excinfo.value).lower()


async def test_readme_unauthorized_message_mentions_token() -> None:
    recorder = Recorder([(401, {"message": "Bad credentials"})])
    client = client_for(recorder)
    with pytest.raises(FetchError) as excinfo:
        await client.readme("J0nan", "Hackpot")
    message = str(excinfo.value)
    assert "token" in message.lower()
    assert TOKEN not in message


async def test_network_failure_becomes_fetch_error() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    http = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    client = GitHubClient(TOKEN, http, target_repo=TARGET)
    with pytest.raises(FetchError) as excinfo:
        await client.repo_meta("a", "b")
    assert excinfo.value.public_hint is True


# --------------------------------------------------------------------------- #
# get_file (S16)
# --------------------------------------------------------------------------- #

async def test_get_file_returns_text_and_sha() -> None:
    content = "# OSINT\n\n## Resources\n\n- [Aaa](https://a.dev) — A. é\n"
    recorder = Recorder([(200, {"path": LEAF, "sha": "sha-1", "content": b64(content), "encoding": "base64"})])
    client = client_for(recorder)
    text, sha = await client.get_file(LEAF, "main")
    assert (text, sha) == (content, "sha-1")
    assert recorder.requests[0].method == "GET"
    assert recorder.requests[0].url.path == f"/repos/{TARGET}/contents/{LEAF}"
    assert recorder.requests[0].url.params["ref"] == "main"


async def test_get_file_missing_returns_none() -> None:
    recorder = Recorder([(404, {"message": "Not Found", "documentation_url": "x"})])
    client = client_for(recorder)
    assert await client.get_file(LEAF, "main") == (None, "")


async def test_get_file_server_error_raises() -> None:
    recorder = Recorder([(500, {"message": "Server Error"})])
    client = client_for(recorder)
    with pytest.raises(FetchError) as excinfo:
        await client.get_file(LEAF, "main")
    assert excinfo.value.public_hint is True


async def test_get_file_directory_payload_raises() -> None:
    recorder = Recorder([(200, [{"name": "a.md"}])])
    client = client_for(recorder)
    with pytest.raises(FetchError):
        await client.get_file(LEAF, "main")


# --------------------------------------------------------------------------- #
# put_file (S8, S16)
# --------------------------------------------------------------------------- #

async def test_put_file_payload_fields_exactly() -> None:
    content = "# OSINT\n\n## Resources\n\n- [Aaa](https://a.dev) — A.\n"
    recorder = Recorder([(201, {"content": {"sha": "new"}, "commit": {"html_url": "https://github.com/c/1"}})])
    client = client_for(recorder)
    url = await client.put_file(LEAF, content, "sha-1", "docs: add entry", "main")
    assert url == "https://github.com/c/1"
    request = recorder.requests[0]
    assert request.method == "PUT"
    assert request.url.path == f"/repos/{TARGET}/contents/{LEAF}"
    body = body_of(recorder, 0)
    assert set(body) == {"message", "content", "branch", "sha"}
    assert body["message"] == "docs: add entry"
    assert body["branch"] == "main"
    assert body["sha"] == "sha-1"
    assert base64.b64decode(body["content"]).decode("utf-8") == content


async def test_put_file_omits_sha_when_creating() -> None:
    recorder = Recorder([(201, {"commit": {"html_url": "https://github.com/c/2"}})])
    client = client_for(recorder)
    url = await client.put_file(LEAF, "new", None, "docs: create", "main")
    assert url == "https://github.com/c/2"
    assert "sha" not in body_of(recorder, 0)


async def test_put_file_accepts_nested_commit_url() -> None:
    recorder = Recorder([(201, {"content": {"commit": {"html_url": "https://github.com/c/3"}}})])
    client = client_for(recorder)
    assert await client.put_file(LEAF, "x", None, "m", "main") == "https://github.com/c/3"


async def test_put_file_409_raises_conflict_error() -> None:
    recorder = Recorder([(409, {"message": "conflict"})])
    client = client_for(recorder)
    with pytest.raises(ConflictError):
        await client.put_file(LEAF, "x", "sha-1", "m", "main")


async def test_put_file_403_mentions_contents_write() -> None:
    recorder = Recorder([(403, {"message": "Resource not accessible by integration"})])
    client = client_for(recorder)
    with pytest.raises(FetchError) as excinfo:
        await client.put_file(LEAF, "x", "sha-1", "m", "main")
    message = str(excinfo.value)
    assert "contents:write" in message
    assert TARGET in message
    assert "token" in message.lower()
    assert TOKEN not in message


# --------------------------------------------------------------------------- #
# commit_entry (S13, S16, A1)
# --------------------------------------------------------------------------- #

LEAF_README = (
    "# OSINT\n"
    "\n"
    "## Resources\n"
    "\n"
    "- [Aaa](https://example.com/aaa) — A. `type:tool` `free`\n"
    "- [Zzz](https://example.com/zzz) — Z. `type:tool` `free`\n"
)

ENTRY = "- [Mmm](https://example.com/mmm) — M. `type:tool` `free`"


async def test_commit_entry_inserts_into_existing_readme() -> None:
    recorder = Recorder(
        [
            (200, {"sha": "sha-1", "content": b64(LEAF_README)}),
            (201, {"commit": {"html_url": "https://github.com/c/insert"}}),
        ]
    )
    client = client_for(recorder)
    url, status = await client.commit_entry(LEAF, ENTRY, "main", "OSINT", "desc")
    assert (url, status) == ("https://github.com/c/insert", "inserted")
    assert body_of(recorder, 1)["sha"] == "sha-1"
    committed = base64.b64decode(body_of(recorder, 1)["content"]).decode("utf-8")
    assert committed.index("[Aaa]") < committed.index("[Mmm]") < committed.index("[Zzz]")


async def test_commit_entry_creates_missing_leaf_from_template() -> None:
    recorder = Recorder(
        [
            (404, {"message": "Not Found", "documentation_url": "x"}),
            (201, {"commit": {"html_url": "https://github.com/c/create"}}),
        ]
    )
    client = client_for(recorder)
    url, status = await client.commit_entry(LEAF, ENTRY, "main", "OSINT", "Open source intel.")
    assert (url, status) == ("https://github.com/c/create", "created")
    body = body_of(recorder, 1)
    assert "sha" not in body
    committed = base64.b64decode(body["content"]).decode("utf-8")
    assert committed == (
        leaf_template("OSINT", "Open source intel.") + ENTRY + "\n"
    )


async def test_commit_entry_title_falls_back_to_leaf_path() -> None:
    recorder = Recorder(
        [
            (404, {"message": "Not Found"}),
            (201, {"commit": {"html_url": "https://github.com/c/create"}}),
        ]
    )
    client = client_for(recorder)
    await client.commit_entry(LEAF, ENTRY, "main", "", "Open source intel.")
    committed = base64.b64decode(body_of(recorder, 1)["content"]).decode("utf-8")
    assert committed.startswith("# OSINT\n")


async def test_commit_entry_appends_missing_resources_section() -> None:
    existing = "# OSINT\n\nSome prose without the section.\n"
    recorder = Recorder(
        [
            (200, {"sha": "sha-9", "content": b64(existing)}),
            (201, {"commit": {"html_url": "https://github.com/c/append"}}),
        ]
    )
    client = client_for(recorder)
    url, status = await client.commit_entry(LEAF, ENTRY, "main", "OSINT", "desc")
    assert (url, status) == ("https://github.com/c/append", "inserted")
    committed = base64.b64decode(body_of(recorder, 1)["content"]).decode("utf-8")
    assert committed == existing + "\n## Resources\n\n" + ENTRY + "\n"


async def test_commit_entry_duplicate_raises_and_never_puts() -> None:
    recorder = Recorder([(200, {"sha": "sha-1", "content": b64(LEAF_README)})])
    client = client_for(recorder)
    entry = "- [Other](https://example.com/aaa) — dup. `type:tool` `free`"
    with pytest.raises(DuplicateError):
        await client.commit_entry(LEAF, entry, "main", "OSINT", "desc")
    assert len(recorder.requests) == 1


async def test_commit_entry_conflict_retries_once_with_fresh_sha() -> None:
    refetched = LEAF_README.replace(
        "- [Zzz](https://example.com/zzz) — Z. `type:tool` `free`\n",
        "- [Bbb](https://example.com/bbb) — B. `type:tool` `free`\n"
        "- [Zzz](https://example.com/zzz) — Z. `type:tool` `free`\n",
    )
    recorder = Recorder(
        [
            (200, {"sha": "sha-1", "content": b64(LEAF_README)}),
            (409, {"message": "conflict"}),
            (200, {"sha": "sha-2", "content": b64(refetched)}),
            (201, {"commit": {"html_url": "https://github.com/c/retry"}}),
        ]
    )
    client = client_for(recorder)
    url, status = await client.commit_entry(LEAF, ENTRY, "main", "OSINT", "desc")
    assert (url, status) == ("https://github.com/c/retry", "inserted")
    assert len(recorder.requests) == 4
    first, second = body_of(recorder, 1), body_of(recorder, 3)
    assert first["sha"] == "sha-1"
    assert second["sha"] == "sha-2"
    assert first["content"] != second["content"]
    committed = base64.b64decode(second["content"]).decode("utf-8")
    assert "[Bbb]" in committed
    assert committed.index("[Bbb]") < committed.index("[Mmm]") < committed.index("[Zzz]")


async def test_commit_entry_conflict_twice_raises() -> None:
    recorder = Recorder(
        [
            (200, {"sha": "sha-1", "content": b64(LEAF_README)}),
            (409, {"message": "conflict"}),
            (200, {"sha": "sha-2", "content": b64(LEAF_README)}),
            (409, {"message": "conflict"}),
        ]
    )
    client = client_for(recorder)
    with pytest.raises(ConflictError):
        await client.commit_entry(LEAF, ENTRY, "main", "OSINT", "desc")
    assert len(recorder.requests) == 4


async def test_commit_entry_duplicate_after_conflict_raises() -> None:
    # Someone else committed the same URL between our GET and PUT.
    refetched = LEAF_README + "- [Other](https://example.com/mmm) — taken. `type:tool` `free`\n"
    recorder = Recorder(
        [
            (200, {"sha": "sha-1", "content": b64(LEAF_README)}),
            (409, {"message": "conflict"}),
            (200, {"sha": "sha-2", "content": b64(refetched)}),
        ]
    )
    client = client_for(recorder)
    with pytest.raises(DuplicateError):
        await client.commit_entry(LEAF, ENTRY, "main", "OSINT", "desc")
    assert len(recorder.requests) == 3
