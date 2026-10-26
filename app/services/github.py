"""GitHub service: repo-URL detection, S13 bullet building/insertion, Contents API.

Pure helpers (`parse_repo_url`, `build_entry_line`, `parse_entry_line`,
`insert_entry`, `leaf_template`) do no I/O and are unit-testable on their own. `GitHubClient` is the only network
surface; it takes an already-configured `httpx.AsyncClient` (timeouts/retries live
there) and the sender's PAT (S8), and every failure is reported as a short, safe
`FetchError` that never contains the token (S12, S15).

Specs covered: S3 (GitHub link detection + README fetch), S4 (target repo),
S13 (leaf README bullet format), S15 (public-only ask-the-user fallback),
S16 (commit to `main` through the Contents API), A1 (missing leaf README).
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from app.config import REPO_RE
from app.logging_config import get_logger

logger = get_logger(__name__)

# --- S13: the target repo's contribution guidelines -------------------------- #

#: Allowed `type:` tags (J0nan/Hackpot CONTRIBUTING.md).
ENTRY_TYPES: tuple[str, ...] = ("tool", "course", "docs", "wordlist", "lab", "article", "video")
#: Allowed cost tags.
COST_TAGS: tuple[str, ...] = ("free", "paid", "freemium")
#: Separator between display name, link and description in a bullet.
EM_DASH = "—"
#: Heading of the section every bullet lives under.
RESOURCES_HEADING = "## Resources"

MAX_URL_LEN = 2000  # Security: URLs https-only, <= 2000 chars
MAX_NAME_LEN = 120
MAX_DESCRIPTION_LEN = 500
MAX_TAG_LEN = 40

DEFAULT_TARGET_REPO = "J0nan/Hackpot"  # S4; callers should pass Settings.target_repo

_GITHUB_HOST = "github.com"
_OWNER_RE = re.compile(r"^[A-Za-z0-9._-]{1,39}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
# "- [Name](url)" bullet; the template's HTML comment hint never matches it.
_BULLET_RE = re.compile(r"^[ \t]*-[ \t]+\[(?P<name>[^\]]*)\]\((?P<url>[^)\s]+)\)")
_RESOURCES_HEADING_RE = re.compile(r"^[ \t]*##[ \t]+Resources[ \t]*$", re.IGNORECASE)
_NEXT_HEADING_RE = re.compile(r"^[ \t]*##[ \t]")  # `###` is not a section end
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_TAG_UNSAFE_RE = re.compile(r"[\s`'\"\\|]")
# --- pasted-bullet grammar (parse_entry_line; mirrors build_entry_line output) ---
_ENTRY_DASH_RE = re.compile(r"^-[ \t]")
_ENTRY_LINK_RE = re.compile(
    r"^-[ \t]+\[(?P<name>[^\]]*)\]\((?P<url>[^)]*)\)[ \t]*(?P<rest>.*)$"
)
_ENTRY_SEPARATOR_RE = re.compile(rf"^(?:{re.escape(EM_DASH)}|-)[ \t]+(?P<body>.*)$")
_ENTRY_TAG_RE = re.compile(r"[ \t]*`(?P<tag>[^`]*)`[ \t]*$")

#: S15 — every read failure tells the caller to ask the user for the info and
#: to remember that all links must be public. Safe to show to an admin verbatim.
PUBLIC_HINT = (
    "GitHub didn't return that information — ask the user for a summary and remind "
    "them that all links must be public."
)
TOKEN_HINT = (
    "GitHub refused the request with the sender's token — ask them for a valid token, "
    "then for a summary, and remind them that all links must be public."
)


class FetchError(Exception):
    """A GitHub read/write failed; carries a short, secret-free message.

    `public_hint=True` means the caller must ask the user for the missing
    information and remind them that all links must be public (S15).
    """

    def __init__(self, message: str, public_hint: bool = False) -> None:
        super().__init__(message)
        self.public_hint = public_hint


class ConflictError(FetchError):
    """HTTP 409: the branch moved under us; refetch the sha and retry (S16)."""


class DuplicateError(FetchError):
    """The canonical URL is already listed in the leaf README (flow step 7)."""


class EntryLineError(ValueError):
    """A pasted entry bullet is not a parseable `- [Name](url) …` line (S4.3/S4.4).

    The message names the single problem in short, user-safe terms and never
    echoes the pasted payload. Derives from ValueError so handlers that already
    catch format errors keep working.
    """


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def parse_repo_url(url: str) -> tuple[str, str] | None:
    """Return (owner, repo) for an https GitHub repo URL, else None (S3).

    Tolerates `www.`, a trailing slash, a `.git` suffix, deeper paths
    (`/tree/…`, `/blob/…`, `/issues/3`), a query/fragment and host casing.
    Owner/repo case is preserved exactly as written.
    """
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme.lower() != "https":
        return None
    host = parts.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    # Exact host match: userinfo, ports and look-alikes (evil.com/github.com/…) fail.
    if host != _GITHUB_HOST:
        return None
    segments = [s for s in parts.path.split("/") if s]
    if len(segments) < 2:
        return None
    owner, repo = segments[0], segments[1]
    if repo.lower().endswith(".git"):
        repo = repo[: -len(".git")]
    if not _OWNER_RE.match(owner) or not _REPO_RE.match(repo):
        return None
    return owner, repo


def _canonical_url(url: str) -> str:
    """Compare form for duplicate detection: no scheme, no trailing slash, LC host."""
    text = url.strip()
    text = _SCHEME_RE.sub("", text, count=1)
    text = text.rstrip("/")
    if not text:
        return ""
    host, _, path = text.partition("/")
    host = host.lower()
    return f"{host}/{path}" if path else host


def canonical_url_key(url: str) -> str:
    """Canonical identity of a resource URL for the intake duplicate check.

    GitHub repo URLs collapse to lower-case ``github.com/{owner}/{repo}``, so
    www, host casing, trailing slashes, the ``.git`` suffix and deeper paths
    (``/tree/…``, ``/issues/3``) all match the repo the bot would index for
    them (:func:`parse_repo_url`). Anything else uses the README comparison
    form (:func:`_canonical_url`) so intake and commit-time dedup agree.
    """
    parsed = parse_repo_url(url)
    if parsed is not None:
        return f"{_GITHUB_HOST}/{parsed[0].lower()}/{parsed[1].lower()}"
    return _canonical_url(url)


def _one_line(value: str, field: str, limit: int) -> str:
    """Trim and reject anything that would break the single-line bullet (Security)."""
    text = (value or "").strip()
    if not text:
        raise ValueError(f"entry {field} must not be empty")
    if "\n" in text or "\r" in text:
        raise ValueError(f"entry {field} must not contain newlines")
    if len(text) > limit:
        raise ValueError(f"entry {field} exceeds the {limit} character limit")
    return text


def _normalize_url(url: str) -> str:
    """Shared URL rule for build and parse: https-only, no whitespace, <=2000 chars."""
    link = (url or "").strip()
    if not link:
        raise ValueError("entry url must not be empty")
    if any(c.isspace() for c in link):
        raise ValueError("entry url must not contain whitespace")
    if not link.startswith("https://"):
        raise ValueError("entry url must be an https:// URL")
    if len(link) > MAX_URL_LEN:
        raise ValueError(f"entry url exceeds the {MAX_URL_LEN} character limit")
    return link


def _normalize_platform_tags(platform_tags: list[str] | tuple[str, ...] | None) -> list[str]:
    """Shared tag rule: trim, skip empty, ban unsafe chars, <=40 chars, dedupe (CI)."""
    tags: list[str] = []
    seen: set[str] = set()
    for raw in platform_tags or []:
        tag = (raw or "").strip()
        if not tag:
            continue
        if _TAG_UNSAFE_RE.search(tag):
            raise ValueError(f"invalid platform tag {tag!r}")
        if len(tag) > MAX_TAG_LEN:
            raise ValueError(f"platform tag exceeds the {MAX_TAG_LEN} character limit")
        if tag.casefold() in seen:
            continue
        seen.add(tag.casefold())
        tags.append(tag)
    return tags


def build_entry_line(
    name: str,
    url: str,
    description: str,
    type_tag: str,
    cost_tag: str = "",
    platform_tags: list[str] | None = None,
) -> str:
    """Build one S13 bullet: `- [Name](url) — Description. `type:tool` `free` `linux``."""
    display = _one_line(name, "name", MAX_NAME_LEN)
    summary = _one_line(description, "description", MAX_DESCRIPTION_LEN)
    link = _normalize_url(url)
    if type_tag not in ENTRY_TYPES:
        raise ValueError(f"invalid type tag {type_tag!r}: expected one of {', '.join(ENTRY_TYPES)}")
    cost = (cost_tag or "").strip()
    if cost and cost not in COST_TAGS:
        raise ValueError(f"invalid cost tag {cost!r}: expected one of {', '.join(COST_TAGS)}")

    tags: list[str] = [f"type:{type_tag}"]
    if cost:
        tags.append(cost)
    tags.extend(_normalize_platform_tags(platform_tags))

    # "strips trailing punctuation from description then appends `.`"
    sentence = summary.rstrip(".,;:!?").rstrip() or summary
    rendered = " ".join(f"`{tag}`" for tag in tags)
    return f"- [{display}]({link}) {EM_DASH} {sentence}. {rendered}"


@dataclass(frozen=True)
class ParsedEntry:
    """Fields recovered from a pasted entry bullet; the flow re-validates and rebuilds."""

    name: str
    url: str
    description: str
    tags: tuple[str, ...]


def parse_entry_line(line: str) -> ParsedEntry:
    """Parse a pasted S13 bullet back into its fields (edit-confirm flow, S4.3).

    Accepts exactly what `build_entry_line` emits, plus the minimal tolerances a
    human editing needs: leading/trailing whitespace anywhere, `-` (hyphen-minus)
    as an equivalent of the em dash separator, an optional trailing period on the
    description, optional tags, and multiple spaces between tokens. The url is
    returned raw as typed; URL locking/comparison is the flow's job via
    `_canonical_url`. Name, url, description and tag limits are the same checks
    `build_entry_line` uses, so anything that parses here also rebuilds.
    """
    text = (line or "").strip()
    if not _ENTRY_DASH_RE.match(text):
        raise EntryLineError("missing leading dash: the line must start with '- '")
    link_match = _ENTRY_LINK_RE.match(text)
    if link_match is None:
        raise EntryLineError("missing link: the line must contain '[name](url)'")
    sep_match = _ENTRY_SEPARATOR_RE.match(link_match.group("rest"))
    if sep_match is None:
        raise EntryLineError(
            f"missing description separator: '{EM_DASH}' (or '-') must follow the link"
        )
    body = sep_match.group("body")

    tags: list[str] = []
    while True:  # tags are the trailing `...` run, if any
        tag_match = _ENTRY_TAG_RE.search(body)
        if tag_match is None:
            break
        tags.append(tag_match.group("tag"))
        body = body[: tag_match.start()]
    tags.reverse()

    description = body.strip()
    if description.endswith("."):
        description = description[:-1].rstrip()

    try:
        name = _one_line(link_match.group("name"), "name", MAX_NAME_LEN)
        summary = _one_line(description, "description", MAX_DESCRIPTION_LEN)
        link = _normalize_url(link_match.group("url"))
        normalized_tags = tuple(_normalize_platform_tags(tags))
    except ValueError as exc:
        raise EntryLineError(str(exc)) from exc

    return ParsedEntry(name=name, url=link, description=summary, tags=normalized_tags)


def insert_entry(readme_text: str, entry_line: str) -> tuple[str, str]:
    """Insert `entry_line` into the `## Resources` section of `readme_text`.

    Returns (new_text, status) with status one of:
      * "inserted"  — bullet added alphabetically (case-insensitive by display name)
      * "duplicate" — the canonical URL is already listed; text returned unchanged
      * "no-section" — no `## Resources` heading; text returned unchanged
    Everything outside the insertion point is preserved byte-for-byte, including
    blank lines, CRLF endings and a missing trailing newline.
    """
    match = _BULLET_RE.match((entry_line or "").strip())
    if match is None:
        raise ValueError("entry_line must be a '- [Name](url) …' bullet")
    new_name, new_url = match.group("name"), _canonical_url(match.group("url"))

    lines = readme_text.splitlines(keepends=True)
    heading = next(
        (i for i, raw in enumerate(lines) if _RESOURCES_HEADING_RE.match(raw.rstrip("\r\n"))), None
    )
    if heading is None:
        return readme_text, "no-section"
    end = next(
        (i for i in range(heading + 1, len(lines)) if _NEXT_HEADING_RE.match(lines[i].rstrip("\r\n"))),
        len(lines),
    )

    bullets: list[tuple[int, str, str]] = []
    for i in range(heading + 1, end):
        row = _BULLET_RE.match(lines[i].rstrip("\r\n"))
        if row is not None:
            bullets.append((i, row.group("name"), _canonical_url(row.group("url"))))

    if any(url == new_url for _, _, url in bullets):
        return readme_text, "duplicate"

    if bullets:
        key = new_name.casefold()
        index = next(
            (i for i, name, _ in bullets if name.casefold() > key), bullets[-1][0] + 1
        )
    else:
        # Keep the file byte-for-byte: land after the last non-blank line of the
        # section (the format hint comment), or directly under the heading.
        index = heading + 1
        for i in range(heading + 1, end):
            if lines[i].strip():
                index = i + 1

    newline = "\r\n" if any(line.endswith("\r\n") for line in lines) else "\n"
    if index == len(lines) and lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] += newline
    lines.insert(index, entry_line + newline)
    return "".join(lines), "inserted"


def leaf_template(title: str, description: str) -> str:
    """A1 skeleton for a missing leaf README, mirroring the repo's existing leaves."""
    return (
        f"# {title}\n\n{description}\n\n{RESOURCES_HEADING}\n\n"
        "<!-- Format: - [Name](https://url) — what it does and why it matters. Tags: "
        "`type:tool|course|docs|wordlist|lab|article|video` `free|paid|freemium` "
        "`platform or tech` -->\n"
    )


def leaf_title_from_path(path: str) -> str:
    """Human title for a leaf README path: last segment, underscores become spaces."""
    segments = [s for s in (path or "").replace("\\", "/").split("/") if s]
    if len(segments) >= 2 and segments[-1].casefold() == "readme.md":
        segments = segments[:-1]
    return segments[-1].replace("_", " ").strip() if segments else ""


def _append_section(readme_text: str, entry_line: str) -> str:
    """Add a `## Resources` section (with the bullet) to a file that lacks one (S13)."""
    newline = "\r\n" if "\r\n" in readme_text else "\n"
    base = readme_text if not readme_text or readme_text.endswith(("\n", "\r")) else readme_text + newline
    return f"{base}{newline}{RESOURCES_HEADING}{newline}{newline}{entry_line}{newline}"


# --------------------------------------------------------------------------- #
# Network client
# --------------------------------------------------------------------------- #

def _read_error(status: int) -> FetchError:
    """Map a failing read to the S15 message (never leak the response body)."""
    if status in (401, 403):
        return FetchError(f"{TOKEN_HINT} (HTTP {status})", public_hint=True)
    return FetchError(f"{PUBLIC_HINT} (HTTP {status})", public_hint=True)


def _write_error(status: int, target_repo: str) -> FetchError:
    if status in (401, 403):
        return FetchError(
            f"GitHub rejected the commit: the sender's token needs `contents:write` on "
            f"{target_repo} (HTTP {status})."
        )
    if status == 404:
        return FetchError(
            f"GitHub could not write to {target_repo} — the repo may be private or the "
            f"branch missing (HTTP 404). {PUBLIC_HINT}"
        )
    return FetchError(f"GitHub rejected the commit (HTTP {status}).")


class GitHubClient:
    """Thin GitHub REST client for the bot flow (S3, S4, S16).

    The caller owns the `httpx.AsyncClient` (timeouts and bounded retries are
    configured there, per the Security section); this class owns headers, error
    mapping and the S13/A1 commit orchestration.
    """

    BASE = "https://api.github.com"

    def __init__(
        self,
        token: str | None,
        client: httpx.AsyncClient,
        target_repo: str = DEFAULT_TARGET_REPO,
    ) -> None:
        if not isinstance(target_repo, str) or not REPO_RE.match(target_repo):
            raise ValueError(f"target repo must be 'owner/repo', got {target_repo!r}")
        self.target_repo = target_repo
        self._client = client
        self._headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hackpot-bot",
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    # -- transport ---------------------------------------------------------- #

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        log_hint: str = "",
    ) -> httpx.Response:
        url = f"{self.BASE}{path}"
        # S5: DEBUG request summary. Never the request body — `log_hint` carries
        # only safe coordinates (branch, byte count), never content.
        logger.debug("github %s %s%s", method, path, f" {log_hint}" if log_hint else "")
        try:
            response = await self._client.request(
                method, url, headers=self._headers, params=params, json=json_body
            )
        except httpx.HTTPError as exc:  # timeout, connect error, protocol error
            logger.warning("github %s %s unreachable (%s)", method, path, type(exc).__name__)
            raise FetchError(f"GitHub is unreachable right now. {PUBLIC_HINT}", public_hint=True) from exc
        if response.status_code == 404:
            # 404 is normal control flow for get_file ("leaf README not created yet")
            logger.debug("github %s %s -> HTTP 404 (expected miss path)", method, path)
        elif response.status_code >= 400:
            logger.warning("github %s %s -> HTTP %d", method, path, response.status_code)
        return response

    @staticmethod
    def _payload(response: httpx.Response, error: FetchError) -> Any:
        """JSON body of a successful response, else raise the prepared FetchError."""
        if response.status_code >= 400:
            raise error
        try:
            return response.json()
        except ValueError as exc:
            raise FetchError("GitHub returned an unexpected response. " + PUBLIC_HINT, public_hint=True) from exc

    @staticmethod
    def _decode(data: Any, what: str) -> str:
        if not isinstance(data, dict):
            raise FetchError(f"GitHub returned no {what}. {PUBLIC_HINT}", public_hint=True)
        raw = data.get("content")
        if not isinstance(raw, str):
            raise FetchError(f"GitHub returned no {what} content. {PUBLIC_HINT}", public_hint=True)
        try:
            decoded = base64.b64decode(raw, validate=False)
        except (binascii.Error, ValueError) as exc:
            raise FetchError(f"GitHub returned unreadable {what} content. {PUBLIC_HINT}", public_hint=True) from exc
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FetchError(f"The {what} is not a text file. {PUBLIC_HINT}", public_hint=True) from exc

    # -- reads -------------------------------------------------------------- #

    async def repo_meta(self, owner: str, repo: str) -> dict[str, Any]:
        """Public metadata used to pre-fill the entry interview (S14)."""
        response = await self._request("GET", f"/repos/{owner}/{repo}")
        data = self._payload(response, _read_error(response.status_code))
        if not isinstance(data, dict):
            raise _read_error(response.status_code)
        return {
            "description": data.get("description") or "",
            "default_branch": data.get("default_branch") or "",
            "homepage": data.get("homepage") or "",
            "stars": int(data.get("stargazers_count") or 0),
        }

    async def readme(self, owner: str, repo: str) -> str:
        """Decoded README of the submitted repo; FetchError → ask for a summary (S3, S15)."""
        response = await self._request("GET", f"/repos/{owner}/{repo}/readme")
        data = self._payload(response, _read_error(response.status_code))
        return self._decode(data, "README")

    async def get_file(self, path: str, branch: str) -> tuple[str | None, str]:
        """Read a file from the target repo: (text, sha), or (None, "") when absent."""
        response = await self._request(
            "GET",
            f"/repos/{self.target_repo}/contents/{quote(path, safe='/')}",
            params={"ref": branch},
            log_hint=f"branch={branch}",
        )
        if response.status_code == 404:
            return None, ""
        data = self._payload(response, _read_error(response.status_code))
        if isinstance(data, list):
            raise FetchError(
                f"{path} is a directory, not a file. {PUBLIC_HINT}", public_hint=True
            )
        text = self._decode(data, path)
        sha = str(data["sha"]) if isinstance(data, dict) and data.get("sha") else ""
        return text, sha

    # -- writes ------------------------------------------------------------- #

    async def put_file(
        self,
        path: str,
        content: str,
        sha: str | None,
        message: str,
        branch: str,
    ) -> str:
        """Commit `content` at `path` with the sender's PAT; returns the commit URL.

        `path` must already be validated by the caller via `Settings.readme_path`.
        """
        payload: dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if sha is not None:
            payload["sha"] = sha
        response = await self._request(
            "PUT",
            f"/repos/{self.target_repo}/contents/{quote(path, safe='/')}",
            json_body=payload,
            log_hint=f"branch={branch} bytes={len(content.encode('utf-8'))}",
        )
        if response.status_code == 409:
            raise ConflictError(
                f"GitHub rejected the commit: {path} changed on {branch} while we were "
                "reading it (HTTP 409)."
            )
        data = self._payload(response, _write_error(response.status_code, self.target_repo))
        url = self._commit_url(data)
        if not url:
            raise FetchError(f"GitHub did not confirm the commit for {path}.")
        # S5: INFO milestone — the commit landed; url is public, carries no secret.
        logger.info("github commit ok path=%s branch=%s url=%s", path, branch, url)
        return url

    @staticmethod
    def _commit_url(data: Any) -> str:
        if not isinstance(data, dict):
            return ""
        content = data.get("content")
        if isinstance(content, dict):
            commit = content.get("commit")
            if isinstance(commit, dict) and isinstance(commit.get("html_url"), str):
                return commit["html_url"]
        commit = data.get("commit")
        if isinstance(commit, dict) and isinstance(commit.get("html_url"), str):
            return commit["html_url"]
        return ""

    async def commit_entry(
        self,
        path: str,
        entry_line: str,
        branch: str,
        leaf_title: str,
        leaf_description: str,
    ) -> tuple[str, str]:
        """Flow step 7: GET leaf README → insert alphabetically → PUT (S13, S16, A1).

        Returns (commit_url, status) with status "created" (new leaf README) or
        "inserted". Raises DuplicateError when the URL is already listed, and
        retries once on ConflictError with a freshly fetched sha.
        """
        title = (leaf_title or "").strip() or leaf_title_from_path(path)
        message = f"docs: add resource entry to {path}"
        existing_text, existing_sha = await self.get_file(path, branch)
        status = "inserted" if existing_text is not None else "created"
        text = existing_text
        sha: str | None = existing_sha or None

        for attempt in range(2):
            base = leaf_template(title, leaf_description) if text is None else text
            new_text, section_status = insert_entry(base, entry_line)
            if section_status == "duplicate":
                # Never echo the admin-supplied bullet into the error (S12).
                logger.warning("github duplicate path=%s (nothing committed)", path)
                raise DuplicateError(
                    f"That link is already listed in {path} — nothing was committed."
                )
            if section_status == "no-section":  # A1 safety net / existing file lacks it
                new_text = _append_section(base, entry_line)
            try:
                commit_url = await self.put_file(
                    path, new_text, sha if text is not None else None, message, branch
                )
            except ConflictError:
                if attempt == 1:
                    raise
                text, sha = await self.get_file(path, branch)  # fresh sha + fresh content
                sha = sha or None
                status = "inserted" if text is not None else "created"
                continue
            return commit_url, status
        raise ConflictError(  # pragma: no cover - loop always returns or re-raises
            f"Could not commit to {path} on {branch}: the file kept changing (HTTP 409)."
        )
