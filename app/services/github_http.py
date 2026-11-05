"""Blocking GitHub HTTP helpers shared by the category and mirror syncs."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import quote

import httpx

API_ROOT = "https://api.github.com"
RAW_ROOT = "https://raw.githubusercontent.com"
DEFAULT_TIMEOUT = 30.0


class GitHubHttpError(RuntimeError):
    """A GitHub request failed or returned an unusable payload."""

    def __init__(self, message: str, *, status: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


def _headers(token: str | None, user_agent: str) -> dict[str, str]:
    headers = {"User-Agent": user_agent}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _tree_headers(token: str | None, user_agent: str) -> dict[str, str]:
    headers = _headers(token, user_agent)
    headers["Accept"] = "application/vnd.github+json"
    headers["X-GitHub-Api-Version"] = "2022-11-28"
    return headers


def get_tree(repo: str, branch: str, token: str | None, *, user_agent: str) -> dict[str, Any]:
    """One recursive ``git/trees`` call; raises :class:`GitHubHttpError`."""
    url = f"{API_ROOT}/repos/{repo}/git/trees/{quote(branch, safe='')}"
    try:
        response = httpx.get(
            url,
            headers=_tree_headers(token, user_agent),
            params={"recursive": "1"},
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=True,
        )
    except httpx.HTTPError as exc:
        raise GitHubHttpError(f"GitHub tree request failed: {exc}") from exc
    if response.status_code != 200:
        raise GitHubHttpError(
            f"GitHub tree call returned HTTP {response.status_code}",
            status=response.status_code,
            body=response.text,
        )
    try:
        data = response.json()
    except ValueError as exc:
        raise GitHubHttpError(
            "GitHub tree response was not JSON",
            status=response.status_code,
            body=response.text,
        ) from exc
    if not isinstance(data, dict):
        raise GitHubHttpError(
            "GitHub tree response was not an object", status=response.status_code
        )
    return data


def get_raw(url: str, token: str | None, *, user_agent: str) -> str | None:
    """Fetch one raw file; None on any transport failure or non-200."""
    try:
        response = httpx.get(
            url,
            headers=_headers(token, user_agent),
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=True,
        )
    except httpx.HTTPError:
        return None
    return response.text if response.status_code == 200 else None


def get_many(
    urls: list[str],
    token: str | None,
    fetch: Callable[[str, str | None], str | None],
    *,
    workers: int = 8,
) -> dict[str, str | None]:
    """Fetch every URL in threads; ``fetch`` receives ``(url, token)``."""
    if not urls:
        return {}
    with ThreadPoolExecutor(max_workers=min(workers, len(urls))) as pool:
        return dict(zip(urls, pool.map(lambda url: fetch(url, token), urls)))