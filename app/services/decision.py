"""Qwen System One decision-model client (Specs S5, S6, S7).

Single outbound seam to the decision API whose request/response shape was
verified against the live service (ODD log entry L4):

    POST {QWEN_API_URL}
    Authorization: Bearer {QWEN_API_KEY}
    Content-Type: application/json
    body: {"model": ..., "state": {"ticket_id", "content"}, "questions": {...}}

Everything the bot shows as a placement candidate comes from
``answers.folder.probabilities`` (S7); ``answers.cost.choice`` and
``answers.needs_admin.noul`` come from the same call, so there is no second
round-trip for cost.

Security rules for this module (S12):
  * the API key is held as ``SecretStr`` and is never placed in an exception
    message; any server-returned body excerpt is whitespace-collapsed,
    truncated, and scrubbed of the key before it reaches ``DecisionError``;
  * bounded retries (2 extra attempts) with backoff, 30 s default timeout;
  * the raw response dict is kept on the result for the SQLite audit row (S10).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import SecretStr

from app.config import MAX_CATEGORIES
from app.logging_config import get_logger

logger = get_logger(__name__)

__all__ = [
    "ClassificationResult",
    "DecisionClient",
    "DecisionError",
    "FolderCandidate",
    "build_request",
]

# Question identifiers used in the request and parsed back from the response.
FOLDER_QUESTION = "folder"
COST_QUESTION = "cost"
ADMIN_QUESTION = "needs_admin"

# Verbatim wording sent to the model (kept here so tests can pin it).
FOLDER_INSTRUCTIONS = "Which Hackpot leaf category should this resource go into?"
COST_INSTRUCTIONS = "What does this resource cost someone who wants to use it today?"
ADMIN_INSTRUCTIONS = (
    "Is this resource sensitive or unusual enough that a human admin should "
    "double-check the placement?"
)

# Cost is a fixed 3-option choice (S13 tag vocabulary); one line per option.
COST_CRITERIA: dict[str, str] = {
    "free": "No money required: fully free, open-source, or public without a paywall.",
    "paid": "Payment or paid subscription is required to use the core resource.",
    "freemium": "A free tier exists, but meaningful capability needs payment.",
}

# Hard cap on the state content we are willing to send (model limit is far
# larger: 65536 tokens); callers may pass a smaller cap.
MAX_STATE_CHARS = 20_000

# Bounded retry policy (Security section): 1 attempt + 2 retries.
MAX_ATTEMPTS = 3
RETRY_DELAYS: tuple[float, ...] = (1.0, 2.0)
RETRY_STATUS_429 = 429

# Response excerpts must stay short and log-safe.
BODY_EXCERPT_LIMIT = 300
EXCERPT_SUFFIX = "..."
REDACTED = "[redacted]"

SleepFn = Callable[[float], Awaitable[None]]


class DecisionError(Exception):
    """Decision API is unreachable, rejected us, or answered unintelligibly.

    The message is safe to show in the bot and to store in the audit trail:
    it never contains the API key.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __repr__(self) -> str:  # pragma: no cover - trivial, but keeps leaks out
        return f"DecisionError({self.message!r})"


@dataclass(frozen=True)
class FolderCandidate:
    """One leaf category option, ranked by the model's own probability."""

    folder: str
    probability: float
    chosen: bool


@dataclass(frozen=True)
class ClassificationResult:
    """Parsed decision answer plus everything the audit row needs."""

    candidates: list[FolderCandidate]
    needs_admin: float | None
    cost: str
    request_id: str
    raw: dict


def _trim_content(content: str, max_state_chars: int) -> str:
    """Hard-cap ``content``, preferring a paragraph boundary over mid-word."""
    if max_state_chars <= 0:
        raise ValueError("max_state_chars must be a positive character cap")
    text = content.strip()
    if len(text) <= max_state_chars:
        return text
    window = text[:max_state_chars]
    boundary = window.rfind("\n\n")
    if boundary > 0:
        return window[:boundary].rstrip()
    return window


def build_request(
    model: str,
    ticket_id: str,
    content: str,
    categories: Mapping[str, str],
    max_state_chars: int = MAX_STATE_CHARS,
) -> dict[str, Any]:
    """Build the System One request body (verified shape, L4).

    ``categories`` is the leaf-path -> criteria map from ``CATEGORIES_JSON``
    (S18); its keys are exactly the folders the model may answer with (S7).
    """
    if not model or not model.strip():
        raise ValueError("model must be a non-empty string")
    if not categories:
        raise ValueError("categories must contain at least one leaf category")
    if len(categories) > MAX_CATEGORIES:
        raise ValueError(
            f"categories exceeds the {MAX_CATEGORIES}-option limit of the decision model"
        )

    criteria = {str(path): str(description) for path, description in categories.items()}
    return {
        "model": model,
        "state": {"ticket_id": ticket_id, "content": _trim_content(content, max_state_chars)},
        "questions": {
            FOLDER_QUESTION: {
                "type": "choice",
                "instructions": FOLDER_INSTRUCTIONS,
                "criteria": criteria,
            },
            COST_QUESTION: {
                "type": "choice",
                "instructions": COST_INSTRUCTIONS,
                "criteria": dict(COST_CRITERIA),
            },
            ADMIN_QUESTION: {
                "type": "noul",
                "instructions": ADMIN_INSTRUCTIONS,
            },
        },
    }


def _excerpt(body_text: str, limit: int = BODY_EXCERPT_LIMIT) -> str:
    """Whitespace-collapsed, length-bounded excerpt safe for errors/logs."""
    collapsed = " ".join(body_text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit].rstrip() + EXCERPT_SUFFIX


def _number(value: Any) -> float | None:
    """Coerce a JSON number to float, rejecting bools and anything else."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _parse_classification(
    data: dict[str, Any], threshold: float, max_candidates: int
) -> ClassificationResult:
    """Turn a verified-shape response into ranked candidates (S7)."""
    answers = data.get("answers")
    if not isinstance(answers, Mapping):
        raise DecisionError(f"decision response carries no answers object for the '{FOLDER_QUESTION}' question")

    folder_answer = answers.get(FOLDER_QUESTION)
    if not isinstance(folder_answer, Mapping):
        raise DecisionError(f"decision response is missing the '{FOLDER_QUESTION}' answer")

    probabilities = folder_answer.get("probabilities")
    if not isinstance(probabilities, Mapping) or not probabilities:
        raise DecisionError(f"decision '{FOLDER_QUESTION}' answer has no usable probabilities mapping")

    scored: list[tuple[str, float]] = []
    for name, raw_probability in probabilities.items():
        if not isinstance(name, str) or not name:
            raise DecisionError(f"decision '{FOLDER_QUESTION}' probabilities contain an invalid option name")
        probability = _number(raw_probability)
        if probability is None:
            raise DecisionError(
                f"decision '{FOLDER_QUESTION}' answer has a non-numeric probability for {name!r}"
            )
        scored.append((name, probability))

    choice = folder_answer.get("choice")
    chosen_folder = choice if isinstance(choice, str) else ""
    scored.sort(key=lambda item: item[1], reverse=True)
    candidates = [
        FolderCandidate(folder=name, probability=probability, chosen=name == chosen_folder)
        for name, probability in scored
        if probability >= threshold
    ][:max_candidates]

    admin_answer = answers.get(ADMIN_QUESTION)
    needs_admin = (
        _number(admin_answer.get("noul")) if isinstance(admin_answer, Mapping) else None
    )

    cost_answer = answers.get(COST_QUESTION)
    cost = ""
    if isinstance(cost_answer, Mapping):
        raw_cost = cost_answer.get("choice")
        cost = raw_cost if isinstance(raw_cost, str) else ""

    raw_request_id = data.get("request_id")
    request_id = raw_request_id if isinstance(raw_request_id, str) else ""

    return ClassificationResult(
        candidates=candidates,
        needs_admin=needs_admin,
        cost=cost,
        request_id=request_id,
        raw=data,
    )


class DecisionClient:
    """Async client for the System One ``/systemone`` endpoint (S5, S6).

    The caller owns the ``httpx.AsyncClient`` (so the bot can share one pool);
    this class owns the endpoint URL, the Bearer credential, and the retry
    policy.
    """

    def __init__(
        self,
        *,
        api_url: str,
        api_key: SecretStr | str,
        model: str,
        client: httpx.AsyncClient,
        timeout_s: float = 30.0,
        sleep: SleepFn | None = None,
    ) -> None:
        if not api_url or not api_url.strip():
            raise ValueError("api_url must be a non-empty URL")
        if not api_url.startswith("https://"):
            raise ValueError("api_url must be an https:// URL")
        self._api_key = SecretStr(api_key) if isinstance(api_key, str) else api_key
        if not self._api_key.get_secret_value().strip():
            raise ValueError("api_key must be a non-empty secret")
        if not model or not model.strip():
            raise ValueError("model must be a non-empty string")

        self._api_url = api_url.strip()
        self._model = model
        self._client = client
        self._timeout_s = timeout_s
        # Injectable so tests never wait on real backoff.
        self._sleep: SleepFn = sleep if sleep is not None else asyncio.sleep

    def _headers(self) -> dict[str, str]:
        """Exact auth headers verified against the live API (L4)."""
        return {
            "Authorization": f"Bearer {self._api_key.get_secret_value()}",
            "Content-Type": "application/json",
        }

    def _safe(self, message: str) -> str:
        """Scrub the credential from any text headed for an exception."""
        secret = self._api_key.get_secret_value()
        if secret and secret in message:
            message = message.replace(secret, REDACTED)
        return message

    @staticmethod
    def _retryable(status_code: int) -> bool:
        return status_code == RETRY_STATUS_429 or 500 <= status_code <= 599

    async def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        """POST the request body, retrying transport errors and 5xx/429."""
        last_failure = "no attempt was made"
        for attempt in range(MAX_ATTEMPTS):
            is_last = attempt == MAX_ATTEMPTS - 1
            try:
                response = await self._client.post(
                    self._api_url, json=body, headers=self._headers(), timeout=self._timeout_s
                )
            except httpx.TransportError as exc:
                # httpx transport messages carry the URL only, but they are
                # still user-supplied text: keep them through _safe().
                last_failure = f"transport error ({type(exc).__name__}: {self._safe(str(exc))})"
                if is_last:
                    logger.error(
                        "decision attempt %d/%d hit a transport error after exhausting retries",
                        attempt + 1,
                        MAX_ATTEMPTS,
                    )
                    raise DecisionError(
                        self._safe(
                            f"decision request failed after {attempt + 1} attempts: {last_failure}"
                        )
                    ) from exc
                logger.warning(
                    "decision attempt %d/%d failed with a transport error (%s); retrying",
                    attempt + 1,
                    MAX_ATTEMPTS,
                    type(exc).__name__,
                )
                await self._sleep(RETRY_DELAYS[attempt])
                continue

            if not response.is_success:
                excerpt = self._safe(_excerpt(response.text))
                detail = f"HTTP {response.status_code}: {excerpt}"
                status_class = f"{response.status_code // 100}xx"
                if self._retryable(response.status_code) and not is_last:
                    last_failure = detail
                    logger.warning(
                        "decision attempt %d/%d failed with HTTP %d (%s); retrying",
                        attempt + 1,
                        MAX_ATTEMPTS,
                        response.status_code,
                        status_class,
                    )
                    await self._sleep(RETRY_DELAYS[attempt])
                    continue
                logger.error(
                    "decision attempt %d/%d rejected with HTTP %d (%s)",
                    attempt + 1,
                    MAX_ATTEMPTS,
                    response.status_code,
                    status_class,
                )
                raise DecisionError(
                    self._safe(
                        f"decision API rejected the request after {attempt + 1} "
                        f"attempt(s) with {detail}"
                    )
                )

            try:
                data = response.json()
            except ValueError as exc:
                logger.error("decision API returned invalid JSON (attempt %d/%d)", attempt + 1, MAX_ATTEMPTS)
                raise DecisionError(
                    self._safe(
                        "decision API returned invalid JSON: "
                        f"{self._safe(_excerpt(response.text))}"
                    )
                ) from exc
            if not isinstance(data, dict):
                logger.error(
                    "decision API returned an unexpected JSON type: %s", type(data).__name__
                )
                raise DecisionError(
                    self._safe(
                        f"decision API returned an unexpected JSON type: {type(data).__name__}"
                    )
                )
            return data

        # Unreachable: every branch above returns or raises.
        raise DecisionError(self._safe(f"decision request failed: {last_failure}"))

    async def classify(
        self,
        ticket_id: str,
        content: str,
        categories: Mapping[str, str],
        threshold: float,
        max_candidates: int,
    ) -> ClassificationResult:
        """Ask the model where ``content`` belongs and rank the options (S5, S7).

        ``threshold`` is ``CONFIDENCE_THRESHOLD`` and ``max_candidates`` is
        ``MAX_CANDIDATES_SHOWN`` from docker compose (S6) — validation of both
        happens here, before any network call.
        """
        if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
            raise ValueError("threshold must be a number between 0 and 1")
        if not 0.0 <= float(threshold) <= 1.0:
            raise ValueError("threshold must be between 0.0 and 1.0")
        if not isinstance(max_candidates, int) or isinstance(max_candidates, bool):
            raise ValueError("max_candidates must be a positive integer")
        if max_candidates < 1:
            raise ValueError("max_candidates must be a positive integer")

        body = build_request(self._model, ticket_id, content, categories)
        data = await self._post(body)
        result = _parse_classification(data, float(threshold), max_candidates)
        chosen = result.candidates[0].folder if result.candidates else ""
        logger.info(
            "decision ok request_id=%s folder=%s candidates=%d",
            result.request_id,
            chosen,
            len(result.candidates),
        )
        return result
