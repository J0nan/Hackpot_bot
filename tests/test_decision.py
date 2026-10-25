"""Tests for the Qwen System One decision client (Specs S5, S6, S7).

All HTTP is mocked with ``httpx.MockTransport`` — no live network. The API key
is always a fake value, and the tests assert it can never leak into errors.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any, Awaitable, Callable

import httpx
import pytest
from pydantic import SecretStr

from app.config import MAX_CATEGORIES
from app.services.decision import (
    ClassificationResult,
    DecisionClient,
    DecisionError,
    FolderCandidate,
    build_request,
)

FAKE_KEY = "sk-test-key-DO-NOT-LEAK"
API_URL = "https://decision.test/compatible-mode/v1/systemone"
MODEL = "decision-model-preview"
TICKET = "ticket-1"

FOLDER_INSTRUCTIONS = "Which Hackpot leaf category should this resource go into?"
ADMIN_INSTRUCTIONS = (
    "Is this resource sensitive or unusual enough that a human admin should "
    "double-check the placement?"
)

CATEGORIES: dict[str, str] = {
    "01_Exploitation/Web_Exploitation": "web application exploitation tooling",
    "02_Web_Application/Vulnerability_Specific": "vulnerability-specific writeups",
    "03_Network/Protocol_Abuse": "network protocol abuse material",
}

CONTENT = "https://github.com/example/tool\n\nA tool that does web things."


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
class Recorder:
    """MockTransport handler that replays scripted outcomes and records traffic.

    The same object records outgoing requests and the retry sleeps the client
    asks for, so a test can never wire the two to different recorders.
    """

    def __init__(self, outcomes: list[httpx.Response | Exception] | None = None) -> None:
        self.outcomes: list[httpx.Response | Exception] = list(outcomes or [])
        self.requests: list[httpx.Request] = []
        self.sleeps: list[float] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert self.outcomes, "test scripted no responses"
        self.requests.append(request)
        # The last scripted outcome repeats if more attempts happen than outcomes.
        outcome = self.outcomes[min(len(self.requests) - 1, len(self.outcomes) - 1)]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)

    @property
    def calls(self) -> int:
        return len(self.requests)


def scripted_handler(
    outcomes: list[httpx.Response | Exception],
    recorder: Recorder,
) -> Recorder:
    """Script ``outcomes`` onto ``recorder`` and return it as the transport handler."""
    recorder.outcomes = list(outcomes)
    return recorder


def ok(payload: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json=payload)


def verified_response(
    probabilities: dict[str, float] | None = None,
    *,
    choice: str | None = "02_Web_Application/Vulnerability_Specific",
    noul: float | None = 0.02,
    cost: str | None = "free",
    request_id: str | None = "req-42",
) -> dict[str, Any]:
    """Canned response in the VERIFIED shape (ODD log entry L4)."""
    folder: dict[str, Any] = {"type": "choice", "confidence": 0.75}
    if choice is not None:
        folder["choice"] = choice
    if probabilities is not None:
        folder["probabilities"] = probabilities

    answers: dict[str, Any] = {"folder": folder}
    if cost is not None:
        answers["cost"] = {
            "type": "choice",
            "choice": cost,
            "confidence": 0.9,
            "probabilities": {"free": 0.9, "paid": 0.05, "freemium": 0.05},
        }
    if noul is not None:
        answers["needs_admin"] = {"type": "noul", "noul": noul}

    body: dict[str, Any] = {
        "model": MODEL,
        "answers": answers,
        "usage": {"input_tokens": 341},
        "latency_ms": 560.5,
    }
    if request_id is not None:
        body["request_id"] = request_id
    return body


PROBABILITIES = {
    "01_Exploitation/Web_Exploitation": 0.02,
    "02_Web_Application/Vulnerability_Specific": 0.75,
    "03_Network/Protocol_Abuse": 0.0,
    "04_RE/Reverse_Engineering": 0.18,
    "05_Mobile/Android": 0.05,
}


@pytest.fixture()
async def make_client():
    """Build DecisionClient instances over a shared, properly closed AsyncClient pool."""
    pool: list[httpx.AsyncClient] = []

    def _make(
        handler: Recorder | Callable[[httpx.Request], httpx.Response],
        *,
        api_key: SecretStr | str = FAKE_KEY,
        api_url: str = API_URL,
        model: str = MODEL,
        timeout_s: float = 30.0,
    ) -> DecisionClient:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        pool.append(client)
        # A Recorder doubles as the injected sleep sink; anything else keeps the
        # production default (asyncio.sleep).
        sleep = handler.sleep if isinstance(handler, Recorder) else None
        return DecisionClient(
            api_url=api_url,
            api_key=api_key,
            model=model,
            client=client,
            timeout_s=timeout_s,
            sleep=sleep,
        )

    yield _make
    for client in pool:
        await client.aclose()


# --------------------------------------------------------------------------- #
# build_request — S5 / S7
# --------------------------------------------------------------------------- #
def test_build_request_question_shape() -> None:
    request = build_request(MODEL, TICKET, CONTENT, CATEGORIES)

    assert request["model"] == MODEL
    assert request["state"] == {"ticket_id": TICKET, "content": CONTENT}

    questions = request["questions"]
    assert set(questions) == {"folder", "cost", "needs_admin"}

    folder = questions["folder"]
    assert folder["type"] == "choice"
    assert folder["instructions"] == FOLDER_INSTRUCTIONS
    # criteria map keys must be exactly the configured leaf categories (S18).
    assert list(folder["criteria"].keys()) == list(CATEGORIES.keys())
    assert folder["criteria"] == CATEGORIES

    cost = questions["cost"]
    assert cost["type"] == "choice"
    assert set(cost["criteria"]) == {"free", "paid", "freemium"}
    for description in cost["criteria"].values():
        assert isinstance(description, str) and description.strip()
        assert "\n" not in description

    needs_admin = questions["needs_admin"]
    assert needs_admin["type"] == "noul"
    assert needs_admin["instructions"] == ADMIN_INSTRUCTIONS


def test_build_request_is_json_serializable_and_key_free() -> None:
    request = build_request(MODEL, TICKET, CONTENT, CATEGORIES)
    assert FAKE_KEY not in json.dumps(request)


def test_build_request_does_not_alias_caller_categories() -> None:
    categories = dict(CATEGORIES)
    request = build_request(MODEL, TICKET, CONTENT, categories)
    request["questions"]["folder"]["criteria"]["99_New/Leaf"] = "injected"
    assert "99_New/Leaf" not in categories


def test_build_request_keeps_short_content_untouched() -> None:
    request = build_request(MODEL, TICKET, CONTENT, CATEGORIES, max_state_chars=20000)
    assert request["state"]["content"] == CONTENT


def test_build_request_caps_content_at_paragraph_boundary() -> None:
    paragraphs = [f"P{i}:" + "a" * 25 for i in range(2000)]
    content = "\n\n".join(paragraphs)
    assert len(content) > 30_000

    trimmed = build_request(MODEL, TICKET, content, CATEGORIES, max_state_chars=20_000)[
        "state"
    ]["content"]

    assert len(trimmed) <= 20_000
    used = trimmed.split("\n\n")
    # the last retained paragraph is complete, and the next one would not fit
    assert used[-1] == paragraphs[len(used) - 1]
    assert len("\n\n".join(paragraphs[: len(used) + 1])) > 20_000


def test_build_request_hard_cuts_when_no_paragraph_boundary_exists() -> None:
    content = "z" * 30_000
    trimmed = build_request(MODEL, TICKET, content, CATEGORIES, max_state_chars=20_000)[
        "state"
    ]["content"]
    assert trimmed == "z" * 20_000


def test_build_request_rejects_empty_categories() -> None:
    with pytest.raises(ValueError, match="categories"):
        build_request(MODEL, TICKET, CONTENT, {})


def test_build_request_rejects_categories_over_model_option_limit() -> None:
    too_many = {f"01_Dom_{i}/Leaf_{i}": "criteria" for i in range(MAX_CATEGORIES + 1)}
    with pytest.raises(ValueError, match=str(MAX_CATEGORIES)):
        build_request(MODEL, TICKET, CONTENT, too_many)


# --------------------------------------------------------------------------- #
# DecisionClient construction
# --------------------------------------------------------------------------- #
def test_client_accepts_plain_string_key(make_client) -> None:
    recorder = Recorder()
    client = make_client(scripted_handler([ok(verified_response())], recorder), api_key=FAKE_KEY)
    assert isinstance(client, DecisionClient)


def test_client_rejects_blank_credentials(make_client) -> None:
    recorder = Recorder()
    handler = scripted_handler([ok(verified_response())], recorder)
    with pytest.raises(ValueError, match="api_key"):
        make_client(handler, api_key=SecretStr("  "))
    with pytest.raises(ValueError, match="api_url"):
        make_client(handler, api_url="")


# --------------------------------------------------------------------------- #
# classify — outgoing request contract (S5, S6)
# --------------------------------------------------------------------------- #
async def test_classify_posts_verified_contract(make_client) -> None:
    recorder = Recorder()
    client = make_client(scripted_handler([ok(verified_response(PROBABILITIES))], recorder))

    await client.classify(TICKET, CONTENT, CATEGORIES, threshold=0.15, max_candidates=3)

    assert recorder.calls == 1
    request = recorder.requests[0]
    assert str(request.url) == API_URL
    assert request.method == "POST"
    # Bearer scheme confirmed by the live test (L4)
    assert request.headers["authorization"] == f"Bearer {FAKE_KEY}"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == build_request(MODEL, TICKET, CONTENT, CATEGORIES)


async def test_classify_authorizes_with_secretstr_key_from_settings(make_client) -> None:
    """Settings.qwen_api_key is a SecretStr (S6) — same header as the str form."""
    recorder = Recorder()
    client = make_client(
        scripted_handler([ok(verified_response(PROBABILITIES))], recorder),
        api_key=SecretStr(FAKE_KEY),
    )

    await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert recorder.requests[0].headers["authorization"] == f"Bearer {FAKE_KEY}"
    # credential travels only in the header, never in the request body
    assert FAKE_KEY not in recorder.requests[0].content.decode()


async def test_classify_uses_injected_model_and_url(make_client) -> None:
    recorder = Recorder()
    client = make_client(
        scripted_handler([ok(verified_response(PROBABILITIES))], recorder),
        api_url="https://other.host.example/v1/systemone",
        model="other-model",
    )

    await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert str(recorder.requests[0].url) == "https://other.host.example/v1/systemone"
    assert json.loads(recorder.requests[0].content)["model"] == "other-model"


async def test_classify_validates_before_any_http_call(make_client) -> None:
    recorder = Recorder()
    client = make_client(scripted_handler([ok(verified_response(PROBABILITIES))], recorder))

    with pytest.raises(ValueError, match="categories"):
        await client.classify(TICKET, CONTENT, {}, 0.15, 3)
    with pytest.raises(ValueError, match=str(MAX_CATEGORIES)):
        too_many = {f"01_Dom_{i}/Leaf_{i}": "criteria" for i in range(MAX_CATEGORIES + 1)}
        await client.classify(TICKET, CONTENT, too_many, 0.15, 3)
    with pytest.raises(ValueError, match="max_candidates"):
        await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 0)
    with pytest.raises(ValueError, match="threshold"):
        await client.classify(TICKET, CONTENT, CATEGORIES, 1.5, 3)

    assert recorder.calls == 0


# --------------------------------------------------------------------------- #
# classify — parsing candidates (S7)
# --------------------------------------------------------------------------- #
async def test_classify_orders_and_thresholds_candidates(make_client) -> None:
    recorder = Recorder()
    client = make_client(scripted_handler([ok(verified_response(PROBABILITIES))], recorder))

    result = await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert isinstance(result, ClassificationResult)
    # 0.02 / 0.05 / 0.0 entries fall below the configured threshold
    assert [c.folder for c in result.candidates] == [
        "02_Web_Application/Vulnerability_Specific",
        "04_RE/Reverse_Engineering",
    ]
    assert [c.probability for c in result.candidates] == [0.75, 0.18]
    assert [c.chosen for c in result.candidates] == [True, False]
    assert all(isinstance(c, FolderCandidate) for c in result.candidates)


async def test_classify_truncates_to_max_candidates(make_client) -> None:
    recorder = Recorder()
    client = make_client(scripted_handler([ok(verified_response(PROBABILITIES))], recorder))

    result = await client.classify(TICKET, CONTENT, CATEGORIES, 0.0, 3)

    assert [(c.folder, c.probability) for c in result.candidates] == [
        ("02_Web_Application/Vulnerability_Specific", 0.75),
        ("04_RE/Reverse_Engineering", 0.18),
        ("05_Mobile/Android", 0.05),
    ]


async def test_classify_keeps_folder_names_as_given(make_client) -> None:
    recorder = Recorder()
    probs = {"02_Web_Application/Vulnerability_Specific": 0.6, "zzz odd name": 0.3}
    client = make_client(scripted_handler([ok(verified_response(probs))], recorder))

    result = await client.classify(TICKET, CONTENT, CATEGORIES, 0.1, 5)

    assert [c.folder for c in result.candidates] == ["02_Web_Application/Vulnerability_Specific", "zzz odd name"]


async def test_classify_chosen_flag_follows_model_choice(make_client) -> None:
    recorder = Recorder()
    client = make_client(
        scripted_handler(
            [ok(verified_response(PROBABILITIES, choice="04_RE/Reverse_Engineering"))], recorder
        )
    )

    result = await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert [c.chosen for c in result.candidates] == [False, True]


async def test_classify_without_choice_marks_nothing_chosen(make_client) -> None:
    recorder = Recorder()
    client = make_client(
        scripted_handler([ok(verified_response(PROBABILITIES, choice=None))], recorder)
    )

    result = await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert [c.chosen for c in result.candidates] == [False, False]


async def test_classify_populates_audit_fields(make_client) -> None:
    recorder = Recorder()
    payload = verified_response(PROBABILITIES)
    client = make_client(scripted_handler([ok(payload)], recorder))

    result = await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert result.needs_admin == 0.02
    assert result.cost == "free"
    assert result.request_id == "req-42"
    assert result.raw == payload
    assert result.raw["usage"] == {"input_tokens": 341}


async def test_classify_defaults_for_missing_optional_answers(make_client) -> None:
    recorder = Recorder()
    payload = verified_response(PROBABILITIES, noul=None, cost=None, request_id=None)
    client = make_client(scripted_handler([ok(payload)], recorder))

    result = await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert result.needs_admin is None
    assert result.cost == ""
    assert result.request_id == ""


async def test_classify_garbled_optional_answers_are_tolerated(make_client) -> None:
    recorder = Recorder()
    payload = verified_response(PROBABILITIES)
    payload["answers"]["needs_admin"] = {"type": "noul", "noul": "not-a-number"}
    payload["answers"]["cost"] = {"type": "choice"}
    client = make_client(scripted_handler([ok(payload)], recorder))

    result = await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert result.needs_admin is None
    assert result.cost == ""


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda p: p.pop("answers"), id="no-answers"),
        pytest.param(lambda p: p.__setitem__("answers", []), id="answers-not-object"),
        pytest.param(lambda p: p["answers"].pop("folder"), id="no-folder"),
        pytest.param(lambda p: p["answers"].__setitem__("folder", "garbage"), id="folder-string"),
        pytest.param(lambda p: p["answers"]["folder"].pop("probabilities"), id="no-probabilities"),
        pytest.param(
            lambda p: p["answers"]["folder"].__setitem__("probabilities", {}), id="empty-probabilities"
        ),
        pytest.param(
            lambda p: p["answers"]["folder"].__setitem__("probabilities", {"a": "maybe"}),
            id="non-numeric-probabilities",
        ),
        pytest.param(lambda p: p.clear(), id="empty-body"),
    ],
)
async def test_classify_raises_on_garbled_folder(make_client, mutate) -> None:
    recorder = Recorder()
    payload = verified_response(PROBABILITIES)
    mutate(payload)
    client = make_client(scripted_handler([ok(payload)], recorder))

    with pytest.raises(DecisionError, match="folder"):
        await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)
    assert recorder.calls == 1


async def test_classify_empty_candidate_list_is_valid(make_client) -> None:
    recorder = Recorder()
    client = make_client(
        scripted_handler([ok(verified_response({"02_Web_Application/Vulnerability_Specific": 0.02}))], recorder)
    )

    result = await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert result.candidates == []


def test_result_dataclasses_are_frozen() -> None:
    candidate = FolderCandidate(folder="01_A/B", probability=0.5, chosen=True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        candidate.folder = "other"  # type: ignore[misc]

    result = ClassificationResult(
        candidates=[candidate], needs_admin=None, cost="free", request_id="r", raw={}
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.cost = "paid"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# retries and error safety
# --------------------------------------------------------------------------- #
async def test_retries_500_then_succeeds(make_client) -> None:
    recorder = Recorder()
    client = make_client(
        scripted_handler(
            [
                httpx.Response(500, text="boom"),
                httpx.Response(502, text="bad gateway"),
                ok(verified_response(PROBABILITIES)),
            ],
            recorder,
        )
    )

    result = await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert recorder.calls == 3
    assert len(recorder.sleeps) == 2
    assert recorder.sleeps == sorted(recorder.sleeps)  # increasing backoff
    assert [c.folder for c in result.candidates] == [
        "02_Web_Application/Vulnerability_Specific",
        "04_RE/Reverse_Engineering",
    ]


async def test_retries_429(make_client) -> None:
    recorder = Recorder()
    client = make_client(
        scripted_handler(
            [httpx.Response(429, text="slow down"), ok(verified_response(PROBABILITIES))], recorder
        )
    )

    await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert recorder.calls == 2
    assert len(recorder.sleeps) == 1


async def test_exhausted_500_raises_after_three_attempts(make_client) -> None:
    recorder = Recorder()
    client = make_client(scripted_handler([httpx.Response(500, text="boom")], recorder))

    with pytest.raises(DecisionError, match="500") as excinfo:
        await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert recorder.calls == 3
    assert len(recorder.sleeps) == 2
    assert "boom" in str(excinfo.value)


async def test_client_errors_are_not_retried(make_client) -> None:
    recorder = Recorder()
    client = make_client(scripted_handler([httpx.Response(400, text="bad request")], recorder))

    with pytest.raises(DecisionError, match="400"):
        await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert recorder.calls == 1
    assert recorder.sleeps == []


async def test_transport_error_is_retried_then_raises(make_client) -> None:
    recorder = Recorder()
    client = make_client(scripted_handler([httpx.ConnectError("no route")], recorder))

    with pytest.raises(DecisionError, match="ConnectError"):
        await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert recorder.calls == 3
    assert len(recorder.sleeps) == 2


async def test_transport_error_then_success(make_client) -> None:
    recorder = Recorder()
    client = make_client(
        scripted_handler(
            [httpx.ReadTimeout("slow"), ok(verified_response(PROBABILITIES))], recorder
        )
    )

    result = await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert recorder.calls == 2
    assert result.cost == "free"


async def test_invalid_json_raises_decision_error(make_client) -> None:
    recorder = Recorder()
    client = make_client(scripted_handler([httpx.Response(200, text="<html>nope")], recorder))

    with pytest.raises(DecisionError, match="JSON"):
        await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert recorder.calls == 1


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        pytest.param(lambda: httpx.Response(500, text=f"leak {FAKE_KEY} here"), "500", id="server-echo"),
        pytest.param(lambda: httpx.Response(200, text=FAKE_KEY), "JSON", id="invalid-json"),
        pytest.param(lambda: httpx.ConnectError(FAKE_KEY), "ConnectError", id="transport"),
    ],
)
async def test_errors_never_leak_the_api_key(make_client, outcome, expected) -> None:
    recorder = Recorder()
    client = make_client(scripted_handler([outcome()], recorder))

    with pytest.raises(DecisionError) as excinfo:
        await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    message = str(excinfo.value)
    assert expected in message
    assert FAKE_KEY not in message
    assert FAKE_KEY not in repr(excinfo.value)
    assert "[redacted]" in message


async def test_response_excerpt_is_truncated(make_client) -> None:
    recorder = Recorder()
    verbose = "e" * 5000
    client = make_client(scripted_handler([httpx.Response(500, text=verbose)], recorder))

    with pytest.raises(DecisionError) as excinfo:
        await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    message = str(excinfo.value)
    assert "e" * 400 not in message
    assert "..." in message
    assert len(message) < 500


async def test_error_excerpt_collapses_newlines(make_client) -> None:
    recorder = Recorder()
    client = make_client(
        scripted_handler([httpx.Response(503, text="line one\n\nline two")], recorder)
    )

    with pytest.raises(DecisionError) as excinfo:
        await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert "\n" not in str(excinfo.value)


async def test_default_sleep_is_asyncio_sleep(make_client) -> None:
    """No injected recorder must not break retries — the default awaitable is used."""
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(500, text="boom")
        return ok(verified_response(PROBABILITIES))

    client = make_client(handler)
    result = await client.classify(TICKET, CONTENT, CATEGORIES, 0.15, 3)

    assert len(calls) == 2
    assert result.request_id == "req-42"
