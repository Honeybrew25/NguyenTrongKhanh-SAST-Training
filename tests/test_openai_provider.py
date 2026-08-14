from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from vulngym_enrich.openai_verifier_agent import OpenAIResponsesProvider
from vulngym_enrich.verifier_agent import ProviderError


ROOT = Path(__file__).resolve().parents[1]
RESPONSE_SCHEMA = ROOT / "schemas" / "verifier-agent-response.schema.json"
ADJUDICATOR_SCHEMA = ROOT / "schemas" / "machine-adjudicator-response.schema.json"


def _decision(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "action": "FINAL",
        "working_hypothesis": "The fixed value cannot be attacker controlled.",
        "tool_requests": [],
        "verdict": "FALSE_POSITIVE",
        "confidence": "HIGH",
        "reason_codes": ["CONSTANT_VALUE"],
        "attacker_capability": "A caller can select only a fixed operation.",
        "entry_point": "The handler receives an operation name.",
        "security_effect": "The scanner models arbitrary command execution.",
        "controls": "An allowlist replaces input with a constant.",
        "reasoning": "Every reachable sink receives the fixed constant.",
        "evidence": [
            {
                "file": "src/app.py",
                "start_line": 3,
                "end_line": 5,
                "description": "The allowlist fixes the sink value.",
            }
        ],
        "abstain_reason": None,
    }
    value.update(overrides)
    return value


def _response(
    payload: dict[str, Any] | str,
    *,
    response_id: str,
    model: str = "gpt-5.6-luna",
    input_tokens: int = 10,
    output_tokens: int = 5,
) -> dict[str, Any]:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return {
        "id": response_id,
        "model": model,
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": text}],
            }
        ],
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "input_tokens_details": {"cached_tokens": 2},
            "output_tokens_details": {"reasoning_tokens": 1},
        },
    }


def _provider(outcomes: list[dict[str, Any]], calls: list[dict[str, Any]]) -> OpenAIResponsesProvider:
    remaining = list(outcomes)

    def transport(payload: dict[str, Any]) -> dict[str, Any]:
        calls.append(payload)
        return remaining.pop(0)

    return OpenAIResponsesProvider(
        response_schema=RESPONSE_SCHEMA,
        prompt_text="Pinned blind-review prompt.",
        timeout_seconds=30,
        model="gpt-5.6-luna",
        reasoning_effort="low",
        max_attempts=3,
        retry_delay_seconds=0,
        api_key="sk-test-secret-never-persist",
        http_json=transport,
    )


def test_openai_provider_uses_responses_structured_output_and_redacts_key(
    tmp_path: Path,
) -> None:
    calls: list[dict[str, Any]] = []
    provider = _provider([_response(_decision(), response_id="resp_1")], calls)
    case = tmp_path / "run" / "cases" / "one"

    assert provider.complete({"task": "test"}, case_directory=case, step=1) == _decision()
    assert len(calls) == 1
    payload = calls[0]
    assert payload["model"] == "gpt-5.6-luna"
    assert payload["reasoning"] == {"effort": "low"}
    assert payload["store"] is False
    assert payload["text"]["format"]["type"] == "json_schema"
    assert payload["text"]["format"]["strict"] is True
    assert "$schema" not in payload["text"]["format"]["schema"]
    assert "$id" not in payload["text"]["format"]["schema"]

    metadata = provider.response_metadata(case, 1)
    assert metadata["response_id"] == "resp_1"
    assert metadata["model_version"] == "gpt-5.6-luna"
    assert metadata["normalized_usage"] == {
        "cached_input_tokens": 2,
        "input_tokens": 10,
        "output_tokens": 5,
        "reasoning_tokens": 1,
        "total_tokens": 15,
    }
    persisted = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "run").rglob("*")
        if path.is_file()
    )
    assert "sk-test-secret-never-persist" not in persisted


def test_openai_provider_preserves_isolated_conversation_history(tmp_path: Path) -> None:
    calls: list[dict[str, Any]] = []
    provider = _provider(
        [
            _response(_decision(), response_id="resp_1"),
            _response(_decision(), response_id="resp_2"),
        ],
        calls,
    )
    case = tmp_path / "case"
    provider.complete({"step": 1}, case_directory=case, step=1)
    provider.complete({"step": 2}, case_directory=case, step=2)

    assert [message["role"] for message in calls[0]["input"]] == [
        "developer",
        "user",
    ]
    assert [message["role"] for message in calls[1]["input"]] == [
        "developer",
        "user",
        "assistant",
        "user",
    ]
    assert "\"step\": 1" in calls[1]["input"][1]["content"]
    assert "\"step\": 2" in calls[1]["input"][3]["content"]


def test_openai_provider_retries_invalid_schema_and_freezes_attempt_usage(
    tmp_path: Path,
) -> None:
    calls: list[dict[str, Any]] = []
    provider = _provider(
        [
            _response("not-json", response_id="resp_bad", input_tokens=7, output_tokens=2),
            _response(_decision(), response_id="resp_ok", input_tokens=11, output_tokens=5),
        ],
        calls,
    )
    case = tmp_path / "case"
    provider.complete({"task": "test"}, case_directory=case, step=1)

    metadata = provider.response_metadata(case, 1)
    assert len(calls) == 2
    assert metadata["attempts"] == 2
    assert metadata["attempt_history"][0]["cause"] == "RESPONSE_SCHEMA"
    assert metadata["attempt_history"][0]["normalized_usage"]["total_tokens"] == 9
    assert metadata["attempt_history"][1]["outcome"] == "ACCEPTED"
    assert (case / "step-01-schema-retry-01-raw-response.json").is_file()


def test_openai_provider_rejects_model_revision_change(tmp_path: Path) -> None:
    calls: list[dict[str, Any]] = []
    provider = _provider(
        [
            _response(_decision(), response_id="resp_1"),
            _response(_decision(), response_id="resp_2", model="gpt-5.6-luna-2026-09"),
        ],
        calls,
    )
    provider.complete({"step": 1}, case_directory=tmp_path / "one", step=1)
    with pytest.raises(ProviderError, match="OPENAI_MODEL_VERSION_CHANGED_DURING_RUN"):
        provider.complete({"step": 1}, case_directory=tmp_path / "two", step=1)


@pytest.mark.parametrize(
    ("decision", "expected_operations"),
    [
        (
            _decision(
                verdict="TRUE_POSITIVE",
                reason_codes=["OTHER_EXPLAINED"],
            ),
            ["CLEARED_FP_REASON_CODES_FOR_NON_FP_VERDICT"],
        ),
        (
            _decision(
                verdict="ABSTAIN",
                confidence="LOW",
                reason_codes=["OTHER_EXPLAINED"],
                abstain_reason="INSUFFICIENT_CONTEXT",
            ),
            [
                "CLEARED_FP_REASON_CODES_FOR_NON_FP_VERDICT",
                "CLEARED_OPTIONAL_EVIDENCE_FOR_ABSTAIN",
            ],
        ),
    ],
)
def test_openai_provider_audits_safe_contract_normalization(
    tmp_path: Path,
    decision: dict[str, Any],
    expected_operations: list[str],
) -> None:
    calls: list[dict[str, Any]] = []
    provider = _provider([_response(decision, response_id="resp_normalized")], calls)
    case = tmp_path / "case"

    accepted = provider.complete({"task": "test"}, case_directory=case, step=1)

    assert accepted["reason_codes"] == []
    if accepted["verdict"] == "ABSTAIN":
        assert accepted["evidence"] == []
    metadata = provider.response_metadata(case, 1)
    assert [
        item["operation"] for item in metadata["contract_normalizations"]
    ] == expected_operations
    raw = json.loads((case / "step-01-raw-response.json").read_text(encoding="utf-8"))
    assert json.loads(raw["output"][0]["content"][0]["text"]) == decision


def test_openai_provider_persists_exhausted_schema_retry_audit(tmp_path: Path) -> None:
    calls: list[dict[str, Any]] = []
    invalid = _decision(verdict="FALSE_POSITIVE", reason_codes=[])
    provider = _provider(
        [_response(invalid, response_id=f"resp_bad_{number}") for number in range(3)],
        calls,
    )
    case = tmp_path / "case"

    with pytest.raises(ProviderError, match="OPENAI_RESPONSE_SCHEMA_INVALID"):
        provider.complete(
            {"task": "blind_security_finding_verification"},
            case_directory=case,
            step=1,
        )

    audit = json.loads(
        (case / "step-01-provider-metadata.json").read_text(encoding="utf-8")
    )
    assert audit["status"] == "FAILED"
    assert audit["error_code"] == "OPENAI_RESPONSE_SCHEMA_INVALID"
    assert audit["attempts"] == 3
    assert [item["outcome"] for item in audit["attempt_history"]] == [
        "RETRY",
        "RETRY",
        "FAILED",
    ]
    assert all(item["raw_response"] for item in audit["attempt_history"])


def test_openai_provider_projects_unsupported_unique_items_for_api_only(
    tmp_path: Path,
) -> None:
    calls: list[dict[str, Any]] = []
    provider = OpenAIResponsesProvider(
        response_schema=ADJUDICATOR_SCHEMA,
        prompt_text="Pinned final-adjudication prompt.",
        timeout_seconds=30,
        model="gpt-5.6-luna",
        reasoning_effort="low",
        max_attempts=1,
        retry_delay_seconds=0,
        api_key="sk-test-secret-never-persist",
        http_json=lambda payload: calls.append(payload) or _response(
            {
                "finding_id": "finding-1",
                "verdict": "UNCERTAIN",
                "confidence": "LOW",
                "reason_codes": [],
                "reasoning": "The evidence remains incomplete.",
                "evidence": [],
                "uncertainty_reason": "Missing reachability evidence.",
            },
            response_id="resp_projected",
        ),
    )

    provider.complete({"task": "test"}, case_directory=tmp_path / "case", step=1)

    api_schema = calls[0]["text"]["format"]["schema"]
    assert "uniqueItems" not in api_schema["properties"]["reason_codes"]
    assert provider.configuration["api_schema_projection"] == {
        "protocol": "openai-structured-output-subset-v1",
        "removed_keywords": ["/properties/reason_codes/uniqueItems"],
    }
    original = json.loads(ADJUDICATOR_SCHEMA.read_text(encoding="utf-8"))
    assert original["properties"]["reason_codes"]["uniqueItems"] is True
