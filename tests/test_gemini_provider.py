from __future__ import annotations

import hashlib
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from vulngym_enrich import gemini_verifier_agent
from vulngym_enrich.gemini_verifier_agent import GeminiApiProvider
from vulngym_enrich.verifier_agent import ProviderError, _provider_usage


ROOT = Path(__file__).resolve().parents[1]
RESPONSE_SCHEMA = ROOT / "schemas" / "verifier-agent-response.schema.json"


def _response(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "action": "FINAL",
        "working_hypothesis": "The fixed value cannot be attacker controlled.",
        "tool_requests": [],
        "verdict": "FALSE_POSITIVE",
        "confidence": "HIGH",
        "reason_codes": ["CONSTANT_VALUE"],
        "attacker_capability": "A caller can select only a fixed operation.",
        "entry_point": "The request handler receives the operation name.",
        "security_effect": "The scanner models arbitrary command execution.",
        "controls": "An allowlist replaces input with a constant.",
        "reasoning": "Every reachable sink receives the allowlisted constant.",
        "evidence": [
            {
                "file": "src/app.py",
                "start_line": 3,
                "end_line": 5,
                "description": "The allowlist fixes the value before the sink.",
            }
        ],
        "abstain_reason": None,
    }
    value.update(overrides)
    return value


class FakeApiError(Exception):
    def __init__(
        self,
        code: int,
        message: str = "provider failed",
        *,
        details: Any | None = None,
    ):
        self.code = code
        self.message = message
        self.details = details
        self.response = None
        super().__init__(message)


class FakeContent:
    def __init__(self, text: str, signature: str):
        self.text = text
        self.signature = signature

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return {
            "role": "model",
            "parts": [
                {"text": self.text},
                {"thought_signature": self.signature},
            ],
        }


class FakeCandidate:
    def __init__(self, content: FakeContent):
        self.content = content

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return {"content": self.content.model_dump()}


class FakeResponse:
    def __init__(
        self,
        payload: dict[str, Any] | str,
        *,
        response_id: str,
        model_version: str,
        usage: dict[str, int] | None = None,
    ):
        self.text = (
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            if isinstance(payload, dict)
            else payload
        )
        self.response_id = response_id
        self.model_version = model_version
        self.usage_metadata = usage or {}
        self.content = FakeContent(self.text, f"signature-{response_id}")
        self.candidates = [FakeCandidate(self.content)]
        self.parsed = payload if isinstance(payload, dict) else None

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return {
            "response_id": self.response_id,
            "model_version": self.model_version,
            "usage_metadata": self.usage_metadata,
            "candidates": [candidate.model_dump() for candidate in self.candidates],
        }


class FakeModels:
    def __init__(self, outcomes: list[FakeResponse | Exception]):
        self.outcomes = list(outcomes)
        self.calls: list[dict[str, Any]] = []

    def generate_content(self, **kwargs: Any) -> FakeResponse:
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeClient:
    def __init__(self, outcomes: list[FakeResponse | Exception]):
        self.models = FakeModels(outcomes)


def _install_fake_sdk(
    monkeypatch: pytest.MonkeyPatch,
    *,
    client_factory: Any | None = None,
) -> None:
    google_module = types.ModuleType("google")
    genai_module = types.ModuleType("google.genai")
    errors_module = types.ModuleType("google.genai.errors")
    errors_module.APIError = FakeApiError
    genai_module.Client = client_factory or (lambda **_: FakeClient([]))
    genai_module.errors = errors_module
    google_module.genai = genai_module
    monkeypatch.setitem(sys.modules, "google", google_module)
    monkeypatch.setitem(sys.modules, "google.genai", genai_module)
    monkeypatch.setitem(sys.modules, "google.genai.errors", errors_module)


def _provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    client: FakeClient,
    **overrides: Any,
) -> GeminiApiProvider:
    _install_fake_sdk(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "AQ.test-only-secret-key")
    values: dict[str, Any] = {
        "response_schema": RESPONSE_SCHEMA,
        "prompt_text": "Pinned blind-review prompt.",
        "timeout_seconds": 30,
        "model": "gemini-pinned-test-model",
        "thinking_level": "high",
        "seed": 17,
        "temperature": 0.1,
        "max_attempts": 3,
        "client": client,
        "sdk_version": "2.14.0-test",
        "retry_delay_seconds": 0,
        "rate_limit_retry_delay_seconds": 0,
        "min_request_interval_seconds": 0,
    }
    values.update(overrides)
    return GeminiApiProvider(**values)


def test_gemini_provider_preserves_full_content_and_captures_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first_payload = _response(
        action="REQUEST_TOOLS",
        working_hypothesis="Read the complete handler.",
        tool_requests=[
            {
                "tool": "read_file",
                "path": "src/app.py",
                "query": None,
                "start_line": 1,
                "end_line": 20,
                "case_sensitive": None,
            }
        ],
        verdict=None,
        confidence=None,
        reason_codes=[],
        attacker_capability=None,
        entry_point=None,
        security_effect=None,
        controls=None,
        reasoning=None,
        evidence=[],
    )
    first_response = FakeResponse(
        first_payload,
        response_id="response-1",
        model_version="gemini-server-001",
        usage={
            "prompt_token_count": 10,
            "candidates_token_count": 5,
            "thoughts_token_count": 2,
            "total_token_count": 17,
        },
    )
    client = FakeClient(
        [
            first_response,
            FakeResponse(
                _response(),
                response_id="response-2",
                model_version="gemini-server-001",
                usage={
                    "prompt_token_count": 20,
                    "candidates_token_count": 7,
                    "thoughts_token_count": 3,
                    "total_token_count": 30,
                },
            ),
        ]
    )
    provider = _provider(tmp_path, monkeypatch, client)
    case = tmp_path / "case"

    assert provider.complete({"step": 1}, case_directory=case, step=1) == first_payload
    assert provider.complete({"step": 2}, case_directory=case, step=2) == _response()

    assert len(client.models.calls) == 2
    first_call, second_call = client.models.calls
    assert first_call["model"] == "gemini-pinned-test-model"
    assert first_call["config"]["thinking_config"] == {
        "thinking_level": "high",
        "include_thoughts": False,
    }
    assert first_call["config"]["seed"] == 17
    assert first_call["config"]["temperature"] == 0.1
    assert "$schema" not in first_call["config"]["response_json_schema"]
    assert "$id" not in first_call["config"]["response_json_schema"]
    # The exact SDK content object, including its thought signature, is reused.
    assert second_call["contents"][1] is first_response.content
    assert second_call["contents"][1].signature == "signature-response-1"

    metadata = provider.response_metadata(case, 2)
    assert metadata["model_version"] == "gemini-server-001"
    assert metadata["response_id"] == "response-2"
    assert metadata["raw_response"]["bytes"] <= provider.max_event_bytes
    assert metadata["adapter"]["sha256"] == provider.adapter_sha256
    assert metadata["configuration_sha256"] == provider.configuration_sha256
    assert metadata["provider_version"] == provider.version
    assert metadata["attempt_history"] == [
        {
            "attempt": 1,
            "outcome": "ACCEPTED",
            "cause": None,
            "provider_code": None,
            "raw_response": None,
        }
    ]
    assert provider.observed_model_versions == ("gemini-server-001",)
    assert provider.observed_response_ids == ("response-1", "response-2")
    assert _provider_usage(case) == {
        "input_tokens": 30,
        "output_tokens": 12,
        "reasoning_tokens": 5,
        "total_tokens": 47,
    }
    session = (case / "provider-session.json").read_text(encoding="utf-8")
    assert "AQ.test-only-secret-key" not in session
    assert json.loads(session)["configuration"]["credential_source"] == "GEMINI_API_KEY"


def test_gemini_retries_only_schema_failure_and_keeps_failed_raw_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = FakeClient(
        [
            FakeResponse(
                "not-json",
                response_id="invalid-response",
                model_version="gemini-server-001",
            ),
            FakeResponse(
                _response(),
                response_id="valid-response",
                model_version="gemini-server-001",
            ),
        ]
    )
    provider = _provider(
        tmp_path, monkeypatch, client, max_attempts=2
    )
    case = tmp_path / "schema-retry"

    assert provider.complete({"step": 1}, case_directory=case, step=1) == _response()

    assert len(client.models.calls) == 2
    assert len(client.models.calls[1]["contents"][-1]["parts"]) == 2
    assert (case / "step-01-schema-retry-01-raw-response.json").is_file()
    metadata = json.loads(
        (case / "step-01-provider-metadata.json").read_text(encoding="utf-8")
    )
    assert metadata["attempts"] == 2
    assert [item["outcome"] for item in metadata["attempt_history"]] == [
        "RETRY",
        "ACCEPTED",
    ]
    assert metadata["attempt_history"][0]["cause"] == "RESPONSE_SCHEMA"
    assert metadata["attempt_history"][0]["raw_response"]["sha256"]


def test_gemini_retries_transient_api_error_but_not_client_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transient_client = FakeClient(
        [
            FakeApiError(503),
            FakeResponse(
                _response(),
                response_id="after-retry",
                model_version="gemini-server-001",
            ),
        ]
    )
    provider = _provider(
        tmp_path, monkeypatch, transient_client, max_attempts=2
    )
    assert provider.complete(
        {"step": 1}, case_directory=tmp_path / "transient", step=1
    ) == _response()
    assert len(transient_client.models.calls) == 2
    metadata = provider.response_metadata(tmp_path / "transient", 1)
    assert metadata["attempt_history"][0] == {
        "attempt": 1,
        "outcome": "RETRY",
        "cause": "TRANSPORT",
        "provider_code": 503,
        "raw_response": None,
    }

    secret = "AIzaSecretThatMustNeverReachDiagnostics12345"
    client_error = FakeClient([FakeApiError(400, f"bad key: {secret}")])
    provider = _provider(tmp_path, monkeypatch, client_error, max_attempts=3)
    failed_case = tmp_path / "client-error"
    with pytest.raises(ProviderError) as exc_info:
        provider.complete({"step": 1}, case_directory=failed_case, step=1)
    assert len(client_error.models.calls) == 1
    assert secret not in str(exc_info.value)
    failure_metadata = json.loads(
        (failed_case / "step-01-provider-metadata.json").read_text(encoding="utf-8")
    )
    assert failure_metadata["status"] == "FAILED"
    assert failure_metadata["attempt_history"] == [
        {
            "attempt": 1,
            "outcome": "FAILED",
            "cause": "TRANSPORT",
            "provider_code": 400,
            "raw_response": None,
        }
    ]
    assert not failed_case.exists() or all(
        secret not in path.read_text(encoding="utf-8", errors="replace")
        for path in failed_case.rglob("*")
        if path.is_file()
    )


def test_gemini_honors_rate_limit_retry_info_without_persisting_error_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(gemini_verifier_agent.time, "sleep", sleeps.append)
    client = FakeClient(
        [
            FakeApiError(
                429,
                "quota for private-project-name",
                details=[
                    {
                        "@type": "type.googleapis.com/google.rpc.RetryInfo",
                        "retryDelay": "17s",
                    }
                ],
            ),
            FakeResponse(
                _response(),
                response_id="after-rate-limit",
                model_version="gemini-server-001",
            ),
        ]
    )
    provider = _provider(
        tmp_path,
        monkeypatch,
        client,
        max_attempts=2,
        rate_limit_retry_delay_seconds=5,
        max_rate_limit_wait_seconds=30,
    )
    case = tmp_path / "rate-limit"

    assert provider.complete({"step": 1}, case_directory=case, step=1) == _response()
    assert sleeps == [17.0]
    metadata = provider.response_metadata(case, 1)
    assert metadata["attempt_history"][0] == {
        "attempt": 1,
        "outcome": "RETRY",
        "cause": "TRANSPORT",
        "provider_code": 429,
        "raw_response": None,
        "retry_delay_seconds": 17.0,
    }
    assert "private-project-name" not in json.dumps(metadata)


def test_gemini_retries_invalid_final_semantics_with_controller_feedback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invalid = _response(
        verdict="TRUE_POSITIVE",
        reason_codes=["CONSTANT_VALUE"],
        evidence=[
            {
                "file": "src/app.py",
                "start_line": 30,
                "end_line": 32,
                "description": "This range was not exposed.",
            }
        ],
    )
    valid = _response(
        verdict="TRUE_POSITIVE",
        reason_codes=[],
        evidence=[
            {
                "file": "src/app.py",
                "start_line": 3,
                "end_line": 5,
                "description": "The controller exposed this source range.",
            }
        ],
    )
    client = FakeClient(
        [
            FakeResponse(
                invalid,
                response_id="invalid-semantics",
                model_version="gemini-server-001",
            ),
            FakeResponse(
                valid,
                response_id="valid-semantics",
                model_version="gemini-server-001",
            ),
        ]
    )
    provider = _provider(tmp_path, monkeypatch, client, max_attempts=2)
    request = {
        "task": "blind_security_finding_verification",
        "step": 1,
        "initial_observations": [
            {
                "ok": True,
                "tool": "read_file",
                "path": "src/app.py",
                "start_line": 1,
                "end_line": 10,
                "content": "bounded source",
            }
        ],
    }
    case = tmp_path / "semantic-retry"

    assert provider.complete(request, case_directory=case, step=1) == valid
    feedback = client.models.calls[1]["contents"][-1]["parts"][1]["text"]
    assert "only FALSE_POSITIVE" in feedback
    metadata = provider.response_metadata(case, 1)
    assert metadata["attempt_history"][0]["cause"] == "RESPONSE_SEMANTICS"
    assert metadata["attempt_history"][0]["validation_feedback"] == (
        "only FALSE_POSITIVE may contain false-positive reason codes"
    )


def test_gemini_retries_citation_outside_controller_exposure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invalid = _response(
        evidence=[
            {
                "file": "src/app.py",
                "start_line": 30,
                "end_line": 32,
                "description": "This range was not exposed.",
            }
        ]
    )
    valid = _response()
    client = FakeClient(
        [
            FakeResponse(
                invalid,
                response_id="invalid-evidence",
                model_version="gemini-server-001",
            ),
            FakeResponse(
                valid,
                response_id="valid-evidence",
                model_version="gemini-server-001",
            ),
        ]
    )
    provider = _provider(tmp_path, monkeypatch, client, max_attempts=2)
    request = {
        "task": "blind_security_finding_verification",
        "step": 1,
        "initial_observations": [
            {
                "ok": True,
                "tool": "read_file",
                "path": "src/app.py",
                "start_line": 1,
                "end_line": 10,
                "content": "bounded source",
            }
        ],
    }
    case = tmp_path / "evidence-retry"

    assert provider.complete(request, case_directory=case, step=1) == valid
    feedback = client.models.calls[1]["contents"][-1]["parts"][1]["text"]
    assert "already exposed" in feedback
    metadata = provider.response_metadata(case, 1)
    assert metadata["attempt_history"][0]["cause"] == "RESPONSE_SEMANTICS"


def test_gemini_redacts_secret_shaped_text_from_response_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "AIzaSecretThatMustNotBePersisted123456789"
    client = FakeClient(
        [
            FakeResponse(
                _response(working_hypothesis=f"api_key={secret}"),
                response_id="redacted-response",
                model_version="gemini-server-001",
            )
        ]
    )
    provider = _provider(tmp_path, monkeypatch, client)
    case = tmp_path / "redaction"

    result = provider.complete({"step": 1}, case_directory=case, step=1)

    assert secret not in json.dumps(result)
    assert "[REDACTED]" in result["working_hypothesis"]
    assert all(
        secret not in path.read_text(encoding="utf-8", errors="replace")
        for path in case.rglob("*")
        if path.is_file()
    )


def test_gemini_uses_google_key_precedence_without_persisting_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}
    fake_client = FakeClient([])

    def client_factory(**kwargs: Any) -> FakeClient:
        captured.update(kwargs)
        return fake_client

    _install_fake_sdk(monkeypatch, client_factory=client_factory)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-secret")
    monkeypatch.setenv("GOOGLE_API_KEY", "google-secret")
    provider = GeminiApiProvider(
        response_schema=RESPONSE_SCHEMA,
        prompt_text="prompt",
        timeout_seconds=30,
        model="gemini-pinned-test-model",
        client=None,
        sdk_version="2.14.0-test",
    )

    assert captured["api_key"] == "google-secret"
    assert captured["http_options"]["retry_options"] == {"attempts": 1}
    serialized_config = json.dumps(provider.configuration)
    assert "google-secret" not in serialized_config
    assert "gemini-secret" not in serialized_config
    assert provider.configuration["credential_source"] == "GOOGLE_API_KEY"


def test_gemini_provider_version_locks_adapter_and_generation_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _provider(tmp_path, monkeypatch, FakeClient([]), seed=11)
    second = _provider(tmp_path, monkeypatch, FakeClient([]), seed=12)

    assert first.adapter_sha256 == second.adapter_sha256
    assert first.configuration_sha256 != second.configuration_sha256
    assert first.version != second.version
    assert first.adapter_sha256 in first.version
    assert first.configuration_sha256 in first.version

    with pytest.raises(ProviderError, match="latest"):
        _provider(tmp_path, monkeypatch, FakeClient([]), model="gemini-flash-latest")


def test_gemini_fails_closed_without_server_model_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = FakeClient(
        [
            FakeResponse(
                _response(),
                response_id="response-without-version",
                model_version="",
            )
        ]
    )
    provider = _provider(tmp_path, monkeypatch, client)

    with pytest.raises(ProviderError, match="MODEL_VERSION_MISSING"):
        provider.complete(
            {"step": 1}, case_directory=tmp_path / "missing-version", step=1
        )


def test_gemini_rejects_backend_model_version_change_within_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = FakeClient(
        [
            FakeResponse(
                _response(),
                response_id="response-1",
                model_version="gemini-server-001",
            ),
            FakeResponse(
                _response(),
                response_id="response-2",
                model_version="gemini-server-002",
            ),
        ]
    )
    provider = _provider(tmp_path, monkeypatch, client)
    case = tmp_path / "changed-version"

    provider.complete({"step": 1}, case_directory=case, step=1)
    with pytest.raises(ProviderError, match="MODEL_VERSION_CHANGED_DURING_RUN"):
        provider.complete({"step": 2}, case_directory=case, step=2)


def test_gemini_rejects_reused_response_id_within_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = FakeClient(
        [
            FakeResponse(
                _response(),
                response_id="duplicate-response",
                model_version="gemini-server-001",
            ),
            FakeResponse(
                _response(),
                response_id="duplicate-response",
                model_version="gemini-server-001",
            ),
        ]
    )
    provider = _provider(tmp_path, monkeypatch, client)
    case = tmp_path / "duplicate-response"

    provider.complete({"step": 1}, case_directory=case, step=1)
    with pytest.raises(ProviderError, match="RESPONSE_ID_REUSED_DURING_RUN"):
        provider.complete({"step": 2}, case_directory=case, step=2)


def test_gemini_archives_prior_provider_artifacts_before_resumed_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = tmp_path / "case"
    first = _provider(
        tmp_path,
        monkeypatch,
        FakeClient(
            [
                FakeResponse(
                    _response(reasoning="first attempt"),
                    response_id="first-response",
                    model_version="gemini-server-001",
                )
            ]
        ),
    )
    first.complete({"step": 1}, case_directory=case, step=1)
    first_raw_sha = first.response_metadata(case, 1)["raw_response"]["sha256"]
    first.close_case(case)

    resumed = _provider(
        tmp_path,
        monkeypatch,
        FakeClient(
            [
                FakeResponse(
                    _response(reasoning="resumed attempt"),
                    response_id="resumed-response",
                    model_version="gemini-server-001",
                )
            ]
        ),
    )
    resumed.complete({"step": 1}, case_directory=case, step=1)

    archive = case / "attempts" / "0001"
    assert (archive / "step-01-raw-response.json").is_file()
    assert (archive / "step-01-response.json").is_file()
    assert (archive / "step-01-events.jsonl").is_file()
    assert (archive / "step-01-provider-metadata.json").is_file()
    assert (archive / "provider-session.json").is_file()
    assert hashlib.sha256(
        (archive / "step-01-raw-response.json").read_bytes()
    ).hexdigest() == first_raw_sha
    assert resumed.response_metadata(case, 1)["response_id"] == "resumed-response"


def test_cli_selects_gemini_provider_and_passes_reproducibility_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = {
        "schema_version": 1,
        "finding_id": "finding-test",
        "member_finding_ids": ["finding-test"],
        "repo_url": "https://github.com/example/project",
        "commit": "a" * 40,
        "scanner": {"name": "semgrep", "version": "1.0"},
        "rule": {
            "id": "python/example",
            "ruleset_commit": "b" * 40,
            "cwe": ["CWE-78"],
            "category": "security",
            "severity": "warning",
        },
        "message": "Possible command execution",
        "location": {"file": "src/app.py", "start_line": 1, "end_line": 1},
        "dataflow_trace": [],
        "snippet": "run(value)",
        "fingerprint": "fingerprint",
        "provenance": {"raw_result_ref": "raw.json#0", "scan_id": "scan"},
    }
    input_path = tmp_path / "input.jsonl"
    input_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "profile_id": "test-profile",
                "threat_model": "Prove attacker influence and security effect.",
                "limits": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_text("Pinned prompt.\n", encoding="utf-8")
    captured: dict[str, Any] = {}

    class ProviderStub:
        provider_id = "gemini-stub"
        version = "test"
        model = "gemini-model"
        stateful = True

    def provider_factory(**kwargs: Any) -> ProviderStub:
        captured["provider_args"] = kwargs
        return ProviderStub()

    def execute_stub(**kwargs: Any) -> dict[str, Any]:
        captured["execute_args"] = kwargs
        return {
            "complete": True,
            "case_counts": {"total": 1, "success": 1, "failed": 0},
        }

    monkeypatch.setattr(gemini_verifier_agent, "GeminiApiProvider", provider_factory)
    monkeypatch.setattr(gemini_verifier_agent, "execute_run", execute_stub)
    result = gemini_verifier_agent.main(
        [
            "--input",
            str(input_path),
            "--snapshot-root",
            str(tmp_path / "snapshots"),
            "--run-dir",
            str(tmp_path / "run"),
            "--profile",
            str(profile_path),
            "--prompt",
            str(prompt_path),
            "--response-schema",
            str(RESPONSE_SCHEMA),
            "--provider",
            "gemini-api",
            "--model",
            "gemini-model",
            "--gemini-thinking-level",
            "medium",
            "--seed",
            "23",
            "--temperature",
            "0.2",
            "--gemini-max-attempts",
            "2",
            "--development-run",
        ]
    )

    assert result == 0
    assert captured["provider_args"]["model"] == "gemini-model"
    assert captured["provider_args"]["thinking_level"] == "medium"
    assert captured["provider_args"]["seed"] == 23
    assert captured["provider_args"]["temperature"] == 0.2
    assert captured["provider_args"]["max_attempts"] == 2
    assert captured["execute_args"]["evaluation_mode"] == "DEVELOPMENT"
