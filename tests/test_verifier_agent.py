from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from vulngym_enrich import verifier_agent
from vulngym_enrich.verifier_agent import (
    AgentProfile,
    BlindInputError,
    EvidenceToolbox,
    PredictionError,
    ProviderError,
    SourcePolicyError,
    VerifierError,
    _provider_usage,
    audit_provider_events,
    execute_run,
    run_finding,
    validate_blind_input,
)


ROOT = Path(__file__).resolve().parents[1]


def _assert_prediction_schema(value: dict[str, Any]) -> None:
    schema = json.loads(
        (ROOT / "schemas" / "verifier-prediction.schema.json").read_text(
            encoding="utf-8"
        )
    )
    errors = list(Draft202012Validator(schema).iter_errors(value))
    assert not errors, errors[0].message if errors else ""


def _assert_run_schema(value: dict[str, Any]) -> None:
    schema = json.loads(
        (ROOT / "schemas" / "verifier-run.schema.json").read_text(
            encoding="utf-8"
        )
    )
    errors = list(Draft202012Validator(schema).iter_errors(value))
    assert not errors, errors[0].message if errors else ""


def _profile(**overrides: Any) -> AgentProfile:
    values: dict[str, Any] = {
        "profile_id": "test-profile",
        "max_steps": 4,
        "max_tool_calls_per_step": 3,
        "max_context_chars": 20_000,
        "max_read_lines": 50,
        "max_source_file_bytes": 100_000,
        "max_search_results": 10,
        "max_directory_entries": 20,
        "initial_context_radius": 2,
        "trace_context_radius": 1,
        "max_initial_trace_nodes": 4,
        "max_evidence_lines": 10,
        "search_timeout_seconds": 5,
        "provider_timeout_seconds": 30,
        "threat_model": "Attacker control, reachability, effect, and controls must be proved.",
    }
    values.update(overrides)
    return AgentProfile(**values)


def _record() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "finding_id": "finding-test",
        "member_finding_ids": ["finding-member"],
        "repo_url": "https://github.com/example/project",
        "commit": "a" * 40,
        "scanner": {"name": "semgrep", "version": "1.171.0"},
        "rule": {
            "id": "py/example",
            "ruleset_commit": "b" * 40,
            "cwe": ["CWE-78"],
            "category": "security",
            "severity": "warning",
        },
        "message": "Possible command execution",
        "location": {
            "file": "src/app.py",
            "start_line": 5,
            "end_line": 5,
        },
        "dataflow_trace": [],
        "snippet": "run(clean)",
        "fingerprint": "fingerprint",
        "provenance": {"raw_result_ref": "raw.json#result/0", "scan_id": "scan"},
    }


def _response(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "action": "FINAL",
        "working_hypothesis": "The value is constrained before the sink.",
        "tool_requests": [],
        "verdict": "FALSE_POSITIVE",
        "confidence": "HIGH",
        "reason_codes": ["CONSTANT_VALUE"],
        "attacker_capability": "An HTTP caller can select only a fixed action name.",
        "entry_point": "handler receives the request value.",
        "security_effect": "The scanner models run as arbitrary command execution.",
        "controls": "A strict allowlist replaces the request value with a constant.",
        "reasoning": "Every reachable call passes the allowlisted constant to run.",
        "evidence": [
            {
                "file": "src/app.py",
                "start_line": 3,
                "end_line": 5,
                "description": "The allowlist selects a fixed constant before the sink.",
            }
        ],
        "abstain_reason": None,
    }
    value.update(overrides)
    return value


class FakeProvider:
    provider_id = "fake-provider"
    model = "fake-model"
    version = "1.0"
    stateful = False

    def __init__(self, responses: list[dict[str, Any] | Exception]):
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []

    def complete(
        self,
        request: dict[str, Any],
        *,
        case_directory: Path,
        step: int,
    ) -> dict[str, Any]:
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _snapshot(tmp_path: Path) -> Path:
    root = tmp_path / "snapshot"
    source = root / "src" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "def handler(value):\n"
        "    allowed = {'status': 'echo-status'}\n"
        "    clean = allowed.get(value)\n"
        "    if clean is None:\n"
        "        return run(clean)\n"
        "    return None\n",
        encoding="utf-8",
    )
    return root


def _write_profile_and_prompt(tmp_path: Path) -> tuple[Path, Path]:
    profile = _profile()
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "profile_id": profile.profile_id,
                "threat_model": profile.threat_model,
                "limits": {
                    field: getattr(profile, field)
                    for field in profile.__dataclass_fields__
                    if field not in {"profile_id", "threat_model"}
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_text("Pinned test prompt.\n", encoding="utf-8")
    return profile_path, prompt_path


def _write_input(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_complete_summary(input_path: Path, *, records: int = 1) -> Path:
    summary_path = input_path.parent / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "complete": True,
                "blind_verifier_input": {
                    "path": input_path.name,
                    "records": records,
                    "sha256": _file_sha256(input_path),
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return summary_path


def test_blind_input_rejects_duplicate_and_recursive_label_metadata() -> None:
    record = _record()
    validate_blind_input([record])

    duplicate = dict(record)
    with pytest.raises(BlindInputError, match="duplicate finding_id"):
        validate_blind_input([record, duplicate])

    contaminated = _record()
    contaminated["provenance"] = {
        "raw_result_ref": "raw.json#0",
        "nested": {"linked_report_ids": ["hidden"]},
    }
    with pytest.raises(BlindInputError, match="forbidden blind-input key"):
        validate_blind_input([contaminated])


def test_blind_input_rejects_advisory_identifier_and_path_traversal() -> None:
    contaminated = _record()
    contaminated["message"] = "Known as CVE-2026-12345"
    with pytest.raises(BlindInputError, match="advisory identifier"):
        validate_blind_input([contaminated])

    traversal = _record()
    traversal["location"] = {
        "file": "../labels.jsonl",
        "start_line": 1,
        "end_line": 1,
    }
    with pytest.raises(BlindInputError, match="unsafe source path"):
        validate_blind_input([traversal])


@pytest.mark.parametrize(
    "leaked_key",
    [
        "Linked-Report-Ids",
        "linkedReportIds",
        "Match-Tier",
        "vulngymMatches",
        "technicalLabel",
        "fixedCommit",
    ],
)
def test_blind_input_rejects_nested_leakage_key_variants(leaked_key: str) -> None:
    contaminated = _record()
    contaminated["provenance"] = {
        "raw_result_ref": "raw.json#0",
        "nested": [{"human_only_metadata": {leaked_key: "opaque-value"}}],
    }

    with pytest.raises(BlindInputError, match="forbidden blind-input key"):
        validate_blind_input([contaminated])


def test_blind_input_rejects_identifiers_nested_in_arrays() -> None:
    contaminated = _record()
    contaminated["provenance"] = {
        "raw_result_ref": "raw.json#0",
        "nested": [{"notes": [["candidate entry-00123"]]}],
    }

    with pytest.raises(BlindInputError, match="VulnGym entry identifier"):
        validate_blind_input([contaminated])


def test_toolbox_rejects_symlink_and_never_exposes_git(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    outside = tmp_path / "labels.txt"
    outside.write_text("FP_CONFIRMED", encoding="utf-8")
    link = snapshot / "src" / "escape.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable in this environment")
    toolbox = EvidenceToolbox(snapshot, _profile())
    with pytest.raises(SourcePolicyError, match="symlink"):
        toolbox._safe_path("src/escape.txt")
    with pytest.raises(SourcePolicyError, match="unsafe source path"):
        toolbox._safe_path(".git/config")


def test_agent_uses_controller_tools_and_freezes_structured_evidence(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(tmp_path)
    tool_response = _response(
        action="REQUEST_TOOLS",
        working_hypothesis="Inspect the allowlist assignment.",
        tool_requests=[
            {
                "tool": "read_file",
                "path": "src/app.py",
                "query": None,
                "start_line": 1,
                "end_line": 6,
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
        abstain_reason=None,
    )
    provider = FakeProvider([tool_response, _response()])

    prediction = run_finding(
        record=_record(),
        snapshot=snapshot,
        profile=_profile(),
        provider=provider,
        case_directory=tmp_path / "case",
    )

    assert prediction["verdict"] == "FALSE_POSITIVE"
    assert prediction["evaluation_eligible"] is True
    assert prediction["reason_codes"] == ["CONSTANT_VALUE"]
    assert prediction["agent"]["controller_tool_calls"] == 1
    assert prediction["evidence"][0]["file"] == "src/app.py"
    assert "3:     clean = allowed.get(value)" in prediction["evidence"][0]["code"]
    assert all("vulngym_matches" not in request["finding"] for request in provider.requests)
    _assert_prediction_schema(prediction)


def test_agent_splits_oversized_evidence_without_dropping_source_lines(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(tmp_path)
    source = snapshot / "src" / "app.py"
    source.write_text(
        "".join(f"line {number}\n" for number in range(1, 31)),
        encoding="utf-8",
    )
    tool_response = _response(
        action="REQUEST_TOOLS",
        working_hypothesis="Inspect the complete relevant block.",
        tool_requests=[
            {
                "tool": "read_file",
                "path": "src/app.py",
                "query": None,
                "start_line": 1,
                "end_line": 30,
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
        abstain_reason=None,
    )
    final_response = _response(
        evidence=[
            {
                "file": "src/app.py",
                "start_line": 1,
                "end_line": 21,
                "description": "The complete cited block supports the decision.",
            }
        ]
    )

    prediction = run_finding(
        record=_record(),
        snapshot=snapshot,
        profile=_profile(max_evidence_lines=10),
        provider=FakeProvider([tool_response, final_response]),
        case_directory=tmp_path / "case",
    )

    assert [node["line"] for node in prediction["evidence"]] == [
        "1-10",
        "11-20",
        21,
    ]
    assert "1: line 1" in prediction["evidence"][0]["code"]
    assert "21: line 21" in prediction["evidence"][2]["code"]
    _assert_prediction_schema(prediction)


def test_model_receives_only_bounded_non_identity_finding_projection(
    tmp_path: Path,
) -> None:
    record = _record()
    record["message"] = "M" * 50_000
    record["snippet"] = "S" * 50_000
    record["dataflow_trace"] = [
        {
            "file": "src/app.py",
            "line": 5,
            "description": "D" * 50_000,
            "code": "C" * 50_000,
        }
    ]
    profile = _profile(max_context_chars=4_000)
    provider = FakeProvider([_response()])

    prediction = run_finding(
        record=record,
        snapshot=_snapshot(tmp_path),
        profile=profile,
        provider=provider,
        case_directory=tmp_path / "case",
    )

    projection = provider.requests[0]["finding"]
    assert set(projection) == {
        "scanner",
        "rule",
        "message",
        "location",
        "dataflow_trace",
        "snippet",
    }
    encoded_projection = json.dumps(
        projection, ensure_ascii=False, separators=(",", ":")
    )
    assert len(encoded_projection) <= profile.max_context_chars
    for controller_only_key in (
        "schema_version",
        "finding_id",
        "member_finding_ids",
        "repo_url",
        "commit",
        "fingerprint",
        "provenance",
    ):
        assert controller_only_key not in projection
    assert prediction["finding_id"] == record["finding_id"]


def test_false_positive_without_reason_code_is_rejected(tmp_path: Path) -> None:
    provider = FakeProvider([_response(reason_codes=[])])
    with pytest.raises(PredictionError, match="requires at least one reason code"):
        run_finding(
            record=_record(),
            snapshot=_snapshot(tmp_path),
            profile=_profile(),
            provider=provider,
            case_directory=tmp_path / "case",
        )


def test_provider_failure_is_not_converted_to_abstain(tmp_path: Path) -> None:
    provider = FakeProvider([ProviderError("transport failed")])
    with pytest.raises(ProviderError, match="transport failed"):
        run_finding(
            record=_record(),
            snapshot=_snapshot(tmp_path),
            profile=_profile(),
            provider=provider,
            case_directory=tmp_path / "case",
        )


def test_development_prediction_is_ineligible_and_stateful_delta_is_small(
    tmp_path: Path,
) -> None:
    tool_response = _response(
        action="REQUEST_TOOLS",
        working_hypothesis="Inspect the full function.",
        tool_requests=[
            {
                "tool": "read_file",
                "path": "src/app.py",
                "query": None,
                "start_line": 1,
                "end_line": 6,
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
        abstain_reason=None,
    )
    provider = FakeProvider([tool_response, _response()])
    provider.stateful = True
    prediction = run_finding(
        record=_record(),
        snapshot=_snapshot(tmp_path),
        profile=_profile(),
        provider=provider,
        case_directory=tmp_path / "case",
        evaluation_eligible=False,
        exclusion_reason="DEVELOPMENT_OR_PARTIAL_INPUT",
    )

    assert prediction["evaluation_eligible"] is False
    assert prediction["exclusion_reason"] == "DEVELOPMENT_OR_PARTIAL_INPUT"
    assert "finding" in provider.requests[0]
    assert "finding" not in provider.requests[1]
    assert "latest_controller_exchange" in provider.requests[1]
    _assert_prediction_schema(prediction)


def test_provider_usage_uses_last_cumulative_counter_per_session(tmp_path: Path) -> None:
    case = tmp_path / "case"
    case.mkdir()
    for step, usage in enumerate(
        [
            {"input_tokens": 100, "cached_input_tokens": 0, "output_tokens": 20},
            {"input_tokens": 240, "cached_input_tokens": 80, "output_tokens": 35},
        ],
        1,
    ):
        events = [
            {"type": "thread.started", "thread_id": "same-session"},
            {"type": "turn.completed", "usage": usage},
        ]
        (case / f"step-{step:02d}-events.jsonl").write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )

    assert _provider_usage(case) == {
        "cached_input_tokens": 80,
        "input_tokens": 240,
        "output_tokens": 35,
    }


def test_provider_event_audit_rejects_direct_shell_tool(tmp_path: Path) -> None:
    events = tmp_path / "events.jsonl"
    events.write_text(
        json.dumps(
            {
                "type": "item.completed",
                "item": {"type": "command_execution", "command": "rg secret .."},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ProviderError):
        audit_provider_events(events)


@pytest.mark.parametrize(
    "event_type",
    ["future_tool_execution", "function_call", "computer_action"],
)
def test_provider_event_audit_rejects_unknown_tool_like_events(
    tmp_path: Path, event_type: str
) -> None:
    events = tmp_path / "events.jsonl"
    events.write_text(
        json.dumps(
            {
                "type": "item.completed",
                "item": {"type": event_type, "name": "unrecognized-provider-capability"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ProviderError):
        audit_provider_events(events)


def test_provider_event_audit_accepts_known_non_tool_events(tmp_path: Path) -> None:
    events = tmp_path / "events.jsonl"
    rows = [
        {"type": "thread.started", "thread_id": "thread-1"},
        {"type": "turn.started"},
        {
            "type": "item.completed",
            "item": {"type": "agent_message", "text": "structured response written"},
        },
        {"type": "turn.completed", "usage": {"input_tokens": 10}},
    ]
    events.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    audit_provider_events(events)


@pytest.mark.parametrize(
    ("identity_key", "identity_value"),
    [
        ("finding_id", "forged-finding"),
        ("evaluation_eligible", False),
        ("exclusion_reason", "MODEL_SELECTED_EXCLUSION"),
        ("agent", {"provider": "forged"}),
    ],
)
def test_response_schema_and_controller_reject_model_supplied_identity(
    tmp_path: Path, identity_key: str, identity_value: Any
) -> None:
    response = _response()
    response[identity_key] = identity_value
    schema = json.loads(
        (ROOT / "schemas" / "verifier-agent-response.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert list(Draft202012Validator(schema).iter_errors(response))
    with pytest.raises(ProviderError, match="unexpected keys"):
        run_finding(
            record=_record(),
            snapshot=_snapshot(tmp_path),
            profile=_profile(),
            provider=FakeProvider([response]),
            case_directory=tmp_path / "case",
        )


def _official_cli_args(
    *,
    input_path: Path,
    run_directory: Path,
    profile_path: Path,
    prompt_path: Path,
) -> list[str]:
    return [
        "--input",
        str(input_path),
        "--snapshot-root",
        str(input_path.parent / "snapshots"),
        "--run-dir",
        str(run_directory),
        "--profile",
        str(profile_path),
        "--prompt",
        str(prompt_path),
        "--response-schema",
        str(ROOT / "schemas" / "verifier-agent-response.schema.json"),
        "--model",
        "pinned-test-model",
    ]


def test_official_mode_requires_valid_complete_summary_count_and_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "blind-verifier-input.jsonl"
    _write_input(input_path, [_record()])
    profile_path, prompt_path = _write_profile_and_prompt(tmp_path)
    args = _official_cli_args(
        input_path=input_path,
        run_directory=tmp_path / "run",
        profile_path=profile_path,
        prompt_path=prompt_path,
    )
    summary_path = input_path.parent / "summary.json"

    def provider_must_not_start(**_: Any) -> FakeProvider:
        raise AssertionError("provider started before official input validation")

    monkeypatch.setattr(verifier_agent, "CodexCliProvider", provider_must_not_start)
    invalid_summaries: list[str | None] = [
        None,
        "{not-json}\n",
        json.dumps({"complete": True}),
        json.dumps(
            {
                "complete": False,
                "blind_verifier_input": {
                    "records": 1,
                    "sha256": _file_sha256(input_path),
                },
            }
        ),
        json.dumps(
            {
                "complete": True,
                "blind_verifier_input": {
                    "records": 2,
                    "sha256": _file_sha256(input_path),
                },
            }
        ),
        json.dumps(
            {
                "complete": True,
                "blind_verifier_input": {
                    "records": 1,
                    "sha256": "0" * 64,
                },
            }
        ),
    ]
    for rendered in invalid_summaries:
        if rendered is None:
            summary_path.unlink(missing_ok=True)
        else:
            summary_path.write_text(rendered + "\n", encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            verifier_agent.main(args)
        assert exc_info.value.code == 2


def test_official_mode_accepts_verified_summary_and_forbids_record_filtering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "blind-verifier-input.jsonl"
    _write_input(input_path, [_record()])
    _write_complete_summary(input_path)
    profile_path, prompt_path = _write_profile_and_prompt(tmp_path)
    args = _official_cli_args(
        input_path=input_path,
        run_directory=tmp_path / "run",
        profile_path=profile_path,
        prompt_path=prompt_path,
    )
    captured: dict[str, Any] = {}

    def fake_execute_run(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {
            "complete": True,
            "case_counts": {"total": 1, "success": 1, "failed": 0},
        }

    monkeypatch.setattr(
        verifier_agent,
        "CodexCliProvider",
        lambda **_: FakeProvider([]),
    )
    monkeypatch.setattr(verifier_agent, "execute_run", fake_execute_run)

    assert verifier_agent.main(args) == 0
    assert captured["evaluation_mode"] == "OFFICIAL"
    assert [row["finding_id"] for row in captured["records"]] == ["finding-test"]

    with pytest.raises(SystemExit) as exc_info:
        verifier_agent.main([*args, "--finding-id", "finding-test"])
    assert exc_info.value.code == 2
    assert "--finding-id" in capsys.readouterr().err


@pytest.mark.parametrize("tamper_kind", ["checksum", "schema", "identity"])
def test_official_resume_rejects_tampered_success_prediction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper_kind: str,
) -> None:
    input_path = tmp_path / "blind-verifier-input.jsonl"
    _write_input(input_path, [_record()])
    _write_complete_summary(input_path)
    profile_path, prompt_path = _write_profile_and_prompt(tmp_path)
    snapshot = _snapshot(tmp_path)
    monkeypatch.setattr(
        verifier_agent.SnapshotResolver,
        "resolve",
        lambda self, record: snapshot,
    )
    snapshot_root = tmp_path / "snapshots"
    snapshot_root.mkdir()
    run_directory = tmp_path / f"run-{tamper_kind}"
    common = {
        "records": [_record()],
        "input_path": input_path,
        "snapshot_root": snapshot_root,
        "run_directory": run_directory,
        "profile": _profile(),
        "profile_path": profile_path,
        "prompt_path": prompt_path,
        "evaluation_mode": "OFFICIAL",
    }
    first_manifest = execute_run(provider=FakeProvider([_response()]), **common)
    assert first_manifest["complete"] is True
    _assert_run_schema(first_manifest)

    case_directory = next((run_directory / "cases").iterdir())
    prediction_path = case_directory / "prediction.json"
    status_path = case_directory / "status.json"
    prediction = json.loads(prediction_path.read_text(encoding="utf-8"))
    if tamper_kind == "checksum":
        prediction["reasoning"] = "tampered after the successful run"
    elif tamper_kind == "schema":
        del prediction["verdict"]
    else:
        prediction["finding_id"] = "forged-finding-id"
    prediction_path.write_text(
        json.dumps(prediction, indent=2) + "\n", encoding="utf-8"
    )
    if tamper_kind != "checksum":
        status = json.loads(status_path.read_text(encoding="utf-8"))
        status["prediction_sha256"] = _file_sha256(prediction_path)
        status_path.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")

    resumed_provider = FakeProvider([])
    with pytest.raises(VerifierError, match="prediction"):
        execute_run(provider=resumed_provider, **common)
    assert resumed_provider.requests == []


def test_verifier_schemas_accept_current_blind_inputs() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "blind-verifier-input.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)
    inputs = [
        ROOT
        / "artifacts"
        / "annotation-queue"
        / "day2-full-v4-20260804-semgrep-only"
        / "blind-verifier-input.jsonl",
    ]
    for input_path in inputs:
        if not input_path.exists():
            continue
        for line_number, line in enumerate(input_path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            errors = list(validator.iter_errors(json.loads(line)))
            assert not errors, f"{input_path.name}:{line_number}: {errors[0].message}"
