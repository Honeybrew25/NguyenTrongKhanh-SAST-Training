from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from vulngym_enrich import machine_review
from vulngym_enrich.machine_evaluator import (
    validate_frozen_machine_reference_package,
    validate_machine_reference_classification_inputs,
)
from vulngym_enrich.machine_review import (
    MachineReviewError,
    adjudicate,
    finalize_review,
    prepare_adjudication,
    prepare_review,
    reconcile_reviews,
)


ROOT = Path(__file__).resolve().parents[1]
PROVIDER = "google-gemini-api-isolated-json"
SDK = "sdk-test"


def _json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _value_sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _config(path: Path, role: str, model: str, seed: int) -> Path:
    _json(
        path,
        {
            "schema_version": 1,
            "id": role.casefold().replace("_", "-"),
            "kind": "MODEL",
            "role": role,
            "provider": PROVIDER,
            "provider_version": SDK,
            "model": model,
            "model_version": None,
            "thinking_level": "HIGH",
            "temperature": 0.0,
            "seed": seed,
        },
    )
    return path


def test_local_identity_config_is_frozen_with_artifact_digest() -> None:
    value = machine_review._validate_identity_config(
        {
            "schema_version": 1,
            "id": "reviewer-a",
            "kind": "MODEL",
            "role": "REVIEWER_A",
            "provider": machine_review.LOCAL_PROVIDER_ID,
            "provider_version": "openai-chat-completions-json-schema-v1",
            "model": "google/gemma-4-E4B-it",
            "model_version": None,
            "thinking_level": "SERVER_DEFAULT",
            "temperature": 0,
            "seed": 17011,
            "base_url": "http://127.0.0.1:1234/v1",
            "model_revision_sha256": "A" * 64,
            "max_tokens": 8192,
        },
        "REVIEWER_A",
    )
    assert value["provider"] == machine_review.LOCAL_PROVIDER_ID
    assert value["model_revision_sha256"] == "a" * 64
    assert value["thinking_level"] == "server_default"


def test_local_identity_config_rejects_remote_endpoint() -> None:
    with pytest.raises(MachineReviewError, match="loopback"):
        machine_review._validate_identity_config(
            {
                "schema_version": 1,
                "id": "reviewer-a",
                "kind": "MODEL",
                "role": "REVIEWER_A",
                "provider": machine_review.LOCAL_PROVIDER_ID,
                "provider_version": "openai-chat-completions-json-schema-v1",
                "model": "model-a",
                "model_version": None,
                "thinking_level": "SERVER_DEFAULT",
                "temperature": 0,
                "seed": 1,
                "base_url": "https://remote.example/v1",
                "model_revision_sha256": "a" * 64,
                "max_tokens": 8192,
            },
            "REVIEWER_A",
        )


def _sample(tmp_path: Path) -> tuple[Path, Path, Path, list[dict[str, Any]]]:
    sample = tmp_path / "sample"
    sample.mkdir(parents=True)
    snapshot_root = tmp_path / "snapshots"
    findings: list[dict[str, Any]] = []
    packets: list[dict[str, Any]] = []
    index: list[dict[str, Any]] = []
    for number in range(1, 5):
        finding_id = f"finding-{number}"
        commit = f"{number:040x}"
        finding = {
            "schema_version": 1,
            "finding_id": finding_id,
            "repo_url": "https://github.com/acme/repo",
            "commit": commit,
            "scanner": {"name": "opengrep", "version": "1.22.0"},
            "rule": {"id": "test.rule", "severity": "WARNING"},
            "message": "Potential unsafe value",
            "location": {
                "file": "src/app.py",
                "start_line": 1,
                "end_line": 1,
            },
            "dataflow_trace": [],
            "snippet": "dangerous(value)",
            "fingerprint": f"fingerprint-{number}",
            "provenance": {"scan_id": "opengrep-test"},
        }
        findings.append(finding)
        index.append({"finding_id": finding_id, "review_order": number})
        packets.append(
            {
                "schema_version": 1,
                "finding_id": finding_id,
                "review_order": number,
                "finding": {
                    **finding,
                    "scanner": {"name": "other", "version": "1.22.0"},
                },
                "initial_source_evidence": [],
                "snapshot": {
                    "repo_url": finding["repo_url"],
                    "commit": commit,
                    "git_state_verified": True,
                },
            }
        )
        source = snapshot_root / "acme__repo" / commit / "src" / "app.py"
        source.parent.mkdir(parents=True)
        source.write_text("dangerous(value)\n", encoding="utf-8")
    _jsonl(sample / "sampled-findings.jsonl", findings)
    _jsonl(sample / "sampling-index.jsonl", index)
    _json(
        sample / "sample-manifest.json",
        {
            "sample_id": "sample-test",
            "sampling": {"sample_size": 4},
            "outputs": {
                "sampled-findings.jsonl": {
                    "sha256": _sha(sample / "sampled-findings.jsonl")
                },
                "sampling-index.jsonl": {
                    "sha256": _sha(sample / "sampling-index.jsonl")
                },
            },
        },
    )
    evidence = tmp_path / "evidence-packets.jsonl"
    _jsonl(evidence, packets)
    return sample, evidence, snapshot_root, findings


def _prediction(finding_id: str, verdict: str, confidence: str = "HIGH") -> dict[str, Any]:
    fp = verdict == "FALSE_POSITIVE"
    return {
        "schema_version": 1,
        "finding_id": finding_id,
        "verdict": verdict,
        "confidence": confidence,
        "reason_codes": ["CONSTANT_VALUE"] if fp else [],
        "attacker_capability": "The caller may supply value.",
        "entry_point": "The value reaches the shown function.",
        "security_effect": "The reported sink may have a security effect.",
        "controls": "The source-backed condition determines the result.",
        "reasoning": "A source-backed reviewer decision.",
        "evidence": (
            []
            if verdict == "ABSTAIN"
            else [
                {
                    "file": "src/app.py",
                    "line": 1,
                    "description": "The relevant operation at the pinned commit.",
                    "code": "1: dangerous(value)",
                }
            ]
        ),
        "abstain_reason": "INSUFFICIENT_CONTEXT" if verdict == "ABSTAIN" else None,
        "evaluation_eligible": False,
        "exclusion_reason": "DEVELOPMENT_OR_PARTIAL_INPUT",
        "agent": {
            "profile_id": "profile-test",
            "provider": PROVIDER,
            "provider_version": "COMPOSITE",
            "model": "",
            "steps": 1,
            "controller_tool_calls": 0,
        },
    }


def _verifier_run(
    run: Path,
    input_path: Path,
    findings: list[dict[str, Any]],
    outcomes: dict[str, tuple[str, str]],
    *,
    model: str,
    seed: int,
    model_version: str,
    snapshot_root: Path,
) -> None:
    input_rows = [json.loads(line) for line in input_path.read_text().splitlines()]
    record_count = len(input_rows)
    frozen_input = run / "blind-verifier-input.jsonl"
    _jsonl(frozen_input, input_rows)
    predictions: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    configuration = {
        "sdk_version": SDK,
        "model": model,
        "thinking_level": "high",
        "seed": seed,
        "temperature": 0.0,
    }
    provider_configuration = {
        "schema_version": 1,
        "provider": PROVIDER,
        "provider_version": "COMPOSITE",
        "sdk_version": SDK,
        "configuration": configuration,
        "configuration_sha256": _value_sha(configuration),
    }
    _json(run / "gemini-provider-configuration.json", provider_configuration)
    _json(
        run / "run-identity.json",
        {
            "schema_version": 1,
            "provider": {
                "id": PROVIDER,
                "version": "COMPOSITE",
                "model": model,
            },
        },
    )
    by_id = {str(row["finding_id"]): row for row in findings}
    for input_row in input_rows:
        finding_id = str(input_row["finding_id"])
        verdict, confidence = outcomes[finding_id]
        prediction = _prediction(finding_id, verdict, confidence)
        prediction["agent"]["model"] = model
        predictions.append(prediction)
        case = run / "cases" / hashlib.sha256(finding_id.encode()).hexdigest()[:20]
        _json(case / "prediction.json", prediction)
        raw = {"responseId": f"response-{model}-{finding_id}", "modelVersion": model_version}
        _json(case / "step-01-raw-response.json", raw)
        metadata = {
            "schema_version": 1,
            "provider": PROVIDER,
            "provider_version": "COMPOSITE",
            "sdk_version": SDK,
            "configured_model": model,
            "configuration": configuration,
            "configuration_sha256": _value_sha(configuration),
            "step": 1,
            "model_version": model_version,
            "response_id": f"response-{model}-{finding_id}",
            "normalized_usage": {"input_tokens": 10, "output_tokens": 2},
            "raw_response": {
                "path": "step-01-raw-response.json",
                "bytes": (case / "step-01-raw-response.json").stat().st_size,
                "sha256": _sha(case / "step-01-raw-response.json"),
            },
        }
        _json(case / "step-01-provider-metadata.json", metadata)
        _json(case / "provider-session.json", {"provider": PROVIDER})
        status = {
            "schema_version": 1,
            "status": "SUCCESS",
            "identity": {"finding_id": finding_id},
            "prediction_sha256": _sha(case / "prediction.json"),
        }
        _json(case / "status.json", status)
        cases.append(status)
        assert by_id[finding_id]["commit"] == input_row["commit"]
    _jsonl(run / "verifier-predictions.jsonl", predictions)
    components = {
        name: _sha(path)
        for name, path in machine_review.SOURCE_REVIEW_COMPONENTS.items()
    }
    _json(
        run / "verifier-run.json",
        {
            "schema_version": 1,
            "status": "COMPLETE",
            "complete": True,
            "evaluation_mode": "DEVELOPMENT",
            "case_counts": {
                "total": record_count,
                "success": record_count,
                "failed": 0,
            },
            "input": {
                "frozen_copy": frozen_input.name,
                "sha256": _sha(frozen_input),
                "records": record_count,
            },
            "predictions": {
                "path": "verifier-predictions.jsonl",
                "sha256": _sha(run / "verifier-predictions.jsonl"),
                "records": record_count,
            },
            "profile": {"sha256": components["profile"]},
            "prompt": {"sha256": components["prompt"]},
            "response_schema": {"sha256": components["response_schema"]},
            "prediction_schema": {"sha256": components["prediction_schema"]},
            "controller": {"sha256": components["controller"]},
            "provider": {
                "id": PROVIDER,
                "version": "COMPOSITE",
                "model": model,
                "usage": {
                    "input_tokens": 10 * record_count,
                    "output_tokens": 2 * record_count,
                },
            },
            "source_policy": {"snapshot_root": str(snapshot_root)},
            "cases": cases,
        },
    )


def _prepare(tmp_path: Path) -> tuple[Path, Path, list[dict[str, Any]]]:
    sample, evidence, snapshots, findings = _sample(tmp_path)
    review = tmp_path / "review"
    configs = tmp_path / "configs"
    prepare_review(
        sample_directory=sample,
        evidence_packets_path=evidence,
        snapshot_root=snapshots,
        output_directory=review,
        reviewer_a_config_path=_config(configs / "a.json", "REVIEWER_A", "model-a", 1),
        reviewer_b_config_path=_config(configs / "b.json", "REVIEWER_B", "model-b", 2),
        adjudicator_config_path=_config(configs / "c.json", "ADJUDICATOR_C", "model-c", 3),
        evaluated_agent_model="model-under-test",
        expected_records=4,
        audit_fraction=0.5,
        reviewer_a_seed="order-a",
        reviewer_b_seed="order-b",
        created_at="2026-08-13T00:00:00+00:00",
    )
    return review, snapshots, findings


def test_prepare_freezes_independently_ordered_inputs_and_rejects_model_alias(tmp_path: Path) -> None:
    review, _, findings = _prepare(tmp_path)
    a = [json.loads(line)["finding_id"] for line in (review / "reviewer-a/blind-input.jsonl").read_text().splitlines()]
    b = [json.loads(line)["finding_id"] for line in (review / "reviewer-b/blind-input.jsonl").read_text().splitlines()]
    assert set(a) == set(b) == {row["finding_id"] for row in findings}
    assert a != b
    manifest = json.loads((review / "machine-review-manifest.json").read_text())
    assert manifest["publication_policy"]["human_gold"] is False
    assert "requirements-gemini.lock" in manifest["identity"]["implementation"]

    sample, evidence, snapshots, _ = _sample(tmp_path / "other")
    configs = tmp_path / "bad-configs"
    with pytest.raises(MachineReviewError, match="latest"):
        prepare_review(
            sample_directory=sample,
            evidence_packets_path=evidence,
            snapshot_root=snapshots,
            output_directory=tmp_path / "bad-review",
            reviewer_a_config_path=_config(configs / "a.json", "REVIEWER_A", "model-latest", 1),
            reviewer_b_config_path=_config(configs / "b.json", "REVIEWER_B", "model-b", 2),
            adjudicator_config_path=_config(configs / "c.json", "ADJUDICATOR_C", "model-c", 3),
            evaluated_agent_model="agent",
            expected_records=4,
        )


class _FakeProvider:
    provider_id = PROVIDER
    sdk_version = SDK
    version = "COMPOSITE-FINAL"

    def __init__(self) -> None:
        self.model = "model-c"
        self.configuration = {
            "sdk_version": SDK,
            "model": self.model,
            "thinking_level": "high",
            "seed": 3,
            "temperature": 0.0,
        }
        self.configuration_sha256 = _value_sha(self.configuration)

    def complete(self, request: dict[str, Any], *, case_directory: Path, step: int) -> dict[str, Any]:
        context = request["untrusted_adjudication_context"]
        finding_id = context["finding_id"]
        allowed = machine_review._allowed_evidence(context)
        response = (
            {
                "finding_id": finding_id,
                "verdict": "UNCERTAIN",
                "confidence": "LOW",
                "reason_codes": [],
                "reasoning": "Evidence remains insufficient after blind-first adjudication.",
                "evidence": [],
                "uncertainty_reason": "The exposed source does not establish all security conditions.",
            }
            if finding_id == sorted(row["finding_id"] for row in [context])[0]
            and "MODEL_DISAGREEMENT" in context["route_reasons"]
            else {
                "finding_id": finding_id,
                "verdict": "FALSE_POSITIVE",
                "confidence": "HIGH",
                "reason_codes": ["CONSTANT_VALUE"],
                "reasoning": "The exposed source proves a concrete negating condition.",
                "evidence": [allowed[0]],
                "uncertainty_reason": None,
            }
        )
        case_directory.mkdir(parents=True, exist_ok=True)
        raw = {"responseId": f"final-{finding_id}", "modelVersion": "actual-c"}
        _json(case_directory / "step-01-raw-response.json", raw)
        _json(case_directory / "step-01-response.json", response)
        metadata = {
            "schema_version": 1,
            "provider": self.provider_id,
            "provider_version": self.version,
            "sdk_version": self.sdk_version,
            "configured_model": self.model,
            "configuration": self.configuration,
            "configuration_sha256": self.configuration_sha256,
            "model_version": "actual-c",
            "response_id": f"final-{finding_id}",
            "step": 1,
            "normalized_usage": {"input_tokens": 5, "output_tokens": 2},
            "raw_response": {
                "path": "step-01-raw-response.json",
                "bytes": (case_directory / "step-01-raw-response.json").stat().st_size,
                "sha256": _sha(case_directory / "step-01-raw-response.json"),
            },
        }
        _json(case_directory / "step-01-provider-metadata.json", metadata)
        _json(case_directory / "provider-session.json", {"provider": self.provider_id})
        run = case_directory.parent.parent
        _json(
            run / "gemini-provider-configuration.json",
            {
                "provider": self.provider_id,
                "provider_version": self.version,
                "sdk_version": self.sdk_version,
                "configuration": self.configuration,
                "configuration_sha256": self.configuration_sha256,
            },
        )
        return response

    def response_metadata(self, case_directory: Path, step: int) -> dict[str, Any]:
        return json.loads((case_directory / "step-01-provider-metadata.json").read_text())

    def close_case(self, case_directory: Path) -> None:
        return None


def test_machine_review_routes_blind_first_and_finalizes_machine_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    review, snapshots, findings = _prepare(tmp_path)
    a_outcomes = {
        "finding-1": ("FALSE_POSITIVE", "HIGH"),
        "finding-2": ("TRUE_POSITIVE", "HIGH"),
        "finding-3": ("FALSE_POSITIVE", "HIGH"),
        "finding-4": ("FALSE_POSITIVE", "MEDIUM"),
    }
    b_outcomes = {
        "finding-1": ("FALSE_POSITIVE", "HIGH"),
        "finding-2": ("FALSE_POSITIVE", "HIGH"),
        "finding-3": ("FALSE_POSITIVE", "HIGH"),
        "finding-4": ("FALSE_POSITIVE", "HIGH"),
    }
    _verifier_run(
        review / "reviewer-a/run",
        review / "reviewer-a/blind-input.jsonl",
        findings,
        a_outcomes,
        model="model-a",
        seed=1,
        model_version="actual-a",
        snapshot_root=snapshots,
    )
    _verifier_run(
        review / "reviewer-b/run",
        review / "reviewer-b/blind-input.jsonl",
        findings,
        b_outcomes,
        model="model-b",
        seed=2,
        model_version="actual-b",
        snapshot_root=snapshots,
    )
    reconciliation = reconcile_reviews(
        review_directory=review,
        reviewer_a_run=review / "reviewer-a/run",
        reviewer_b_run=review / "reviewer-b/run",
        created_at="2026-08-13T01:00:00+00:00",
    )
    assert reconciliation["counts"] == {
        "routed_to_adjudicator": 3,
        "consensus_high_fp_not_routed": 1,
        "consensus_high_fp_total": 2,
        "consensus_high_fp_audited": 1,
    }
    assert reconciliation["agreement"]["records"] == 4
    assert reconciliation["agreement"]["agreements"] == 3
    blind_rows = [
        json.loads(line)
        for line in (review / "adjudicator-c/blind-input.jsonl").read_text().splitlines()
    ]
    c_outcomes = {row["finding_id"]: ("ABSTAIN", "HIGH") for row in blind_rows}
    routed_findings = [
        next(item for item in findings if item["finding_id"] == row["finding_id"])
        for row in blind_rows
    ]
    _verifier_run(
        review / "adjudicator-c/blind",
        review / "adjudicator-c/blind-input.jsonl",
        routed_findings,
        c_outcomes,
        model="model-c",
        seed=3,
        model_version="actual-c",
        snapshot_root=snapshots,
    )
    # The test helper writes a fixed total of four; adapt the routed run manifest.
    blind_run_path = review / "adjudicator-c/blind/verifier-run.json"
    blind_run = json.loads(blind_run_path.read_text())
    routed_count = len(blind_rows)
    blind_run["case_counts"] = {
        "total": routed_count,
        "success": routed_count,
        "failed": 0,
    }
    blind_run["input"]["records"] = routed_count
    blind_run["predictions"]["records"] = routed_count
    _json(blind_run_path, blind_run)

    preparation = prepare_adjudication(
        review_directory=review,
        blind_run=review / "adjudicator-c/blind",
        created_at="2026-08-13T02:00:00+00:00",
    )
    assert preparation["blindness_transition"][
        "blind_prediction_frozen_before_a_b_exposure"
    ]
    adjudication_rows = [
        json.loads(line)
        for line in (review / "adjudicator-c/adjudication-input.jsonl").read_text().splitlines()
    ]
    assert all("agent" not in json.dumps(row["anonymous_reviews"]) for row in adjudication_rows)

    monkeypatch.setattr(machine_review, "_new_adjudicator_provider", lambda **kwargs: _FakeProvider())
    adjudicate(
        review_directory=review,
        prompt_path=ROOT / "config/machine-adjudicator-prompt-v1.md",
        response_schema_path=ROOT / "schemas/machine-adjudicator-response.schema.json",
        model="model-c",
        thinking_level="high",
        temperature=0.0,
        seed=3,
    )
    summary = finalize_review(
        review_directory=review,
        reviewed_at="2026-08-13T03:00:00+00:00",
    )
    assert summary["status"] == "MACHINE_REFERENCE_READY_WITH_UNCERTAINTY"
    assert summary["publication_policy"]["publish_as_official"] is False
    assert summary["method_quality"]["adjudication"]["routed_records"] == 3
    assert summary["method_quality"]["consensus_high_fp_audit"][
        "audited_records"
    ] == 1
    labels = [
        json.loads(line)
        for line in (review / "machine-reference-labels.jsonl").read_text().splitlines()
    ]
    assert len(labels) == 4
    assert all(row["reviewer"]["kind"] == "MODEL" for row in labels)
    assert all(row["linked_entry_ids"] == [] for row in labels)
    assert any(row["label"] == "MACHINE_UNCERTAIN" for row in labels)
    predictions = [
        {"finding_id": row["finding_id"], "verdict": "ABSTAIN"}
        for row in labels
    ]
    validate_machine_reference_classification_inputs(labels, predictions)
    schema = json.loads((ROOT / "schemas/machine-reference-label.schema.json").read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    assert not [error for row in labels for error in validator.iter_errors(row)]
    assert validate_frozen_machine_reference_package(
        review / "machine-reference-labels.jsonl"
    ) == labels

    reconciliation_path = review / "reconciliation/reconciliation.jsonl"
    reconciliation_summary_path = (
        review / "reconciliation/reconciliation-summary.json"
    )
    original_reconciliation = [
        json.loads(line) for line in reconciliation_path.read_text().splitlines()
    ]
    reconciliation_summary = json.loads(reconciliation_summary_path.read_text())
    tampered_reconciliation = json.loads(json.dumps(original_reconciliation))
    tampered_reconciliation[0]["reviewer_a"]["reasoning"] = "Tampered opinion."
    _jsonl(reconciliation_path, tampered_reconciliation)
    reconciliation_summary["outputs"]["reconciliation"]["sha256"] = _sha(
        reconciliation_path
    )
    _json(reconciliation_summary_path, reconciliation_summary)
    with pytest.raises(ValueError, match="reconstructed A/B predictions"):
        validate_frozen_machine_reference_package(
            review / "machine-reference-labels.jsonl"
        )
    _jsonl(reconciliation_path, original_reconciliation)
    reconciliation_summary["outputs"]["reconciliation"]["sha256"] = _sha(
        reconciliation_path
    )
    _json(reconciliation_summary_path, reconciliation_summary)

    labels[0]["reasoning"] = "Tampered after finalization."
    _jsonl(review / "machine-reference-labels.jsonl", labels)
    with pytest.raises(ValueError, match="checksum proof"):
        validate_frozen_machine_reference_package(
            review / "machine-reference-labels.jsonl"
        )


def test_reconcile_routes_tampered_evidence_but_rejects_missing_model_version(
    tmp_path: Path,
) -> None:
    review, snapshots, findings = _prepare(tmp_path)
    outcomes = {row["finding_id"]: ("FALSE_POSITIVE", "HIGH") for row in findings}
    for role, model, seed in (("a", "model-a", 1), ("b", "model-b", 2)):
        _verifier_run(
            review / f"reviewer-{role}/run",
            review / f"reviewer-{role}/blind-input.jsonl",
            findings,
            outcomes,
            model=model,
            seed=seed,
            model_version=f"actual-{role}",
            snapshot_root=snapshots,
        )
    run_path = review / "reviewer-a/run/verifier-run.json"
    run_manifest = json.loads(run_path.read_text())
    run_manifest["evaluation_mode"] = "OFFICIAL"
    _json(run_path, run_manifest)
    with pytest.raises(MachineReviewError, match="DEVELOPMENT mode"):
        reconcile_reviews(
            review_directory=review,
            reviewer_a_run=review / "reviewer-a/run",
            reviewer_b_run=review / "reviewer-b/run",
        )
    run_manifest["evaluation_mode"] = "DEVELOPMENT"
    _json(run_path, run_manifest)

    case = next((review / "reviewer-a/run/cases").iterdir())
    metadata_path = case / "step-01-provider-metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["model_version"] = ""
    _json(metadata_path, metadata)
    with pytest.raises(MachineReviewError, match="metadata proof|model_version"):
        reconcile_reviews(
            review_directory=review,
            reviewer_a_run=review / "reviewer-a/run",
            reviewer_b_run=review / "reviewer-b/run",
        )
