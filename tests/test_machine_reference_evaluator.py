from __future__ import annotations

from copy import deepcopy

import pytest

from vulngym_enrich.evaluator import validate_official_classification_inputs
from vulngym_enrich.machine_evaluator import (
    machine_reference_metrics,
    validate_machine_reference_classification_inputs,
)


def _machine_label(finding_id: str, label: str) -> dict:
    return {
        "schema_version": 1,
        "finding_id": finding_id,
        "label": label,
        "confidence": "HIGH" if label != "MACHINE_UNCERTAIN" else "LOW",
        "reason_codes": (
            ["CONSTANT_VALUE"] if label == "MACHINE_FALSE_POSITIVE" else []
        ),
        "reasoning": "Frozen source-backed model review.",
        "evidence": (
            []
            if label == "MACHINE_UNCERTAIN"
            else [
                {
                    "file": "src/example.py",
                    "line": 10,
                    "description": "Relevant source evidence.",
                    "code": "10: value = source()",
                }
            ]
        ),
        "uncertainty_reason": (
            "The exposed source is insufficient."
            if label == "MACHINE_UNCERTAIN"
            else None
        ),
        "reviewer": {
            "id": "reviewer-c",
            "kind": "MODEL",
            "role": "ADJUDICATOR_C",
            "provider": "gemini-api",
            "provider_version": "google-genai-test",
            "model": "gemini-test",
            "model_version": "gemini-server-test",
            "participants": [
                {
                    "id": "reviewer-c",
                    "provider": "gemini-api",
                    "provider_version": "google-genai-test",
                    "model": "gemini-test",
                    "model_version": "gemini-server-test",
                }
            ],
        },
        "reviewed_at": "2026-08-13T12:00:00+07:00",
        "provenance": {
            "method": "LLM_ADJUDICATED",
            "source_scanner": "opengrep",
            "blind_first": True,
            "route_reasons": ["MODEL_DISAGREEMENT"],
            "reviewer_a_prediction_sha256": "a" * 64,
            "reviewer_b_prediction_sha256": "b" * 64,
            "adjudicator_blind_prediction_sha256": "c" * 64,
            "adjudicator_final_prediction_sha256": "d" * 64,
        },
        "linked_entry_ids": [],
    }


def _prediction(finding_id: str, verdict: str) -> dict:
    return {
        "finding_id": finding_id,
        "verdict": verdict,
        # Machine-reference evaluation is explicitly exploratory and may consume
        # a frozen development run without changing its eligibility bit.
        "evaluation_eligible": False,
    }


def test_machine_reference_metrics_are_explicitly_non_official() -> None:
    labels = [
        _machine_label("tp", "MACHINE_TRUE_POSITIVE"),
        _machine_label("fp", "MACHINE_FALSE_POSITIVE"),
        _machine_label("uncertain", "MACHINE_UNCERTAIN"),
    ]
    predictions = [
        _prediction("tp", "TRUE_POSITIVE"),
        _prediction("fp", "FALSE_POSITIVE"),
        _prediction("uncertain", "ABSTAIN"),
    ]

    report = machine_reference_metrics(labels, predictions)

    assert report["reference_policy"] == {
        "tier": "LLM_ADJUDICATED_MACHINE_REFERENCE",
        "human_gold": False,
        "publish_as_official": False,
        "metrics_name": (
            "exploratory metrics against frozen LLM-adjudicated reference labels"
        ),
    }
    assert report["positive_class"] == "machine_referenced_vulnerability"
    assert "TP_NOVEL" not in repr(report)
    assert report["confusion_matrix_decided_only"] == {
        "tp": 1,
        "fp": 0,
        "tn": 1,
        "fn": 0,
    }
    assert report["machine_prevalence"] == {
        "records": 3,
        "machine_true_positive": 1,
        "machine_false_positive": 1,
        "machine_uncertain": 1,
        "tp_fraction_lower_bound": 1 / 3,
        "tp_fraction_upper_bound": 2 / 3,
    }


def test_machine_reference_cannot_pass_human_gold_gate() -> None:
    label = _machine_label("finding", "MACHINE_TRUE_POSITIVE")
    prediction = _prediction("finding", "TRUE_POSITIVE")
    validate_machine_reference_classification_inputs([label], [prediction])
    with pytest.raises(ValueError, match="invalid gold label|human-reviewed"):
        validate_official_classification_inputs([label], [prediction])


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda row: row["reviewer"].update(kind="HUMAN"), "kind MODEL"),
        (lambda row: row["provenance"].update(method="HUMAN"), "provenance"),
        (lambda row: row.update(linked_entry_ids=["entry-00001"]), "cannot claim"),
        (lambda row: row.update(evidence=[]), "requires evidence"),
    ],
)
def test_machine_reference_gate_rejects_false_provenance(
    mutation, message: str
) -> None:
    row = deepcopy(_machine_label("finding", "MACHINE_TRUE_POSITIVE"))
    mutation(row)
    with pytest.raises(ValueError, match=message):
        validate_machine_reference_classification_inputs(
            [row], [_prediction("finding", "TRUE_POSITIVE")]
        )
