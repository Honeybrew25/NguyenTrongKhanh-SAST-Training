from __future__ import annotations

from copy import deepcopy

import pytest

from vulngym_enrich.evaluator import validate_official_classification_inputs


def _label(finding_id: str, label: str) -> dict:
    row = {
        "schema_version": 1,
        "finding_id": finding_id,
        "label": label,
        "reason_codes": [],
        "reasoning": "Evidence-backed independent review.",
        "reviewer": {"id": "human-reviewer-1", "kind": "HUMAN"},
        "reviewed_at": "2026-08-06T14:00:00+07:00",
        "evidence": ["src/example.py:10-14"],
        "linked_entry_ids": [],
        "linked_report_ids": [],
    }
    if label == "TP_KNOWN":
        row["linked_entry_ids"] = ["entry-00001"]
        row["linked_report_ids"] = ["GHSA-AAAA-BBBB-CCCC"]
    elif label == "FP_CONFIRMED":
        row["reason_codes"] = ["NO_ATTACKER_CONTROL"]
    return row


def _prediction(finding_id: str, verdict: str = "TRUE_POSITIVE") -> dict:
    return {
        "finding_id": finding_id,
        "verdict": verdict,
        "evaluation_eligible": True,
    }


def test_official_gold_gate_accepts_complete_human_labels() -> None:
    labels = [
        _label("known", "TP_KNOWN"),
        _label("novel", "TP_NOVEL"),
        _label("false", "FP_CONFIRMED"),
        _label("uncertain", "UNCERTAIN"),
    ]
    predictions = [_prediction(row["finding_id"]) for row in labels]
    validate_official_classification_inputs(labels, predictions)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda row: row.update(label=None), "incomplete or invalid gold label"),
        (lambda row: row["reviewer"].update(kind="AI_TECHNICAL_REVIEW"), "human-reviewed"),
        (lambda row: row.update(evidence=[]), "evidence is required"),
        (lambda row: row.update(reviewed_at="2026-08-06"), "include a timezone"),
    ],
)
def test_official_gold_gate_rejects_incomplete_review(mutation, message: str) -> None:
    row = _label("finding", "TP_NOVEL")
    mutation(row)
    with pytest.raises(ValueError, match=message):
        validate_official_classification_inputs([row], [_prediction("finding")])


def test_official_gold_gate_requires_known_links_and_fp_reason() -> None:
    known = _label("known", "TP_KNOWN")
    known["linked_entry_ids"] = []
    with pytest.raises(ValueError, match="requires linked entry and report"):
        validate_official_classification_inputs([known], [_prediction("known")])

    false_positive = _label("false", "FP_CONFIRMED")
    false_positive["reason_codes"] = []
    with pytest.raises(ValueError, match="requires a reason code"):
        validate_official_classification_inputs(
            [false_positive], [_prediction("false", "FALSE_POSITIVE")]
        )


def test_official_gold_gate_rejects_mismatched_or_ineligible_predictions() -> None:
    label = _label("finding", "TP_NOVEL")
    with pytest.raises(ValueError, match="finding IDs differ"):
        validate_official_classification_inputs([label], [_prediction("different")])

    prediction = deepcopy(_prediction("finding"))
    prediction["evaluation_eligible"] = False
    with pytest.raises(ValueError, match="not official-evaluation eligible"):
        validate_official_classification_inputs([label], [prediction])
