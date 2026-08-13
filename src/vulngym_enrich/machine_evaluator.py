from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .evaluator import (
    ABSTAIN_VERDICT,
    FP_REASON_CODES,
    NEGATIVE_VERDICT,
    POSITIVE_VERDICT,
    load_jsonl,
    ratio,
)


MACHINE_TRUE_LABEL = "MACHINE_TRUE_POSITIVE"
MACHINE_FALSE_LABEL = "MACHINE_FALSE_POSITIVE"
MACHINE_UNCERTAIN_LABEL = "MACHINE_UNCERTAIN"
ALL_MACHINE_REFERENCE_LABELS = {
    MACHINE_TRUE_LABEL,
    MACHINE_FALSE_LABEL,
    MACHINE_UNCERTAIN_LABEL,
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_LINE_RANGE_RE = re.compile(r"^([1-9][0-9]*)-([1-9][0-9]*)$")
_MACHINE_LABEL_KEYS = {
    "schema_version",
    "finding_id",
    "label",
    "confidence",
    "reason_codes",
    "reasoning",
    "evidence",
    "uncertainty_reason",
    "reviewer",
    "reviewed_at",
    "provenance",
    "linked_entry_ids",
}
_REVIEWER_KEYS = {
    "id",
    "kind",
    "role",
    "provider",
    "provider_version",
    "model",
    "model_version",
    "participants",
}
_PARTICIPANT_KEYS = {
    "id",
    "provider",
    "provider_version",
    "model",
    "model_version",
}
_PROVENANCE_KEYS = {
    "method",
    "source_scanner",
    "blind_first",
    "route_reasons",
    "reviewer_a_prediction_sha256",
    "reviewer_b_prediction_sha256",
    "adjudicator_blind_prediction_sha256",
    "adjudicator_final_prediction_sha256",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_frozen_machine_reference_package(
    labels_path: Path, summary_path: Path | None = None
) -> list[dict[str, Any]]:
    """Verify the full frozen review package before evaluator use.

    Per-row provenance hashes are useful only when they remain connected to the
    immutable A/B/C runs.  Re-running the read-only finalization gates validates
    those run inventories and reconstructs every label from the frozen decisions.
    """

    labels_path = labels_path.resolve(strict=True)
    summary_path = (
        summary_path.resolve(strict=True)
        if summary_path is not None
        else labels_path.parent / "machine-review-summary.json"
    )
    if (
        summary_path.name != "machine-review-summary.json"
        or summary_path.parent != labels_path.parent
        or labels_path.name != "machine-reference-labels.jsonl"
    ):
        raise ValueError(
            "machine-reference labels and summary must be the canonical files "
            "from one review directory"
        )
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("machine-reference summary is invalid JSON") from exc
    if (
        not isinstance(summary, dict)
        or summary.get("schema_version") != 1
        or summary.get("status") != "MACHINE_REFERENCE_READY_WITH_UNCERTAINTY"
        or summary.get("reference_tier")
        != "LLM_ADJUDICATED_MACHINE_REFERENCE"
        or summary.get("publication_policy", {}).get("human_gold") is not False
        or summary.get("publication_policy", {}).get("publish_as_official") is not False
    ):
        raise ValueError("machine-reference summary policy is invalid")
    output = summary.get("outputs", {}).get("machine_reference_labels")
    if (
        not isinstance(output, dict)
        or output.get("path") != labels_path.name
        or output.get("sha256") != _sha256(labels_path)
    ):
        raise ValueError("machine-reference label checksum proof is invalid")

    # Lazy import avoids a module cycle: finalization itself invokes the core
    # label validator above, while this package gate is evaluator-CLI-only.
    from .machine_review import finalize_review

    verified_summary = finalize_review(review_directory=labels_path.parent)
    if verified_summary != summary:
        raise ValueError("machine-reference summary changed during verification")
    labels = load_jsonl(labels_path)
    if output.get("records") != len(labels) or summary.get("records") != len(labels):
        raise ValueError("machine-reference record count proof is invalid")
    return labels


def _unique_nonempty_strings(value: Any, field: str, finding_id: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item.strip() for item in value)
        or len(value) != len(set(value))
    ):
        raise ValueError(f"invalid {field} for {finding_id}")
    return value


def _valid_line(value: Any) -> bool:
    if isinstance(value, int) and not isinstance(value, bool):
        return value >= 1
    if not isinstance(value, str):
        return False
    matched = _LINE_RANGE_RE.fullmatch(value)
    return bool(matched and int(matched.group(2)) >= int(matched.group(1)))


def _validate_evidence(value: Any, finding_id: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 12:
        raise ValueError(f"machine-reference evidence is invalid for {finding_id}")
    for node in value:
        if not isinstance(node, dict) or set(node) != {
            "file",
            "line",
            "description",
            "code",
        }:
            raise ValueError(
                f"machine-reference evidence node is invalid for {finding_id}"
            )
        if not _valid_line(node.get("line")) or any(
            not isinstance(node.get(field), str) or not node[field].strip()
            for field in ("file", "description", "code")
        ):
            raise ValueError(
                f"machine-reference evidence node is invalid for {finding_id}"
            )
    return value


def _validate_reviewer(value: Any, finding_id: str) -> str:
    if (
        not isinstance(value, dict)
        or set(value) != _REVIEWER_KEYS
        or value.get("kind") != "MODEL"
    ):
        raise ValueError(
            f"machine-reference reviewer must have kind MODEL: {finding_id}"
        )
    for field in (
        "id",
        "role",
        "provider",
        "provider_version",
        "model",
        "model_version",
    ):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise ValueError(
                f"machine-reference reviewer {field} is required for {finding_id}"
            )
    role = value["role"]
    if role not in {"CONSENSUS_A_B", "ADJUDICATOR_C"}:
        raise ValueError(
            f"machine-reference reviewer role is invalid for {finding_id}"
        )
    participants = value.get("participants")
    expected = 2 if role == "CONSENSUS_A_B" else 1
    if not isinstance(participants, list) or len(participants) != expected:
        raise ValueError(
            f"machine-reference reviewer participants are invalid for {finding_id}"
        )
    participant_ids: set[str] = set()
    participant_models: set[str] = set()
    for participant in participants:
        if not isinstance(participant, dict) or set(participant) != _PARTICIPANT_KEYS:
            raise ValueError(
                f"machine-reference reviewer participant is invalid for {finding_id}"
            )
        for field in _PARTICIPANT_KEYS:
            if (
                not isinstance(participant.get(field), str)
                or not participant[field].strip()
            ):
                raise ValueError(
                    f"machine-reference participant {field} is required for {finding_id}"
                )
        participant_ids.add(participant["id"])
        participant_models.add(participant["model"])
    if len(participant_ids) != expected or (
        role == "CONSENSUS_A_B" and len(participant_models) != 2
    ):
        raise ValueError(
            f"machine-reference reviewer participants are not independent for {finding_id}"
        )
    return role


def _validate_provenance(value: Any, role: str, finding_id: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != _PROVENANCE_KEYS
        or value.get("method") != "LLM_ADJUDICATED"
        or value.get("source_scanner") != "opengrep"
        or not isinstance(value.get("blind_first"), bool)
    ):
        raise ValueError(f"machine-reference provenance is invalid for {finding_id}")
    route_reasons = _unique_nonempty_strings(
        value.get("route_reasons"), "route_reasons", finding_id
    )
    for field in (
        "reviewer_a_prediction_sha256",
        "reviewer_b_prediction_sha256",
    ):
        checksum = value.get(field)
        if not isinstance(checksum, str) or not _SHA256_RE.fullmatch(checksum):
            raise ValueError(
                f"machine-reference provenance {field} is invalid for {finding_id}"
            )
    c_blind = value.get("adjudicator_blind_prediction_sha256")
    c_final = value.get("adjudicator_final_prediction_sha256")
    if role == "ADJUDICATOR_C":
        if (
            value["blind_first"] is not True
            or not route_reasons
            or not isinstance(c_blind, str)
            or not _SHA256_RE.fullmatch(c_blind)
            or not isinstance(c_final, str)
            or not _SHA256_RE.fullmatch(c_final)
        ):
            raise ValueError(
                f"machine-reference adjudication provenance is invalid for {finding_id}"
            )
    elif (
        value["blind_first"] is not False
        or route_reasons
        or c_blind is not None
        or c_final is not None
    ):
        raise ValueError(
            f"machine-reference consensus provenance is invalid for {finding_id}"
        )


def validate_machine_reference_classification_inputs(
    labels: list[dict[str, Any]], predictions: list[dict[str, Any]]
) -> None:
    """Fail closed for model-authored references without promoting them to gold."""

    if not labels:
        raise ValueError("machine-reference labels are empty")
    if not predictions:
        raise ValueError("machine-reference predictions are empty")

    label_ids: set[str] = set()
    for index, row in enumerate(labels, 1):
        if not isinstance(row, dict) or set(row) != _MACHINE_LABEL_KEYS:
            raise ValueError(f"machine-reference row {index} has invalid fields")
        finding_id = row.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id.strip():
            raise ValueError(
                f"machine-reference row {index} has an invalid finding_id"
            )
        if finding_id in label_ids:
            raise ValueError(f"duplicate machine-reference finding_id: {finding_id}")
        label_ids.add(finding_id)
        if row.get("schema_version") != 1:
            raise ValueError(
                f"invalid machine-reference schema_version for {finding_id}"
            )
        label = row.get("label")
        if label not in ALL_MACHINE_REFERENCE_LABELS:
            raise ValueError(
                f"invalid machine-reference label for {finding_id}: {label!r}"
            )
        if row.get("confidence") not in {"HIGH", "MEDIUM", "LOW"}:
            raise ValueError(
                f"invalid machine-reference confidence for {finding_id}"
            )
        reasoning = row.get("reasoning")
        if not isinstance(reasoning, str) or not reasoning.strip():
            raise ValueError(
                f"machine-reference reasoning is required for {finding_id}"
            )
        evidence = _validate_evidence(row.get("evidence"), finding_id)
        if label != MACHINE_UNCERTAIN_LABEL and not evidence:
            raise ValueError(
                f"decided machine-reference label requires evidence: {finding_id}"
            )

        reason_codes = _unique_nonempty_strings(
            row.get("reason_codes"), "machine-reference reason_codes", finding_id
        )
        unknown_reason_codes = sorted(set(reason_codes) - FP_REASON_CODES)
        if unknown_reason_codes:
            raise ValueError(
                f"unknown machine-reference reason codes for {finding_id}: "
                f"{unknown_reason_codes}"
            )
        uncertainty_reason = row.get("uncertainty_reason")
        if label == MACHINE_FALSE_LABEL:
            if not reason_codes:
                raise ValueError(
                    f"MACHINE_FALSE_POSITIVE requires a reason code: {finding_id}"
                )
            if uncertainty_reason is not None:
                raise ValueError(
                    f"decided machine-reference label cannot be uncertain: {finding_id}"
                )
        elif label == MACHINE_TRUE_LABEL:
            if reason_codes or uncertainty_reason is not None:
                raise ValueError(
                    f"MACHINE_TRUE_POSITIVE has invalid reason fields: {finding_id}"
                )
        elif (
            reason_codes
            or not isinstance(uncertainty_reason, str)
            or not uncertainty_reason.strip()
        ):
            raise ValueError(
                f"MACHINE_UNCERTAIN requires uncertainty_reason only: {finding_id}"
            )

        role = _validate_reviewer(row.get("reviewer"), finding_id)
        reviewed_at = row.get("reviewed_at")
        if not isinstance(reviewed_at, str) or not reviewed_at.strip():
            raise ValueError(f"reviewed_at is required for {finding_id}")
        try:
            parsed_timestamp = datetime.fromisoformat(
                reviewed_at.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError(f"reviewed_at is invalid for {finding_id}") from exc
        if parsed_timestamp.tzinfo is None:
            raise ValueError(
                f"reviewed_at must include a timezone for {finding_id}"
            )
        _validate_provenance(row.get("provenance"), role, finding_id)
        if row.get("linked_entry_ids") != []:
            raise ValueError(
                f"machine-reference labels cannot claim VulnGym linkage: {finding_id}"
            )

    prediction_ids: set[str] = set()
    for index, row in enumerate(predictions, 1):
        if not isinstance(row, dict):
            raise ValueError(f"prediction row {index} must be an object")
        finding_id = row.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id.strip():
            raise ValueError(f"prediction row {index} has an invalid finding_id")
        if finding_id in prediction_ids:
            raise ValueError(f"duplicate prediction finding_id: {finding_id}")
        prediction_ids.add(finding_id)
        if row.get("verdict") not in {
            POSITIVE_VERDICT,
            NEGATIVE_VERDICT,
            ABSTAIN_VERDICT,
        }:
            raise ValueError(f"invalid verdict for {finding_id}: {row.get('verdict')}")

    if label_ids != prediction_ids:
        missing_labels = sorted(prediction_ids - label_ids)
        missing_predictions = sorted(label_ids - prediction_ids)
        raise ValueError(
            "machine-reference and prediction finding IDs differ: "
            f"missing_labels={missing_labels}, "
            f"missing_predictions={missing_predictions}"
        )


def machine_reference_metrics(
    labels: list[dict[str, Any]], predictions: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compute metrics that remain explicitly exploratory and model-referenced."""

    validate_machine_reference_classification_inputs(labels, predictions)
    counts: dict[str, int] = defaultdict(int)
    label_by_id: dict[str, str] = {}
    for row in labels:
        machine_label = str(row["label"])
        counts[machine_label] += 1
        if machine_label in {MACHINE_TRUE_LABEL, MACHINE_FALSE_LABEL}:
            label_by_id[str(row["finding_id"])] = machine_label

    prediction_by_id = {
        str(row["finding_id"]): str(row["verdict"]) for row in predictions
    }
    tp = fp = tn = fn = abstain_true = abstain_false = 0
    for finding_id, label in label_by_id.items():
        is_true = label == MACHINE_TRUE_LABEL
        verdict = prediction_by_id[finding_id]
        if verdict == ABSTAIN_VERDICT:
            if is_true:
                abstain_true += 1
            else:
                abstain_false += 1
        elif verdict == POSITIVE_VERDICT:
            if is_true:
                tp += 1
            else:
                fp += 1
        elif is_true:
            fn += 1
        else:
            tn += 1

    decided = tp + fp + tn + fn
    reference_total = len(label_by_id)
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    report: dict[str, Any] = {
        "positive_class": "machine_referenced_vulnerability",
        "confusion_matrix_decided_only": {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
        },
        "metrics_decided_only": {
            "precision": precision,
            "recall_tp_retention": recall,
            "f1": f1,
            "specificity": ratio(tn, tn + fp),
            "false_positive_rate": ratio(fp, fp + tn),
            "false_negative_rate": ratio(fn, fn + tp),
            "accuracy": ratio(tp + tn, decided),
        },
        "metrics_end_to_end": {
            "tp_retention": ratio(tp, tp + fn + abstain_true),
            "false_positive_removal_rate": ratio(
                tn, tn + fp + abstain_false
            ),
        },
        "coverage": {
            "machine_reference_decided_total": reference_total,
            "agent_decided": decided,
            "agent_abstained": abstain_true + abstain_false,
            "selective_coverage": ratio(decided, reference_total),
            "abstain_on_machine_true": abstain_true,
            "abstain_on_machine_false": abstain_false,
        },
        "excluded_machine_reference": {
            MACHINE_UNCERTAIN_LABEL: counts[MACHINE_UNCERTAIN_LABEL]
        },
    }
    total = len(labels)
    machine_true = counts[MACHINE_TRUE_LABEL]
    machine_false = counts[MACHINE_FALSE_LABEL]
    uncertain = counts[MACHINE_UNCERTAIN_LABEL]
    report["reference_policy"] = {
        "tier": "LLM_ADJUDICATED_MACHINE_REFERENCE",
        "human_gold": False,
        "publish_as_official": False,
        "metrics_name": (
            "exploratory metrics against frozen LLM-adjudicated reference labels"
        ),
    }
    report["machine_prevalence"] = {
        "records": total,
        "machine_true_positive": machine_true,
        "machine_false_positive": machine_false,
        "machine_uncertain": uncertain,
        "tp_fraction_lower_bound": ratio(machine_true, total),
        "tp_fraction_upper_bound": ratio(machine_true + uncertain, total),
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate only against a frozen LLM-adjudicated machine reference."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    classify = commands.add_parser("classify")
    classify.add_argument("--labels", type=Path, required=True)
    classify.add_argument(
        "--reference-summary",
        type=Path,
        help=(
            "frozen machine-review summary (defaults to machine-review-summary.json "
            "beside --labels)"
        ),
    )
    classify.add_argument("--predictions", type=Path, required=True)
    classify.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        labels = validate_frozen_machine_reference_package(
            args.labels, args.reference_summary
        )
        report = machine_reference_metrics(
            labels, load_jsonl(args.predictions)
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
