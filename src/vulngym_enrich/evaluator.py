from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .candidate_matcher import STRICT, STRONG, match_normalized_finding_entry
from .matcher import finding_matches_entry

TRUE_LABELS = {"TP_KNOWN", "TP_NOVEL"}
FALSE_LABEL = "FP_CONFIRMED"
POSITIVE_VERDICT = "TRUE_POSITIVE"
NEGATIVE_VERDICT = "FALSE_POSITIVE"
ABSTAIN_VERDICT = "ABSTAIN"
EXCLUDED_GOLD_LABELS = {"UNCERTAIN", "DUPLICATE", "OUT_OF_SCOPE"}
ALL_GOLD_LABELS = TRUE_LABELS | {FALSE_LABEL} | EXCLUDED_GOLD_LABELS
FP_REASON_CODES = {
    "UNREACHABLE_CODE",
    "NO_ATTACKER_CONTROL",
    "SANITIZED_BEFORE_SINK",
    "CONSTANT_VALUE",
    "AUTHZ_PRECONDITION_BLOCKS_ATTACK",
    "SAFE_API_USAGE",
    "TYPE_OR_SCHEMA_CONSTRAINT",
    "TEST_OR_FIXTURE_ONLY",
    "DEAD_OR_UNUSED_PATH",
    "FRAMEWORK_GUARANTEE",
    "SCANNER_MODELING_ERROR",
    "OTHER_EXPLAINED",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
    return rows


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _unique_nonempty_strings(value: Any, field: str, finding_id: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item.strip() for item in value)
        or len(value) != len(set(value))
    ):
        raise ValueError(f"invalid {field} for {finding_id}")
    return value


def validate_official_classification_inputs(
    labels: list[dict[str, Any]], predictions: list[dict[str, Any]]
) -> None:
    """Fail closed before computing official verifier metrics.

    The lower-level ``classification_metrics`` function deliberately remains useful
    for fixtures and exploratory analysis. The CLI calls this gate by default so an
    empty template, AI-authored labels, incomplete evidence, or mismatched corpora
    cannot silently become an official-looking metric report.
    """

    if not labels:
        raise ValueError("official gold labels are empty")
    if not predictions:
        raise ValueError("official verifier predictions are empty")

    label_ids: set[str] = set()
    for index, row in enumerate(labels, 1):
        if not isinstance(row, dict):
            raise ValueError(f"gold label row {index} must be an object")
        finding_id = row.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id.strip():
            raise ValueError(f"gold label row {index} has an invalid finding_id")
        if finding_id in label_ids:
            raise ValueError(f"duplicate label finding_id: {finding_id}")
        label_ids.add(finding_id)
        if row.get("schema_version") != 1:
            raise ValueError(f"invalid gold-label schema_version for {finding_id}")

        label = row.get("label")
        if label not in ALL_GOLD_LABELS:
            raise ValueError(f"incomplete or invalid gold label for {finding_id}: {label!r}")
        reasoning = row.get("reasoning")
        if not isinstance(reasoning, str) or not reasoning.strip():
            raise ValueError(f"gold label reasoning is required for {finding_id}")
        evidence = _unique_nonempty_strings(row.get("evidence"), "evidence", finding_id)
        if not evidence:
            raise ValueError(f"gold label evidence is required for {finding_id}")

        reviewer = row.get("reviewer")
        if not isinstance(reviewer, dict) or set(reviewer) != {"id", "kind"}:
            raise ValueError(f"gold label reviewer is invalid for {finding_id}")
        if reviewer.get("kind") != "HUMAN":
            raise ValueError(f"official gold label must be human-reviewed: {finding_id}")
        if not isinstance(reviewer.get("id"), str) or not reviewer["id"].strip():
            raise ValueError(f"human reviewer id is required for {finding_id}")

        reviewed_at = row.get("reviewed_at")
        if not isinstance(reviewed_at, str) or not reviewed_at.strip():
            raise ValueError(f"reviewed_at is required for {finding_id}")
        try:
            parsed_timestamp = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"reviewed_at is invalid for {finding_id}") from exc
        if parsed_timestamp.tzinfo is None:
            raise ValueError(f"reviewed_at must include a timezone for {finding_id}")

        reason_codes = _unique_nonempty_strings(
            row.get("reason_codes"), "reason_codes", finding_id
        )
        unknown_reason_codes = sorted(set(reason_codes) - FP_REASON_CODES)
        if unknown_reason_codes:
            raise ValueError(
                f"unknown false-positive reason codes for {finding_id}: "
                f"{unknown_reason_codes}"
            )
        linked_entry_ids = _unique_nonempty_strings(
            row.get("linked_entry_ids"), "linked_entry_ids", finding_id
        )
        linked_report_ids = _unique_nonempty_strings(
            row.get("linked_report_ids"), "linked_report_ids", finding_id
        )

        if label == FALSE_LABEL:
            if not reason_codes:
                raise ValueError(f"FP_CONFIRMED requires a reason code: {finding_id}")
            if linked_entry_ids or linked_report_ids:
                raise ValueError(
                    f"FP_CONFIRMED cannot link VulnGym entries or reports: {finding_id}"
                )
        elif reason_codes:
            raise ValueError(f"only FP_CONFIRMED may use FP reason codes: {finding_id}")

        if label == "TP_KNOWN":
            if not linked_entry_ids or not linked_report_ids:
                raise ValueError(
                    f"TP_KNOWN requires linked entry and report IDs: {finding_id}"
                )
        elif linked_entry_ids or linked_report_ids:
            raise ValueError(
                f"only TP_KNOWN may link VulnGym entries or reports: {finding_id}"
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
        if row.get("evaluation_eligible") is not True:
            raise ValueError(f"prediction is not official-evaluation eligible: {finding_id}")

    if label_ids != prediction_ids:
        missing_labels = sorted(prediction_ids - label_ids)
        missing_predictions = sorted(label_ids - prediction_ids)
        raise ValueError(
            "gold-label and prediction finding IDs differ: "
            f"missing_labels={missing_labels}, "
            f"missing_predictions={missing_predictions}"
        )


def coverage_metrics(entries: list[dict[str, Any]], findings: list[dict[str, Any]], tolerance: int = 5) -> dict[str, Any]:
    by_snapshot: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        by_snapshot[(entry["repo_url"].removesuffix(".git").rstrip("/"), entry["commit"].lower())].append(entry)

    matched_entry_ids: set[str] = set()
    matched_report_ids: set[str] = set()
    finding_details: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        key = (str(finding.get("repo_url", "")).removesuffix(".git").rstrip("/"), str(finding.get("commit", "")).lower())
        matches = []
        for entry in by_snapshot.get(key, []):
            if "location" in finding:
                normalized_match = match_normalized_finding_entry(finding, entry, tolerance)
                is_match = bool(
                    normalized_match and normalized_match["tier"] in {STRICT, STRONG}
                )
            else:
                is_match = finding_matches_entry(finding, entry, tolerance=tolerance)
            if is_match:
                matches.append(entry["entry_id"])
                matched_entry_ids.add(entry["entry_id"])
                matched_report_ids.add(entry["report_id"])
        finding_details.append(
            {"index": index, "finding_id": finding.get("finding_id"), "matched_entry_ids": sorted(matches)}
        )

    all_reports = {entry["report_id"] for entry in entries}
    return {
        "policy": {
            "path": "normalized_exact",
            "line_tolerance": tolerance,
            "line_ranges": "inclusive_interval",
            "normalized_finding_contract": "source trace plus sink location",
        },
        "totals": {"entries": len(entries), "advisories": len(all_reports), "findings": len(findings)},
        "recall": {
            "entry_level": {
                "numerator": len(matched_entry_ids),
                "denominator": len(entries),
                "value": ratio(len(matched_entry_ids), len(entries)),
            },
            "advisory_level": {
                "numerator": len(matched_report_ids),
                "denominator": len(all_reports),
                "value": ratio(len(matched_report_ids), len(all_reports)),
            },
        },
        "unmatched_findings": sum(not detail["matched_entry_ids"] for detail in finding_details),
        "findings": finding_details,
    }


def classification_metrics(labels: list[dict[str, Any]], predictions: list[dict[str, Any]]) -> dict[str, Any]:
    label_by_id: dict[str, str] = {}
    seen_label_ids: set[str] = set()
    excluded_label_counts: dict[str, int] = defaultdict(int)
    for row in labels:
        finding_id = row["finding_id"]
        adjudication = row.get("adjudication")
        label = row.get("label") or (
            adjudication.get("label") if isinstance(adjudication, dict) else None
        )
        if finding_id in seen_label_ids:
            raise ValueError(f"duplicate label finding_id: {finding_id}")
        seen_label_ids.add(finding_id)
        if label in TRUE_LABELS or label == FALSE_LABEL:
            label_by_id[finding_id] = label
        else:
            excluded_label_counts[str(label)] += 1

    prediction_by_id: dict[str, str] = {}
    seen_prediction_ids: set[str] = set()
    excluded_predictions: list[str] = []
    for row in predictions:
        finding_id = row["finding_id"]
        verdict = row["verdict"]
        if verdict not in {POSITIVE_VERDICT, NEGATIVE_VERDICT, ABSTAIN_VERDICT}:
            raise ValueError(f"invalid verdict for {finding_id}: {verdict}")
        if finding_id in seen_prediction_ids:
            raise ValueError(f"duplicate prediction finding_id: {finding_id}")
        seen_prediction_ids.add(finding_id)
        if row.get("evaluation_eligible") is False:
            excluded_predictions.append(finding_id)
            continue
        prediction_by_id[finding_id] = verdict

    excluded_labeled_cases = sorted(set(excluded_predictions).intersection(label_by_id))
    for finding_id in excluded_labeled_cases:
        del label_by_id[finding_id]

    tp = fp = tn = fn = abstain_true = abstain_false = 0
    missing_predictions: list[str] = []
    for finding_id, label in label_by_id.items():
        is_true = label in TRUE_LABELS
        verdict = prediction_by_id.get(finding_id)
        if verdict is None:
            missing_predictions.append(finding_id)
        elif verdict == ABSTAIN_VERDICT:
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
    labeled_total = len(label_by_id)
    missing_true = sum(label_by_id[finding_id] in TRUE_LABELS for finding_id in missing_predictions)
    missing_false = len(missing_predictions) - missing_true
    precision = ratio(tp, tp + fp)
    decided_recall = ratio(tp, tp + fn)
    if precision is None or decided_recall is None:
        f1 = None
    elif precision + decided_recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * decided_recall / (precision + decided_recall)
    specificity = ratio(tn, tn + fp)
    end_to_end_tp_retention = ratio(tp, tp + fn + abstain_true + missing_true)
    end_to_end_fp_removal = ratio(tn, tn + fp + abstain_false + missing_false)

    return {
        "positive_class": "real_vulnerability",
        "confusion_matrix_decided_only": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics_decided_only": {
            "precision": precision,
            "recall_tp_retention": decided_recall,
            "f1": f1,
            "specificity": specificity,
            "accuracy": ratio(tp + tn, decided),
        },
        "metrics_end_to_end": {
            "tp_retention": end_to_end_tp_retention,
            "false_positive_removal_rate": end_to_end_fp_removal,
        },
        "coverage": {
            "labeled_total": labeled_total,
            "decided": decided,
            "abstained": abstain_true + abstain_false,
            "missing": len(missing_predictions),
            "selective_coverage": ratio(decided, labeled_total),
            "abstain_on_true": abstain_true,
            "abstain_on_false": abstain_false,
            "missing_on_true": missing_true,
            "missing_on_false": missing_false,
        },
        "excluded_labels": dict(sorted(excluded_label_counts.items())),
        "excluded_predictions": sorted(excluded_predictions),
        "excluded_labeled_cases": excluded_labeled_cases,
        "missing_predictions": sorted(missing_predictions),
        "extra_predictions": sorted(set(prediction_by_id) - set(label_by_id)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate VulnGym coverage or finding-verifier classification.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    coverage = subparsers.add_parser("coverage")
    coverage.add_argument("--entries", type=Path, default=Path("benchmark/VulnGym/data/entries.jsonl"))
    coverage.add_argument("--findings", type=Path, required=True)
    coverage.add_argument("--line-tolerance", type=int, default=5)
    coverage.add_argument("--output", type=Path)

    classify = subparsers.add_parser("classify")
    classify.add_argument("--labels", type=Path, required=True)
    classify.add_argument("--predictions", type=Path, required=True)
    classify.add_argument("--output", type=Path)
    classify.add_argument(
        "--allow-incomplete-gold",
        action="store_true",
        help="skip the human-gold/evidence gate for development fixtures only",
    )

    args = parser.parse_args(argv)
    if args.command == "coverage":
        if args.line_tolerance < 0:
            parser.error("--line-tolerance must be non-negative")
        report = coverage_metrics(load_jsonl(args.entries), load_jsonl(args.findings), args.line_tolerance)
    else:
        labels = load_jsonl(args.labels)
        predictions = load_jsonl(args.predictions)
        if not args.allow_incomplete_gold:
            try:
                validate_official_classification_inputs(labels, predictions)
            except ValueError as exc:
                parser.error(str(exc))
        report = classification_metrics(labels, predictions)

    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"wrote report: {args.output}")
    else:
        print(rendered, end="")
    return 1 if report.get("missing_predictions") else 0


if __name__ == "__main__":
    raise SystemExit(main())
