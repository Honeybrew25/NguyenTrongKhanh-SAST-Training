from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .matcher import finding_matches_entry

TRUE_LABELS = {"TP_KNOWN", "TP_NOVEL"}
FALSE_LABEL = "FP_CONFIRMED"
POSITIVE_VERDICT = "TRUE_POSITIVE"
NEGATIVE_VERDICT = "FALSE_POSITIVE"
ABSTAIN_VERDICT = "ABSTAIN"


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
            if finding_matches_entry(finding, entry, tolerance=tolerance):
                matches.append(entry["entry_id"])
                matched_entry_ids.add(entry["entry_id"])
                matched_report_ids.add(entry["report_id"])
        finding_details.append(
            {"index": index, "finding_id": finding.get("finding_id"), "matched_entry_ids": sorted(matches)}
        )

    all_reports = {entry["report_id"] for entry in entries}
    return {
        "policy": {"path": "normalized_exact", "line_tolerance": tolerance, "line_ranges": "inclusive_interval"},
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
    excluded_label_counts: dict[str, int] = defaultdict(int)
    for row in labels:
        finding_id = row["finding_id"]
        label = row.get("label") or row.get("adjudication", {}).get("label")
        if finding_id in label_by_id:
            raise ValueError(f"duplicate label finding_id: {finding_id}")
        if label in TRUE_LABELS or label == FALSE_LABEL:
            label_by_id[finding_id] = label
        else:
            excluded_label_counts[str(label)] += 1

    prediction_by_id: dict[str, str] = {}
    for row in predictions:
        finding_id = row["finding_id"]
        verdict = row["verdict"]
        if verdict not in {POSITIVE_VERDICT, NEGATIVE_VERDICT, ABSTAIN_VERDICT}:
            raise ValueError(f"invalid verdict for {finding_id}: {verdict}")
        if finding_id in prediction_by_id:
            raise ValueError(f"duplicate prediction finding_id: {finding_id}")
        prediction_by_id[finding_id] = verdict

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
    total = decided + abstain_true + abstain_false
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = None if precision is None or recall is None or precision + recall == 0 else 2 * precision * recall / (precision + recall)
    specificity = ratio(tn, tn + fp)
    fp_removal = ratio(tn, tn + fp)

    return {
        "positive_class": "real_vulnerability",
        "confusion_matrix_decided_only": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics_decided_only": {
            "precision": precision,
            "recall_tp_retention": recall,
            "f1": f1,
            "specificity": specificity,
            "false_positive_removal_rate": fp_removal,
            "accuracy": ratio(tp + tn, decided),
        },
        "coverage": {
            "labeled_total": total,
            "decided": decided,
            "abstained": abstain_true + abstain_false,
            "selective_coverage": ratio(decided, total),
            "abstain_on_true": abstain_true,
            "abstain_on_false": abstain_false,
        },
        "excluded_labels": dict(sorted(excluded_label_counts.items())),
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

    args = parser.parse_args(argv)
    if args.command == "coverage":
        if args.line_tolerance < 0:
            parser.error("--line-tolerance must be non-negative")
        report = coverage_metrics(load_jsonl(args.entries), load_jsonl(args.findings), args.line_tolerance)
    else:
        report = classification_metrics(load_jsonl(args.labels), load_jsonl(args.predictions))

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
