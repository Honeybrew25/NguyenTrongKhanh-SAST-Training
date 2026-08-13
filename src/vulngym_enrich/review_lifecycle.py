from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .evaluator import (
    classification_metrics,
    load_jsonl,
    validate_official_classification_inputs,
)


_PACKET_FILES = {
    "candidate-findings.jsonl",
    "human-candidate-matches.jsonl",
    "human-gold-label.schema.json",
    "human-gold-labels.template.jsonl",
    "README.md",
    "review-manifest.json",
}
_CONFIRMATION_KIND = "HUMAN_CONFIRMATION_OF_AI_TECHNICAL_REVIEW"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"{label} is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is invalid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object: {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
            handle.write("\n")
    temporary.replace(path)


def _ordered_ids(rows: list[dict[str, Any]], label: str) -> list[str]:
    ids: list[str] = []
    for index, row in enumerate(rows, 1):
        finding_id = row.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            raise ValueError(f"{label} row {index} has no finding_id")
        ids.append(finding_id)
    if len(ids) != len(set(ids)):
        raise ValueError(f"{label} contains duplicate finding IDs")
    return ids


def freeze_predictions(run_directory: Path) -> dict[str, Any]:
    run_path = run_directory.resolve()
    manifest_path = run_path / "verifier-run.json"
    predictions_path = run_path / "verifier-predictions.jsonl"
    freeze_path = run_path / "prediction-freeze.json"
    run = _read_object(manifest_path, "verifier run manifest")

    if run.get("complete") is not True or run.get("status") != "COMPLETE":
        raise ValueError("only a COMPLETE verifier run can be frozen")
    if run.get("evaluation_mode") != "OFFICIAL":
        raise ValueError("development predictions cannot be frozen as official")
    provider = run.get("provider")
    if (
        not isinstance(provider, dict)
        or provider.get("model_explicitly_pinned") is not True
        or not isinstance(provider.get("model"), str)
        or not provider["model"]
    ):
        raise ValueError("official prediction freeze requires a pinned model")
    counts = run.get("case_counts")
    if (
        not isinstance(counts, dict)
        or counts.get("failed") != 0
        or counts.get("success") != counts.get("total")
    ):
        raise ValueError("every verifier case must be successful before freeze")

    prediction_hash = _sha256(predictions_path)
    prediction_meta = run.get("predictions", {})
    if prediction_meta.get("sha256") != prediction_hash:
        raise ValueError("prediction checksum does not match verifier-run.json")
    predictions = load_jsonl(predictions_path)
    input_path = run_path / str(run.get("input", {}).get("frozen_copy", ""))
    inputs = load_jsonl(input_path)
    prediction_ids = _ordered_ids(predictions, "predictions")
    input_ids = _ordered_ids(inputs, "frozen input")
    expected_records = run.get("input", {}).get("records")
    if len(inputs) != expected_records or len(predictions) != expected_records:
        raise ValueError("predictions do not cover the complete frozen input")
    if prediction_ids != input_ids:
        raise ValueError("prediction IDs or ordering differ from frozen input")
    if any(row.get("evaluation_eligible") is not True for row in predictions):
        raise ValueError("every frozen prediction must be evaluation eligible")
    if _sha256(input_path) != run.get("input", {}).get("sha256"):
        raise ValueError("frozen input checksum does not match verifier-run.json")
    case_ids = [
        case.get("identity", {}).get("finding_id") for case in run.get("cases", [])
    ]
    if sorted(case_ids) != sorted(input_ids):
        raise ValueError("verifier cases do not exactly match frozen input")

    freeze = {
        "schema_version": 1,
        "freeze_id": f"prediction-freeze-{run['run_id']}",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "status": "FROZEN",
        "run": {
            "path": manifest_path.name,
            "sha256": _sha256(manifest_path),
            "run_id": run["run_id"],
            "evaluation_mode": run["evaluation_mode"],
        },
        "input": {"sha256": run["input"]["sha256"], "records": len(inputs)},
        "predictions": {
            "path": predictions_path.name,
            "sha256": prediction_hash,
            "records": len(predictions),
        },
        "provider": {
            "id": provider["id"],
            "version": provider["version"],
            "model": provider["model"],
        },
        "policy": {
            "checksum_detects_post_freeze_changes": True,
            "labels_loaded_before_freeze": False,
            "human_review_may_start": True,
        },
    }
    if freeze_path.exists():
        existing = _read_object(freeze_path, "prediction freeze")
        for section, field in (
            ("run", "sha256"),
            ("input", "sha256"),
            ("input", "records"),
            ("predictions", "sha256"),
            ("predictions", "records"),
        ):
            if existing.get(section, {}).get(field) != freeze[section][field]:
                raise ValueError("an incompatible prediction freeze already exists")
        return existing
    _write_json(freeze_path, freeze)
    return freeze


def _human_template(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "finding_id": candidate["finding_id"],
        "label": None,
        "reason_codes": [],
        "reasoning": "",
        "reviewer": {"id": "", "kind": "HUMAN"},
        "reviewed_at": "",
        "evidence": [],
        "linked_entry_ids": [],
        "linked_report_ids": [],
    }


def prepare_human_review(
    *,
    run_directory: Path,
    source_queue: Path,
    output_directory: Path,
    schema_path: Path,
) -> dict[str, Any]:
    run_path = run_directory.resolve()
    queue_path = source_queue.resolve()
    output_path = output_directory.resolve()
    freeze_path = run_path / "prediction-freeze.json"
    freeze = _read_object(freeze_path, "prediction freeze")
    if (
        freeze.get("status") != "FROZEN"
        or freeze.get("policy", {}).get("human_review_may_start") is not True
    ):
        raise ValueError("prediction freeze does not authorize human review")

    candidate_path = queue_path / "candidate-findings.jsonl"
    match_path = queue_path / "human-candidate-matches.jsonl"
    candidates = load_jsonl(candidate_path)
    matches = load_jsonl(match_path)
    candidate_ids = _ordered_ids(candidates, "human-review candidates")
    if len(candidates) != freeze.get("input", {}).get("records"):
        raise ValueError("candidate count does not match frozen verifier corpus")
    matched_member_ids = {
        member
        for row in matches
        for member in row.get("member_finding_ids", [])
        if isinstance(member, str)
    }
    if set(candidate_ids) != matched_member_ids:
        raise ValueError("candidate and human-match finding IDs differ")

    manifest_path = run_path / str(freeze.get("run", {}).get("path", ""))
    if _sha256(manifest_path) != freeze.get("run", {}).get("sha256"):
        raise ValueError("verifier manifest changed after prediction freeze")
    run = _read_object(manifest_path, "verifier run manifest")
    input_path = run_path / str(run.get("input", {}).get("frozen_copy", ""))
    if _sha256(input_path) != freeze.get("input", {}).get("sha256"):
        raise ValueError("frozen blind input is missing or changed")
    if set(_ordered_ids(load_jsonl(input_path), "frozen input")) != set(candidate_ids):
        raise ValueError("candidate IDs do not match frozen verifier input")
    if not schema_path.is_file():
        raise ValueError(f"human gold-label schema is missing: {schema_path}")

    output_path.mkdir(parents=True, exist_ok=True)
    sources = {
        "candidate-findings.jsonl": candidate_path,
        "human-candidate-matches.jsonl": match_path,
        "human-gold-label.schema.json": schema_path,
    }
    for name, source in sources.items():
        destination = output_path / name
        if destination.exists() and _sha256(destination) != _sha256(source):
            raise ValueError(f"review packet contains a conflicting file: {destination}")
        if not destination.exists():
            shutil.copyfile(source, destination)

    template_path = output_path / "human-gold-labels.template.jsonl"
    expected_template = [_human_template(candidate) for candidate in candidates]
    if template_path.exists():
        if _ordered_ids(load_jsonl(template_path), "human-label template") != candidate_ids:
            raise ValueError("existing human-label template has incompatible IDs")
    else:
        _write_jsonl(template_path, expected_template)

    checklist_path = output_path / "README.md"
    if not checklist_path.exists():
        checklist_path.write_text(
            "# Gói thẩm định OpenGrep độc lập\n\n"
            "Không mở `verifier-predictions.jsonl`, thư mục `cases/` hoặc metrics "
            "trước khi hoàn tất và khóa đủ 14 nhãn.\n\n"
            "Với từng finding, đọc `candidate-findings.jsonl`, metadata liên kết "
            "trong `human-candidate-matches.jsonl` và source đúng repo/commit. "
            "Xác minh attacker control, reachability, security effect và mọi control.\n\n"
            "- `TP_KNOWN`: lỗ hổng thật và khớp VulnGym; điền entry/report ID.\n"
            "- `TP_NOVEL`: lỗ hổng thật nhưng không thuộc match VulnGym.\n"
            "- `FP_CONFIRMED`: source chứng minh điều kiện phủ định; bắt buộc reason code.\n"
            "- `UNCERTAIN`: bằng chứng chưa đủ; không ép thành TP/FP.\n"
            "- `DUPLICATE`/`OUT_OF_SCOPE`: chỉ dùng khi đúng định nghĩa guideline.\n\n"
            "Mỗi record phải có reasoning, reviewer HUMAN, timestamp có timezone và "
            "ít nhất một evidence `file:dòng`. Lưu bản hoàn chỉnh thành "
            "`human-gold-labels.jsonl`.\n",
            encoding="utf-8",
        )

    manifest = {
        "schema_version": 1,
        "review_id": output_path.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "AWAITING_INDEPENDENT_HUMAN",
        "records": len(candidates),
        "prediction_commitment": {
            "freeze_sha256": _sha256(freeze_path),
            "prediction_sha256": freeze["predictions"]["sha256"],
            "prediction_contents_included": False,
        },
        "files": {
            "candidates": {
                "path": "candidate-findings.jsonl",
                "sha256": _sha256(output_path / "candidate-findings.jsonl"),
            },
            "matches": {
                "path": "human-candidate-matches.jsonl",
                "sha256": _sha256(output_path / "human-candidate-matches.jsonl"),
            },
            "template": {
                "path": template_path.name,
                "sha256": _sha256(template_path),
            },
            "schema": {
                "path": "human-gold-label.schema.json",
                "sha256": _sha256(output_path / "human-gold-label.schema.json"),
            },
        },
        "exclusions": [
            "verifier-predictions.jsonl",
            "technical-review-labels.jsonl",
            "provisional-metrics.json",
        ],
    }
    packet_manifest_path = output_path / "review-manifest.json"
    if packet_manifest_path.exists():
        existing = _read_object(packet_manifest_path, "review manifest")
        if existing.get("prediction_commitment") != manifest["prediction_commitment"]:
            raise ValueError("review packet has an incompatible prediction commitment")
        manifest = existing
    else:
        _write_json(packet_manifest_path, manifest)
    unexpected = sorted(path.name for path in output_path.iterdir() if path.is_file())
    unexpected = sorted(set(unexpected) - _PACKET_FILES)
    if unexpected:
        raise ValueError(f"human-review packet contains unexpected files: {unexpected}")
    return manifest


def evaluate_frozen_review(
    *, run_directory: Path, review_directory: Path, output_path: Path
) -> dict[str, Any]:
    run_path = run_directory.resolve()
    review_path = review_directory.resolve()
    freeze_path = run_path / "prediction-freeze.json"
    freeze = _read_object(freeze_path, "prediction freeze")
    if freeze.get("status") != "FROZEN":
        raise ValueError("official predictions are not frozen")
    predictions_path = run_path / str(freeze.get("predictions", {}).get("path", ""))
    if _sha256(predictions_path) != freeze.get("predictions", {}).get("sha256"):
        raise ValueError("predictions changed after freeze")
    review_manifest = _read_object(review_path / "review-manifest.json", "review manifest")
    commitment = review_manifest.get("prediction_commitment", {})
    if commitment.get("freeze_sha256") != _sha256(freeze_path):
        raise ValueError("review packet does not commit to this prediction freeze")
    if commitment.get("prediction_sha256") != _sha256(predictions_path):
        raise ValueError("review packet prediction commitment is invalid")
    if commitment.get("prediction_contents_included") is not False:
        raise ValueError("review packet does not satisfy prediction blindness")
    labels_path = review_path / "human-gold-labels.jsonl"
    labels = load_jsonl(labels_path)
    predictions = load_jsonl(predictions_path)
    validate_official_classification_inputs(labels, predictions)
    metrics = classification_metrics(labels, predictions)
    _write_json(output_path, metrics)
    return metrics


def normalize_human_confirmed_technical(
    *,
    human_confirmation_path: Path,
    technical_labels_path: Path,
    output_path: Path,
    fp_reason_code: str,
) -> dict[str, Any]:
    """Make a non-independent corpus explicit instead of mislabeling it as gold."""

    human_rows = load_jsonl(human_confirmation_path)
    technical_rows = load_jsonl(technical_labels_path)
    human_ids = _ordered_ids(human_rows, "human confirmation")
    technical_ids = _ordered_ids(technical_rows, "technical labels")
    if human_ids != technical_ids:
        raise ValueError("human confirmation and technical-label IDs or ordering differ")
    technical_by_id = {row["finding_id"]: row for row in technical_rows}
    normalized: list[dict[str, Any]] = []
    compared_fields = (
        "label",
        "reasoning",
        "evidence",
        "linked_entry_ids",
        "linked_report_ids",
    )
    for human in human_rows:
        finding_id = human["finding_id"]
        technical = technical_by_id[finding_id]
        reviewer = human.get("reviewer")
        if (
            not isinstance(reviewer, dict)
            or reviewer.get("kind") != "HUMAN"
            or not isinstance(reviewer.get("id"), str)
            or not reviewer["id"].strip()
        ):
            raise ValueError(f"human confirmer identity is invalid: {finding_id}")
        mismatches = [
            field for field in compared_fields if human.get(field) != technical.get(field)
        ]
        if mismatches:
            raise ValueError(
                f"confirmation differs from technical review for {finding_id}: {mismatches}"
            )
        label = human.get("label")
        reason_codes = [fp_reason_code] if label == "FP_CONFIRMED" else []
        linked_entry_ids = (
            list(human.get("linked_entry_ids", [])) if label == "TP_KNOWN" else []
        )
        linked_report_ids = (
            list(human.get("linked_report_ids", [])) if label == "TP_KNOWN" else []
        )
        normalized.append(
            {
                "schema_version": 1,
                "finding_id": finding_id,
                "label": label,
                "reason_codes": reason_codes,
                "reasoning": human.get("reasoning"),
                "reviewer": {
                    "id": reviewer["id"],
                    "kind": _CONFIRMATION_KIND,
                },
                "reviewed_at": human.get("reviewed_at"),
                "evidence": list(human.get("evidence", [])),
                "linked_entry_ids": linked_entry_ids,
                "linked_report_ids": linked_report_ids,
                "assessment_basis": "AI_TECHNICAL_REVIEW_CONFIRMED_BY_HUMAN",
                "independent_human_gold": False,
            }
        )
    _write_jsonl(output_path, normalized)
    manifest = {
        "schema_version": 1,
        "corpus_id": output_path.parent.name,
        "status": "NON_INDEPENDENT_EXPLORATORY",
        "records": len(normalized),
        "label_policy": "HUMAN_CONFIRMATION_OF_AI_TECHNICAL_REVIEW",
        "independent_human_gold": False,
        "limitations": [
            "The human confirmer had access to the AI technical labels.",
            "Reasoning and evidence are retained from the AI technical review.",
            "This corpus must not be used for official independent-human metrics.",
        ],
        "inputs": {
            "human_confirmation": {
                "path": human_confirmation_path.as_posix(),
                "sha256": _sha256(human_confirmation_path),
            },
            "technical_labels": {
                "path": technical_labels_path.as_posix(),
                "sha256": _sha256(technical_labels_path),
            },
        },
        "normalized_labels": {
            "path": output_path.name,
            "sha256": _sha256(output_path),
            "records": len(normalized),
        },
    }
    _write_json(output_path.parent / "confirmation-manifest.json", manifest)
    return manifest


def evaluate_exploratory_confirmation(
    *,
    labels_path: Path,
    run_directory: Path,
    output_path: Path,
) -> dict[str, Any]:
    run_path = run_directory.resolve()
    freeze_path = run_path / "prediction-freeze.json"
    freeze = _read_object(freeze_path, "prediction freeze")
    predictions_path = run_path / str(freeze.get("predictions", {}).get("path", ""))
    if freeze.get("status") != "FROZEN":
        raise ValueError("predictions must be frozen before exploratory evaluation")
    if _sha256(predictions_path) != freeze.get("predictions", {}).get("sha256"):
        raise ValueError("predictions changed after freeze")
    labels = load_jsonl(labels_path)
    predictions = load_jsonl(predictions_path)
    if len(labels) != freeze.get("input", {}).get("records"):
        raise ValueError("exploratory labels do not cover the frozen input")
    if any(
        row.get("independent_human_gold") is not False
        or row.get("reviewer", {}).get("kind") != _CONFIRMATION_KIND
        for row in labels
    ):
        raise ValueError("labels are not an explicit human-confirmed technical corpus")
    if set(_ordered_ids(labels, "exploratory labels")) != set(
        _ordered_ids(predictions, "predictions")
    ):
        raise ValueError("exploratory label and prediction IDs differ")
    metrics = classification_metrics(labels, predictions)
    report = {
        "schema_version": 1,
        "evaluation_id": output_path.parent.name,
        "status": "EXPLORATORY_NON_INDEPENDENT",
        "publish_as_official": False,
        "warning": (
            "Metrics use human-confirmed AI technical labels, not independent human gold."
        ),
        "inputs": {
            "labels": {"path": labels_path.as_posix(), "sha256": _sha256(labels_path)},
            "prediction_freeze": {
                "path": freeze_path.as_posix(),
                "sha256": _sha256(freeze_path),
            },
            "predictions": {
                "path": predictions_path.as_posix(),
                "sha256": _sha256(predictions_path),
            },
        },
        "metrics": metrics,
    }
    _write_json(output_path, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Cross-platform prediction freeze, human review, and evaluation gates."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("freeze")
    freeze.add_argument("--run-dir", type=Path, required=True)
    prepare = commands.add_parser("prepare-review")
    prepare.add_argument("--run-dir", type=Path, required=True)
    prepare.add_argument("--source-queue", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument(
        "--schema", type=Path, default=Path("schemas/human-gold-label.schema.json")
    )
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--run-dir", type=Path, required=True)
    evaluate.add_argument("--review-dir", type=Path, required=True)
    evaluate.add_argument("--output", type=Path)
    confirm = commands.add_parser("confirm-technical")
    confirm.add_argument("--human-confirmation", type=Path, required=True)
    confirm.add_argument("--technical-labels", type=Path, required=True)
    confirm.add_argument("--output", type=Path, required=True)
    confirm.add_argument("--fp-reason-code", default="OTHER_EXPLAINED")
    exploratory = commands.add_parser("evaluate-exploratory")
    exploratory.add_argument("--labels", type=Path, required=True)
    exploratory.add_argument("--run-dir", type=Path, required=True)
    exploratory.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            result = freeze_predictions(args.run_dir)
        elif args.command == "prepare-review":
            result = prepare_human_review(
                run_directory=args.run_dir,
                source_queue=args.source_queue,
                output_directory=args.output_dir,
                schema_path=args.schema,
            )
        elif args.command == "evaluate":
            output = args.output or args.review_dir / "metrics.json"
            result = evaluate_frozen_review(
                run_directory=args.run_dir,
                review_directory=args.review_dir,
                output_path=output,
            )
        elif args.command == "confirm-technical":
            result = normalize_human_confirmed_technical(
                human_confirmation_path=args.human_confirmation,
                technical_labels_path=args.technical_labels,
                output_path=args.output,
                fp_reason_code=args.fp_reason_code,
            )
        else:
            result = evaluate_exploratory_confirmation(
                labels_path=args.labels,
                run_directory=args.run_dir,
                output_path=args.output,
            )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
