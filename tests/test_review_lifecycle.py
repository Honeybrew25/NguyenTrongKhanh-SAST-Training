from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vulngym_enrich.review_lifecycle import (
    evaluate_exploratory_confirmation,
    evaluate_frozen_review,
    freeze_predictions,
    normalize_human_confirmed_technical,
    prepare_human_review,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def _jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _run(tmp_path: Path) -> tuple[Path, Path, Path]:
    run = tmp_path / "run"
    queue = tmp_path / "queue"
    schema = tmp_path / "human-schema.json"
    finding = {
        "schema_version": 1,
        "finding_id": "finding-1",
        "repo_url": "https://github.com/example/project",
        "commit": "a" * 40,
        "scanner": {"name": "other", "version": "opengrep 1.22.0"},
        "rule": {"id": "rule", "ruleset_commit": "b" * 40},
        "message": "message",
        "location": {"file": "app.py", "start_line": 1, "end_line": 1},
        "provenance": {"raw_result_ref": "raw.json#0"},
    }
    prediction = {
        "finding_id": "finding-1",
        "verdict": "TRUE_POSITIVE",
        "evaluation_eligible": True,
    }
    _jsonl(run / "blind-verifier-input.jsonl", [finding])
    _jsonl(run / "verifier-predictions.jsonl", [prediction])
    manifest = {
        "run_id": "test-run",
        "status": "COMPLETE",
        "complete": True,
        "evaluation_mode": "OFFICIAL",
        "input": {
            "frozen_copy": "blind-verifier-input.jsonl",
            "sha256": _sha(run / "blind-verifier-input.jsonl"),
            "records": 1,
        },
        "predictions": {
            "sha256": _sha(run / "verifier-predictions.jsonl"),
            "records": 1,
        },
        "provider": {
            "id": "provider",
            "version": "1",
            "model": "pinned-model",
            "model_explicitly_pinned": True,
        },
        "case_counts": {"total": 1, "success": 1, "failed": 0},
        "cases": [{"identity": {"finding_id": "finding-1"}}],
    }
    _json(run / "verifier-run.json", manifest)
    candidate = {**finding, "canonical_finding_id": "canonical-1"}
    _jsonl(queue / "candidate-findings.jsonl", [candidate])
    _jsonl(
        queue / "human-candidate-matches.jsonl",
        [{"member_finding_ids": ["finding-1"]}],
    )
    _json(schema, {"type": "object"})
    return run, queue, schema


def test_freeze_and_prepare_review_exclude_predictions(tmp_path: Path) -> None:
    run, queue, schema = _run(tmp_path)
    freeze = freeze_predictions(run)
    review = tmp_path / "review"
    packet = prepare_human_review(
        run_directory=run,
        source_queue=queue,
        output_directory=review,
        schema_path=schema,
    )

    assert freeze["status"] == "FROZEN"
    assert packet["prediction_commitment"]["prediction_contents_included"] is False
    assert {path.name for path in review.iterdir()} == {
        "candidate-findings.jsonl",
        "human-candidate-matches.jsonl",
        "human-gold-label.schema.json",
        "human-gold-labels.template.jsonl",
        "README.md",
        "review-manifest.json",
    }
    assert not (review / "verifier-predictions.jsonl").exists()


def test_freeze_rejects_incomplete_run(tmp_path: Path) -> None:
    run, _, _ = _run(tmp_path)
    manifest = json.loads((run / "verifier-run.json").read_text())
    manifest["complete"] = False
    _json(run / "verifier-run.json", manifest)
    with pytest.raises(ValueError, match="COMPLETE"):
        freeze_predictions(run)


def test_evaluate_requires_human_gold_and_frozen_hash(tmp_path: Path) -> None:
    run, queue, schema = _run(tmp_path)
    freeze_predictions(run)
    review = tmp_path / "review"
    prepare_human_review(
        run_directory=run,
        source_queue=queue,
        output_directory=review,
        schema_path=schema,
    )
    with pytest.raises(FileNotFoundError):
        evaluate_frozen_review(
            run_directory=run,
            review_directory=review,
            output_path=review / "metrics.json",
        )

    label = {
        "schema_version": 1,
        "finding_id": "finding-1",
        "label": "TP_NOVEL",
        "reason_codes": [],
        "reasoning": "Independent source review proves reachability and impact.",
        "reviewer": {"id": "human-1", "kind": "HUMAN"},
        "reviewed_at": "2026-08-12T14:00:00+07:00",
        "evidence": ["app.py:1"],
        "linked_entry_ids": [],
        "linked_report_ids": [],
    }
    _jsonl(review / "human-gold-labels.jsonl", [label])
    metrics = evaluate_frozen_review(
        run_directory=run,
        review_directory=review,
        output_path=review / "metrics.json",
    )
    assert metrics["confusion_matrix_decided_only"]["tp"] == 1
    assert (review / "metrics.json").is_file()


def test_human_confirmed_technical_metrics_remain_exploratory(tmp_path: Path) -> None:
    run, _, _ = _run(tmp_path)
    freeze_predictions(run)
    technical = tmp_path / "technical.jsonl"
    confirmation = tmp_path / "confirmation.jsonl"
    base = {
        "schema_version": 1,
        "finding_id": "finding-1",
        "label": "TP_KNOWN",
        "reasoning": "The reviewed sink is reachable from the documented input.",
        "reviewed_at": "2026-08-12T14:00:00+07:00",
        "evidence": ["app.py:1"],
        "linked_entry_ids": ["entry-00001"],
        "linked_report_ids": ["GHSA-TEST"],
    }
    _jsonl(
        technical,
        [{**base, "reviewer": {"id": "ai", "kind": "AI_TECHNICAL_REVIEW"}}],
    )
    _jsonl(
        confirmation,
        [{**base, "reviewer": {"id": "human-1", "kind": "HUMAN"}}],
    )
    normalized = tmp_path / "exploratory" / "labels.jsonl"
    manifest = normalize_human_confirmed_technical(
        human_confirmation_path=confirmation,
        technical_labels_path=technical,
        output_path=normalized,
        fp_reason_code="OTHER_EXPLAINED",
    )
    report = evaluate_exploratory_confirmation(
        labels_path=normalized,
        run_directory=run,
        output_path=tmp_path / "exploratory" / "provisional-metrics.json",
    )

    assert manifest["independent_human_gold"] is False
    assert report["status"] == "EXPLORATORY_NON_INDEPENDENT"
    assert report["publish_as_official"] is False
    assert report["metrics"]["confusion_matrix_decided_only"]["tp"] == 1
