from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIRECTORY = ROOT / "data" / "enriched"


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_opengrep_machine_dataset_and_release_proofs() -> None:
    dataset = DATASET_DIRECTORY / "opengrep-machine-reviewed-r1.jsonl"
    schema_path = ROOT / "schemas" / "machine-enriched-finding.schema.json"
    manifest_path = ROOT / "data" / "releases" / "opengrep-machine-reviewed-r1-20260814.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    rows = _load_jsonl(dataset)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert len(rows) == len({row["finding_id"] for row in rows}) == 400
    assert manifest["status"] == "FROZEN_MACHINE_ENRICHED_DATASET"
    assert manifest["reference_policy"]["human_gold"] is False
    assert manifest["reference_policy"]["uncertain_is_false_positive"] is False
    assert manifest["counts"]["labels"] == {
        "MACHINE_FALSE_POSITIVE": 367,
        "MACHINE_TRUE_POSITIVE": 7,
        "MACHINE_UNCERTAIN": 26,
    }
    assert manifest["counts"]["linkage"] == {
        "MACHINE_TP_UNLINKED": 7,
        "NOT_APPLICABLE": 393,
    }
    for row in rows:
        errors = list(validator.iter_errors(row))
        assert not errors, errors[0].message if errors else ""
        assert row["finding_id"] == row["finding"]["finding_id"]
        assert row["finding_id"] == row["machine_reference"]["finding_id"]
        assert row["finding"]["scanner"]["name"] == "opengrep"
        assert row["machine_reference"]["provenance"]["method"] == "LLM_ADJUDICATED"


def test_machine_benchmark_has_no_repository_or_finding_leakage() -> None:
    directory = ROOT / "data" / "splits" / "opengrep-machine-benchmark-r1-20260814"
    manifest = json.loads((directory / "split-manifest.json").read_text(encoding="utf-8"))
    rows = {split: _load_jsonl(directory / f"{split}.jsonl") for split in ("train", "validation", "test")}
    repository_sets = {
        split: {row["features"]["repository"] for row in members}
        for split, members in rows.items()
    }
    finding_sets = {
        split: {row["finding_id"] for row in members}
        for split, members in rows.items()
    }
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        assert not repository_sets[left] & repository_sets[right]
        assert not finding_sets[left] & finding_sets[right]
    assert [len(rows[split]) for split in ("train", "validation", "test")] == [6, 4, 4]
    for split, members in rows.items():
        labels = [row["machine_reference"]["label"] for row in members]
        assert labels.count("MACHINE_TRUE_POSITIVE") == labels.count("MACHINE_FALSE_POSITIVE")
        assert "MACHINE_UNCERTAIN" not in labels
    assert manifest["gates"] == {
        "balanced_records": 14,
        "finding_overlap": 0,
        "repository_overlap": 0,
    }


def test_three_baseline_prediction_sets_cover_the_same_test_ids() -> None:
    directory = ROOT / "data" / "splits" / "opengrep-machine-benchmark-r1-20260814"
    test_ids = {row["finding_id"] for row in _load_jsonl(directory / "test.jsonl")}
    prediction_files = (
        "raw-opengrep-predictions.jsonl",
        "snippet-only-predictions.jsonl",
        "repository-context-predictions.jsonl",
    )
    for name in prediction_files:
        rows = _load_jsonl(directory / name)
        assert {row["finding_id"] for row in rows} == test_ids
        assert all(row["verdict"] in {"TRUE_POSITIVE", "FALSE_POSITIVE", "ABSTAIN"} for row in rows)

    expected = {
        "raw-opengrep-metrics.json": ({"tp": 2, "fp": 2, "tn": 0, "fn": 0}, 1.0),
        "snippet-only-metrics.json": ({"tp": 0, "fp": 0, "tn": 2, "fn": 0}, 0.5),
        "repository-context-metrics.json": ({"tp": 1, "fp": 0, "tn": 2, "fn": 1}, 1.0),
    }
    for name, (confusion, coverage) in expected.items():
        report = json.loads((directory / name).read_text(encoding="utf-8"))
        assert report["confusion_matrix_decided_only"] == confusion
        assert report["coverage"]["selective_coverage"] == coverage
        assert report["reference_policy"]["human_gold"] is False
        assert report["reference_policy"]["publish_as_official"] is False
        assert set(report["breakdowns"]) == {"repository", "rule", "cwe", "language", "dataflow"}
