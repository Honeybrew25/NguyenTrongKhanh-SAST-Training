from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "enriched-finding.schema.json"
DATASET_DIRECTORY = ROOT / "data" / "enriched"


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_day2_enriched_findings_conform_to_schema() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    datasets = sorted(DATASET_DIRECTORY.glob("*.jsonl"))

    assert datasets
    for dataset in datasets:
        rows = _load_jsonl(dataset)
        assert rows
        for line_number, row in enumerate(rows, 1):
            errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
            assert not errors, (
                f"{dataset.name}:{line_number}: {errors[0].message if errors else ''}"
            )


def test_day2_confirmed_false_positives_have_unique_ids_and_evidence() -> None:
    rows = [row for dataset in sorted(DATASET_DIRECTORY.glob("*.jsonl")) for row in _load_jsonl(dataset)]
    finding_ids = [row["finding_id"] for row in rows]
    canonical_ids = [row["canonical_finding_id"] for row in rows]

    assert len(finding_ids) == len(set(finding_ids))
    assert len(canonical_ids) == len(set(canonical_ids))
    for row in rows:
        adjudication = row["adjudication"]
        assert adjudication["label"] == "FP_CONFIRMED"
        assert adjudication["reason_codes"]
        assert adjudication["evidence"]
        assert not adjudication.get("linked_entry_ids")
        assert not adjudication.get("linked_report_ids")
        assert len(row["provenance"]["evidence_refs"]) >= 2
