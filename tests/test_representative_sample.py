from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulngym_enrich.representative_sample import create_sample, load_population


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def _finding(index: int, *, scanner: str = "semgrep", canonical: int | None = None) -> dict:
    canonical = index if canonical is None else canonical
    return {
        "schema_version": 1,
        "finding_id": f"finding-{index:064x}",
        "canonical_finding_id": f"canonical-{canonical:064x}",
        "repo_url": f"https://github.com/acme/repo-{index % 7}",
        "commit": f"{index % 11:040x}",
        "scanner": {"name": scanner, "version": "1.171.0"},
        "rule": {
            "id": f"rule-{index % 13}",
            "severity": ("ERROR", "WARNING", "INFO")[index % 3],
        },
        "location": {"file": f"src/file-{index % 17}.py", "start_line": index + 1},
        "dataflow_trace": [{"file": "src/source.py", "line": 1}] if index % 4 == 0 else [],
    }


def test_create_equal_probability_reproducible_sample(tmp_path: Path) -> None:
    population_path = tmp_path / "population.jsonl"
    rows = [_finding(index) for index in range(1000)]
    duplicate = dict(rows[10])
    duplicate["finding_id"] = f"finding-{2000:064x}"
    rows.append(duplicate)
    population_path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    pipeline_path = tmp_path / "summary.json"
    _write_json(
        pipeline_path,
        {"scan_id": "semgrep-test", "coverage": {"complete": True}},
    )
    schema_path = tmp_path / "schema.json"
    _write_json(schema_path, {"type": "object"})
    output = tmp_path / "sample"

    manifest = create_sample(
        project_root=tmp_path,
        population_path=population_path,
        pipeline_summary_path=pipeline_path,
        schema_path=schema_path,
        output_directory=output,
        sample_id="sample-r1",
        sample_size=100,
        seed="fixed-seed",
        created_at="2026-08-12T12:00:00+07:00",
        expected_population=1000,
    )

    findings = [json.loads(line) for line in (output / "sampled-findings.jsonl").read_text().splitlines()]
    index = [json.loads(line) for line in (output / "sampling-index.jsonl").read_text().splitlines()]
    assert manifest["sampling"]["population_size"] == 1000
    assert manifest["sampling"]["sample_size"] == 100
    assert manifest["sampling"]["inclusion_probability"] == 0.1
    assert manifest["sampling"]["analysis_weight"] == 10.0
    assert len(findings) == len(index) == 100
    assert len({row["finding_id"] for row in findings}) == 100
    assert len({row["canonical_finding_id"] for row in index}) == 100
    assert create_sample(
        project_root=tmp_path,
        population_path=population_path,
        pipeline_summary_path=pipeline_path,
        schema_path=schema_path,
        output_directory=output,
        sample_id="sample-r1",
        sample_size=100,
        seed="fixed-seed",
        created_at="2026-08-12T12:00:00+07:00",
        expected_population=1000,
    ) == manifest


def test_load_population_rejects_mixed_scanners(tmp_path: Path) -> None:
    path = tmp_path / "population.jsonl"
    path.write_text(json.dumps(_finding(1, scanner="opengrep")) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="expected scanner semgrep"):
        load_population(path)


def test_create_sample_supports_opengrep_population(tmp_path: Path) -> None:
    population_path = tmp_path / "population.jsonl"
    population_path.write_text(
        "".join(json.dumps(_finding(index, scanner="opengrep")) + "\n" for index in range(10)),
        encoding="utf-8",
    )
    pipeline_path = tmp_path / "summary.json"
    _write_json(
        pipeline_path,
        {"scan_id": "opengrep-test", "coverage": {"complete": True}},
    )
    schema_path = tmp_path / "schema.json"
    _write_json(schema_path, {"type": "object"})

    manifest = create_sample(
        project_root=tmp_path,
        population_path=population_path,
        pipeline_summary_path=pipeline_path,
        schema_path=schema_path,
        output_directory=tmp_path / "sample",
        sample_id="opengrep-sample-r1",
        sample_size=4,
        seed="fixed-opengrep-seed",
        created_at="2026-08-12T12:00:00+07:00",
        scanner_name="opengrep",
        expected_population=10,
    )

    assert manifest["source"]["scanner"] == "opengrep"
    assert manifest["generation_identity"]["scanner"] == "opengrep"


def test_create_sample_rejects_incomplete_or_wrong_population(tmp_path: Path) -> None:
    population_path = tmp_path / "population.jsonl"
    population_path.write_text(json.dumps(_finding(1)) + "\n", encoding="utf-8")
    pipeline_path = tmp_path / "summary.json"
    _write_json(pipeline_path, {"coverage": {"complete": False}})
    schema_path = tmp_path / "schema.json"
    _write_json(schema_path, {"type": "object"})
    with pytest.raises(ValueError, match="coverage must be complete"):
        create_sample(
            project_root=tmp_path,
            population_path=population_path,
            pipeline_summary_path=pipeline_path,
            schema_path=schema_path,
            output_directory=tmp_path / "output",
            sample_id="sample-r1",
            sample_size=1,
            seed="seed",
            created_at="2026-08-12T12:00:00+07:00",
        )

    _write_json(pipeline_path, {"coverage": {"complete": True}})
    with pytest.raises(ValueError, match="expected 2 canonical clusters, found 1"):
        create_sample(
            project_root=tmp_path,
            population_path=population_path,
            pipeline_summary_path=pipeline_path,
            schema_path=schema_path,
            output_directory=tmp_path / "output",
            sample_id="sample-r1",
            sample_size=1,
            seed="seed",
            created_at="2026-08-12T12:00:00+07:00",
            expected_population=2,
        )
