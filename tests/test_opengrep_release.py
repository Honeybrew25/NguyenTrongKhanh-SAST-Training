from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vulngym_enrich.opengrep_release import build_opengrep_release


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def _fixture(tmp_path: Path) -> tuple[Path, dict]:
    normalized = tmp_path / "normalized"
    pipeline = {
        "schema_version": 1,
        "scan_id": "opengrep-full-test",
        "frozen_provenance": {
            "scanner_pins": {"opengrep": {"version": "1.22.0"}}
        },
        "coverage": {
            "complete": True,
            "jobs_expected": 1,
            "jobs_accounted": 1,
            "status_counts": {"SUCCESS": 1},
            "blocking_statuses": {},
        },
        "normalization": {"findings": 1, "by_scanner": {"opengrep": 1}},
        "matching": {
            "counts_by_tier": {"CANDIDATE_REVIEW": 1},
            "policy": {"unmatched_label_policy": "UNLABELED_NOT_FALSE_POSITIVE"},
        },
    }
    finding = {
        "schema_version": 1,
        "canonical_finding_id": "canonical-1",
        "finding_id": "finding-1",
        "repo_url": "https://github.com/example/project",
        "commit": "a" * 40,
        "scanner": {"name": "opengrep", "version": "1.22.0"},
        "rule": {"id": "test.rule", "ruleset_commit": "b" * 40},
        "message": "test",
        "location": {"file": "src/app.py", "start_line": 4, "end_line": 4},
        "dataflow_trace": [],
        "snippet": "sink(value)",
        "fingerprint": "fingerprint",
        "provenance": {"raw_result_ref": "raw.json#results/0"},
    }
    match = {
        "canonical_finding_id": "canonical-1",
        "finding_id": "canonical-1",
        "match_tier": "CANDIDATE_REVIEW",
        "matches": [{"entry_id": "entry-00001", "report_id": "GHSA-TEST"}],
        "member_finding_ids": ["finding-1"],
    }
    _write_json(normalized / "full-pipeline-summary.json", pipeline)
    _write_jsonl(normalized / "security-deduplicated.jsonl", [finding])
    _write_jsonl(normalized / "canonical-security-matches.jsonl", [match])
    return normalized, pipeline


def test_build_opengrep_release_freezes_blind_corpus(tmp_path: Path) -> None:
    normalized, _ = _fixture(tmp_path)
    queue = tmp_path / "queue"
    corpus = tmp_path / "corpus"

    result = build_opengrep_release(
        normalized_directory=normalized,
        queue_directory=queue,
        corpus_directory=corpus,
        project_root=tmp_path,
        corpus_id="opengrep-test-v1",
        created_at="2026-08-12T00:00:00+00:00",
    )

    blind = json.loads((queue / "blind-verifier-input.jsonl").read_text())
    assert blind["scanner"] == {"name": "other", "version": "opengrep 1.22.0"}
    assert "canonical_finding_id" not in blind
    serialized = json.dumps(blind)
    assert "entry-00001" not in serialized
    assert "GHSA-TEST" not in serialized
    assert (corpus / "blind-verifier-input.jsonl").read_bytes() == (
        queue / "blind-verifier-input.jsonl"
    ).read_bytes()
    summary = json.loads((corpus / "summary.json").read_text())
    digest = hashlib.sha256((corpus / "blind-verifier-input.jsonl").read_bytes()).hexdigest()
    assert summary["complete"] is True
    assert summary["blind_verifier_input"] == {
        "path": "blind-verifier-input.jsonl",
        "sha256": digest,
        "records": 1,
    }
    assert result["candidate_clusters"] == 1


def test_build_opengrep_release_rejects_incomplete_coverage(tmp_path: Path) -> None:
    normalized, pipeline = _fixture(tmp_path)
    pipeline["coverage"]["complete"] = False
    _write_json(normalized / "full-pipeline-summary.json", pipeline)

    with pytest.raises(ValueError, match="coverage must be complete"):
        build_opengrep_release(
            normalized_directory=normalized,
            queue_directory=tmp_path / "queue",
            corpus_directory=tmp_path / "corpus",
            project_root=tmp_path,
            corpus_id="opengrep-test-v1",
            created_at="2026-08-12T00:00:00+00:00",
        )


def test_build_opengrep_release_rejects_candidate_count_mismatch(
    tmp_path: Path,
) -> None:
    normalized, pipeline = _fixture(tmp_path)
    pipeline["matching"]["counts_by_tier"]["CANDIDATE_REVIEW"] = 2
    _write_json(normalized / "full-pipeline-summary.json", pipeline)

    with pytest.raises(ValueError, match="candidate match count"):
        build_opengrep_release(
            normalized_directory=normalized,
            queue_directory=tmp_path / "queue",
            corpus_directory=tmp_path / "corpus",
            project_root=tmp_path,
            corpus_id="opengrep-test-v1",
            created_at="2026-08-12T00:00:00+00:00",
        )
