from __future__ import annotations

import json
from pathlib import Path

from vulngym_enrich.hybrid_review import _project_blind_finding, reconcile_reviews


def _json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def _jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sample(tmp_path: Path) -> tuple[Path, list[dict]]:
    sample = tmp_path / "sample"
    sample.mkdir()
    findings = [
        {
            "schema_version": 1,
            "finding_id": f"finding-{index:064x}",
            "repo_url": "https://github.com/acme/repo",
            "commit": f"{index:040x}",
            "scanner": {"name": "opengrep", "version": "1.22.0"},
            "rule": {"id": "rule"},
            "location": {"file": "x.py", "start_line": 1},
        }
        for index in range(1, 5)
    ]
    index = [
        {"finding_id": row["finding_id"], "review_order": number}
        for number, row in enumerate(findings, 1)
    ]
    _jsonl(sample / "sampled-findings.jsonl", findings)
    _jsonl(sample / "sampling-index.jsonl", index)
    _json(
        sample / "sample-manifest.json",
        {
            "sampling": {"sample_size": 4},
            "outputs": {
                "sampled-findings.jsonl": {
                    "sha256": _sha256(sample / "sampled-findings.jsonl")
                },
                "sampling-index.jsonl": {
                    "sha256": _sha256(sample / "sampling-index.jsonl")
                },
            },
        },
    )
    return sample, findings


def _prediction(finding_id: str, verdict: str, confidence: str = "HIGH") -> dict:
    return {
        "finding_id": finding_id,
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": "Source-backed reviewer decision.",
        "evidence": [],
    }


def test_opengrep_uses_frozen_other_scanner_contract() -> None:
    projected = _project_blind_finding(
        {
            "schema_version": 1,
            "finding_id": "finding-1",
            "scanner": {"name": "opengrep", "version": "1.22.0"},
            "provenance": {
                "raw_result_ref": "raw.json#0",
                "observed_by": [{"scanner": "opengrep", "rule_id": "rule"}],
            },
        }
    )
    assert projected["scanner"]["name"] == "other"
    assert projected["provenance"]["observed_by"][0]["scanner"] == "opengrep"


def test_reconcile_routes_silver_and_human_review(tmp_path: Path) -> None:
    sample, findings = _sample(tmp_path)
    a = [
        _prediction(findings[0]["finding_id"], "FALSE_POSITIVE"),
        _prediction(findings[1]["finding_id"], "TRUE_POSITIVE"),
        _prediction(findings[2]["finding_id"], "ABSTAIN", "MEDIUM"),
        _prediction(findings[3]["finding_id"], "FALSE_POSITIVE"),
    ]
    b = [
        _prediction(findings[0]["finding_id"], "FALSE_POSITIVE"),
        _prediction(findings[1]["finding_id"], "TRUE_POSITIVE"),
        _prediction(findings[2]["finding_id"], "FALSE_POSITIVE"),
        _prediction(findings[3]["finding_id"], "FALSE_POSITIVE", "LOW"),
    ]
    reviewer_a = tmp_path / "a.jsonl"
    reviewer_b = tmp_path / "b.jsonl"
    _jsonl(reviewer_a, a)
    _jsonl(reviewer_b, b)

    summary = reconcile_reviews(
        sample_directory=sample,
        reviewer_a_path=reviewer_a,
        reviewer_b_path=reviewer_b,
        output_directory=tmp_path / "out",
        audit_fraction=0.0,
    )

    assert summary["counts"] == {
        "high_consensus": 2,
        "silver_without_human_review": 1,
        "needs_human_review": 3,
        "uncertain_or_true_positive": 2,
    }
    assert summary["publication_policy"]["official_metrics_require_human_gold_for_all_400"]
    human = (tmp_path / "out/human-adjudication.template.jsonl").read_text().splitlines()
    assert len(human) == 3


def test_reconcile_audit_is_deterministic(tmp_path: Path) -> None:
    sample, findings = _sample(tmp_path)
    rows = [_prediction(row["finding_id"], "FALSE_POSITIVE") for row in findings]
    reviewer_a = tmp_path / "a.jsonl"
    reviewer_b = tmp_path / "b.jsonl"
    _jsonl(reviewer_a, rows)
    _jsonl(reviewer_b, rows)

    first = reconcile_reviews(
        sample_directory=sample,
        reviewer_a_path=reviewer_a,
        reviewer_b_path=reviewer_b,
        output_directory=tmp_path / "first",
        audit_fraction=0.5,
        audit_seed="fixed",
    )
    second = reconcile_reviews(
        sample_directory=sample,
        reviewer_a_path=reviewer_a,
        reviewer_b_path=reviewer_b,
        output_directory=tmp_path / "second",
        audit_fraction=0.5,
        audit_seed="fixed",
    )
    assert first["counts"] == second["counts"]
    assert (
        (tmp_path / "first/needs-human-review.jsonl").read_text()
        == (tmp_path / "second/needs-human-review.jsonl").read_text()
    )
