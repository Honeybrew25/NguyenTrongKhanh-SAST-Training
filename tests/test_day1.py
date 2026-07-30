from __future__ import annotations

import json
from pathlib import Path

from vulngym_enrich.audit import audit
from vulngym_enrich.checkout import repo_slug
from vulngym_enrich.evaluator import classification_metrics, coverage_metrics
from vulngym_enrich.matcher import LineSpan, endpoint_match, finding_matches_entry, normalize_path

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "benchmark" / "VulnGym"


def test_line_span_parse_and_distance() -> None:
    assert LineSpan.parse(10) == LineSpan(10, 10)
    assert LineSpan.parse("10-15") == LineSpan(10, 15)
    assert LineSpan(10, 15).distance(LineSpan(14, 20)) == 0
    assert LineSpan(10, 15).distance(LineSpan(18, 20)) == 3


def test_endpoint_range_matching_regression() -> None:
    candidate = {"file": "./src\\handler.py", "line": 103}
    truth = {"file": "src/handler.py", "line": "100-102"}
    assert normalize_path(candidate["file"]) == "src/handler.py"
    assert endpoint_match(candidate, truth, tolerance=1)
    assert not endpoint_match(candidate, truth, tolerance=0)


def test_finding_requires_snapshot_and_both_roles() -> None:
    entry = {
        "repo_url": "https://github.com/org/repo",
        "commit": "a" * 40,
        "entry_point": {"file": "source.py", "line": "10-12"},
        "critical_operation": {"file": "sink.py", "line": "40-42"},
    }
    finding = {
        **entry,
        "entry_point": {"file": "./source.py", "line": 13},
        "critical_operation": {"file": "sink.py", "line": 45},
    }
    assert finding_matches_entry(finding, entry, tolerance=3)
    assert not finding_matches_entry({**finding, "commit": "b" * 40}, entry, tolerance=3)


def test_audit_frozen_vulngym() -> None:
    manifest, errors = audit(BENCHMARK)
    assert errors == []
    stats = manifest["statistics"]
    assert stats["reports"] == 184
    assert stats["entries"] == 408
    assert stats["verified_entries"] == 393
    assert stats["distinct_repositories"] == 23
    assert stats["distinct_snapshots"] == 166
    assert stats["entries_with_line_ranges"] == 44
    assert manifest["benchmark"]["tag"] == "v0.1.4"
    assert manifest["benchmark"]["commit"] == "cd69f7e163e08485ab5496115ae03439cda6e27e"


def test_all_upstream_entries_match_themselves_including_ranges() -> None:
    entries = [json.loads(line) for line in (BENCHMARK / "data" / "entries.jsonl").read_text(encoding="utf-8").splitlines()]
    report = coverage_metrics(entries, entries, tolerance=0)
    assert report["recall"]["entry_level"]["numerator"] == 408
    assert report["recall"]["advisory_level"]["numerator"] == 184


def test_classification_metrics_with_abstention() -> None:
    labels = [
        {"finding_id": "a", "label": "TP_KNOWN"},
        {"finding_id": "b", "label": "FP_CONFIRMED"},
        {"finding_id": "c", "label": "TP_NOVEL"},
        {"finding_id": "d", "label": "UNCERTAIN"},
    ]
    predictions = [
        {"finding_id": "a", "verdict": "TRUE_POSITIVE"},
        {"finding_id": "b", "verdict": "FALSE_POSITIVE"},
        {"finding_id": "c", "verdict": "ABSTAIN"},
    ]
    report = classification_metrics(labels, predictions)
    assert report["confusion_matrix_decided_only"] == {"tp": 1, "fp": 0, "tn": 1, "fn": 0}
    assert report["coverage"]["abstained"] == 1
    assert report["excluded_labels"] == {"UNCERTAIN": 1}


def test_repo_slug_rejects_non_github_and_accepts_expected() -> None:
    assert repo_slug("https://github.com/Tencent/VulnGym.git") == "Tencent__VulnGym"
    try:
        repo_slug("https://example.com/org/repo")
    except ValueError:
        pass
    else:
        raise AssertionError("non-GitHub URL was accepted")
