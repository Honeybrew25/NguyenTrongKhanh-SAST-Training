from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path

import pytest

from vulngym_enrich.candidate_matcher import (
    CANDIDATE,
    STRONG,
    STRICT,
    UNMATCHED,
    aggregate_canonical_matches,
    match_candidates,
)
from vulngym_enrich.evaluator import classification_metrics, coverage_metrics
from vulngym_enrich.normalizer import (
    NormalizationContext,
    _encoded_rule_prefix,
    _status_input_path,
    merge_sarif_evidence,
    normalize_sarif,
    normalize_semgrep_json,
)

REPO = "https://github.com/example/project"
COMMIT = "a" * 40
RULESET = "b" * 40


def _context(source_root: Path, scanner: str = "semgrep", version: str = "1.171.0") -> NormalizationContext:
    return NormalizationContext(
        repo_url=REPO,
        commit=COMMIT,
        scanner_name=scanner,
        scanner_version=version,
        ruleset_commit=RULESET,
        scan_id="day2-pilot",
        raw_result_ref="artifacts/raw.json",
        source_root=source_root,
        read_source_snippets=True,
    )


def _json_result() -> dict:
    return {
        "version": "1.171.0",
        "results": [
            {
                "check_id": "python.lang.security.command-injection",
                "path": "src\\app.py",
                "start": {"line": 3, "col": 1},
                "end": {"line": 3, "col": 16},
                "extra": {
                    "message": "attacker input reaches a process sink",
                    "severity": "ERROR",
                    "fingerprint": "requires login",
                    "lines": "requires login",
                    "metadata": {"cwe": ["CWE-78: OS Command Injection"], "category": "security"},
                },
            }
        ],
    }


def _sarif(version: str = "1.171.0") -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "semgrep",
                        "semanticVersion": version,
                        "rules": [
                            {
                                "id": "python.lang.security.command-injection",
                                "properties": {"tags": ["external/cwe/cwe-078"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "python.lang.security.command-injection",
                        "level": "error",
                        "message": {"text": "attacker input reaches a process sink"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.py"},
                                    "region": {"startLine": 3, "endLine": 3, "startColumn": 1, "endColumn": 16},
                                }
                            }
                        ],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": {
                                                    "message": {"text": "source"},
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "src/app.py"},
                                                        "region": {"startLine": 1, "snippet": {"text": "value = request.args['x']"}},
                                                    },
                                                }
                                            },
                                            {
                                                "location": {
                                                    "message": {"text": "sink"},
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "src/app.py"},
                                                        "region": {"startLine": 3, "snippet": {"text": "os.system(value)"}},
                                                    },
                                                }
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_json_normalization_joins_sarif_codeflow_and_source_snippet(tmp_path: Path) -> None:
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("value = request.args['x']\nvalue = str(value)\nos.system(value)\n", encoding="utf-8")
    context = _context(tmp_path)

    first = normalize_semgrep_json(_json_result(), context)
    second = normalize_semgrep_json(_json_result(), context)
    assert first[0]["finding_id"] == second[0]["finding_id"]
    assert first[0]["location"]["file"] == "src/app.py"
    assert first[0]["snippet"] == "os.system(value)"
    assert first[0]["fingerprint"] is not None
    assert first[0]["rule"]["cwe"] == ["CWE-78"]

    sarif_findings = normalize_sarif(
        _sarif(), replace(context, raw_result_ref="artifacts/raw.sarif")
    )
    merged = merge_sarif_evidence(first, sarif_findings)
    assert [(node["line"], node["description"]) for node in merged[0]["dataflow_trace"]] == [
        (1, "source"),
        (3, "sink"),
    ]
    assert merged[0]["provenance"]["raw_result_ref"].endswith("#results/0")
    assert len(merged[0]["provenance"]["evidence_refs"]) == 2


def test_normalizer_rejects_unpinned_scanner_version(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="scanner version mismatch"):
        normalize_semgrep_json({**_json_result(), "version": "unexpected"}, _context(tmp_path))


def test_rule_id_drops_workspace_dependent_absolute_prefix(tmp_path: Path) -> None:
    ruleset_root = tmp_path / "rules" / "semgrep-rules"
    raw = _json_result()
    raw["results"][0]["check_id"] = (
        _encoded_rule_prefix(ruleset_root) + ".python.lang.security.stable-rule"
    )
    finding = normalize_semgrep_json(
        raw, replace(_context(tmp_path), ruleset_root=ruleset_root)
    )[0]
    assert finding["rule"]["id"] == "python.lang.security.stable-rule"


def test_opengrep_uses_semgrep_compatible_json_and_rule_ids(tmp_path: Path) -> None:
    ruleset_root = tmp_path / "rules" / "semgrep-rules"
    raw = _json_result()
    raw["version"] = "1.22.0"
    raw["results"][0]["check_id"] = (
        _encoded_rule_prefix(ruleset_root) + ".python.lang.security.stable-rule"
    )
    context = replace(
        _context(tmp_path),
        scanner_name="opengrep",
        scanner_version="1.22.0",
        ruleset_root=ruleset_root,
    )

    finding = normalize_semgrep_json(raw, context)[0]

    assert finding["scanner"] == {"name": "opengrep", "version": "1.22.0"}
    assert finding["rule"]["id"] == "python.lang.security.stable-rule"


def test_status_input_prefers_contained_frozen_copy(tmp_path: Path) -> None:
    attempt = tmp_path / "attempt"
    frozen = attempt / "inputs" / "scan-profile.json"
    frozen.parent.mkdir(parents=True)
    frozen.write_text("{}\n", encoding="utf-8")

    assert _status_input_path(
        attempt,
        "scan_profile",
        {"path": str(tmp_path / "mutable.json"), "frozen_path": "inputs/scan-profile.json"},
    ) == frozen.resolve()
    with pytest.raises(ValueError, match="escapes attempt directory"):
        _status_input_path(
            attempt,
            "scan_profile",
            {"path": "ignored", "frozen_path": "../outside.json"},
        )


def test_tiered_matcher_never_labels_unmatched_as_false_positive(tmp_path: Path) -> None:
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("source\nflow\nsink\n", encoding="utf-8")
    finding = merge_sarif_evidence(
        normalize_semgrep_json(_json_result(), _context(tmp_path)),
        normalize_sarif(_sarif(), _context(tmp_path)),
    )[0]
    entry = {
        "entry_id": "entry-00001",
        "report_id": "GHSA-AAAA-BBBB-CCCC",
        "repo_url": REPO,
        "commit": COMMIT,
        "entry_point": {"file": "src/app.py", "line": 1},
        "critical_operation": {"file": "src/app.py", "line": 3},
        "verify": 1,
    }
    sink_only = copy.deepcopy(finding)
    sink_only["finding_id"] = "sink-only"
    sink_only["dataflow_trace"] = []
    unmatched = copy.deepcopy(finding)
    unmatched["finding_id"] = "unmatched"
    unmatched["location"] = {**unmatched["location"], "start_line": 30, "end_line": 30}

    rows, summary = match_candidates([finding, sink_only, unmatched], [entry], tolerance=2)
    assert [row["match_tier"] for row in rows] == [STRICT, CANDIDATE, UNMATCHED]
    assert summary["policy"]["unmatched_label_policy"] == "UNLABELED_NOT_FALSE_POSITIVE"

    finding["canonical_finding_id"] = "canonical-one"
    sink_only["canonical_finding_id"] = "canonical-one"
    unmatched["canonical_finding_id"] = "canonical-two"
    canonical, canonical_summary = aggregate_canonical_matches(
        [finding, sink_only, unmatched], rows, summary
    )
    assert [row["match_tier"] for row in canonical] == [STRICT, UNMATCHED]
    assert canonical_summary["unit"] == "canonical_cluster"
    assert canonical_summary["total_observations"] == 3
    coverage = coverage_metrics([entry], [finding], tolerance=0)
    assert coverage["recall"]["entry_level"]["numerator"] == 1


def test_strong_match_requires_compatible_category_or_cwe_and_dataflow(tmp_path: Path) -> None:
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("source\nflow\nsink\n", encoding="utf-8")
    finding = merge_sarif_evidence(
        normalize_semgrep_json(_json_result(), _context(tmp_path)),
        normalize_sarif(_sarif(), _context(tmp_path)),
    )[0]
    entry = {
        "entry_id": "entry-strong",
        "report_id": "GHSA-STRONG-MATCH-TEST",
        "repo_url": REPO,
        "commit": COMMIT,
        # Both endpoints are close, but deliberately not exact, so Tier A does
        # not hide the additional Tier B requirements under test.
        "entry_point": {"file": "src/app.py", "line": 2},
        "critical_operation": {"file": "src/app.py", "line": 4},
        "vuln_category_l1": "命令注入",
        "vuln_category_l2": "OS命令注入",
        "verify": 1,
    }

    compatible = copy.deepcopy(finding)
    compatible["finding_id"] = "compatible"
    incompatible = copy.deepcopy(finding)
    incompatible["finding_id"] = "incompatible"
    incompatible["rule"]["cwe"] = ["CWE-79"]
    incompatible["rule"]["category"] = "security"
    no_trace = copy.deepcopy(finding)
    no_trace["finding_id"] = "no-trace"
    no_trace["dataflow_trace"] = []

    rows, summary = match_candidates(
        [compatible, incompatible, no_trace], [entry], tolerance=1
    )

    assert [row["match_tier"] for row in rows] == [STRONG, CANDIDATE, CANDIDATE]
    assert rows[0]["matches"][0]["dataflow_supported"] is True
    assert rows[0]["matches"][0]["category_cwe_compatible"] is True
    assert rows[0]["matches"][0]["category_cwe_evidence"] == [
        "family:command_injection"
    ]
    assert rows[1]["matches"][0]["category_cwe_compatible"] is False
    assert rows[2]["matches"][0]["dataflow_supported"] is False
    assert "compatible CWE/vulnerability category" in summary["policy"]["strong"]


def test_strong_match_accepts_specific_category_without_cwe(tmp_path: Path) -> None:
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("source\nflow\nsink\n", encoding="utf-8")
    finding = merge_sarif_evidence(
        normalize_semgrep_json(_json_result(), _context(tmp_path)),
        normalize_sarif(_sarif(), _context(tmp_path)),
    )[0]
    finding["rule"]["cwe"] = []
    finding["rule"]["category"] = "command-injection"
    entry = {
        "entry_id": "entry-category",
        "report_id": "GHSA-CATEGORY-MATCH",
        "repo_url": REPO,
        "commit": COMMIT,
        "entry_point": {"file": "src/app.py", "line": 2},
        "critical_operation": {"file": "src/app.py", "line": 4},
        "vuln_category_l1": "命令注入",
        "verify": 1,
    }

    rows, _ = match_candidates([finding], [entry], tolerance=1)

    assert rows[0]["match_tier"] == STRONG
    assert rows[0]["matches"][0]["category_cwe_evidence"] == [
        "family:command_injection"
    ]


def test_classification_coverage_includes_missing_and_abstained_predictions() -> None:
    labels = [
        {"finding_id": "tp", "label": "TP_KNOWN"},
        {"finding_id": "fp", "label": "FP_CONFIRMED"},
        {"finding_id": "missing-true", "label": "TP_NOVEL"},
        {"finding_id": "missing-false", "label": "FP_CONFIRMED"},
    ]
    predictions = [
        {"finding_id": "tp", "verdict": "TRUE_POSITIVE"},
        {"finding_id": "fp", "verdict": "ABSTAIN"},
    ]
    report = classification_metrics(labels, predictions)
    assert report["coverage"] == {
        "labeled_total": 4,
        "decided": 1,
        "abstained": 1,
        "missing": 2,
        "selective_coverage": 0.25,
        "abstain_on_true": 0,
        "abstain_on_false": 1,
        "missing_on_true": 1,
        "missing_on_false": 1,
    }
    assert report["metrics_end_to_end"]["tp_retention"] == 0.5
    assert report["metrics_end_to_end"]["false_positive_removal_rate"] == 0.0

    all_wrong = classification_metrics(
        [
            {"finding_id": "positive", "label": "TP_KNOWN"},
            {"finding_id": "negative", "label": "FP_CONFIRMED"},
        ],
        [
            {"finding_id": "positive", "verdict": "FALSE_POSITIVE"},
            {"finding_id": "negative", "verdict": "TRUE_POSITIVE"},
        ],
    )
    assert all_wrong["metrics_decided_only"]["f1"] == 0.0


def test_classification_metrics_excludes_ineligible_predictions() -> None:
    report = classification_metrics(
        [
            {"finding_id": "eligible", "label": "TP_KNOWN"},
            {"finding_id": "contaminated", "label": "UNCERTAIN"},
        ],
        [
            {"finding_id": "eligible", "verdict": "TRUE_POSITIVE"},
            {
                "finding_id": "contaminated",
                "verdict": "TRUE_POSITIVE",
                "evaluation_eligible": False,
            },
        ],
    )

    assert report["excluded_predictions"] == ["contaminated"]
    assert report["extra_predictions"] == []
    assert report["coverage"]["labeled_total"] == 1


def test_classification_metrics_does_not_count_ineligible_gold_as_missing() -> None:
    report = classification_metrics(
        [
            {"finding_id": "official", "label": "TP_KNOWN"},
            {"finding_id": "development", "label": "FP_CONFIRMED"},
        ],
        [
            {"finding_id": "official", "verdict": "TRUE_POSITIVE"},
            {
                "finding_id": "development",
                "verdict": "ABSTAIN",
                "evaluation_eligible": False,
            },
        ],
    )

    assert report["excluded_predictions"] == ["development"]
    assert report["excluded_labeled_cases"] == ["development"]
    assert report["coverage"]["labeled_total"] == 1
    assert report["coverage"]["missing"] == 0
