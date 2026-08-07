from __future__ import annotations

import itertools
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from vulngym_enrich.dedup import deduplicate_findings, main, semantic_match


REPO = "https://github.com/example/project"
COMMIT = "a" * 40
RULESET = "b" * 40


def finding(
    finding_id: str,
    *,
    scanner: str = "semgrep",
    scanner_version: str = "1.0.0",
    rule_id: str = "python.command-injection",
    repo_url: str = REPO,
    commit: str = COMMIT,
    file: str = "src/handler.py",
    start_line: int = 20,
    end_line: int | None = None,
    start_col: int | None = 5,
    end_col: int | None = 20,
    cwe: list[str] | None = None,
    category: str | None = None,
    snippet: str | None = "os.system(user_input)",
    fingerprint: str | None = None,
    raw_result_ref: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "finding_id": finding_id,
        "canonical_finding_id": None,
        "repo_url": repo_url,
        "commit": commit,
        "scanner": {"name": scanner, "version": scanner_version},
        "rule": {
            "id": rule_id,
            "ruleset_commit": RULESET,
            "cwe": ["CWE-78"] if cwe is None else cwe,
            "category": category,
            "severity": "ERROR",
        },
        "message": "command injection",
        "location": {
            "file": file,
            "start_line": start_line,
            "end_line": start_line if end_line is None else end_line,
            "start_col": start_col,
            "end_col": end_col,
        },
        "dataflow_trace": [],
        "snippet": snippet,
        "fingerprint": fingerprint,
        "provenance": {
            "raw_result_ref": raw_result_ref or f"raw/{scanner}.json#results/{finding_id}",
            "scan_id": "scan-day-2",
            "observed_by": [{"scanner": scanner, "rule_id": rule_id}],
        },
    }


def by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {row["finding_id"]: row for row in rows}


def test_exact_duplicates_keep_raw_observations() -> None:
    first = finding("finding-exact", raw_result_ref="raw/one.json#results/0")
    second = finding("finding-exact", raw_result_ref="raw/two.json#results/7")

    output, summary = deduplicate_findings([second, first])

    assert len(output) == 2
    assert {row["provenance"]["raw_result_ref"] for row in output} == {
        "raw/one.json#results/0",
        "raw/two.json#results/7",
    }
    assert len({row["canonical_finding_id"] for row in output}) == 1
    assert output[0]["provenance"]["observed_by"] == [
        {"scanner": "semgrep", "rule_id": "python.command-injection"}
    ]
    assert summary["statistics"] == {
        "input_findings": 2,
        "output_findings": 2,
        "exact_groups": 1,
        "exact_duplicate_observations": 1,
        "canonical_clusters": 1,
        "cross_tool_merges": 0,
        "cross_tool_clusters": 0,
        "exact_duplicate_clusters": 1,
        "singleton_clusters": 0,
        "findings_with_canonical_id": 2,
    }
    assert summary["clusters"][0]["cluster_type"] == "EXACT_DUPLICATE"


@pytest.mark.parametrize("evidence", ["rule", "fingerprint", "cwe", "category"])
def test_cross_tool_semantic_grouping_requires_supported_shared_evidence(evidence: str) -> None:
    common: dict[str, Any] = {
        "rule_id": "rule-a",
        "cwe": [],
        "category": None,
        "snippet": None,
        "fingerprint": None,
    }
    left_values = dict(common)
    right_values = dict(common)
    if evidence != "rule":
        right_values["rule_id"] = "rule-b"
    if evidence == "fingerprint":
        left_values["fingerprint"] = right_values["fingerprint"] = "snippet-sha256"
    elif evidence == "cwe":
        left_values["cwe"] = right_values["cwe"] = ["CWE-79"]
    elif evidence == "category":
        left_values["category"] = right_values["category"] = "injection"

    semgrep = finding("semgrep-result", scanner="semgrep", start_line=30, **left_values)
    other = finding("other-result", scanner="other", start_line=32, **right_values)
    output, summary = deduplicate_findings([semgrep, other], line_tolerance=2)

    rows = by_id(output)
    assert rows["semgrep-result"]["canonical_finding_id"] == rows["other-result"]["canonical_finding_id"]
    expected_observers = [
        {"scanner": "other", "rule_id": right_values["rule_id"]},
        {"scanner": "semgrep", "rule_id": left_values["rule_id"]},
    ]
    assert rows["semgrep-result"]["provenance"]["observed_by"] == expected_observers
    assert rows["other-result"]["provenance"]["observed_by"] == expected_observers
    assert summary["statistics"]["canonical_clusters"] == 1
    assert summary["statistics"]["cross_tool_merges"] == 1
    assert summary["clusters"][0]["cluster_type"] == "CROSS_TOOL_SEMANTIC"


def test_same_line_different_cwe_does_not_merge_even_with_shared_rule() -> None:
    semgrep = finding("command", scanner="semgrep", cwe=["CWE-78"], snippet=None)
    other = finding("xss", scanner="other", cwe=["CWE-79"], snippet=None)

    assert not semantic_match(semgrep, other, line_tolerance=0)
    output, summary = deduplicate_findings([semgrep, other], line_tolerance=0)

    assert len({row["canonical_finding_id"] for row in output}) == 2
    assert summary["statistics"]["canonical_clusters"] == 2


def test_same_line_different_sink_does_not_merge() -> None:
    first_sink = finding(
        "first-sink",
        scanner="semgrep",
        start_col=5,
        end_col=15,
        snippet="os.system(first)",
    )
    second_sink = finding(
        "second-sink",
        scanner="other",
        start_col=30,
        end_col=42,
        snippet="os.system(second)",
    )

    assert not semantic_match(first_sink, second_sink, line_tolerance=0)
    output, _ = deduplicate_findings([first_sink, second_sink], line_tolerance=0)
    assert len({row["canonical_finding_id"] for row in output}) == 2


@pytest.mark.parametrize(
    "change",
    [
        {"scanner": "semgrep", "start_line": 21},
        {"repo_url": "https://github.com/example/other"},
        {"commit": "c" * 40},
        {"file": "src/other.py"},
        {"start_line": 26},
    ],
)
def test_semantic_scope_boundaries_do_not_merge(change: dict[str, Any]) -> None:
    left = finding("left", scanner="semgrep", snippet=None)
    right_values: dict[str, Any] = {"scanner": "other", "snippet": None, **change}
    right = finding("right", **right_values)

    output, _ = deduplicate_findings([left, right], line_tolerance=5)

    assert len({row["canonical_finding_id"] for row in output}) == 2


def test_clustering_is_deterministic_for_every_input_permutation() -> None:
    rows = [
        finding("sg-a", scanner="semgrep", start_line=10, raw_result_ref="raw/sg-a"),
        finding("other-a", scanner="other", start_line=11, raw_result_ref="raw/other-a"),
        finding(
            "sg-b",
            scanner="semgrep",
            rule_id="python.xss",
            cwe=["CWE-79"],
            snippet="render(user_input)",
            start_line=80,
            raw_result_ref="raw/sg-b",
        ),
        finding(
            "other-b",
            scanner="other",
            rule_id="python.xss",
            cwe=["CWE-79"],
            snippet="render(user_input)",
            start_line=81,
            raw_result_ref="raw/other-b",
        ),
    ]
    expected_output, expected_summary = deduplicate_findings(rows, line_tolerance=2)

    for permutation in itertools.permutations(rows):
        output, summary = deduplicate_findings(permutation, line_tolerance=2)
        assert output == expected_output
        assert summary == expected_summary


def test_complete_link_clustering_never_creates_a_tolerance_chain() -> None:
    rows = [
        finding("line-10", scanner="semgrep", start_line=10, snippet=None, cwe=[]),
        finding("line-12", scanner="other", start_line=12, snippet=None, cwe=[]),
        finding("line-14", scanner="semgrep", start_line=14, snippet=None, cwe=[]),
    ]

    output, summary = deduplicate_findings(rows, line_tolerance=2)

    assert summary["statistics"]["canonical_clusters"] == 2
    cluster_ids = {row["canonical_finding_id"] for row in output}
    assert len(cluster_ids) == 2
    for cluster in summary["clusters"]:
        assert cluster["end_line"] - cluster["start_line"] <= 2


def test_dedup_does_not_mutate_input() -> None:
    rows = [finding("left", scanner="semgrep"), finding("right", scanner="other")]
    original = deepcopy(rows)

    deduplicate_findings(rows)

    assert rows == original


def test_cli_reads_and_writes_jsonl_with_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    input_path = tmp_path / "normalized.jsonl"
    output_path = tmp_path / "deduplicated.jsonl"
    summary_path = tmp_path / "summary.json"
    rows = [finding("semgrep", scanner="semgrep"), finding("other", scanner="other")]
    input_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    assert (
        main(
            [
                "--input",
                str(input_path),
                "--output",
                str(output_path),
                "--summary",
                str(summary_path),
                "--line-tolerance",
                "0",
            ]
        )
        == 0
    )

    written = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    printed = json.loads(capsys.readouterr().out)
    assert len(written) == 2
    assert len({row["canonical_finding_id"] for row in written}) == 1
    assert summary["statistics"]["output_findings"] == 2
    assert printed == summary["statistics"]


def test_rejects_conflicting_reuse_of_finding_id() -> None:
    rows = [finding("duplicate-id", start_line=10), finding("duplicate-id", start_line=11)]

    with pytest.raises(ValueError, match="conflicting observations"):
        deduplicate_findings(rows)


def test_rejects_negative_tolerance() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        deduplicate_findings([], line_tolerance=-1)
