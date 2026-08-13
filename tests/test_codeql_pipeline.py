from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vulngym_enrich.codeql_pipeline import (
    build_blind_verifier_input,
    build_candidate_review_queue,
    postprocess,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_postprocess_marks_missing_jobs_as_partial(tmp_path: Path) -> None:
    commit = "a" * 40
    repo_url = "https://github.com/example/project"
    scan_id = "codeql-test"
    job = {
        "job_id": "job-one",
        "repo_url": repo_url,
        "repo_slug": "example__project",
        "commit": commit,
        "language": "python",
        "routing_reason": "test",
        "priority": 0,
    }
    second_job = {
        **job,
        "job_id": "job-two",
        "language": "javascript-typescript",
    }
    plan = {
        "scan_id": scan_id,
        "profile_sha256": "1" * 64,
        "job_count": 2,
        "jobs": [job, second_job],
    }
    plan_path = tmp_path / "plan.json"
    entries_path = tmp_path / "entries.jsonl"
    _write_json(plan_path, plan)
    entries_path.write_text("", encoding="utf-8")

    job_dir = (
        tmp_path
        / "scans"
        / "example__project"
        / commit
        / "codeql"
        / "python"
    )
    attempt_dir = job_dir / "attempts" / "0001"
    raw_path = attempt_dir / "raw.sarif"
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "semanticVersion": "2.25.5",
                        "rules": [{"id": "py/test", "properties": {"tags": ["CWE-79"]}}],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/test",
                        "level": "warning",
                        "message": {"text": "test finding"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.py"},
                                    "region": {"startLine": 7, "snippet": {"text": "sink(x)"}},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    _write_json(raw_path, sarif)
    attempt = {
        "scan_id": scan_id,
        "attempt": 1,
        "status": "SUCCESS",
        "repo_url": repo_url,
        "commit": commit,
        "language": "python",
        "source_root": str(tmp_path / "source"),
        "profile_sha256": "1" * 64,
        "tool": {"version": "2.25.5"},
        "query_pack": {"name": "codeql/python-queries", "version": "1.8.3"},
        "query_suite": "security-extended",
        "result_summary": {"findings": 1},
        "checksums": {"raw.sarif": _sha256(raw_path)},
    }
    _write_json(attempt_dir / "status.json", attempt)
    _write_json(
        job_dir / "status.json",
        {
            "scan_id": scan_id,
            "repo_url": repo_url,
            "commit": commit,
            "language": "python",
            "status": "SUCCESS",
            "attempt_status": "attempts/0001/status.json",
        },
    )

    summary = postprocess(
        project_root=tmp_path,
        plan_path=plan_path,
        scan_root=tmp_path / "scans",
        entries_path=entries_path,
        output_directory=tmp_path / "output",
    )

    assert summary["complete"] is False
    assert summary["coverage"]["status_counts"] == {"PENDING": 1, "SUCCESS": 1}
    assert summary["normalized"]["findings"] == 1
    assert summary["canonical_matches"]["counts_by_tier"]["UNMATCHED"] == 1
    assert (tmp_path / "output" / "summary.json").exists()


def test_postprocess_rejects_changed_sarif(tmp_path: Path) -> None:
    commit = "b" * 40
    repo_url = "https://github.com/example/project"
    job = {
        "job_id": "job-one",
        "repo_url": repo_url,
        "repo_slug": "example__project",
        "commit": commit,
        "language": "go",
        "routing_reason": "test",
        "priority": 0,
    }
    plan_path = tmp_path / "plan.json"
    entries_path = tmp_path / "entries.jsonl"
    _write_json(
        plan_path,
        {"scan_id": "scan", "profile_sha256": "2" * 64, "job_count": 1, "jobs": [job]},
    )
    entries_path.write_text("", encoding="utf-8")
    job_dir = tmp_path / "scans" / "example__project" / commit / "codeql" / "go"
    attempt_dir = job_dir / "attempts" / "0001"
    raw_path = attempt_dir / "raw.sarif"
    _write_json(raw_path, {"runs": []})
    _write_json(
        attempt_dir / "status.json",
        {
            "scan_id": "scan",
            "status": "SUCCESS",
            "repo_url": repo_url,
            "commit": commit,
            "language": "go",
            "profile_sha256": "2" * 64,
            "checksums": {"raw.sarif": "0" * 64},
        },
    )
    _write_json(
        job_dir / "status.json",
        {
            "scan_id": "scan",
            "status": "SUCCESS",
            "repo_url": repo_url,
            "commit": commit,
            "language": "go",
            "attempt_status": "attempts/0001/status.json",
        },
    )

    try:
        postprocess(
            project_root=tmp_path,
            plan_path=plan_path,
            scan_root=tmp_path / "scans",
            entries_path=entries_path,
            output_directory=tmp_path / "output",
        )
    except ValueError as exc:
        assert "checksum mismatch" in str(exc)
    else:
        raise AssertionError("changed SARIF was accepted")


def test_candidate_queue_marks_codeql_only_location() -> None:
    finding = {
        "canonical_finding_id": "codeql-one",
        "finding_id": "codeql-one-observation",
        "repo_url": "https://github.com/example/project",
        "commit": "c" * 40,
        "location": {"file": "src/app.js", "start_line": 20, "end_line": 20},
        "rule": {"id": "js/example"},
        "scanner": {"name": "codeql", "version": "2.25.5"},
        "message": "example",
        "dataflow_trace": [],
        "snippet": "sink(value)",
        "fingerprint": "fingerprint",
        "provenance": {"raw_result_ref": "raw.sarif#result/0"},
    }
    match = {
        "canonical_finding_id": "codeql-one",
        "match_tier": "CANDIDATE_REVIEW",
        "matches": [{"entry_id": "entry-one"}],
    }

    queue, summary = build_candidate_review_queue(
        [finding], [match], semgrep_findings=[], semgrep_matches=[]
    )

    assert queue[0]["novelty_vs_semgrep"] == "CODEQL_ONLY_LOCATION"
    assert summary["counts_by_novelty_vs_semgrep"] == {"CODEQL_ONLY_LOCATION": 1}

    blind = build_blind_verifier_input(queue)
    assert blind[0]["finding_id"] == "codeql-one"
    assert "vulngym_matches" not in blind[0]
    assert "match_tier" not in blind[0]
    assert "novelty_vs_semgrep" not in blind[0]


def test_postprocess_requires_every_query_lane_for_complete_coverage(
    tmp_path: Path,
) -> None:
    commit = "d" * 40
    repo_url = "https://github.com/openclaw/openclaw"
    scan_id = "codeql-lanes"
    profile_sha256 = "1" * 64
    entries_path = tmp_path / "entries.jsonl"
    entries_path.write_text("", encoding="utf-8")
    required_lanes = ["fast", "heavy-standard", "extreme-command-injection"]
    plans: dict[str, Path] = {}

    lane_inputs = (
        ("fast", "a" * 64, "3" * 64, 44),
        ("heavy-standard", "b" * 64, "4" * 64, 55),
        ("extreme-command-injection", "c" * 64, "8" * 64, 5),
    )
    for lane, inventory, suite_sha256, query_count in lane_inputs:
        selection = {
            "selection_id": "openclaw-lanes-v2",
            "config_sha256": "2" * 64,
            "language": "javascript-typescript",
            "lane": lane,
            "suite_sha256": suite_sha256,
            "query_count": query_count,
            "inventory_sha256": inventory,
            "base_query_count": 104,
            "base_inventory_sha256": "5" * 64,
            "required_lanes": required_lanes,
        }
        job = {
            "job_id": f"{lane}-job",
            "base_job_id": "base-job",
            "repo_url": repo_url,
            "repo_slug": "openclaw__openclaw",
            "commit": commit,
            "language": "javascript-typescript",
            "routing_reason": "test",
            "priority": 0,
            "query_lane": lane,
            "query_inventory_sha256": inventory,
        }
        plan = {
            "scan_id": scan_id,
            "profile_sha256": profile_sha256,
            "manifest_sha256": "6" * 64,
            "entries_sha256": "7" * 64,
            "query_selection": selection,
            "job_count": 1,
            "jobs": [job],
        }
        plan_path = tmp_path / f"{lane}-plan.json"
        _write_json(plan_path, plan)
        plans[lane] = plan_path

        job_dir = (
            tmp_path
            / "scans"
            / "openclaw__openclaw"
            / commit
            / "codeql"
            / "javascript-typescript"
            / "lanes"
            / lane
        )
        attempt_dir = job_dir / "attempts" / "0001"
        raw_path = attempt_dir / "raw.sarif"
        _write_json(raw_path, {"version": "2.1.0", "runs": []})
        _write_json(
            attempt_dir / "status.json",
            {
                "scan_id": scan_id,
                "attempt": 1,
                "status": "SUCCESS",
                "repo_url": repo_url,
                "commit": commit,
                "language": "javascript-typescript",
                "source_root": str(tmp_path / "source"),
                "profile_sha256": profile_sha256,
                "query_selection": selection,
                "tool": {"version": "2.25.5"},
                "query_pack": {
                    "name": "codeql/javascript-queries",
                    "version": "2.3.10",
                },
                "query_suite": "security-extended",
                "result_summary": {"findings": 0},
                "checksums": {"raw.sarif": _sha256(raw_path)},
            },
        )
        _write_json(
            job_dir / "status.json",
            {
                "scan_id": scan_id,
                "repo_url": repo_url,
                "commit": commit,
                "language": "javascript-typescript",
                "query_lane": lane,
                "status": "SUCCESS",
                "attempt_status": "attempts/0001/status.json",
            },
        )

    fast_only = postprocess(
        project_root=tmp_path,
        plan_path=plans["fast"],
        scan_root=tmp_path / "scans",
        entries_path=entries_path,
        output_directory=tmp_path / "fast-output",
    )
    assert fast_only["coverage"]["execution_complete"] is True
    assert fast_only["coverage"]["query_coverage_complete"] is False
    assert fast_only["complete"] is False
    assert "QUERY_LANE_PARTIAL" in fast_only["warning"]

    without_extreme = postprocess(
        project_root=tmp_path,
        plan_path=plans["fast"],
        additional_plan_paths=[plans["heavy-standard"]],
        scan_root=tmp_path / "scans",
        entries_path=entries_path,
        output_directory=tmp_path / "without-extreme-output",
    )
    assert without_extreme["coverage"]["execution_complete"] is True
    assert without_extreme["coverage"]["query_coverage_complete"] is False
    assert without_extreme["complete"] is False
    assert "QUERY_LANE_PARTIAL" in without_extreme["warning"]

    combined = postprocess(
        project_root=tmp_path,
        plan_path=plans["fast"],
        additional_plan_paths=[
            plans["heavy-standard"],
            plans["extreme-command-injection"],
        ],
        scan_root=tmp_path / "scans",
        entries_path=entries_path,
        output_directory=tmp_path / "combined-output",
    )
    assert combined["coverage"]["execution_complete"] is True
    assert combined["coverage"]["query_coverage_complete"] is True
    assert combined["coverage"]["query_lanes"]["base_job_count"] == 1
    assert combined["complete"] is True
    assert combined["warning"] is None
