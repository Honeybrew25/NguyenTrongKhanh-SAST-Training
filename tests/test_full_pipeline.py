from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vulngym_enrich.full_pipeline import (
    _scanner_errors,
    discover_scan_jobs,
    run_full_pipeline,
    validate_scan_coverage,
)


REPO = "https://github.com/example/project"
COMMIT = "a" * 40
RULESET = "b" * 40
SCANNER_VERSION = "1.0.0"


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pipeline_fixture(tmp_path: Path) -> tuple[dict, dict[str, Path]]:
    project = tmp_path / "project"
    manifest_path = project / "artifacts" / "manifests" / "manifest.json"
    scanner_lock_path = project / "config" / "scanners.lock.json"
    scan_profile_path = project / "config" / "scan-profile.json"
    entries_path = project / "benchmark" / "entries.jsonl"
    scan_root = project / "artifacts" / "scans" / "full-scan"
    source_root = project / "worktree"
    source = source_root / "src" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "value = request.args['x']\nvalue = str(value)\nos.system(value)\n",
        encoding="utf-8",
    )

    manifest = {"snapshots": [{"repo_url": REPO, "commit": COMMIT}]}
    _write_json(manifest_path, manifest)
    _write_json(scanner_lock_path, {"schema_version": 1})
    _write_json(
        scan_profile_path,
        {"schema_version": 1, "rules": {"root": "rules/semgrep-rules"}},
    )
    entry = {
        "entry_id": "entry-00001",
        "report_id": "GHSA-AAAA-BBBB-CCCC",
        "repo_url": REPO,
        "commit": COMMIT,
        "entry_point": {"file": "src/app.py", "line": 1},
        "critical_operation": {"file": "src/app.py", "line": 3},
        "verify": 1,
    }
    entries_path.parent.mkdir(parents=True, exist_ok=True)
    entries_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    input_sources = {
        "manifest": manifest_path,
        "scanner_lock": scanner_lock_path,
        "scan_profile": scan_profile_path,
    }
    run_inputs = {
        name: {"path": str(path), "sha256": _sha256(path)}
        for name, path in input_sources.items()
    }
    executable_hashes = {"semgrep": "c" * 64}
    _write_json(
        scan_root / "run.json",
        {
            "schema_version": 1,
            "scan_id": scan_root.name,
            "inputs": run_inputs,
            "ruleset_commit": RULESET,
            "scanner_pins": {
                scanner: {
                    "version": SCANNER_VERSION,
                    "executable_sha256": checksum,
                }
                for scanner, checksum in executable_hashes.items()
            },
            "execution": {"job_timeout_seconds": 60, "rule_config_override": []},
        },
    )

    raw = {
        "version": SCANNER_VERSION,
        "results": [
            {
                "check_id": "python.lang.security.command-injection",
                "path": "src/app.py",
                "start": {"line": 3, "col": 1},
                "end": {"line": 3, "col": 16},
                "extra": {
                    "message": "attacker input reaches a process sink",
                    "severity": "ERROR",
                    "lines": "os.system(value)",
                    "metadata": {
                        "cwe": ["CWE-78: OS Command Injection"],
                        "category": "security",
                    },
                },
            }
        ],
        "errors": [],
        "paths": {"scanned": ["src/app.py"]},
    }
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "scanner",
                        "semanticVersion": SCANNER_VERSION,
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
                                    "region": {
                                        "startLine": 3,
                                        "endLine": 3,
                                        "startColumn": 1,
                                        "endColumn": 16,
                                    },
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
                                                        "region": {"startLine": 1},
                                                    },
                                                }
                                            },
                                            {
                                                "location": {
                                                    "message": {"text": "sink"},
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "src/app.py"},
                                                        "region": {"startLine": 3},
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

    status_paths: dict[str, Path] = {}
    frozen_names = {
        "manifest": "manifest.json",
        "scanner_lock": "scanners.lock.json",
        "scan_profile": "scan-profile.json",
    }
    for scanner in ("semgrep",):
        scanner_root = scan_root / "example__project" / COMMIT / scanner
        attempt = scanner_root / "attempts" / "0001"
        _write_json(attempt / "raw.json", raw)
        _write_json(attempt / "raw.sarif", sarif)
        frozen_inputs = {}
        for name, source_path in input_sources.items():
            frozen_path = attempt / "inputs" / frozen_names[name]
            frozen_path.parent.mkdir(parents=True, exist_ok=True)
            frozen_path.write_bytes(source_path.read_bytes())
            frozen_inputs[name] = {
                **run_inputs[name],
                "frozen_path": f"inputs/{frozen_names[name]}",
            }
        status = {
            "schema_version": 1,
            "scan_id": scan_root.name,
            "attempt": 1,
            "repo_url": REPO,
            "commit": COMMIT,
            "scanner": {
                "name": scanner,
                "observed_version": SCANNER_VERSION,
                "executable_sha256": executable_hashes[scanner],
            },
            "ruleset_commit": RULESET,
            "status": "SUCCESS",
            "exit_code": 0,
            "error": None,
            "cwd": str(source_root),
            "inputs": frozen_inputs,
            "outputs": {"json": "raw.json", "sarif": "raw.sarif"},
            "checksums": {
                "raw.json": _sha256(attempt / "raw.json"),
                "raw.sarif": _sha256(attempt / "raw.sarif"),
            },
        }
        status_path = attempt / "status.json"
        _write_json(status_path, status)
        status_paths[scanner] = status_path
        _write_json(
            scanner_root / "status.json",
            {
                "schema_version": 1,
                "scan_id": scan_root.name,
                "repo_url": REPO,
                "commit": COMMIT,
                "scanner": scanner,
                "status": "SUCCESS",
                "attempt_status": "attempts/0001/status.json",
            },
        )

    return (
        {
            "scan_root": scan_root,
            "manifest_path": manifest_path,
            "entries_path": entries_path,
            "output_directory": project / "artifacts" / "full-pipeline",
            "scanners": ("semgrep",),
        },
        status_paths,
    )


def _job(
    scan_root: Path,
    scanner: str,
    status: str = "SUCCESS",
    *,
    pointer_schema_version: int = 1,
    scheduling: dict | None = None,
) -> None:
    scanner_root = scan_root / "example__project" / COMMIT / scanner
    attempt = {
        "schema_version": 1,
        "scan_id": scan_root.name,
        "repo_url": REPO,
        "commit": COMMIT,
        "scanner": {"name": scanner},
        "status": status,
    }
    pointer = {
        "schema_version": pointer_schema_version,
        "scan_id": scan_root.name,
        "repo_url": REPO,
        "commit": COMMIT,
        "scanner": scanner,
        "status": status,
        "attempt_status": "attempts/0001/status.json",
    }
    if scheduling is not None:
        pointer["scheduling"] = scheduling
    _write_json(scanner_root / "attempts" / "0001" / "status.json", attempt)
    _write_json(scanner_root / "status.json", pointer)


def _timeout_attempts(scan_root: Path, scanner: str, count: int) -> None:
    scanner_root = scan_root / "example__project" / COMMIT / scanner
    for number in range(2, count + 2):
        _write_json(
            scanner_root / "attempts" / f"{number:04d}" / "status.json",
            {
                "schema_version": 1,
                "scan_id": scan_root.name,
                "attempt": number,
                "repo_url": REPO,
                "commit": COMMIT,
                "scanner": {"name": scanner},
                "status": "TIMEOUT",
            },
        )


def _write_retry_policy(scan_root: Path) -> str:
    policy_path = scan_root / "retry-policy.json"
    _write_json(
        policy_path,
        {
            "schema_version": 1,
            "scan_id": scan_root.name,
            "policy": "bounded-timeout-retry",
            "max_completed_timeout_attempts": 2,
        },
    )
    return _sha256(policy_path)


def _quarantine_scheduling(policy_sha256: str) -> dict:
    return {
        "state": "QUARANTINED",
        "reason": "timeout_budget_exhausted",
        "matching_timeout_attempts": 2,
        "limit": 2,
        "policy_sha256": policy_sha256,
        "decided_at": "2026-08-05T02:30:00+00:00",
    }


def test_discovers_attempts_and_requires_complete_semgrep_matrix(tmp_path: Path) -> None:
    scan_root = tmp_path / "full-scan"
    _job(scan_root, "semgrep")
    _job(scan_root, "other")
    jobs = discover_scan_jobs(scan_root)

    coverage = validate_scan_coverage(
        jobs,
        {"snapshots": [{"repo_url": REPO, "commit": COMMIT}]},
        scanners=["semgrep"],
    )

    assert len(jobs) == 2
    assert coverage == {
        "snapshots_expected": 1,
        "scanners_expected": ["semgrep"],
        "jobs_expected": 1,
        "jobs_accounted": 1,
        "status_counts": {"SUCCESS": 1},
        "missing_jobs": [],
        "unexpected_jobs": [],
        "ignored_nonselected_jobs": 1,
        "invalid_status_jobs": [],
        "blocking_statuses": {},
        "complete": True,
    }


def test_running_and_missing_jobs_keep_coverage_incomplete(tmp_path: Path) -> None:
    scan_root = tmp_path / "full-scan"
    _job(scan_root, "semgrep", status="RUNNING")

    coverage = validate_scan_coverage(
        discover_scan_jobs(scan_root),
        {"snapshots": [{"repo_url": REPO, "commit": COMMIT}]},
        scanners=["semgrep"],
    )

    assert coverage["complete"] is False
    assert coverage["jobs_accounted"] == 1
    assert coverage["blocking_statuses"] == {"RUNNING": 1}
    assert coverage["missing_jobs"] == []


def test_mixed_pointer_schemas_surface_quarantine_as_coverage_blocker(
    tmp_path: Path,
) -> None:
    scan_root = tmp_path / "full-scan"
    scheduling = _quarantine_scheduling(_write_retry_policy(scan_root))
    _job(
        scan_root,
        "semgrep",
        status="TIMEOUT",
        pointer_schema_version=2,
        scheduling=scheduling,
    )
    _timeout_attempts(scan_root, "semgrep", 1)

    jobs = discover_scan_jobs(scan_root)
    by_scanner = {job["scanner"]: job for job in jobs}

    assert by_scanner["semgrep"]["pointer_schema_version"] == 2
    assert by_scanner["semgrep"]["scheduling"] == scheduling
    assert by_scanner["semgrep"]["scheduling_state"] == "QUARANTINED"
    assert (
        by_scanner["semgrep"]["scheduling_reason"]
        == "timeout_budget_exhausted"
    )

    coverage = validate_scan_coverage(
        jobs,
        {"snapshots": [{"repo_url": REPO, "commit": COMMIT}]},
        scanners=["semgrep"],
    )

    assert coverage["status_counts"] == {"TIMEOUT": 1}
    assert coverage["blocking_statuses"] == {"QUARANTINED_TIMEOUT": 1}
    assert coverage["complete"] is False
    assert coverage["invalid_status_jobs"] == [
        {
            "repo_url": REPO,
            "commit": COMMIT,
            "scanner": "semgrep",
            "status": "TIMEOUT",
            "error_type": None,
            "scheduling_state": "QUARANTINED",
            "scheduling_reason": "timeout_budget_exhausted",
            "blocking_status": "QUARANTINED_TIMEOUT",
        }
    ]


def test_quarantined_orphan_preserves_interrupted_latest_attempt(
    tmp_path: Path,
) -> None:
    scan_root = tmp_path / "full-scan"
    scanner_root = scan_root / "example__project" / COMMIT / "semgrep"
    policy_sha256 = _write_retry_policy(scan_root)
    for number in (1, 2):
        _write_json(
            scanner_root / "attempts" / f"{number:04d}" / "status.json",
            {
                "schema_version": 1,
                "scan_id": scan_root.name,
                "attempt": number,
                "repo_url": REPO,
                "commit": COMMIT,
                "scanner": {"name": "semgrep"},
                "status": "TIMEOUT",
            },
        )
    interrupted = {
        "schema_version": 1,
        "scan_id": scan_root.name,
        "attempt": 3,
        "repo_url": REPO,
        "commit": COMMIT,
        "scanner": {"name": "semgrep"},
        "status": "INTERRUPTED",
        "error": {"type": "OrphanedAttempt"},
    }
    _write_json(scanner_root / "attempts" / "0003" / "status.json", interrupted)
    _write_json(
        scanner_root / "status.json",
        {
            "schema_version": 2,
            "scan_id": scan_root.name,
            "repo_url": REPO,
            "commit": COMMIT,
            "scanner": "semgrep",
            "latest_attempt": 3,
            "status": "INTERRUPTED",
            "attempt_status": "attempts/0003/status.json",
            "scheduling": _quarantine_scheduling(policy_sha256),
        },
    )

    jobs = discover_scan_jobs(scan_root)
    assert jobs[0]["status"] == "INTERRUPTED"
    coverage = validate_scan_coverage(
        jobs,
        {"snapshots": [{"repo_url": REPO, "commit": COMMIT}]},
        scanners=["semgrep"],
    )
    assert coverage["blocking_statuses"] == {"QUARANTINED_TIMEOUT": 1}
    assert coverage["complete"] is False


@pytest.mark.parametrize("sidecar_exists", [False, True])
def test_quarantine_requires_matching_retry_policy_sidecar(
    tmp_path: Path, sidecar_exists: bool
) -> None:
    scan_root = tmp_path / "full-scan"
    if sidecar_exists:
        _write_retry_policy(scan_root)
    _job(
        scan_root,
        "semgrep",
        status="TIMEOUT",
        pointer_schema_version=2,
        scheduling=_quarantine_scheduling("0" * 64),
    )
    _timeout_attempts(scan_root, "semgrep", 1)

    message = "SHA-256 mismatch" if sidecar_exists else "does not exist"
    with pytest.raises(ValueError, match=message):
        discover_scan_jobs(scan_root)


def test_pointer_schema_v2_rejects_invalid_quarantine_scheduling(
    tmp_path: Path,
) -> None:
    scan_root = tmp_path / "full-scan"
    scheduling = _quarantine_scheduling(_write_retry_policy(scan_root))
    scheduling["matching_timeout_attempts"] = 1
    _job(
        scan_root,
        "semgrep",
        status="TIMEOUT",
        pointer_schema_version=2,
        scheduling=scheduling,
    )

    with pytest.raises(ValueError, match="greater than or equal"):
        discover_scan_jobs(scan_root)


def test_quarantine_limit_must_match_retry_policy_sidecar(tmp_path: Path) -> None:
    scan_root = tmp_path / "full-scan"
    policy_sha256 = _write_retry_policy(scan_root)
    scheduling = _quarantine_scheduling(policy_sha256)
    scheduling["limit"] = 1
    _job(
        scan_root,
        "semgrep",
        status="TIMEOUT",
        pointer_schema_version=2,
        scheduling=scheduling,
    )
    _timeout_attempts(scan_root, "semgrep", 1)

    with pytest.raises(ValueError, match="does not match retry policy sidecar"):
        discover_scan_jobs(scan_root)


@pytest.mark.parametrize(
    ("snapshot", "message"),
    [
        ("not-an-object", r"manifest\.snapshots\[0\] must be an object"),
        ({"commit": COMMIT}, r"manifest\.snapshots\[0\]\.repo_url must be a non-empty string"),
        ({"repo_url": REPO, "commit": "  "}, r"manifest\.snapshots\[0\]\.commit must be a non-empty string"),
    ],
)
def test_manifest_snapshot_identity_is_validated(snapshot: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        validate_scan_coverage([], {"snapshots": [snapshot]}, scanners=["semgrep"])


def test_nonselected_scanner_is_ignored_and_invalid_skip_is_blocked(tmp_path: Path) -> None:
    scan_root = tmp_path / "full-scan"
    _job(scan_root, "semgrep", status="SKIPPED")
    _job(scan_root, "other", status="SUCCESS")

    coverage = validate_scan_coverage(
        discover_scan_jobs(scan_root),
        {"snapshots": [{"repo_url": REPO, "commit": COMMIT}]},
        scanners=["semgrep"],
    )

    assert coverage["ignored_nonselected_jobs"] == 1
    assert coverage["unexpected_jobs"] == []
    assert coverage["blocking_statuses"] == {"SKIPPED": 1}
    assert coverage["invalid_status_jobs"][0]["error_type"] is None
    assert coverage["complete"] is False


def test_attempt_pointer_cannot_escape_scanner_directory(tmp_path: Path) -> None:
    scan_root = tmp_path / "full-scan"
    pointer = scan_root / "example__project" / COMMIT / "semgrep" / "status.json"
    _write_json(
        pointer,
        {
            "schema_version": 1,
            "attempt_status": "../../../../../outside.json",
            "scan_id": scan_root.name,
            "repo_url": REPO,
            "commit": COMMIT,
            "scanner": "semgrep",
            "status": "SUCCESS",
        },
    )

    with pytest.raises(ValueError, match="escapes its scanner directory"):
        discover_scan_jobs(scan_root)


def test_partial_file_is_unresolved_when_alternate_engine_has_file_error(
    tmp_path: Path,
) -> None:
    jobs = []
    for scanner, errors in (
        (
            "semgrep",
            [{"type": ["PartialParsing", []], "path": "src/app.py", "message": "parse"}],
        ),
        (
            "other",
            [{"type": "Timeout", "path": "src/app.py", "message": "rule timeout"}],
        ),
    ):
        attempt = tmp_path / scanner / "attempts" / "0001"
        _write_json(
            attempt / "raw.json",
            {"results": [], "errors": errors, "paths": {"scanned": ["src/app.py"]}},
        )
        jobs.append(
            {
                "repo_url": REPO,
                "commit": COMMIT,
                "scanner": scanner,
                "status": "SUCCESS",
                "attempt_status_path": attempt / "status.json",
                "attempt": {"outputs": {"json": "raw.json"}},
            }
        )

    observations, summary = _scanner_errors(jobs)

    partial = next(row for row in observations if row["scanner"] == "semgrep")
    assert partial["alternate_engines"] == [
        {"scanner": "other", "file_status": "FILE_ERROR:Timeout"}
    ]
    assert summary["partial_parsing_engine_files"] == 1
    assert summary["partial_parsing_files"] == 1
    assert summary["unresolved_partial_files"] == 1


def test_run_full_pipeline_end_to_end_with_frozen_provenance(tmp_path: Path) -> None:
    arguments, _ = _pipeline_fixture(tmp_path)

    summary = run_full_pipeline(**arguments)

    assert summary["coverage"]["complete"] is True
    assert summary["normalization"]["findings"] == 1
    assert summary["normalization"]["with_dataflow_trace"] == 1
    assert summary["deduplication"]["canonical_clusters"] == 1
    assert summary["deduplication"]["cross_tool_clusters"] == 0
    assert summary["matching"]["counts_by_tier"] == {
        "STRICT_SOURCE_SINK": 1,
        "STRONG_SOURCE_SINK": 0,
        "CANDIDATE_REVIEW": 0,
        "UNMATCHED": 0,
    }
    provenance = summary["frozen_provenance"]
    assert provenance["scan_id"] == arguments["scan_root"].name
    assert provenance["inputs"]["manifest"]["sha256"] == _sha256(
        arguments["manifest_path"]
    )
    assert provenance["matching_entries"]["sha256"] == _sha256(
        arguments["entries_path"]
    )
    matches = [
        json.loads(line)
        for line in (arguments["output_directory"] / "canonical-security-matches.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert len(matches) == 1
    assert matches[0]["match_tier"] == "STRICT_SOURCE_SINK"


def test_run_full_pipeline_blocks_heterogeneous_attempt_provenance(tmp_path: Path) -> None:
    arguments, status_paths = _pipeline_fixture(tmp_path)
    status = json.loads(status_paths["semgrep"].read_text(encoding="utf-8"))
    status["inputs"]["scan_profile"]["sha256"] = "e" * 64
    _write_json(status_paths["semgrep"], status)

    with pytest.raises(
        ValueError,
        match="attempt provenance mismatch for scan_profile.sha256",
    ):
        run_full_pipeline(**arguments)
