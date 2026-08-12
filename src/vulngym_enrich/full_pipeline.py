from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

from .audit import load_jsonl
from .candidate_matcher import aggregate_canonical_matches, match_candidates
from .dedup import DEFAULT_LINE_TOLERANCE, deduplicate_findings
from .normalizer import finding_statistics, main as normalize_main, write_jsonl
from .scanner import DEFAULT_SCANNERS, SUPPORTED_SCANNERS


_FROZEN_INPUT_NAMES = ("manifest", "scanner_lock", "scan_profile")
_POINTER_SCHEMA_VERSIONS = (1, 2)
_QUARANTINE_SCHEDULING_FIELDS = frozenset(
    {
        "state",
        "reason",
        "matching_timeout_attempts",
        "limit",
        "policy_sha256",
        "decided_at",
    }
)


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"{label} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validated_manifest_snapshots(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    snapshots = manifest.get("snapshots")
    if not isinstance(snapshots, list):
        raise ValueError("manifest.snapshots must be a list")
    for index, snapshot in enumerate(snapshots):
        if not isinstance(snapshot, dict):
            raise ValueError(f"manifest.snapshots[{index}] must be an object")
        for field in ("repo_url", "commit"):
            value = snapshot.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"manifest.snapshots[{index}].{field} must be a non-empty string"
                )
    return snapshots


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _required_sha256(value: Any, label: str) -> str:
    text = _required_string(value, label).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"{label} must be a 64-character SHA-256")
    return text


def _contained_path(parent: Path, relative: str, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label} must be a non-empty relative path")
    candidate = (parent / relative).resolve()
    try:
        candidate.relative_to(parent.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} escapes its scanner directory: {relative}") from exc
    return candidate


def _required_iso_datetime(value: Any, label: str) -> str:
    text = _required_string(value, label)
    normalized = f"{text[:-1]}+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 datetime") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone offset")
    return text


def _validated_pointer_scheduling(
    pointer: dict[str, Any], pointer_path: Path, scan_root: Path
) -> tuple[int, dict[str, Any] | None]:
    schema_version = pointer.get("schema_version")
    if type(schema_version) is not int or schema_version not in _POINTER_SCHEMA_VERSIONS:
        raise ValueError(
            f"scanner status pointer.schema_version must be one of "
            f"{list(_POINTER_SCHEMA_VERSIONS)}: {pointer_path}"
        )

    if schema_version == 1:
        if "scheduling" in pointer:
            raise ValueError(
                f"scanner status pointer schema v1 must not contain scheduling: "
                f"{pointer_path}"
            )
        return schema_version, None

    scheduling = pointer.get("scheduling")
    if not isinstance(scheduling, dict):
        raise ValueError(
            f"scanner status pointer schema v2 scheduling must be an object: "
            f"{pointer_path}"
        )
    scheduling_fields = set(scheduling)
    if scheduling_fields != _QUARANTINE_SCHEDULING_FIELDS:
        missing = sorted(_QUARANTINE_SCHEDULING_FIELDS - scheduling_fields)
        unexpected = sorted(scheduling_fields - _QUARANTINE_SCHEDULING_FIELDS)
        raise ValueError(
            f"scanner status pointer scheduling fields are invalid: {pointer_path}: "
            f"missing={missing}, unexpected={unexpected}"
        )
    if scheduling.get("state") != "QUARANTINED":
        raise ValueError(
            f"scanner status pointer scheduling.state must be 'QUARANTINED': "
            f"{pointer_path}"
        )
    if scheduling.get("reason") != "timeout_budget_exhausted":
        raise ValueError(
            "scanner status pointer scheduling.reason must be "
            f"'timeout_budget_exhausted': {pointer_path}"
        )
    if pointer.get("status") not in {"TIMEOUT", "INTERRUPTED", "FAILED"}:
        raise ValueError(
            "quarantined scanner status pointer must preserve a blocking attempt "
            f"status (TIMEOUT, INTERRUPTED, or FAILED): "
            f"{pointer_path}"
        )

    matching_timeout_attempts = scheduling.get("matching_timeout_attempts")
    limit = scheduling.get("limit")
    if type(matching_timeout_attempts) is not int or matching_timeout_attempts < 1:
        raise ValueError(
            "scanner status pointer scheduling.matching_timeout_attempts must be "
            f"a positive integer: {pointer_path}"
        )
    if type(limit) is not int or limit < 1:
        raise ValueError(
            f"scanner status pointer scheduling.limit must be a positive integer: "
            f"{pointer_path}"
        )
    if matching_timeout_attempts < limit:
        raise ValueError(
            "scanner status pointer scheduling.matching_timeout_attempts must be "
            f"greater than or equal to scheduling.limit: {pointer_path}"
        )
    observed_timeout_attempts = 0
    for attempt_status_path in sorted(
        pointer_path.parent.glob("attempts/*/status.json")
    ):
        attempt_status = _read_object(attempt_status_path, "attempt status")
        if attempt_status.get("status") == "TIMEOUT":
            observed_timeout_attempts += 1
    if observed_timeout_attempts != matching_timeout_attempts:
        raise ValueError(
            "scanner status pointer scheduling.matching_timeout_attempts does not "
            f"match immutable TIMEOUT attempts: {pointer_path}: "
            f"{matching_timeout_attempts} != {observed_timeout_attempts}"
        )

    policy_sha256_value = scheduling.get("policy_sha256")
    policy_sha256 = _required_sha256(
        policy_sha256_value,
        "scanner status pointer scheduling.policy_sha256",
    )
    if policy_sha256_value != policy_sha256:
        raise ValueError(
            "scanner status pointer scheduling.policy_sha256 must use lowercase "
            f"hexadecimal: {pointer_path}"
        )
    _required_iso_datetime(
        scheduling.get("decided_at"),
        "scanner status pointer scheduling.decided_at",
    )

    policy_path = scan_root / "retry-policy.json"
    policy = _read_object(policy_path, "retry policy sidecar")
    if policy.get("schema_version") != 1:
        raise ValueError(
            f"retry policy sidecar.schema_version must be 1: {policy_path}"
        )
    if policy.get("scan_id") != scan_root.name:
        raise ValueError(
            f"retry policy sidecar scan_id does not match scan root: {policy_path}: "
            f"{policy.get('scan_id')!r} != {scan_root.name!r}"
        )
    if policy.get("policy") != "bounded-timeout-retry":
        raise ValueError(
            f"retry policy sidecar.policy must be 'bounded-timeout-retry': "
            f"{policy_path}"
        )
    policy_timeout_limit = policy.get("max_completed_timeout_attempts")
    if type(policy_timeout_limit) is not int or policy_timeout_limit < 1:
        raise ValueError(
            "retry policy sidecar.max_completed_timeout_attempts must be a "
            f"positive integer: {policy_path}"
        )
    if limit != policy_timeout_limit:
        raise ValueError(
            "scanner status pointer scheduling.limit does not match retry policy "
            f"sidecar: {pointer_path}: {limit} != {policy_timeout_limit}"
        )
    observed_policy_sha256 = _sha256_file(policy_path)
    if observed_policy_sha256 != policy_sha256:
        raise ValueError(
            f"retry policy sidecar SHA-256 mismatch: {policy_path}: "
            f"{observed_policy_sha256!r} != {policy_sha256!r}"
        )
    return schema_version, dict(scheduling)


def discover_scan_jobs(scan_root: Path) -> list[dict[str, Any]]:
    """Resolve each scanner pointer to its latest immutable attempt status."""

    root = scan_root.resolve()
    if not root.is_dir():
        raise ValueError(f"scan root does not exist: {root}")
    jobs: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for pointer_path in sorted(root.glob("*/*/*/status.json")):
        pointer = _read_object(pointer_path, "scanner status pointer")
        pointer_schema_version, scheduling = _validated_pointer_scheduling(
            pointer, pointer_path, root
        )
        scanner_directory = pointer_path.parent
        attempt_status_path = _contained_path(
            scanner_directory,
            pointer.get("attempt_status"),
            "attempt_status",
        )
        attempt = _read_object(attempt_status_path, "attempt status")
        scanner_value = attempt.get("scanner") or {}
        scanner = scanner_value.get("name") if isinstance(scanner_value, dict) else None
        key = (attempt.get("repo_url"), attempt.get("commit"), scanner)
        if not all(isinstance(value, str) and value for value in key):
            raise ValueError(f"attempt has an invalid job identity: {attempt_status_path}")
        if key in seen:
            raise ValueError(f"duplicate scanner job pointer: {key}")
        seen.add(key)
        expected_pointer = {
            "repo_url": attempt["repo_url"],
            "commit": attempt["commit"],
            "scanner": scanner,
            "scan_id": attempt.get("scan_id"),
            "status": attempt.get("status"),
        }
        for field, expected in expected_pointer.items():
            if pointer.get(field) != expected:
                raise ValueError(
                    f"pointer/attempt mismatch for {field}: {pointer_path}: "
                    f"{pointer.get(field)!r} != {expected!r}"
                )
        if attempt.get("scan_id") != root.name:
            raise ValueError(
                f"attempt scan_id does not match scan root: {attempt_status_path}: "
                f"{attempt.get('scan_id')!r} != {root.name!r}"
            )
        jobs.append(
            {
                **expected_pointer,
                "pointer_path": pointer_path,
                "pointer_schema_version": pointer_schema_version,
                "scheduling": scheduling,
                "scheduling_state": (
                    scheduling.get("state") if scheduling is not None else None
                ),
                "scheduling_reason": (
                    scheduling.get("reason") if scheduling is not None else None
                ),
                "attempt_status_path": attempt_status_path,
                "attempt": attempt,
            }
        )
    return jobs


def validate_scan_coverage(
    jobs: Iterable[dict[str, Any]],
    manifest: dict[str, Any],
    scanners: Sequence[str] = DEFAULT_SCANNERS,
) -> dict[str, Any]:
    if not scanners or len(set(scanners)) != len(scanners):
        raise ValueError("scanners must be a non-empty sequence without duplicates")
    unsupported = sorted(set(scanners) - set(SUPPORTED_SCANNERS))
    if unsupported:
        raise ValueError(f"unsupported scanners: {unsupported}")
    snapshots = _validated_manifest_snapshots(manifest)
    expected = {
        (snapshot["repo_url"], snapshot["commit"], scanner)
        for snapshot in snapshots
        for scanner in scanners
    }
    if len(expected) != len(snapshots) * len(scanners):
        raise ValueError("manifest contains duplicate or invalid snapshot identities")
    rows = list(jobs)
    selected_rows = [row for row in rows if row["scanner"] in scanners]
    ignored_nonselected = [row for row in rows if row["scanner"] not in scanners]
    actual = {
        (row["repo_url"], row["commit"], row["scanner"]) for row in selected_rows
    }
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    expected_rows = [
        row
        for row in selected_rows
        if (row["repo_url"], row["commit"], row["scanner"]) in expected
    ]
    counts = Counter(str(row.get("status")) for row in expected_rows)
    invalid_status_jobs = []
    for row in expected_rows:
        status = row.get("status")
        error = row.get("attempt", {}).get("error") or {}
        valid_skip = (
            status == "SKIPPED"
            and isinstance(error, dict)
            and error.get("type") == "NoApplicableRuleConfig"
        )
        if status != "SUCCESS" and not valid_skip:
            invalid_job = {
                "repo_url": row["repo_url"],
                "commit": row["commit"],
                "scanner": row["scanner"],
                "status": status,
                "error_type": error.get("type") if isinstance(error, dict) else None,
            }
            scheduling_state = row.get("scheduling_state")
            scheduling_reason = row.get("scheduling_reason")
            if scheduling_state is not None:
                invalid_job["scheduling_state"] = scheduling_state
                invalid_job["scheduling_reason"] = scheduling_reason
            if scheduling_state == "QUARANTINED":
                invalid_job["blocking_status"] = "QUARANTINED_TIMEOUT"
            invalid_status_jobs.append(invalid_job)
    blocking = dict(
        sorted(
            Counter(
                str(row.get("blocking_status", row["status"]))
                for row in invalid_status_jobs
            ).items()
        )
    )
    return {
        "snapshots_expected": len(snapshots),
        "scanners_expected": list(scanners),
        "jobs_expected": len(expected),
        "jobs_accounted": len(actual & expected),
        "status_counts": dict(sorted(counts.items())),
        "missing_jobs": [
            {"repo_url": repo, "commit": commit, "scanner": scanner}
            for repo, commit, scanner in missing
        ],
        "unexpected_jobs": [
            {"repo_url": repo, "commit": commit, "scanner": scanner}
            for repo, commit, scanner in unexpected
        ],
        "ignored_nonselected_jobs": len(ignored_nonselected),
        "invalid_status_jobs": invalid_status_jobs,
        "blocking_statuses": blocking,
        "complete": not missing and not unexpected and not invalid_status_jobs,
    }


def _selected_expected_jobs(
    jobs: Iterable[dict[str, Any]], manifest: dict[str, Any], scanners: Sequence[str]
) -> list[dict[str, Any]]:
    snapshots = _validated_manifest_snapshots(manifest)
    expected = {
        (snapshot["repo_url"], snapshot["commit"], scanner)
        for snapshot in snapshots
        for scanner in scanners
    }
    return [
        row
        for row in jobs
        if (row["repo_url"], row["commit"], row["scanner"]) in expected
    ]


def validate_batch_provenance(
    *,
    scan_root: Path,
    manifest_path: Path,
    jobs: Iterable[dict[str, Any]],
    scanners: Sequence[str],
) -> dict[str, Any]:
    """Require one immutable scanner/config provenance tuple for the selected batch."""

    root = scan_root.resolve()
    run_path = root / "run.json"
    run = _read_object(run_path, "scan run metadata")
    scan_id = _required_string(run.get("scan_id"), "scan run metadata.scan_id")
    if scan_id != root.name:
        raise ValueError(
            f"scan run metadata.scan_id does not match scan root: {scan_id!r} != {root.name!r}"
        )

    run_inputs = run.get("inputs")
    if not isinstance(run_inputs, dict):
        raise ValueError("scan run metadata.inputs must be an object")
    frozen_inputs: dict[str, dict[str, str]] = {}
    for name in _FROZEN_INPUT_NAMES:
        provenance = run_inputs.get(name)
        if not isinstance(provenance, dict):
            raise ValueError(f"scan run metadata.inputs.{name} must be an object")
        checksum = _required_sha256(
            provenance.get("sha256"), f"scan run metadata.inputs.{name}.sha256"
        )
        path = _required_string(
            provenance.get("path"), f"scan run metadata.inputs.{name}.path"
        )
        frozen_inputs[name] = {"path": path, "sha256": checksum}

    manifest_checksum = _sha256_file(manifest_path)
    if frozen_inputs["manifest"]["sha256"] != manifest_checksum:
        raise ValueError("manifest checksum does not match scan run metadata")

    ruleset_commit = _required_string(
        run.get("ruleset_commit"), "scan run metadata.ruleset_commit"
    )
    scanner_pins = run.get("scanner_pins")
    if not isinstance(scanner_pins, dict):
        raise ValueError("scan run metadata.scanner_pins must be an object")
    selected_pins: dict[str, dict[str, str]] = {}
    for scanner in scanners:
        pin = scanner_pins.get(scanner)
        if not isinstance(pin, dict):
            raise ValueError(f"scan run metadata.scanner_pins.{scanner} must be an object")
        selected_pins[scanner] = {
            "version": _required_string(
                pin.get("version"), f"scan run metadata.scanner_pins.{scanner}.version"
            ),
            "executable_sha256": _required_sha256(
                pin.get("executable_sha256"),
                f"scan run metadata.scanner_pins.{scanner}.executable_sha256",
            ),
        }

    for job in jobs:
        attempt = job.get("attempt")
        if not isinstance(attempt, dict):
            raise ValueError("selected job attempt must be an object")
        identity = f"{job['repo_url']}@{job['commit']}:{job['scanner']}"
        if attempt.get("scan_id") != scan_id:
            raise ValueError(f"attempt provenance mismatch for scan_id: {identity}")
        attempt_inputs = attempt.get("inputs")
        if not isinstance(attempt_inputs, dict):
            raise ValueError(f"attempt inputs must be an object: {identity}")
        for name in _FROZEN_INPUT_NAMES:
            provenance = attempt_inputs.get(name)
            if not isinstance(provenance, dict):
                raise ValueError(f"attempt input {name} must be an object: {identity}")
            checksum = provenance.get("sha256")
            if checksum != frozen_inputs[name]["sha256"]:
                raise ValueError(
                    f"attempt provenance mismatch for {name}.sha256: {identity}"
                )
        if attempt.get("ruleset_commit") != ruleset_commit:
            raise ValueError(f"attempt provenance mismatch for ruleset_commit: {identity}")
        scanner = attempt.get("scanner")
        if not isinstance(scanner, dict) or scanner.get("name") != job["scanner"]:
            raise ValueError(f"attempt scanner provenance is invalid: {identity}")
        pin = selected_pins[job["scanner"]]
        if scanner.get("observed_version") != pin["version"]:
            raise ValueError(f"attempt provenance mismatch for scanner version: {identity}")
        if scanner.get("executable_sha256") != pin["executable_sha256"]:
            raise ValueError(
                f"attempt provenance mismatch for scanner executable_sha256: {identity}"
            )

    execution = run.get("execution")
    if not isinstance(execution, dict):
        raise ValueError("scan run metadata.execution must be an object")
    return {
        "scan_run": str(run_path),
        "scan_id": scan_id,
        "inputs": frozen_inputs,
        "ruleset_commit": ruleset_commit,
        "scanner_pins": selected_pins,
        "execution": execution,
    }


def _job_output_path(output_directory: Path, job: dict[str, Any]) -> Path:
    attempt_status = Path(job["attempt_status_path"])
    # The scanner layout already uses a filesystem-safe repository slug and commit.
    scanner_directory = attempt_status.parents[2]
    commit_directory = scanner_directory.parent
    repo_directory = commit_directory.parent
    return (
        output_directory
        / "jobs"
        / repo_directory.name
        / commit_directory.name
        / f"{job['scanner']}-security.jsonl"
    )


def _normalize_successful_jobs(
    jobs: Iterable[dict[str, Any]], output_directory: Path
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    job_summaries: list[dict[str, Any]] = []
    for job in sorted(
        (row for row in jobs if row.get("status") == "SUCCESS"),
        key=lambda row: (row["repo_url"], row["commit"], row["scanner"]),
    ):
        output_path = _job_output_path(output_directory, job)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = normalize_main(
                [
                    "--status",
                    str(job["attempt_status_path"]),
                    "--category",
                    "security",
                    "--output",
                    str(output_path),
                ]
            )
        if exit_code != 0:
            raise RuntimeError(
                f"normalizer failed for {job['repo_url']}@{job['commit']} "
                f"with {job['scanner']}"
            )
        rows = load_jsonl(output_path)
        findings.extend(rows)
        job_summaries.append(
            {
                "repo_url": job["repo_url"],
                "commit": job["commit"],
                "scanner": job["scanner"],
                "attempt_status": str(job["attempt_status_path"]),
                "normalized_output": str(output_path),
                "statistics": finding_statistics(rows),
            }
        )
    return findings, job_summaries


def _portable_source_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").lstrip("./").casefold()


def _error_type(error: dict[str, Any]) -> str:
    value = error.get("type") or error.get("error_type") or error.get("level") or "unknown"
    if isinstance(value, list) and value:
        value = value[0]
    return str(value)


def _error_path(error: dict[str, Any]) -> str:
    if error.get("path"):
        return str(error["path"])
    spans = error.get("spans") or []
    if isinstance(spans, list) and spans and isinstance(spans[0], dict):
        return str(spans[0].get("file") or spans[0].get("path") or "")
    return ""


def _scanner_errors(jobs: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = list(jobs)
    observations: list[dict[str, Any]] = []
    scan_index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for job in rows:
        if job.get("status") != "SUCCESS":
            continue
        attempt = job["attempt"]
        attempt_directory = Path(job["attempt_status_path"]).parent
        raw_path = attempt_directory / (attempt.get("outputs") or {}).get("json", "raw.json")
        raw = _read_object(raw_path, "raw scanner JSON")
        errors = raw.get("errors") or []
        if not isinstance(errors, list):
            raise ValueError(f"raw scanner errors must be a list: {raw_path}")
        scanned = (raw.get("paths") or {}).get("scanned") or []
        if not isinstance(scanned, list):
            raise ValueError(f"raw scanner paths.scanned must be a list: {raw_path}")
        file_errors: dict[str, set[str]] = {}
        for error in errors:
            if not isinstance(error, dict):
                continue
            path = _portable_source_path(_error_path(error))
            if path:
                file_errors.setdefault(path, set()).add(_error_type(error))
        scan_index[(job["repo_url"], job["commit"], job["scanner"])] = {
            "scanned": {_portable_source_path(path) for path in scanned},
            "file_errors": file_errors,
        }
        for index, error in enumerate(errors):
            error_object = error if isinstance(error, dict) else {"message": str(error)}
            error_type = _error_type(error_object)
            source_path = _error_path(error_object)
            spans = error_object.get("spans") or []
            observations.append(
                {
                    "repo_url": job["repo_url"],
                    "commit": job["commit"],
                    "scanner": job["scanner"],
                    "error_index": index,
                    "error_type": error_type,
                    "level": str(error_object.get("level") or ""),
                    "path": source_path.replace("\\", "/"),
                    "span_count": len(spans) if isinstance(spans, list) else 0,
                    "message": str(error_object.get("message") or error_object.get("long_msg") or ""),
                    "raw_result_ref": f"{raw_path.as_posix()}#errors/{index}",
                }
            )

    statuses = {
        (job["repo_url"], job["commit"], job["scanner"]): str(job.get("status"))
        for job in rows
    }
    scanners = sorted({job["scanner"] for job in rows})
    unresolved_partial_files: set[tuple[str, str, str]] = set()
    for observation in observations:
        if observation["error_type"] != "PartialParsing":
            observation["alternate_engines"] = []
            continue
        portable_path = _portable_source_path(observation["path"])
        alternate_statuses = []
        for scanner in scanners:
            if scanner == observation["scanner"]:
                continue
            key = (observation["repo_url"], observation["commit"], scanner)
            status = statuses.get(key, "MISSING")
            alternate = scan_index.get(key)
            if status != "SUCCESS" or alternate is None:
                file_status = status
            elif portable_path in alternate["file_errors"]:
                error_types = sorted(alternate["file_errors"][portable_path])
                file_status = (
                    "PARTIAL"
                    if "PartialParsing" in error_types
                    else "FILE_ERROR:" + ",".join(error_types)
                )
            elif portable_path in alternate["scanned"]:
                file_status = "SCANNED_CLEAN"
            else:
                file_status = "NOT_SCANNED"
            alternate_statuses.append({"scanner": scanner, "file_status": file_status})
        observation["alternate_engines"] = alternate_statuses
        if not any(item["file_status"] == "SCANNED_CLEAN" for item in alternate_statuses):
            unresolved_partial_files.add(
                (
                    observation["repo_url"],
                    observation["commit"],
                    portable_path,
                )
            )

    partial_observations = [row for row in observations if row["error_type"] == "PartialParsing"]
    summary = {
        "observations": len(observations),
        "by_scanner": dict(sorted(Counter(row["scanner"] for row in observations).items())),
        "by_type": dict(sorted(Counter(row["error_type"] for row in observations).items())),
        "jobs_with_errors": len(
            {(row["repo_url"], row["commit"], row["scanner"]) for row in observations}
        ),
        "partial_parsing_observations": len(partial_observations),
        "partial_parsing_engine_files": len(
            {
                (row["repo_url"], row["commit"], row["scanner"], row["path"])
                for row in partial_observations
            }
        ),
        "partial_parsing_files": len(
            {
                (row["repo_url"], row["commit"], row["path"])
                for row in partial_observations
            }
        ),
        "unresolved_partial_files": len(unresolved_partial_files),
    }
    return observations, summary


def run_full_pipeline(
    *,
    scan_root: Path,
    manifest_path: Path,
    entries_path: Path,
    output_directory: Path,
    scanners: Sequence[str] = DEFAULT_SCANNERS,
    line_tolerance: int = DEFAULT_LINE_TOLERANCE,
    allow_incomplete: bool = False,
) -> dict[str, Any]:
    if line_tolerance < 0:
        raise ValueError("line_tolerance must be non-negative")
    manifest = _read_object(manifest_path, "manifest")
    jobs = discover_scan_jobs(scan_root)
    coverage = validate_scan_coverage(jobs, manifest, scanners)
    if not coverage["complete"] and not allow_incomplete:
        raise RuntimeError(
            "scan coverage is incomplete: "
            f"{coverage['jobs_accounted']}/{coverage['jobs_expected']} jobs accounted; "
            f"blocking={coverage['blocking_statuses']}"
        )

    selected_jobs = _selected_expected_jobs(jobs, manifest, scanners)
    frozen_provenance = validate_batch_provenance(
        scan_root=scan_root,
        manifest_path=manifest_path,
        jobs=selected_jobs,
        scanners=scanners,
    )
    frozen_provenance["matching_entries"] = {
        "path": str(entries_path.resolve()),
        "sha256": _sha256_file(entries_path),
    }

    output_directory.mkdir(parents=True, exist_ok=True)
    normalized, per_job = _normalize_successful_jobs(selected_jobs, output_directory)
    normalized_path = output_directory / "security-normalized.jsonl"
    write_jsonl(normalized_path, normalized)
    normalized_summary = finding_statistics(normalized)

    deduplicated, dedup_summary = deduplicate_findings(normalized, line_tolerance)
    deduplicated_path = output_directory / "security-deduplicated.jsonl"
    write_jsonl(deduplicated_path, deduplicated)
    (output_directory / "security-dedup-summary.json").write_text(
        json.dumps(dedup_summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    entries = load_jsonl(entries_path)
    observation_matches, match_summary = match_candidates(
        deduplicated,
        entries,
        tolerance=line_tolerance,
    )
    canonical_matches, canonical_match_summary = aggregate_canonical_matches(
        deduplicated,
        observation_matches,
        match_summary,
    )
    matches_path = output_directory / "canonical-security-matches.jsonl"
    write_jsonl(matches_path, canonical_matches)
    (output_directory / "canonical-security-match-summary.json").write_text(
        json.dumps(canonical_match_summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    scanner_errors, scanner_error_summary = _scanner_errors(selected_jobs)
    scanner_errors_path = output_directory / "scanner-errors.jsonl"
    write_jsonl(scanner_errors_path, scanner_errors)

    summary = {
        "schema_version": 1,
        "scan_id": scan_root.resolve().name,
        "frozen_provenance": frozen_provenance,
        "coverage": coverage,
        "normalization": normalized_summary,
        "deduplication": dedup_summary["statistics"],
        "matching": canonical_match_summary,
        "scanner_errors": scanner_error_summary,
        "normalized_jobs": per_job,
        "outputs": {
            "normalized": str(normalized_path),
            "deduplicated": str(deduplicated_path),
            "matches": str(matches_path),
            "scanner_errors": str(scanner_errors_path),
        },
    }
    (output_directory / "full-pipeline-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Normalize, deduplicate and match a complete VulnGym scanner batch."
    )
    parser.add_argument("--scan-root", type=Path, required=True)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("artifacts/manifests/vulngym-v0.1.4.json"),
    )
    parser.add_argument(
        "--entries",
        type=Path,
        default=Path("benchmark/VulnGym/data/entries.jsonl"),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--scanner", action="append", choices=SUPPORTED_SCANNERS, dest="scanners")
    parser.add_argument("--line-tolerance", type=int, default=DEFAULT_LINE_TOLERANCE)
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="produce provisional output even when jobs are missing, running, failed or timed out",
    )
    args = parser.parse_args(argv)
    try:
        summary = run_full_pipeline(
            scan_root=args.scan_root,
            manifest_path=args.manifest,
            entries_path=args.entries,
            output_directory=args.output_dir,
            scanners=args.scanners or DEFAULT_SCANNERS,
            line_tolerance=args.line_tolerance,
            allow_incomplete=args.allow_incomplete,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 2
    print(json.dumps({
        "coverage": summary["coverage"],
        "normalization": summary["normalization"],
        "deduplication": summary["deduplication"],
        "matching_counts": summary["matching"]["counts_by_tier"],
        "scanner_errors": summary["scanner_errors"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
