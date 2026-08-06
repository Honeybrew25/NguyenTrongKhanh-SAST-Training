from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .candidate_matcher import aggregate_canonical_matches, match_candidates
from .dedup import deduplicate_findings
from .normalizer import (
    NormalizationContext,
    finding_statistics,
    normalize_sarif,
    write_jsonl,
)


# The CodeQL query sources embedded in bundle 2.25.5 resolve to this tagged
# github/codeql commit. Query-pack versions remain the executable query identity.
DEFAULT_QUERY_SOURCE_COMMIT = "b551e89ea8e011c0e3301fd0ce05589c9f2d3681"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected JSON object")
            rows.append(value)
    return rows


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _portable_path(path: Path, project_root: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _attempt_status_path(pointer_path: Path, pointer: dict[str, Any]) -> Path:
    relative = pointer.get("attempt_status")
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"pointer is missing attempt_status: {pointer_path}")
    attempt_path = (pointer_path.parent / relative).resolve()
    try:
        attempt_path.relative_to(pointer_path.parent.resolve())
    except ValueError as exc:
        raise ValueError(f"attempt status escapes job directory: {pointer_path}") from exc
    return attempt_path


def _job_directory(scan_root: Path, job: dict[str, Any]) -> Path:
    return (
        scan_root
        / str(job["repo_slug"])
        / str(job["commit"])
        / "codeql"
        / str(job["language"])
    )


def _normalized_repo(value: Any) -> str:
    return str(value or "").rstrip("/").removesuffix(".git").lower()


def _normalized_file(value: Any) -> str:
    return str(value or "").replace("\\", "/").lstrip("./").lower()


def _line_distance(left: dict[str, Any], right: dict[str, Any]) -> int:
    left_start = int(left["start_line"])
    left_end = int(left.get("end_line") or left_start)
    right_start = int(right["start_line"])
    right_end = int(right.get("end_line") or right_start)
    if left_end < right_start:
        return right_start - left_end
    if right_end < left_start:
        return left_start - right_end
    return 0


def build_candidate_review_queue(
    codeql_findings: list[dict[str, Any]],
    codeql_matches: list[dict[str, Any]],
    *,
    semgrep_findings: list[dict[str, Any]] | None = None,
    semgrep_matches: list[dict[str, Any]] | None = None,
    line_tolerance: int = 5,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings_by_id = {
        str(finding["canonical_finding_id"]): finding for finding in codeql_findings
    }
    semgrep_tiers = {
        str(match.get("canonical_finding_id") or match.get("finding_id")): str(
            match.get("match_tier")
        )
        for match in semgrep_matches or []
    }
    semgrep_by_location: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for finding in semgrep_findings or []:
        key = (
            _normalized_repo(finding.get("repo_url")),
            str(finding.get("commit") or "").lower(),
            _normalized_file((finding.get("location") or {}).get("file")),
        )
        semgrep_by_location.setdefault(key, []).append(finding)

    queue: list[dict[str, Any]] = []
    novelty_counts: Counter[str] = Counter()
    tier_counts: Counter[str] = Counter()
    for match in codeql_matches:
        tier = str(match["match_tier"])
        if tier == "UNMATCHED":
            continue
        canonical_id = str(match["canonical_finding_id"])
        finding = findings_by_id[canonical_id]
        location = finding["location"]
        key = (
            _normalized_repo(finding.get("repo_url")),
            str(finding.get("commit") or "").lower(),
            _normalized_file(location.get("file")),
        )
        nearby = []
        for semgrep_finding in semgrep_by_location.get(key, []):
            distance = _line_distance(location, semgrep_finding["location"])
            if distance > line_tolerance:
                continue
            semgrep_id = str(
                semgrep_finding.get("canonical_finding_id")
                or semgrep_finding.get("finding_id")
            )
            nearby.append(
                {
                    "canonical_finding_id": semgrep_id,
                    "rule_id": (semgrep_finding.get("rule") or {}).get("id"),
                    "start_line": semgrep_finding["location"]["start_line"],
                    "end_line": semgrep_finding["location"]["end_line"],
                    "line_distance": distance,
                    "match_tier": semgrep_tiers.get(semgrep_id),
                }
            )
        nearby.sort(
            key=lambda row: (
                row["line_distance"],
                row["start_line"],
                str(row["canonical_finding_id"]),
            )
        )
        if any(
            row["match_tier"] not in {None, "UNMATCHED"} for row in nearby
        ):
            novelty = "ALREADY_CANDIDATE_IN_SEMGREP"
        elif nearby:
            novelty = "NEW_MATCH_EVIDENCE_ON_EXISTING_SEMGREP_LOCATION"
        elif semgrep_findings is not None:
            novelty = "CODEQL_ONLY_LOCATION"
        else:
            novelty = "SEMGREP_COMPARISON_NOT_PROVIDED"
        novelty_counts[novelty] += 1
        tier_counts[tier] += 1
        queue.append(
            {
                "schema_version": 1,
                "candidate_id": f"candidate-{canonical_id}",
                "match_tier": tier,
                "novelty_vs_semgrep": novelty,
                "finding": finding,
                "vulngym_matches": match["matches"],
                "nearby_semgrep_findings": nearby,
                "review_status": "PENDING_VERIFIER_AND_HUMAN_REVIEW",
            }
        )

    summary = {
        "candidate_findings": len(queue),
        "counts_by_match_tier": dict(sorted(tier_counts.items())),
        "counts_by_novelty_vs_semgrep": dict(sorted(novelty_counts.items())),
        "comparison_policy": {
            "same_snapshot_and_file": True,
            "line_tolerance": line_tolerance,
            "does_not_merge_baseline_metrics": True,
            "candidate_is_not_a_tp_or_fp_label": True,
        },
    }
    return queue, summary


def build_blind_verifier_input(
    candidate_queue: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Remove matcher and benchmark metadata before independent verification."""

    rows: list[dict[str, Any]] = []
    for candidate in candidate_queue:
        finding = candidate["finding"]
        canonical_id = str(finding["canonical_finding_id"])
        rows.append(
            {
                "schema_version": 1,
                "finding_id": canonical_id,
                "member_finding_ids": [str(finding["finding_id"])],
                "repo_url": finding["repo_url"],
                "commit": finding["commit"],
                "scanner": finding["scanner"],
                "rule": finding["rule"],
                "message": finding["message"],
                "location": finding["location"],
                "dataflow_trace": finding["dataflow_trace"],
                "snippet": finding["snippet"],
                "fingerprint": finding["fingerprint"],
                "provenance": finding["provenance"],
            }
        )
    return rows


def _validate_identity(
    *,
    plan: dict[str, Any],
    job: dict[str, Any],
    pointer: dict[str, Any],
    attempt: dict[str, Any],
    attempt_path: Path,
) -> None:
    expected = {
        "scan_id": plan["scan_id"],
        "repo_url": job["repo_url"],
        "commit": job["commit"],
        "language": job["language"],
    }
    for field, expected_value in expected.items():
        if pointer.get(field) != expected_value:
            raise ValueError(
                f"pointer {field} mismatch at {attempt_path}: "
                f"{pointer.get(field)!r} != {expected_value!r}"
            )
        if attempt.get(field) != expected_value:
            raise ValueError(
                f"attempt {field} mismatch at {attempt_path}: "
                f"{attempt.get(field)!r} != {expected_value!r}"
            )
    if attempt.get("profile_sha256") != plan.get("profile_sha256"):
        raise ValueError(f"profile checksum mismatch at {attempt_path}")
    if pointer.get("status") != attempt.get("status"):
        raise ValueError(f"pointer/attempt state mismatch at {attempt_path}")


def collect_successful_findings(
    *,
    project_root: Path,
    plan: dict[str, Any],
    scan_root: Path,
    ruleset_commit: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    findings: list[dict[str, Any]] = []
    jobs_report: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()

    for job in plan["jobs"]:
        pointer_path = _job_directory(scan_root, job) / "status.json"
        if not pointer_path.exists():
            counts["PENDING"] += 1
            jobs_report.append({**job, "status": "PENDING"})
            continue

        pointer = _read_json(pointer_path)
        state = str(pointer.get("status") or "INVALID")
        counts[state] += 1
        job_report = {**job, "status": state}
        if state != "SUCCESS":
            jobs_report.append(job_report)
            continue

        attempt_path = _attempt_status_path(pointer_path, pointer)
        attempt = _read_json(attempt_path)
        _validate_identity(
            plan=plan,
            job=job,
            pointer=pointer,
            attempt=attempt,
            attempt_path=attempt_path,
        )
        raw_path = attempt_path.parent / "raw.sarif"
        expected_checksum = (attempt.get("checksums") or {}).get("raw.sarif")
        if not isinstance(expected_checksum, str) or not expected_checksum:
            raise ValueError(f"successful attempt lacks raw.sarif checksum: {attempt_path}")
        actual_checksum = _sha256(raw_path)
        if actual_checksum != expected_checksum:
            raise ValueError(f"raw.sarif checksum mismatch: {raw_path}")

        tool = attempt.get("tool") or {}
        scanner_version = str(tool.get("version") or "")
        context = NormalizationContext(
            repo_url=str(job["repo_url"]),
            commit=str(job["commit"]),
            scanner_name="codeql",
            scanner_version=scanner_version,
            ruleset_commit=ruleset_commit,
            scan_id=str(plan["scan_id"]),
            raw_result_ref=_portable_path(raw_path, project_root),
            source_root=Path(str(attempt["source_root"])),
            read_source_snippets=False,
        )
        job_findings = normalize_sarif(_read_json(raw_path), context)
        expected_findings = (attempt.get("result_summary") or {}).get("findings")
        if expected_findings != len(job_findings):
            raise ValueError(
                f"normalized finding count mismatch at {raw_path}: "
                f"{len(job_findings)} != {expected_findings!r}"
            )
        findings.extend(job_findings)
        job_report.update(
            {
                "attempt": attempt.get("attempt"),
                "duration_seconds": attempt.get("duration_seconds"),
                "result_summary": attempt.get("result_summary"),
                "raw_sarif": _portable_path(raw_path, project_root),
                "raw_sarif_sha256": actual_checksum,
                "query_pack": attempt.get("query_pack"),
                "query_suite": attempt.get("query_suite"),
            }
        )
        jobs_report.append(job_report)

    return findings, jobs_report, dict(sorted(counts.items()))


def postprocess(
    *,
    project_root: Path,
    plan_path: Path,
    scan_root: Path,
    entries_path: Path,
    output_directory: Path,
    ruleset_commit: str = DEFAULT_QUERY_SOURCE_COMMIT,
    line_tolerance: int = 5,
    semgrep_findings_path: Path | None = None,
    semgrep_matches_path: Path | None = None,
) -> dict[str, Any]:
    plan = _read_json(plan_path)
    entries = _read_jsonl(entries_path)
    findings, jobs_report, status_counts = collect_successful_findings(
        project_root=project_root,
        plan=plan,
        scan_root=scan_root,
        ruleset_commit=ruleset_commit,
    )
    canonicalized, dedup_summary = deduplicate_findings(findings)
    observation_matches, observation_match_summary = match_candidates(
        canonicalized,
        entries,
        tolerance=line_tolerance,
        verified_only=True,
    )
    canonical_matches, canonical_match_summary = aggregate_canonical_matches(
        canonicalized,
        observation_matches,
        observation_match_summary,
    )
    semgrep_findings = (
        _read_jsonl(semgrep_findings_path) if semgrep_findings_path else None
    )
    semgrep_matches = (
        _read_jsonl(semgrep_matches_path) if semgrep_matches_path else None
    )
    candidate_queue, candidate_summary = build_candidate_review_queue(
        canonicalized,
        canonical_matches,
        semgrep_findings=semgrep_findings,
        semgrep_matches=semgrep_matches,
        line_tolerance=line_tolerance,
    )
    blind_verifier_input = build_blind_verifier_input(candidate_queue)

    output_directory.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_directory / "normalized-observations.jsonl", findings)
    write_jsonl(
        output_directory / "canonicalized-observations.jsonl", canonicalized
    )
    write_jsonl(output_directory / "matches-observation.jsonl", observation_matches)
    write_jsonl(output_directory / "matches-canonical.jsonl", canonical_matches)
    write_jsonl(output_directory / "candidate-review-queue.jsonl", candidate_queue)
    blind_input_path = output_directory / "blind-verifier-input.jsonl"
    write_jsonl(blind_input_path, blind_verifier_input)
    _write_json(output_directory / "dedup-summary.json", dedup_summary)
    _write_json(
        output_directory / "match-observation-summary.json",
        observation_match_summary,
    )
    _write_json(
        output_directory / "match-canonical-summary.json", canonical_match_summary
    )
    _write_json(output_directory / "candidate-review-summary.json", candidate_summary)

    planned_jobs = int(plan["job_count"])
    successful_jobs = status_counts.get("SUCCESS", 0)
    complete = successful_jobs == planned_jobs and set(status_counts) <= {"SUCCESS"}
    summary = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "scan_id": plan["scan_id"],
        "complete": complete,
        "warning": (
            None
            if complete
            else "PARTIAL_RESULT: only successful jobs present at generation time are included"
        ),
        "separate_baseline": "codeql",
        "unmatched_label_policy": "UNLABELED_NOT_FALSE_POSITIVE",
        "inputs": {
            "plan": _portable_path(plan_path, project_root),
            "plan_sha256": _sha256(plan_path),
            "profile_sha256": plan.get("profile_sha256"),
            "entries": _portable_path(entries_path, project_root),
            "entries_sha256": _sha256(entries_path),
            "query_source_commit": ruleset_commit,
            "semgrep_findings": (
                _portable_path(semgrep_findings_path, project_root)
                if semgrep_findings_path
                else None
            ),
            "semgrep_findings_sha256": (
                _sha256(semgrep_findings_path) if semgrep_findings_path else None
            ),
            "semgrep_matches": (
                _portable_path(semgrep_matches_path, project_root)
                if semgrep_matches_path
                else None
            ),
            "semgrep_matches_sha256": (
                _sha256(semgrep_matches_path) if semgrep_matches_path else None
            ),
        },
        "coverage": {
            "planned_jobs": planned_jobs,
            "status_counts": status_counts,
            "successful_jobs": successful_jobs,
            "successful_fraction": successful_jobs / planned_jobs if planned_jobs else 0.0,
        },
        "normalized": finding_statistics(findings),
        "deduplication": dedup_summary["statistics"],
        "observation_matches": observation_match_summary,
        "canonical_matches": canonical_match_summary,
        "candidate_review": candidate_summary,
        "blind_verifier_input": {
            "records": len(blind_verifier_input),
            "path": _portable_path(blind_input_path, project_root),
            "sha256": _sha256(blind_input_path),
            "contains_vulngym_match_metadata": False,
            "safe_only_for_an_independent_verifier": True,
        },
        "jobs": jobs_report,
        "outputs": {
            name: _portable_path(output_directory / name, project_root)
            for name in (
                "normalized-observations.jsonl",
                "canonicalized-observations.jsonl",
                "dedup-summary.json",
                "matches-observation.jsonl",
                "match-observation-summary.json",
                "matches-canonical.jsonl",
                "match-canonical-summary.json",
                "candidate-review-queue.jsonl",
                "candidate-review-summary.json",
                "blind-verifier-input.jsonl",
            )
        },
    }
    _write_json(output_directory / "summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Normalize and match successful CodeQL jobs without mixing scanner baselines."
    )
    parser.add_argument(
        "--plan",
        type=Path,
        default=Path(
            "artifacts/manifests/codeql-full-security-extended-v3-20260805.json"
        ),
    )
    parser.add_argument("--scan-root", type=Path)
    parser.add_argument(
        "--entries",
        type=Path,
        default=Path("benchmark/VulnGym/data/entries.jsonl"),
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--semgrep-findings",
        type=Path,
        help="optional Semgrep canonical findings used only for novelty comparison",
    )
    parser.add_argument(
        "--semgrep-matches",
        type=Path,
        help="optional Semgrep canonical matches used only for novelty comparison",
    )
    parser.add_argument(
        "--ruleset-commit",
        default=DEFAULT_QUERY_SOURCE_COMMIT,
        help="40-character github/codeql source commit for result provenance",
    )
    parser.add_argument("--line-tolerance", type=int, default=5)
    args = parser.parse_args(argv)
    if args.line_tolerance < 0:
        parser.error("--line-tolerance must be non-negative")

    project_root = Path.cwd().resolve()
    plan_path = (project_root / args.plan).resolve()
    plan = _read_json(plan_path)
    scan_root = (
        (project_root / args.scan_root).resolve()
        if args.scan_root
        else project_root / "artifacts" / "scans" / str(plan["scan_id"])
    )
    output_directory = (
        (project_root / args.output_dir).resolve()
        if args.output_dir
        else project_root / "artifacts" / "normalized" / str(plan["scan_id"])
    )
    summary = postprocess(
        project_root=project_root,
        plan_path=plan_path,
        scan_root=scan_root,
        entries_path=(project_root / args.entries).resolve(),
        output_directory=output_directory,
        ruleset_commit=args.ruleset_commit,
        line_tolerance=args.line_tolerance,
        semgrep_findings_path=(
            (project_root / args.semgrep_findings).resolve()
            if args.semgrep_findings
            else None
        ),
        semgrep_matches_path=(
            (project_root / args.semgrep_matches).resolve()
            if args.semgrep_matches
            else None
        ),
    )
    print(
        json.dumps(
            {
                "complete": summary["complete"],
                "coverage": summary["coverage"],
                "normalized": summary["normalized"],
                "canonical_counts_by_tier": summary["canonical_matches"][
                    "counts_by_tier"
                ],
                "candidate_review": summary["candidate_review"],
                "output": _portable_path(output_directory / "summary.json", project_root),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
