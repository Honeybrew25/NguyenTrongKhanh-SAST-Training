from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


_CANDIDATE_TIER = "CANDIDATE_REVIEW"
_LABEL_POLICY = "UNLABELED_NOT_FALSE_POSITIVE"


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


def _read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    try:
        handle = path.open(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"JSONL input does not exist: {path}") from exc
    with handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: record must be an object")
            yield value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
            handle.write("\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _display_path(path: Path, project_root: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(project_root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _validate_complete_opengrep_pipeline(summary: dict[str, Any]) -> None:
    coverage = summary.get("coverage")
    if not isinstance(coverage, dict) or coverage.get("complete") is not True:
        raise ValueError("pipeline coverage must be complete before release")
    expected = coverage.get("jobs_expected")
    accounted = coverage.get("jobs_accounted")
    if type(expected) is not int or expected < 1 or accounted != expected:
        raise ValueError("pipeline must account for every expected scan job")
    if coverage.get("status_counts") != {"SUCCESS": expected}:
        raise ValueError("every scan job must have SUCCESS status before release")
    if coverage.get("blocking_statuses"):
        raise ValueError("pipeline contains blocking scan statuses")

    pins = summary.get("frozen_provenance", {}).get("scanner_pins", {})
    if set(pins) != {"opengrep"}:
        raise ValueError("release input must be an OpenGrep-only pipeline")
    scanner_counts = summary.get("normalization", {}).get("by_scanner")
    findings = summary.get("normalization", {}).get("findings")
    if scanner_counts != {"opengrep": findings}:
        raise ValueError("all normalized findings must come from OpenGrep")
    policy = summary.get("matching", {}).get("policy", {})
    if policy.get("unmatched_label_policy") != _LABEL_POLICY:
        raise ValueError("pipeline must preserve UNMATCHED findings as unlabeled")


def _blind_finding(finding: dict[str, Any]) -> dict[str, Any]:
    blind = {key: value for key, value in finding.items() if key != "canonical_finding_id"}
    scanner = blind.get("scanner", {})
    if scanner.get("name") != "opengrep":
        raise ValueError("candidate finding is not from OpenGrep")
    version = scanner.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("candidate finding has no OpenGrep version")
    # The frozen Semgrep verifier contract names non-Semgrep engines "other".
    # Adapt only at the blind-input boundary so old release identities stay valid.
    blind["scanner"] = {"name": "other", "version": f"opengrep {version}"}
    return blind


def _gold_template(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "finding_id": finding["finding_id"],
        "label": None,
        "reason_codes": [],
        "reasoning": "",
        "reviewer": {"id": "", "kind": "HUMAN"},
        "reviewed_at": "",
        "evidence": [],
    }


def build_opengrep_release(
    *,
    normalized_directory: Path,
    queue_directory: Path,
    corpus_directory: Path,
    project_root: Path,
    corpus_id: str,
    created_at: str,
) -> dict[str, Any]:
    """Freeze a label-blind verifier corpus from a complete OpenGrep pipeline."""

    pipeline_path = normalized_directory / "full-pipeline-summary.json"
    matches_path = normalized_directory / "canonical-security-matches.jsonl"
    findings_path = normalized_directory / "security-deduplicated.jsonl"
    pipeline = _read_object(pipeline_path, "pipeline summary")
    _validate_complete_opengrep_pipeline(pipeline)

    candidate_matches: list[dict[str, Any]] = []
    candidate_ids: set[str] = set()
    for match in _read_jsonl(matches_path):
        if match.get("match_tier") != _CANDIDATE_TIER:
            continue
        canonical_id = match.get("canonical_finding_id")
        if not isinstance(canonical_id, str) or not canonical_id:
            raise ValueError("candidate match is missing canonical_finding_id")
        if canonical_id in candidate_ids:
            raise ValueError(f"duplicate candidate match: {canonical_id}")
        candidate_ids.add(canonical_id)
        candidate_matches.append(match)

    expected_candidates = (
        pipeline.get("matching", {}).get("counts_by_tier", {}).get(_CANDIDATE_TIER)
    )
    if expected_candidates != len(candidate_matches):
        raise ValueError(
            "candidate match count does not agree with pipeline summary: "
            f"{len(candidate_matches)} != {expected_candidates}"
        )

    findings_by_id: dict[str, dict[str, Any]] = {}
    for finding in _read_jsonl(findings_path):
        canonical_id = finding.get("canonical_finding_id")
        if canonical_id not in candidate_ids:
            continue
        if canonical_id in findings_by_id:
            raise ValueError(f"duplicate canonical finding: {canonical_id}")
        findings_by_id[canonical_id] = finding
    missing = sorted(candidate_ids - set(findings_by_id))
    if missing:
        raise ValueError(f"candidate findings are missing: {missing}")

    candidate_matches.sort(key=lambda row: row["canonical_finding_id"])
    candidate_findings = [
        findings_by_id[match["canonical_finding_id"]] for match in candidate_matches
    ]
    candidate_observations = sum(
        len(match.get("member_finding_ids", [])) for match in candidate_matches
    )

    candidate_output = queue_directory / "candidate-findings.jsonl"
    match_output = queue_directory / "human-candidate-matches.jsonl"
    blind_output = queue_directory / "blind-verifier-input.jsonl"
    template_output = queue_directory / "human-gold-labels.template.jsonl"
    _write_jsonl(candidate_output, candidate_findings)
    _write_jsonl(match_output, candidate_matches)
    _write_jsonl(blind_output, (_blind_finding(row) for row in candidate_findings))
    _write_jsonl(template_output, (_gold_template(row) for row in candidate_findings))

    file_integrity = {
        path.name: {"records": len(candidate_findings), "sha256": _sha256(path)}
        for path in (candidate_output, match_output, blind_output, template_output)
    }
    queue_summary = {
        "schema_version": 1,
        "scan_id": pipeline["scan_id"],
        "scanner": "opengrep",
        "source_pipeline": _display_path(pipeline_path, project_root),
        "candidate_clusters": len(candidate_findings),
        "candidate_observations": candidate_observations,
        "blind_input": blind_output.name,
        "human_match_metadata": match_output.name,
        "findings": candidate_output.name,
        "human_gold_template": template_output.name,
        "file_integrity": file_integrity,
        "label_policy": _LABEL_POLICY,
        "leakage_control": (
            "blind verifier input excludes canonical IDs, VulnGym entry IDs, "
            "report IDs, matches, patches, and adjudication labels"
        ),
    }
    queue_summary_path = queue_directory / "queue-summary.json"
    _write_json(queue_summary_path, queue_summary)

    corpus_input = corpus_directory / "blind-verifier-input.jsonl"
    corpus_input.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(blind_output, corpus_input)
    corpus_summary = {
        "schema_version": 1,
        "corpus_id": corpus_id,
        "created_at": created_at,
        "complete": True,
        "scope": {
            "scanner": "opengrep",
            "scan_id": pipeline["scan_id"],
            "candidate_policy": "CANDIDATE_REVIEW_ONLY",
            "label_policy": _LABEL_POLICY,
        },
        "source_pipeline": {
            "path": _display_path(pipeline_path, project_root),
            "sha256": _sha256(pipeline_path),
            "jobs_expected": pipeline["coverage"]["jobs_expected"],
            "jobs_accounted": pipeline["coverage"]["jobs_accounted"],
            "complete": True,
        },
        "source_queue": {
            "path": _display_path(queue_summary_path, project_root),
            "sha256": _sha256(queue_summary_path),
            "candidate_clusters": len(candidate_findings),
        },
        "blind_verifier_input": {
            "path": corpus_input.name,
            "sha256": _sha256(corpus_input),
            "records": len(candidate_findings),
        },
        "leakage_control": {
            "human_match_metadata_included": False,
            "prior_predictions_included": False,
            "prior_technical_labels_included": False,
            "provisional_metrics_included": False,
        },
    }
    corpus_summary_path = corpus_directory / "summary.json"
    _write_json(corpus_summary_path, corpus_summary)

    return {
        "scan_id": pipeline["scan_id"],
        "candidate_clusters": len(candidate_findings),
        "candidate_observations": candidate_observations,
        "queue_summary": _display_path(queue_summary_path, project_root),
        "corpus_summary": _display_path(corpus_summary_path, project_root),
        "blind_input_sha256": corpus_summary["blind_verifier_input"]["sha256"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a leak-free annotation queue and frozen verifier corpus from "
            "a complete OpenGrep-only full pipeline."
        )
    )
    parser.add_argument("--normalized-dir", type=Path, required=True)
    parser.add_argument("--queue-dir", type=Path, required=True)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--corpus-id", required=True)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--created-at",
        default=datetime.now(timezone.utc).isoformat(),
        help="Pinned ISO-8601 corpus timestamp (defaults to current UTC time).",
    )
    args = parser.parse_args(argv)
    try:
        result = build_opengrep_release(
            normalized_directory=args.normalized_dir,
            queue_directory=args.queue_dir,
            corpus_directory=args.corpus_dir,
            project_root=args.project_root,
            corpus_id=args.corpus_id,
            created_at=args.created_at,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
