from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .verifier_agent import (
    AgentProfile,
    EvidenceToolbox,
    SnapshotResolver,
    validate_blind_input,
)


_BLIND_KEYS = (
    "schema_version",
    "finding_id",
    "member_finding_ids",
    "repo_url",
    "commit",
    "scanner",
    "rule",
    "message",
    "location",
    "dataflow_trace",
    "snippet",
    "fingerprint",
    "provenance",
)
_VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "ABSTAIN"}
_CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON file: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        handle = path.open("r", encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"missing JSONL file: {path}") from exc
    with handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"JSONL row must be an object: {path}:{line_number}")
            rows.append(row)
    return rows


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
            handle.write("\n")
    temporary.replace(path)


def _ordered_ids(rows: list[dict[str, Any]], label: str) -> list[str]:
    ids: list[str] = []
    for index, row in enumerate(rows, 1):
        finding_id = row.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            raise ValueError(f"{label} row {index} has no finding_id")
        ids.append(finding_id)
    if len(ids) != len(set(ids)):
        raise ValueError(f"{label} contains duplicate finding IDs")
    return ids


def _project_blind_finding(row: dict[str, Any]) -> dict[str, Any]:
    projected = {key: row[key] for key in _BLIND_KEYS if key in row}
    scanner = projected.get("scanner")
    if isinstance(scanner, dict) and scanner.get("name") == "opengrep":
        # The frozen v1 blind-input contract represents every non-Semgrep scanner
        # as `other`. Detailed provenance still records `opengrep`; do not mutate
        # the immutable Semgrep verifier/release files merely to add an enum value.
        projected["scanner"] = {**scanner, "name": "other"}
    return projected


def _verify_sample(sample_directory: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    manifest = _read_json(sample_directory / "sample-manifest.json")
    outputs = manifest.get("outputs")
    if not isinstance(outputs, dict):
        raise ValueError("sample manifest has no outputs proof")
    for name in ("sampled-findings.jsonl", "sampling-index.jsonl"):
        proof = outputs.get(name)
        path = sample_directory / name
        if not isinstance(proof, dict) or proof.get("sha256") != _sha256(path):
            raise ValueError(f"sample output checksum mismatch: {name}")
    findings = _read_jsonl(sample_directory / "sampled-findings.jsonl")
    index = _read_jsonl(sample_directory / "sampling-index.jsonl")
    finding_ids = _ordered_ids(findings, "sample findings")
    index_ids = _ordered_ids(index, "sampling index")
    if finding_ids != index_ids:
        raise ValueError("sample findings and sampling index differ in IDs or order")
    expected = manifest.get("sampling", {}).get("sample_size")
    if expected != len(findings):
        raise ValueError("sample record count does not match manifest")
    return manifest, findings, index


def prepare_review(
    *,
    sample_directory: Path,
    snapshot_root: Path,
    output_directory: Path,
    profile_path: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    sample_directory = sample_directory.resolve()
    snapshot_root = snapshot_root.resolve()
    output_directory = output_directory.resolve()
    profile_path = profile_path.resolve()
    manifest, findings, index = _verify_sample(sample_directory)
    profile = AgentProfile.load(profile_path)
    blind = [_project_blind_finding(row) for row in findings]
    validate_blind_input(blind, profile)

    identity = {
        "sample_id": manifest.get("sample_id"),
        "sample_manifest_sha256": _sha256(sample_directory / "sample-manifest.json"),
        "sample_findings_sha256": _sha256(sample_directory / "sampled-findings.jsonl"),
        "profile_sha256": _sha256(profile_path),
        "records": len(blind),
    }
    manifest_path = output_directory / "hybrid-review-manifest.json"
    if manifest_path.exists():
        existing = _read_json(manifest_path)
        if existing.get("identity") != identity:
            raise ValueError("existing hybrid-review directory has a different identity")
        for proof in existing.get("outputs", {}).values():
            if not isinstance(proof, dict):
                continue
            path = output_directory / str(proof.get("path") or "")
            if not path.is_file() or _sha256(path) != proof.get("sha256"):
                raise ValueError(f"existing hybrid-review output changed: {path}")
        return existing

    output_directory.mkdir(parents=True, exist_ok=False)
    blind_path = output_directory / "blind-verifier-input.jsonl"
    evidence_path = output_directory / "evidence-packets.jsonl"
    _write_jsonl(blind_path, blind)

    resolver = SnapshotResolver(snapshot_root)
    packets: list[dict[str, Any]] = []
    for position, (finding, sample_index) in enumerate(zip(blind, index), 1):
        snapshot = resolver.resolve(finding)
        toolbox = EvidenceToolbox(snapshot, profile)
        packets.append(
            {
                "schema_version": 1,
                "finding_id": finding["finding_id"],
                "review_order": sample_index["review_order"],
                "finding": finding,
                "initial_source_evidence": toolbox.initial_observations(finding),
                "snapshot": {
                    "repo_url": finding["repo_url"],
                    "commit": finding["commit"],
                    "git_state_verified": True,
                },
            }
        )
        if position % 25 == 0 or position == len(blind):
            print(f"[{position}/{len(blind)}] evidence packets")
    _write_jsonl(evidence_path, packets)

    for name in ("human-gold-label.schema.json", "human-gold-labels.template.jsonl"):
        shutil.copyfile(sample_directory / name, output_directory / name)
    readme_path = output_directory / "README.md"
    readme_path.write_text(
        "# OpenGrep hybrid review (400 finding)\n\n"
        "- `blind-verifier-input.jsonl`: cùng một đầu vào không chứa nhãn cho hai LLM.\n"
        "- `evidence-packets.jsonl`: đoạn mã nguồn đúng commit để con người tra cứu nhanh.\n"
        "- `reviewer-a/` và `reviewer-b/`: hai run độc lập; không cho reviewer này đọc kết quả reviewer kia.\n"
        "- Chỉ chạy `reconcile` khi cả hai file `verifier-predictions.jsonl` đủ 400 record.\n"
        "- Nhãn đồng thuận của máy là SILVER, không phải human gold và không được dùng cho metrics chính thức.\n"
        "- `human-gold-labels.jsonl` chỉ được tạo từ đánh giá thật của con người.\n",
        encoding="utf-8",
    )
    created = created_at or datetime.now(timezone.utc).isoformat()
    datetime.fromisoformat(created.replace("Z", "+00:00"))
    outputs: dict[str, Any] = {}
    for path, records in (
        (blind_path, len(blind)),
        (evidence_path, len(packets)),
        (output_directory / "human-gold-label.schema.json", None),
        (output_directory / "human-gold-labels.template.jsonl", len(blind)),
        (readme_path, None),
    ):
        outputs[path.name] = {
            "path": path.name,
            "sha256": _sha256(path),
            "records": records,
        }
    result = {
        "schema_version": 1,
        "review_id": output_directory.name,
        "created_at": created,
        "status": "EVIDENCE_READY_AWAITING_TWO_INDEPENDENT_LLM_RUNS",
        "identity": identity,
        "source": {
            "sample_directory": str(sample_directory),
            "snapshot_root": str(snapshot_root),
            "scanner": "opengrep",
        },
        "review_policy": {
            "reviewers": 2,
            "predictions_must_be_independent": True,
            "reviewers_must_not_see_each_others_predictions": True,
            "reviewers_must_not_be_the_agent_under_evaluation": True,
            "high_consensus_is_silver_not_human_gold": True,
            "human_review_required_for": [
                "MODEL_DISAGREEMENT",
                "ABSTAIN_OR_UNCERTAIN",
                "LOW_OR_MEDIUM_CONFIDENCE",
                "TRUE_POSITIVE_REQUIRES_KNOWN_NOVEL_LINKAGE",
                "DETERMINISTIC_CONSENSUS_FP_AUDIT",
            ],
        },
        "outputs": outputs,
        "expected_predictions": {
            "reviewer_a": "reviewer-a/verifier-predictions.jsonl",
            "reviewer_b": "reviewer-b/verifier-predictions.jsonl",
        },
    }
    _write_json(manifest_path, result)
    return result


def _prediction_map(path: Path, expected_ids: list[str], reviewer: str) -> dict[str, dict[str, Any]]:
    rows = _read_jsonl(path)
    ids = _ordered_ids(rows, reviewer)
    if set(ids) != set(expected_ids) or len(ids) != len(expected_ids):
        raise ValueError(f"{reviewer} does not cover the exact sample")
    mapped = {str(row["finding_id"]): row for row in rows}
    for finding_id, row in mapped.items():
        if row.get("verdict") not in _VERDICTS:
            raise ValueError(f"{reviewer} has invalid verdict for {finding_id}")
        if row.get("confidence") not in _CONFIDENCES:
            raise ValueError(f"{reviewer} has invalid confidence for {finding_id}")
        if not isinstance(row.get("reasoning"), str) or not row["reasoning"].strip():
            raise ValueError(f"{reviewer} has no reasoning for {finding_id}")
        if not isinstance(row.get("evidence"), list):
            raise ValueError(f"{reviewer} has invalid evidence for {finding_id}")
    return mapped


def _audit_selected(seed: str, finding_id: str, fraction: float) -> bool:
    value = int.from_bytes(
        hashlib.sha256(f"{seed}\0{finding_id}".encode()).digest(), "big"
    ) / (1 << 256)
    return value < fraction


def _human_template(finding_id: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "finding_id": finding_id,
        "label": None,
        "reason_codes": [],
        "reasoning": "",
        "reviewer": {"id": "", "kind": "HUMAN"},
        "reviewed_at": "",
        "evidence": [],
        "linked_entry_ids": [],
        "linked_report_ids": [],
    }


def reconcile_reviews(
    *,
    sample_directory: Path,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
    output_directory: Path,
    audit_fraction: float = 0.15,
    audit_seed: str = "opengrep-hybrid-human-audit-r1-20260813",
) -> dict[str, Any]:
    if not 0.0 <= audit_fraction <= 1.0:
        raise ValueError("audit_fraction must be between 0 and 1")
    _, findings, index = _verify_sample(sample_directory.resolve())
    expected_ids = _ordered_ids(findings, "sample findings")
    a = _prediction_map(reviewer_a_path.resolve(), expected_ids, "reviewer A")
    b = _prediction_map(reviewer_b_path.resolve(), expected_ids, "reviewer B")
    finding_by_id = {str(row["finding_id"]): row for row in findings}
    order_by_id = {str(row["finding_id"]): row["review_order"] for row in index}

    consensus: list[dict[str, Any]] = []
    silver: list[dict[str, Any]] = []
    human_queue: list[dict[str, Any]] = []
    uncertain_or_novel: list[dict[str, Any]] = []
    human_templates: list[dict[str, Any]] = []
    reason_counts: dict[str, int] = {}
    verdict_pairs: dict[str, int] = {}
    for finding_id in expected_ids:
        pa, pb = a[finding_id], b[finding_id]
        pair = f"{pa['verdict']}|{pb['verdict']}"
        verdict_pairs[pair] = verdict_pairs.get(pair, 0) + 1
        high_agreement = (
            pa["verdict"] == pb["verdict"]
            and pa["confidence"] == "HIGH"
            and pb["confidence"] == "HIGH"
            and pa["verdict"] != "ABSTAIN"
        )
        machine_record = {
            "schema_version": 1,
            "finding_id": finding_id,
            "review_order": order_by_id[finding_id],
            "consensus": high_agreement,
            "consensus_verdict": pa["verdict"] if high_agreement else None,
            "label_tier": "SILVER_CONSENSUS" if high_agreement else "NO_CONSENSUS",
            "reviewer_a": pa,
            "reviewer_b": pb,
        }
        if high_agreement:
            consensus.append(machine_record)
        reasons: list[str] = []
        if pa["verdict"] != pb["verdict"]:
            reasons.append("MODEL_DISAGREEMENT")
        if "ABSTAIN" in {pa["verdict"], pb["verdict"]}:
            reasons.append("ABSTAIN_OR_UNCERTAIN")
        if "HIGH" not in {pa["confidence"]} or "HIGH" not in {pb["confidence"]}:
            reasons.append("LOW_OR_MEDIUM_CONFIDENCE")
        if "TRUE_POSITIVE" in {pa["verdict"], pb["verdict"]}:
            reasons.append("TRUE_POSITIVE_REQUIRES_KNOWN_NOVEL_LINKAGE")
        audit = (
            high_agreement
            and pa["verdict"] == "FALSE_POSITIVE"
            and _audit_selected(audit_seed, finding_id, audit_fraction)
        )
        if audit:
            reasons.append("DETERMINISTIC_CONSENSUS_FP_AUDIT")
        if pa["verdict"] in {"TRUE_POSITIVE", "ABSTAIN"} or pb["verdict"] in {
            "TRUE_POSITIVE",
            "ABSTAIN",
        }:
            uncertain_or_novel.append(machine_record)
        if reasons:
            queue_record = {
                **machine_record,
                "review_reasons": reasons,
                "finding": finding_by_id[finding_id],
            }
            human_queue.append(queue_record)
            human_templates.append(_human_template(finding_id))
            for reason in reasons:
                reason_counts[reason] = reason_counts.get(reason, 0) + 1
        elif high_agreement:
            silver.append(machine_record)
        else:
            # Same verdict with non-HIGH confidence reaches this branch only if a
            # malformed future policy bypasses the confidence reason above.
            raise AssertionError(f"unrouted review record: {finding_id}")

    output_directory = output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    paths = {
        "consensus_high": output_directory / "consensus-high.jsonl",
        "silver_consensus": output_directory / "silver-consensus.jsonl",
        "needs_human_review": output_directory / "needs-human-review.jsonl",
        "uncertain_or_novel": output_directory / "uncertain-or-novel.jsonl",
        "human_template": output_directory / "human-adjudication.template.jsonl",
    }
    _write_jsonl(paths["consensus_high"], consensus)
    _write_jsonl(paths["silver_consensus"], silver)
    _write_jsonl(paths["needs_human_review"], human_queue)
    _write_jsonl(paths["uncertain_or_novel"], uncertain_or_novel)
    _write_jsonl(paths["human_template"], human_templates)
    summary = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "AWAITING_TARGETED_HUMAN_ADJUDICATION" if human_queue else "SILVER_ONLY_READY",
        "records": len(expected_ids),
        "reviewer_inputs": {
            "reviewer_a": {"path": str(reviewer_a_path), "sha256": _sha256(reviewer_a_path)},
            "reviewer_b": {"path": str(reviewer_b_path), "sha256": _sha256(reviewer_b_path)},
        },
        "counts": {
            "high_consensus": len(consensus),
            "silver_without_human_review": len(silver),
            "needs_human_review": len(human_queue),
            "uncertain_or_true_positive": len(uncertain_or_novel),
        },
        "human_review_reasons": dict(sorted(reason_counts.items())),
        "verdict_pairs": dict(sorted(verdict_pairs.items())),
        "audit": {"fraction": audit_fraction, "seed": audit_seed},
        "publication_policy": {
            "hybrid_results_are_exploratory": True,
            "silver_consensus_is_not_human_gold": True,
            "official_metrics_require_human_gold_for_all_400": True,
        },
        "outputs": {
            key: {"path": path.name, "sha256": _sha256(path)}
            for key, path in paths.items()
        },
    }
    _write_json(output_directory / "hybrid-review-summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare and reconcile a two-LLM plus human OpenGrep review."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--sample-dir", type=Path, required=True)
    prepare.add_argument("--snapshot-root", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--profile", type=Path, default=Path("config/verifier-profile-v1.json"))
    prepare.add_argument("--created-at")
    reconcile = commands.add_parser("reconcile")
    reconcile.add_argument("--sample-dir", type=Path, required=True)
    reconcile.add_argument("--reviewer-a", type=Path, required=True)
    reconcile.add_argument("--reviewer-b", type=Path, required=True)
    reconcile.add_argument("--output-dir", type=Path, required=True)
    reconcile.add_argument("--audit-fraction", type=float, default=0.15)
    reconcile.add_argument("--audit-seed", default="opengrep-hybrid-human-audit-r1-20260813")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare_review(
                sample_directory=args.sample_dir,
                snapshot_root=args.snapshot_root,
                output_directory=args.output_dir,
                profile_path=args.profile,
                created_at=args.created_at,
            )
        else:
            result = reconcile_reviews(
                sample_directory=args.sample_dir,
                reviewer_a_path=args.reviewer_a,
                reviewer_b_path=args.reviewer_b,
                output_directory=args.output_dir,
                audit_fraction=args.audit_fraction,
                audit_seed=args.audit_seed,
            )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
