from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator

from .candidate_matcher import CANDIDATE, STRICT, STRONG, UNMATCHED, match_candidates
from .machine_evaluator import (
    MACHINE_FALSE_LABEL,
    MACHINE_TRUE_LABEL,
    MACHINE_UNCERTAIN_LABEL,
    machine_reference_metrics,
    validate_frozen_machine_reference_package,
)


SPLITS = ("train", "validation", "test")
TARGET_POSITIVES = {"train": 3, "validation": 2, "test": 2}


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected an object")
            rows.append(row)
    if not rows:
        raise ValueError(f"JSONL input is empty: {path}")
    return rows


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _stable_hash(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def _portable(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _atomic_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    count = 0
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            )
            count += 1
    os.replace(temporary, path)
    return count


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def _language(finding: dict[str, Any]) -> str:
    suffix = Path(str(finding["location"]["file"]).casefold()).suffix
    if suffix == ".py":
        return "python"
    if suffix == ".go":
        return "go"
    if suffix in {".ts", ".tsx", ".mts", ".cts"}:
        return "typescript"
    if suffix in {".js", ".jsx", ".mjs", ".cjs"}:
        return "javascript"
    return suffix.removeprefix(".") or "unknown"


def _features(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository": finding["repo_url"],
        "rule_id": finding["rule"]["id"],
        "cwes": sorted(set(finding["rule"].get("cwe") or [])),
        "language": _language(finding),
        "has_dataflow": bool(finding.get("dataflow_trace")),
    }


def _validate_created_at(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("created-at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("created-at must include a timezone")


def build_dataset(
    *,
    review_directory: Path,
    entries_path: Path,
    dataset_path: Path,
    manifest_path: Path,
    schema_path: Path,
    created_at: str,
) -> dict[str, Any]:
    _validate_created_at(created_at)
    review_directory = review_directory.resolve(strict=True)
    labels_path = review_directory / "machine-reference-labels.jsonl"
    labels = validate_frozen_machine_reference_package(labels_path)
    findings_path = review_directory / "frozen-inputs" / "sampled-findings.jsonl"
    findings = _load_jsonl(findings_path)
    entries = _load_jsonl(entries_path.resolve(strict=True))
    schema_path = schema_path.resolve(strict=True)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    finding_by_id = {str(row.get("finding_id")): row for row in findings}
    label_by_id = {str(row.get("finding_id")): row for row in labels}
    if len(finding_by_id) != 400 or len(label_by_id) != 400:
        raise ValueError("machine dataset requires exactly 400 unique findings and labels")
    if set(finding_by_id) != set(label_by_id):
        raise ValueError("sampled findings and machine-reference labels differ")
    if any(row.get("scanner", {}).get("name") != "opengrep" for row in findings):
        raise ValueError("machine dataset must remain OpenGrep-only")

    tp_findings = [
        finding_by_id[finding_id]
        for finding_id, label in label_by_id.items()
        if label["label"] == MACHINE_TRUE_LABEL
    ]
    matches, match_summary = match_candidates(
        tp_findings, entries, tolerance=5, verified_only=True
    )
    match_by_id = {str(row["finding_id"]): row for row in matches}
    enriched: list[dict[str, Any]] = []
    linkage_counts: Counter[str] = Counter()
    label_counts: Counter[str] = Counter()
    for finding_id in sorted(finding_by_id):
        finding = finding_by_id[finding_id]
        label = label_by_id[finding_id]
        label_counts[str(label["label"])] += 1
        if label["label"] == MACHINE_TRUE_LABEL:
            match = match_by_id[finding_id]
            accepted = [
                node for node in match["matches"] if node["tier"] in {STRICT, STRONG}
            ]
            linked_entry_ids = sorted({str(node["entry_id"]) for node in accepted})
            linked_report_ids = sorted({str(node["report_id"]) for node in accepted})
            linkage_status = (
                "MACHINE_TP_LINKED" if linked_entry_ids else "MACHINE_TP_UNLINKED"
            )
            linkage = {
                "status": linkage_status,
                "linked_after_verdict_freeze": True,
                "match_tier": match["match_tier"],
                "linked_entry_ids": linked_entry_ids,
                "linked_report_ids": linked_report_ids,
                "candidate_matches": match["matches"] if match["match_tier"] == CANDIDATE else [],
            }
        else:
            linkage_status = "NOT_APPLICABLE"
            linkage = {
                "status": linkage_status,
                "linked_after_verdict_freeze": True,
                "match_tier": None,
                "linked_entry_ids": [],
                "linked_report_ids": [],
                "candidate_matches": [],
            }
        linkage_counts[linkage_status] += 1
        enriched.append(
            {
                "schema_version": 1,
                "finding_id": finding_id,
                "finding": finding,
                "machine_reference": label,
                "post_freeze_linkage": linkage,
                "features": _features(finding),
                "corpus_role": "PREVALENCE_400",
            }
        )

    for index, row in enumerate(enriched, 1):
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            raise ValueError(f"enriched row {index} violates schema: {errors[0].message}")

    _atomic_jsonl(dataset_path, enriched)
    implementation_path = Path(__file__).resolve()
    manifest = {
        "schema_version": 1,
        "release_id": "opengrep-machine-reviewed-r1-20260814",
        "created_at": created_at,
        "status": "FROZEN_MACHINE_ENRICHED_DATASET",
        "reference_policy": {
            "tier": "LLM_ADJUDICATED_MACHINE_REFERENCE",
            "human_gold": False,
            "publish_as_official": False,
            "uncertain_is_false_positive": False,
            "linkage_performed_after_verdict_freeze": True,
        },
        "sources": {
            "machine_reference_labels": {"path": _portable(labels_path), "sha256": _sha256(labels_path), "records": 400},
            "machine_reference_summary": {"path": _portable(review_directory / "machine-review-summary.json"), "sha256": _sha256(review_directory / "machine-review-summary.json")},
            "sampled_findings": {"path": _portable(findings_path), "sha256": _sha256(findings_path), "records": 400},
            "vulngym_entries": {"path": _portable(entries_path.resolve()), "sha256": _sha256(entries_path.resolve()), "verified_only": True},
        },
        "outputs": {
            "dataset": {"path": _portable(dataset_path), "sha256": _sha256(dataset_path), "records": 400},
        },
        "counts": {
            "labels": dict(sorted(label_counts.items())),
            "linkage": dict(sorted(linkage_counts.items())),
            "repositories": len({row["features"]["repository"] for row in enriched}),
        },
        "linkage_summary": match_summary,
        "identity": {
            "implementation": {"path": _portable(implementation_path), "sha256": _sha256(implementation_path)},
            "schema": {"path": _portable(schema_path), "sha256": _sha256(schema_path)},
        },
    }
    _atomic_json(manifest_path, manifest)
    return manifest


def _validate_dataset(dataset_path: Path, manifest_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("status") != "FROZEN_MACHINE_ENRICHED_DATASET":
        raise ValueError("machine dataset manifest policy is invalid")
    output = manifest.get("outputs", {}).get("dataset", {})
    rows = _load_jsonl(dataset_path)
    if output.get("sha256") != _sha256(dataset_path) or output.get("records") != len(rows):
        raise ValueError("machine dataset checksum proof is invalid")
    if len(rows) != 400 or len({row.get("finding_id") for row in rows}) != 400:
        raise ValueError("machine dataset must contain 400 unique records")
    for key in ("machine_reference_labels", "machine_reference_summary", "sampled_findings", "vulngym_entries"):
        proof = manifest.get("sources", {}).get(key, {})
        source = Path(str(proof.get("path") or ""))
        if not source.is_file() or proof.get("sha256") != _sha256(source):
            raise ValueError(f"machine dataset source proof is invalid: {key}")
    labels_source = Path(manifest["sources"]["machine_reference_labels"]["path"])
    validate_frozen_machine_reference_package(labels_source)
    for key in ("implementation", "schema"):
        proof = manifest.get("identity", {}).get(key, {})
        path = Path(str(proof.get("path") or ""))
        if not path.is_file() or proof.get("sha256") != _sha256(path):
            raise ValueError(f"machine dataset identity differs: {key}")
    return rows, manifest


def _repo_assignment(rows: list[dict[str, Any]], seed: str) -> dict[str, str]:
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_repo[row["features"]["repository"]].append(row)
    tp_counts = {
        repo: sum(row["machine_reference"]["label"] == MACHINE_TRUE_LABEL for row in members)
        for repo, members in by_repo.items()
    }
    positive_repos = [repo for repo, count in tp_counts.items() if count]
    targets = tuple(TARGET_POSITIVES[split] for split in SPLITS)
    candidates: list[tuple[tuple[Any, ...], dict[str, str]]] = []
    for choices in itertools.product(SPLITS, repeat=len(positive_repos)):
        assignment = dict(zip(positive_repos, choices, strict=True))
        counts = tuple(
            sum(tp_counts[repo] for repo in positive_repos if assignment[repo] == split)
            for split in SPLITS
        )
        if counts != targets:
            continue
        fp_capacity = tuple(
            sum(
                row["machine_reference"]["label"] == MACHINE_FALSE_LABEL
                for repo in positive_repos
                if assignment[repo] == split
                for row in by_repo[repo]
            )
            for split in SPLITS
        )
        score = (
            sum(min(fp_capacity[index], targets[index]) for index in range(3)),
            fp_capacity[2],
            fp_capacity[1],
            _stable_hash(seed, *(f"{repo}:{assignment[repo]}" for repo in sorted(assignment))),
        )
        candidates.append((score, assignment))
    if not candidates:
        raise ValueError("cannot allocate machine-positive repositories to 3/2/2 splits")
    assignment = dict(max(candidates, key=lambda item: item[0])[1])
    for repo in sorted(set(by_repo) - set(assignment)):
        assignment[repo] = SPLITS[int(_stable_hash(seed, repo), 16) % len(SPLITS)]

    # Move FP-only repositories deterministically when a split lacks enough negatives.
    for split in SPLITS:
        needed = TARGET_POSITIVES[split] - sum(
            row["machine_reference"]["label"] == MACHINE_FALSE_LABEL
            for repo, members in by_repo.items()
            if assignment[repo] == split
            for row in members
        )
        if needed <= 0:
            continue
        donors = sorted(
            (
                repo
                for repo, count in tp_counts.items()
                if count == 0 and assignment[repo] != split
            ),
            key=lambda repo: _stable_hash(seed, split, repo),
        )
        for repo in donors:
            assignment[repo] = split
            needed -= sum(
                row["machine_reference"]["label"] == MACHINE_FALSE_LABEL
                for row in by_repo[repo]
            )
            if needed <= 0:
                break
        if needed > 0:
            raise ValueError(f"not enough machine negatives for {split}")
    return assignment


def _similarity(positive: dict[str, Any], negative: dict[str, Any]) -> int:
    left, right = positive["features"], negative["features"]
    return (
        16 * (left["repository"] == right["repository"])
        + 8 * (left["rule_id"] == right["rule_id"])
        + 4 * bool(set(left["cwes"]) & set(right["cwes"]))
        + 2 * (left["language"] == right["language"])
        + (left["has_dataflow"] == right["has_dataflow"])
    )


def create_splits(
    *, dataset_path: Path, manifest_path: Path, output_directory: Path, seed: str, created_at: str
) -> dict[str, Any]:
    _validate_created_at(created_at)
    if not seed:
        raise ValueError("split seed must not be empty")
    rows, dataset_manifest = _validate_dataset(dataset_path, manifest_path)
    assignment = _repo_assignment(rows, seed)
    outputs: dict[str, Any] = {}
    selected_ids: set[str] = set()
    for split in SPLITS:
        eligible = [row for row in rows if assignment[row["features"]["repository"]] == split]
        positives = sorted(
            (row for row in eligible if row["machine_reference"]["label"] == MACHINE_TRUE_LABEL),
            key=lambda row: row["finding_id"],
        )
        negatives = [row for row in eligible if row["machine_reference"]["label"] == MACHINE_FALSE_LABEL]
        chosen_negatives: list[dict[str, Any]] = []
        for positive in positives:
            available = [row for row in negatives if row not in chosen_negatives]
            chosen = max(
                available,
                key=lambda row: (_similarity(positive, row), _stable_hash(seed, split, positive["finding_id"], row["finding_id"])),
            )
            chosen_negatives.append(chosen)
        selected = sorted(positives + chosen_negatives, key=lambda row: row["finding_id"])
        expected = TARGET_POSITIVES[split] * 2
        if len(positives) != TARGET_POSITIVES[split] or len(selected) != expected:
            raise ValueError(f"balanced split {split} has invalid class counts")
        ids = {row["finding_id"] for row in selected}
        if ids & selected_ids:
            raise ValueError("finding leakage detected between splits")
        selected_ids.update(ids)
        path = output_directory / f"{split}.jsonl"
        _atomic_jsonl(path, selected)
        outputs[split] = {
            "path": str(path),
            "sha256": _sha256(path),
            "records": len(selected),
            "machine_true_positive": len(positives),
            "machine_false_positive": len(chosen_negatives),
            "repositories": sorted({row["features"]["repository"] for row in selected}),
        }
    repository_sets = {
        split: {repo for repo, assigned in assignment.items() if assigned == split}
        for split in SPLITS
    }
    if any(repository_sets[a] & repository_sets[b] for a, b in itertools.combinations(SPLITS, 2)):
        raise ValueError("repository leakage detected between splits")
    split_manifest = {
        "schema_version": 1,
        "split_id": "opengrep-machine-benchmark-r1-20260814",
        "created_at": created_at,
        "status": "FROZEN_LEAK_FREE_BALANCED_SPLITS",
        "seed": seed,
        "policy": {
            "group_unit": "repository",
            "finding_level_random_split": False,
            "uncertain_excluded": True,
            "class_balance": "1:1_MACHINE_TRUE_POSITIVE_TO_MACHINE_FALSE_POSITIVE",
            "train_validation_test_positive_targets": TARGET_POSITIVES,
            "human_gold": False,
        },
        "source": {
            "dataset": {"path": str(dataset_path), "sha256": _sha256(dataset_path), "records": len(rows)},
            "dataset_manifest": {"path": str(manifest_path), "sha256": _sha256(manifest_path)},
            "reference_release": dataset_manifest["release_id"],
        },
        "repository_assignment": dict(sorted(assignment.items())),
        "outputs": outputs,
        "gates": {"repository_overlap": 0, "finding_overlap": 0, "balanced_records": 14},
        "limitations": [
            "Only seven machine-positive records exist, so the balanced benchmark is limited to fourteen records.",
            "The prevalence corpus remains the complete 400-record dataset and is not replaced by this benchmark.",
        ],
    }
    _atomic_json(output_directory / "split-manifest.json", split_manifest)
    return split_manifest


def create_raw_predictions(*, split_path: Path, output_path: Path) -> dict[str, Any]:
    rows = _load_jsonl(split_path)
    predictions = [
        {
            "finding_id": row["finding_id"],
            "verdict": "TRUE_POSITIVE",
            "baseline": {"id": "raw-opengrep-accept-all", "navigation": False},
        }
        for row in rows
    ]
    _atomic_jsonl(output_path, predictions)
    return {"path": str(output_path), "sha256": _sha256(output_path), "records": len(predictions)}


def prepare_agent_input(*, review_directory: Path, split_path: Path, output_path: Path) -> dict[str, Any]:
    validate_frozen_machine_reference_package(
        review_directory / "machine-reference-labels.jsonl"
    )
    requested = {row["finding_id"] for row in _load_jsonl(split_path)}
    packets_path = review_directory / "frozen-inputs" / "evidence-packets.jsonl"
    packets = [row for row in _load_jsonl(packets_path) if row.get("finding_id") in requested]
    if len(packets) != len(requested) or {row.get("finding_id") for row in packets} != requested:
        raise ValueError("test split and frozen evidence packets differ")
    findings = [row.get("finding") for row in packets]
    if any(not isinstance(row, dict) for row in findings):
        raise ValueError("frozen evidence packet is missing its blind finding")
    _atomic_jsonl(output_path, findings)
    return {
        "path": str(output_path),
        "sha256": _sha256(output_path),
        "records": len(packets),
        "source_evidence_packets_sha256": _sha256(packets_path),
        "label_fields_included": False,
    }


def import_agent_predictions(
    *, run_predictions_path: Path, split_path: Path, output_path: Path, baseline_id: str, navigation: bool
) -> dict[str, Any]:
    source = _load_jsonl(run_predictions_path)
    requested = {row["finding_id"] for row in _load_jsonl(split_path)}
    if {row.get("finding_id") for row in source} != requested:
        raise ValueError("agent predictions and test split IDs differ")
    allowed = {"TRUE_POSITIVE", "FALSE_POSITIVE", "ABSTAIN"}
    predictions: list[dict[str, Any]] = []
    for row in source:
        if row.get("verdict") not in allowed:
            raise ValueError(f"invalid agent verdict: {row.get('finding_id')}")
        agent = row.get("agent")
        if not isinstance(agent, dict):
            raise ValueError(f"missing agent provenance: {row.get('finding_id')}")
        calls = agent.get("controller_tool_calls")
        if not isinstance(calls, int) or calls < 0:
            raise ValueError(f"invalid controller tool-call count: {row.get('finding_id')}")
        if not navigation and calls != 0:
            raise ValueError("snippet-only baseline unexpectedly used repository navigation")
        predictions.append(
            {
                "finding_id": row["finding_id"],
                "verdict": row["verdict"],
                "baseline": {
                    "id": baseline_id,
                    "navigation": navigation,
                    "source_prediction_sha256": hashlib.sha256(
                        json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                    "agent": agent,
                },
            }
        )
    predictions.sort(key=lambda row: row["finding_id"])
    _atomic_jsonl(output_path, predictions)
    return {
        "path": str(output_path),
        "sha256": _sha256(output_path),
        "records": len(predictions),
        "source_predictions": {"path": str(run_predictions_path), "sha256": _sha256(run_predictions_path)},
    }


def evaluate_predictions(
    *, review_directory: Path, split_path: Path, predictions_path: Path, output_path: Path, baseline_id: str
) -> dict[str, Any]:
    full_labels = validate_frozen_machine_reference_package(
        review_directory / "machine-reference-labels.jsonl"
    )
    label_by_id = {row["finding_id"]: row for row in full_labels}
    split_rows = _load_jsonl(split_path)
    predictions = _load_jsonl(predictions_path)
    ids = [row["finding_id"] for row in split_rows]
    if len(ids) != len(set(ids)) or set(ids) != {row.get("finding_id") for row in predictions}:
        raise ValueError("split and baseline prediction IDs differ")
    labels = [label_by_id[finding_id] for finding_id in ids]
    report = machine_reference_metrics(labels, predictions)
    prediction_by_id = {row["finding_id"]: row for row in predictions}

    def summarize(group_rows: list[dict[str, Any]]) -> dict[str, Any]:
        group_labels = [label_by_id[row["finding_id"]] for row in group_rows]
        group_predictions = [prediction_by_id[row["finding_id"]] for row in group_rows]
        metrics = machine_reference_metrics(group_labels, group_predictions)
        return {
            "records": len(group_rows),
            "confusion_matrix_decided_only": metrics["confusion_matrix_decided_only"],
            "metrics_decided_only": metrics["metrics_decided_only"],
            "metrics_end_to_end": metrics["metrics_end_to_end"],
            "coverage": metrics["coverage"],
        }

    dimensions: dict[str, dict[str, list[dict[str, Any]]]] = {
        "repository": defaultdict(list),
        "rule": defaultdict(list),
        "cwe": defaultdict(list),
        "language": defaultdict(list),
        "dataflow": defaultdict(list),
    }
    for row in split_rows:
        features = row["features"]
        dimensions["repository"][features["repository"]].append(row)
        dimensions["rule"][features["rule_id"]].append(row)
        dimensions["language"][features["language"]].append(row)
        dimensions["dataflow"]["with_trace" if features["has_dataflow"] else "without_trace"].append(row)
        for cwe in features["cwes"] or ["UNKNOWN"]:
            dimensions["cwe"][cwe].append(row)
    report["breakdowns"] = {
        dimension: {key: summarize(group) for key, group in sorted(groups.items())}
        for dimension, groups in dimensions.items()
    }
    report.update(
        {
            "schema_version": 1,
            "baseline_id": baseline_id,
            "evaluation_scope": "LEAK_FREE_BALANCED_TEST_SPLIT",
            "reference_release": review_directory.name,
            "inputs": {
                "split": {"path": str(split_path), "sha256": _sha256(split_path)},
                "predictions": {"path": str(predictions_path), "sha256": _sha256(predictions_path)},
                "full_reference_labels_sha256": _sha256(review_directory / "machine-reference-labels.jsonl"),
            },
        }
    )
    _atomic_json(output_path, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the post-freeze OpenGrep machine dataset and leak-free benchmark.")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--review-dir", type=Path, required=True)
    build.add_argument("--entries", type=Path, default=Path("benchmark/VulnGym/data/entries.jsonl"))
    build.add_argument("--dataset", type=Path, required=True)
    build.add_argument("--manifest", type=Path, required=True)
    build.add_argument("--schema", type=Path, default=Path("schemas/machine-enriched-finding.schema.json"))
    build.add_argument("--created-at", required=True)
    split = commands.add_parser("split")
    split.add_argument("--dataset", type=Path, required=True)
    split.add_argument("--manifest", type=Path, required=True)
    split.add_argument("--output-dir", type=Path, required=True)
    split.add_argument("--seed", required=True)
    split.add_argument("--created-at", required=True)
    raw = commands.add_parser("raw-baseline")
    raw.add_argument("--split", type=Path, required=True)
    raw.add_argument("--output", type=Path, required=True)
    prepare = commands.add_parser("prepare-agent-input")
    prepare.add_argument("--review-dir", type=Path, required=True)
    prepare.add_argument("--split", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    imported = commands.add_parser("import-agent-predictions")
    imported.add_argument("--run-predictions", type=Path, required=True)
    imported.add_argument("--split", type=Path, required=True)
    imported.add_argument("--output", type=Path, required=True)
    imported.add_argument("--baseline-id", required=True)
    imported.add_argument("--navigation", action="store_true")
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--review-dir", type=Path, required=True)
    evaluate.add_argument("--split", type=Path, required=True)
    evaluate.add_argument("--predictions", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    evaluate.add_argument("--baseline-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = build_dataset(review_directory=args.review_dir, entries_path=args.entries, dataset_path=args.dataset, manifest_path=args.manifest, schema_path=args.schema, created_at=args.created_at)
        elif args.command == "split":
            result = create_splits(dataset_path=args.dataset, manifest_path=args.manifest, output_directory=args.output_dir, seed=args.seed, created_at=args.created_at)
        elif args.command == "raw-baseline":
            result = create_raw_predictions(split_path=args.split, output_path=args.output)
        elif args.command == "prepare-agent-input":
            result = prepare_agent_input(review_directory=args.review_dir, split_path=args.split, output_path=args.output)
        elif args.command == "import-agent-predictions":
            result = import_agent_predictions(run_predictions_path=args.run_predictions, split_path=args.split, output_path=args.output, baseline_id=args.baseline_id, navigation=args.navigation)
        else:
            result = evaluate_predictions(review_directory=args.review_dir, split_path=args.split, predictions_path=args.predictions, output_path=args.output, baseline_id=args.baseline_id)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
