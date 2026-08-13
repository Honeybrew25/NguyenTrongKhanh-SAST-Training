from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


@dataclass
class PopulationUnit:
    canonical_finding_id: str
    representative: dict[str, Any]
    member_count: int


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _portable(path: Path, project_root: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def _atomic_write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    count = 0
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
            count += 1
    os.replace(temporary, path)
    return count


def _scanner_name(finding: dict[str, Any]) -> str:
    scanner = finding.get("scanner")
    return str(scanner.get("name") or "") if isinstance(scanner, dict) else ""


def _finding_id(finding: dict[str, Any]) -> str:
    value = finding.get("finding_id")
    if not isinstance(value, str) or not value:
        raise ValueError("finding is missing finding_id")
    return value


def _canonical_id(finding: dict[str, Any]) -> str:
    value = finding.get("canonical_finding_id") or finding.get("finding_id")
    if not isinstance(value, str) or not value:
        raise ValueError("finding is missing canonical_finding_id/finding_id")
    return value


def _snapshot_identity(finding: dict[str, Any]) -> tuple[str, str]:
    repo_url = str(finding.get("repo_url") or "")
    commit = str(finding.get("commit") or "")
    if not repo_url.startswith("https://github.com/") or len(commit) != 40:
        raise ValueError(f"finding has invalid snapshot identity: {_finding_id(finding)}")
    return repo_url, commit


def load_population(path: Path, scanner_name: str = "semgrep") -> list[PopulationUnit]:
    representatives: dict[str, dict[str, Any]] = {}
    member_counts: Counter[str] = Counter()
    identities: dict[str, tuple[str, str]] = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                finding = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(finding, dict):
                raise ValueError(f"{path}:{line_number}: expected a JSON object")
            observed_scanner = _scanner_name(finding)
            if observed_scanner != scanner_name:
                raise ValueError(
                    f"{path}:{line_number}: expected scanner {scanner_name}, "
                    f"got {observed_scanner or 'missing'}"
                )
            canonical_id = _canonical_id(finding)
            identity = _snapshot_identity(finding)
            previous_identity = identities.setdefault(canonical_id, identity)
            if previous_identity != identity:
                raise ValueError(
                    f"canonical cluster spans different snapshots: {canonical_id}"
                )
            member_counts[canonical_id] += 1
            current = representatives.get(canonical_id)
            if current is None or _finding_id(finding) < _finding_id(current):
                representatives[canonical_id] = finding
    if not representatives:
        raise ValueError(f"population input is empty: {path}")
    return [
        PopulationUnit(
            canonical_finding_id=canonical_id,
            representative=representatives[canonical_id],
            member_count=member_counts[canonical_id],
        )
        for canonical_id in representatives
    ]


def _rule_id(finding: dict[str, Any]) -> str:
    rule = finding.get("rule")
    return str(rule.get("id") or "UNKNOWN") if isinstance(rule, dict) else "UNKNOWN"


def _severity(finding: dict[str, Any]) -> str:
    rule = finding.get("rule")
    value = rule.get("severity") if isinstance(rule, dict) else None
    return str(value or "UNKNOWN").upper()


def _has_dataflow(finding: dict[str, Any]) -> bool:
    value = finding.get("dataflow_trace")
    return isinstance(value, list) and bool(value)


def _language(finding: dict[str, Any]) -> str:
    location = finding.get("location")
    file_path = str(location.get("file") or "") if isinstance(location, dict) else ""
    suffix = Path(file_path.casefold()).suffix
    if suffix == ".py":
        return "python"
    if suffix == ".go":
        return "go"
    if suffix in {".ts", ".tsx", ".mts", ".cts"}:
        return "typescript"
    if suffix in {".js", ".jsx", ".mjs", ".cjs"}:
        return "javascript"
    return suffix.removeprefix(".") or "unknown"


def _implicit_sort_key(unit: PopulationUnit) -> tuple[Any, ...]:
    finding = unit.representative
    location = finding.get("location")
    location = location if isinstance(location, dict) else {}
    return (
        str(finding.get("repo_url") or "").casefold(),
        _rule_id(finding).casefold(),
        _severity(finding),
        _has_dataflow(finding),
        str(finding.get("commit") or ""),
        str(location.get("file") or "").casefold(),
        int(location.get("start_line") or 0),
        unit.canonical_finding_id,
    )


def systematic_sample(
    units: list[PopulationUnit], sample_size: int, seed: str
) -> tuple[list[tuple[int, PopulationUnit]], float, float]:
    if not seed:
        raise ValueError("sampling seed must not be empty")
    if sample_size < 1 or sample_size > len(units):
        raise ValueError(
            f"sample size must be between 1 and population size {len(units)}"
        )
    ordered = sorted(units, key=_implicit_sort_key)
    interval = len(ordered) / sample_size
    seed_fraction = int.from_bytes(hashlib.sha256(seed.encode()).digest(), "big") / (
        1 << 256
    )
    random_start = seed_fraction * interval
    positions = [math.floor(random_start + index * interval) for index in range(sample_size)]
    if len(set(positions)) != sample_size or positions[-1] >= len(ordered):
        raise AssertionError("systematic sampling produced invalid positions")
    selected = [(position, ordered[position]) for position in positions]
    selected.sort(
        key=lambda item: hashlib.sha256(
            f"{seed}\0review-order\0{item[1].canonical_finding_id}".encode()
        ).digest()
    )
    return selected, interval, random_start


def _distribution(units: Iterable[PopulationUnit]) -> dict[str, Any]:
    typed = list(units)
    return {
        "records": len(typed),
        "repositories": dict(
            sorted(Counter(unit.representative["repo_url"] for unit in typed).items())
        ),
        "rules": dict(sorted(Counter(_rule_id(unit.representative) for unit in typed).items())),
        "severity": dict(
            sorted(Counter(_severity(unit.representative) for unit in typed).items())
        ),
        "dataflow": {
            "with_trace": sum(_has_dataflow(unit.representative) for unit in typed),
            "without_trace": sum(not _has_dataflow(unit.representative) for unit in typed),
        },
        "languages": dict(
            sorted(Counter(_language(unit.representative) for unit in typed).items())
        ),
    }


def _label_template(finding_id: str) -> dict[str, Any]:
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


def create_sample(
    *,
    project_root: Path,
    population_path: Path,
    pipeline_summary_path: Path,
    schema_path: Path,
    output_directory: Path,
    sample_id: str,
    sample_size: int,
    seed: str,
    created_at: str,
    scanner_name: str = "semgrep",
    expected_population: int | None = None,
) -> dict[str, Any]:
    project_root = project_root.resolve()
    population_path = population_path.resolve()
    pipeline_summary_path = pipeline_summary_path.resolve()
    schema_path = schema_path.resolve()
    output_directory = output_directory.resolve()
    datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    pipeline = _read_json(pipeline_summary_path)
    coverage = pipeline.get("coverage")
    if not isinstance(coverage, dict) or coverage.get("complete") is not True:
        raise ValueError("source pipeline coverage must be complete")
    units = load_population(population_path, scanner_name=scanner_name)
    if expected_population is not None and len(units) != expected_population:
        raise ValueError(
            f"expected {expected_population} canonical clusters, found {len(units)}"
        )
    selected, interval, random_start = systematic_sample(units, sample_size, seed)
    selected_units = [unit for _, unit in selected]
    finding_ids = [_finding_id(unit.representative) for unit in selected_units]
    canonical_ids = [unit.canonical_finding_id for unit in selected_units]
    if len(set(finding_ids)) != sample_size or len(set(canonical_ids)) != sample_size:
        raise AssertionError("sample contains duplicate identities")

    generation_identity = {
        "sample_id": sample_id,
        "population_sha256": _sha256(population_path),
        "pipeline_summary_sha256": _sha256(pipeline_summary_path),
        "sample_size": sample_size,
        "seed": seed,
        "scanner": scanner_name,
        "method": "equal-probability systematic sample with implicit stratification",
    }
    manifest_path = output_directory / "sample-manifest.json"
    if manifest_path.exists():
        existing = _read_json(manifest_path)
        if existing.get("generation_identity") != generation_identity:
            raise ValueError(f"existing sample has a different identity: {manifest_path}")
        for output in existing.get("outputs", {}).values():
            if not isinstance(output, dict):
                continue
            path = output_directory / str(output.get("path") or "")
            if not path.is_file() or _sha256(path) != output.get("sha256"):
                raise ValueError(f"existing sample output is missing or modified: {path}")
        return existing

    output_directory.mkdir(parents=True, exist_ok=False)
    findings_path = output_directory / "sampled-findings.jsonl"
    index_path = output_directory / "sampling-index.jsonl"
    template_path = output_directory / "human-gold-labels.template.jsonl"
    copied_schema_path = output_directory / "human-gold-label.schema.json"
    _atomic_write_jsonl(findings_path, (unit.representative for unit in selected_units))
    weight = len(units) / sample_size
    _atomic_write_jsonl(
        index_path,
        (
            {
                "schema_version": 1,
                "sample_id": sample_id,
                "review_order": review_order,
                "population_position": position,
                "finding_id": _finding_id(unit.representative),
                "canonical_finding_id": unit.canonical_finding_id,
                "canonical_member_count": unit.member_count,
                "inclusion_probability": sample_size / len(units),
                "analysis_weight": weight,
                "repository": unit.representative["repo_url"],
                "rule_id": _rule_id(unit.representative),
                "severity": _severity(unit.representative),
                "has_dataflow_trace": _has_dataflow(unit.representative),
                "language": _language(unit.representative),
            }
            for review_order, (position, unit) in enumerate(selected, 1)
        ),
    )
    _atomic_write_jsonl(template_path, (_label_template(finding_id) for finding_id in finding_ids))
    shutil.copyfile(schema_path, copied_schema_path)

    finite_population_correction = math.sqrt((len(units) - sample_size) / (len(units) - 1))
    worst_case_margin = (
        1.96 * math.sqrt(0.25 / sample_size) * finite_population_correction
        if len(units) > 1
        else 0.0
    )
    outputs = {}
    for path, records in (
        (findings_path, sample_size),
        (index_path, sample_size),
        (template_path, sample_size),
        (copied_schema_path, None),
    ):
        outputs[path.name] = {
            "path": path.name,
            "sha256": _sha256(path),
            "records": records,
        }
    manifest = {
        "schema_version": 1,
        "sample_id": sample_id,
        "created_at": created_at,
        "status": "SAMPLED_AWAITING_HUMAN_LABELS",
        "generation_identity": generation_identity,
        "source": {
            "scanner": scanner_name,
            "scan_id": pipeline.get("scan_id"),
            "population_unit": "canonical_cluster",
            "population_path": _portable(population_path, project_root),
            "population_sha256": generation_identity["population_sha256"],
            "pipeline_summary_path": _portable(pipeline_summary_path, project_root),
            "pipeline_summary_sha256": generation_identity[
                "pipeline_summary_sha256"
            ],
            "coverage": coverage,
        },
        "sampling": {
            "population_size": len(units),
            "sample_size": sample_size,
            "method": generation_identity["method"],
            "seed": seed,
            "implicit_sort_keys": [
                "repository",
                "rule_id",
                "severity",
                "has_dataflow_trace",
                "commit",
                "file",
                "start_line",
                "canonical_finding_id",
            ],
            "systematic_interval": interval,
            "random_start": random_start,
            "inclusion_probability": sample_size / len(units),
            "analysis_weight": weight,
            "confidence_note": (
                "Worst-case 95% margin for an unweighted binary proportion; "
                "excludes labeling error and design/model bias."
            ),
            "worst_case_95_percent_margin": worst_case_margin,
        },
        "distribution": {
            "population": _distribution(units),
            "sample": _distribution(selected_units),
        },
        "leakage_control": {
            "vulngym_match_metadata_included": False,
            "agent_predictions_included": False,
            "prior_human_labels_included": False,
            "review_order_randomized_after_selection": True,
        },
        "outputs": outputs,
        "next_gate": (
            "A human reviewer must copy the label template to human-gold-labels.jsonl "
            "and replace every placeholder with source-backed labels."
        ),
    }
    _atomic_write_json(manifest_path, manifest)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create an equal-probability human-review sample from scanner canonical clusters."
    )
    parser.add_argument("--population", type=Path, required=True)
    parser.add_argument("--pipeline-summary", type=Path, required=True)
    parser.add_argument(
        "--schema", type=Path, default=Path("schemas/human-gold-label.schema.json")
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--sample-size", type=int, default=400)
    parser.add_argument("--scanner", choices=("semgrep", "opengrep"), default="semgrep")
    parser.add_argument("--seed", default="representative-r1-20260812")
    parser.add_argument(
        "--created-at",
        default=datetime.now(timezone.utc).isoformat(),
        help="fixed ISO-8601 timestamp recorded in the immutable manifest",
    )
    parser.add_argument("--expected-population", type=int)
    args = parser.parse_args(argv)
    try:
        manifest = create_sample(
            project_root=Path.cwd(),
            population_path=args.population,
            pipeline_summary_path=args.pipeline_summary,
            schema_path=args.schema,
            output_directory=args.output_dir,
            sample_id=args.sample_id,
            sample_size=args.sample_size,
            seed=args.seed,
            created_at=args.created_at,
            scanner_name=args.scanner,
            expected_population=args.expected_population,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "status": manifest["status"],
                "population_size": manifest["sampling"]["population_size"],
                "sample_size": manifest["sampling"]["sample_size"],
                "worst_case_95_percent_margin": manifest["sampling"][
                    "worst_case_95_percent_margin"
                ],
                "output": str((args.output_dir / "sample-manifest.json").resolve()),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
