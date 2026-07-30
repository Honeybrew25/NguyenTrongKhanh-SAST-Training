from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .matcher import LineSpan

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_ENTRY_ID = re.compile(r"^entry-\d{5}$")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
    return rows


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_node(node: Any, context: str) -> None:
    if not isinstance(node, dict):
        raise ValueError(f"{context}: node must be an object")
    missing = {"file", "line", "code"} - set(node)
    if missing:
        raise ValueError(f"{context}: missing keys {sorted(missing)}")
    if not isinstance(node["file"], str) or not node["file"]:
        raise ValueError(f"{context}: file must be a non-empty string")
    if not isinstance(node["code"], str):
        raise ValueError(f"{context}: code must be a string")
    LineSpan.parse(node["line"])


def audit(benchmark: Path) -> tuple[dict[str, Any], list[str]]:
    entries_path = benchmark / "data" / "entries.jsonl"
    reports_path = benchmark / "data" / "reports.jsonl"
    entries = load_jsonl(entries_path)
    reports = load_jsonl(reports_path)
    errors: list[str] = []

    report_by_id = {row.get("report_id"): row for row in reports}
    if len(report_by_id) != len(reports):
        errors.append("duplicate report_id in reports.jsonl")

    entry_by_id = {row.get("entry_id"): row for row in entries}
    if len(entry_by_id) != len(entries):
        errors.append("duplicate entry_id in entries.jsonl")

    grouped_entries: dict[str, list[str]] = defaultdict(list)
    for index, entry in enumerate(entries, 1):
        context = f"entry row {index}"
        entry_id = entry.get("entry_id")
        report_id = entry.get("report_id")
        if not isinstance(entry_id, str) or not _ENTRY_ID.fullmatch(entry_id):
            errors.append(f"{context}: invalid entry_id {entry_id!r}")
        if report_id not in report_by_id:
            errors.append(f"{context}: unknown report_id {report_id!r}")
        else:
            grouped_entries[report_id].append(entry_id)
        if entry.get("verify") not in (0, 1):
            errors.append(f"{context}: verify must be 0 or 1")
        if not _SHA40.fullmatch(str(entry.get("commit", ""))):
            errors.append(f"{context}: invalid commit")
        if not str(entry.get("repo_url", "")).startswith("https://github.com/"):
            errors.append(f"{context}: invalid repo_url")
        for field in ("entry_point", "critical_operation"):
            try:
                _validate_node(entry.get(field), f"{context}.{field}")
            except ValueError as exc:
                errors.append(str(exc))
        trace = entry.get("trace")
        if not isinstance(trace, list):
            errors.append(f"{context}.trace: must be a list")
        else:
            for trace_index, node in enumerate(trace):
                try:
                    _validate_node(node, f"{context}.trace[{trace_index}]")
                except ValueError as exc:
                    errors.append(str(exc))

    for report_id, report in report_by_id.items():
        expected = sorted(grouped_entries.get(report_id, []))
        actual = report.get("entry_ids")
        if actual != expected:
            errors.append(f"report {report_id}: entry_ids do not match entries.jsonl")
        if report.get("num_entries") != len(expected):
            errors.append(f"report {report_id}: num_entries mismatch")

    snapshots: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in entries:
        key = (entry["repo_url"], entry["commit"])
        snapshot = snapshots.setdefault(
            key,
            {
                "repo_url": entry["repo_url"],
                "commit": entry["commit"],
                "projects": set(),
                "report_ids": set(),
                "entry_ids": [],
            },
        )
        snapshot["projects"].add(entry["project"])
        snapshot["report_ids"].add(entry["report_id"])
        snapshot["entry_ids"].append(entry["entry_id"])

    serialized_snapshots = []
    for snapshot in snapshots.values():
        serialized_snapshots.append(
            {
                **snapshot,
                "projects": sorted(snapshot["projects"]),
                "report_ids": sorted(snapshot["report_ids"]),
                "entry_ids": sorted(snapshot["entry_ids"]),
                "num_reports": len(snapshot["report_ids"]),
                "num_entries": len(snapshot["entry_ids"]),
            }
        )
    serialized_snapshots.sort(key=lambda item: (item["repo_url"], item["commit"]))

    try:
        benchmark_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=benchmark, check=True, text=True, capture_output=True
        ).stdout.strip()
        benchmark_tag = subprocess.run(
            ["git", "describe", "--tags", "--exact-match"], cwd=benchmark, check=True, text=True, capture_output=True
        ).stdout.strip()
    except subprocess.CalledProcessError:
        benchmark_commit = "unknown"
        benchmark_tag = "unknown"

    l1_reports: dict[str, set[str]] = defaultdict(set)
    for entry in entries:
        l1_reports[entry["vuln_category_l1"]].add(entry["report_id"])

    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark": {
            "name": "Tencent/VulnGym",
            "tag": benchmark_tag,
            "commit": benchmark_commit,
            "entries_sha256": sha256_file(entries_path),
            "reports_sha256": sha256_file(reports_path),
        },
        "statistics": {
            "reports": len(reports),
            "entries": len(entries),
            "verified_entries": sum(entry["verify"] == 1 for entry in entries),
            "unverified_entries": sum(entry["verify"] == 0 for entry in entries),
            "distinct_repositories": len({entry["repo_url"] for entry in entries}),
            "distinct_projects": len({entry["project"] for entry in entries}),
            "distinct_snapshots": len(serialized_snapshots),
            "entries_with_line_ranges": sum(
                any(isinstance(entry[field]["line"], str) and "-" in entry[field]["line"] for field in ("entry_point", "critical_operation"))
                for entry in entries
            ),
            "entries_by_repository": dict(sorted(Counter(entry["repo_url"] for entry in entries).items())),
            "advisories_by_l1_category": dict(sorted((category, len(ids)) for category, ids in l1_reports.items())),
        },
        "snapshots": serialized_snapshots,
    }
    return manifest, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate VulnGym and emit a reproducible snapshot manifest.")
    parser.add_argument("--benchmark", type=Path, default=Path("benchmark/VulnGym"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    manifest, errors = audit(args.benchmark)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        print(f"audit failed with {len(errors)} error(s)")
        return 1
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote manifest: {args.output}")
    print(json.dumps(manifest["statistics"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
