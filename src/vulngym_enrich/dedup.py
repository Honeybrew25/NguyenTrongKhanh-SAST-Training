from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from .matcher import LineSpan, normalize_commit, normalize_path, normalize_repo

DEFAULT_LINE_TOLERANCE = 5


def _sha256_json(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _scanner_name(finding: dict[str, Any]) -> str:
    scanner = finding.get("scanner")
    if not isinstance(scanner, dict) or not isinstance(scanner.get("name"), str):
        return ""
    return scanner["name"].strip().casefold()


def _scanner_version(finding: dict[str, Any]) -> str:
    scanner = finding.get("scanner")
    if not isinstance(scanner, dict) or not isinstance(scanner.get("version"), str):
        return ""
    return scanner["version"].strip()


def _rule_id(finding: dict[str, Any]) -> str:
    rule = finding.get("rule")
    if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
        return ""
    return rule["id"].strip().casefold()


def _ruleset_commit(finding: dict[str, Any]) -> str:
    rule = finding.get("rule")
    if not isinstance(rule, dict) or not isinstance(rule.get("ruleset_commit"), str):
        return ""
    return rule["ruleset_commit"].strip().lower()


def _location(finding: dict[str, Any]) -> dict[str, Any]:
    value = finding.get("location")
    return value if isinstance(value, dict) else {}


def _location_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    location = _location(finding)
    return (
        normalize_path(location.get("file")),
        location.get("start_line"),
        location.get("end_line"),
        location.get("start_col"),
        location.get("end_col"),
    )


def _snapshot_key(finding: dict[str, Any]) -> tuple[str, str]:
    return normalize_repo(finding.get("repo_url")), normalize_commit(finding.get("commit"))


def _exact_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    """Identity of one scanner observation before cross-tool clustering."""

    return (
        *_snapshot_key(finding),
        _scanner_name(finding),
        _scanner_version(finding),
        _rule_id(finding),
        _ruleset_commit(finding),
        *_location_key(finding),
    )


def _line_span(finding: dict[str, Any]) -> LineSpan:
    location = _location(finding)
    start = location.get("start_line")
    end = location.get("end_line")
    if isinstance(start, bool) or not isinstance(start, int) or start < 1:
        raise ValueError("location.start_line must be a positive integer")
    if isinstance(end, bool) or not isinstance(end, int) or end < start:
        raise ValueError("location.end_line must be an integer not smaller than start_line")
    return LineSpan(start, end)


def _cwes(finding: dict[str, Any]) -> set[str]:
    rule = finding.get("rule") or {}
    raw = rule.get("cwe") if isinstance(rule, dict) else None
    if not isinstance(raw, list):
        return set()
    return {str(value).strip().casefold() for value in raw if str(value).strip()}


def _categories(finding: dict[str, Any]) -> set[str]:
    rule = finding.get("rule") or {}
    raw = rule.get("category") if isinstance(rule, dict) else None
    values = raw if isinstance(raw, list) else [raw]
    categories: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        categories.update(
            part.strip().casefold()
            for part in re.split(r"[,;|]", value)
            if part.strip()
        )
    return categories


def _normalized_snippet(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = " ".join(value.split())
    return normalized or None


def _actual_snippet_fingerprint(finding: dict[str, Any]) -> str | None:
    snippet = _normalized_snippet(finding.get("snippet"))
    return hashlib.sha256(snippet.encode("utf-8")).hexdigest() if snippet else None


def _evidence_fingerprint(finding: dict[str, Any]) -> str | None:
    snippet_fingerprint = _actual_snippet_fingerprint(finding)
    if snippet_fingerprint:
        return snippet_fingerprint
    value = finding.get("fingerprint")
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    return None if value.casefold() == "requires login" else value.casefold()


def _columns_are_disjoint(a: dict[str, Any], b: dict[str, Any]) -> bool:
    a_location = _location(a)
    b_location = _location(b)
    if not (
        a_location.get("start_line") == a_location.get("end_line")
        == b_location.get("start_line")
        == b_location.get("end_line")
    ):
        return False
    values = (
        a_location.get("start_col"),
        a_location.get("end_col"),
        b_location.get("start_col"),
        b_location.get("end_col"),
    )
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        return False
    a_start, a_end, b_start, b_end = values
    return a_end < b_start or b_end < a_start


def _shared_evidence(a: dict[str, Any], b: dict[str, Any]) -> bool:
    same_rule = bool(_rule_id(a)) and _rule_id(a) == _rule_id(b)
    a_fingerprint = _evidence_fingerprint(a)
    b_fingerprint = _evidence_fingerprint(b)
    same_fingerprint = bool(a_fingerprint) and a_fingerprint == b_fingerprint
    same_cwe = bool(_cwes(a) & _cwes(b))
    same_category = bool(_categories(a) & _categories(b))
    return same_rule or same_fingerprint or same_cwe or same_category


def semantic_match(a: dict[str, Any], b: dict[str, Any], line_tolerance: int) -> bool:
    """Return whether observations from two different tools describe one sink.

    Shared evidence is necessary but not sufficient. Conflicting CWE or concrete
    snippet evidence, and disjoint same-line columns, prevent an unsafe merge.
    """

    if line_tolerance < 0:
        raise ValueError("line_tolerance must be non-negative")
    if _scanner_name(a) == _scanner_name(b):
        return False
    if _snapshot_key(a) != _snapshot_key(b):
        return False
    if _location_key(a)[0] != _location_key(b)[0]:
        return False
    if _line_span(a).distance(_line_span(b)) > line_tolerance:
        return False

    a_cwes, b_cwes = _cwes(a), _cwes(b)
    if a_cwes and b_cwes and not a_cwes.intersection(b_cwes):
        return False
    a_snippet = _actual_snippet_fingerprint(a)
    b_snippet = _actual_snippet_fingerprint(b)
    if a_snippet and b_snippet and a_snippet != b_snippet:
        return False
    if _columns_are_disjoint(a, b):
        return False
    return _shared_evidence(a, b)


def _validate_finding(finding: Any, index: int) -> None:
    if not isinstance(finding, dict):
        raise ValueError(f"finding[{index}] must be an object")
    if not isinstance(finding.get("finding_id"), str) or not finding["finding_id"].strip():
        raise ValueError(f"finding[{index}].finding_id must be a non-empty string")
    repo_url, commit = _snapshot_key(finding)
    if not repo_url or not commit:
        raise ValueError(f"finding[{index}] has an invalid snapshot")
    if not _scanner_name(finding) or not _scanner_version(finding):
        raise ValueError(f"finding[{index}] has an invalid scanner")
    if not _rule_id(finding) or not _ruleset_commit(finding):
        raise ValueError(f"finding[{index}] has an invalid rule")
    if not _location_key(finding)[0]:
        raise ValueError(f"finding[{index}].location.file must be non-empty")
    _line_span(finding)
    provenance = finding.get("provenance")
    if not isinstance(provenance, dict) or not isinstance(provenance.get("raw_result_ref"), str):
        raise ValueError(f"finding[{index}] has invalid provenance.raw_result_ref")
    if not provenance["raw_result_ref"].strip():
        raise ValueError(f"finding[{index}].provenance.raw_result_ref must not be empty")


def _finding_sort_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    location = _location_key(finding)
    sortable_location = (
        location[0],
        location[1],
        location[2],
        -1 if location[3] is None else location[3],
        -1 if location[4] is None else location[4],
    )
    return (
        *_snapshot_key(finding),
        *sortable_location,
        _scanner_name(finding),
        _scanner_version(finding),
        _rule_id(finding),
        finding["finding_id"],
        finding["provenance"]["raw_result_ref"],
    )


def _groups_compatible(
    left: list[dict[str, Any]], right: list[dict[str, Any]], line_tolerance: int
) -> bool:
    return all(semantic_match(a, b, line_tolerance) for a in left for b in right)


def _cluster_compatible(
    left: list[list[dict[str, Any]]],
    right: list[list[dict[str, Any]]],
    line_tolerance: int,
) -> bool:
    return all(
        _groups_compatible(left_group, right_group, line_tolerance)
        for left_group in left
        for right_group in right
    )


def _group_sort_key(group: list[dict[str, Any]]) -> tuple[Any, ...]:
    return _finding_sort_key(group[0])


def _cluster_sort_key(cluster: list[list[dict[str, Any]]]) -> tuple[Any, ...]:
    return min(_group_sort_key(group) for group in cluster)


def _canonical_id(members: list[dict[str, Any]]) -> str:
    identities = sorted(
        {
            (
                finding["finding_id"],
                *_exact_key(finding),
            )
            for finding in members
        },
        key=lambda value: tuple(str(part) for part in value),
    )
    return f"canonical-{_sha256_json(identities)}"


def _observed_by(members: list[dict[str, Any]]) -> list[dict[str, str]]:
    observations: set[tuple[str, str]] = set()
    for finding in members:
        observations.add((_scanner_name(finding), str((finding.get("rule") or {}).get("id") or "").strip()))
        provenance = finding.get("provenance") or {}
        for observation in provenance.get("observed_by") or []:
            if not isinstance(observation, dict):
                continue
            scanner = observation.get("scanner")
            rule_id = observation.get("rule_id")
            if isinstance(scanner, str) and scanner.strip() and isinstance(rule_id, str) and rule_id.strip():
                observations.add((scanner.strip().casefold(), rule_id.strip()))
    return [
        {"scanner": scanner, "rule_id": rule_id}
        for scanner, rule_id in sorted(observations)
    ]


def _cluster_summary(
    canonical_id: str, members: list[dict[str, Any]]
) -> dict[str, Any]:
    scanners = sorted({_scanner_name(finding) for finding in members})
    finding_ids = sorted({finding["finding_id"] for finding in members})
    rule_ids = sorted({str((finding.get("rule") or {}).get("id") or "") for finding in members})
    spans = [_line_span(finding) for finding in members]
    if len(scanners) > 1:
        cluster_type = "CROSS_TOOL_SEMANTIC"
    elif len(members) > 1:
        cluster_type = "EXACT_DUPLICATE"
    else:
        cluster_type = "SINGLETON"
    return {
        "canonical_finding_id": canonical_id,
        "cluster_type": cluster_type,
        "repo_url": normalize_repo(members[0].get("repo_url")),
        "commit": normalize_commit(members[0].get("commit")),
        "file": normalize_path(_location(members[0]).get("file")),
        "start_line": min(span.start for span in spans),
        "end_line": max(span.end for span in spans),
        "member_count": len(members),
        "finding_ids": finding_ids,
        "scanners": scanners,
        "rule_ids": rule_ids,
        "observed_by": _observed_by(members),
    }


def deduplicate_findings(
    findings: Iterable[dict[str, Any]], line_tolerance: int = DEFAULT_LINE_TOLERANCE
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Assign canonical clusters while retaining every raw observation."""

    if line_tolerance < 0:
        raise ValueError("line_tolerance must be non-negative")
    rows = [copy.deepcopy(finding) for finding in findings]
    for index, finding in enumerate(rows):
        _validate_finding(finding, index)

    identity_by_finding_id: dict[str, tuple[Any, ...]] = {}
    for finding in rows:
        finding_id = finding["finding_id"]
        identity = _exact_key(finding)
        previous = identity_by_finding_id.setdefault(finding_id, identity)
        if previous != identity:
            raise ValueError(f"finding_id {finding_id!r} refers to conflicting observations")

    exact_by_key: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for finding in rows:
        exact_by_key[_exact_key(finding)].append(finding)
    exact_groups = [sorted(group, key=_finding_sort_key) for group in exact_by_key.values()]
    exact_groups.sort(key=_group_sort_key)

    clusters: list[list[list[dict[str, Any]]]] = [[group] for group in exact_groups]
    semantic_buckets: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for index, group in enumerate(exact_groups):
        representative = group[0]
        semantic_buckets[
            (*_snapshot_key(representative), normalize_path(_location(representative).get("file")))
        ].append(index)
    candidate_pairs: list[tuple[int, int]] = []
    for bucket in semantic_buckets.values():
        bucket.sort(
            key=lambda index: (
                _line_span(exact_groups[index][0]).start,
                _line_span(exact_groups[index][0]).end,
                _group_sort_key(exact_groups[index]),
            )
        )
        for offset, left_index in enumerate(bucket):
            left_span = _line_span(exact_groups[left_index][0])
            for right_index in bucket[offset + 1 :]:
                right_span = _line_span(exact_groups[right_index][0])
                if right_span.start - left_span.end > line_tolerance:
                    break
                if _cluster_compatible(clusters[left_index], clusters[right_index], line_tolerance):
                    candidate_pairs.append((left_index, right_index))
    candidate_pairs.sort(
        key=lambda pair: (_cluster_sort_key(clusters[pair[0]]), _cluster_sort_key(clusters[pair[1]]))
    )

    parent = list(range(len(clusters)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    for left_index, right_index in candidate_pairs:
        left_root, right_root = find(left_index), find(right_index)
        if left_root == right_root:
            continue
        left_cluster, right_cluster = clusters[left_root], clusters[right_root]
        if not _cluster_compatible(left_cluster, right_cluster, line_tolerance):
            continue
        if _cluster_sort_key(right_cluster) < _cluster_sort_key(left_cluster):
            left_root, right_root = right_root, left_root
            left_cluster, right_cluster = right_cluster, left_cluster
        clusters[left_root] = sorted(left_cluster + right_cluster, key=_group_sort_key)
        clusters[right_root] = []
        parent[right_root] = left_root

    final_clusters = [cluster for index, cluster in enumerate(clusters) if find(index) == index and cluster]
    final_clusters.sort(key=_cluster_sort_key)

    summaries: list[dict[str, Any]] = []
    output: list[dict[str, Any]] = []
    for cluster in final_clusters:
        members = sorted(
            (finding for exact_group in cluster for finding in exact_group),
            key=_finding_sort_key,
        )
        canonical_id = _canonical_id(members)
        observations = _observed_by(members)
        for finding in members:
            finding["canonical_finding_id"] = canonical_id
            finding["provenance"]["observed_by"] = copy.deepcopy(observations)
            output.append(finding)
        summaries.append(_cluster_summary(canonical_id, members))

    output.sort(key=_finding_sort_key)
    summaries.sort(key=lambda summary: summary["canonical_finding_id"])
    cross_tool_clusters = sum(summary["cluster_type"] == "CROSS_TOOL_SEMANTIC" for summary in summaries)
    exact_duplicate_clusters = sum(summary["cluster_type"] == "EXACT_DUPLICATE" for summary in summaries)
    statistics = {
        "input_findings": len(rows),
        "output_findings": len(output),
        "exact_groups": len(exact_groups),
        "exact_duplicate_observations": len(rows) - len(exact_groups),
        "canonical_clusters": len(summaries),
        "cross_tool_merges": len(exact_groups) - len(summaries),
        "cross_tool_clusters": cross_tool_clusters,
        "exact_duplicate_clusters": exact_duplicate_clusters,
        "singleton_clusters": sum(summary["cluster_type"] == "SINGLETON" for summary in summaries),
        "findings_with_canonical_id": sum(bool(finding.get("canonical_finding_id")) for finding in output),
    }
    summary = {
        "policy": {
            "exact_key": "snapshot + scanner/version + rule/ruleset + normalized location",
            "semantic_scope": "different scanners, same snapshot and file",
            "line_tolerance": line_tolerance,
            "shared_evidence": "same rule id OR snippet fingerprint OR intersecting CWE/category",
            "conflict_vetoes": ["disjoint CWE", "different concrete snippets", "disjoint same-line columns"],
            "retains_raw_observations": True,
        },
        "statistics": statistics,
        "clusters": summaries,
    }
    return output, summary


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: finding must be an object")
            rows.append(value)
    return rows


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows)
    path.write_text(payload, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deduplicate normalized scanner findings without dropping evidence.")
    parser.add_argument(
        "--input",
        "--findings",
        dest="inputs",
        action="append",
        type=Path,
        required=True,
        help="repeat for findings from multiple scanners",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--line-tolerance", type=int, default=DEFAULT_LINE_TOLERANCE)
    args = parser.parse_args(argv)
    if args.line_tolerance < 0:
        parser.error("--line-tolerance must be non-negative")

    rows = [finding for path in args.inputs for finding in _load_jsonl(path)]
    findings, summary = deduplicate_findings(rows, args.line_tolerance)
    _write_jsonl(args.output, findings)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary["statistics"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
