from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .audit import load_jsonl
from .matcher import endpoint_match, normalize_commit, normalize_repo
from .normalizer import write_jsonl

STRICT = "STRICT_SOURCE_SINK"
STRONG = "STRONG_SOURCE_SINK"
CANDIDATE = "CANDIDATE_REVIEW"
UNMATCHED = "UNMATCHED"
_TIER_RANK = {STRICT: 0, STRONG: 1, CANDIDATE: 2, UNMATCHED: 3}

_CWE = re.compile(r"CWE[-_/ ]?(\d+)", re.IGNORECASE)

# VulnGym stores vulnerability classes as free-text Chinese/English categories,
# while scanner rules normally expose CWE identifiers.  These deliberately
# broad families allow related CWEs (for example CWE-77 and CWE-78) to match the
# same benchmark category without treating the generic scanner category
# ``security`` as evidence of compatibility.
_CWE_FAMILIES: dict[str, frozenset[int]] = {
    "authentication": frozenset({287, 288, 290, 294, 305, 306, 307, 308, 521, 798}),
    "authorization": frozenset({269, 284, 285, 639, 862, 863}),
    "code_injection": frozenset({94, 95, 96, 917}),
    "command_injection": frozenset({77, 78, 88}),
    "deserialization": frozenset({502}),
    "dns_rebinding": frozenset({350}),
    "file_operation": frozenset({59, 73, 377, 378, 379, 434}),
    "information_disclosure": frozenset({200, 201, 203, 209, 212, 215, 359}),
    "mass_assignment": frozenset({915}),
    "origin_integrity": frozenset({345, 346, 347, 353, 494}),
    "path_traversal": frozenset({22, 23, 35, 36, 73}),
    "privilege_escalation": frozenset({250, 266, 269}),
    "prototype_pollution": frozenset({1321}),
    "race_condition": frozenset({362, 367}),
    "sandbox_escape": frozenset({265, 693}),
    "sql_injection": frozenset({89, 564, 943}),
    "ssrf": frozenset({441, 918}),
    "supply_chain": frozenset({494, 506, 829, 1104}),
    "template_injection": frozenset({1336}),
    "xss": frozenset({79, 80, 83, 87, 116}),
}

_CATEGORY_ALIASES: dict[str, tuple[str, ...]] = {
    "authentication": (
        "authentication bypass",
        "authentication",
        "auth bypass",
        "bl-auth-bypass",
        "身份认证",
        "认证绕过",
    ),
    "authorization": (
        "authorization",
        "authz",
        "bl-authz",
        "授权",
        "权限绕过",
        "越权",
    ),
    "code_injection": (
        "code injection",
        "eval injection",
        "expression injection",
        "代码注入",
        "表达式注入",
        "脚本生成注入",
    ),
    "command_injection": (
        "command injection",
        "os command",
        "shell injection",
        "命令注入",
    ),
    "deserialization": ("deserialization", "反序列化"),
    "dns_rebinding": ("dns rebinding", "dns重绑定"),
    "file_operation": (
        "arbitrary file",
        "file operation",
        "file upload",
        "任意文件",
        "文件操作",
        "文件读取",
        "文件写入",
    ),
    "information_disclosure": ("information disclosure", "信息泄露"),
    "mass_assignment": ("mass assignment", "参数/属性污染", "参数属性污染"),
    "origin_integrity": ("origin integrity", "来源/签名/完整性", "来源签名完整性"),
    "path_traversal": (
        "directory traversal",
        "path traversal",
        "zip slip",
        "路径穿越",
        "路径遍历",
    ),
    "privilege_escalation": ("privilege escalation", "特权提升"),
    "prototype_pollution": ("prototype pollution", "原型链污染"),
    "race_condition": ("race condition", "toctou", "竞争条件"),
    "sandbox_escape": ("sandbox escape", "sandbox bypass", "沙箱逃逸", "沙盒逃逸"),
    "sql_injection": ("sql injection", "sql注入", "sql 注入"),
    "ssrf": ("server-side request forgery", "ssrf", "服务端请求伪造"),
    "supply_chain": ("supply chain", "供应链攻击"),
    "template_injection": ("template injection", "ssti", "模板注入"),
    "xss": ("cross-site scripting", "stored xss", "xss", "跨站脚本", "存储型xss"),
}


def _location_node(finding: dict[str, Any]) -> dict[str, Any]:
    location = finding.get("location") or {}
    start = location.get("start_line")
    end = location.get("end_line")
    line: Any = start
    if isinstance(start, int) and isinstance(end, int) and start != end:
        line = f"{start}-{end}"
    return {"file": location.get("file"), "line": line}


def _trace_nodes(finding: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = []
    for node in finding.get("dataflow_trace") or []:
        if isinstance(node, dict):
            nodes.append({"file": node.get("file"), "line": node.get("line")})
    return nodes


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [text for item in value for text in _strings(item)]
    return []


def _cwes(values: Iterable[Any]) -> set[int]:
    found: set[int] = set()
    for value in values:
        for text in _strings(value):
            found.update(int(number) for number in _CWE.findall(text))
    return found


def _category_key(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _families_from_categories(values: Iterable[Any]) -> set[str]:
    categories = [_category_key(text) for value in values for text in _strings(value)]
    return {
        family
        for family, aliases in _CATEGORY_ALIASES.items()
        if any(_category_key(alias) in category for alias in aliases for category in categories)
    }


def _families_from_cwes(cwes: set[int]) -> set[str]:
    return {
        family for family, members in _CWE_FAMILIES.items() if cwes.intersection(members)
    }


def _category_cwe_compatibility(
    finding: dict[str, Any], entry: dict[str, Any]
) -> tuple[bool, list[str]]:
    rule = finding.get("rule") if isinstance(finding.get("rule"), dict) else {}
    finding_cwes = _cwes([rule.get("cwe")])
    entry_category_values = [
        entry.get("vuln_category_l1"),
        entry.get("vuln_category_l2"),
        entry.get("category"),
    ]
    entry_cwes = _cwes(
        [
            entry.get("cwe"),
            entry.get("cwes"),
            entry.get("vuln_cwe"),
            entry.get("vuln_cwes"),
            *entry_category_values,
        ]
    )
    finding_families = _families_from_cwes(finding_cwes) | _families_from_categories(
        [rule.get("category")]
    )
    entry_families = _families_from_cwes(entry_cwes) | _families_from_categories(
        entry_category_values
    )

    common_cwes = finding_cwes.intersection(entry_cwes)
    common_families = finding_families.intersection(entry_families)
    evidence = [f"cwe:CWE-{cwe}" for cwe in sorted(common_cwes)]
    evidence.extend(f"family:{family}" for family in sorted(common_families))
    return bool(evidence), evidence


def match_normalized_finding_entry(
    finding: dict[str, Any], entry: dict[str, Any], tolerance: int
) -> dict[str, Any] | None:
    sink = _location_node(finding)
    trace = _trace_nodes(finding)
    sink_exact = endpoint_match(sink, entry["critical_operation"], tolerance=0)
    source_exact = bool(trace) and any(
        endpoint_match(node, entry["entry_point"], tolerance=0) for node in trace
    )
    category_cwe_compatible, compatibility_evidence = _category_cwe_compatibility(
        finding, entry
    )
    if sink_exact and source_exact:
        tier = STRICT
        source_supported_by_trace = True
    else:
        sink_near = endpoint_match(sink, entry["critical_operation"], tolerance=tolerance)
        source_near = bool(trace) and any(
            endpoint_match(node, entry["entry_point"], tolerance=tolerance) for node in trace
        )
        if sink_near and source_near and category_cwe_compatible:
            tier = STRONG
        elif sink_near:
            tier = CANDIDATE
        else:
            return None
        source_supported_by_trace = source_near
    return {
        "tier": tier,
        "entry_id": entry["entry_id"],
        "report_id": entry["report_id"],
        "source_supported_by_trace": source_supported_by_trace,
        "sink_supported_by_location": True,
        "dataflow_supported": source_supported_by_trace,
        "category_cwe_compatible": category_cwe_compatible,
        "category_cwe_evidence": compatibility_evidence,
    }


def match_candidates(
    findings: Iterable[dict[str, Any]],
    entries: Iterable[dict[str, Any]],
    tolerance: int = 5,
    verified_only: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if tolerance < 0:
        raise ValueError("tolerance must be non-negative")
    by_snapshot: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    entries_considered = 0
    for entry in entries:
        if verified_only and entry.get("verify") != 1:
            continue
        entries_considered += 1
        by_snapshot[(normalize_repo(entry.get("repo_url")), normalize_commit(entry.get("commit")))].append(entry)

    output: list[dict[str, Any]] = []
    tier_counts: Counter[str] = Counter()
    for finding in findings:
        key = (normalize_repo(finding.get("repo_url")), normalize_commit(finding.get("commit")))
        matches = [
            match
            for entry in by_snapshot.get(key, [])
            if (match := match_normalized_finding_entry(finding, entry, tolerance)) is not None
        ]
        if matches:
            best_rank = min(_TIER_RANK[match["tier"]] for match in matches)
            matches = [match for match in matches if _TIER_RANK[match["tier"]] == best_rank]
            matches.sort(key=lambda match: (match["entry_id"], match["report_id"]))
            tier = matches[0]["tier"]
        else:
            tier = UNMATCHED
        tier_counts[tier] += 1
        output.append(
            {
                "finding_id": finding.get("finding_id"),
                "match_tier": tier,
                "matches": matches,
            }
        )
    summary = {
        "policy": {
            "strict": "exact source trace and sink location",
            "strong": (
                "source trace and sink location within line tolerance, with compatible "
                "CWE/vulnerability category"
            ),
            "candidate": (
                "sink location within line tolerance but missing compatible category/CWE "
                "or source dataflow evidence; human review required"
            ),
            "line_tolerance": tolerance,
            "verified_entries_only": verified_only,
            "unmatched_label_policy": "UNLABELED_NOT_FALSE_POSITIVE",
        },
        "total_findings": len(output),
        "entries_considered": entries_considered,
        "counts_by_tier": {tier: tier_counts[tier] for tier in (STRICT, STRONG, CANDIDATE, UNMATCHED)},
    }
    return output, summary


def aggregate_canonical_matches(
    findings: list[dict[str, Any]], matches: list[dict[str, Any]], summary: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if len(findings) != len(matches):
        raise ValueError("findings and matches must have the same length")
    groups: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for finding, match in zip(findings, matches, strict=True):
        canonical_id = finding.get("canonical_finding_id") or finding.get("finding_id")
        if not isinstance(canonical_id, str) or not canonical_id:
            raise ValueError("canonical aggregation requires finding_id or canonical_finding_id")
        groups[canonical_id].append((finding, match))

    aggregated: list[dict[str, Any]] = []
    tier_counts: Counter[str] = Counter()
    for canonical_id in sorted(groups):
        members = groups[canonical_id]
        best_rank = min(_TIER_RANK[match["match_tier"]] for _, match in members)
        tier = next(name for name, rank in _TIER_RANK.items() if rank == best_rank)
        unique_matches: dict[tuple[Any, ...], dict[str, Any]] = {}
        for _, match in members:
            if _TIER_RANK[match["match_tier"]] != best_rank:
                continue
            for candidate in match["matches"]:
                key = (
                    candidate["entry_id"],
                    candidate["report_id"],
                    candidate["tier"],
                    candidate["source_supported_by_trace"],
                )
                unique_matches[key] = candidate
        tier_counts[tier] += 1
        aggregated.append(
            {
                "finding_id": canonical_id,
                "canonical_finding_id": canonical_id,
                "member_finding_ids": sorted(
                    {str(finding["finding_id"]) for finding, _ in members}
                ),
                "match_tier": tier,
                "matches": [unique_matches[key] for key in sorted(unique_matches)],
            }
        )

    canonical_summary = dict(summary)
    canonical_summary["unit"] = "canonical_cluster"
    canonical_summary["total_observations"] = len(findings)
    canonical_summary["total_findings"] = len(aggregated)
    canonical_summary["counts_by_tier"] = {
        tier: tier_counts[tier] for tier in (STRICT, STRONG, CANDIDATE, UNMATCHED)
    }
    return aggregated, canonical_summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Tier normalized findings against VulnGym entries.")
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--entries", type=Path, default=Path("benchmark/VulnGym/data/entries.jsonl"))
    parser.add_argument("--line-tolerance", type=int, default=5)
    parser.add_argument("--include-unverified", action="store_true")
    parser.add_argument(
        "--canonical",
        action="store_true",
        help="aggregate observation-level matches by canonical_finding_id",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args(argv)

    findings = load_jsonl(args.findings)
    entries = load_jsonl(args.entries)
    matches, summary = match_candidates(
        findings,
        entries,
        tolerance=args.line_tolerance,
        verified_only=not args.include_unverified,
    )
    if args.canonical:
        matches, summary = aggregate_canonical_matches(findings, matches, summary)
    write_jsonl(args.output, matches)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
