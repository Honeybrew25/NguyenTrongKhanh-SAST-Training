from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlparse

from .matcher import normalize_path

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_CWE = re.compile(r"CWE[-_/ ]?(\d+)", re.IGNORECASE)


@dataclass(frozen=True)
class NormalizationContext:
    repo_url: str
    commit: str
    scanner_name: str
    scanner_version: str
    ruleset_commit: str
    scan_id: str
    raw_result_ref: str
    source_root: Path | None = None
    read_source_snippets: bool = False
    ruleset_root: Path | None = None

    def validate(self) -> None:
        if not self.repo_url.startswith("https://github.com/"):
            raise ValueError("repo_url must be a public GitHub HTTPS URL")
        if not _SHA40.fullmatch(self.commit):
            raise ValueError("commit must be a lowercase 40-character SHA-1")
        if self.scanner_name not in {"semgrep", "opengrep", "codeql", "other"}:
            raise ValueError(f"unsupported scanner name: {self.scanner_name}")
        if not self.scanner_version:
            raise ValueError("scanner_version must not be empty")
        if not _SHA40.fullmatch(self.ruleset_commit):
            raise ValueError("ruleset_commit must be a lowercase 40-character SHA-1")
        if not self.scan_id or not self.raw_result_ref:
            raise ValueError("scan_id and raw_result_ref must not be empty")


def _sha256_json(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 1 else None
    if isinstance(value, str) and value.isdigit() and int(value) >= 1:
        return int(value)
    return None


def _path_from_uri(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    parsed = urlparse(value)
    if parsed.scheme == "file":
        value = unquote(parsed.path)
        if re.fullmatch(r"/[A-Za-z]:/.*", value):
            value = value[1:]
    return normalize_path(value)


def _relative_path(value: Any, source_root: Path | None) -> str:
    path = _path_from_uri(value)
    if not path:
        return ""
    if source_root is None:
        return path
    root = source_root.resolve()
    candidate = Path(path)
    try:
        if candidate.is_absolute():
            return normalize_path(str(candidate.resolve().relative_to(root)))
    except (OSError, ValueError):
        pass
    root_text = normalize_path(str(root)).rstrip("/")
    if path.lower().startswith(root_text.lower() + "/"):
        return path[len(root_text) + 1 :]
    return path


def _portable_path_ref(path: Path, project_root: Path) -> str:
    try:
        return normalize_path(str(path.resolve().relative_to(project_root.resolve())))
    except ValueError:
        return normalize_path(str(path.resolve()))


def _status_input_path(
    attempt_directory: Path, name: str, provenance: dict[str, Any]
) -> Path:
    frozen_path = provenance.get("frozen_path")
    if frozen_path is None:
        return Path(str(provenance.get("path", "")))
    if not isinstance(frozen_path, str) or not frozen_path:
        raise ValueError(f"invalid frozen input path: {name}")
    candidate = (attempt_directory / frozen_path).resolve()
    try:
        candidate.relative_to(attempt_directory.resolve())
    except ValueError as exc:
        raise ValueError(f"frozen input escapes attempt directory: {name}") from exc
    return candidate


def _cwes(value: Any) -> list[str]:
    values: Iterable[Any]
    if isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = (value,)
    found: set[str] = set()
    for item in values:
        if not isinstance(item, str):
            continue
        matches = _CWE.findall(item)
        if matches:
            found.update(f"CWE-{int(number)}" for number in matches)
    return sorted(found)


def _category(metadata: dict[str, Any]) -> str | None:
    value = metadata.get("category") or metadata.get("subcategory")
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, list):
        values = sorted({str(item).strip() for item in value if str(item).strip()})
        return ", ".join(values) or None
    return None


def _encoded_rule_prefix(path: Path) -> str:
    normalized = normalize_path(str(path.resolve()))
    segments = []
    for segment in normalized.split("/"):
        cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "", segment)
        if cleaned:
            segments.append(cleaned)
    return ".".join(segments)


def _normalize_rule_id(value: Any, context: NormalizationContext) -> str:
    rule_id = str(value or "").strip()
    if not rule_id or context.scanner_name not in {"semgrep", "opengrep"}:
        return rule_id
    if context.ruleset_root is None:
        return rule_id
    prefix = _encoded_rule_prefix(context.ruleset_root) + "."
    if rule_id.startswith(prefix):
        return rule_id[len(prefix) :]
    # A moved workspace changes the absolute prefix. The final two ruleset-root
    # path segments are sufficient to identify the start of the pinned corpus.
    root_parts = [part for part in normalize_path(str(context.ruleset_root)).split("/") if part]
    if len(root_parts) >= 2:
        tail = ".".join(re.sub(r"[^A-Za-z0-9_.-]+", "", part) for part in root_parts[-2:]) + "."
        marker = rule_id.rfind(tail)
        if marker >= 0:
            return rule_id[marker + len(tail) :]
    return rule_id


def _location(path: Any, start: Any, end: Any, source_root: Path | None) -> dict[str, Any]:
    start = start if isinstance(start, dict) else {}
    end = end if isinstance(end, dict) else {}
    start_line = _as_int(start.get("line"))
    end_line = _as_int(end.get("line")) or start_line
    file_path = _relative_path(path, source_root)
    if not file_path or start_line is None or end_line is None:
        raise ValueError(f"finding has an invalid location: {path!r}:{start!r}-{end!r}")
    if end_line < start_line:
        end_line = start_line
    return {
        "file": file_path,
        "start_line": start_line,
        "end_line": end_line,
        "start_col": _as_int(start.get("col") or start.get("column")),
        "end_col": _as_int(end.get("col") or end.get("column")),
    }


def _region_location(
    physical: dict[str, Any], source_root: Path | None
) -> dict[str, Any] | None:
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    path = artifact.get("uri")
    start_line = _as_int(region.get("startLine"))
    if not path or start_line is None:
        return None
    return {
        "file": _relative_path(path, source_root),
        "start_line": start_line,
        "end_line": _as_int(region.get("endLine")) or start_line,
        "start_col": _as_int(region.get("startColumn")),
        "end_col": _as_int(region.get("endColumn")),
    }


def _read_snippet(location: dict[str, Any], source_root: Path | None) -> str | None:
    if source_root is None:
        return None
    root = source_root.resolve()
    try:
        candidate = (root / location["file"]).resolve()
        candidate.relative_to(root)
        lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None
    start = location["start_line"] - 1
    end = location["end_line"]
    if start >= len(lines):
        return None
    return "\n".join(lines[start:end])


def _usable_snippet(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    if value.strip().lower() == "requires login":
        return None
    return value


def _snippet_fingerprint(snippet: str | None) -> str | None:
    if snippet is None:
        return None
    normalized = " ".join(snippet.split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest() if normalized else None


def _find_semgrep_loc(value: Any) -> tuple[str, dict[str, Any], dict[str, Any], str | None] | None:
    if isinstance(value, dict):
        if "path" in value and "start" in value:
            return (
                str(value.get("path", "")),
                value.get("start") or {},
                value.get("end") or value.get("start") or {},
                _usable_snippet(value.get("content") or value.get("code")),
            )
        if isinstance(value.get("location"), dict):
            located = _find_semgrep_loc(value["location"])
            if located:
                code = _usable_snippet(value.get("content") or value.get("code"))
                return located[:3] + (code or located[3],)
        for nested in value.values():
            located = _find_semgrep_loc(nested)
            if located:
                return located
    elif isinstance(value, list):
        for nested in value:
            located = _find_semgrep_loc(nested)
            if located:
                code = next((_usable_snippet(item) for item in value if _usable_snippet(item)), None)
                return located[:3] + (code or located[3],)
    return None


def _semgrep_trace(extra: dict[str, Any], source_root: Path | None) -> list[dict[str, Any]]:
    trace = extra.get("dataflow_trace")
    if not isinstance(trace, dict):
        return []
    nodes: list[dict[str, Any]] = []
    items: list[tuple[str, Any]] = []
    if trace.get("taint_source") is not None:
        items.append(("source", trace["taint_source"]))
    intermediate = trace.get("intermediate_vars") or []
    if isinstance(intermediate, list):
        items.extend(("intermediate", item) for item in intermediate)
    if trace.get("taint_sink") is not None:
        items.append(("sink", trace["taint_sink"]))
    seen: set[tuple[str, int, str]] = set()
    for role, value in items:
        located = _find_semgrep_loc(value)
        if not located:
            continue
        path, start, end, code = located
        try:
            loc = _location(path, start, end, source_root)
        except ValueError:
            continue
        line: int | str = loc["start_line"]
        if loc["end_line"] != loc["start_line"]:
            line = f"{loc['start_line']}-{loc['end_line']}"
        key = (loc["file"], loc["start_line"], role)
        if key in seen:
            continue
        seen.add(key)
        nodes.append({"file": loc["file"], "line": line, "description": role, "code": code})
    return nodes


def _finding_id(context: NormalizationContext, rule_id: str, location: dict[str, Any]) -> str:
    natural_key = {
        "repo_url": context.repo_url.rstrip("/").removesuffix(".git"),
        "commit": context.commit,
        "scanner": context.scanner_name,
        "rule_id": rule_id,
        "location": location,
        "ruleset_commit": context.ruleset_commit,
    }
    return f"finding-{_sha256_json(natural_key)}"


def normalize_semgrep_json(raw: dict[str, Any], context: NormalizationContext) -> list[dict[str, Any]]:
    context.validate()
    raw_version = raw.get("version")
    if raw_version and str(raw_version) != context.scanner_version:
        raise ValueError(
            f"scanner version mismatch: raw={raw_version!r}, expected={context.scanner_version!r}"
        )
    results = raw.get("results")
    if not isinstance(results, list):
        raise ValueError("Semgrep-compatible JSON must contain a results array")
    findings: list[dict[str, Any]] = []
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ValueError(f"results[{index}] must be an object")
        rule_id = _normalize_rule_id(result.get("check_id"), context)
        if not rule_id:
            raise ValueError(f"results[{index}] is missing check_id")
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        location = _location(result.get("path"), result.get("start"), result.get("end"), context.source_root)
        snippet = _usable_snippet(extra.get("lines")) or _read_snippet(
            location, context.source_root if context.read_source_snippets else None
        )
        fingerprint = _snippet_fingerprint(snippet)
        if fingerprint is None:
            raw_fingerprint = extra.get("fingerprint")
            if isinstance(raw_fingerprint, str) and raw_fingerprint.lower() != "requires login":
                fingerprint = raw_fingerprint
        findings.append(
            {
                "schema_version": 1,
                "finding_id": _finding_id(context, rule_id, location),
                "canonical_finding_id": None,
                "repo_url": context.repo_url.rstrip("/").removesuffix(".git"),
                "commit": context.commit,
                "scanner": {"name": context.scanner_name, "version": context.scanner_version},
                "rule": {
                    "id": rule_id,
                    "ruleset_commit": context.ruleset_commit,
                    "cwe": _cwes(metadata.get("cwe")),
                    "category": _category(metadata),
                    "severity": str(extra.get("severity")) if extra.get("severity") is not None else None,
                },
                "message": str(extra.get("message") or ""),
                "location": location,
                "dataflow_trace": _semgrep_trace(extra, context.source_root),
                "snippet": snippet,
                "fingerprint": fingerprint,
                "provenance": {
                    "raw_result_ref": f"{context.raw_result_ref}#results/{index}",
                    "evidence_refs": [f"{context.raw_result_ref}#results/{index}"],
                    "scan_id": context.scan_id,
                    "observed_by": [{"scanner": context.scanner_name, "rule_id": rule_id}],
                },
            }
        )
    return findings


def _sarif_message(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("text") or value.get("markdown") or "")
    return ""


def _sarif_trace(result: dict[str, Any], source_root: Path | None) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for code_flow in result.get("codeFlows") or []:
        for thread_flow in code_flow.get("threadFlows") or []:
            for item in thread_flow.get("locations") or []:
                location = item.get("location") or {}
                physical = location.get("physicalLocation") or {}
                loc = _region_location(physical, source_root)
                if not loc or not loc["file"]:
                    continue
                message = _sarif_message(location.get("message")) or "path step"
                key = (loc["file"], loc["start_line"], message)
                if key in seen:
                    continue
                seen.add(key)
                region = physical.get("region") or {}
                line: int | str = loc["start_line"]
                if loc["end_line"] != loc["start_line"]:
                    line = f"{loc['start_line']}-{loc['end_line']}"
                snippet = region.get("snippet") or {}
                nodes.append(
                    {
                        "file": loc["file"],
                        "line": line,
                        "description": message,
                        "code": _usable_snippet(snippet.get("text")),
                    }
                )
    return nodes


def normalize_sarif(raw: dict[str, Any], context: NormalizationContext) -> list[dict[str, Any]]:
    context.validate()
    runs = raw.get("runs")
    if not isinstance(runs, list):
        raise ValueError("SARIF must contain a runs array")
    findings: list[dict[str, Any]] = []
    for run_index, run in enumerate(runs):
        driver = ((run.get("tool") or {}).get("driver") or {})
        raw_version = driver.get("semanticVersion") or driver.get("version")
        if raw_version and str(raw_version) != context.scanner_version:
            raise ValueError(
                f"scanner version mismatch: raw={raw_version!r}, expected={context.scanner_version!r}"
            )
        descriptors = {
            str(rule.get("id")): rule
            for rule in driver.get("rules") or []
            if isinstance(rule, dict) and rule.get("id")
        }
        for result_index, result in enumerate(run.get("results") or []):
            raw_rule_id = str(result.get("ruleId") or "").strip()
            rule_id = _normalize_rule_id(raw_rule_id, context)
            if not raw_rule_id:
                raise ValueError(f"runs[{run_index}].results[{result_index}] is missing ruleId")
            descriptor = descriptors.get(raw_rule_id, {})
            locations = result.get("locations") or []
            if not locations:
                raise ValueError(f"SARIF result {rule_id!r} has no location")
            physical = (locations[0].get("physicalLocation") or {})
            location = _region_location(physical, context.source_root)
            if not location or not location["file"]:
                raise ValueError(f"SARIF result {rule_id!r} has an invalid location")
            region = physical.get("region") or {}
            snippet = _usable_snippet((region.get("snippet") or {}).get("text")) or _read_snippet(
                location, context.source_root if context.read_source_snippets else None
            )
            properties = descriptor.get("properties") or {}
            tags = properties.get("tags") or []
            cwe_values = [*tags, properties.get("cwe"), result.get("properties", {}).get("cwe")]
            severity = result.get("level") or (descriptor.get("defaultConfiguration") or {}).get("level")
            fingerprint = _snippet_fingerprint(snippet)
            if fingerprint is None and result.get("partialFingerprints"):
                fingerprint = _sha256_json(result["partialFingerprints"])
            findings.append(
                {
                    "schema_version": 1,
                    "finding_id": _finding_id(context, rule_id, location),
                    "canonical_finding_id": None,
                    "repo_url": context.repo_url.rstrip("/").removesuffix(".git"),
                    "commit": context.commit,
                    "scanner": {"name": context.scanner_name, "version": context.scanner_version},
                    "rule": {
                        "id": rule_id,
                        "ruleset_commit": context.ruleset_commit,
                        "cwe": _cwes(cwe_values),
                        "category": str(properties.get("category")) if properties.get("category") else None,
                        "severity": str(severity) if severity is not None else None,
                    },
                    "message": _sarif_message(result.get("message")),
                    "location": location,
                    "dataflow_trace": _sarif_trace(result, context.source_root),
                    "snippet": snippet,
                    "fingerprint": fingerprint,
                    "provenance": {
                        "raw_result_ref": (
                            f"{context.raw_result_ref}#runs/{run_index}/results/{result_index}"
                        ),
                        "evidence_refs": [
                            f"{context.raw_result_ref}#runs/{run_index}/results/{result_index}"
                        ],
                        "scan_id": context.scan_id,
                        "observed_by": [{"scanner": context.scanner_name, "rule_id": rule_id}],
                    },
                }
            )
    return findings


def merge_sarif_evidence(
    findings: list[dict[str, Any]], sarif_findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Join SARIF code-flow evidence into JSON findings without changing their identity."""

    by_rule_path: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for sarif_finding in sarif_findings:
        key = (sarif_finding["rule"]["id"], sarif_finding["location"]["file"])
        by_rule_path.setdefault(key, []).append(sarif_finding)

    for finding in findings:
        key = (finding["rule"]["id"], finding["location"]["file"])
        location = finding["location"]
        candidates = []
        for sarif_finding in by_rule_path.get(key, []):
            sarif_location = sarif_finding["location"]
            same_lines = (
                sarif_location["start_line"] == location["start_line"]
                and sarif_location["end_line"] == location["end_line"]
            )
            same_start_column = (
                location.get("start_col") is None
                or sarif_location.get("start_col") is None
                or location["start_col"] == sarif_location["start_col"]
            )
            same_message = (
                not finding.get("message")
                or not sarif_finding.get("message")
                or finding["message"] == sarif_finding["message"]
            )
            if same_lines and same_start_column and same_message:
                candidates.append(sarif_finding)
        if len(candidates) != 1:
            continue
        sarif_finding = candidates[0]
        if sarif_finding["dataflow_trace"]:
            finding["dataflow_trace"] = sarif_finding["dataflow_trace"]
            references = set(finding["provenance"].get("evidence_refs") or [])
            references.update(sarif_finding["provenance"].get("evidence_refs") or [])
            finding["provenance"]["evidence_refs"] = sorted(references)
        for field in ("snippet", "fingerprint"):
            if not finding.get(field) and sarif_finding.get(field):
                finding[field] = sarif_finding[field]
        finding["rule"]["cwe"] = sorted(
            set(finding["rule"].get("cwe") or []) | set(sarif_finding["rule"].get("cwe") or [])
        )
        if not finding["rule"].get("category"):
            finding["rule"]["category"] = sarif_finding["rule"].get("category")
    return findings


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows)
    path.write_text(payload, encoding="utf-8")


def finding_statistics(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(findings)
    trace_lengths = [len(row.get("dataflow_trace") or []) for row in rows]
    return {
        "findings": len(rows),
        "unique_rules": len({row["rule"]["id"] for row in rows}),
        "unique_files": len({row["location"]["file"] for row in rows}),
        "with_dataflow_trace": sum(length > 0 for length in trace_lengths),
        "trace_nodes": sum(trace_lengths),
        "max_trace_nodes": max(trace_lengths, default=0),
        "by_scanner": dict(sorted(Counter(row["scanner"]["name"] for row in rows).items())),
        "by_severity": dict(
            sorted(Counter(str(row["rule"].get("severity")) for row in rows).items())
        ),
        "by_category": dict(
            sorted(Counter(str(row["rule"].get("category")) for row in rows).items())
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize Semgrep/OpenGrep JSON or SARIF findings.")
    parser.add_argument(
        "--status",
        type=Path,
        help="successful vulngym-scan attempt status; infers JSON, SARIF, snapshot and provenance",
    )
    parser.add_argument("--input", type=Path)
    parser.add_argument("--format", choices=("semgrep-json", "sarif"))
    parser.add_argument(
        "--sarif-input",
        type=Path,
        help="optional matching SARIF used to add codeFlows to Semgrep-compatible JSON",
    )
    parser.add_argument("--repo-url")
    parser.add_argument("--commit")
    parser.add_argument("--scanner", choices=("semgrep", "opengrep", "codeql", "other"))
    parser.add_argument("--scanner-version")
    parser.add_argument("--ruleset-commit")
    parser.add_argument("--scan-id")
    parser.add_argument("--raw-result-ref")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument(
        "--read-source-snippets",
        action="store_true",
        help="read snippets from --source-root; disabled for status-based reproducible normalization",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    parser.add_argument(
        "--category",
        action="append",
        dest="categories",
        help="optional case-insensitive rule category filter; repeatable",
    )
    args = parser.parse_args(argv)

    if args.status:
        if any(
            value is not None
            for value in (
                args.input,
                args.format,
                args.repo_url,
                args.commit,
                args.scanner,
                args.scanner_version,
                args.ruleset_commit,
                args.scan_id,
                args.raw_result_ref,
                args.source_root,
                args.read_source_snippets or None,
                args.sarif_input,
            )
        ):
            parser.error("--status cannot be combined with explicit input/provenance arguments")
        status = json.loads(args.status.read_text(encoding="utf-8"))
        if status.get("status") != "SUCCESS":
            parser.error("--status must reference a SUCCESS attempt")
        scanner = status.get("scanner") or {}
        attempt_directory = args.status.resolve().parent
        input_provenance = status.get("inputs") or {}
        frozen_inputs: dict[str, Path] = {}
        for name, provenance in input_provenance.items():
            if not isinstance(provenance, dict):
                parser.error(f"invalid frozen input provenance: {name}")
            try:
                provenance_path = _status_input_path(attempt_directory, name, provenance)
            except ValueError as exc:
                parser.error(str(exc))
            expected = provenance.get("sha256")
            if not provenance_path.is_file() or not expected or _sha256_file(provenance_path) != expected:
                parser.error(f"frozen input checksum mismatch or missing: {name}")
            frozen_inputs[name] = provenance_path
        missing_frozen_inputs = {"manifest", "scanner_lock", "scan_profile"} - set(frozen_inputs)
        if missing_frozen_inputs:
            parser.error(
                "status is missing frozen input provenance: "
                + ", ".join(sorted(missing_frozen_inputs))
            )
        args.input = attempt_directory / (status.get("outputs") or {}).get("json", "raw.json")
        args.sarif_input = attempt_directory / (status.get("outputs") or {}).get("sarif", "raw.sarif")
        checksums = status.get("checksums") or {}
        for raw_path in (args.input, args.sarif_input):
            expected = checksums.get(raw_path.name)
            if not expected or _sha256_file(raw_path) != expected:
                parser.error(f"scanner output checksum mismatch or missing from status: {raw_path.name}")
        args.format = "semgrep-json"
        args.repo_url = status.get("repo_url")
        args.commit = status.get("commit")
        args.scanner = scanner.get("name")
        args.scanner_version = scanner.get("observed_version")
        args.ruleset_commit = status.get("ruleset_commit")
        args.scan_id = status.get("scan_id")
        args.source_root = Path(status["cwd"]) if status.get("cwd") else None
        profile_ref = input_provenance.get("scan_profile") or {}
        profile_path = frozen_inputs["scan_profile"]
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        original_profile_path = Path(profile_ref["path"])
        project_root = original_profile_path.resolve().parent.parent
        args.raw_result_ref = _portable_path_ref(args.input, project_root)
        args.sarif_result_ref = _portable_path_ref(args.sarif_input, project_root)
        configured_root = Path(profile["rules"]["root"])
        args.ruleset_root = (
            configured_root
            if configured_root.is_absolute()
            else project_root / configured_root
        ).resolve()
    else:
        required = {
            "--input": args.input,
            "--format": args.format,
            "--repo-url": args.repo_url,
            "--commit": args.commit,
            "--scanner": args.scanner,
            "--scanner-version": args.scanner_version,
            "--ruleset-commit": args.ruleset_commit,
            "--scan-id": args.scan_id,
        }
        missing = [flag for flag, value in required.items() if value is None]
        if missing:
            parser.error(f"missing required arguments without --status: {', '.join(missing)}")

    context = NormalizationContext(
        repo_url=args.repo_url,
        commit=args.commit,
        scanner_name=args.scanner,
        scanner_version=args.scanner_version,
        ruleset_commit=args.ruleset_commit,
        scan_id=args.scan_id,
        raw_result_ref=args.raw_result_ref or normalize_path(str(args.input)),
        source_root=args.source_root,
        read_source_snippets=args.read_source_snippets,
        ruleset_root=getattr(args, "ruleset_root", None),
    )
    raw = json.loads(args.input.read_text(encoding="utf-8"))
    if args.format == "semgrep-json":
        findings = normalize_semgrep_json(raw, context)
        if args.sarif_input:
            sarif = json.loads(args.sarif_input.read_text(encoding="utf-8"))
            sarif_context = replace(
                context,
                raw_result_ref=getattr(
                    args, "sarif_result_ref", normalize_path(str(args.sarif_input))
                ),
            )
            findings = merge_sarif_evidence(findings, normalize_sarif(sarif, sarif_context))
    else:
        if args.sarif_input:
            parser.error("--sarif-input is only valid with --format semgrep-json")
        findings = normalize_sarif(raw, context)
    if args.categories:
        selected_categories = {category.strip().casefold() for category in args.categories}
        findings = [
            finding
            for finding in findings
            if str(finding["rule"].get("category") or "").strip().casefold()
            in selected_categories
        ]
    write_jsonl(args.output, findings)
    statistics = finding_statistics(findings)
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(
            json.dumps(statistics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    print(f"normalized {len(findings)} finding(s) to {args.output}")
    print(json.dumps(statistics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
