from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from .checkout import (
    InterprocessLockTimeout,
    interprocess_lock,
    repo_slug,
    verify_snapshot_state,
)


VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "ABSTAIN"}
CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}
FP_REASON_CODES = {
    "UNREACHABLE_CODE",
    "NO_ATTACKER_CONTROL",
    "SANITIZED_BEFORE_SINK",
    "CONSTANT_VALUE",
    "AUTHZ_PRECONDITION_BLOCKS_ATTACK",
    "SAFE_API_USAGE",
    "TYPE_OR_SCHEMA_CONSTRAINT",
    "TEST_OR_FIXTURE_ONLY",
    "DEAD_OR_UNUSED_PATH",
    "FRAMEWORK_GUARANTEE",
    "SCANNER_MODELING_ERROR",
    "OTHER_EXPLAINED",
}
ABSTAIN_REASONS = {
    "INSUFFICIENT_CONTEXT",
    "MISSING_EXTERNAL_IMPLEMENTATION",
    "AMBIGUOUS_ATTACKER_CONTROL",
    "AMBIGUOUS_REACHABILITY",
    "CONFLICTING_EVIDENCE",
    "OTHER_EXPLAINED",
}

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_ADVISORY_ID = re.compile(
    r"\b(?:CVE-[0-9]{4}-[0-9]{4,}|GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4})\b",
    re.IGNORECASE,
)
_ENTRY_ID = re.compile(r"\bentry-[0-9]{5}\b", re.IGNORECASE)
CONTROLLER_PROTOCOL_VERSION = "blind-verifier-controller-v1"
_CONTROLLER_PATH = Path(__file__).resolve()
_DEFAULT_RESPONSE_SCHEMA = (
    _CONTROLLER_PATH.parents[2] / "schemas" / "verifier-agent-response.schema.json"
)
_DEFAULT_PREDICTION_SCHEMA = (
    _CONTROLLER_PATH.parents[2] / "schemas" / "verifier-prediction.schema.json"
)
_ALLOWED_INPUT_KEYS = {
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
}
_FORBIDDEN_KEYS = {
    "adjudication",
    "candidate_id",
    "cve",
    "cves",
    "exclusion_reason",
    "fixed_commit",
    "gold_label",
    "human_label",
    "label",
    "labels",
    "linked_entry_ids",
    "linked_report_ids",
    "match_tier",
    "matches",
    "metrics",
    "nearby_semgrep_findings",
    "novelty_vs_semgrep",
    "patch",
    "prediction",
    "report_id",
    "technical_label",
    "verdict",
    "vulngym_matches",
}
_FORBIDDEN_KEY_TOKENS = {
    re.sub(r"[^a-z0-9]", "", key.casefold()) for key in _FORBIDDEN_KEYS
} | {
    "benchmarkentry",
    "benchmarkentries",
    "groundtruth",
    "humanreview",
    "isvulnerable",
    "knownvulnerability",
    "linkedreportid",
    "linkedentryid",
    "expectedverdict",
    "referencelabel",
    "truelabel",
}
_NESTED_INPUT_KEYS = {
    "scanner": {"name", "version"},
    "rule": {"id", "ruleset_commit", "cwe", "category", "severity"},
    "location": {"file", "start_line", "end_line", "start_col", "end_col"},
    "trace": {"file", "line", "description", "code"},
    "provenance": {"raw_result_ref", "evidence_refs", "scan_id", "observed_by"},
    "observed_by": {"scanner", "rule_id"},
}
_ALLOWED_RESPONSE_KEYS = {
    "action",
    "working_hypothesis",
    "tool_requests",
    "verdict",
    "confidence",
    "reason_codes",
    "attacker_capability",
    "entry_point",
    "security_effect",
    "controls",
    "reasoning",
    "evidence",
    "abstain_reason",
}
_ALLOWED_PREDICTION_KEYS = {
    "schema_version",
    "finding_id",
    "verdict",
    "confidence",
    "reason_codes",
    "attacker_capability",
    "entry_point",
    "security_effect",
    "controls",
    "reasoning",
    "evidence",
    "abstain_reason",
    "evaluation_eligible",
    "exclusion_reason",
    "agent",
}
_ALLOWED_PROVIDER_EVENT_KEYS = {
    "thread.started": {"type", "thread_id"},
    "turn.started": {"type"},
    "item.completed": {"type", "item"},
    "turn.completed": {"type", "usage"},
}
_ALLOWED_PROVIDER_ITEM_KEYS = {"id", "type", "text"}


class VerifierError(RuntimeError):
    """Base exception for a verifier run that must not become a prediction."""


class BlindInputError(VerifierError):
    """Raised when supposedly blind input contains invalid or label-bearing data."""


class SourcePolicyError(VerifierError):
    """Raised when source evidence escapes the pinned snapshot policy."""


class ProviderError(VerifierError):
    """Raised for model transport, protocol, or isolation failures."""


class TerminalProviderError(ProviderError):
    """A provider-wide failure for which later cases must not be attempted."""

    def __init__(self, code: str, message: str | None = None):
        self.code = code
        super().__init__(message or code)


class PredictionError(VerifierError):
    """Raised when the model's final decision does not meet the evidence contract."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _classify_provider_failure(text: str) -> str | None:
    """Map provider diagnostics to stable, non-secret operational codes."""

    normalized = text.casefold()
    if any(
        marker in normalized
        for marker in (
            "token_revoked",
            "invalidated oauth token",
            "oauth token has been revoked",
            "sign in again",
        )
    ):
        return "PROVIDER_TOKEN_REVOKED"
    if any(
        marker in normalized
        for marker in (
            "usage limit",
            "usage_limit",
            "upgrade to pro",
            "purchase more credits",
        )
    ):
        return "PROVIDER_USAGE_LIMIT"
    if any(
        marker in normalized
        for marker in (
            "rate limit",
            "rate_limit",
            "too many requests",
        )
    ):
        return "PROVIDER_RATE_LIMIT"
    return None


_PROVIDER_SECRET_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+"),
    re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b"),
    re.compile(
        r"(?i)(access[_-]?token|refresh[_-]?token|token|authorization|cookie|"
        r"continuation(?:[_-]?(?:token|data))?)"
        r"(\s*[\"']?\s*[:=]\s*[\"']?)([^\s\"',;}{]{6,})"
    ),
    re.compile(r"\b[A-Za-z0-9+/=_-]{96,}\b"),
)


def _redact_provider_diagnostics(text: str) -> str:
    """Bound and redact diagnostics before they enter persistent artifacts."""

    redacted = text
    for index, pattern in enumerate(_PROVIDER_SECRET_PATTERNS):
        if index == 2:
            redacted = pattern.sub(r"\1\2[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted[-4000:]


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(path)


def _write_json(path: Path, value: Any) -> None:
    _atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    rendered = "".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
        for row in rows
    )
    _atomic_write_text(path, rendered)


def load_jsonl(
    path: Path, profile: "AgentProfile | None" = None
) -> list[dict[str, Any]]:
    limits = profile or AgentProfile.default_limits()
    size = path.stat().st_size
    if size > limits.max_input_bytes:
        raise BlindInputError(
            f"blind input exceeds {limits.max_input_bytes} bytes: {path}"
        )
    rows: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        line_number = 0
        while True:
            raw_bytes = handle.readline(limits.max_input_line_bytes + 1)
            if not raw_bytes:
                break
            line_number += 1
            if len(raw_bytes) > limits.max_input_line_bytes:
                raise BlindInputError(
                    f"{path}:{line_number}: record exceeds "
                    f"{limits.max_input_line_bytes} bytes"
                )
            if not raw_bytes.strip():
                continue
            try:
                raw = raw_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise BlindInputError(
                    f"{path}:{line_number}: input is not valid UTF-8"
                ) from exc
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise BlindInputError(
                    f"{path}:{line_number}: invalid JSON: {exc}"
                ) from exc
            if not isinstance(row, dict):
                raise BlindInputError(f"{path}:{line_number}: record must be an object")
            rows.append(row)
            if len(rows) > limits.max_input_records:
                raise BlindInputError(
                    f"blind input exceeds {limits.max_input_records} records"
                )
    if not rows:
        raise BlindInputError(f"blind input is empty: {path}")
    return rows


def _walk_forbidden_metadata(
    value: Any, profile: "AgentProfile", path: str = "$"
) -> None:
    stack: list[tuple[Any, str, int]] = [(value, path, 0)]
    visited = 0
    while stack:
        current, current_path, depth = stack.pop()
        if depth > profile.max_input_depth:
            raise BlindInputError(
                f"blind input exceeds nesting depth at {current_path}"
            )
        visited += 1
        if visited > profile.max_input_container_items:
            raise BlindInputError("blind input contains too many nested values")
        if isinstance(current, dict):
            for key, nested in current.items():
                token = re.sub(r"[^a-z0-9]", "", str(key).casefold())
                if token in _FORBIDDEN_KEY_TOKENS:
                    raise BlindInputError(
                        f"forbidden blind-input key at {current_path}.{key}"
                    )
                stack.append((nested, f"{current_path}.{key}", depth + 1))
        elif isinstance(current, list):
            for index, nested in enumerate(current):
                stack.append((nested, f"{current_path}[{index}]", depth + 1))
        elif isinstance(current, str):
            if len(current) > profile.max_input_string_chars:
                raise BlindInputError(
                    f"blind-input string exceeds limit at {current_path}"
                )
            if _ADVISORY_ID.search(current):
                raise BlindInputError(
                    f"advisory identifier leaked into blind input at {current_path}"
                )
            if _ENTRY_ID.search(current):
                raise BlindInputError(
                    f"VulnGym entry identifier leaked into blind input at {current_path}"
                )


def _require_allowed_keys(value: dict[str, Any], kind: str, path: str) -> None:
    unexpected = sorted(set(value) - _NESTED_INPUT_KEYS[kind])
    if unexpected:
        raise BlindInputError(f"unexpected blind-input keys at {path}: {unexpected}")


def normalize_source_path(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SourcePolicyError("source path must be a non-empty string")
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        raise SourcePolicyError(f"absolute source path is forbidden: {value!r}")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or not candidate.parts:
        raise SourcePolicyError(f"absolute or empty source path is forbidden: {value!r}")
    if any(part in {"", ".", "..", ".git"} for part in candidate.parts):
        raise SourcePolicyError(f"unsafe source path is forbidden: {value!r}")
    return candidate.as_posix()


def _validate_line_span(start: Any, end: Any, context: str) -> tuple[int, int]:
    if not isinstance(start, int) or isinstance(start, bool) or start < 1:
        raise BlindInputError(f"{context}.start_line must be a positive integer")
    if not isinstance(end, int) or isinstance(end, bool) or end < start:
        raise BlindInputError(f"{context}.end_line must be >= start_line")
    return start, end


def parse_trace_line(value: Any, context: str) -> tuple[int, int]:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value, value
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*-[1-9][0-9]*", value):
        start_text, end_text = value.split("-", 1)
        start, end = int(start_text), int(end_text)
        if end >= start:
            return start, end
    raise BlindInputError(f"{context}.line must be a positive line or inclusive range")


def validate_blind_record(
    record: dict[str, Any], profile: "AgentProfile | None" = None
) -> None:
    limits = profile or AgentProfile.default_limits()
    unexpected = sorted(set(record) - _ALLOWED_INPUT_KEYS)
    if unexpected:
        raise BlindInputError(f"unexpected blind-input keys: {unexpected}")
    _walk_forbidden_metadata(record, limits)
    if record.get("schema_version") != 1:
        raise BlindInputError("schema_version must be 1")
    finding_id = record.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id or len(finding_id) > 512:
        raise BlindInputError("finding_id must be a non-empty string")
    member_ids = record.get("member_finding_ids")
    if member_ids is not None:
        if (
            not isinstance(member_ids, list)
            or not member_ids
            or len(member_ids) > 512
            or not all(isinstance(item, str) and item for item in member_ids)
            or len(set(member_ids)) != len(member_ids)
        ):
            raise BlindInputError("member_finding_ids must contain unique non-empty strings")
    repo_slug(str(record.get("repo_url") or ""))
    commit = record.get("commit")
    if not isinstance(commit, str) or not _SHA40.fullmatch(commit):
        raise BlindInputError("commit must be a full lowercase SHA-1")
    for object_name in ("scanner", "rule", "location", "provenance"):
        if not isinstance(record.get(object_name), dict):
            raise BlindInputError(f"{object_name} must be an object")
    _require_allowed_keys(record["scanner"], "scanner", "scanner")
    _require_allowed_keys(record["rule"], "rule", "rule")
    _require_allowed_keys(record["location"], "location", "location")
    _require_allowed_keys(record["provenance"], "provenance", "provenance")
    scanner = record["scanner"]
    if scanner.get("name") not in {"semgrep", "other"}:
        raise BlindInputError("scanner.name is invalid")
    if not isinstance(scanner.get("version"), str) or not scanner["version"]:
        raise BlindInputError("scanner.version must be a non-empty string")
    rule = record["rule"]
    if not isinstance(rule.get("id"), str) or not rule["id"]:
        raise BlindInputError("rule.id must be a non-empty string")
    if not isinstance(rule.get("ruleset_commit"), str) or not _SHA40.fullmatch(
        rule["ruleset_commit"]
    ):
        raise BlindInputError("rule.ruleset_commit must be a full lowercase SHA-1")
    cwe = rule.get("cwe", [])
    if (
        not isinstance(cwe, list)
        or len(cwe) > 128
        or any(not isinstance(item, str) for item in cwe)
        or len(cwe) != len(set(cwe))
    ):
        raise BlindInputError("rule.cwe must contain unique strings")
    for field in ("category", "severity"):
        if rule.get(field) is not None and not isinstance(rule[field], str):
            raise BlindInputError(f"rule.{field} must be a string or null")
    if not isinstance(record.get("message"), str):
        raise BlindInputError("message must be a string")
    for field in ("snippet", "fingerprint"):
        if record.get(field) is not None and not isinstance(record[field], str):
            raise BlindInputError(f"{field} must be a string or null")
    provenance = record["provenance"]
    if not isinstance(provenance.get("raw_result_ref"), str) or not provenance[
        "raw_result_ref"
    ]:
        raise BlindInputError("provenance.raw_result_ref must be a non-empty string")
    if provenance.get("scan_id") is not None and not isinstance(
        provenance["scan_id"], str
    ):
        raise BlindInputError("provenance.scan_id must be a string")
    evidence_refs = provenance.get("evidence_refs", [])
    if (
        not isinstance(evidence_refs, list)
        or len(evidence_refs) > 512
        or any(not isinstance(item, str) or not item for item in evidence_refs)
        or len(evidence_refs) != len(set(evidence_refs))
    ):
        raise BlindInputError("provenance.evidence_refs must contain unique strings")
    observed_by = provenance.get("observed_by") or []
    if not isinstance(observed_by, list) or len(observed_by) > 512:
        raise BlindInputError("provenance.observed_by must be an array")
    for index, observation in enumerate(observed_by):
        if not isinstance(observation, dict):
            raise BlindInputError(f"provenance.observed_by[{index}] must be an object")
        _require_allowed_keys(
            observation, "observed_by", f"provenance.observed_by[{index}]"
        )
        if any(
            not isinstance(observation.get(field), str) or not observation[field]
            for field in ("scanner", "rule_id")
        ):
            raise BlindInputError(
                f"provenance.observed_by[{index}] fields must be non-empty strings"
            )
    location = record["location"]
    normalize_source_path(location.get("file"))
    _validate_line_span(
        location.get("start_line"), location.get("end_line"), "location"
    )
    trace = record.get("dataflow_trace")
    if trace is None:
        trace = []
    if not isinstance(trace, list):
        raise BlindInputError("dataflow_trace must be an array")
    if len(trace) > limits.max_trace_nodes:
        raise BlindInputError(
            f"dataflow_trace exceeds {limits.max_trace_nodes} nodes"
        )
    for index, node in enumerate(trace):
        if not isinstance(node, dict):
            raise BlindInputError(f"dataflow_trace[{index}] must be an object")
        _require_allowed_keys(node, "trace", f"dataflow_trace[{index}]")
        normalize_source_path(node.get("file"))
        parse_trace_line(node.get("line"), f"dataflow_trace[{index}]")
        if not isinstance(node.get("description"), str):
            raise BlindInputError(
                f"dataflow_trace[{index}].description must be a string"
            )
        if node.get("code") is not None and not isinstance(node["code"], str):
            raise BlindInputError(
                f"dataflow_trace[{index}].code must be a string or null"
            )


def validate_blind_input(
    records: list[dict[str, Any]], profile: "AgentProfile | None" = None
) -> None:
    limits = profile or AgentProfile.default_limits()
    if len(records) > limits.max_input_records:
        raise BlindInputError(
            f"blind input exceeds {limits.max_input_records} records"
        )
    seen: set[str] = set()
    for index, record in enumerate(records, 1):
        try:
            validate_blind_record(record, limits)
        except (BlindInputError, SourcePolicyError, ValueError) as exc:
            raise BlindInputError(f"blind record {index}: {exc}") from exc
        finding_id = str(record["finding_id"])
        if finding_id in seen:
            raise BlindInputError(f"duplicate finding_id: {finding_id}")
        seen.add(finding_id)


@dataclass(frozen=True)
class AgentProfile:
    profile_id: str
    max_steps: int
    max_tool_calls_per_step: int
    max_context_chars: int
    max_read_lines: int
    max_source_file_bytes: int
    max_search_results: int
    max_directory_entries: int
    initial_context_radius: int
    trace_context_radius: int
    max_initial_trace_nodes: int
    max_evidence_lines: int
    search_timeout_seconds: int
    provider_timeout_seconds: int
    threat_model: str
    max_input_bytes: int = 268_435_456
    max_input_line_bytes: int = 8_388_608
    max_input_records: int = 10_000
    max_input_depth: int = 16
    max_input_container_items: int = 100_000
    max_input_string_chars: int = 1_000_000
    max_trace_nodes: int = 512
    max_search_output_bytes: int = 2_097_152
    max_provider_event_bytes: int = 16_777_216
    max_provider_response_bytes: int = 1_048_576

    @classmethod
    def default_limits(cls) -> "AgentProfile":
        return cls(
            profile_id="default-input-limits",
            max_steps=5,
            max_tool_calls_per_step=4,
            max_context_chars=80_000,
            max_read_lines=180,
            max_source_file_bytes=2_000_000,
            max_search_results=40,
            max_directory_entries=100,
            initial_context_radius=16,
            trace_context_radius=5,
            max_initial_trace_nodes=12,
            max_evidence_lines=25,
            search_timeout_seconds=15,
            provider_timeout_seconds=900,
            threat_model="default bounded-input validation",
        )

    @classmethod
    def load(cls, path: Path) -> "AgentProfile":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("schema_version") != 1:
            raise ValueError("verifier profile must be a schema_version 1 object")
        limits = raw.get("limits")
        if not isinstance(limits, dict):
            raise ValueError("verifier profile limits must be an object")
        defaults = cls.default_limits()
        values = {
            "profile_id": raw.get("profile_id"),
            "threat_model": raw.get("threat_model"),
            **{
                field: limits.get(field, getattr(defaults, field))
                for field in cls.__dataclass_fields__
                if field not in {"profile_id", "threat_model"}
            },
        }
        string_fields = ("profile_id", "threat_model")
        for field in string_fields:
            if not isinstance(values.get(field), str) or not values[field]:
                raise ValueError(f"verifier profile {field} must be non-empty")
        integer_fields = (
            "max_steps",
            "max_tool_calls_per_step",
            "max_context_chars",
            "max_read_lines",
            "max_source_file_bytes",
            "max_search_results",
            "max_directory_entries",
            "initial_context_radius",
            "trace_context_radius",
            "max_initial_trace_nodes",
            "max_evidence_lines",
            "search_timeout_seconds",
            "provider_timeout_seconds",
            "max_input_bytes",
            "max_input_line_bytes",
            "max_input_records",
            "max_input_depth",
            "max_input_container_items",
            "max_input_string_chars",
            "max_trace_nodes",
            "max_search_output_bytes",
            "max_provider_event_bytes",
            "max_provider_response_bytes",
        )
        for field in integer_fields:
            value = values.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"verifier profile {field} must be a positive integer")
        if values["max_steps"] > 12 or values["max_tool_calls_per_step"] > 12:
            raise ValueError("verifier profile tool-loop limits are unreasonably high")
        if values["max_input_line_bytes"] > values["max_input_bytes"]:
            raise ValueError("max_input_line_bytes cannot exceed max_input_bytes")
        return cls(**{field: values[field] for field in cls.__dataclass_fields__})


class SnapshotResolver:
    def __init__(self, root: Path, *, verify_git: bool = True):
        self.root = root.resolve(strict=True)
        self.verify_git = verify_git
        self._verified: set[tuple[str, str]] = set()

    def resolve(self, record: dict[str, Any]) -> Path:
        slug = repo_slug(str(record["repo_url"]))
        commit = str(record["commit"])
        candidate = (self.root / slug / commit).resolve(strict=True)
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise SourcePolicyError(f"snapshot escapes configured root: {candidate}") from exc
        if not candidate.is_dir():
            raise SourcePolicyError(f"snapshot is not a directory: {candidate}")
        identity = (slug, commit)
        if self.verify_git and identity not in self._verified:
            verify_snapshot_state(candidate, commit)
            self._verified.add(identity)
        return candidate


def _redact_advisory_ids(value: str) -> str:
    value = _ADVISORY_ID.sub("[REDACTED_ADVISORY_ID]", value)
    return _ENTRY_ID.sub("[REDACTED_VULNGYM_ENTRY]", value)


class EvidenceToolbox:
    """Read-only, bounded source tools; the model never receives filesystem access."""

    def __init__(self, root: Path, profile: AgentProfile):
        self.root = root.resolve(strict=True)
        self.profile = profile
        self.context_chars = 0
        self.exposed_ranges: dict[str, list[tuple[int, int]]] = {}

    def _safe_path(self, relative: Any) -> tuple[str, Path]:
        normalized = normalize_source_path(relative)
        current = self.root
        for part in PurePosixPath(normalized).parts:
            current = current / part
            if current.is_symlink():
                raise SourcePolicyError(f"symlink source path is forbidden: {normalized}")
        resolved = current.resolve(strict=True)
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise SourcePolicyError(f"source path escapes snapshot: {normalized}") from exc
        return normalized, resolved

    def _consume(self, result: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        remaining = self.profile.max_context_chars - self.context_chars
        if len(encoded) > remaining:
            return {
                "ok": False,
                "error": "CONTEXT_BUDGET_EXHAUSTED",
                "remaining_chars": max(0, remaining),
            }
        self.context_chars += len(encoded)
        return result

    def _read_lines(
        self, relative: Any, start_line: int, end_line: int, *, expose: bool = True
    ) -> dict[str, Any]:
        if (
            not isinstance(start_line, int)
            or not isinstance(end_line, int)
            or start_line < 1
            or end_line < start_line
        ):
            raise SourcePolicyError("read_file requires a valid inclusive line range")
        if end_line - start_line + 1 > self.profile.max_read_lines:
            raise SourcePolicyError(
                f"read range exceeds {self.profile.max_read_lines} lines"
            )
        normalized, path = self._safe_path(relative)
        if not path.is_file():
            raise SourcePolicyError(f"source path is not a regular file: {normalized}")
        size = path.stat().st_size
        if size > self.profile.max_source_file_bytes:
            raise SourcePolicyError(
                f"source file exceeds {self.profile.max_source_file_bytes} bytes: {normalized}"
            )
        payload = path.read_bytes()
        if b"\0" in payload:
            raise SourcePolicyError(f"binary source file is forbidden: {normalized}")
        lines = payload.decode("utf-8", errors="replace").splitlines()
        if start_line > len(lines):
            raise SourcePolicyError(
                f"line {start_line} exceeds {len(lines)} lines in {normalized}"
            )
        actual_end = min(end_line, len(lines))
        content = "\n".join(
            f"{line_number}: {_redact_advisory_ids(lines[line_number - 1])}"
            for line_number in range(start_line, actual_end + 1)
        )
        if expose:
            self.exposed_ranges.setdefault(normalized, []).append(
                (start_line, actual_end)
            )
        return {
            "ok": True,
            "tool": "read_file",
            "path": normalized,
            "start_line": start_line,
            "end_line": actual_end,
            "content": content,
        }

    def read_file(self, relative: Any, start_line: Any, end_line: Any) -> dict[str, Any]:
        result = self._read_lines(relative, start_line, end_line, expose=False)
        consumed = self._consume(result)
        if consumed.get("ok") is True:
            self.exposed_ranges.setdefault(str(result["path"]), []).append(
                (int(result["start_line"]), int(result["end_line"]))
            )
        return consumed

    def search_code(
        self,
        query: Any,
        relative: Any = ".",
        case_sensitive: Any = True,
    ) -> dict[str, Any]:
        if not isinstance(query, str) or not query or len(query) > 200:
            raise SourcePolicyError("search query must contain 1-200 characters")
        if any(character in query for character in ("\x00", "\r", "\n")):
            raise SourcePolicyError("search query must be a single text line")
        if relative in (None, "", "."):
            normalized_scope, scope_path = ".", self.root
        else:
            normalized_scope, scope_path = self._safe_path(relative)
        if not scope_path.exists():
            raise SourcePolicyError(f"search scope does not exist: {normalized_scope}")
        command = [
            "rg",
            "--fixed-strings",
            "--line-number",
            "--column",
            "--no-heading",
            "--color",
            "never",
            "--max-columns",
            "1000",
            "--max-columns-preview",
            "--glob",
            "!**/.git/**",
            "--glob",
            "!**/node_modules/**",
            "--glob",
            "!**/.venv/**",
            "--glob",
            "!**/vendor/**",
            "--glob",
            "!**/dist/**",
            "--glob",
            "!**/build/**",
        ]
        if case_sensitive is False:
            command.append("--ignore-case")
        command.extend(["--", query, normalized_scope])
        matches: list[dict[str, Any]] = []
        pending_exposures: list[tuple[str, int]] = []
        pattern = re.compile(r"^(.*?):([1-9][0-9]*):([1-9][0-9]*):(.*)$")
        timed_out = threading.Event()
        stopped_at_limit = False
        stdout_bytes = 0
        process: subprocess.Popen[bytes] | None = None

        def expire() -> None:
            timed_out.set()
            if process is not None:
                _terminate_process_tree(process)  # type: ignore[arg-type]

        try:
            with tempfile.TemporaryFile() as stderr_handle:
                process = subprocess.Popen(
                command,
                cwd=self.root,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=stderr_handle,
                    creationflags=(
                        subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
                    ),
                    start_new_session=os.name != "nt",
                )
                assert process.stdout is not None
                timer = threading.Timer(self.profile.search_timeout_seconds, expire)
                timer.daemon = True
                timer.start()
                try:
                    while True:
                        raw = process.stdout.readline(self.profile.max_input_line_bytes + 1)
                        if not raw:
                            break
                        stdout_bytes += len(raw)
                        if len(raw) > self.profile.max_input_line_bytes:
                            raise SourcePolicyError("source search emitted an oversized line")
                        if stdout_bytes > self.profile.max_search_output_bytes:
                            raise SourcePolicyError("source search exceeded its output budget")
                        parsed = pattern.match(raw.decode("utf-8", errors="replace").rstrip("\r\n"))
                        if not parsed:
                            continue
                        raw_path, raw_line, raw_column, code = parsed.groups()
                        match_path = normalize_source_path(raw_path)
                        line = int(raw_line)
                        pending_exposures.append((match_path, line))
                        matches.append(
                            {
                                "path": match_path,
                                "line": line,
                                "column": int(raw_column),
                                "code": _redact_advisory_ids(code),
                            }
                        )
                        if len(matches) >= self.profile.max_search_results:
                            stopped_at_limit = True
                            _terminate_process_tree(process)  # type: ignore[arg-type]
                            break
                    process.wait(timeout=30)
                finally:
                    timer.cancel()
                    if process.poll() is None:
                        _terminate_process_tree(process)  # type: ignore[arg-type]
                        process.wait(timeout=30)
                if timed_out.is_set():
                    raise SourcePolicyError("source search exceeded its timeout")
                if process.returncode not in (0, 1) and not stopped_at_limit:
                    stderr_handle.seek(0)
                    detail = stderr_handle.read(1000).decode("utf-8", errors="replace")
                    raise SourcePolicyError(f"source search failed: {detail.strip()}")
        except FileNotFoundError as exc:
            raise SourcePolicyError("rg is required for bounded source search") from exc
        consumed = self._consume(
            {
                "ok": True,
                "tool": "search_code",
                "query": query,
                "scope": normalized_scope,
                "matches": matches,
                "truncated": stopped_at_limit,
            }
        )
        if consumed.get("ok") is True:
            for match_path, line in pending_exposures:
                self.exposed_ranges.setdefault(match_path, []).append((line, line))
        return consumed

    def list_directory(self, relative: Any = ".") -> dict[str, Any]:
        if relative in (None, "", "."):
            normalized, path = ".", self.root
        else:
            normalized, path = self._safe_path(relative)
        if not path.is_dir():
            raise SourcePolicyError(f"directory does not exist: {normalized}")
        entries = []
        for child in sorted(path.iterdir(), key=lambda item: item.name.casefold()):
            if child.name == ".git" or child.is_symlink():
                continue
            entries.append(child.name + ("/" if child.is_dir() else ""))
            if len(entries) >= self.profile.max_directory_entries:
                break
        return self._consume(
            {
                "ok": True,
                "tool": "list_directory",
                "path": normalized,
                "entries": entries,
                "truncated": len(entries) >= self.profile.max_directory_entries,
            }
        )

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        try:
            tool = request.get("tool")
            if tool == "read_file":
                return self.read_file(
                    request.get("path"),
                    request.get("start_line"),
                    request.get("end_line"),
                )
            if tool == "search_code":
                return self.search_code(
                    request.get("query"),
                    request.get("path") or ".",
                    request.get("case_sensitive", True),
                )
            if tool == "list_directory":
                return self.list_directory(request.get("path") or ".")
            raise SourcePolicyError(f"unknown source tool: {tool!r}")
        except (SourcePolicyError, OSError) as exc:
            return {"ok": False, "error": type(exc).__name__, "detail": str(exc)}

    def initial_observations(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        observations: list[dict[str, Any]] = []
        location = record["location"]
        start = max(1, int(location["start_line"]) - self.profile.initial_context_radius)
        end = int(location["end_line"]) + self.profile.initial_context_radius
        observations.append(
            self.execute(
                {
                    "tool": "read_file",
                    "path": location["file"],
                    "start_line": start,
                    "end_line": end,
                }
            )
        )
        trace = record.get("dataflow_trace") or []
        if len(trace) > self.profile.max_initial_trace_nodes:
            head = self.profile.max_initial_trace_nodes // 2
            tail = self.profile.max_initial_trace_nodes - head
            trace = [*trace[:head], *trace[-tail:]]
        seen: set[tuple[str, int, int]] = set()
        for index, node in enumerate(trace):
            try:
                line_start, line_end = parse_trace_line(
                    node.get("line"), f"dataflow_trace[{index}]"
                )
                path = normalize_source_path(node.get("file"))
            except (BlindInputError, SourcePolicyError) as exc:
                observations.append(
                    {"ok": False, "error": type(exc).__name__, "detail": str(exc)}
                )
                continue
            read_start = max(1, line_start - self.profile.trace_context_radius)
            read_end = line_end + self.profile.trace_context_radius
            key = (path, read_start, read_end)
            if key in seen:
                continue
            seen.add(key)
            observations.append(
                self.execute(
                    {
                        "tool": "read_file",
                        "path": path,
                        "start_line": read_start,
                        "end_line": read_end,
                    }
                )
            )
        return observations

    def evidence_node(self, citation: dict[str, Any]) -> dict[str, Any]:
        path = normalize_source_path(citation.get("file"))
        start = citation.get("start_line")
        end = citation.get("end_line")
        description = citation.get("description")
        if not isinstance(description, str) or not description.strip():
            raise PredictionError("evidence description must be non-empty")
        if (
            not isinstance(start, int)
            or not isinstance(end, int)
            or start < 1
            or end < start
            or end - start + 1 > self.profile.max_evidence_lines
        ):
            raise PredictionError("evidence line range is invalid or too large")
        if not any(
            exposed_start <= start and end <= exposed_end
            for exposed_start, exposed_end in self.exposed_ranges.get(path, [])
        ):
            raise PredictionError(
                f"evidence was not exposed to the verifier: {path}:{start}-{end}"
            )
        source = self._read_lines(path, start, end, expose=False)
        line: int | str = start if start == end else f"{start}-{end}"
        return {
            "file": path,
            "line": line,
            "description": description.strip(),
            "code": source["content"],
        }


class Provider(Protocol):
    provider_id: str
    model: str | None
    version: str
    stateful: bool

    def complete(
        self,
        request: dict[str, Any],
        *,
        case_directory: Path,
        step: int,
    ) -> dict[str, Any]: ...


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def audit_provider_events(
    path: Path, *, max_bytes: int = 16_777_216
) -> dict[str, Any]:
    if path.stat().st_size > max_bytes:
        raise ProviderError("provider event log exceeds its byte budget")
    thread_id: str | None = None
    saw_turn_started = False
    saw_turn_completed = False
    agent_messages: list[str] = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ProviderError(
                    f"provider event log line {line_number} is not JSON"
                ) from exc
            if not isinstance(event, dict):
                raise ProviderError(
                    f"provider event log line {line_number} is not an object"
                )
            event_type = event.get("type")
            if event_type not in _ALLOWED_PROVIDER_EVENT_KEYS:
                raise ProviderError(
                    f"provider emitted unapproved event type at line {line_number}: "
                    f"{event_type!r}"
                )
            unexpected = set(event) - _ALLOWED_PROVIDER_EVENT_KEYS[str(event_type)]
            if unexpected:
                raise ProviderError(
                    f"provider event {event_type} has unapproved fields: {sorted(unexpected)}"
                )
            if event_type == "thread.started":
                value = event.get("thread_id")
                if not isinstance(value, str) or not value or thread_id is not None:
                    raise ProviderError("provider reported an invalid thread lifecycle")
                thread_id = value
            elif event_type == "turn.started":
                if saw_turn_started or saw_turn_completed:
                    raise ProviderError("provider reported an invalid turn lifecycle")
                saw_turn_started = True
            elif event_type == "item.completed":
                item = event.get("item")
                if not isinstance(item, dict):
                    raise ProviderError("provider item event must contain an object")
                unexpected_item = set(item) - _ALLOWED_PROVIDER_ITEM_KEYS
                if unexpected_item:
                    raise ProviderError(
                        "provider item event has unapproved fields: "
                        f"{sorted(unexpected_item)}"
                    )
                if item.get("type") != "agent_message":
                    raise ProviderError(
                        "provider used an unapproved direct capability: "
                        f"{item.get('type')!r}"
                    )
                text = item.get("text")
                if not isinstance(text, str):
                    raise ProviderError("provider agent message must contain text")
                agent_messages.append(text)
            elif event_type == "turn.completed":
                if not saw_turn_started or saw_turn_completed:
                    raise ProviderError("provider reported an invalid turn completion")
                usage = event.get("usage")
                if not isinstance(usage, dict) or not all(
                    isinstance(key, str)
                    and isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    for key, value in usage.items()
                ):
                    raise ProviderError("provider turn usage must be non-negative integers")
                saw_turn_completed = True
    if not thread_id or not saw_turn_started or not saw_turn_completed or not agent_messages:
        raise ProviderError("provider event log is missing an approved completed turn")
    return {
        "thread_id": thread_id,
        "final_agent_message": agent_messages[-1],
        "agent_message_count": len(agent_messages),
    }


class CodexCliProvider:
    provider_id = "codex-cli-isolated-json"
    stateful = True

    def __init__(
        self,
        *,
        executable: str,
        response_schema: Path,
        prompt_text: str,
        timeout_seconds: int,
        model: str | None = None,
        max_event_bytes: int = 16_777_216,
        max_response_bytes: int = 1_048_576,
    ):
        resolved = shutil.which(executable)
        if not resolved:
            raise ProviderError(f"Codex CLI executable not found: {executable}")
        self.executable = resolved
        self.response_schema = response_schema.resolve(strict=True)
        self.response_schema_sha256 = sha256_file(self.response_schema)
        self.prompt_text = prompt_text
        self.timeout_seconds = timeout_seconds
        self.model = model
        self.max_event_bytes = max_event_bytes
        self.max_response_bytes = max_response_bytes
        version_result = subprocess.run(
            [self.executable, "--version"],
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=30,
        )
        if version_result.returncode != 0:
            raise ProviderError("unable to read Codex CLI version")
        self.version = version_result.stdout.strip()
        self._sandboxes: dict[str, tempfile.TemporaryDirectory[str]] = {}
        self._session_ids: dict[str, str] = {}

    @staticmethod
    def _case_key(case_directory: Path) -> str:
        return str(case_directory.resolve())

    def _sandbox_for(self, case_directory: Path) -> Path:
        key = self._case_key(case_directory)
        temporary = self._sandboxes.get(key)
        if temporary is None:
            temporary = tempfile.TemporaryDirectory(
                prefix="vulngym-verifier-provider-"
            )
            self._sandboxes[key] = temporary
        return Path(temporary.name)

    def close_case(self, case_directory: Path) -> None:
        key = self._case_key(case_directory)
        temporary = self._sandboxes.pop(key, None)
        self._session_ids.pop(key, None)
        if temporary is not None:
            temporary.cleanup()

    @staticmethod
    def _thread_id(events_path: Path) -> str | None:
        with events_path.open(encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                if not raw.strip():
                    continue
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                thread_id = event.get("thread_id") if isinstance(event, dict) else None
                if event.get("type") == "thread.started" and isinstance(thread_id, str):
                    return thread_id
        return None

    def complete(
        self,
        request: dict[str, Any],
        *,
        case_directory: Path,
        step: int,
    ) -> dict[str, Any]:
        case_directory.mkdir(parents=True, exist_ok=True)
        events_path = case_directory / f"step-{step:02d}-events.jsonl"
        stderr_path = case_directory / f"step-{step:02d}-stderr.log"
        response_path = case_directory / f"step-{step:02d}-response.json"
        key = self._case_key(case_directory)
        sandbox = self._sandbox_for(case_directory)
        request_text = (
            "<controller_request>\n"
            + json.dumps(request, ensure_ascii=False, indent=2)
            + "\n</controller_request>\n"
        )
        if step == 1:
            prompt = self.prompt_text.rstrip() + "\n\n" + request_text
            command = [
                self.executable,
                "exec",
                "--ignore-user-config",
                "--ignore-rules",
                "--sandbox",
                "read-only",
                "--skip-git-repo-check",
                "--color",
                "never",
                "--json",
                "--output-schema",
                str(self.response_schema),
                "--output-last-message",
                str(response_path.resolve()),
                "-C",
                str(sandbox),
            ]
        else:
            session_id = self._session_ids.get(key)
            if not session_id:
                raise ProviderError("Codex session ID is missing for a resumed verifier step")
            prompt = (
                "Use only this new controller response and the prior conversation. "
                "Continue following the original isolation and JSON rules.\n\n"
                + request_text
            )
            command = [
                self.executable,
                "exec",
                "resume",
                "--ignore-user-config",
                "--ignore-rules",
                "--skip-git-repo-check",
                "--json",
                "--output-schema",
                str(self.response_schema),
                "--output-last-message",
                str(response_path.resolve()),
            ]
        if self.model:
            command.extend(["--model", self.model])
        if step > 1:
            command.append(self._session_ids[key])
        command.append("-")
        creation_flags = (
            subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        )
        with events_path.open("w", encoding="utf-8", newline="\n") as stdout_handle, stderr_path.open(
            "w", encoding="utf-8", newline="\n"
        ) as stderr_handle:
            process = subprocess.Popen(
                command,
                cwd=sandbox,
                stdin=subprocess.PIPE,
                stdout=stdout_handle,
                stderr=stderr_handle,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=creation_flags,
                start_new_session=os.name != "nt",
            )
            try:
                process.communicate(prompt, timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                _terminate_process_tree(process)
                process.wait(timeout=30)
                raise ProviderError(
                    f"Codex provider exceeded {self.timeout_seconds}s at step {step}"
                ) from exc
            except BaseException:
                _terminate_process_tree(process)
                process.wait(timeout=30)
                raise
        if process.returncode != 0:
            stderr_detail = stderr_path.read_text(
                encoding="utf-8", errors="replace"
            )[-2000:]
            events_detail = events_path.read_text(
                encoding="utf-8", errors="replace"
            )[-4000:]
            raw_detail = "\n".join(
                part.strip() for part in (stderr_detail, events_detail) if part.strip()
            )
            failure_code = _classify_provider_failure(raw_detail)
            persisted_code = failure_code or "PROVIDER_EXIT_NONZERO"
            _atomic_write_text(
                stderr_path,
                f"provider_failure={persisted_code} exit={process.returncode} step={step}\n",
            )
            _atomic_write_text(
                events_path,
                json.dumps(
                    {
                        "type": "provider.failure",
                        "code": persisted_code,
                        "exit_code": process.returncode,
                        "step": step,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n",
            )
            if failure_code:
                raise TerminalProviderError(failure_code)
            raise ProviderError(
                f"PROVIDER_EXIT_NONZERO exit={process.returncode} step={step}"
            )
        audit = audit_provider_events(events_path, max_bytes=self.max_event_bytes)
        thread_id = str(audit["thread_id"])
        if step == 1:
            if not thread_id:
                raise ProviderError("Codex provider did not report a session ID")
            self._session_ids[key] = thread_id
            _write_json(
                case_directory / "provider-session.json",
                {"provider": self.provider_id, "thread_id": thread_id},
            )
        elif thread_id and thread_id != self._session_ids[key]:
            raise ProviderError("Codex resumed an unexpected verifier session")
        if not response_path.is_file():
            raise ProviderError(f"Codex provider did not write step {step} response")
        if response_path.stat().st_size > self.max_response_bytes:
            raise ProviderError("Codex provider response exceeds its byte budget")
        try:
            response = json.loads(response_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProviderError(f"Codex provider returned invalid JSON at step {step}") from exc
        if not isinstance(response, dict):
            raise ProviderError("Codex provider response must be an object")
        try:
            audited_response = json.loads(str(audit["final_agent_message"]))
        except json.JSONDecodeError as exc:
            raise ProviderError(
                "audited provider message is not the structured response"
            ) from exc
        if audited_response != response:
            raise ProviderError(
                "output-last-message does not match the audited provider event"
            )
        return response


def _require_text(response: dict[str, Any], field: str) -> str:
    value = response.get(field)
    if not isinstance(value, str) or not value.strip():
        raise PredictionError(f"final response {field} must be non-empty")
    return value.strip()


def validate_provider_response(response: dict[str, Any]) -> str:
    unexpected = sorted(set(response) - _ALLOWED_RESPONSE_KEYS)
    if unexpected:
        raise ProviderError(f"provider response has unexpected keys: {unexpected}")
    missing = sorted(_ALLOWED_RESPONSE_KEYS - set(response))
    if missing:
        raise ProviderError(f"provider response is missing keys: {missing}")
    action = response.get("action")
    if action not in {"REQUEST_TOOLS", "FINAL"}:
        raise ProviderError(f"invalid provider action: {action!r}")
    if not isinstance(response.get("working_hypothesis"), str):
        raise ProviderError("working_hypothesis must be a string")
    requests = response.get("tool_requests")
    if not isinstance(requests, list):
        raise ProviderError("tool_requests must be an array")
    return str(action)


def _validate_final_response(
    response: dict[str, Any], toolbox: EvidenceToolbox
) -> dict[str, Any]:
    if response.get("tool_requests"):
        raise PredictionError("FINAL response must not contain tool requests")
    verdict = response.get("verdict")
    confidence = response.get("confidence")
    reason_codes = response.get("reason_codes")
    if verdict not in VERDICTS:
        raise PredictionError(f"invalid verdict: {verdict!r}")
    if confidence not in CONFIDENCES:
        raise PredictionError(f"invalid confidence: {confidence!r}")
    if not isinstance(reason_codes, list) or not all(
        isinstance(code, str) for code in reason_codes
    ):
        raise PredictionError("reason_codes must be an array of strings")
    if len(set(reason_codes)) != len(reason_codes):
        raise PredictionError("reason_codes must be unique")
    unknown_codes = sorted(set(reason_codes) - FP_REASON_CODES)
    if unknown_codes:
        raise PredictionError(f"unknown false-positive reason codes: {unknown_codes}")
    if verdict == "FALSE_POSITIVE" and not reason_codes:
        raise PredictionError("FALSE_POSITIVE requires at least one reason code")
    if verdict != "FALSE_POSITIVE" and reason_codes:
        raise PredictionError("only FALSE_POSITIVE may contain false-positive reason codes")
    abstain_reason = response.get("abstain_reason")
    if verdict == "ABSTAIN":
        if abstain_reason not in ABSTAIN_REASONS:
            raise PredictionError("ABSTAIN requires a valid abstain_reason")
    elif abstain_reason is not None:
        raise PredictionError("non-ABSTAIN response must set abstain_reason to null")
    evidence = response.get("evidence")
    if not isinstance(evidence, list):
        raise PredictionError("evidence must be an array")
    if verdict != "ABSTAIN" and not evidence:
        raise PredictionError(f"{verdict} requires source evidence")
    if len(evidence) > 12 or not all(isinstance(item, dict) for item in evidence):
        raise PredictionError("evidence must contain at most 12 objects")
    normalized_evidence: list[dict[str, Any]] = []
    for item in evidence:
        start = item.get("start_line")
        end = item.get("end_line")
        if (
            isinstance(start, int)
            and isinstance(end, int)
            and start >= 1
            and end >= start
            and end - start + 1 > toolbox.profile.max_evidence_lines
        ):
            for chunk_start in range(
                start, end + 1, toolbox.profile.max_evidence_lines
            ):
                chunk = dict(item)
                chunk["start_line"] = chunk_start
                chunk["end_line"] = min(
                    end, chunk_start + toolbox.profile.max_evidence_lines - 1
                )
                normalized_evidence.append(chunk)
        else:
            normalized_evidence.append(item)
    if len(normalized_evidence) > 12:
        raise PredictionError(
            "evidence exceeds 12 objects after splitting oversized ranges"
        )
    evidence_nodes = [toolbox.evidence_node(item) for item in normalized_evidence]
    return {
        "verdict": verdict,
        "confidence": confidence,
        "reason_codes": reason_codes,
        "attacker_capability": _require_text(response, "attacker_capability"),
        "entry_point": _require_text(response, "entry_point"),
        "security_effect": _require_text(response, "security_effect"),
        "controls": _require_text(response, "controls"),
        "reasoning": _require_text(response, "reasoning"),
        "evidence": evidence_nodes,
        "abstain_reason": abstain_reason,
    }


def _truncate_model_text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    if len(text) <= limit:
        return text
    marker = "...[TRUNCATED_BY_CONTROLLER]"
    return text[: max(0, limit - len(marker))] + marker


def model_finding_projection(
    record: dict[str, Any], profile: AgentProfile
) -> dict[str, Any]:
    """Project only non-identity finding facts into a bounded model request."""

    budget = min(
        profile.max_context_chars,
        max(256, max(1_500, profile.max_context_chars // 3)),
    )
    per_text = max(128, min(4_096, budget // 8))
    source_trace = record.get("dataflow_trace") or []
    trace_limit = min(len(source_trace), profile.max_initial_trace_nodes)
    if len(source_trace) > trace_limit:
        head = trace_limit // 2
        tail = trace_limit - head
        selected_trace = [*source_trace[:head], *source_trace[-tail:]]
    else:
        selected_trace = source_trace
    trace = []
    for node in selected_trace:
        trace.append(
            {
                "file": node.get("file"),
                "line": node.get("line"),
                "description": _truncate_model_text(node.get("description"), per_text),
                "code": _truncate_model_text(node.get("code"), per_text),
            }
        )
    projection: dict[str, Any] = {
        "scanner": {
            key: record["scanner"].get(key) for key in ("name", "version")
        },
        "rule": {
            key: record["rule"].get(key)
            for key in ("id", "ruleset_commit", "cwe", "category", "severity")
            if key in record["rule"]
        },
        "message": _truncate_model_text(record.get("message"), per_text),
        "location": {
            key: record["location"].get(key)
            for key in ("file", "start_line", "end_line", "start_col", "end_col")
            if key in record["location"]
        },
        "dataflow_trace": trace,
        "snippet": _truncate_model_text(record.get("snippet"), per_text),
    }
    while len(json.dumps(projection, ensure_ascii=False, separators=(",", ":"))) > budget:
        if projection["dataflow_trace"]:
            projection["dataflow_trace"].pop()
            continue
        changed = False
        for field in ("message", "snippet"):
            value = projection[field]
            if isinstance(value, str) and len(value) > 64:
                projection[field] = _truncate_model_text(value, max(64, len(value) // 2))
                changed = True
        if not changed:
            break
    encoded = json.dumps(projection, ensure_ascii=False, separators=(",", ":"))
    if len(encoded) > budget:
        raise ProviderError("bounded model finding projection exceeds context budget")
    return projection


def run_finding(
    *,
    record: dict[str, Any],
    snapshot: Path,
    profile: AgentProfile,
    provider: Provider,
    case_directory: Path,
    evaluation_eligible: bool = True,
    exclusion_reason: str | None = None,
) -> dict[str, Any]:
    toolbox = EvidenceToolbox(snapshot, profile)
    model_finding = model_finding_projection(record, profile)
    toolbox.context_chars = len(
        json.dumps(model_finding, ensure_ascii=False, separators=(",", ":"))
    )
    observations = toolbox.initial_observations(record)
    history: list[dict[str, Any]] = []
    total_tool_calls = 0
    try:
        for step in range(1, profile.max_steps + 1):
            request = {
            "protocol_version": 1,
            "task": "blind_security_finding_verification",
            "step": step,
            "remaining_steps_after_this": profile.max_steps - step,
            "threat_model": profile.threat_model,
            "finding": model_finding,
            "initial_observations": observations,
            "tool_history": history,
            "available_controller_tools": {
                "read_file": {
                    "arguments": ["path", "start_line", "end_line"],
                    "max_lines": profile.max_read_lines,
                },
                "search_code": {
                    "arguments": ["query", "path", "case_sensitive"],
                    "fixed_string_only": True,
                    "max_results": profile.max_search_results,
                },
                "list_directory": {
                    "arguments": ["path"],
                    "max_entries": profile.max_directory_entries,
                },
            },
            "decision_policy": {
                "true_positive": "prove attacker influence, reachable entry, security effect, and no effective blocking control",
                "false_positive": "prove a concrete negating condition; absence of proof is not false-positive evidence",
                "abstain": "use when relevant source evidence remains insufficient or conflicting",
                "direct_model_tools_forbidden": True,
                "evidence_must_be_previously_exposed": True,
                "max_lines_per_evidence_citation": profile.max_evidence_lines,
            },
            }
            if step > 1 and getattr(provider, "stateful", False):
                request = {
                    "protocol_version": 1,
                    "task": "blind_security_finding_verification_continuation",
                    "step": step,
                    "remaining_steps_after_this": profile.max_steps - step,
                    "latest_controller_exchange": history[-1],
                    "max_lines_per_evidence_citation": profile.max_evidence_lines,
                    "direct_model_tools_forbidden": True,
                }
            response = provider.complete(
                request, case_directory=case_directory, step=step
            )
            action = validate_provider_response(response)
            if action == "FINAL":
                final = _validate_final_response(response, toolbox)
                prediction = {
                "schema_version": 1,
                "finding_id": record["finding_id"],
                **final,
                "evaluation_eligible": evaluation_eligible,
                "agent": {
                    "profile_id": profile.profile_id,
                    "provider": provider.provider_id,
                    "provider_version": provider.version,
                    "model": provider.model,
                    "steps": step,
                    "controller_tool_calls": total_tool_calls,
                },
                }
                if not evaluation_eligible:
                    if not exclusion_reason:
                        raise PredictionError(
                            "ineligible prediction requires an exclusion reason"
                        )
                    prediction["exclusion_reason"] = exclusion_reason
                return prediction
            requests = response["tool_requests"]
            if not requests:
                raise ProviderError("REQUEST_TOOLS response must contain at least one request")
            if len(requests) > profile.max_tool_calls_per_step:
                raise ProviderError(
                    f"provider requested more than {profile.max_tool_calls_per_step} tools"
                )
            if step == profile.max_steps:
                raise ProviderError("provider requested tools after the final permitted step")
            tool_results = []
            for tool_request in requests:
                if not isinstance(tool_request, dict):
                    raise ProviderError("each tool request must be an object")
                tool_results.append(toolbox.execute(tool_request))
                total_tool_calls += 1
            history.append(
                {
                    "step": step,
                    "working_hypothesis": response["working_hypothesis"],
                    "requests": requests,
                    "results": tool_results,
                }
            )
        raise ProviderError("verifier exhausted its step budget without a decision")
    finally:
        close_case = getattr(provider, "close_case", None)
        if callable(close_case):
            close_case(case_directory)


def _load_official_corpus_proof(
    input_path: Path, records: list[dict[str, Any]]
) -> dict[str, Any]:
    summary_path = input_path.parent / "summary.json"
    if not summary_path.is_file():
        raise VerifierError(
            f"official verifier input requires a complete corpus summary: {summary_path}"
        )
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerifierError(f"invalid official corpus summary: {summary_path}") from exc
    if not isinstance(summary, dict) or summary.get("complete") is not True:
        raise VerifierError("official corpus summary must declare complete=true")
    blind = summary.get("blind_verifier_input")
    if not isinstance(blind, dict):
        raise VerifierError("official corpus summary is missing blind_verifier_input proof")
    expected_hash = blind.get("sha256")
    expected_records = blind.get("records")
    declared_path = blind.get("path")
    actual_hash = sha256_file(input_path)
    if (
        not isinstance(expected_hash, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
        or expected_hash != actual_hash
    ):
        raise VerifierError("official corpus blind-input checksum does not match")
    if (
        not isinstance(expected_records, int)
        or isinstance(expected_records, bool)
        or expected_records != len(records)
    ):
        raise VerifierError("official corpus blind-input record count does not match")
    if not isinstance(declared_path, str) or Path(declared_path).name != input_path.name:
        raise VerifierError("official corpus blind-input path does not match")
    return {
        "path": str(summary_path),
        "sha256": sha256_file(summary_path),
        "complete": True,
        "input_sha256": actual_hash,
        "records": len(records),
    }


def _response_schema_identity(provider: Provider) -> tuple[Path, str]:
    path_value = getattr(provider, "response_schema", _DEFAULT_RESPONSE_SCHEMA)
    path = Path(path_value).resolve(strict=True)
    checksum = sha256_file(path)
    declared = getattr(provider, "response_schema_sha256", checksum)
    if declared != checksum:
        raise ProviderError("provider response schema checksum mismatch")
    return path, checksum


def _controller_identity() -> dict[str, str]:
    return {
        "protocol_version": CONTROLLER_PROTOCOL_VERSION,
        "path": str(_CONTROLLER_PATH),
        "sha256": sha256_file(_CONTROLLER_PATH),
    }


def _case_identity(
    *,
    record: dict[str, Any],
    profile_sha256: str,
    prompt_sha256: str,
    provider: Provider,
    evaluation_mode: str,
    response_schema_sha256: str,
    prediction_schema_sha256: str,
    controller_sha256: str,
    corpus_proof_sha256: str | None,
) -> dict[str, Any]:
    return {
        "finding_id": record["finding_id"],
        "record_sha256": sha256_bytes(_json_bytes(record)),
        "profile_sha256": profile_sha256,
        "prompt_sha256": prompt_sha256,
        "provider": provider.provider_id,
        "provider_version": provider.version,
        "model": provider.model,
        "evaluation_mode": evaluation_mode,
        "response_schema_sha256": response_schema_sha256,
        "prediction_schema_sha256": prediction_schema_sha256,
        "controller_sha256": controller_sha256,
        "controller_protocol_version": CONTROLLER_PROTOCOL_VERSION,
        "corpus_proof_sha256": corpus_proof_sha256,
    }


def _provider_usage(case_directory: Path) -> dict[str, int]:
    usage_by_session: dict[str, dict[str, int]] = {}
    for events_path in sorted(case_directory.glob("step-*-events.jsonl")):
        session_id = events_path.stem
        with events_path.open(encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                if not raw.strip():
                    continue
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if (
                    isinstance(event, dict)
                    and event.get("type") == "thread.started"
                    and isinstance(event.get("thread_id"), str)
                ):
                    session_id = str(event["thread_id"])
                usage = event.get("usage") if isinstance(event, dict) else None
                if not isinstance(usage, dict):
                    continue
                current: dict[str, int] = {}
                for key, value in usage.items():
                    if isinstance(value, int) and not isinstance(value, bool):
                        current[str(key)] = value
                if current:
                    # Codex reports cumulative usage when a thread is resumed. Keep the
                    # newest counters for that thread, then sum only distinct threads.
                    usage_by_session[session_id] = current
    totals: dict[str, int] = defaultdict(int)
    for usage in usage_by_session.values():
        for key, value in usage.items():
            totals[key] += value
    return dict(sorted(totals.items()))


def _validate_frozen_prediction(
    prediction: Any,
    *,
    record: dict[str, Any],
    profile: AgentProfile,
    provider: Provider,
    evaluation_mode: str,
) -> dict[str, Any]:
    if not isinstance(prediction, dict):
        raise VerifierError("prediction must be a JSON object")
    unexpected = sorted(set(prediction) - _ALLOWED_PREDICTION_KEYS)
    required = _ALLOWED_PREDICTION_KEYS - {"exclusion_reason"}
    missing = sorted(required - set(prediction))
    if unexpected or missing:
        raise VerifierError(
            f"prediction schema mismatch: unexpected={unexpected}, missing={missing}"
        )
    if prediction.get("schema_version") != 1:
        raise VerifierError("prediction schema_version must be 1")
    if prediction.get("finding_id") != record.get("finding_id"):
        raise VerifierError("prediction finding identity does not match the case")
    if prediction.get("verdict") not in VERDICTS:
        raise VerifierError("prediction verdict is invalid")
    if prediction.get("confidence") not in CONFIDENCES:
        raise VerifierError("prediction confidence is invalid")
    expected_eligible = evaluation_mode == "OFFICIAL"
    if prediction.get("evaluation_eligible") is not expected_eligible:
        raise VerifierError("prediction eligibility does not match evaluation mode")
    if expected_eligible and "exclusion_reason" in prediction:
        raise VerifierError("official prediction cannot carry an exclusion reason")
    if not expected_eligible and prediction.get("exclusion_reason") != (
        "DEVELOPMENT_OR_PARTIAL_INPUT"
    ):
        raise VerifierError("development prediction has an invalid exclusion reason")
    agent = prediction.get("agent")
    expected_agent = {
        "profile_id": profile.profile_id,
        "provider": provider.provider_id,
        "provider_version": provider.version,
        "model": provider.model,
    }
    if not isinstance(agent, dict) or any(
        agent.get(key) != value for key, value in expected_agent.items()
    ):
        raise VerifierError("prediction agent identity does not match the case")
    if set(agent) != {
        "profile_id",
        "provider",
        "provider_version",
        "model",
        "steps",
        "controller_tool_calls",
    }:
        raise VerifierError("prediction agent schema is invalid")
    for key in ("steps", "controller_tool_calls"):
        value = agent.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise VerifierError(f"prediction agent {key} is invalid")
    if agent["steps"] < 1:
        raise VerifierError("prediction agent steps must be positive")
    if agent["steps"] > profile.max_steps:
        raise VerifierError("prediction agent steps exceed the configured limit")
    if agent["controller_tool_calls"] > (
        profile.max_steps * profile.max_tool_calls_per_step
    ):
        raise VerifierError("prediction controller tool calls exceed the configured limit")
    reason_codes = prediction.get("reason_codes")
    if not isinstance(reason_codes, list) or any(
        not isinstance(code, str) for code in reason_codes
    ):
        raise VerifierError("prediction reason_codes schema is invalid")
    if len(reason_codes) != len(set(reason_codes)) or set(reason_codes) - FP_REASON_CODES:
        raise VerifierError("prediction reason_codes are invalid")
    verdict = prediction["verdict"]
    if (verdict == "FALSE_POSITIVE") != bool(reason_codes):
        raise VerifierError("prediction reason_codes do not match verdict")
    abstain_reason = prediction.get("abstain_reason")
    if verdict == "ABSTAIN":
        if abstain_reason not in ABSTAIN_REASONS:
            raise VerifierError("prediction abstain reason is invalid")
    elif abstain_reason is not None:
        raise VerifierError("non-abstain prediction has an abstain reason")
    for field in (
        "attacker_capability",
        "entry_point",
        "security_effect",
        "controls",
        "reasoning",
    ):
        if not isinstance(prediction.get(field), str) or not prediction[field].strip():
            raise VerifierError(f"prediction {field} must be non-empty")
    evidence = prediction.get("evidence")
    if (
        not isinstance(evidence, list)
        or len(evidence) > 12
        or (verdict != "ABSTAIN" and not evidence)
    ):
        raise VerifierError("prediction evidence schema is invalid")
    for index, node in enumerate(evidence):
        if not isinstance(node, dict) or set(node) != {
            "file",
            "line",
            "description",
            "code",
        }:
            raise VerifierError(f"prediction evidence[{index}] schema is invalid")
        try:
            normalize_source_path(node.get("file"))
            start, end = parse_trace_line(
                node.get("line"), f"prediction.evidence[{index}]"
            )
        except (BlindInputError, SourcePolicyError) as exc:
            raise VerifierError(f"prediction evidence[{index}] is invalid: {exc}") from exc
        if end - start + 1 > profile.max_evidence_lines:
            raise VerifierError(
                f"prediction evidence[{index}] exceeds the configured line limit"
            )
        if not all(
            isinstance(node.get(field), str) and node[field]
            for field in ("description", "code")
        ):
            raise VerifierError(f"prediction evidence[{index}] text is invalid")
    return prediction


_CASE_RUNTIME_PATTERNS = (
    "step-*-events.jsonl",
    "step-*-stderr.log",
    "step-*-response.json",
    "provider-session.json",
    "prediction.json",
)


def _next_case_attempt_number(case_directory: Path) -> int:
    attempts_directory = case_directory / "attempts"
    numbers = [
        int(path.name)
        for path in attempts_directory.iterdir()
        if path.is_dir() and re.fullmatch(r"[0-9]{4}", path.name)
    ] if attempts_directory.is_dir() else []
    return max(numbers, default=0) + 1


def _archive_case_runtime_artifacts(case_directory: Path) -> int | None:
    """Move the previous mutable attempt aside before a retry."""

    if not case_directory.exists():
        return None
    paths: list[Path] = []
    status_path = case_directory / "status.json"
    if status_path.is_file():
        paths.append(status_path)
    for pattern in _CASE_RUNTIME_PATTERNS:
        paths.extend(
            path for path in sorted(case_directory.glob(pattern)) if path.is_file()
        )
    if not paths:
        return None
    attempt = _next_case_attempt_number(case_directory)
    archive = case_directory / "attempts" / f"{attempt:04d}"
    archive.mkdir(parents=True, exist_ok=False)
    for path in paths:
        path.replace(archive / path.name)
    return attempt


def _write_run_state(
    run_directory: Path,
    *,
    records: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    run_identity_sha256: str,
    state: str,
    current: dict[str, Any] | None = None,
    blocker: str | None = None,
) -> None:
    """Persist a small aggregate checkpoint after every lifecycle transition."""

    success = sum(case.get("status") == "SUCCESS" for case in cases)
    failed = sum(case.get("status") == "FAILED" for case in cases)
    interrupted = sum(case.get("status") == "INTERRUPTED" for case in cases)
    running = 1 if current else 0
    pending = max(len(records) - len(cases) - running, 0)

    def project(case: dict[str, Any]) -> dict[str, Any]:
        identity = case.get("identity")
        finding_id = identity.get("finding_id") if isinstance(identity, dict) else None
        projected = {
            "finding_id": finding_id,
            "status": case.get("status"),
            "attempt": case.get("attempt"),
        }
        if case.get("error_code"):
            projected["error_code"] = case["error_code"]
        return projected

    payload: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_directory.name,
        "updated_at": _utc_now(),
        "state": state,
        "status": state,
        "complete": state == "COMPLETE",
        "run_identity_sha256": run_identity_sha256,
        "case_counts": {
            "total": len(records),
            "success": success,
            "failed": failed,
            "interrupted": interrupted,
            "running": running,
            "pending": pending,
        },
        "cases": [project(case) for case in cases],
    }
    if current:
        payload["current_case"] = project(current)
    if blocker:
        payload["blocker"] = blocker
    _write_json(run_directory / "run-state.json", payload)


def _execute_run_locked(
    *,
    records: list[dict[str, Any]],
    input_path: Path,
    snapshot_root: Path,
    run_directory: Path,
    profile: AgentProfile,
    profile_path: Path,
    prompt_path: Path,
    provider: Provider,
    evaluation_mode: str = "OFFICIAL",
    force: bool = False,
) -> dict[str, Any]:
    if evaluation_mode not in {"OFFICIAL", "DEVELOPMENT"}:
        raise ValueError(f"invalid evaluation mode: {evaluation_mode}")
    if evaluation_mode == "OFFICIAL" and not provider.model:
        raise VerifierError("official verifier runs require an explicitly pinned model")
    if evaluation_mode == "OFFICIAL" and force:
        raise VerifierError(
            "--force is forbidden for official runs; use a new run directory"
        )
    validate_blind_input(records, profile)
    corpus_proof = (
        _load_official_corpus_proof(input_path, records)
        if evaluation_mode == "OFFICIAL"
        else None
    )
    source_input_sha256 = sha256_file(input_path)
    frozen_content = "".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
        for row in records
    )
    input_sha256 = sha256_bytes(frozen_content.encode("utf-8"))
    profile_sha256 = sha256_file(profile_path)
    prompt_sha256 = sha256_file(prompt_path)
    response_schema_path, response_schema_sha256 = _response_schema_identity(provider)
    prediction_schema_path = _DEFAULT_PREDICTION_SCHEMA.resolve(strict=True)
    prediction_schema_sha256 = sha256_file(prediction_schema_path)
    controller = _controller_identity()
    provider_executable_value = getattr(provider, "executable", None)
    provider_executable_path = (
        Path(str(provider_executable_value)).resolve()
        if provider_executable_value
        else None
    )
    provider_executable_sha256 = (
        sha256_file(provider_executable_path)
        if provider_executable_path is not None and provider_executable_path.is_file()
        else None
    )
    run_identity = {
        "schema_version": 1,
        "input_sha256": input_sha256,
        "input_records": len(records),
        "profile_sha256": profile_sha256,
        "prompt_sha256": prompt_sha256,
        "evaluation_mode": evaluation_mode,
        "corpus_proof_sha256": (corpus_proof or {}).get("sha256"),
        "response_schema_sha256": response_schema_sha256,
        "prediction_schema_sha256": prediction_schema_sha256,
        "controller_sha256": controller["sha256"],
        "controller_protocol_version": CONTROLLER_PROTOCOL_VERSION,
        "provider": {
            "id": provider.provider_id,
            "version": provider.version,
            "model": provider.model,
            "executable_sha256": provider_executable_sha256,
        },
    }
    run_identity_path = run_directory / "run-identity.json"
    if run_identity_path.exists():
        try:
            existing_run_identity = json.loads(
                run_identity_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise VerifierError("run directory has an invalid run identity") from exc
        if existing_run_identity != run_identity:
            raise VerifierError(
                "run identity mismatch; use a new run directory for changed inputs or agent identity"
            )
    elif run_directory.exists() and any(run_directory.iterdir()):
        raise VerifierError(
            "non-empty run directory has no immutable identity; use a new run directory"
        )
    run_directory.mkdir(parents=True, exist_ok=True)
    if not run_identity_path.exists():
        _write_json(run_identity_path, run_identity)
    run_identity_sha256 = sha256_file(run_identity_path)
    frozen_input = run_directory / "blind-verifier-input.jsonl"
    if frozen_input.exists():
        if sha256_file(frozen_input) != input_sha256:
            raise VerifierError("run directory contains a different frozen blind input")
    else:
        _atomic_write_text(frozen_input, frozen_content)
    resolver = SnapshotResolver(snapshot_root)
    predictions: dict[str, dict[str, Any]] = {}
    cases: list[dict[str, Any]] = []
    terminal_blocker: str | None = None
    _write_run_state(
        run_directory,
        records=records,
        cases=cases,
        run_identity_sha256=run_identity_sha256,
        state="RUNNING",
    )
    for index, record in enumerate(records, 1):
        finding_id = str(record["finding_id"])
        case_key = sha256_bytes(finding_id.encode("utf-8"))[:20]
        case_directory = run_directory / "cases" / case_key
        case_status_path = case_directory / "status.json"
        prediction_path = case_directory / "prediction.json"
        identity = _case_identity(
            record=record,
            profile_sha256=profile_sha256,
            prompt_sha256=prompt_sha256,
            provider=provider,
            evaluation_mode=evaluation_mode,
            response_schema_sha256=response_schema_sha256,
            prediction_schema_sha256=prediction_schema_sha256,
            controller_sha256=controller["sha256"],
            corpus_proof_sha256=(corpus_proof or {}).get("sha256"),
        )
        if case_status_path.exists() and not force:
            try:
                previous = json.loads(case_status_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise VerifierError(f"invalid case status for prediction {finding_id}") from exc
            if previous.get("identity") != identity:
                raise VerifierError(
                    f"case identity mismatch for {finding_id}; use a new run directory"
                )
            if previous.get("status") == "SUCCESS" and previous.get("identity") == identity:
                if not prediction_path.is_file():
                    raise VerifierError(
                        f"successful prediction is missing for {finding_id}"
                    )
                expected_prediction_sha256 = previous.get("prediction_sha256")
                actual_prediction_sha256 = sha256_file(prediction_path)
                if expected_prediction_sha256 != actual_prediction_sha256:
                    raise VerifierError(
                        f"prediction checksum mismatch for {finding_id}"
                    )
                try:
                    prediction = json.loads(prediction_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    raise VerifierError(
                        f"prediction JSON is invalid for {finding_id}"
                    ) from exc
                _validate_frozen_prediction(
                    prediction,
                    record=record,
                    profile=profile,
                    provider=provider,
                    evaluation_mode=evaluation_mode,
                )
                previous["provider_usage"] = _provider_usage(case_directory)
                _write_json(case_status_path, previous)
                predictions[finding_id] = prediction
                cases.append(previous)
                print(f"[{index}/{len(records)}] reuse {finding_id}")
                _write_run_state(
                    run_directory,
                    records=records,
                    cases=cases,
                    run_identity_sha256=run_identity_sha256,
                    state="RUNNING",
                )
                continue
        _archive_case_runtime_artifacts(case_directory)
        attempt = _next_case_attempt_number(case_directory)
        started_at = _utc_now()
        started = time.monotonic()
        running_status = {
            "schema_version": 1,
            "status": "RUNNING",
            "identity": identity,
            "attempt": attempt,
            "started_at": started_at,
        }
        _write_json(case_status_path, running_status)
        _write_run_state(
            run_directory,
            records=records,
            cases=cases,
            current=running_status,
            run_identity_sha256=run_identity_sha256,
            state="RUNNING",
        )
        print(f"[{index}/{len(records)}] verify {finding_id}")
        terminal_failure = False
        try:
            snapshot = resolver.resolve(record)
            prediction = run_finding(
                record=record,
                snapshot=snapshot,
                profile=profile,
                provider=provider,
                case_directory=case_directory,
                evaluation_eligible=evaluation_mode == "OFFICIAL",
                exclusion_reason=(
                    None
                    if evaluation_mode == "OFFICIAL"
                    else "DEVELOPMENT_OR_PARTIAL_INPUT"
                ),
            )
            _validate_frozen_prediction(
                prediction,
                record=record,
                profile=profile,
                provider=provider,
                evaluation_mode=evaluation_mode,
            )
            _write_json(prediction_path, prediction)
            status = {
                "schema_version": 1,
                "status": "SUCCESS",
                "identity": identity,
                "attempt": attempt,
                "started_at": started_at,
                "completed_at": _utc_now(),
                "elapsed_seconds": time.monotonic() - started,
                "prediction_sha256": sha256_file(prediction_path),
                "provider_usage": _provider_usage(case_directory),
            }
            predictions[finding_id] = prediction
        except KeyboardInterrupt:
            status = {
                "schema_version": 1,
                "status": "INTERRUPTED",
                "identity": identity,
                "attempt": attempt,
                "started_at": started_at,
                "completed_at": _utc_now(),
                "elapsed_seconds": time.monotonic() - started,
                "error_code": "INTERRUPTED_BY_USER",
                "provider_usage": _provider_usage(case_directory),
            }
            _write_json(case_status_path, status)
            cases.append(status)
            _write_run_state(
                run_directory,
                records=records,
                cases=cases,
                run_identity_sha256=run_identity_sha256,
                state="INTERRUPTED",
                blocker="INTERRUPTED_BY_USER",
            )
            raise
        except Exception as exc:
            terminal_failure = isinstance(exc, TerminalProviderError)
            error_code = (
                exc.code
                if isinstance(exc, TerminalProviderError)
                else (
                    "PROVIDER_ERROR"
                    if isinstance(exc, ProviderError)
                    else type(exc).__name__.upper()
                )
            )
            safe_error = (
                error_code
                if isinstance(exc, ProviderError)
                else _redact_provider_diagnostics(str(exc))
            )
            status = {
                "schema_version": 1,
                "status": "FAILED",
                "identity": identity,
                "attempt": attempt,
                "started_at": started_at,
                "completed_at": _utc_now(),
                "elapsed_seconds": time.monotonic() - started,
                "error_type": type(exc).__name__,
                "error_code": error_code,
                "error": safe_error,
                "provider_usage": _provider_usage(case_directory),
            }
        _write_json(case_status_path, status)
        cases.append(status)
        if terminal_failure:
            terminal_blocker = status["error_code"]
        if terminal_blocker:
            _write_run_state(
                run_directory,
                records=records,
                cases=cases,
                run_identity_sha256=run_identity_sha256,
                state="BLOCKED_PROVIDER",
                blocker=terminal_blocker,
            )
            break
        _write_run_state(
            run_directory,
            records=records,
            cases=cases,
            run_identity_sha256=run_identity_sha256,
            state="RUNNING",
        )
    ordered_predictions = [
        predictions[str(record["finding_id"])]
        for record in records
        if str(record["finding_id"]) in predictions
    ]
    predictions_path = run_directory / "verifier-predictions.jsonl"
    _write_jsonl(predictions_path, ordered_predictions)
    success_count = sum(case["status"] == "SUCCESS" for case in cases)
    failed_count = sum(case["status"] == "FAILED" for case in cases)
    run_complete = success_count == len(records) and failed_count == 0
    aggregate_usage: dict[str, int] = defaultdict(int)
    for case in cases:
        for key, value in (case.get("provider_usage") or {}).items():
            if isinstance(value, int):
                aggregate_usage[str(key)] += value
    manifest = {
        "schema_version": 1,
        "run_id": run_directory.name,
        "created_at": _utc_now(),
        "status": "COMPLETE" if run_complete else "INCOMPLETE",
        "complete": run_complete,
        "evaluation_mode": evaluation_mode,
        "input": {
            "source": str(input_path),
            "source_sha256": source_input_sha256,
            "frozen_copy": frozen_input.name,
            "sha256": input_sha256,
            "records": len(records),
        },
        "predictions": {
            "path": predictions_path.name,
            "sha256": sha256_file(predictions_path),
            "records": len(ordered_predictions),
        },
        "profile": {
            "path": str(profile_path),
            "profile_id": profile.profile_id,
            "sha256": profile_sha256,
        },
        "prompt": {"path": str(prompt_path), "sha256": prompt_sha256},
        "corpus_proof": corpus_proof,
        "response_schema": {
            "path": str(response_schema_path),
            "sha256": response_schema_sha256,
        },
        "prediction_schema": {
            "path": str(prediction_schema_path),
            "sha256": prediction_schema_sha256,
        },
        "controller": controller,
        "provider": {
            "id": provider.provider_id,
            "version": provider.version,
            "model": provider.model,
            "model_explicitly_pinned": provider.model is not None,
            "usage": dict(sorted(aggregate_usage.items())),
        },
        "blindness": {
            "forbidden_metadata_validated_recursively": True,
            "model_receives_controller_context_only": True,
            "model_direct_source_filesystem_access": False,
            "model_direct_git_history_access": False,
            "web_or_browser_tools_allowed": False,
            "labels_loaded_by_runner": False,
        },
        "source_policy": {
            "snapshot_root": str(snapshot_root),
            "exact_commit_verified": True,
            "dirty_snapshot_rejected": True,
            "symlink_and_path_escape_rejected": True,
            "advisory_ids_redacted_from_source_context": True,
        },
        "case_counts": {
            "total": len(records),
            "success": success_count,
            "failed": failed_count,
        },
        "cases": cases,
    }
    _write_json(run_directory / "verifier-run.json", manifest)
    _write_run_state(
        run_directory,
        records=records,
        cases=cases,
        run_identity_sha256=run_identity_sha256,
        state=(
            "COMPLETE"
            if run_complete
            else ("BLOCKED_PROVIDER" if terminal_blocker else "INCOMPLETE")
        ),
        blocker=terminal_blocker,
    )
    return manifest


def execute_run(
    *,
    records: list[dict[str, Any]],
    input_path: Path,
    snapshot_root: Path,
    run_directory: Path,
    profile: AgentProfile,
    profile_path: Path,
    prompt_path: Path,
    provider: Provider,
    evaluation_mode: str = "OFFICIAL",
    force: bool = False,
) -> dict[str, Any]:
    """Run with a singleton lock so one directory has exactly one writer."""

    lock_path = run_directory.parent / f".{run_directory.name}.run.lock"
    try:
        with interprocess_lock(lock_path, timeout_seconds=1):
            return _execute_run_locked(
                records=records,
                input_path=input_path,
                snapshot_root=snapshot_root,
                run_directory=run_directory,
                profile=profile,
                profile_path=profile_path,
                prompt_path=prompt_path,
                provider=provider,
                evaluation_mode=evaluation_mode,
                force=force,
            )
    except InterprocessLockTimeout as exc:
        raise VerifierError(
            f"run directory is busy: {run_directory}"
        ) from exc


def _select_records(
    records: list[dict[str, Any]], finding_ids: list[str] | None
) -> list[dict[str, Any]]:
    if not finding_ids:
        return records
    requested = set(finding_ids)
    selected = [row for row in records if row.get("finding_id") in requested]
    missing = sorted(requested - {str(row.get("finding_id")) for row in selected})
    if missing:
        raise BlindInputError(f"requested finding IDs not present in input: {missing}")
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run an isolated, label-blind source-review agent over scanner findings."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, default=Path("worktrees"))
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument(
        "--profile", type=Path, default=Path("config/verifier-profile-v1.json")
    )
    parser.add_argument(
        "--prompt", type=Path, default=Path("config/verifier-prompt-v1.md")
    )
    parser.add_argument(
        "--response-schema",
        type=Path,
        default=Path("schemas/verifier-agent-response.schema.json"),
    )
    parser.add_argument("--codex-executable", default="codex")
    parser.add_argument("--model")
    parser.add_argument(
        "--development-run",
        action="store_true",
        help="mark predictions ineligible; required for partial input or an unpinned model",
    )
    parser.add_argument("--finding-id", action="append")
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate blind input and exact snapshots without invoking a model",
    )
    args = parser.parse_args(argv)

    profile = AgentProfile.load(args.profile)
    if args.finding_id and not args.development_run:
        parser.error("--finding-id is forbidden for official verifier runs")
    if args.force and not args.development_run:
        parser.error("--force is forbidden for official verifier runs; use a new run directory")
    try:
        all_records = load_jsonl(args.input, profile)
        records = _select_records(all_records, args.finding_id)
        validate_blind_input(records, profile)
    except (OSError, VerifierError, ValueError) as exc:
        parser.error(str(exc))
    if args.validate_only:
        corpus_proof = None
        if not args.development_run:
            try:
                corpus_proof = _load_official_corpus_proof(args.input, records)
            except VerifierError as exc:
                parser.error(str(exc))
        resolver = SnapshotResolver(args.snapshot_root)
        snapshots: set[Path] = set()
        for record in records:
            snapshot = resolver.resolve(record)
            snapshots.add(snapshot)
            EvidenceToolbox(snapshot, profile).initial_observations(record)
        print(
            json.dumps(
                {
                    "status": "VALID",
                    "records": len(records),
                    "snapshots": len(snapshots),
                    "profile_id": profile.profile_id,
                    "evaluation_mode": (
                        "DEVELOPMENT" if args.development_run else "OFFICIAL"
                    ),
                    "official_corpus_verified": corpus_proof is not None,
                    "input_sha256": sha256_file(args.input),
                    "profile_sha256": sha256_file(args.profile),
                    "prompt_sha256": sha256_file(args.prompt),
                    "response_schema_sha256": sha256_file(args.response_schema),
                    "controller_sha256": sha256_file(_CONTROLLER_PATH),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if not args.development_run:
        try:
            _load_official_corpus_proof(args.input, records)
        except VerifierError as exc:
            parser.error(str(exc))
    if not args.model and not args.development_run:
        parser.error("official verifier runs require an explicit --model")

    try:
        prompt_text = args.prompt.read_text(encoding="utf-8")
        provider = CodexCliProvider(
            executable=args.codex_executable,
            response_schema=args.response_schema,
            prompt_text=prompt_text,
            timeout_seconds=profile.provider_timeout_seconds,
            model=args.model,
            max_event_bytes=profile.max_provider_event_bytes,
            max_response_bytes=profile.max_provider_response_bytes,
        )
        manifest = execute_run(
            records=records,
            input_path=args.input,
            snapshot_root=args.snapshot_root,
            run_directory=args.run_dir,
            profile=profile,
            profile_path=args.profile,
            prompt_path=args.prompt,
            provider=provider,
            evaluation_mode="DEVELOPMENT" if args.development_run else "OFFICIAL",
            force=args.force,
        )
    except (OSError, VerifierError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(manifest["case_counts"], ensure_ascii=False, indent=2))
    return 0 if manifest["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
