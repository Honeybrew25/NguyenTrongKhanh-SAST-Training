from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .verifier_agent import (
    VerifierError,
    _redact_advisory_ids,
    normalize_source_path,
    parse_trace_line,
    repo_slug,
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
ROLES = ("REVIEWER_A", "REVIEWER_B", "ADJUDICATOR_C")
ROLE_KEYS = {
    "REVIEWER_A": "reviewer_a",
    "REVIEWER_B": "reviewer_b",
    "ADJUDICATOR_C": "adjudicator_c",
}
MAX_JSONL_RECORDS = 10_000
MAX_JSONL_LINE_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_LINES = 25
SOURCE_SCANNER = {"name": "opengrep", "version": "1.22.0"}
GEMINI_PROVIDER_ID = "google-gemini-api-isolated-json"
OPENAI_PROVIDER_ID = "openai-responses-api-isolated-json"
LOCAL_PROVIDER_ID = "local-openai-compatible-isolated-json"
SUPPORTED_REVIEW_PROVIDERS = {
    GEMINI_PROVIDER_ID,
    OPENAI_PROVIDER_ID,
    LOCAL_PROVIDER_ID,
}
BLIND_FINDING_KEYS = (
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
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "machine-reference-label.schema.json"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
IMPLEMENTATION_SOURCES = {
    "requirements-gemini.lock": PROJECT_ROOT / "requirements-gemini.lock",
    "machine-reference-label.schema.json": SCHEMA_PATH,
    "machine-review.py": Path(__file__).resolve(),
    "gemini-verifier-agent.py": PROJECT_ROOT
    / "src"
    / "vulngym_enrich"
    / "gemini_verifier_agent.py",
    "openai-verifier-agent.py": PROJECT_ROOT
    / "src"
    / "vulngym_enrich"
    / "openai_verifier_agent.py",
    "local-verifier-agent.py": PROJECT_ROOT
    / "src"
    / "vulngym_enrich"
    / "local_verifier_agent.py",
    "machine-evaluator.py": PROJECT_ROOT
    / "src"
    / "vulngym_enrich"
    / "machine_evaluator.py",
    "machine-adjudicator-prompt-v1.md": PROJECT_ROOT
    / "config"
    / "machine-adjudicator-prompt-v1.md",
    "machine-adjudicator-response.schema.json": PROJECT_ROOT
    / "schemas"
    / "machine-adjudicator-response.schema.json",
    "verifier-agent.py": PROJECT_ROOT / "src" / "vulngym_enrich" / "verifier_agent.py",
    "verifier-profile-v1.json": PROJECT_ROOT
    / "config"
    / "verifier-profile-v1.json",
    "verifier-prompt-local-v1.md": PROJECT_ROOT
    / "config"
    / "verifier-prompt-local-v1.md",
    "verifier-agent-response.schema.json": PROJECT_ROOT
    / "schemas"
    / "verifier-agent-response.schema.json",
    "verifier-prediction.schema.json": PROJECT_ROOT
    / "schemas"
    / "verifier-prediction.schema.json",
}
SOURCE_REVIEW_COMPONENTS = {
    "profile": IMPLEMENTATION_SOURCES["verifier-profile-v1.json"],
    "prompt": IMPLEMENTATION_SOURCES["verifier-prompt-local-v1.md"],
    "response_schema": IMPLEMENTATION_SOURCES["verifier-agent-response.schema.json"],
    "prediction_schema": IMPLEMENTATION_SOURCES["verifier-prediction.schema.json"],
    "controller": IMPLEMENTATION_SOURCES["verifier-agent.py"],
}


class MachineReviewError(ValueError):
    """A machine-reference gate failed closed."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _value_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path, label: str | None = None) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MachineReviewError(f"missing {label or 'JSON'}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise MachineReviewError(f"invalid {label or 'JSON'}: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MachineReviewError(f"{label or 'JSON'} must be an object: {path}")
    return value


def _read_jsonl(path: Path, label: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        handle = path.open("rb")
    except FileNotFoundError as exc:
        raise MachineReviewError(f"missing {label or 'JSONL'}: {path}") from exc
    with handle:
        for line_number in range(1, MAX_JSONL_RECORDS + 2):
            raw = handle.readline(MAX_JSONL_LINE_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_JSONL_LINE_BYTES:
                raise MachineReviewError(
                    f"oversized {label or 'JSONL'} row: {path}:{line_number}"
                )
            if not raw.strip():
                continue
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise MachineReviewError(
                    f"invalid {label or 'JSONL'} row: {path}:{line_number}: {exc}"
                ) from exc
            if not isinstance(value, dict):
                raise MachineReviewError(
                    f"{label or 'JSONL'} row must be an object: {path}:{line_number}"
                )
            rows.append(value)
    if len(rows) > MAX_JSONL_RECORDS:
        raise MachineReviewError(f"too many {label or 'JSONL'} records: {path}")
    return rows


def _atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_text(
        path,
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    _atomic_text(
        path,
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
            for row in rows
        ),
    )


def _ordered_ids(rows: list[dict[str, Any]], label: str) -> list[str]:
    ids: list[str] = []
    for index, row in enumerate(rows, 1):
        finding_id = row.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            raise MachineReviewError(f"{label} row {index} has no finding_id")
        ids.append(finding_id)
    if len(ids) != len(set(ids)):
        raise MachineReviewError(f"{label} contains duplicate finding IDs")
    return ids


def _file_identity(path: Path, *, records: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"path": path.name, "sha256": _sha256(path)}
    if records is not None:
        result["records"] = records
    return result


def _verify_file_identity(root: Path, proof: Any, label: str) -> Path:
    if not isinstance(proof, dict):
        raise MachineReviewError(f"missing file proof for {label}")
    relative = proof.get("path")
    if (
        not isinstance(relative, str)
        or not relative
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
    ):
        raise MachineReviewError(f"invalid file proof path for {label}")
    path = root / relative
    if not path.is_file() or _sha256(path) != proof.get("sha256"):
        raise MachineReviewError(f"file proof mismatch for {label}: {path}")
    return path


def _portable_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _is_latest_alias(model: str) -> bool:
    normalized = model.strip().casefold()
    return (
        normalized == "latest"
        or normalized.endswith("/latest")
        or normalized.endswith("-latest")
        or normalized.endswith(":latest")
    )


def _validate_identity_config(value: dict[str, Any], expected_role: str) -> dict[str, Any]:
    base_keys = {
        "schema_version",
        "id",
        "kind",
        "role",
        "provider",
        "provider_version",
        "model",
        "model_version",
        "thinking_level",
        "temperature",
        "seed",
    }
    provider = value.get("provider")
    local_keys = {"base_url", "model_revision_sha256", "max_tokens"}
    expected_keys = base_keys | (local_keys if provider == LOCAL_PROVIDER_ID else set())
    if set(value) != expected_keys:
        raise MachineReviewError(
            f"{expected_role} config keys differ: {sorted(set(value) ^ expected_keys)}"
        )
    if value.get("schema_version") != 1 or value.get("kind") != "MODEL":
        raise MachineReviewError(f"{expected_role} config is not a MODEL identity")
    if value.get("role") != expected_role:
        raise MachineReviewError(f"expected config role {expected_role}")
    for field in ("id", "provider", "provider_version", "model"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise MachineReviewError(f"{expected_role} config {field} is required")
    if value["provider"] not in SUPPORTED_REVIEW_PROVIDERS:
        raise MachineReviewError(
            f"{expected_role} uses an unsupported isolated provider"
        )
    if _is_latest_alias(value["model"]):
        raise MachineReviewError(f"{expected_role} uses a mutable latest model alias")
    if value.get("model_version") is not None:
        raise MachineReviewError(
            f"{expected_role} model_version must be null before the API run"
        )
    thinking = value.get("thinking_level")
    if not isinstance(thinking, str) or thinking.casefold() not in {
        "minimal",
        "low",
        "medium",
        "high",
        "server_default",
    }:
        raise MachineReviewError(f"{expected_role} thinking_level is invalid")
    temperature = value.get("temperature")
    if (
        not isinstance(temperature, (int, float))
        or isinstance(temperature, bool)
        or not math.isfinite(float(temperature))
        or not 0 <= float(temperature) <= 2
    ):
        raise MachineReviewError(f"{expected_role} temperature is invalid")
    seed = value.get("seed")
    if (
        not isinstance(seed, int)
        or isinstance(seed, bool)
        or not -(2**31) <= seed < 2**31
    ):
        raise MachineReviewError(f"{expected_role} seed is invalid")
    if provider == LOCAL_PROVIDER_ID:
        base_url = value.get("base_url")
        revision = value.get("model_revision_sha256")
        max_tokens = value.get("max_tokens")
        if (
            not isinstance(base_url, str)
            or not re.fullmatch(
                r"http://(?:127\.0\.0\.1|localhost|\[::1\])(?::[0-9]+)?/v1",
                base_url,
            )
        ):
            raise MachineReviewError(
                f"{expected_role} local base_url must be loopback and end in /v1"
            )
        if not isinstance(revision, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", revision
        ):
            raise MachineReviewError(
                f"{expected_role} local model revision SHA-256 is invalid"
            )
        if (
            not isinstance(max_tokens, int)
            or isinstance(max_tokens, bool)
            or not 256 <= max_tokens <= 131072
        ):
            raise MachineReviewError(f"{expected_role} local max_tokens is invalid")
    normalized = dict(value)
    normalized["thinking_level"] = thinking.casefold()
    normalized["temperature"] = float(temperature)
    if provider == LOCAL_PROVIDER_ID:
        normalized["model_revision_sha256"] = value["model_revision_sha256"].lower()
    return normalized


def _load_sample(sample_directory: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    manifest_path = sample_directory / "sample-manifest.json"
    findings_path = sample_directory / "sampled-findings.jsonl"
    index_path = sample_directory / "sampling-index.jsonl"
    manifest = _read_json(manifest_path, "sample manifest")
    outputs = manifest.get("outputs")
    if not isinstance(outputs, dict):
        raise MachineReviewError("sample manifest has no outputs proof")
    for name, path in (
        ("sampled-findings.jsonl", findings_path),
        ("sampling-index.jsonl", index_path),
    ):
        proof = outputs.get(name)
        if not isinstance(proof, dict) or proof.get("sha256") != _sha256(path):
            raise MachineReviewError(f"sample output checksum mismatch: {name}")
    findings = _read_jsonl(findings_path, "sample findings")
    index = _read_jsonl(index_path, "sampling index")
    if _ordered_ids(findings, "sample findings") != _ordered_ids(index, "sampling index"):
        raise MachineReviewError("sample findings and sampling index differ in IDs or order")
    if manifest.get("sampling", {}).get("sample_size") != len(findings):
        raise MachineReviewError("sample size differs from the manifest")
    return manifest, findings, index


def _load_evidence_packets(path: Path, expected_ids: list[str]) -> list[dict[str, Any]]:
    packets = _read_jsonl(path, "evidence packets")
    if _ordered_ids(packets, "evidence packets") != expected_ids:
        raise MachineReviewError("evidence packets do not exactly match the frozen sample")
    for finding_id, packet in zip(expected_ids, packets):
        finding = packet.get("finding")
        snapshot = packet.get("snapshot")
        if (
            not isinstance(finding, dict)
            or finding.get("finding_id") != finding_id
            or not isinstance(snapshot, dict)
            or snapshot.get("repo_url") != finding.get("repo_url")
            or snapshot.get("commit") != finding.get("commit")
            or snapshot.get("git_state_verified") is not True
        ):
            raise MachineReviewError(f"invalid evidence packet identity: {finding_id}")
    return packets


def _blind_projection(finding: dict[str, Any]) -> dict[str, Any]:
    forbidden = {
        "verdict",
        "label",
        "reasoning",
        "reviewer",
        "gold",
        "ground_truth",
        "adjudication",
    }
    if forbidden & {str(key).casefold() for key in finding}:
        raise MachineReviewError(
            f"blind finding contains forbidden review fields: {finding.get('finding_id')}"
        )
    projected = {
        key: finding[key] for key in BLIND_FINDING_KEYS if key in finding
    }
    scanner = projected.get("scanner")
    if isinstance(scanner, dict) and scanner.get("name") == "opengrep":
        # The immutable verifier-v1 blind contract names non-Semgrep scanners
        # `other`; full OpenGrep provenance remains frozen in the source sample.
        projected["scanner"] = {**scanner, "name": "other"}
    return json.loads(json.dumps(projected))


def _shuffled(rows: list[dict[str, Any]], seed: str) -> list[dict[str, Any]]:
    if not seed:
        raise MachineReviewError("review-order seed cannot be empty")
    return sorted(
        rows,
        key=lambda row: hashlib.sha256(
            f"{seed}\0{row['finding_id']}".encode("utf-8")
        ).digest(),
    )


def _check_stage_outputs(root: Path, manifest: dict[str, Any], key: str = "outputs") -> None:
    outputs = manifest.get(key)
    if not isinstance(outputs, dict):
        raise MachineReviewError(f"manifest has no {key} proof")
    for name, proof in outputs.items():
        _verify_file_identity(root, proof, str(name))


def prepare_review(
    *,
    sample_directory: Path,
    evidence_packets_path: Path,
    snapshot_root: Path,
    output_directory: Path,
    reviewer_a_config_path: Path,
    reviewer_b_config_path: Path,
    adjudicator_config_path: Path,
    evaluated_agent_model: str,
    expected_records: int = 400,
    audit_fraction: float = 0.20,
    audit_failure_threshold: float = 0.10,
    audit_seed: str = "opengrep-machine-fp-audit-r1-20260813",
    reviewer_a_seed: str = "opengrep-machine-review-a-order-r1-20260813",
    reviewer_b_seed: str = "opengrep-machine-review-b-order-r1-20260813",
    created_at: str | None = None,
) -> dict[str, Any]:
    if expected_records < 1:
        raise MachineReviewError("expected_records must be positive")
    if not 0 < audit_fraction <= 1 or not math.isfinite(audit_fraction):
        raise MachineReviewError("audit_fraction must be greater than 0 and at most 1")
    if (
        not 0 <= audit_failure_threshold <= 1
        or not math.isfinite(audit_failure_threshold)
    ):
        raise MachineReviewError(
            "audit_failure_threshold must be between 0 and 1"
        )
    if not audit_seed:
        raise MachineReviewError("audit_seed cannot be empty")
    if reviewer_a_seed == reviewer_b_seed:
        raise MachineReviewError("reviewer A/B order seeds must differ")
    if not isinstance(evaluated_agent_model, str) or not evaluated_agent_model.strip():
        raise MachineReviewError("evaluated_agent_model is required")
    if _is_latest_alias(evaluated_agent_model):
        raise MachineReviewError("evaluated agent uses a mutable latest alias")

    sample_directory = sample_directory.resolve()
    evidence_packets_path = evidence_packets_path.resolve()
    snapshot_root = snapshot_root.resolve(strict=True)
    if not snapshot_root.is_dir():
        raise MachineReviewError("snapshot_root must be a directory")
    output_directory = output_directory.resolve()
    sample_manifest, findings, index = _load_sample(sample_directory)
    expected_ids = _ordered_ids(findings, "sample findings")
    if len(findings) != expected_records:
        raise MachineReviewError(
            f"machine review requires exactly {expected_records} findings, got {len(findings)}"
        )
    packets = _load_evidence_packets(evidence_packets_path, expected_ids)
    for position, (finding, index_row, packet) in enumerate(
        zip(findings, index, packets), 1
    ):
        finding_id = expected_ids[position - 1]
        if finding.get("scanner") != SOURCE_SCANNER:
            raise MachineReviewError(
                f"machine review accepts only OpenGrep 1.22.0: {finding_id}"
            )
        if (
            packet.get("schema_version") != 1
            or packet.get("review_order") != index_row.get("review_order")
            or packet.get("finding") != _blind_projection(finding)
        ):
            raise MachineReviewError(
                f"evidence packet differs from the exact blind sample projection: {finding_id}"
            )
    configs: dict[str, dict[str, Any]] = {}
    for role, path in (
        ("REVIEWER_A", reviewer_a_config_path),
        ("REVIEWER_B", reviewer_b_config_path),
        ("ADJUDICATOR_C", adjudicator_config_path),
    ):
        configs[ROLE_KEYS[role]] = _validate_identity_config(
            _read_json(path.resolve(), f"{role} config"), role
        )
    models = [configs[key]["model"] for key in configs]
    models.append(evaluated_agent_model.strip())
    if len(models) != len({model.casefold() for model in models}):
        raise MachineReviewError(
            "reviewer A, reviewer B, adjudicator C, and evaluated agent models must differ"
        )
    api_seeds = [configs[key]["seed"] for key in configs]
    if len(api_seeds) != len(set(api_seeds)):
        raise MachineReviewError("reviewer A/B/C API seeds must differ")
    reviewer_ids = [configs[key]["id"].casefold() for key in configs]
    if len(reviewer_ids) != len(set(reviewer_ids)):
        raise MachineReviewError("reviewer A/B/C identity IDs must differ")
    identity = {
        "sample_manifest_sha256": _sha256(sample_directory / "sample-manifest.json"),
        "sample_findings_sha256": _sha256(sample_directory / "sampled-findings.jsonl"),
        "sampling_index_sha256": _sha256(sample_directory / "sampling-index.jsonl"),
        "evidence_packets_sha256": _sha256(evidence_packets_path),
        "records": len(findings),
        "finding_ids_sha256": _value_sha256(expected_ids),
        "snapshot_root": _portable_path(snapshot_root, PROJECT_ROOT),
        "source_scanner": SOURCE_SCANNER,
        "reviewer_configs": {
            key: _value_sha256(value) for key, value in configs.items()
        },
        "evaluated_agent_model": evaluated_agent_model.strip(),
        "implementation": {
            name: _sha256(path.resolve(strict=True))
            for name, path in IMPLEMENTATION_SOURCES.items()
        },
        "policy": {
            "audit_fraction": float(audit_fraction),
            "audit_failure_threshold": float(audit_failure_threshold),
            "audit_seed": audit_seed,
            "reviewer_a_order_seed": reviewer_a_seed,
            "reviewer_b_order_seed": reviewer_b_seed,
        },
    }
    manifest_path = output_directory / "machine-review-manifest.json"
    if manifest_path.exists():
        existing = _read_json(manifest_path, "machine-review manifest")
        if existing.get("identity") != identity:
            raise MachineReviewError("existing machine-review identity differs")
        return _load_machine_manifest(output_directory)
    if output_directory.exists() and any(output_directory.iterdir()):
        raise MachineReviewError(
            "non-empty machine-review directory has no immutable manifest"
        )

    frozen = output_directory / "frozen-inputs"
    frozen.mkdir(parents=True, exist_ok=False)
    sources = {
        "sample-manifest.json": sample_directory / "sample-manifest.json",
        "sampled-findings.jsonl": sample_directory / "sampled-findings.jsonl",
        "sampling-index.jsonl": sample_directory / "sampling-index.jsonl",
        "evidence-packets.jsonl": evidence_packets_path,
        "machine-reference-label.schema.json": SCHEMA_PATH,
        **IMPLEMENTATION_SOURCES,
    }
    for name, source in sources.items():
        shutil.copyfile(source, frozen / name)
    config_directory = frozen / "reviewer-configs"
    config_directory.mkdir()
    for key, config in configs.items():
        _write_json(config_directory / f"{key.replace('_', '-')}.json", config)

    blind = [_blind_projection(finding) for finding in findings]
    a_rows = _shuffled(blind, reviewer_a_seed)
    b_rows = _shuffled(blind, reviewer_b_seed)
    if len(blind) > 1 and _ordered_ids(a_rows, "reviewer A input") == _ordered_ids(
        b_rows, "reviewer B input"
    ):
        raise MachineReviewError("reviewer A/B order seeds produced the same order")
    a_path = output_directory / "reviewer-a" / "blind-input.jsonl"
    b_path = output_directory / "reviewer-b" / "blind-input.jsonl"
    _write_jsonl(a_path, a_rows)
    _write_jsonl(b_path, b_rows)

    created = created_at or _utc_now()
    parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise MachineReviewError("created_at must include a timezone")
    outputs: dict[str, Any] = {}
    for path, count in (
        (frozen / "sample-manifest.json", None),
        (frozen / "sampled-findings.jsonl", len(findings)),
        (frozen / "sampling-index.jsonl", len(index)),
        (frozen / "evidence-packets.jsonl", len(packets)),
        (frozen / "machine-reference-label.schema.json", None),
        (frozen / "requirements-gemini.lock", None),
        (frozen / "machine-review.py", None),
        (frozen / "gemini-verifier-agent.py", None),
        (frozen / "openai-verifier-agent.py", None),
        (frozen / "local-verifier-agent.py", None),
        (frozen / "machine-evaluator.py", None),
        (frozen / "machine-adjudicator-prompt-v1.md", None),
        (frozen / "machine-adjudicator-response.schema.json", None),
        (frozen / "verifier-agent.py", None),
        (frozen / "verifier-profile-v1.json", None),
        (frozen / "verifier-prompt-local-v1.md", None),
        (frozen / "verifier-agent-response.schema.json", None),
        (frozen / "verifier-prediction.schema.json", None),
        (config_directory / "reviewer-a.json", None),
        (config_directory / "reviewer-b.json", None),
        (config_directory / "adjudicator-c.json", None),
        (a_path, len(a_rows)),
        (b_path, len(b_rows)),
    ):
        relative = path.relative_to(output_directory).as_posix()
        outputs[relative] = {
            "path": relative,
            "sha256": _sha256(path),
            **({"records": count} if count is not None else {}),
        }
    manifest = {
        "schema_version": 1,
        "review_id": output_directory.name,
        "created_at": created,
        "status": "AWAITING_INDEPENDENT_REVIEWERS_A_B",
        "reference_tier": "LLM_ADJUDICATED_MACHINE_REFERENCE",
        "identity": identity,
        "requested_reviewers": configs,
        "publication_policy": {
            "human_gold": False,
            "publish_as_official": False,
            "metrics_name": "exploratory metrics against frozen LLM-adjudicated reference labels",
            "never_claim_tp_novel": True,
        },
        "routing_policy": {
            "all_disagreement": True,
            "any_true_positive": True,
            "any_abstain": True,
            "any_non_high_confidence": True,
            "any_invalid_evidence": True,
            "consensus_high_fp_audit_fraction": float(audit_fraction),
            "consensus_high_fp_audit_seed": audit_seed,
            "consensus_high_fp_audit_failure_threshold": float(
                audit_failure_threshold
            ),
        },
        "outputs": outputs,
    }
    _write_json(manifest_path, manifest)
    return manifest


def _load_machine_manifest(review_directory: Path) -> dict[str, Any]:
    manifest = _read_json(
        review_directory / "machine-review-manifest.json", "machine-review manifest"
    )
    expected_publication_policy = {
        "human_gold": False,
        "publish_as_official": False,
        "metrics_name": (
            "exploratory metrics against frozen LLM-adjudicated reference labels"
        ),
        "never_claim_tp_novel": True,
    }
    if (
        manifest.get("schema_version") != 1
        or manifest.get("reference_tier")
        != "LLM_ADJUDICATED_MACHINE_REFERENCE"
        or manifest.get("status") != "AWAITING_INDEPENDENT_REVIEWERS_A_B"
        or manifest.get("publication_policy") != expected_publication_policy
    ):
        raise MachineReviewError("machine-review manifest policy is invalid")
    _check_stage_outputs(review_directory, manifest)
    identity = manifest.get("identity")
    if not isinstance(identity, dict):
        raise MachineReviewError("machine-review manifest identity is invalid")
    current_implementation = {
        name: _sha256(path.resolve(strict=True))
        for name, path in IMPLEMENTATION_SOURCES.items()
    }
    if identity.get("implementation") != current_implementation:
        raise MachineReviewError(
            "live machine-review implementation differs from the frozen release"
        )
    frozen_directory = review_directory / "frozen-inputs"
    for name, checksum in current_implementation.items():
        frozen_path = frozen_directory / name
        if not frozen_path.is_file() or _sha256(frozen_path) != checksum:
            raise MachineReviewError(
                f"frozen methodology component differs from live release: {name}"
            )
    frozen_identities = {
        "sample_manifest_sha256": _sha256(
            frozen_directory / "sample-manifest.json"
        ),
        "sample_findings_sha256": _sha256(
            frozen_directory / "sampled-findings.jsonl"
        ),
        "sampling_index_sha256": _sha256(
            frozen_directory / "sampling-index.jsonl"
        ),
        "evidence_packets_sha256": _sha256(
            frozen_directory / "evidence-packets.jsonl"
        ),
    }
    if any(identity.get(key) != value for key, value in frozen_identities.items()):
        raise MachineReviewError("frozen corpus identity differs from the manifest")
    configs = {
        key: _frozen_config(review_directory, role)
        for role, key in ROLE_KEYS.items()
    }
    if manifest.get("requested_reviewers") != configs or identity.get(
        "reviewer_configs"
    ) != {key: _value_sha256(config) for key, config in configs.items()}:
        raise MachineReviewError("frozen reviewer configs differ from the manifest")
    if identity.get("source_scanner") != SOURCE_SCANNER:
        raise MachineReviewError("machine-review source scanner identity is invalid")
    frozen_findings = _read_jsonl(
        frozen_directory / "sampled-findings.jsonl", "frozen sample"
    )
    frozen_ids = _ordered_ids(frozen_findings, "frozen sample")
    if (
        not frozen_ids
        or identity.get("records") != len(frozen_ids)
        or identity.get("finding_ids_sha256") != _value_sha256(frozen_ids)
        or any(finding.get("scanner") != SOURCE_SCANNER for finding in frozen_findings)
    ):
        raise MachineReviewError("frozen OpenGrep corpus identity is invalid")
    evaluated_model = identity.get("evaluated_agent_model")
    requested_models = [config["model"] for config in configs.values()]
    if (
        not isinstance(evaluated_model, str)
        or not evaluated_model
        or _is_latest_alias(evaluated_model)
        or len({model.casefold() for model in [*requested_models, evaluated_model]})
        != 4
        or len({config["seed"] for config in configs.values()}) != 3
        or len({config["id"].casefold() for config in configs.values()}) != 3
    ):
        raise MachineReviewError("frozen reviewer independence identity is invalid")
    policy = identity.get("policy")
    if not isinstance(policy, dict):
        raise MachineReviewError("machine-review routing identity is invalid")
    audit_fraction = policy.get("audit_fraction")
    audit_failure_threshold = policy.get("audit_failure_threshold")
    if (
        not isinstance(audit_fraction, (int, float))
        or isinstance(audit_fraction, bool)
        or not math.isfinite(float(audit_fraction))
        or not 0 < float(audit_fraction) <= 1
        or not isinstance(audit_failure_threshold, (int, float))
        or isinstance(audit_failure_threshold, bool)
        or not math.isfinite(float(audit_failure_threshold))
        or not 0 <= float(audit_failure_threshold) <= 1
        or not isinstance(policy.get("audit_seed"), str)
        or not policy["audit_seed"]
        or policy.get("reviewer_a_order_seed")
        == policy.get("reviewer_b_order_seed")
    ):
        raise MachineReviewError("machine-review routing identity is invalid")
    expected_routing = {
        "all_disagreement": True,
        "any_true_positive": True,
        "any_abstain": True,
        "any_non_high_confidence": True,
        "any_invalid_evidence": True,
        "consensus_high_fp_audit_fraction": policy.get("audit_fraction"),
        "consensus_high_fp_audit_seed": policy.get("audit_seed"),
        "consensus_high_fp_audit_failure_threshold": policy.get(
            "audit_failure_threshold"
        ),
    }
    if manifest.get("routing_policy") != expected_routing:
        raise MachineReviewError("machine-review routing policy differs from identity")
    return manifest


def _load_frozen_base_manifest(review_directory: Path) -> dict[str, Any]:
    """Validate an older frozen release without comparing it to live implementation."""

    manifest = _read_json(
        review_directory / "machine-review-manifest.json", "base machine-review manifest"
    )
    identity = manifest.get("identity")
    implementation = identity.get("implementation") if isinstance(identity, dict) else None
    if (
        manifest.get("schema_version") != 1
        or manifest.get("reference_tier") != "LLM_ADJUDICATED_MACHINE_REFERENCE"
        or not isinstance(implementation, dict)
        or not implementation
    ):
        raise MachineReviewError("base machine-review manifest identity is invalid")
    _check_stage_outputs(review_directory, manifest)
    frozen = review_directory / "frozen-inputs"
    for name, checksum in implementation.items():
        path = frozen / str(name)
        if (
            not isinstance(checksum, str)
            or not re.fullmatch(r"[0-9a-f]{64}", checksum)
            or not path.is_file()
            or _sha256(path) != checksum
        ):
            raise MachineReviewError(
                f"base frozen implementation proof differs: {name}"
            )
    frozen_identities = {
        "sample_manifest_sha256": _sha256(frozen / "sample-manifest.json"),
        "sample_findings_sha256": _sha256(frozen / "sampled-findings.jsonl"),
        "sampling_index_sha256": _sha256(frozen / "sampling-index.jsonl"),
        "evidence_packets_sha256": _sha256(frozen / "evidence-packets.jsonl"),
    }
    if any(identity.get(key) != value for key, value in frozen_identities.items()):
        raise MachineReviewError("base frozen corpus identity differs from its manifest")
    return manifest


def prepare_r6_migration(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Freeze r5 partial runs and produce retry-only inputs for an r6 release."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    if base_review_directory == review_directory:
        raise MachineReviewError("migration base and destination must differ")
    manifest = _load_machine_manifest(review_directory)
    base_manifest = _load_frozen_base_manifest(base_review_directory)
    identity = manifest["identity"]
    base_identity = base_manifest["identity"]
    comparable_keys = {
        "sample_manifest_sha256",
        "sample_findings_sha256",
        "sampling_index_sha256",
        "evidence_packets_sha256",
        "records",
        "finding_ids_sha256",
        "snapshot_root",
        "source_scanner",
        "reviewer_configs",
        "evaluated_agent_model",
        "policy",
    }
    if any(identity.get(key) != base_identity.get(key) for key in comparable_keys):
        raise MachineReviewError("r6 identity differs from the r5 migration base")
    migration_path = review_directory / "migration-r6.json"
    if migration_path.is_file():
        existing = _read_json(migration_path, "r6 migration manifest")
        _check_stage_outputs(review_directory, existing)
        if existing.get("identity", {}).get("base_manifest_sha256") != _sha256(
            base_review_directory / "machine-review-manifest.json"
        ):
            raise MachineReviewError("existing r6 migration uses a different base")
        for role in ("a", "b"):
            role_proof = existing.get("roles", {}).get(f"reviewer_{role}")
            if not isinstance(role_proof, dict):
                raise MachineReviewError("existing r6 migration role proof is invalid")
            copied_run = review_directory / str(role_proof.get("base_run") or "")
            if (
                not copied_run.is_dir()
                or _artifact_inventory(copied_run)
                != role_proof.get("base_artifacts")
                or _sha256(copied_run / "verifier-run.json")
                != role_proof.get("base_verifier_run_sha256")
            ):
                raise MachineReviewError(
                    f"existing reviewer {role} r5 base copy changed"
                )
        return existing

    findings, _ = _frozen_rows(review_directory)
    findings_by_id = {str(row["finding_id"]): row for row in findings}
    expected_snapshot_root = _frozen_snapshot_root(manifest)
    role_summaries: dict[str, Any] = {}
    outputs: dict[str, Any] = {}
    for role, role_name in (("a", "REVIEWER_A"), ("b", "REVIEWER_B")):
        base_input = base_review_directory / f"reviewer-{role}" / "blind-input.jsonl"
        new_input = review_directory / f"reviewer-{role}" / "blind-input.jsonl"
        if _sha256(base_input) != _sha256(new_input):
            raise MachineReviewError(f"reviewer {role} input differs between r5 and r6")
        expected_ids = _ordered_ids(
            _read_jsonl(new_input, f"reviewer {role} input"),
            f"reviewer {role} input",
        )
        source_run = base_review_directory / f"reviewer-{role}" / "run"
        source_manifest = _read_json(
            source_run / "verifier-run.json", f"base reviewer {role} run"
        )
        source_cases = source_manifest.get("cases")
        if not isinstance(source_cases, list) or len(source_cases) != len(expected_ids):
            raise MachineReviewError(f"base reviewer {role} case proofs are incomplete")
        success_set = {
            str(row.get("identity", {}).get("finding_id"))
            for row in source_cases
            if isinstance(row, dict) and row.get("status") == "SUCCESS"
        }
        failed_set = {
            str(row.get("identity", {}).get("finding_id"))
            for row in source_cases
            if isinstance(row, dict) and row.get("status") == "FAILED"
        }
        if (
            success_set | failed_set != set(expected_ids)
            or success_set & failed_set
            or not failed_set
        ):
            raise MachineReviewError(f"base reviewer {role} partial status is invalid")
        success_ids = [item for item in expected_ids if item in success_set]
        failed_ids = [item for item in expected_ids if item in failed_set]
        copied_run = review_directory / f"reviewer-{role}" / "base-r5"
        if copied_run.exists():
            raise MachineReviewError(
                f"partial reviewer {role} migration exists without a manifest"
            )
        shutil.copytree(source_run, copied_run)
        base_run = _load_run(
            run_directory=copied_run,
            review_directory=review_directory,
            expected_input=copied_run / "blind-verifier-input.jsonl",
            expected_ids=expected_ids,
            findings_by_id=findings_by_id,
            expected_snapshot_root=expected_snapshot_root,
            config=_frozen_config(review_directory, role_name),
            label=f"reviewer {role} r5 base",
            success_ids=success_ids,
        )
        input_rows = _read_jsonl(new_input, f"reviewer {role} input")
        retry_rows = [
            row for row in input_rows if str(row["finding_id"]) in failed_set
        ]
        retry_input = review_directory / f"reviewer-{role}" / "retry-input.jsonl"
        _write_jsonl(retry_input, retry_rows)
        copied_relative = copied_run.relative_to(review_directory).as_posix()
        retry_relative = retry_input.relative_to(review_directory).as_posix()
        outputs[retry_relative] = {
            "path": retry_relative,
            "sha256": _sha256(retry_input),
            "records": len(retry_rows),
        }
        role_summaries[f"reviewer_{role}"] = {
            "base_run": copied_relative,
            "base_verifier_run_sha256": base_run["proof"]["verifier_run_sha256"],
            "base_artifacts": base_run["proof"]["artifacts"],
            "reused_success": len(success_ids),
            "reused_finding_ids_sha256": _value_sha256(success_ids),
            "retry_input": retry_relative,
            "retry_records": len(failed_ids),
            "retry_finding_ids": failed_ids,
            "retry_finding_ids_sha256": _value_sha256(failed_ids),
            "retry_run": f"reviewer-{role}/retry-run",
            "composite_run": f"reviewer-{role}/run",
        }
    created = created_at or _utc_now()
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r5-to-r6-v1",
        "created_at": created,
        "status": "AWAITING_RETRY_RUNS",
        "identity": {
            "base_review_directory": _portable_path(
                base_review_directory, PROJECT_ROOT
            ),
            "base_manifest_sha256": _sha256(
                base_review_directory / "machine-review-manifest.json"
            ),
            "r6_manifest_sha256": _sha256(
                review_directory / "machine-review-manifest.json"
            ),
            "base_implementation_sha256": _value_sha256(
                base_identity["implementation"]
            ),
            "r6_implementation_sha256": _value_sha256(identity["implementation"]),
            "policy": "REUSE_CHECKSUM_VERIFIED_R5_SUCCESS_RETRY_ONLY_FAILED",
        },
        "roles": role_summaries,
        "outputs": outputs,
    }
    _write_json(migration_path, migration)
    return migration


def _partial_run_success_ids(run_directory: Path, expected_ids: list[str]) -> list[str]:
    run = _read_json(run_directory / "verifier-run.json", "partial verifier run")
    cases = run.get("cases")
    if not isinstance(cases, list) or len(cases) != len(expected_ids):
        raise MachineReviewError("partial verifier run has incomplete case proofs")
    status_by_id: dict[str, str] = {}
    for case in cases:
        finding_id = (
            case.get("identity", {}).get("finding_id")
            if isinstance(case, dict)
            else None
        )
        case_status = case.get("status") if isinstance(case, dict) else None
        if (
            not isinstance(finding_id, str)
            or finding_id in status_by_id
            or finding_id not in set(expected_ids)
            or case_status not in {"SUCCESS", "FAILED"}
        ):
            raise MachineReviewError("partial verifier run has invalid case status")
        status_by_id[finding_id] = case_status
    if set(status_by_id) != set(expected_ids):
        raise MachineReviewError("partial verifier run does not cover its input")
    return [finding_id for finding_id in expected_ids if status_by_id[finding_id] == "SUCCESS"]


def prepare_r7_supplement(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Reuse every verified r5/r6 success and retry only remaining r6 failures."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    if base_review_directory == review_directory:
        raise MachineReviewError("supplement base and destination must differ")
    manifest = _load_machine_manifest(review_directory)
    base_manifest = _load_frozen_base_manifest(base_review_directory)
    base_migration = _load_r6_migration(base_review_directory)
    if base_migration.get("status") != "AWAITING_RETRY_RUNS":
        raise MachineReviewError("r7 supplement requires an incomplete r6 migration")
    identity = manifest["identity"]
    base_identity = base_manifest["identity"]
    comparable_keys = {
        "sample_manifest_sha256",
        "sample_findings_sha256",
        "sampling_index_sha256",
        "evidence_packets_sha256",
        "records",
        "finding_ids_sha256",
        "snapshot_root",
        "source_scanner",
        "reviewer_configs",
        "evaluated_agent_model",
        "policy",
    }
    if any(identity.get(key) != base_identity.get(key) for key in comparable_keys):
        raise MachineReviewError("r7 identity differs from the r6 supplement base")
    migration_path = review_directory / "migration-r7.json"
    if migration_path.is_file():
        return _load_r7_migration(review_directory)

    findings, _ = _frozen_rows(review_directory)
    findings_by_id = {str(row["finding_id"]): row for row in findings}
    expected_snapshot_root = _frozen_snapshot_root(manifest)
    role_summaries: dict[str, Any] = {}
    outputs: dict[str, Any] = {}
    for role, role_name in (("a", "REVIEWER_A"), ("b", "REVIEWER_B")):
        base_full_input = base_review_directory / f"reviewer-{role}" / "blind-input.jsonl"
        new_full_input = review_directory / f"reviewer-{role}" / "blind-input.jsonl"
        if _sha256(base_full_input) != _sha256(new_full_input):
            raise MachineReviewError(f"reviewer {role} input differs between r6 and r7")
        full_ids = _ordered_ids(
            _read_jsonl(new_full_input, f"reviewer {role} input"),
            f"reviewer {role} input",
        )
        r6_role = base_migration["roles"][f"reviewer_{role}"]
        r6_retry_input = base_review_directory / str(r6_role["retry_input"])
        r6_retry_ids = _ordered_ids(
            _read_jsonl(r6_retry_input, f"reviewer {role} r6 retry input"),
            f"reviewer {role} r6 retry input",
        )
        r5_success_ids = [
            finding_id for finding_id in full_ids if finding_id not in set(r6_retry_ids)
        ]
        r6_retry_run = base_review_directory / str(r6_role["retry_run"])
        r6_success_ids = _partial_run_success_ids(r6_retry_run, r6_retry_ids)
        remaining_ids = [
            finding_id for finding_id in r6_retry_ids if finding_id not in set(r6_success_ids)
        ]
        if not remaining_ids:
            raise MachineReviewError(f"reviewer {role} has no failed r6 case to supplement")
        if set(r5_success_ids) & set(r6_success_ids):
            raise MachineReviewError(f"reviewer {role} supplement sources overlap")
        if set(r5_success_ids) | set(r6_success_ids) | set(remaining_ids) != set(full_ids):
            raise MachineReviewError(f"reviewer {role} supplement partition is invalid")

        config = _frozen_config(review_directory, role_name)
        source_specs = (
            (
                "r5-base",
                base_review_directory / str(r6_role["base_run"]),
                full_ids,
                r5_success_ids,
            ),
            ("r6-retry", r6_retry_run, r6_retry_ids, r6_success_ids),
        )
        sources: list[dict[str, Any]] = []
        for source_name, source_run, source_ids, selected_ids in source_specs:
            _load_run(
                run_directory=source_run,
                review_directory=base_review_directory,
                expected_input=source_run / "blind-verifier-input.jsonl",
                expected_ids=source_ids,
                findings_by_id=findings_by_id,
                expected_snapshot_root=expected_snapshot_root,
                config=config,
                label=f"reviewer {role} {source_name} source",
                success_ids=selected_ids,
            )
            copied_run = (
                review_directory / f"reviewer-{role}" / "sources" / source_name
            )
            if copied_run.exists():
                raise MachineReviewError(
                    f"partial reviewer {role} r7 source copy exists without a manifest"
                )
            copied_run.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source_run, copied_run)
            copied = _load_run(
                run_directory=copied_run,
                review_directory=review_directory,
                expected_input=copied_run / "blind-verifier-input.jsonl",
                expected_ids=source_ids,
                findings_by_id=findings_by_id,
                expected_snapshot_root=expected_snapshot_root,
                config=config,
                label=f"reviewer {role} copied {source_name} source",
                success_ids=selected_ids,
            )
            sources.append(
                {
                    "name": source_name,
                    "run": copied_run.relative_to(review_directory).as_posix(),
                    "input_finding_ids": source_ids,
                    "input_finding_ids_sha256": _value_sha256(source_ids),
                    "selected_success_ids": selected_ids,
                    "selected_success_ids_sha256": _value_sha256(selected_ids),
                    "verifier_run_sha256": copied["proof"]["verifier_run_sha256"],
                    "artifacts": copied["proof"]["artifacts"],
                }
            )

        input_rows = _read_jsonl(new_full_input, f"reviewer {role} input")
        retry_rows = [
            row for row in input_rows if str(row["finding_id"]) in set(remaining_ids)
        ]
        retry_input = review_directory / f"reviewer-{role}" / "retry-input.jsonl"
        _write_jsonl(retry_input, retry_rows)
        retry_relative = retry_input.relative_to(review_directory).as_posix()
        outputs[retry_relative] = {
            "path": retry_relative,
            "sha256": _sha256(retry_input),
            "records": len(retry_rows),
        }
        reused_ids = [
            finding_id for finding_id in full_ids if finding_id not in set(remaining_ids)
        ]
        role_summaries[f"reviewer_{role}"] = {
            "sources": sources,
            "reused_success": len(reused_ids),
            "reused_finding_ids_sha256": _value_sha256(reused_ids),
            "retry_input": retry_relative,
            "retry_records": len(remaining_ids),
            "retry_finding_ids": remaining_ids,
            "retry_finding_ids_sha256": _value_sha256(remaining_ids),
            "retry_run": f"reviewer-{role}/retry-run",
            "composite_run": f"reviewer-{role}/run",
        }

    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r6-to-r7-supplement-v1",
        "created_at": created_at or _utc_now(),
        "status": "AWAITING_RETRY_RUNS",
        "identity": {
            "base_review_directory": _portable_path(base_review_directory, PROJECT_ROOT),
            "base_manifest_sha256": _sha256(
                base_review_directory / "machine-review-manifest.json"
            ),
            "base_migration_sha256": _sha256(
                base_review_directory / "migration-r6.json"
            ),
            "r7_manifest_sha256": _sha256(
                review_directory / "machine-review-manifest.json"
            ),
            "base_implementation_sha256": _value_sha256(
                base_identity["implementation"]
            ),
            "r7_implementation_sha256": _value_sha256(identity["implementation"]),
            "policy": "REUSE_CHECKSUM_VERIFIED_R5_R6_SUCCESS_RETRY_ONLY_REMAINING_FAILED",
        },
        "roles": role_summaries,
        "outputs": outputs,
    }
    _write_json(migration_path, migration)
    return migration


def _frozen_rows(review_directory: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings = _read_jsonl(
        review_directory / "frozen-inputs" / "sampled-findings.jsonl",
        "frozen sample",
    )
    packets = _read_jsonl(
        review_directory / "frozen-inputs" / "evidence-packets.jsonl",
        "frozen evidence packets",
    )
    index = _read_jsonl(
        review_directory / "frozen-inputs" / "sampling-index.jsonl",
        "frozen sampling index",
    )
    expected_ids = _ordered_ids(findings, "frozen sample")
    if (
        _ordered_ids(packets, "frozen evidence packets") != expected_ids
        or _ordered_ids(index, "frozen sampling index") != expected_ids
    ):
        raise MachineReviewError("frozen evidence packets no longer match the sample")
    for finding, index_row, packet in zip(findings, index, packets):
        if (
            finding.get("scanner") != SOURCE_SCANNER
            or packet.get("schema_version") != 1
            or packet.get("review_order") != index_row.get("review_order")
            or packet.get("finding") != _blind_projection(finding)
        ):
            raise MachineReviewError(
                "frozen evidence packet differs from the blind sample projection"
            )
    return findings, packets


def _frozen_config(review_directory: Path, role: str) -> dict[str, Any]:
    name = ROLE_KEYS[role].replace("_", "-") + ".json"
    path = review_directory / "frozen-inputs" / "reviewer-configs" / name
    return _validate_identity_config(_read_json(path, f"frozen {role} config"), role)


def _safe_relative_to(path: Path, parent: Path, label: str) -> None:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError as exc:
        raise MachineReviewError(f"{label} must stay inside the machine-review directory") from exc


def _snapshot_root(run: dict[str, Any]) -> Path:
    source_policy = run.get("source_policy")
    value = source_policy.get("snapshot_root") if isinstance(source_policy, dict) else None
    if not isinstance(value, str) or not value:
        raise MachineReviewError("verifier run has no snapshot_root proof")
    root = Path(value)
    if not root.is_absolute():
        root = Path.cwd() / root
    try:
        return root.resolve(strict=True)
    except FileNotFoundError as exc:
        raise MachineReviewError(f"verifier snapshot_root is missing: {root}") from exc


def _frozen_snapshot_root(manifest: dict[str, Any]) -> Path:
    value = manifest.get("identity", {}).get("snapshot_root")
    if not isinstance(value, str) or not value:
        raise MachineReviewError("machine-review manifest has no snapshot_root identity")
    root = Path(value)
    if not root.is_absolute():
        root = PROJECT_ROOT / root
    try:
        return root.resolve(strict=True)
    except FileNotFoundError as exc:
        raise MachineReviewError(
            f"frozen machine-review snapshot_root is missing: {root}"
        ) from exc


def _source_code(
    *, finding: dict[str, Any], evidence: dict[str, Any], snapshot_root: Path
) -> str:
    path_value = normalize_source_path(evidence.get("file"))
    start, end = parse_trace_line(evidence.get("line"), "evidence")
    if end - start + 1 > MAX_EVIDENCE_LINES:
        raise MachineReviewError("evidence line range exceeds the frozen maximum")
    repo = repo_slug(str(finding.get("repo_url") or ""))
    commit = finding.get("commit")
    if not isinstance(commit, str) or len(commit) != 40:
        raise MachineReviewError("finding commit identity is invalid")
    snapshot = (snapshot_root / repo / commit).resolve(strict=True)
    try:
        snapshot.relative_to(snapshot_root)
    except ValueError as exc:
        raise MachineReviewError("snapshot path escapes its root") from exc
    candidate = snapshot
    for part in Path(path_value).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise MachineReviewError(f"evidence source path contains a symlink: {path_value}")
    source = candidate.resolve(strict=True)
    try:
        source.relative_to(snapshot)
    except ValueError as exc:
        raise MachineReviewError(f"evidence source path escapes snapshot: {path_value}") from exc
    if not source.is_file() or source.stat().st_size > 32 * 1024 * 1024:
        raise MachineReviewError(f"evidence source is not a bounded file: {path_value}")
    payload = source.read_bytes()
    if b"\0" in payload:
        raise MachineReviewError(f"evidence source is binary: {path_value}")
    lines = payload.decode("utf-8", errors="replace").splitlines()
    if start > len(lines) or end > len(lines):
        raise MachineReviewError(f"evidence range exceeds source: {path_value}:{start}-{end}")
    return "\n".join(
        f"{number}: {_redact_advisory_ids(lines[number - 1])}"
        for number in range(start, end + 1)
    )


def _evidence_error(
    prediction: dict[str, Any], finding: dict[str, Any], snapshot_root: Path
) -> str | None:
    evidence = prediction.get("evidence")
    verdict = prediction.get("verdict")
    if not isinstance(evidence, list) or len(evidence) > 12:
        return "evidence must be an array of at most 12 objects"
    if verdict != "ABSTAIN" and not evidence:
        return f"{verdict} requires source evidence"
    seen: set[bytes] = set()
    for index, node in enumerate(evidence):
        if not isinstance(node, dict) or set(node) != {
            "file",
            "line",
            "description",
            "code",
        }:
            return f"evidence[{index}] schema is invalid"
        if not isinstance(node.get("description"), str) or not node["description"].strip():
            return f"evidence[{index}] description is empty"
        if not isinstance(node.get("code"), str) or not node["code"]:
            return f"evidence[{index}] code is empty"
        encoded = _canonical_bytes(node)
        if encoded in seen:
            return f"evidence[{index}] duplicates an earlier citation"
        seen.add(encoded)
        try:
            expected = _source_code(
                finding=finding, evidence=node, snapshot_root=snapshot_root
            )
        except (OSError, ValueError) as exc:
            return f"evidence[{index}] cannot be verified: {exc}"
        if node["code"] != expected:
            return f"evidence[{index}] code differs from the pinned source"
    return None


def _validate_prediction_core(
    row: dict[str, Any], *, finding_id: str, run: dict[str, Any], config: dict[str, Any]
) -> None:
    if row.get("schema_version") != 1 or row.get("finding_id") != finding_id:
        raise MachineReviewError(f"prediction identity is invalid: {finding_id}")
    verdict = row.get("verdict")
    confidence = row.get("confidence")
    if verdict not in VERDICTS or confidence not in CONFIDENCES:
        raise MachineReviewError(f"prediction verdict/confidence is invalid: {finding_id}")
    if run.get("evaluation_mode") != "DEVELOPMENT":
        raise MachineReviewError("machine reviewers must run in DEVELOPMENT mode")
    if (
        row.get("evaluation_eligible") is not False
        or row.get("exclusion_reason") != "DEVELOPMENT_OR_PARTIAL_INPUT"
    ):
        raise MachineReviewError(
            f"machine prediction must remain development-only: {finding_id}"
        )
    reason_codes = row.get("reason_codes")
    if (
        not isinstance(reason_codes, list)
        or any(not isinstance(item, str) for item in reason_codes)
        or len(reason_codes) != len(set(reason_codes))
        or set(reason_codes) - FP_REASON_CODES
    ):
        raise MachineReviewError(f"prediction reason_codes are invalid: {finding_id}")
    if (verdict == "FALSE_POSITIVE") != bool(reason_codes):
        raise MachineReviewError(f"prediction reason_codes do not match verdict: {finding_id}")
    for field in (
        "attacker_capability",
        "entry_point",
        "security_effect",
        "controls",
        "reasoning",
    ):
        if not isinstance(row.get(field), str) or not row[field].strip():
            raise MachineReviewError(f"prediction {field} is empty: {finding_id}")
    agent = row.get("agent")
    provider = run.get("provider")
    if not isinstance(agent, dict) or not isinstance(provider, dict):
        raise MachineReviewError(f"prediction agent identity is missing: {finding_id}")
    run_provider_version = provider.get("version")
    if not isinstance(run_provider_version, str) or not run_provider_version:
        raise MachineReviewError("verifier run provider version is missing")
    expected = {
        "provider": config["provider"],
        "provider_version": run_provider_version,
        "model": config["model"],
    }
    if any(agent.get(key) != value for key, value in expected.items()):
        raise MachineReviewError(f"prediction agent identity differs: {finding_id}")
    if any(
        provider.get(key) != value
        for key, value in {
            "id": config["provider"],
            "version": run_provider_version,
            "model": config["model"],
        }.items()
    ):
        raise MachineReviewError("verifier run provider differs from frozen config")


def _artifact_inventory(run_directory: Path) -> dict[str, Any]:
    allowed_names = {
        "verifier-run.json",
        "run-identity.json",
        "run-state.json",
        "verifier-predictions.jsonl",
        "blind-verifier-input.jsonl",
        "status.json",
        "prediction.json",
        "decision.json",
        "provider-session.json",
        "gemini-provider-configuration.json",
        "openai-provider-configuration.json",
        "local-provider-configuration.json",
    }
    rows: list[dict[str, str]] = []
    raw_responses = 0
    for path in sorted(run_directory.rglob("*")):
        if not path.is_file():
            continue
        if path.name in allowed_names or path.name.startswith("step-"):
            relative = path.relative_to(run_directory).as_posix()
            rows.append({"path": relative, "sha256": _sha256(path)})
            if "raw-response" in path.name:
                raw_responses += 1
    return {
        "files": len(rows),
        "raw_responses": raw_responses,
        "inventory_sha256": _value_sha256(rows),
    }


def _load_run(
    *,
    run_directory: Path,
    review_directory: Path,
    expected_input: Path,
    expected_ids: list[str],
    findings_by_id: dict[str, dict[str, Any]],
    expected_snapshot_root: Path,
    config: dict[str, Any],
    label: str,
    success_ids: list[str] | None = None,
) -> dict[str, Any]:
    run_directory = run_directory.resolve()
    _safe_relative_to(run_directory, review_directory, label)
    manifest_path = run_directory / "verifier-run.json"
    run = _read_json(manifest_path, f"{label} verifier run")
    counts = run.get("case_counts")
    partial = success_ids is not None
    expected_success_ids = expected_ids if success_ids is None else success_ids
    if len(expected_success_ids) != len(set(expected_success_ids)) or any(
        finding_id not in set(expected_ids) for finding_id in expected_success_ids
    ):
        raise MachineReviewError(f"{label} expected success IDs are invalid")
    expected_success_set = set(expected_success_ids)
    expected_failed_set = set(expected_ids) - expected_success_set
    if (
        run.get("status") != ("INCOMPLETE" if partial else "COMPLETE")
        or run.get("complete") is not (False if partial else True)
        or not isinstance(counts, dict)
        or counts.get("total") != len(expected_ids)
        or counts.get("success") != len(expected_success_ids)
        or counts.get("failed") != len(expected_failed_set)
    ):
        raise MachineReviewError(f"{label} run completion state differs from expectation")
    frozen_components: dict[str, str] = {}
    for component in ("profile", "prompt", "response_schema", "prediction_schema", "controller"):
        proof = run.get(component)
        checksum = proof.get("sha256") if isinstance(proof, dict) else None
        if not isinstance(checksum, str) or len(checksum) != 64:
            raise MachineReviewError(f"{label} has no frozen {component} checksum")
        frozen_components[component] = checksum
    expected_components = {
        name: _sha256(path.resolve(strict=True))
        for name, path in SOURCE_REVIEW_COMPONENTS.items()
    }
    if frozen_components != expected_components:
        raise MachineReviewError(
            f"{label} source-review components differ from the frozen methodology"
        )
    input_proof = run.get("input")
    predictions_proof = run.get("predictions")
    if not isinstance(input_proof, dict) or not isinstance(predictions_proof, dict):
        raise MachineReviewError(f"{label} run has incomplete file proofs")
    frozen_input = run_directory / str(input_proof.get("frozen_copy") or "")
    if (
        not frozen_input.is_file()
        or _sha256(frozen_input) != input_proof.get("sha256")
        or input_proof.get("records") != len(expected_ids)
        or _sha256(frozen_input) != _sha256(expected_input)
    ):
        raise MachineReviewError(f"{label} frozen input proof is invalid")
    if _ordered_ids(_read_jsonl(frozen_input, f"{label} input"), f"{label} input") != expected_ids:
        raise MachineReviewError(f"{label} run input ordering differs")
    predictions_path = run_directory / str(predictions_proof.get("path") or "")
    if (
        not predictions_path.is_file()
        or _sha256(predictions_path) != predictions_proof.get("sha256")
        or predictions_proof.get("records") != len(expected_success_ids)
    ):
        raise MachineReviewError(f"{label} prediction proof is invalid")
    rows = _read_jsonl(predictions_path, f"{label} predictions")
    ordered_success_ids = [
        finding_id for finding_id in expected_ids if finding_id in expected_success_set
    ]
    if _ordered_ids(rows, f"{label} predictions") != ordered_success_ids:
        raise MachineReviewError(f"{label} predictions do not exactly cover expected successes")

    identity_path = run_directory / "run-identity.json"
    identity = _read_json(identity_path, f"{label} run identity")
    identity_provider = identity.get("provider")
    if not isinstance(identity_provider, dict):
        raise MachineReviewError(f"{label} run identity has no provider")
    provider_configuration_name = {
        GEMINI_PROVIDER_ID: "gemini-provider-configuration.json",
        OPENAI_PROVIDER_ID: "openai-provider-configuration.json",
        LOCAL_PROVIDER_ID: "local-provider-configuration.json",
    }[config["provider"]]
    provider_configuration_path = run_directory / provider_configuration_name
    provider_configuration = _read_json(
        provider_configuration_path, f"{label} provider configuration"
    )
    configuration = provider_configuration.get("configuration")
    if not isinstance(configuration, dict):
        raise MachineReviewError(f"{label} run has no immutable provider configuration")
    expected_configuration = {"model": config["model"]}
    if config["provider"] == GEMINI_PROVIDER_ID:
        expected_configuration.update(
            {
                "seed": config["seed"],
                "temperature": config["temperature"],
                "thinking_level": config["thinking_level"],
            }
        )
    elif config["provider"] == OPENAI_PROVIDER_ID:
        expected_configuration.update(
            {
                "reasoning_effort": config["thinking_level"],
                "max_output_tokens": 16_384,
                "store": False,
            }
        )
    else:
        expected_configuration.update(
            {
                "seed": config["seed"],
                "temperature": config["temperature"],
                "base_url": config["base_url"],
                "model_revision_sha256": config["model_revision_sha256"],
                "max_tokens": config["max_tokens"],
            }
        )
    for key, value in expected_configuration.items():
        observed = configuration.get(key)
        if key == "thinking_level" and isinstance(observed, str):
            observed = observed.casefold()
        if observed != value:
            raise MachineReviewError(f"{label} provider configuration differs at {key}")
    if (
        identity_provider.get("id") != config["provider"]
        or not isinstance(identity_provider.get("version"), str)
        or not identity_provider["version"]
        or identity_provider.get("model") != config["model"]
        or provider_configuration.get("provider") != config["provider"]
        or provider_configuration.get("provider_version") != identity_provider["version"]
        or provider_configuration.get("sdk_version") != config["provider_version"]
        or configuration.get("sdk_version") != config["provider_version"]
        or provider_configuration.get("configuration_sha256")
        != _value_sha256(configuration)
    ):
        raise MachineReviewError(f"{label} immutable provider identity differs")

    snapshot_root = _snapshot_root(run)
    if snapshot_root != expected_snapshot_root.resolve(strict=True):
        raise MachineReviewError(f"{label} snapshot_root differs from the frozen release")
    case_by_id: dict[str, Path] = {}
    case_status_by_id: dict[str, dict[str, Any]] = {}
    all_case_status_by_id: dict[str, dict[str, Any]] = {}
    for status_path in sorted((run_directory / "cases").glob("*/status.json")):
        status = _read_json(status_path, f"{label} case status")
        finding_id = status.get("identity", {}).get("finding_id")
        if (
            not isinstance(finding_id, str)
            or finding_id in all_case_status_by_id
            or finding_id not in set(expected_ids)
            or status.get("status")
            != ("SUCCESS" if finding_id in expected_success_set else "FAILED")
        ):
            raise MachineReviewError(f"{label} has an invalid/duplicate case status")
        all_case_status_by_id[finding_id] = status
        if finding_id in expected_success_set:
            case_by_id[finding_id] = status_path.parent
            case_status_by_id[finding_id] = status
    if set(all_case_status_by_id) != set(expected_ids) or set(case_by_id) != expected_success_set:
        raise MachineReviewError(f"{label} case directories do not exactly cover input")
    manifest_cases = run.get("cases")
    if not isinstance(manifest_cases, list) or len(manifest_cases) != len(expected_ids):
        raise MachineReviewError(f"{label} manifest case proofs are incomplete")
    manifest_case_by_id: dict[str, dict[str, Any]] = {}
    for case_status in manifest_cases:
        finding_id = (
            case_status.get("identity", {}).get("finding_id")
            if isinstance(case_status, dict)
            else None
        )
        if not isinstance(finding_id, str) or finding_id in manifest_case_by_id:
            raise MachineReviewError(f"{label} manifest case identity is invalid")
        manifest_case_by_id[finding_id] = case_status
    if manifest_case_by_id != all_case_status_by_id:
        raise MachineReviewError(f"{label} manifest cases differ from case statuses")

    model_versions: set[str] = set()
    response_ids: set[str] = set()
    aggregate_usage: defaultdict[str, int] = defaultdict(int)
    evidence_errors: dict[str, str] = {}
    row_map: dict[str, dict[str, Any]] = {}
    per_prediction_sha256: dict[str, str] = {}
    for row in rows:
        finding_id = str(row["finding_id"])
        _validate_prediction_core(row, finding_id=finding_id, run=run, config=config)
        case_directory = case_by_id[finding_id]
        prediction_path = case_directory / "prediction.json"
        status = _read_json(case_directory / "status.json", f"{label} case status")
        if (
            not prediction_path.is_file()
            or _sha256(prediction_path) != status.get("prediction_sha256")
            or _read_json(prediction_path, f"{label} case prediction") != row
        ):
            raise MachineReviewError(f"{label} case prediction proof differs: {finding_id}")
        steps = row.get("agent", {}).get("steps")
        if not isinstance(steps, int) or isinstance(steps, bool) or steps < 1:
            raise MachineReviewError(f"{label} prediction step count is invalid")
        for step in range(1, steps + 1):
            metadata_path = case_directory / f"step-{step:02d}-provider-metadata.json"
            metadata = _read_json(metadata_path, f"{label} provider metadata")
            raw_proof = metadata.get("raw_response")
            raw_path = case_directory / f"step-{step:02d}-raw-response.json"
            version = metadata.get("model_version")
            response_id = metadata.get("response_id")
            if (
                metadata.get("provider") != config["provider"]
                or metadata.get("provider_version") != identity_provider["version"]
                or metadata.get("sdk_version") != config["provider_version"]
                or metadata.get("configured_model") != config["model"]
                or metadata.get("configuration") != configuration
                or metadata.get("configuration_sha256")
                != provider_configuration.get("configuration_sha256")
                or metadata.get("step") != step
                or not isinstance(version, str)
                or not version
                or not isinstance(response_id, str)
                or not response_id
                or not isinstance(raw_proof, dict)
                or raw_proof.get("path") != raw_path.name
                or not raw_path.is_file()
                or raw_proof.get("bytes") != raw_path.stat().st_size
                or raw_proof.get("sha256") != _sha256(raw_path)
            ):
                raise MachineReviewError(f"{label} provider metadata proof is invalid")
            if response_id in response_ids:
                raise MachineReviewError(f"{label} has duplicate Gemini response IDs")
            response_ids.add(response_id)
            model_versions.add(version)
            usage_records: list[dict[str, Any]] = []
            accepted_usage = metadata.get("normalized_usage")
            if isinstance(accepted_usage, dict):
                usage_records.append(accepted_usage)
            attempt_history = metadata.get("attempt_history") or []
            if not isinstance(attempt_history, list):
                raise MachineReviewError(f"{label} attempt history is invalid")
            for attempt in attempt_history:
                if not isinstance(attempt, dict):
                    raise MachineReviewError(f"{label} attempt history is invalid")
                retry_usage = attempt.get("normalized_usage")
                if retry_usage is not None:
                    if not isinstance(retry_usage, dict):
                        raise MachineReviewError(f"{label} retry usage is invalid")
                    usage_records.append(retry_usage)
                retry_raw = attempt.get("raw_response")
                if retry_raw is not None:
                    retry_name = retry_raw.get("path") if isinstance(retry_raw, dict) else None
                    retry_path = case_directory / str(retry_name or "")
                    if (
                        not isinstance(retry_name, str)
                        or Path(retry_name).name != retry_name
                        or not retry_name.startswith(f"step-{step:02d}-")
                        or not retry_path.is_file()
                        or retry_raw.get("bytes") != retry_path.stat().st_size
                        or retry_raw.get("sha256") != _sha256(retry_path)
                    ):
                        raise MachineReviewError(
                            f"{label} retry raw-response proof is invalid"
                        )
            for usage_record in usage_records:
                for usage_name, usage_value in usage_record.items():
                    if (
                        isinstance(usage_value, int)
                        and not isinstance(usage_value, bool)
                        and usage_value >= 0
                    ):
                        aggregate_usage[str(usage_name)] += usage_value
        error = _evidence_error(row, findings_by_id[finding_id], snapshot_root)
        if error:
            evidence_errors[finding_id] = error
        row_map[finding_id] = row
        per_prediction_sha256[finding_id] = _value_sha256(row)
    if len(model_versions) != 1:
        raise MachineReviewError(
            f"{label} must have one non-empty server model_version, got {sorted(model_versions)}"
        )
    expected_usage = dict(sorted(aggregate_usage.items()))
    if partial:
        aggregate_usage = defaultdict(int)
        for status in all_case_status_by_id.values():
            for usage_name, usage_value in (status.get("provider_usage") or {}).items():
                if (
                    isinstance(usage_value, int)
                    and not isinstance(usage_value, bool)
                    and usage_value >= 0
                ):
                    aggregate_usage[str(usage_name)] += usage_value
        expected_usage = dict(sorted(aggregate_usage.items()))
    if run.get("provider", {}).get("usage") != expected_usage:
        raise MachineReviewError(f"{label} aggregate provider usage differs")
    return {
        "run_directory": run_directory,
        "manifest": run,
        "rows": row_map,
        "prediction_sha256": per_prediction_sha256,
        "evidence_errors": evidence_errors,
        "model_version": next(iter(model_versions)),
        "proof": {
            "run_directory": _portable_path(run_directory, review_directory),
            "verifier_run_sha256": _sha256(manifest_path),
            "run_identity_sha256": _sha256(identity_path),
            "provider_configuration_sha256": _sha256(provider_configuration_path),
            "input_sha256": _sha256(frozen_input),
            "predictions_sha256": _sha256(predictions_path),
            "records": len(rows),
            "failed_records": len(expected_failed_set),
            "failed_finding_ids_sha256": _value_sha256(
                [finding_id for finding_id in expected_ids if finding_id in expected_failed_set]
            ),
            "requested_model": config["model"],
            "model_version": next(iter(model_versions)),
            "provider": config["provider"],
            "provider_version": identity_provider["version"],
            "sdk_version": config["provider_version"],
            "usage": run.get("provider", {}).get("usage", {}),
            "artifacts": _artifact_inventory(run_directory),
            "frozen_components": frozen_components,
        },
    }


def _load_r6_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r6.json", "r6 migration")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id") != "opengrep-machine-review-r5-to-r6-v1"
        or migration.get("status") not in {"AWAITING_RETRY_RUNS", "COMPLETE"}
        or migration.get("identity", {}).get("r6_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
    ):
        raise MachineReviewError("r6 migration identity is invalid")
    _check_stage_outputs(review_directory, migration)
    for role in ("a", "b"):
        proof = migration.get("roles", {}).get(f"reviewer_{role}")
        if not isinstance(proof, dict):
            raise MachineReviewError(f"r6 reviewer {role} migration proof is invalid")
        base_run = (review_directory / str(proof.get("base_run") or "")).resolve()
        _safe_relative_to(base_run, review_directory, f"reviewer {role} r5 base")
        if (
            not base_run.is_dir()
            or _sha256(base_run / "verifier-run.json")
            != proof.get("base_verifier_run_sha256")
            or _artifact_inventory(base_run) != proof.get("base_artifacts")
        ):
            raise MachineReviewError(f"reviewer {role} r5 base artifacts changed")
    return migration


def _load_migrated_role_sources(
    *, review_directory: Path, role: str
) -> tuple[dict[str, Any], dict[str, Any], list[str], list[str], list[str]]:
    manifest = _load_machine_manifest(review_directory)
    migration = _load_r6_migration(review_directory)
    role_name = "REVIEWER_A" if role == "a" else "REVIEWER_B"
    role_proof = migration["roles"][f"reviewer_{role}"]
    full_input = review_directory / f"reviewer-{role}" / "blind-input.jsonl"
    full_ids = _ordered_ids(
        _read_jsonl(full_input, f"reviewer {role} input"), f"reviewer {role} input"
    )
    retry_input = review_directory / str(role_proof["retry_input"])
    retry_ids = _ordered_ids(
        _read_jsonl(retry_input, f"reviewer {role} retry input"),
        f"reviewer {role} retry input",
    )
    if (
        retry_ids != role_proof.get("retry_finding_ids")
        or _value_sha256(retry_ids) != role_proof.get("retry_finding_ids_sha256")
        or len(retry_ids) != role_proof.get("retry_records")
    ):
        raise MachineReviewError(f"reviewer {role} retry identity differs")
    retry_set = set(retry_ids)
    success_ids = [finding_id for finding_id in full_ids if finding_id not in retry_set]
    if (
        len(success_ids) != role_proof.get("reused_success")
        or _value_sha256(success_ids) != role_proof.get("reused_finding_ids_sha256")
    ):
        raise MachineReviewError(f"reviewer {role} reused-success identity differs")
    findings, _ = _frozen_rows(review_directory)
    findings_by_id = {str(row["finding_id"]): row for row in findings}
    config = _frozen_config(review_directory, role_name)
    base = _load_run(
        run_directory=review_directory / str(role_proof["base_run"]),
        review_directory=review_directory,
        expected_input=review_directory
        / str(role_proof["base_run"])
        / "blind-verifier-input.jsonl",
        expected_ids=full_ids,
        findings_by_id=findings_by_id,
        expected_snapshot_root=_frozen_snapshot_root(manifest),
        config=config,
        label=f"reviewer {role} r5 base",
        success_ids=success_ids,
    )
    retry = _load_run(
        run_directory=review_directory / str(role_proof["retry_run"]),
        review_directory=review_directory,
        expected_input=retry_input,
        expected_ids=retry_ids,
        findings_by_id=findings_by_id,
        expected_snapshot_root=_frozen_snapshot_root(manifest),
        config=config,
        label=f"reviewer {role} r6 retry",
    )
    return base, retry, full_ids, success_ids, retry_ids


def _composite_role_data(
    *, review_directory: Path, role: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    base, retry, full_ids, success_ids, retry_ids = _load_migrated_role_sources(
        review_directory=review_directory, role=role
    )
    rows = {**base["rows"], **retry["rows"]}
    prediction_sha256 = {
        **base["prediction_sha256"],
        **retry["prediction_sha256"],
    }
    evidence_errors = {**base["evidence_errors"], **retry["evidence_errors"]}
    if set(rows) != set(full_ids) or set(prediction_sha256) != set(full_ids):
        raise MachineReviewError(f"reviewer {role} composite does not cover 400 IDs")
    model_versions = sorted({base["model_version"], retry["model_version"]})
    provider_versions = [
        base["proof"]["provider_version"],
        retry["proof"]["provider_version"],
    ]
    usage: defaultdict[str, int] = defaultdict(int)
    for source in (base, retry):
        for name, value in source["proof"].get("usage", {}).items():
            if isinstance(value, int) and not isinstance(value, bool):
                usage[str(name)] += value
    identity = {
        "schema_version": 1,
        "protocol": "reviewer-composite-migration-v1",
        "role": role,
        "records": len(full_ids),
        "finding_ids_sha256": _value_sha256(full_ids),
        "reused_finding_ids_sha256": _value_sha256(success_ids),
        "retry_finding_ids_sha256": _value_sha256(retry_ids),
        "base_verifier_run_sha256": base["proof"]["verifier_run_sha256"],
        "retry_verifier_run_sha256": retry["proof"]["verifier_run_sha256"],
        "base_predictions_sha256": base["proof"]["predictions_sha256"],
        "retry_predictions_sha256": retry["proof"]["predictions_sha256"],
        "provider_versions": provider_versions,
        "model_versions": model_versions,
    }
    return {
        "rows": rows,
        "prediction_sha256": prediction_sha256,
        "evidence_errors": evidence_errors,
        "model_version": "+".join(model_versions),
        "provider_version": _value_sha256(provider_versions),
        "usage": dict(sorted(usage.items())),
        "frozen_components": base["proof"]["frozen_components"],
        "base": base,
        "retry": retry,
        "full_ids": full_ids,
    }, identity


def seal_r6_migration(
    *, review_directory: Path, created_at: str | None = None
) -> dict[str, Any]:
    review_directory = review_directory.resolve()
    _load_machine_manifest(review_directory)
    migration = _load_r6_migration(review_directory)
    role_results: dict[str, Any] = {}
    for role in ("a", "b"):
        data, identity = _composite_role_data(
            review_directory=review_directory, role=role
        )
        config = _frozen_config(
            review_directory, "REVIEWER_A" if role == "a" else "REVIEWER_B"
        )
        run_directory = review_directory / f"reviewer-{role}" / "run"
        identity_path = run_directory / "run-identity.json"
        if identity_path.is_file():
            if _read_json(identity_path, f"reviewer {role} composite identity") != identity:
                raise MachineReviewError(f"reviewer {role} composite identity differs")
        elif run_directory.exists() and any(run_directory.iterdir()):
            raise MachineReviewError(f"reviewer {role} composite directory is partial")
        else:
            run_directory.mkdir(parents=True, exist_ok=True)
            _write_json(identity_path, identity)
            full_input = review_directory / f"reviewer-{role}" / "blind-input.jsonl"
            shutil.copyfile(full_input, run_directory / "blind-verifier-input.jsonl")
            ordered_rows = [data["rows"][finding_id] for finding_id in data["full_ids"]]
            _write_jsonl(run_directory / "verifier-predictions.jsonl", ordered_rows)
            provider_configuration = {
                "schema_version": 1,
                "provider": "MIGRATED_GEMINI_COMPOSITE",
                "provider_version": data["provider_version"],
                "sdk_version": config["provider_version"],
                "configuration": {
                    "model": config["model"],
                    "migration_protocol": identity["protocol"],
                    "provider_versions": identity["provider_versions"],
                },
            }
            provider_configuration["configuration_sha256"] = _value_sha256(
                provider_configuration["configuration"]
            )
            _write_json(
                run_directory / "gemini-provider-configuration.json",
                provider_configuration,
            )
            run_manifest = {
                "schema_version": 1,
                "run_id": run_directory.name,
                "created_at": created_at or _utc_now(),
                "status": "COMPLETE",
                "complete": True,
                "migration_protocol": identity["protocol"],
                "case_counts": {
                    "total": len(data["full_ids"]),
                    "success": len(data["full_ids"]),
                    "failed": 0,
                },
                "input": {
                    "frozen_copy": "blind-verifier-input.jsonl",
                    "sha256": _sha256(run_directory / "blind-verifier-input.jsonl"),
                    "records": len(data["full_ids"]),
                },
                "predictions": {
                    "path": "verifier-predictions.jsonl",
                    "sha256": _sha256(run_directory / "verifier-predictions.jsonl"),
                    "records": len(data["full_ids"]),
                },
                "provider": {
                    "id": "MIGRATED_GEMINI_COMPOSITE",
                    "version": data["provider_version"],
                    "model": config["model"],
                    "model_version": data["model_version"],
                    "usage": data["usage"],
                },
                "migration": identity,
            }
            _write_json(run_directory / "verifier-run.json", run_manifest)
        role_results[f"reviewer_{role}"] = _load_composite_run(
            run_directory=run_directory,
            review_directory=review_directory,
            role=role,
        )["proof"]
    complete = {
        **migration,
        "status": "COMPLETE",
        "completed_at": created_at or _utc_now(),
        "composite_runs": role_results,
    }
    _write_json(review_directory / "migration-r6.json", complete)
    return complete


def _load_composite_run(
    *, run_directory: Path, review_directory: Path, role: str
) -> dict[str, Any]:
    run_directory = run_directory.resolve()
    _safe_relative_to(run_directory, review_directory, f"reviewer {role} composite")
    identity_path = run_directory / "run-identity.json"
    identity = _read_json(identity_path, f"reviewer {role} composite identity")
    if (
        identity.get("protocol") != "reviewer-composite-migration-v1"
        or identity.get("role") != role
    ):
        raise MachineReviewError(f"reviewer {role} composite identity is invalid")
    data, expected_identity = _composite_role_data(
        review_directory=review_directory, role=role
    )
    if identity != expected_identity:
        raise MachineReviewError(f"reviewer {role} composite sources changed")
    run_path = run_directory / "verifier-run.json"
    run = _read_json(run_path, f"reviewer {role} composite run")
    predictions_path = run_directory / "verifier-predictions.jsonl"
    input_path = run_directory / "blind-verifier-input.jsonl"
    provider_path = run_directory / "gemini-provider-configuration.json"
    rows = _read_jsonl(predictions_path, f"reviewer {role} composite predictions")
    expected_rows = [data["rows"][finding_id] for finding_id in data["full_ids"]]
    if (
        run.get("status") != "COMPLETE"
        or run.get("complete") is not True
        or run.get("migration") != identity
        or run.get("case_counts")
        != {"total": len(data["full_ids"]), "success": len(data["full_ids"]), "failed": 0}
        or _sha256(input_path) != run.get("input", {}).get("sha256")
        or _sha256(predictions_path) != run.get("predictions", {}).get("sha256")
        or rows != expected_rows
        or _ordered_ids(rows, f"reviewer {role} composite predictions") != data["full_ids"]
    ):
        raise MachineReviewError(f"reviewer {role} composite run differs")
    provider = _read_json(provider_path, f"reviewer {role} composite provider")
    if (
        provider.get("provider") != "MIGRATED_GEMINI_COMPOSITE"
        or provider.get("provider_version") != data["provider_version"]
        or provider.get("configuration_sha256")
        != _value_sha256(provider.get("configuration"))
    ):
        raise MachineReviewError(f"reviewer {role} composite provider proof is invalid")
    proof = {
        "run_directory": _portable_path(run_directory, review_directory),
        "verifier_run_sha256": _sha256(run_path),
        "run_identity_sha256": _sha256(identity_path),
        "provider_configuration_sha256": _sha256(provider_path),
        "input_sha256": _sha256(input_path),
        "predictions_sha256": _sha256(predictions_path),
        "records": len(rows),
        "failed_records": 0,
        "requested_model": _frozen_config(
            review_directory, "REVIEWER_A" if role == "a" else "REVIEWER_B"
        )["model"],
        "model_version": data["model_version"],
        "model_versions": identity["model_versions"],
        "provider": "MIGRATED_GEMINI_COMPOSITE",
        "provider_version": data["provider_version"],
        "provider_versions": identity["provider_versions"],
        "sdk_version": _frozen_config(
            review_directory, "REVIEWER_A" if role == "a" else "REVIEWER_B"
        )["provider_version"],
        "usage": data["usage"],
        "artifacts": _artifact_inventory(run_directory),
        "frozen_components": data["frozen_components"],
        "migration_sources": {
            "base": data["base"]["proof"],
            "retry": data["retry"]["proof"],
        },
    }
    return {**data, "proof": proof}


def _load_r7_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r7.json", "r7 migration")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r6-to-r7-supplement-v1"
        or migration.get("status") not in {"AWAITING_RETRY_RUNS", "COMPLETE"}
        or migration.get("identity", {}).get("r7_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
    ):
        raise MachineReviewError("r7 supplement identity is invalid")
    _check_stage_outputs(review_directory, migration)
    for role in ("a", "b"):
        role_proof = migration.get("roles", {}).get(f"reviewer_{role}")
        if not isinstance(role_proof, dict):
            raise MachineReviewError(f"r7 reviewer {role} supplement proof is invalid")
        sources = role_proof.get("sources")
        if not isinstance(sources, list) or len(sources) != 2:
            raise MachineReviewError(f"r7 reviewer {role} sources are invalid")
        for source in sources:
            if not isinstance(source, dict):
                raise MachineReviewError(f"r7 reviewer {role} source proof is invalid")
            source_run = (review_directory / str(source.get("run") or "")).resolve()
            _safe_relative_to(source_run, review_directory, f"reviewer {role} source")
            if (
                not source_run.is_dir()
                or _sha256(source_run / "verifier-run.json")
                != source.get("verifier_run_sha256")
                or _artifact_inventory(source_run) != source.get("artifacts")
            ):
                raise MachineReviewError(f"reviewer {role} supplement source changed")
    return migration


def _r7_supplement_role_data(
    *, review_directory: Path, role: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _load_machine_manifest(review_directory)
    migration = _load_r7_migration(review_directory)
    role_name = "REVIEWER_A" if role == "a" else "REVIEWER_B"
    config = _frozen_config(review_directory, role_name)
    role_proof = migration["roles"][f"reviewer_{role}"]
    full_input = review_directory / f"reviewer-{role}" / "blind-input.jsonl"
    full_ids = _ordered_ids(
        _read_jsonl(full_input, f"reviewer {role} input"), f"reviewer {role} input"
    )
    findings, _ = _frozen_rows(review_directory)
    findings_by_id = {str(row["finding_id"]): row for row in findings}
    expected_snapshot_root = _frozen_snapshot_root(manifest)
    source_results: list[dict[str, Any]] = []
    reused_ids: list[str] = []
    for source in role_proof["sources"]:
        source_ids = source.get("input_finding_ids")
        selected_ids = source.get("selected_success_ids")
        if (
            not isinstance(source_ids, list)
            or not all(isinstance(item, str) for item in source_ids)
            or _value_sha256(source_ids) != source.get("input_finding_ids_sha256")
            or not isinstance(selected_ids, list)
            or not all(isinstance(item, str) for item in selected_ids)
            or _value_sha256(selected_ids)
            != source.get("selected_success_ids_sha256")
        ):
            raise MachineReviewError(f"reviewer {role} source ID proof differs")
        source_run = review_directory / str(source["run"])
        loaded = _load_run(
            run_directory=source_run,
            review_directory=review_directory,
            expected_input=source_run / "blind-verifier-input.jsonl",
            expected_ids=source_ids,
            findings_by_id=findings_by_id,
            expected_snapshot_root=expected_snapshot_root,
            config=config,
            label=f"reviewer {role} {source['name']} source",
            success_ids=selected_ids,
        )
        source_results.append(loaded)
        reused_ids.extend(selected_ids)
    if len(reused_ids) != len(set(reused_ids)):
        raise MachineReviewError(f"reviewer {role} supplement success sources overlap")
    ordered_reused_ids = [finding_id for finding_id in full_ids if finding_id in set(reused_ids)]
    if (
        len(ordered_reused_ids) != role_proof.get("reused_success")
        or _value_sha256(ordered_reused_ids)
        != role_proof.get("reused_finding_ids_sha256")
    ):
        raise MachineReviewError(f"reviewer {role} reused-success identity differs")

    retry_input = review_directory / str(role_proof["retry_input"])
    retry_ids = _ordered_ids(
        _read_jsonl(retry_input, f"reviewer {role} r7 retry input"),
        f"reviewer {role} r7 retry input",
    )
    if (
        retry_ids != role_proof.get("retry_finding_ids")
        or len(retry_ids) != role_proof.get("retry_records")
        or _value_sha256(retry_ids) != role_proof.get("retry_finding_ids_sha256")
        or set(ordered_reused_ids) | set(retry_ids) != set(full_ids)
        or set(ordered_reused_ids) & set(retry_ids)
    ):
        raise MachineReviewError(f"reviewer {role} r7 retry identity differs")
    retry = _load_run(
        run_directory=review_directory / str(role_proof["retry_run"]),
        review_directory=review_directory,
        expected_input=retry_input,
        expected_ids=retry_ids,
        findings_by_id=findings_by_id,
        expected_snapshot_root=expected_snapshot_root,
        config=config,
        label=f"reviewer {role} r7 retry",
    )
    rows: dict[str, dict[str, Any]] = {}
    prediction_sha256: dict[str, str] = {}
    evidence_errors: dict[str, str] = {}
    all_results = [*source_results, retry]
    for loaded in all_results:
        if set(rows) & set(loaded["rows"]):
            raise MachineReviewError(f"reviewer {role} supplement predictions overlap")
        rows.update(loaded["rows"])
        prediction_sha256.update(loaded["prediction_sha256"])
        evidence_errors.update(loaded["evidence_errors"])
    if set(rows) != set(full_ids) or set(prediction_sha256) != set(full_ids):
        raise MachineReviewError(f"reviewer {role} r7 composite does not cover all IDs")

    model_versions = sorted({loaded["model_version"] for loaded in all_results})
    provider_versions = [
        loaded["proof"]["provider_version"] for loaded in all_results
    ]
    usage: defaultdict[str, int] = defaultdict(int)
    for loaded in all_results:
        for name, value in loaded["proof"].get("usage", {}).items():
            if isinstance(value, int) and not isinstance(value, bool):
                usage[str(name)] += value
    identity = {
        "schema_version": 1,
        "protocol": "reviewer-composite-supplement-v2",
        "role": role,
        "records": len(full_ids),
        "finding_ids_sha256": _value_sha256(full_ids),
        "reused_finding_ids_sha256": _value_sha256(ordered_reused_ids),
        "retry_finding_ids_sha256": _value_sha256(retry_ids),
        "source_verifier_run_sha256": [
            loaded["proof"]["verifier_run_sha256"] for loaded in source_results
        ],
        "source_predictions_sha256": [
            loaded["proof"]["predictions_sha256"] for loaded in source_results
        ],
        "retry_verifier_run_sha256": retry["proof"]["verifier_run_sha256"],
        "retry_predictions_sha256": retry["proof"]["predictions_sha256"],
        "provider_versions": provider_versions,
        "model_versions": model_versions,
    }
    data = {
        "rows": rows,
        "prediction_sha256": prediction_sha256,
        "evidence_errors": evidence_errors,
        "model_version": "+".join(model_versions),
        "provider_version": _value_sha256(provider_versions),
        "usage": dict(sorted(usage.items())),
        "frozen_components": source_results[0]["proof"]["frozen_components"],
        "sources": source_results,
        "retry": retry,
        "full_ids": full_ids,
    }
    if any(
        loaded["proof"]["frozen_components"] != data["frozen_components"]
        for loaded in all_results
    ):
        raise MachineReviewError(f"reviewer {role} source-review components differ")
    return data, identity


def seal_r7_supplement(
    *, review_directory: Path, created_at: str | None = None
) -> dict[str, Any]:
    review_directory = review_directory.resolve()
    _load_machine_manifest(review_directory)
    migration = _load_r7_migration(review_directory)
    role_results: dict[str, Any] = {}
    for role in ("a", "b"):
        data, identity = _r7_supplement_role_data(
            review_directory=review_directory, role=role
        )
        config = _frozen_config(
            review_directory, "REVIEWER_A" if role == "a" else "REVIEWER_B"
        )
        run_directory = review_directory / f"reviewer-{role}" / "run"
        identity_path = run_directory / "run-identity.json"
        if identity_path.is_file():
            if _read_json(identity_path, f"reviewer {role} composite identity") != identity:
                raise MachineReviewError(f"reviewer {role} r7 composite identity differs")
        elif run_directory.exists() and any(run_directory.iterdir()):
            raise MachineReviewError(f"reviewer {role} r7 composite directory is partial")
        else:
            run_directory.mkdir(parents=True, exist_ok=True)
            _write_json(identity_path, identity)
            full_input = review_directory / f"reviewer-{role}" / "blind-input.jsonl"
            shutil.copyfile(full_input, run_directory / "blind-verifier-input.jsonl")
            ordered_rows = [data["rows"][finding_id] for finding_id in data["full_ids"]]
            _write_jsonl(run_directory / "verifier-predictions.jsonl", ordered_rows)
            provider_configuration = {
                "schema_version": 1,
                "provider": "MIGRATED_GEMINI_SUPPLEMENT_COMPOSITE",
                "provider_version": data["provider_version"],
                "sdk_version": config["provider_version"],
                "configuration": {
                    "model": config["model"],
                    "migration_protocol": identity["protocol"],
                    "provider_versions": identity["provider_versions"],
                },
            }
            provider_configuration["configuration_sha256"] = _value_sha256(
                provider_configuration["configuration"]
            )
            _write_json(
                run_directory / "gemini-provider-configuration.json",
                provider_configuration,
            )
            run_manifest = {
                "schema_version": 1,
                "run_id": run_directory.name,
                "created_at": created_at or _utc_now(),
                "status": "COMPLETE",
                "complete": True,
                "migration_protocol": identity["protocol"],
                "case_counts": {
                    "total": len(data["full_ids"]),
                    "success": len(data["full_ids"]),
                    "failed": 0,
                },
                "input": {
                    "frozen_copy": "blind-verifier-input.jsonl",
                    "sha256": _sha256(run_directory / "blind-verifier-input.jsonl"),
                    "records": len(data["full_ids"]),
                },
                "predictions": {
                    "path": "verifier-predictions.jsonl",
                    "sha256": _sha256(run_directory / "verifier-predictions.jsonl"),
                    "records": len(data["full_ids"]),
                },
                "provider": {
                    "id": "MIGRATED_GEMINI_SUPPLEMENT_COMPOSITE",
                    "version": data["provider_version"],
                    "model": config["model"],
                    "model_version": data["model_version"],
                    "usage": data["usage"],
                },
                "migration": identity,
            }
            _write_json(run_directory / "verifier-run.json", run_manifest)
        role_results[f"reviewer_{role}"] = _load_r7_composite_run(
            run_directory=run_directory,
            review_directory=review_directory,
            role=role,
        )["proof"]
    complete = {
        **migration,
        "status": "COMPLETE",
        "completed_at": created_at or _utc_now(),
        "composite_runs": role_results,
    }
    _write_json(review_directory / "migration-r7.json", complete)
    return complete


def _load_r7_composite_run(
    *, run_directory: Path, review_directory: Path, role: str
) -> dict[str, Any]:
    run_directory = run_directory.resolve()
    _safe_relative_to(run_directory, review_directory, f"reviewer {role} r7 composite")
    identity_path = run_directory / "run-identity.json"
    identity = _read_json(identity_path, f"reviewer {role} r7 composite identity")
    if (
        identity.get("protocol") != "reviewer-composite-supplement-v2"
        or identity.get("role") != role
    ):
        raise MachineReviewError(f"reviewer {role} r7 composite identity is invalid")
    data, expected_identity = _r7_supplement_role_data(
        review_directory=review_directory, role=role
    )
    if identity != expected_identity:
        raise MachineReviewError(f"reviewer {role} r7 composite sources changed")
    run_path = run_directory / "verifier-run.json"
    run = _read_json(run_path, f"reviewer {role} r7 composite run")
    predictions_path = run_directory / "verifier-predictions.jsonl"
    input_path = run_directory / "blind-verifier-input.jsonl"
    provider_path = run_directory / "gemini-provider-configuration.json"
    rows = _read_jsonl(predictions_path, f"reviewer {role} r7 composite predictions")
    expected_rows = [data["rows"][finding_id] for finding_id in data["full_ids"]]
    if (
        run.get("status") != "COMPLETE"
        or run.get("complete") is not True
        or run.get("migration") != identity
        or run.get("case_counts")
        != {"total": len(data["full_ids"]), "success": len(data["full_ids"]), "failed": 0}
        or _sha256(input_path) != run.get("input", {}).get("sha256")
        or _sha256(predictions_path) != run.get("predictions", {}).get("sha256")
        or rows != expected_rows
    ):
        raise MachineReviewError(f"reviewer {role} r7 composite run differs")
    provider = _read_json(provider_path, f"reviewer {role} r7 composite provider")
    if (
        provider.get("provider") != "MIGRATED_GEMINI_SUPPLEMENT_COMPOSITE"
        or provider.get("provider_version") != data["provider_version"]
        or provider.get("configuration_sha256")
        != _value_sha256(provider.get("configuration"))
    ):
        raise MachineReviewError(f"reviewer {role} r7 composite provider proof is invalid")
    proof = {
        "run_directory": _portable_path(run_directory, review_directory),
        "verifier_run_sha256": _sha256(run_path),
        "run_identity_sha256": _sha256(identity_path),
        "provider_configuration_sha256": _sha256(provider_path),
        "input_sha256": _sha256(input_path),
        "predictions_sha256": _sha256(predictions_path),
        "records": len(rows),
        "failed_records": 0,
        "requested_model": _frozen_config(
            review_directory, "REVIEWER_A" if role == "a" else "REVIEWER_B"
        )["model"],
        "model_version": data["model_version"],
        "model_versions": identity["model_versions"],
        "provider": "MIGRATED_GEMINI_SUPPLEMENT_COMPOSITE",
        "provider_version": data["provider_version"],
        "provider_versions": identity["provider_versions"],
        "sdk_version": _frozen_config(
            review_directory, "REVIEWER_A" if role == "a" else "REVIEWER_B"
        )["provider_version"],
        "usage": data["usage"],
        "artifacts": _artifact_inventory(run_directory),
        "frozen_components": data["frozen_components"],
        "migration_sources": {
            "sources": [source["proof"] for source in data["sources"]],
            "retry": data["retry"]["proof"],
        },
    }
    return {**data, "proof": proof}


def _r8_source_run_proof(
    base_review_directory: Path, role: str, migration: dict[str, Any]
) -> tuple[Path, dict[str, Any]]:
    proof = migration.get("composite_runs", {}).get(f"reviewer_{role}")
    if (
        not isinstance(proof, dict)
        or not isinstance(proof.get("records"), int)
        or proof["records"] < 1
    ):
        raise MachineReviewError(f"r8 source reviewer {role} proof is invalid")
    run_directory = base_review_directory / f"reviewer-{role}" / "run"
    checks = {
        "verifier-run.json": "verifier_run_sha256",
        "run-identity.json": "run_identity_sha256",
        "gemini-provider-configuration.json": "provider_configuration_sha256",
        "blind-verifier-input.jsonl": "input_sha256",
        "verifier-predictions.jsonl": "predictions_sha256",
    }
    for name, key in checks.items():
        path = run_directory / name
        if not path.is_file() or _sha256(path) != proof.get(key):
            raise MachineReviewError(
                f"r8 source reviewer {role} changed after r7 seal: {name}"
            )
    if _artifact_inventory(run_directory) != proof.get("artifacts"):
        raise MachineReviewError(
            f"r8 source reviewer {role} artifact inventory changed"
        )
    return run_directory, proof


def _load_r8_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r8.json", "r8 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r7-to-r8-adjudicator-only-v1"
        or migration.get("status")
        not in {"IMPORTED_A_B_AWAITING_RECONCILIATION", "COMPLETE"}
        or not isinstance(identity, dict)
        or identity.get("r8_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
    ):
        raise MachineReviewError("r8 adjudicator-only migration identity is invalid")
    _check_stage_outputs(review_directory, migration)
    base_value = identity.get("base_review_directory")
    if not isinstance(base_value, str) or not base_value:
        raise MachineReviewError("r8 source directory proof is invalid")
    base_directory = Path(base_value)
    if not base_directory.is_absolute():
        base_directory = PROJECT_ROOT / base_directory
    base_directory = base_directory.resolve(strict=True)
    if (
        _sha256(base_directory / "machine-review-manifest.json")
        != identity.get("base_manifest_sha256")
        or _sha256(base_directory / "migration-r7.json")
        != identity.get("base_migration_sha256")
        or _sha256(base_directory / "reconciliation" / "reconciliation-summary.json")
        != identity.get("base_reconciliation_summary_sha256")
        or _sha256(base_directory / "reconciliation" / "reconciliation.jsonl")
        != identity.get("base_reconciliation_sha256")
        or _sha256(base_directory / "adjudicator-c" / "blind-input.jsonl")
        != identity.get("base_blind_input_sha256")
    ):
        raise MachineReviewError("r8 frozen r7 source proof differs")
    base_migration = _load_r7_migration(base_directory)
    if base_migration.get("status") != "COMPLETE":
        raise MachineReviewError("r8 requires a complete r7 A/B migration")
    for role in ("a", "b"):
        _, source_proof = _r8_source_run_proof(
            base_directory, role, base_migration
        )
        role_proof = migration.get("roles", {}).get(f"reviewer_{role}")
        if (
            not isinstance(role_proof, dict)
            or role_proof.get("source") != source_proof
        ):
            raise MachineReviewError(f"r8 reviewer {role} source proof differs")
    return migration


def prepare_r8_adjudicator_migration(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Reuse frozen r7 A/B outputs and move only adjudicator C to OpenAI."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    if base_review_directory == review_directory:
        raise MachineReviewError("r8 base and destination must differ")
    manifest = _load_machine_manifest(review_directory)
    base_manifest = _load_frozen_base_manifest(base_review_directory)
    base_migration = _load_r7_migration(base_review_directory)
    if base_migration.get("status") != "COMPLETE":
        raise MachineReviewError("r8 requires r7 reviewer A/B to be complete")
    comparable = {
        "sample_manifest_sha256",
        "sample_findings_sha256",
        "sampling_index_sha256",
        "evidence_packets_sha256",
        "records",
        "finding_ids_sha256",
        "snapshot_root",
        "source_scanner",
        "evaluated_agent_model",
        "policy",
    }
    if any(
        manifest["identity"].get(key) != base_manifest["identity"].get(key)
        for key in comparable
    ):
        raise MachineReviewError("r8 corpus/policy identity differs from r7")
    for role in ("REVIEWER_A", "REVIEWER_B"):
        if _frozen_config(review_directory, role) != _frozen_config(
            base_review_directory, role
        ):
            raise MachineReviewError(f"r8 {role} config differs from r7")
    c_config = _frozen_config(review_directory, "ADJUDICATOR_C")
    if (
        c_config["provider"] != OPENAI_PROVIDER_ID
        or c_config["model"] != "gpt-5.6-luna"
    ):
        raise MachineReviewError(
            "r8 adjudicator C must use exact model gpt-5.6-luna via OpenAI Responses"
        )
    migration_path = review_directory / "migration-r8.json"
    if migration_path.is_file():
        return _load_r8_migration(review_directory)

    base_summary = _read_json(
        base_review_directory / "reconciliation" / "reconciliation-summary.json",
        "r7 reconciliation summary",
    )
    _check_stage_outputs(base_review_directory, base_summary)
    if (
        base_summary.get("status") != "AWAITING_ADJUDICATOR_C_BLIND_FIRST"
        or base_summary.get("records") != manifest["identity"]["records"]
        or not isinstance(
            base_summary.get("counts", {}).get("routed_to_adjudicator"), int
        )
        or base_summary["counts"]["routed_to_adjudicator"] < 1
    ):
        raise MachineReviewError("r8 requires the sealed r7 400/400 reconciliation")

    roles: dict[str, Any] = {}
    outputs: dict[str, Any] = {}
    for role in ("a", "b"):
        source_run, source_proof = _r8_source_run_proof(
            base_review_directory, role, base_migration
        )
        destination = review_directory / f"reviewer-{role}" / "run"
        if destination.exists() and any(destination.iterdir()):
            raise MachineReviewError(f"r8 reviewer {role} import directory is not empty")
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            source_run / "blind-verifier-input.jsonl",
            destination / "blind-verifier-input.jsonl",
        )
        shutil.copyfile(
            source_run / "verifier-predictions.jsonl",
            destination / "verifier-predictions.jsonl",
        )
        full_ids = _ordered_ids(
            _read_jsonl(
                destination / "blind-verifier-input.jsonl",
                f"r8 reviewer {role} imported input",
            ),
            f"r8 reviewer {role} imported input",
        )
        if _sha256(destination / "blind-verifier-input.jsonl") != _sha256(
            review_directory / f"reviewer-{role}" / "blind-input.jsonl"
        ):
            raise MachineReviewError(f"r8 reviewer {role} input differs from r7")
        source_identity = _read_json(
            source_run / "run-identity.json", f"r7 reviewer {role} identity"
        )
        identity = {
            "schema_version": 1,
            "protocol": "reviewer-composite-adjudicator-migration-v3",
            "role": role,
            "records": len(full_ids),
            "finding_ids_sha256": _value_sha256(full_ids),
            "source_review_directory": _portable_path(
                base_review_directory, PROJECT_ROOT
            ),
            "source_run_identity_sha256": source_proof["run_identity_sha256"],
            "source_verifier_run_sha256": source_proof["verifier_run_sha256"],
            "source_predictions_sha256": source_proof["predictions_sha256"],
            "source_protocol": source_identity.get("protocol"),
        }
        _write_json(destination / "run-identity.json", identity)
        provider_configuration = {
            "schema_version": 1,
            "provider": "IMPORTED_R7_COMPOSITE",
            "provider_version": source_proof["provider_version"],
            "sdk_version": source_proof["sdk_version"],
            "configuration": {
                "model": source_proof["requested_model"],
                "migration_protocol": identity["protocol"],
                "source_predictions_sha256": source_proof["predictions_sha256"],
            },
        }
        provider_configuration["configuration_sha256"] = _value_sha256(
            provider_configuration["configuration"]
        )
        _write_json(
            destination / "gemini-provider-configuration.json",
            provider_configuration,
        )
        run_manifest = {
            "schema_version": 1,
            "run_id": destination.name,
            "created_at": created_at or _utc_now(),
            "status": "COMPLETE",
            "complete": True,
            "migration_protocol": identity["protocol"],
            "case_counts": {"total": len(full_ids), "success": len(full_ids), "failed": 0},
            "input": {
                "frozen_copy": "blind-verifier-input.jsonl",
                "sha256": _sha256(destination / "blind-verifier-input.jsonl"),
                "records": len(full_ids),
            },
            "predictions": {
                "path": "verifier-predictions.jsonl",
                "sha256": _sha256(destination / "verifier-predictions.jsonl"),
                "records": len(full_ids),
            },
            "provider": {
                "id": "IMPORTED_R7_COMPOSITE",
                "version": source_proof["provider_version"],
                "model": source_proof["requested_model"],
                "model_version": source_proof["model_version"],
                "usage": source_proof.get("usage", {}),
            },
            "migration": identity,
        }
        _write_json(destination / "verifier-run.json", run_manifest)
        imported = {
            "run_directory": _portable_path(destination, review_directory),
            "verifier_run_sha256": _sha256(destination / "verifier-run.json"),
            "run_identity_sha256": _sha256(destination / "run-identity.json"),
            "provider_configuration_sha256": _sha256(
                destination / "gemini-provider-configuration.json"
            ),
            "input_sha256": _sha256(destination / "blind-verifier-input.jsonl"),
            "predictions_sha256": _sha256(destination / "verifier-predictions.jsonl"),
            "records": len(full_ids),
            "artifacts": _artifact_inventory(destination),
        }
        roles[f"reviewer_{role}"] = {"source": source_proof, "imported": imported}
        for name, records in (
            ("verifier-run.json", None),
            ("run-identity.json", None),
            ("gemini-provider-configuration.json", None),
            ("blind-verifier-input.jsonl", len(full_ids)),
            ("verifier-predictions.jsonl", len(full_ids)),
        ):
            path = destination / name
            relative = path.relative_to(review_directory).as_posix()
            outputs[relative] = {
                "path": relative,
                "sha256": _sha256(path),
                **({"records": records} if records is not None else {}),
            }

    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r7-to-r8-adjudicator-only-v1",
        "created_at": created_at or _utc_now(),
        "status": "IMPORTED_A_B_AWAITING_RECONCILIATION",
        "identity": {
            "base_review_directory": _portable_path(
                base_review_directory, PROJECT_ROOT
            ),
            "base_manifest_sha256": _sha256(
                base_review_directory / "machine-review-manifest.json"
            ),
            "base_migration_sha256": _sha256(
                base_review_directory / "migration-r7.json"
            ),
            "base_reconciliation_summary_sha256": _sha256(
                base_review_directory
                / "reconciliation"
                / "reconciliation-summary.json"
            ),
            "base_reconciliation_sha256": _sha256(
                base_review_directory / "reconciliation" / "reconciliation.jsonl"
            ),
            "base_blind_input_sha256": _sha256(
                base_review_directory / "adjudicator-c" / "blind-input.jsonl"
            ),
            "r8_manifest_sha256": _sha256(
                review_directory / "machine-review-manifest.json"
            ),
            "policy": "REUSE_R7_A_B_AND_RECONCILE_RETRY_ONLY_OPENAI_ADJUDICATOR_C",
            "adjudicator_provider": OPENAI_PROVIDER_ID,
            "adjudicator_model": "gpt-5.6-luna",
        },
        "roles": roles,
        "outputs": outputs,
    }
    _write_json(migration_path, migration)
    reconciliation = reconcile_reviews(
        review_directory=review_directory,
        reviewer_a_run=review_directory / "reviewer-a" / "run",
        reviewer_b_run=review_directory / "reviewer-b" / "run",
        created_at=created_at,
    )
    if (
        reconciliation.get("counts") != base_summary.get("counts")
        or _sha256(review_directory / "reconciliation" / "reconciliation.jsonl")
        != migration["identity"]["base_reconciliation_sha256"]
        or _sha256(review_directory / "adjudicator-c" / "blind-input.jsonl")
        != migration["identity"]["base_blind_input_sha256"]
    ):
        raise MachineReviewError("r8 reconstructed reconciliation differs from r7")
    migration["status"] = "COMPLETE"
    migration["completed_at"] = created_at or _utc_now()
    migration["reconciliation"] = {
        "summary_sha256": _sha256(
            review_directory / "reconciliation" / "reconciliation-summary.json"
        ),
        "reconciliation_sha256": _sha256(
            review_directory / "reconciliation" / "reconciliation.jsonl"
        ),
        "blind_input_sha256": _sha256(
            review_directory / "adjudicator-c" / "blind-input.jsonl"
        ),
        "routed_records": base_summary["counts"]["routed_to_adjudicator"],
    }
    _write_json(migration_path, migration)
    return _load_r8_migration(review_directory)


def _load_r8_composite_run(
    *, run_directory: Path, review_directory: Path, role: str
) -> dict[str, Any]:
    migration = _load_r8_migration(review_directory)
    role_proof = migration["roles"][f"reviewer_{role}"]
    imported = role_proof["imported"]
    run_directory = run_directory.resolve()
    if _portable_path(run_directory, review_directory) != imported["run_directory"]:
        raise MachineReviewError(f"reviewer {role} r8 run path differs")
    checks = {
        "verifier-run.json": "verifier_run_sha256",
        "run-identity.json": "run_identity_sha256",
        "gemini-provider-configuration.json": "provider_configuration_sha256",
        "blind-verifier-input.jsonl": "input_sha256",
        "verifier-predictions.jsonl": "predictions_sha256",
    }
    for name, key in checks.items():
        if _sha256(run_directory / name) != imported[key]:
            raise MachineReviewError(f"reviewer {role} r8 import changed: {name}")
    if _artifact_inventory(run_directory) != imported["artifacts"]:
        raise MachineReviewError(f"reviewer {role} r8 imported inventory changed")
    identity = _read_json(run_directory / "run-identity.json", "r8 composite identity")
    if (
        identity.get("protocol") != "reviewer-composite-adjudicator-migration-v3"
        or identity.get("role") != role
        or identity.get("source_predictions_sha256")
        != role_proof["source"]["predictions_sha256"]
    ):
        raise MachineReviewError(f"reviewer {role} r8 identity differs")
    input_rows = _read_jsonl(
        run_directory / "blind-verifier-input.jsonl", f"reviewer {role} r8 input"
    )
    rows = _read_jsonl(
        run_directory / "verifier-predictions.jsonl", f"reviewer {role} r8 predictions"
    )
    full_ids = _ordered_ids(input_rows, f"reviewer {role} r8 input")
    if _ordered_ids(rows, f"reviewer {role} r8 predictions") != full_ids:
        raise MachineReviewError(f"reviewer {role} r8 prediction coverage differs")
    findings, _ = _frozen_rows(review_directory)
    findings_by_id = {str(row["finding_id"]): row for row in findings}
    config = _frozen_config(
        review_directory, "REVIEWER_A" if role == "a" else "REVIEWER_B"
    )
    snapshot_root = _frozen_snapshot_root(_load_machine_manifest(review_directory))
    allowed_provider_versions = set(role_proof["source"].get("provider_versions") or [])
    row_map: dict[str, dict[str, Any]] = {}
    prediction_sha256: dict[str, str] = {}
    evidence_errors: dict[str, str] = {}
    for finding_id, row in zip(full_ids, rows):
        agent = row.get("agent")
        if (
            row.get("schema_version") != 1
            or row.get("finding_id") != finding_id
            or row.get("verdict") not in VERDICTS
            or row.get("confidence") not in CONFIDENCES
            or not isinstance(agent, dict)
            or agent.get("provider") != config["provider"]
            or agent.get("model") != config["model"]
            or agent.get("provider_version") not in allowed_provider_versions
            or row.get("evaluation_eligible") is not False
            or row.get("exclusion_reason") != "DEVELOPMENT_OR_PARTIAL_INPUT"
        ):
            raise MachineReviewError(f"reviewer {role} imported prediction is invalid")
        error = _evidence_error(row, findings_by_id[finding_id], snapshot_root)
        if error:
            evidence_errors[finding_id] = error
        row_map[finding_id] = row
        prediction_sha256[finding_id] = _value_sha256(row)
    source = role_proof["source"]
    proof = {
        **imported,
        "failed_records": 0,
        "requested_model": config["model"],
        "model_version": source["model_version"],
        "model_versions": source.get("model_versions", [source["model_version"]]),
        "provider": "IMPORTED_R7_COMPOSITE",
        "provider_version": source["provider_version"],
        "provider_versions": source.get("provider_versions", []),
        "sdk_version": source["sdk_version"],
        "usage": source.get("usage", {}),
        "frozen_components": source["frozen_components"],
        "migration_sources": {"r7_composite": source},
    }
    return {
        "run_directory": run_directory,
        "manifest": _read_json(run_directory / "verifier-run.json", "r8 composite run"),
        "rows": row_map,
        "prediction_sha256": prediction_sha256,
        "evidence_errors": evidence_errors,
        "model_version": proof["model_version"],
        "proof": proof,
        "full_ids": full_ids,
    }


def _load_r9_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r9.json", "r9 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r8-to-r9-adjudicator-supplement-v1"
        or migration.get("status") not in {"AWAITING_RETRY_RUN", "COMPLETE"}
        or not isinstance(identity, dict)
        or identity.get("r9_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
    ):
        raise MachineReviewError("r9 adjudicator supplement identity is invalid")
    _check_stage_outputs(review_directory, migration)
    source = review_directory / str(migration.get("source_run") or "")
    retry_input = review_directory / str(migration.get("retry_input") or "")
    _safe_relative_to(source.resolve(), review_directory, "r9 frozen r8 C source")
    if (
        not source.is_dir()
        or _artifact_inventory(source) != migration.get("source_artifacts")
        or not retry_input.is_file()
        or _sha256(retry_input) != migration.get("retry_input_sha256")
    ):
        raise MachineReviewError("r9 frozen source/retry proof differs")
    retry_ids = _ordered_ids(_read_jsonl(retry_input, "r9 C retry input"), "r9 C retry input")
    if (
        retry_ids != migration.get("retry_finding_ids")
        or _value_sha256(retry_ids) != migration.get("retry_finding_ids_sha256")
        or len(retry_ids) != migration.get("retry_records")
    ):
        raise MachineReviewError("r9 C retry identity differs")
    return migration


def prepare_r9_adjudicator_supplement(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Freeze r8 C successes and create an exact retry queue for its failures."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    if base_review_directory == review_directory:
        raise MachineReviewError("r9 base and destination must differ")
    manifest = _load_machine_manifest(review_directory)
    base_manifest = _load_frozen_base_manifest(base_review_directory)
    migration_r8 = _load_r8_migration(review_directory)
    base_r8 = _load_r8_migration(base_review_directory)
    if migration_r8.get("status") != "COMPLETE" or base_r8.get("status") != "COMPLETE":
        raise MachineReviewError("r9 requires complete r8 A/B imports and reconciliation")
    comparable = {
        "sample_manifest_sha256",
        "sample_findings_sha256",
        "sampling_index_sha256",
        "evidence_packets_sha256",
        "records",
        "finding_ids_sha256",
        "snapshot_root",
        "source_scanner",
        "evaluated_agent_model",
        "policy",
    }
    if any(
        manifest["identity"].get(key) != base_manifest["identity"].get(key)
        for key in comparable
    ):
        raise MachineReviewError("r9 corpus/policy identity differs from r8")
    if _frozen_config(review_directory, "ADJUDICATOR_C") != _frozen_config(
        base_review_directory, "ADJUDICATOR_C"
    ):
        raise MachineReviewError("r9 adjudicator C config differs from r8")
    migration_path = review_directory / "migration-r9.json"
    if migration_path.is_file():
        return _load_r9_migration(review_directory)

    full_input = review_directory / "adjudicator-c" / "blind-input.jsonl"
    base_input = base_review_directory / "adjudicator-c" / "blind-input.jsonl"
    if _sha256(full_input) != _sha256(base_input):
        raise MachineReviewError("r9 adjudicator blind input differs from r8")
    full_ids = _ordered_ids(_read_jsonl(full_input, "r9 C full input"), "r9 C full input")
    base_run = base_review_directory / "adjudicator-c" / "blind"
    success_ids = _partial_run_success_ids(base_run, full_ids)
    retry_ids = [finding_id for finding_id in full_ids if finding_id not in set(success_ids)]
    if not success_ids or not retry_ids:
        raise MachineReviewError("r9 requires both reusable successes and retry failures")

    source = review_directory / "adjudicator-c" / "sources" / "r8-partial"
    if source.exists():
        raise MachineReviewError("r9 frozen C source directory already exists")
    source.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(base_run, source)
    retry_rows_by_id = {
        str(row["finding_id"]): row
        for row in _read_jsonl(full_input, "r9 C full input")
    }
    retry_input = review_directory / "adjudicator-c" / "retry-input.jsonl"
    _write_jsonl(retry_input, [retry_rows_by_id[finding_id] for finding_id in retry_ids])

    findings, _ = _frozen_rows(review_directory)
    loaded = _load_run(
        run_directory=source,
        review_directory=review_directory,
        expected_input=full_input,
        expected_ids=full_ids,
        findings_by_id={str(row["finding_id"]): row for row in findings},
        expected_snapshot_root=_frozen_snapshot_root(manifest),
        config=_frozen_config(review_directory, "ADJUDICATOR_C"),
        label="r9 frozen r8 adjudicator C partial",
        success_ids=success_ids,
    )
    outputs = {
        retry_input.relative_to(review_directory).as_posix(): {
            "path": retry_input.relative_to(review_directory).as_posix(),
            "sha256": _sha256(retry_input),
            "records": len(retry_ids),
        }
    }
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r8-to-r9-adjudicator-supplement-v1",
        "created_at": created_at or _utc_now(),
        "status": "AWAITING_RETRY_RUN",
        "identity": {
            "base_review_directory": _portable_path(base_review_directory, PROJECT_ROOT),
            "base_manifest_sha256": _sha256(base_review_directory / "machine-review-manifest.json"),
            "base_migration_r8_sha256": _sha256(base_review_directory / "migration-r8.json"),
            "base_blind_input_sha256": _sha256(base_input),
            "base_partial_run_sha256": loaded["proof"]["verifier_run_sha256"],
            "r9_manifest_sha256": _sha256(review_directory / "machine-review-manifest.json"),
            "policy": "REUSE_CHECKSUM_VERIFIED_R8_C_SUCCESS_RETRY_ONLY_11_FAILED",
        },
        "source_run": source.relative_to(review_directory).as_posix(),
        "source_artifacts": _artifact_inventory(source),
        "source_proof": loaded["proof"],
        "reused_success": len(success_ids),
        "reused_finding_ids_sha256": _value_sha256(success_ids),
        "retry_input": retry_input.relative_to(review_directory).as_posix(),
        "retry_input_sha256": _sha256(retry_input),
        "retry_records": len(retry_ids),
        "retry_finding_ids": retry_ids,
        "retry_finding_ids_sha256": _value_sha256(retry_ids),
        "outputs": outputs,
    }
    _write_json(migration_path, migration)
    return _load_r9_migration(review_directory)


def _r9_adjudicator_sources(review_directory: Path) -> dict[str, Any]:
    manifest = _load_machine_manifest(review_directory)
    migration = _load_r9_migration(review_directory)
    full_input = review_directory / "adjudicator-c" / "blind-input.jsonl"
    full_ids = _ordered_ids(_read_jsonl(full_input, "r9 C full input"), "r9 C full input")
    retry_ids = list(migration["retry_finding_ids"])
    retry_set = set(retry_ids)
    success_ids = [finding_id for finding_id in full_ids if finding_id not in retry_set]
    if (
        len(success_ids) != migration["reused_success"]
        or _value_sha256(success_ids) != migration["reused_finding_ids_sha256"]
    ):
        raise MachineReviewError("r9 reused C success identity differs")
    findings, _ = _frozen_rows(review_directory)
    findings_by_id = {str(row["finding_id"]): row for row in findings}
    common = {
        "review_directory": review_directory,
        "findings_by_id": findings_by_id,
        "expected_snapshot_root": _frozen_snapshot_root(manifest),
        "config": _frozen_config(review_directory, "ADJUDICATOR_C"),
    }
    base = _load_run(
        run_directory=review_directory / migration["source_run"],
        expected_input=full_input,
        expected_ids=full_ids,
        label="r9 frozen r8 adjudicator C partial",
        success_ids=success_ids,
        **common,
    )
    retry = _load_run(
        run_directory=review_directory / "adjudicator-c" / "retry-run",
        expected_input=review_directory / migration["retry_input"],
        expected_ids=retry_ids,
        label="r9 adjudicator C retry",
        **common,
    )
    rows = {**base["rows"], **retry["rows"]}
    prediction_sha256 = {
        **base["prediction_sha256"],
        **retry["prediction_sha256"],
    }
    evidence_errors = {**base["evidence_errors"], **retry["evidence_errors"]}
    if set(rows) != set(full_ids) or set(prediction_sha256) != set(full_ids):
        raise MachineReviewError("r9 adjudicator composite does not cover routed IDs")
    usage: defaultdict[str, int] = defaultdict(int)
    for source in (base, retry):
        for name, value in source["proof"].get("usage", {}).items():
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                usage[str(name)] += value
    provider_versions = [
        base["proof"]["provider_version"],
        retry["proof"]["provider_version"],
    ]
    model_versions = sorted({base["model_version"], retry["model_version"]})
    identity = {
        "schema_version": 1,
        "protocol": "adjudicator-blind-composite-supplement-v1",
        "records": len(full_ids),
        "finding_ids_sha256": _value_sha256(full_ids),
        "reused_finding_ids_sha256": _value_sha256(success_ids),
        "retry_finding_ids_sha256": _value_sha256(retry_ids),
        "base_verifier_run_sha256": base["proof"]["verifier_run_sha256"],
        "retry_verifier_run_sha256": retry["proof"]["verifier_run_sha256"],
        "base_predictions_sha256": base["proof"]["predictions_sha256"],
        "retry_predictions_sha256": retry["proof"]["predictions_sha256"],
        "provider_versions": provider_versions,
        "model_versions": model_versions,
    }
    return {
        "base": base,
        "retry": retry,
        "full_ids": full_ids,
        "rows": rows,
        "prediction_sha256": prediction_sha256,
        "evidence_errors": evidence_errors,
        "usage": dict(sorted(usage.items())),
        "provider_version": _value_sha256(provider_versions),
        "model_version": "+".join(model_versions),
        "frozen_components": base["proof"]["frozen_components"],
        "identity": identity,
    }


def seal_r9_adjudicator_supplement(
    *, review_directory: Path, created_at: str | None = None
) -> dict[str, Any]:
    review_directory = review_directory.resolve()
    data = _r9_adjudicator_sources(review_directory)
    migration = _load_r9_migration(review_directory)
    if data["base"]["proof"]["frozen_components"] != data["retry"]["proof"]["frozen_components"]:
        raise MachineReviewError("r9 C base/retry source-review components differ")
    run_directory = review_directory / "adjudicator-c" / "blind"
    identity_path = run_directory / "run-identity.json"
    if identity_path.is_file():
        if _read_json(identity_path, "r9 C composite identity") != data["identity"]:
            raise MachineReviewError("r9 C composite identity differs")
    elif run_directory.exists() and any(run_directory.iterdir()):
        raise MachineReviewError("r9 C composite directory is partial")
    else:
        run_directory.mkdir(parents=True, exist_ok=True)
        _write_json(identity_path, data["identity"])
        shutil.copyfile(
            review_directory / "adjudicator-c" / "blind-input.jsonl",
            run_directory / "blind-verifier-input.jsonl",
        )
        ordered = [data["rows"][finding_id] for finding_id in data["full_ids"]]
        _write_jsonl(run_directory / "verifier-predictions.jsonl", ordered)
        config = _frozen_config(review_directory, "ADJUDICATOR_C")
        provider_configuration = {
            "schema_version": 1,
            "provider": "MIGRATED_OPENAI_ADJUDICATOR_COMPOSITE",
            "provider_version": data["provider_version"],
            "sdk_version": config["provider_version"],
            "configuration": {
                "model": config["model"],
                "migration_protocol": data["identity"]["protocol"],
                "provider_versions": data["identity"]["provider_versions"],
            },
        }
        provider_configuration["configuration_sha256"] = _value_sha256(
            provider_configuration["configuration"]
        )
        _write_json(
            run_directory / "openai-provider-configuration.json",
            provider_configuration,
        )
        run = {
            "schema_version": 1,
            "run_id": run_directory.name,
            "created_at": created_at or _utc_now(),
            "status": "COMPLETE",
            "complete": True,
            "migration_protocol": data["identity"]["protocol"],
            "case_counts": {
                "total": len(data["full_ids"]),
                "success": len(data["full_ids"]),
                "failed": 0,
            },
            "input": {
                "frozen_copy": "blind-verifier-input.jsonl",
                "sha256": _sha256(run_directory / "blind-verifier-input.jsonl"),
                "records": len(data["full_ids"]),
            },
            "predictions": {
                "path": "verifier-predictions.jsonl",
                "sha256": _sha256(run_directory / "verifier-predictions.jsonl"),
                "records": len(data["full_ids"]),
            },
            "provider": {
                "id": "MIGRATED_OPENAI_ADJUDICATOR_COMPOSITE",
                "version": data["provider_version"],
                "model": config["model"],
                "model_version": data["model_version"],
                "usage": data["usage"],
            },
            "migration": data["identity"],
        }
        _write_json(run_directory / "verifier-run.json", run)
    loaded = _load_r9_adjudicator_composite(
        run_directory=run_directory, review_directory=review_directory
    )
    complete = {
        **migration,
        "status": "COMPLETE",
        "completed_at": created_at or _utc_now(),
        "composite_run": loaded["proof"],
    }
    _write_json(review_directory / "migration-r9.json", complete)
    return complete


def _load_r9_adjudicator_composite(
    *, run_directory: Path, review_directory: Path
) -> dict[str, Any]:
    run_directory = run_directory.resolve()
    data = _r9_adjudicator_sources(review_directory)
    identity_path = run_directory / "run-identity.json"
    identity = _read_json(identity_path, "r9 C composite identity")
    run_path = run_directory / "verifier-run.json"
    input_path = run_directory / "blind-verifier-input.jsonl"
    predictions_path = run_directory / "verifier-predictions.jsonl"
    provider_path = run_directory / "openai-provider-configuration.json"
    run = _read_json(run_path, "r9 C composite run")
    rows = _read_jsonl(predictions_path, "r9 C composite predictions")
    expected_rows = [data["rows"][finding_id] for finding_id in data["full_ids"]]
    provider = _read_json(provider_path, "r9 C composite provider")
    if (
        identity != data["identity"]
        or run.get("status") != "COMPLETE"
        or run.get("complete") is not True
        or run.get("migration") != identity
        or run.get("case_counts")
        != {"total": len(data["full_ids"]), "success": len(data["full_ids"]), "failed": 0}
        or _sha256(input_path) != run.get("input", {}).get("sha256")
        or _sha256(predictions_path) != run.get("predictions", {}).get("sha256")
        or rows != expected_rows
        or provider.get("provider") != "MIGRATED_OPENAI_ADJUDICATOR_COMPOSITE"
        or provider.get("provider_version") != data["provider_version"]
        or provider.get("configuration_sha256")
        != _value_sha256(provider.get("configuration"))
    ):
        raise MachineReviewError("r9 C composite proof differs")
    proof = {
        "run_directory": _portable_path(run_directory, review_directory),
        "verifier_run_sha256": _sha256(run_path),
        "run_identity_sha256": _sha256(identity_path),
        "provider_configuration_sha256": _sha256(provider_path),
        "input_sha256": _sha256(input_path),
        "predictions_sha256": _sha256(predictions_path),
        "records": len(rows),
        "failed_records": 0,
        "requested_model": _frozen_config(review_directory, "ADJUDICATOR_C")["model"],
        "model_version": data["model_version"],
        "model_versions": identity["model_versions"],
        "provider": "MIGRATED_OPENAI_ADJUDICATOR_COMPOSITE",
        "provider_version": data["provider_version"],
        "provider_versions": identity["provider_versions"],
        "sdk_version": _frozen_config(review_directory, "ADJUDICATOR_C")["provider_version"],
        "usage": data["usage"],
        "artifacts": _artifact_inventory(run_directory),
        "frozen_components": data["frozen_components"],
        "migration_sources": {
            "r8_partial": data["base"]["proof"],
            "r9_retry": data["retry"]["proof"],
        },
    }
    return {
        "run_directory": run_directory,
        "manifest": run,
        "rows": data["rows"],
        "prediction_sha256": data["prediction_sha256"],
        "evidence_errors": data["evidence_errors"],
        "model_version": data["model_version"],
        "proof": proof,
        "full_ids": data["full_ids"],
    }


def _r10_source_composite(
    *, base_review_directory: Path, review_directory: Path
) -> dict[str, Any]:
    base_manifest = _load_frozen_base_manifest(base_review_directory)
    migration = _read_json(base_review_directory / "migration-r9.json", "r9 source migration")
    proof = migration.get("composite_run")
    source = base_review_directory / "adjudicator-c" / "blind"
    if (
        migration.get("migration_id")
        != "opengrep-machine-review-r8-to-r9-adjudicator-supplement-v1"
        or migration.get("status") != "COMPLETE"
        or migration.get("identity", {}).get("r9_manifest_sha256")
        != _sha256(base_review_directory / "machine-review-manifest.json")
        or not isinstance(proof, dict)
        or proof.get("records") != 112
        or proof.get("failed_records") != 0
        or _artifact_inventory(source) != proof.get("artifacts")
    ):
        raise MachineReviewError("r10 requires the complete frozen r9 C composite")
    checks = {
        "verifier-run.json": "verifier_run_sha256",
        "run-identity.json": "run_identity_sha256",
        "openai-provider-configuration.json": "provider_configuration_sha256",
        "blind-verifier-input.jsonl": "input_sha256",
        "verifier-predictions.jsonl": "predictions_sha256",
    }
    for name, key in checks.items():
        path = source / name
        if not path.is_file() or _sha256(path) != proof.get(key):
            raise MachineReviewError(f"r9 C composite changed before r10 import: {name}")
    current_input = review_directory / "adjudicator-c" / "blind-input.jsonl"
    if _sha256(source / "blind-verifier-input.jsonl") != _sha256(current_input):
        raise MachineReviewError("r10 blind input differs from r9")
    rows = _read_jsonl(source / "verifier-predictions.jsonl", "r9 C predictions")
    full_ids = _ordered_ids(
        _read_jsonl(current_input, "r10 C blind input"), "r10 C blind input"
    )
    if _ordered_ids(rows, "r9 C predictions") != full_ids:
        raise MachineReviewError("r9 C prediction coverage differs from r10")
    config = _frozen_config(review_directory, "ADJUDICATOR_C")
    if config != _frozen_config(base_review_directory, "ADJUDICATOR_C"):
        raise MachineReviewError("r10 adjudicator config differs from r9")
    allowed_versions = set(proof.get("provider_versions") or [])
    findings, _ = _frozen_rows(review_directory)
    findings_by_id = {str(row["finding_id"]): row for row in findings}
    snapshot_root = _frozen_snapshot_root(_load_machine_manifest(review_directory))
    row_map: dict[str, dict[str, Any]] = {}
    prediction_sha256: dict[str, str] = {}
    evidence_errors: dict[str, str] = {}
    for finding_id, row in zip(full_ids, rows):
        agent = row.get("agent")
        if (
            row.get("schema_version") != 1
            or row.get("finding_id") != finding_id
            or row.get("verdict") not in VERDICTS
            or row.get("confidence") not in CONFIDENCES
            or not isinstance(agent, dict)
            or agent.get("provider") != config["provider"]
            or agent.get("model") != config["model"]
            or agent.get("provider_version") not in allowed_versions
            or row.get("evaluation_eligible") is not False
            or row.get("exclusion_reason") != "DEVELOPMENT_OR_PARTIAL_INPUT"
        ):
            raise MachineReviewError(f"r9 C imported prediction is invalid: {finding_id}")
        error = _evidence_error(row, findings_by_id[finding_id], snapshot_root)
        if error:
            evidence_errors[finding_id] = error
        row_map[finding_id] = row
        prediction_sha256[finding_id] = _value_sha256(row)
    return {
        "base_manifest": base_manifest,
        "source": source,
        "source_migration": migration,
        "source_proof": proof,
        "full_ids": full_ids,
        "rows": row_map,
        "prediction_sha256": prediction_sha256,
        "evidence_errors": evidence_errors,
    }


def _load_r10_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r10.json", "r10 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r9-to-r10-final-only-v1"
        or migration.get("status") not in {"AWAITING_PREPARATION", "COMPLETE"}
        or not isinstance(identity, dict)
        or identity.get("r10_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
    ):
        raise MachineReviewError("r10 final-only migration identity is invalid")
    _check_stage_outputs(review_directory, migration)
    base_value = identity.get("base_review_directory")
    if not isinstance(base_value, str) or not base_value:
        raise MachineReviewError("r10 source directory proof is invalid")
    base = Path(base_value)
    if not base.is_absolute():
        base = PROJECT_ROOT / base
    base = base.resolve(strict=True)
    if (
        _sha256(base / "machine-review-manifest.json")
        != identity.get("base_manifest_sha256")
        or _sha256(base / "migration-r9.json")
        != identity.get("base_migration_r9_sha256")
    ):
        raise MachineReviewError("r10 frozen r9 source proof differs")
    return migration


def prepare_r10_final_migration(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Import r9 blind C 112/112 and regenerate only final-adjudication input."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    manifest = _load_machine_manifest(review_directory)
    if _load_r8_migration(review_directory).get("status") != "COMPLETE":
        raise MachineReviewError("r10 requires complete imported A/B reconciliation")
    base_manifest = _load_frozen_base_manifest(base_review_directory)
    comparable = {
        "sample_manifest_sha256",
        "sample_findings_sha256",
        "sampling_index_sha256",
        "evidence_packets_sha256",
        "records",
        "finding_ids_sha256",
        "snapshot_root",
        "source_scanner",
        "reviewer_configs",
        "evaluated_agent_model",
        "policy",
    }
    if any(
        manifest["identity"].get(key) != base_manifest["identity"].get(key)
        for key in comparable
    ):
        raise MachineReviewError("r10 corpus/config/policy identity differs from r9")
    migration_path = review_directory / "migration-r10.json"
    if migration_path.is_file():
        return _load_r10_migration(review_directory)
    source = _r10_source_composite(
        base_review_directory=base_review_directory,
        review_directory=review_directory,
    )
    destination = review_directory / "adjudicator-c" / "blind"
    if destination.exists() and any(destination.iterdir()):
        raise MachineReviewError("r10 adjudicator blind import directory is not empty")
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        source["source"] / "blind-verifier-input.jsonl",
        destination / "blind-verifier-input.jsonl",
    )
    ordered = [source["rows"][finding_id] for finding_id in source["full_ids"]]
    _write_jsonl(destination / "verifier-predictions.jsonl", ordered)
    source_proof = source["source_proof"]
    identity = {
        "schema_version": 1,
        "protocol": "adjudicator-blind-final-only-migration-v2",
        "records": len(source["full_ids"]),
        "finding_ids_sha256": _value_sha256(source["full_ids"]),
        "source_review_directory": _portable_path(base_review_directory, PROJECT_ROOT),
        "source_manifest_sha256": _sha256(
            base_review_directory / "machine-review-manifest.json"
        ),
        "source_migration_sha256": _sha256(base_review_directory / "migration-r9.json"),
        "source_verifier_run_sha256": source_proof["verifier_run_sha256"],
        "source_predictions_sha256": source_proof["predictions_sha256"],
    }
    _write_json(destination / "run-identity.json", identity)
    config = _frozen_config(review_directory, "ADJUDICATOR_C")
    provider_configuration = {
        "schema_version": 1,
        "provider": "IMPORTED_R9_ADJUDICATOR_COMPOSITE",
        "provider_version": source_proof["provider_version"],
        "sdk_version": source_proof["sdk_version"],
        "configuration": {
            "model": config["model"],
            "migration_protocol": identity["protocol"],
            "source_predictions_sha256": source_proof["predictions_sha256"],
        },
    }
    provider_configuration["configuration_sha256"] = _value_sha256(
        provider_configuration["configuration"]
    )
    _write_json(
        destination / "openai-provider-configuration.json", provider_configuration
    )
    run = {
        "schema_version": 1,
        "run_id": destination.name,
        "created_at": created_at or _utc_now(),
        "status": "COMPLETE",
        "complete": True,
        "migration_protocol": identity["protocol"],
        "case_counts": {"total": len(ordered), "success": len(ordered), "failed": 0},
        "input": {
            "frozen_copy": "blind-verifier-input.jsonl",
            "sha256": _sha256(destination / "blind-verifier-input.jsonl"),
            "records": len(ordered),
        },
        "predictions": {
            "path": "verifier-predictions.jsonl",
            "sha256": _sha256(destination / "verifier-predictions.jsonl"),
            "records": len(ordered),
        },
        "provider": {
            "id": "IMPORTED_R9_ADJUDICATOR_COMPOSITE",
            "version": source_proof["provider_version"],
            "model": config["model"],
            "model_version": source_proof["model_version"],
            "usage": source_proof.get("usage", {}),
        },
        "migration": identity,
    }
    _write_json(destination / "verifier-run.json", run)
    outputs: dict[str, Any] = {}
    for name, records in (
        ("verifier-run.json", None),
        ("run-identity.json", None),
        ("openai-provider-configuration.json", None),
        ("blind-verifier-input.jsonl", len(ordered)),
        ("verifier-predictions.jsonl", len(ordered)),
    ):
        path = destination / name
        relative = path.relative_to(review_directory).as_posix()
        outputs[relative] = {
            "path": relative,
            "sha256": _sha256(path),
            **({"records": records} if records is not None else {}),
        }
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r9-to-r10-final-only-v1",
        "created_at": created_at or _utc_now(),
        "status": "AWAITING_PREPARATION",
        "identity": {
            "base_review_directory": _portable_path(base_review_directory, PROJECT_ROOT),
            "base_manifest_sha256": _sha256(
                base_review_directory / "machine-review-manifest.json"
            ),
            "base_migration_r9_sha256": _sha256(base_review_directory / "migration-r9.json"),
            "r10_manifest_sha256": _sha256(review_directory / "machine-review-manifest.json"),
            "policy": "REUSE_R9_BLIND_112_RETRY_ONLY_FINAL_WITH_OPENAI_SCHEMA_PROJECTION",
        },
        "source_proof": source_proof,
        "imported_run": _r10_import_proof(destination, review_directory, source),
        "outputs": outputs,
    }
    _write_json(migration_path, migration)
    preparation = prepare_adjudication(
        review_directory=review_directory,
        blind_run=destination,
        created_at=created_at,
    )
    migration["status"] = "COMPLETE"
    migration["completed_at"] = created_at or _utc_now()
    migration["adjudication_preparation_sha256"] = _sha256(
        review_directory / "adjudicator-c" / "adjudication-preparation.json"
    )
    migration["adjudication_input_sha256"] = preparation["outputs"][
        "adjudication_input"
    ]["sha256"]
    _write_json(migration_path, migration)
    return _load_r10_migration(review_directory)


def _load_r11_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r11.json", "r11 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r10-to-r11-evidence-normalization-v1"
        or migration.get("status") != "COMPLETE"
        or not isinstance(identity, dict)
        or identity.get("r11_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
    ):
        raise MachineReviewError("r11 final recovery migration identity is invalid")
    _check_stage_outputs(review_directory, migration)
    for proof in migration.get("recovered_cases") or []:
        if not isinstance(proof, dict):
            raise MachineReviewError("r11 recovered-case proof is invalid")
        relative = proof.get("case_directory")
        if not isinstance(relative, str) or Path(relative).is_absolute():
            raise MachineReviewError("r11 recovered-case path is invalid")
        case_directory = (review_directory / relative).resolve()
        _safe_relative_to(case_directory, review_directory, "r11 recovered case")
        for name, key in (
            ("status.json", "status_sha256"),
            ("decision.json", "decision_sha256"),
            ("step-01-response.json", "response_sha256"),
            ("step-01-provider-metadata.json", "provider_metadata_sha256"),
            ("step-01-raw-response.json", "raw_response_sha256"),
        ):
            path = case_directory / name
            if not path.is_file() or _sha256(path) != proof.get(key):
                raise MachineReviewError(f"r11 recovered case changed: {name}")
    return migration


def prepare_r11_final_recovery(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Recover paid r10 provider responses under the r11 evidence policy."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    manifest = _load_machine_manifest(review_directory)
    if _load_r10_migration(review_directory).get("status") != "COMPLETE":
        raise MachineReviewError("r11 requires complete r10 blind/input migration")
    base_manifest = _load_frozen_base_manifest(base_review_directory)
    base_migration = _load_r10_migration(base_review_directory)
    comparable = {
        "sample_manifest_sha256",
        "sample_findings_sha256",
        "sampling_index_sha256",
        "evidence_packets_sha256",
        "records",
        "finding_ids_sha256",
        "snapshot_root",
        "source_scanner",
        "reviewer_configs",
        "evaluated_agent_model",
        "policy",
    }
    if any(
        manifest["identity"].get(key) != base_manifest["identity"].get(key)
        for key in comparable
    ):
        raise MachineReviewError("r11 corpus/config/policy identity differs from r10")
    migration_path = review_directory / "migration-r11.json"
    if migration_path.is_file():
        return _load_r11_migration(review_directory)

    _, destination_contexts = _load_adjudication_preparation(review_directory)
    _, source_contexts = _load_adjudication_preparation(base_review_directory)
    if destination_contexts != source_contexts:
        raise MachineReviewError("r11 adjudication context differs from r10")
    contexts_by_id = {
        str(context["finding_id"]): context for context in destination_contexts
    }
    source_final = base_review_directory / "adjudicator-c" / "final"
    destination_final = review_directory / "adjudicator-c" / "final"
    if destination_final.exists() and any(destination_final.iterdir()):
        raise MachineReviewError("r11 final recovery destination is not empty")
    source_identity_path = source_final / "run-identity.json"
    source_sidecar_path = source_final / "openai-provider-configuration.json"
    source_identity = _read_json(source_identity_path, "r10 final run identity")
    source_sidecar = _read_json(source_sidecar_path, "r10 final provider configuration")
    destination_input = review_directory / "adjudicator-c" / "adjudication-input.jsonl"
    provider_identity = source_identity.get("provider")
    config = _frozen_config(review_directory, "ADJUDICATOR_C")
    current_adapter_sha256 = _sha256(IMPLEMENTATION_SOURCES["openai-verifier-agent.py"])
    if (
        source_identity.get("schema_version") != 1
        or source_identity.get("protocol") != "machine-adjudication-final-v1"
        or source_identity.get("input_sha256") != _sha256(destination_input)
        or source_identity.get("records") != len(destination_contexts)
        or source_identity.get("prompt_sha256")
        != _sha256(IMPLEMENTATION_SOURCES["machine-adjudicator-prompt-v1.md"])
        or source_identity.get("response_schema_sha256")
        != _sha256(IMPLEMENTATION_SOURCES["machine-adjudicator-response.schema.json"])
        or source_identity.get("blind_first_model_version") != config["model"]
        or not isinstance(provider_identity, dict)
        or provider_identity.get("id") != OPENAI_PROVIDER_ID
        or provider_identity.get("sdk_version") != config["provider_version"]
        or provider_identity.get("model") != config["model"]
        or f"adapter.sha256.{current_adapter_sha256}" not in str(provider_identity.get("version"))
        or source_sidecar.get("provider_version") != provider_identity.get("version")
        or source_sidecar.get("configuration") != provider_identity.get("configuration")
        or source_sidecar.get("configuration_sha256")
        != provider_identity.get("configuration_sha256")
    ):
        raise MachineReviewError("r10 paid final run identity cannot be reused by r11")

    destination_final.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_identity_path, destination_final / "run-identity.json")
    shutil.copyfile(source_sidecar_path, destination_final / source_sidecar_path.name)
    run_identity_sha256 = _sha256(destination_final / "run-identity.json")
    recovered: list[dict[str, Any]] = []
    for source_case in sorted((source_final / "cases").glob("*")):
        if not source_case.is_dir():
            continue
        status_path = source_case / "status.json"
        response_path = source_case / "step-01-response.json"
        metadata_path = source_case / "step-01-provider-metadata.json"
        raw_path = source_case / "step-01-raw-response.json"
        if not all(path.is_file() for path in (status_path, response_path, metadata_path, raw_path)):
            continue
        source_status = _read_json(status_path, "r10 final case status")
        metadata = _read_json(metadata_path, "r10 final provider metadata")
        finding_id = source_status.get("identity", {}).get("finding_id")
        if not isinstance(finding_id, str) or finding_id not in contexts_by_id:
            raise MachineReviewError("r10 final case identity is invalid")
        context = contexts_by_id[finding_id]
        expected_identity = _adjudication_case_identity(
            context, run_identity_sha256=run_identity_sha256
        )
        raw_proof = metadata.get("raw_response")
        if (
            source_status.get("identity") != expected_identity
            or metadata.get("status") != "SUCCESS"
            or metadata.get("provider") != provider_identity.get("id")
            or metadata.get("provider_version") != provider_identity.get("version")
            or metadata.get("sdk_version") != provider_identity.get("sdk_version")
            or metadata.get("configured_model") != provider_identity.get("model")
            or metadata.get("configuration") != source_sidecar.get("configuration")
            or metadata.get("configuration_sha256")
            != source_sidecar.get("configuration_sha256")
            or metadata.get("model_version") != config["model"]
            or not isinstance(metadata.get("response_id"), str)
            or not metadata["response_id"]
            or not isinstance(raw_proof, dict)
            or raw_proof.get("sha256") != _sha256(raw_path)
            or raw_proof.get("bytes") != raw_path.stat().st_size
        ):
            raise MachineReviewError(f"r10 paid response proof is invalid: {finding_id}")
        response = _read_json(response_path, "r10 final provider response")
        decision, normalizations = _normalize_final_response_evidence(response, context)
        destination_case = destination_final / "cases" / source_case.name
        shutil.copytree(source_case, destination_case)
        decision_path = destination_case / "decision.json"
        _write_json(decision_path, decision)
        timestamp = created_at or _utc_now()
        recovered_status = {
            "schema_version": 1,
            "status": "SUCCESS",
            "identity": expected_identity,
            "started_at": source_status.get("started_at") or timestamp,
            "completed_at": timestamp,
            "decision_sha256": _sha256(decision_path),
            "response_sha256": _sha256(destination_case / response_path.name),
            "provider_metadata_sha256": _sha256(destination_case / metadata_path.name),
            "raw_response_sha256": _sha256(destination_case / raw_path.name),
            "response_id": metadata["response_id"],
            "model_version": metadata["model_version"],
            "usage": metadata.get("normalized_usage") or {},
            "evidence_normalizations": normalizations,
            "recovered_from": {
                "release": "r10",
                "source_case": _portable_path(source_case, PROJECT_ROOT),
                "source_response_sha256": _sha256(response_path),
            },
        }
        _write_json(destination_case / "status.json", recovered_status)
        recovered.append(
            {
                "finding_id": finding_id,
                "case_directory": _portable_path(destination_case, review_directory),
                "status_sha256": _sha256(destination_case / "status.json"),
                "decision_sha256": _sha256(decision_path),
                "response_sha256": _sha256(destination_case / response_path.name),
                "provider_metadata_sha256": _sha256(destination_case / metadata_path.name),
                "raw_response_sha256": _sha256(destination_case / raw_path.name),
                "normalizations": normalizations,
            }
        )
    if not recovered:
        raise MachineReviewError("r11 found no paid r10 response to recover")
    outputs = {}
    for path in (
        destination_final / "run-identity.json",
        destination_final / "openai-provider-configuration.json",
    ):
        relative = path.relative_to(review_directory).as_posix()
        outputs[relative] = {"path": relative, "sha256": _sha256(path)}
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r10-to-r11-evidence-normalization-v1",
        "created_at": created_at or _utc_now(),
        "status": "COMPLETE",
        "identity": {
            "base_review_directory": _portable_path(base_review_directory, PROJECT_ROOT),
            "base_manifest_sha256": _sha256(base_review_directory / "machine-review-manifest.json"),
            "base_migration_r10_sha256": _sha256(base_review_directory / "migration-r10.json"),
            "r11_manifest_sha256": _sha256(review_directory / "machine-review-manifest.json"),
            "policy": "REUSE_PAID_R10_RESPONSE_WITH_UNIQUE_FROZEN_EVIDENCE_NORMALIZATION",
        },
        "recovered_cases": recovered,
        "outputs": outputs,
    }
    _write_json(migration_path, migration)
    return _load_r11_migration(review_directory)


def _load_r12_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r12.json", "r12 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r11-to-r12-final-semantics-v1"
        or migration.get("status") != "COMPLETE"
        or not isinstance(identity, dict)
        or identity.get("r12_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
    ):
        raise MachineReviewError("r12 final semantics migration identity is invalid")
    _check_stage_outputs(review_directory, migration)
    recovered = migration.get("recovered_cases")
    if not isinstance(recovered, list) or not recovered:
        raise MachineReviewError("r12 recovered-case proof is missing")
    for proof in recovered:
        if not isinstance(proof, dict):
            raise MachineReviewError("r12 recovered-case proof is invalid")
        relative = proof.get("case_directory")
        if not isinstance(relative, str) or Path(relative).is_absolute():
            raise MachineReviewError("r12 recovered-case path is invalid")
        case_directory = (review_directory / relative).resolve()
        _safe_relative_to(case_directory, review_directory, "r12 recovered case")
        for name, key in (
            ("status.json", "status_sha256"),
            ("decision.json", "decision_sha256"),
            ("step-01-response.json", "response_sha256"),
            ("step-01-provider-metadata.json", "provider_metadata_sha256"),
            ("step-01-raw-response.json", "raw_response_sha256"),
        ):
            path = case_directory / name
            if not path.is_file() or _sha256(path) != proof.get(key):
                raise MachineReviewError(f"r12 recovered case changed: {name}")
    return migration


def prepare_r12_final_semantics_migration(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Reuse every paid r11 final response and normalize forbidden semantics."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    manifest = _load_machine_manifest(review_directory)
    if _load_r10_migration(review_directory).get("status") != "COMPLETE":
        raise MachineReviewError("r12 requires complete r10 blind/input migration")
    base_manifest = _load_frozen_base_manifest(base_review_directory)
    base_migration_path = base_review_directory / "migration-r19.json"
    if base_migration_path.is_file():
        base_migration = _load_r19_migration(base_review_directory)
        base_release = "r19"
    elif (base_review_directory / "migration-r18.json").is_file():
        base_migration_path = base_review_directory / "migration-r18.json"
        base_migration = _load_r18_migration(base_review_directory)
        base_release = "r18"
    elif (base_review_directory / "migration-r17.json").is_file():
        base_migration_path = base_review_directory / "migration-r17.json"
        base_migration = _load_r17_migration(base_review_directory)
        base_release = "r17"
    elif (base_review_directory / "migration-r16.json").is_file():
        base_migration_path = base_review_directory / "migration-r16.json"
        base_migration = _load_r16_migration(base_review_directory)
        base_release = "r16"
    elif (base_review_directory / "migration-r15.json").is_file():
        base_migration_path = base_review_directory / "migration-r15.json"
        base_migration = _load_r15_migration(base_review_directory)
        base_release = "r15"
    elif (base_review_directory / "migration-r14.json").is_file():
        base_migration_path = base_review_directory / "migration-r14.json"
        base_migration = _load_r14_migration(base_review_directory)
        base_release = "r14"
    elif (base_review_directory / "migration-r13.json").is_file():
        base_migration_path = base_review_directory / "migration-r13.json"
        base_migration = _load_r13_migration(base_review_directory)
        base_release = "r13"
    elif (base_review_directory / "migration-r12.json").is_file():
        base_migration_path = base_review_directory / "migration-r12.json"
        base_migration = _load_r12_migration(base_review_directory)
        base_release = "r12"
    else:
        base_migration_path = base_review_directory / "migration-r11.json"
        base_migration = _load_r11_migration(base_review_directory)
        base_release = "r11"
    comparable = {
        "sample_manifest_sha256",
        "sample_findings_sha256",
        "sampling_index_sha256",
        "evidence_packets_sha256",
        "records",
        "finding_ids_sha256",
        "snapshot_root",
        "source_scanner",
        "reviewer_configs",
        "evaluated_agent_model",
        "policy",
    }
    if any(
        manifest["identity"].get(key) != base_manifest["identity"].get(key)
        for key in comparable
    ):
        raise MachineReviewError("r12 corpus/config/policy identity differs from r11")
    migration_path = review_directory / "migration-r12.json"
    if migration_path.is_file():
        return _load_r12_migration(review_directory)

    _, destination_contexts = _load_adjudication_preparation(review_directory)
    _, source_contexts = _load_adjudication_preparation(base_review_directory)
    if destination_contexts != source_contexts:
        raise MachineReviewError("r12 adjudication context differs from r11")
    contexts_by_id = {
        str(context["finding_id"]): context for context in destination_contexts
    }
    source_final = base_review_directory / "adjudicator-c" / "final"
    destination_final = review_directory / "adjudicator-c" / "final"
    if destination_final.exists() and any(destination_final.iterdir()):
        raise MachineReviewError("r12 final migration destination is not empty")
    source_identity_path = source_final / "run-identity.json"
    source_sidecar_path = source_final / "openai-provider-configuration.json"
    source_identity = _read_json(source_identity_path, "r11 final run identity")
    source_sidecar = _read_json(source_sidecar_path, "r11 final provider configuration")
    provider_identity = source_identity.get("provider")
    config = _frozen_config(review_directory, "ADJUDICATOR_C")
    destination_input = review_directory / "adjudicator-c" / "adjudication-input.jsonl"
    current_adapter_sha256 = _sha256(IMPLEMENTATION_SOURCES["openai-verifier-agent.py"])
    if (
        source_identity.get("schema_version") != 1
        or source_identity.get("protocol") != "machine-adjudication-final-v1"
        or source_identity.get("input_sha256") != _sha256(destination_input)
        or source_identity.get("records") != len(destination_contexts)
        or source_identity.get("prompt_sha256")
        != _sha256(IMPLEMENTATION_SOURCES["machine-adjudicator-prompt-v1.md"])
        or source_identity.get("response_schema_sha256")
        != _sha256(IMPLEMENTATION_SOURCES["machine-adjudicator-response.schema.json"])
        or source_identity.get("blind_first_model_version") != config["model"]
        or not isinstance(provider_identity, dict)
        or provider_identity.get("id") != OPENAI_PROVIDER_ID
        or provider_identity.get("sdk_version") != config["provider_version"]
        or provider_identity.get("model") != config["model"]
        or f"adapter.sha256.{current_adapter_sha256}" not in str(provider_identity.get("version"))
        or source_sidecar.get("provider_version") != provider_identity.get("version")
        or source_sidecar.get("configuration") != provider_identity.get("configuration")
        or source_sidecar.get("configuration_sha256")
        != provider_identity.get("configuration_sha256")
    ):
        raise MachineReviewError("r11 paid final run identity cannot be reused by r12")

    destination_final.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_identity_path, destination_final / "run-identity.json")
    shutil.copyfile(source_sidecar_path, destination_final / source_sidecar_path.name)
    run_identity_sha256 = _sha256(destination_final / "run-identity.json")
    recovered: list[dict[str, Any]] = []
    response_ids: set[str] = set()
    for source_case in sorted((source_final / "cases").glob("*")):
        if not source_case.is_dir():
            continue
        status_path = source_case / "status.json"
        response_path = source_case / "step-01-response.json"
        metadata_path = source_case / "step-01-provider-metadata.json"
        raw_path = source_case / "step-01-raw-response.json"
        if not all(path.is_file() for path in (status_path, response_path, metadata_path, raw_path)):
            continue
        source_status = _read_json(status_path, "r11 final case status")
        metadata = _read_json(metadata_path, "r11 final provider metadata")
        finding_id = source_status.get("identity", {}).get("finding_id")
        if not isinstance(finding_id, str) or finding_id not in contexts_by_id:
            raise MachineReviewError("r11 final case identity is invalid")
        context = contexts_by_id[finding_id]
        expected_identity = _adjudication_case_identity(
            context, run_identity_sha256=run_identity_sha256
        )
        response_id = metadata.get("response_id")
        raw_proof = metadata.get("raw_response")
        if (
            source_status.get("identity") != expected_identity
            or metadata.get("status") != "SUCCESS"
            or metadata.get("provider") != provider_identity.get("id")
            or metadata.get("provider_version") != provider_identity.get("version")
            or metadata.get("sdk_version") != provider_identity.get("sdk_version")
            or metadata.get("configured_model") != provider_identity.get("model")
            or metadata.get("configuration") != source_sidecar.get("configuration")
            or metadata.get("configuration_sha256")
            != source_sidecar.get("configuration_sha256")
            or metadata.get("model_version") != config["model"]
            or not isinstance(response_id, str)
            or not response_id
            or response_id in response_ids
            or not isinstance(raw_proof, dict)
            or raw_proof.get("sha256") != _sha256(raw_path)
            or raw_proof.get("bytes") != raw_path.stat().st_size
        ):
            raise MachineReviewError(f"r11 paid response proof is invalid: {finding_id}")
        response_ids.add(response_id)
        response = _read_json(response_path, "r11 final provider response")
        decision, normalizations = _normalize_final_response_evidence(response, context)
        destination_case = destination_final / "cases" / source_case.name
        shutil.copytree(source_case, destination_case)
        decision_path = destination_case / "decision.json"
        _write_json(decision_path, decision)
        timestamp = created_at or _utc_now()
        recovered_status = {
            "schema_version": 1,
            "status": "SUCCESS",
            "identity": expected_identity,
            "started_at": source_status.get("started_at") or timestamp,
            "completed_at": timestamp,
            "decision_sha256": _sha256(decision_path),
            "response_sha256": _sha256(destination_case / response_path.name),
            "provider_metadata_sha256": _sha256(destination_case / metadata_path.name),
            "raw_response_sha256": _sha256(destination_case / raw_path.name),
            "response_id": response_id,
            "model_version": metadata["model_version"],
            "usage": metadata.get("normalized_usage") or {},
            "evidence_normalizations": normalizations,
            "recovered_from": {
                "release": base_release,
                "source_case": _portable_path(source_case, PROJECT_ROOT),
                "source_response_sha256": _sha256(response_path),
            },
        }
        _write_json(destination_case / "status.json", recovered_status)
        recovered.append(
            {
                "finding_id": finding_id,
                "case_directory": _portable_path(destination_case, review_directory),
                "status_sha256": _sha256(destination_case / "status.json"),
                "decision_sha256": _sha256(decision_path),
                "response_sha256": _sha256(destination_case / response_path.name),
                "provider_metadata_sha256": _sha256(destination_case / metadata_path.name),
                "raw_response_sha256": _sha256(destination_case / raw_path.name),
                "normalizations": normalizations,
            }
        )
    expected_recovered = sum(
        1
        for source_case in (source_final / "cases").glob("*")
        if source_case.is_dir()
        and (source_case / "step-01-provider-metadata.json").is_file()
        and _read_json(
            source_case / "step-01-provider-metadata.json",
            f"{base_release} final provider metadata",
        ).get("status")
        == "SUCCESS"
    )
    if expected_recovered < 1:
        raise MachineReviewError("final migration source has no paid successful responses")
    if len(recovered) != expected_recovered:
        raise MachineReviewError(
            f"final migration expected exactly {expected_recovered} paid "
            f"{base_release} responses, observed {len(recovered)}"
        )
    outputs: dict[str, Any] = {}
    for path in (
        destination_final / "run-identity.json",
        destination_final / "openai-provider-configuration.json",
    ):
        relative = path.relative_to(review_directory).as_posix()
        outputs[relative] = {"path": relative, "sha256": _sha256(path)}
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r11-to-r12-final-semantics-v1",
        "created_at": created_at or _utc_now(),
        "status": "COMPLETE",
        "identity": {
            "base_review_directory": _portable_path(base_review_directory, PROJECT_ROOT),
            "base_manifest_sha256": _sha256(base_review_directory / "machine-review-manifest.json"),
            "base_migration_sha256": _sha256(base_migration_path),
            "base_release": base_release,
            "r12_manifest_sha256": _sha256(review_directory / "machine-review-manifest.json"),
            "policy": (
                f"REUSE_{expected_recovered}_PAID_{base_release.upper()}_RESPONSES_"
                "WITH_FAIL_CLOSED_FINAL_NORMALIZATION"
            ),
        },
        "recovered_cases": recovered,
        "outputs": outputs,
    }
    _write_json(migration_path, migration)
    return _load_r12_migration(review_directory)


def _load_r13_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r13.json", "r13 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r12-to-r13-contained-evidence-v1"
        or migration.get("status") != "COMPLETE"
        or not isinstance(identity, dict)
        or identity.get("r13_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
        or identity.get("staging_migration_sha256")
        != _sha256(review_directory / "migration-r12.json")
    ):
        raise MachineReviewError("r13 contained-evidence migration identity is invalid")
    staging = _load_r12_migration(review_directory)
    if len(staging.get("recovered_cases") or []) != 6:
        raise MachineReviewError("r13 must recover exactly 6 paid final responses")
    return migration


def prepare_r13_contained_evidence_migration(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Recover six r12 responses under tightest-containing evidence policy."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    _load_machine_manifest(review_directory)
    base = _load_r12_migration(base_review_directory)
    migration_path = review_directory / "migration-r13.json"
    if migration_path.is_file():
        return _load_r13_migration(review_directory)
    staging = prepare_r12_final_semantics_migration(
        base_review_directory=base_review_directory,
        review_directory=review_directory,
        created_at=created_at,
    )
    if len(staging.get("recovered_cases") or []) != 6:
        raise MachineReviewError("r13 staging did not recover all six paid responses")
    normalized_case = next(
        (
            proof
            for proof in staging["recovered_cases"]
            if proof.get("finding_id")
            == "finding-53f479268313222b0b66941a08dc845d8444f15788f8461b34a53f748dbae2b1"
        ),
        None,
    )
    operations = {
        item.get("operation")
        for item in (normalized_case or {}).get("normalizations", [])
        if isinstance(item, dict)
    }
    if operations != {
        "CLEAR_NON_FP_REASON_CODES_V1",
        "RESTORE_UNIQUE_TIGHTEST_CONTAINING_FROZEN_EVIDENCE_NODE_V1",
    }:
        raise MachineReviewError("r13 target case normalization proof differs")
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r12-to-r13-contained-evidence-v1",
        "created_at": created_at or _utc_now(),
        "status": "COMPLETE",
        "identity": {
            "base_review_directory": _portable_path(base_review_directory, PROJECT_ROOT),
            "base_manifest_sha256": _sha256(base_review_directory / "machine-review-manifest.json"),
            "base_migration_r12_sha256": _sha256(base_review_directory / "migration-r12.json"),
            "base_recovered_records": len(base.get("recovered_cases") or []),
            "staging_migration_sha256": _sha256(review_directory / "migration-r12.json"),
            "r13_manifest_sha256": _sha256(review_directory / "machine-review-manifest.json"),
            "policy": "REUSE_6_PAID_R12_RESPONSES_WITH_TIGHTEST_CONTAINING_FROZEN_EVIDENCE",
        },
        "target_case": normalized_case,
    }
    _write_json(migration_path, migration)
    return _load_r13_migration(review_directory)


def _load_r14_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r14.json", "r14 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r13-to-r14-source-identity-v1"
        or migration.get("status") != "COMPLETE"
        or not isinstance(identity, dict)
        or identity.get("r14_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
        or identity.get("staging_migration_sha256")
        != _sha256(review_directory / "migration-r12.json")
    ):
        raise MachineReviewError("r14 source-identity migration is invalid")
    staging = _load_r12_migration(review_directory)
    if len(staging.get("recovered_cases") or []) != 10:
        raise MachineReviewError("r14 must recover exactly 10 paid final responses")
    return migration


def prepare_r14_source_identity_migration(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Recover ten r13 responses using exact frozen source-range identity."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    _load_machine_manifest(review_directory)
    base = _load_r13_migration(base_review_directory)
    migration_path = review_directory / "migration-r14.json"
    if migration_path.is_file():
        return _load_r14_migration(review_directory)
    staging = prepare_r12_final_semantics_migration(
        base_review_directory=base_review_directory,
        review_directory=review_directory,
        created_at=created_at,
    )
    if len(staging.get("recovered_cases") or []) != 10:
        raise MachineReviewError("r14 staging did not recover all ten paid responses")
    target_id = "finding-a8deb9d2dcfe71ec1229de025eed0849c2031214862bb07739c1524bd0919e3f"
    normalized_case = next(
        (
            proof
            for proof in staging["recovered_cases"]
            if proof.get("finding_id") == target_id
        ),
        None,
    )
    operations = [
        item.get("operation")
        for item in (normalized_case or {}).get("normalizations", [])
        if isinstance(item, dict)
    ]
    if operations != ["RESTORE_UNAMBIGUOUS_FROZEN_SOURCE_IDENTITY_NODE_V1"] * 3:
        raise MachineReviewError("r14 target case normalization proof differs")
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r13-to-r14-source-identity-v1",
        "created_at": created_at or _utc_now(),
        "status": "COMPLETE",
        "identity": {
            "base_review_directory": _portable_path(base_review_directory, PROJECT_ROOT),
            "base_manifest_sha256": _sha256(base_review_directory / "machine-review-manifest.json"),
            "base_migration_r13_sha256": _sha256(base_review_directory / "migration-r13.json"),
            "base_recovered_records": len(
                _load_r12_migration(base_review_directory).get("recovered_cases") or []
            ),
            "staging_migration_sha256": _sha256(review_directory / "migration-r12.json"),
            "r14_manifest_sha256": _sha256(review_directory / "machine-review-manifest.json"),
            "policy": "REUSE_10_PAID_R13_RESPONSES_WITH_UNAMBIGUOUS_FROZEN_SOURCE_IDENTITY",
        },
        "target_case": normalized_case,
    }
    _write_json(migration_path, migration)
    return _load_r14_migration(review_directory)


def _load_r15_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r15.json", "r15 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r14-to-r15-verdict-fields-v1"
        or migration.get("status") != "COMPLETE"
        or not isinstance(identity, dict)
        or identity.get("r15_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
        or identity.get("staging_migration_sha256")
        != _sha256(review_directory / "migration-r12.json")
    ):
        raise MachineReviewError("r15 verdict-field migration identity is invalid")
    staging = _load_r12_migration(review_directory)
    if len(staging.get("recovered_cases") or []) != 21:
        raise MachineReviewError("r15 must recover exactly 21 paid final responses")
    return migration


def prepare_r15_verdict_field_migration(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Recover 21 r14 responses under complete verdict-field semantics."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    _load_machine_manifest(review_directory)
    base = _load_r14_migration(base_review_directory)
    migration_path = review_directory / "migration-r15.json"
    if migration_path.is_file():
        return _load_r15_migration(review_directory)
    staging = prepare_r12_final_semantics_migration(
        base_review_directory=base_review_directory,
        review_directory=review_directory,
        created_at=created_at,
    )
    if len(staging.get("recovered_cases") or []) != 21:
        raise MachineReviewError("r15 staging did not recover all 21 paid responses")
    target_id = "finding-562af9243310a8a96c438a8626cb90c3160315b0e4ab1b5ba1690e8fc7eeff16"
    normalized_case = next(
        (
            proof
            for proof in staging["recovered_cases"]
            if proof.get("finding_id") == target_id
        ),
        None,
    )
    operations = [
        item.get("operation")
        for item in (normalized_case or {}).get("normalizations", [])
        if isinstance(item, dict)
    ]
    if operations != [
        "CLEAR_NON_UNCERTAIN_REASON_V1",
        "RESTORE_UNAMBIGUOUS_FROZEN_SOURCE_IDENTITY_NODE_V1",
        "RESTORE_UNAMBIGUOUS_FROZEN_SOURCE_IDENTITY_NODE_V1",
        "RESTORE_UNAMBIGUOUS_FROZEN_SOURCE_IDENTITY_NODE_V1",
    ]:
        raise MachineReviewError("r15 target case normalization proof differs")
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r14-to-r15-verdict-fields-v1",
        "created_at": created_at or _utc_now(),
        "status": "COMPLETE",
        "identity": {
            "base_review_directory": _portable_path(base_review_directory, PROJECT_ROOT),
            "base_manifest_sha256": _sha256(
                base_review_directory / "machine-review-manifest.json"
            ),
            "base_migration_r14_sha256": _sha256(
                base_review_directory / "migration-r14.json"
            ),
            "base_recovered_records": len(
                _load_r12_migration(base_review_directory).get("recovered_cases") or []
            ),
            "staging_migration_sha256": _sha256(review_directory / "migration-r12.json"),
            "r15_manifest_sha256": _sha256(review_directory / "machine-review-manifest.json"),
            "policy": (
                "REUSE_21_PAID_R14_RESPONSES_WITH_COMPLETE_VERDICT_FIELD_SEMANTICS"
            ),
        },
        "target_case": normalized_case,
        "base_status": base.get("status"),
    }
    _write_json(migration_path, migration)
    return _load_r15_migration(review_directory)


def _load_r16_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r16.json", "r16 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r15-to-r16-context-id-v1"
        or migration.get("status") != "COMPLETE"
        or not isinstance(identity, dict)
        or identity.get("r16_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
        or identity.get("staging_migration_sha256")
        != _sha256(review_directory / "migration-r12.json")
    ):
        raise MachineReviewError("r16 context-identifier migration identity is invalid")
    staging = _load_r12_migration(review_directory)
    if len(staging.get("recovered_cases") or []) != 28:
        raise MachineReviewError("r16 must recover exactly 28 paid final responses")
    return migration


def prepare_r16_context_id_migration(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Recover 28 r15 responses with a context-bound finding identifier."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    _load_machine_manifest(review_directory)
    base = _load_r15_migration(base_review_directory)
    migration_path = review_directory / "migration-r16.json"
    if migration_path.is_file():
        return _load_r16_migration(review_directory)
    staging = prepare_r12_final_semantics_migration(
        base_review_directory=base_review_directory,
        review_directory=review_directory,
        created_at=created_at,
    )
    if len(staging.get("recovered_cases") or []) != 28:
        raise MachineReviewError("r16 staging did not recover all 28 paid responses")
    target_id = "finding-9518f2e8bc0cd8e60893e1b0f5aa3cd9effc012eb793c3a38c29bcad8f021217"
    normalized_case = next(
        (
            proof
            for proof in staging["recovered_cases"]
            if proof.get("finding_id") == target_id
        ),
        None,
    )
    operations = [
        item.get("operation")
        for item in (normalized_case or {}).get("normalizations", [])
        if isinstance(item, dict)
    ]
    if operations != [
        "RESTORE_FROZEN_CONTEXT_FINDING_ID_V1",
        "RESTORE_UNAMBIGUOUS_FROZEN_SOURCE_IDENTITY_NODE_V1",
        "RESTORE_UNAMBIGUOUS_FROZEN_SOURCE_IDENTITY_NODE_V1",
        "RESTORE_UNAMBIGUOUS_FROZEN_SOURCE_IDENTITY_NODE_V1",
    ]:
        raise MachineReviewError("r16 target case normalization proof differs")
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r15-to-r16-context-id-v1",
        "created_at": created_at or _utc_now(),
        "status": "COMPLETE",
        "identity": {
            "base_review_directory": _portable_path(base_review_directory, PROJECT_ROOT),
            "base_manifest_sha256": _sha256(
                base_review_directory / "machine-review-manifest.json"
            ),
            "base_migration_r15_sha256": _sha256(
                base_review_directory / "migration-r15.json"
            ),
            "base_recovered_records": len(
                _load_r12_migration(base_review_directory).get("recovered_cases") or []
            ),
            "staging_migration_sha256": _sha256(review_directory / "migration-r12.json"),
            "r16_manifest_sha256": _sha256(review_directory / "machine-review-manifest.json"),
            "policy": "REUSE_28_PAID_R15_RESPONSES_WITH_CONTEXT_BOUND_FINDING_ID",
        },
        "target_case": normalized_case,
        "base_status": base.get("status"),
    }
    _write_json(migration_path, migration)
    return _load_r16_migration(review_directory)


def _load_r17_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r17.json", "r17 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r16-to-r17-frozen-code-v1"
        or migration.get("status") != "COMPLETE"
        or not isinstance(identity, dict)
        or identity.get("r17_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
        or identity.get("staging_migration_sha256")
        != _sha256(review_directory / "migration-r12.json")
    ):
        raise MachineReviewError("r17 frozen-code migration identity is invalid")
    staging = _load_r12_migration(review_directory)
    if len(staging.get("recovered_cases") or []) != 41:
        raise MachineReviewError("r17 must recover exactly 41 paid final responses")
    return migration


def prepare_r17_frozen_code_migration(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Recover 41 r16 responses using unique exact frozen-code identity."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    _load_machine_manifest(review_directory)
    base = _load_r16_migration(base_review_directory)
    migration_path = review_directory / "migration-r17.json"
    if migration_path.is_file():
        return _load_r17_migration(review_directory)
    staging = prepare_r12_final_semantics_migration(
        base_review_directory=base_review_directory,
        review_directory=review_directory,
        created_at=created_at,
    )
    if len(staging.get("recovered_cases") or []) != 41:
        raise MachineReviewError("r17 staging did not recover all 41 paid responses")
    target_id = "finding-93291c5949d7ea217f6fa11cdaec330d18616fb71bb729e56cb62b0047602013"
    normalized_case = next(
        (
            proof
            for proof in staging["recovered_cases"]
            if proof.get("finding_id") == target_id
        ),
        None,
    )
    operations = [
        item.get("operation")
        for item in (normalized_case or {}).get("normalizations", [])
        if isinstance(item, dict)
    ]
    if operations != [
        "CLEAR_NON_FP_REASON_CODES_V1",
        "RESTORE_UNIQUE_FROZEN_CODE_IDENTITY_NODE_V1",
        "RESTORE_UNIQUE_FROZEN_EVIDENCE_NODE_V1",
        "RESTORE_UNIQUE_FROZEN_EVIDENCE_NODE_V1",
        "RESTORE_UNAMBIGUOUS_FROZEN_SOURCE_IDENTITY_NODE_V1",
    ]:
        raise MachineReviewError("r17 target case normalization proof differs")
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r16-to-r17-frozen-code-v1",
        "created_at": created_at or _utc_now(),
        "status": "COMPLETE",
        "identity": {
            "base_review_directory": _portable_path(base_review_directory, PROJECT_ROOT),
            "base_manifest_sha256": _sha256(
                base_review_directory / "machine-review-manifest.json"
            ),
            "base_migration_r16_sha256": _sha256(
                base_review_directory / "migration-r16.json"
            ),
            "base_recovered_records": len(
                _load_r12_migration(base_review_directory).get("recovered_cases") or []
            ),
            "staging_migration_sha256": _sha256(review_directory / "migration-r12.json"),
            "r17_manifest_sha256": _sha256(review_directory / "machine-review-manifest.json"),
            "policy": "REUSE_41_PAID_R16_RESPONSES_WITH_UNIQUE_EXACT_FROZEN_CODE",
        },
        "target_case": normalized_case,
        "base_status": base.get("status"),
    }
    _write_json(migration_path, migration)
    return _load_r17_migration(review_directory)


def _load_r18_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r18.json", "r18 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r17-to-r18-numbered-code-v1"
        or migration.get("status") != "COMPLETE"
        or not isinstance(identity, dict)
        or identity.get("r18_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
        or identity.get("staging_migration_sha256")
        != _sha256(review_directory / "migration-r12.json")
    ):
        raise MachineReviewError("r18 numbered-code migration identity is invalid")
    staging = _load_r12_migration(review_directory)
    if len(staging.get("recovered_cases") or []) != 68:
        raise MachineReviewError("r18 must recover exactly 68 paid final responses")
    return migration


def prepare_r18_numbered_code_migration(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Recover 68 r17 responses using unique numbered frozen-code identity."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    _load_machine_manifest(review_directory)
    base = _load_r17_migration(base_review_directory)
    migration_path = review_directory / "migration-r18.json"
    if migration_path.is_file():
        return _load_r18_migration(review_directory)
    staging = prepare_r12_final_semantics_migration(
        base_review_directory=base_review_directory,
        review_directory=review_directory,
        created_at=created_at,
    )
    if len(staging.get("recovered_cases") or []) != 68:
        raise MachineReviewError("r18 staging did not recover all 68 paid responses")
    target_id = "finding-bf67bf2789c29922df95e41232233ced4fed7239b031a7a05fc19cca99ab53e5"
    normalized_case = next(
        (
            proof
            for proof in staging["recovered_cases"]
            if proof.get("finding_id") == target_id
        ),
        None,
    )
    operations = [
        item.get("operation")
        for item in (normalized_case or {}).get("normalizations", [])
        if isinstance(item, dict)
    ]
    if operations != [
        "RESTORE_UNIQUE_FROZEN_EVIDENCE_NODE_V1",
        "RESTORE_UNIQUE_FROZEN_EVIDENCE_NODE_V1",
        "RESTORE_UNIQUE_NUMBERED_FROZEN_CODE_NODE_V1",
    ]:
        raise MachineReviewError("r18 target case normalization proof differs")
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r17-to-r18-numbered-code-v1",
        "created_at": created_at or _utc_now(),
        "status": "COMPLETE",
        "identity": {
            "base_review_directory": _portable_path(
                base_review_directory, PROJECT_ROOT
            ),
            "base_manifest_sha256": _sha256(
                base_review_directory / "machine-review-manifest.json"
            ),
            "base_migration_r17_sha256": _sha256(
                base_review_directory / "migration-r17.json"
            ),
            "base_recovered_records": len(
                _load_r12_migration(base_review_directory).get("recovered_cases") or []
            ),
            "staging_migration_sha256": _sha256(
                review_directory / "migration-r12.json"
            ),
            "r18_manifest_sha256": _sha256(
                review_directory / "machine-review-manifest.json"
            ),
            "policy": (
                "REUSE_68_PAID_R17_RESPONSES_WITH_UNIQUE_NUMBERED_FROZEN_CODE"
            ),
        },
        "target_case": normalized_case,
        "base_status": base.get("status"),
    }
    _write_json(migration_path, migration)
    return _load_r18_migration(review_directory)


def _load_r19_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r19.json", "r19 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r18-to-r19-uncertain-evidence-v1"
        or migration.get("status") != "COMPLETE"
        or not isinstance(identity, dict)
        or identity.get("r19_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
        or identity.get("staging_migration_sha256")
        != _sha256(review_directory / "migration-r12.json")
    ):
        raise MachineReviewError("r19 uncertain-evidence migration identity is invalid")
    staging = _load_r12_migration(review_directory)
    if len(staging.get("recovered_cases") or []) != 90:
        raise MachineReviewError("r19 must recover exactly 90 paid final responses")
    return migration


def prepare_r19_uncertain_evidence_migration(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Recover 90 r18 responses while dropping optional unexposed UNCERTAIN evidence."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    _load_machine_manifest(review_directory)
    base = _load_r18_migration(base_review_directory)
    migration_path = review_directory / "migration-r19.json"
    if migration_path.is_file():
        return _load_r19_migration(review_directory)
    staging = prepare_r12_final_semantics_migration(
        base_review_directory=base_review_directory,
        review_directory=review_directory,
        created_at=created_at,
    )
    if len(staging.get("recovered_cases") or []) != 90:
        raise MachineReviewError("r19 staging did not recover all 90 paid responses")
    target_id = "finding-29f26924f6d04f64293f95b69b74e9b5ac6acb543ab5035c69f5b38aa7afd1c0"
    normalized_case = next(
        (
            proof
            for proof in staging["recovered_cases"]
            if proof.get("finding_id") == target_id
        ),
        None,
    )
    operations = [
        item.get("operation")
        for item in (normalized_case or {}).get("normalizations", [])
        if isinstance(item, dict)
    ]
    if operations != [
        "RESTORE_FROZEN_CONTEXT_FINDING_ID_V1",
        "CLEAR_UNEXPOSED_UNCERTAIN_EVIDENCE_NODE_V1",
    ]:
        raise MachineReviewError("r19 target case normalization proof differs")
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r18-to-r19-uncertain-evidence-v1",
        "created_at": created_at or _utc_now(),
        "status": "COMPLETE",
        "identity": {
            "base_review_directory": _portable_path(
                base_review_directory, PROJECT_ROOT
            ),
            "base_manifest_sha256": _sha256(
                base_review_directory / "machine-review-manifest.json"
            ),
            "base_migration_r18_sha256": _sha256(
                base_review_directory / "migration-r18.json"
            ),
            "base_recovered_records": len(
                _load_r12_migration(base_review_directory).get("recovered_cases") or []
            ),
            "staging_migration_sha256": _sha256(
                review_directory / "migration-r12.json"
            ),
            "r19_manifest_sha256": _sha256(
                review_directory / "machine-review-manifest.json"
            ),
            "policy": "REUSE_90_PAID_R18_RESPONSES_DROP_UNEXPOSED_UNCERTAIN_EVIDENCE",
        },
        "target_case": normalized_case,
        "base_status": base.get("status"),
    }
    _write_json(migration_path, migration)
    return _load_r19_migration(review_directory)


def _load_r20_migration(review_directory: Path) -> dict[str, Any]:
    migration = _read_json(review_directory / "migration-r20.json", "r20 migration")
    identity = migration.get("identity")
    if (
        migration.get("schema_version") != 1
        or migration.get("migration_id")
        != "opengrep-machine-review-r19-to-r20-provenance-v1"
        or migration.get("status") != "COMPLETE"
        or not isinstance(identity, dict)
        or identity.get("r20_manifest_sha256")
        != _sha256(review_directory / "machine-review-manifest.json")
        or identity.get("staging_migration_sha256")
        != _sha256(review_directory / "migration-r12.json")
    ):
        raise MachineReviewError("r20 provenance migration identity is invalid")
    staging = _load_r12_migration(review_directory)
    if len(staging.get("recovered_cases") or []) != 112:
        raise MachineReviewError("r20 must recover exactly 112 paid final responses")
    return migration


def prepare_r20_provenance_migration(
    *,
    base_review_directory: Path,
    review_directory: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Recover all r19 responses under corrected reviewer-family provenance."""

    base_review_directory = base_review_directory.resolve(strict=True)
    review_directory = review_directory.resolve()
    _load_machine_manifest(review_directory)
    base = _load_r19_migration(base_review_directory)
    migration_path = review_directory / "migration-r20.json"
    if migration_path.is_file():
        return _load_r20_migration(review_directory)
    staging = prepare_r12_final_semantics_migration(
        base_review_directory=base_review_directory,
        review_directory=review_directory,
        created_at=created_at,
    )
    if len(staging.get("recovered_cases") or []) != 112:
        raise MachineReviewError("r20 staging did not recover all 112 paid responses")
    migration = {
        "schema_version": 1,
        "migration_id": "opengrep-machine-review-r19-to-r20-provenance-v1",
        "created_at": created_at or _utc_now(),
        "status": "COMPLETE",
        "identity": {
            "base_review_directory": _portable_path(
                base_review_directory, PROJECT_ROOT
            ),
            "base_manifest_sha256": _sha256(
                base_review_directory / "machine-review-manifest.json"
            ),
            "base_migration_r19_sha256": _sha256(
                base_review_directory / "migration-r19.json"
            ),
            "base_recovered_records": len(
                _load_r12_migration(base_review_directory).get("recovered_cases") or []
            ),
            "staging_migration_sha256": _sha256(
                review_directory / "migration-r12.json"
            ),
            "r20_manifest_sha256": _sha256(
                review_directory / "machine-review-manifest.json"
            ),
            "policy": "REUSE_112_PAID_R19_RESPONSES_CORRECT_REVIEWER_FAMILY_PROVENANCE",
        },
        "base_status": base.get("status"),
    }
    _write_json(migration_path, migration)
    return _load_r20_migration(review_directory)


def _r10_import_proof(
    run_directory: Path, review_directory: Path, source: dict[str, Any]
) -> dict[str, Any]:
    return {
        "run_directory": _portable_path(run_directory, review_directory),
        "verifier_run_sha256": _sha256(run_directory / "verifier-run.json"),
        "run_identity_sha256": _sha256(run_directory / "run-identity.json"),
        "provider_configuration_sha256": _sha256(
            run_directory / "openai-provider-configuration.json"
        ),
        "input_sha256": _sha256(run_directory / "blind-verifier-input.jsonl"),
        "predictions_sha256": _sha256(run_directory / "verifier-predictions.jsonl"),
        "records": len(source["full_ids"]),
        "failed_records": 0,
        "requested_model": _frozen_config(review_directory, "ADJUDICATOR_C")["model"],
        "model_version": source["source_proof"]["model_version"],
        "model_versions": source["source_proof"].get("model_versions", []),
        "provider": "IMPORTED_R9_ADJUDICATOR_COMPOSITE",
        "provider_version": source["source_proof"]["provider_version"],
        "provider_versions": source["source_proof"].get("provider_versions", []),
        "sdk_version": source["source_proof"]["sdk_version"],
        "usage": source["source_proof"].get("usage", {}),
        "artifacts": _artifact_inventory(run_directory),
        "frozen_components": source["source_proof"]["frozen_components"],
        "migration_sources": {"r9_composite": source["source_proof"]},
    }


def _load_r10_adjudicator_import(
    *, run_directory: Path, review_directory: Path
) -> dict[str, Any]:
    migration = _load_r10_migration(review_directory)
    base_value = migration["identity"]["base_review_directory"]
    base = Path(base_value)
    if not base.is_absolute():
        base = PROJECT_ROOT / base
    source = _r10_source_composite(
        base_review_directory=base.resolve(strict=True),
        review_directory=review_directory,
    )
    proof = _r10_import_proof(run_directory, review_directory, source)
    if proof != migration.get("imported_run"):
        raise MachineReviewError("r10 imported C run proof differs")
    identity = _read_json(run_directory / "run-identity.json", "r10 C identity")
    if identity.get("protocol") != "adjudicator-blind-final-only-migration-v2":
        raise MachineReviewError("r10 imported C protocol differs")
    rows = _read_jsonl(run_directory / "verifier-predictions.jsonl", "r10 C predictions")
    expected_rows = [source["rows"][finding_id] for finding_id in source["full_ids"]]
    if rows != expected_rows:
        raise MachineReviewError("r10 imported C predictions differ")
    return {
        "run_directory": run_directory,
        "manifest": _read_json(run_directory / "verifier-run.json", "r10 C run"),
        "rows": source["rows"],
        "prediction_sha256": source["prediction_sha256"],
        "evidence_errors": source["evidence_errors"],
        "model_version": proof["model_version"],
        "proof": proof,
        "full_ids": source["full_ids"],
    }


def _load_adjudicator_blind_run(
    *,
    run_directory: Path,
    review_directory: Path,
    expected_input: Path,
    expected_ids: list[str],
    findings_by_id: dict[str, dict[str, Any]],
    expected_snapshot_root: Path,
    config: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    identity_path = run_directory / "run-identity.json"
    if identity_path.is_file():
        identity = _read_json(identity_path, f"{label} run identity")
        if identity.get("protocol") == "adjudicator-blind-composite-supplement-v1":
            composite = _load_r9_adjudicator_composite(
                run_directory=run_directory,
                review_directory=review_directory,
            )
            if composite["full_ids"] != expected_ids:
                raise MachineReviewError("r9 C composite ordering differs")
            return composite
        if identity.get("protocol") == "adjudicator-blind-final-only-migration-v2":
            imported = _load_r10_adjudicator_import(
                run_directory=run_directory,
                review_directory=review_directory,
            )
            if imported["full_ids"] != expected_ids:
                raise MachineReviewError("r10 C imported ordering differs")
            return imported
    return _load_run(
        run_directory=run_directory,
        review_directory=review_directory,
        expected_input=expected_input,
        expected_ids=expected_ids,
        findings_by_id=findings_by_id,
        expected_snapshot_root=expected_snapshot_root,
        config=config,
        label=label,
    )


def _load_reviewer_run(
    *,
    run_directory: Path,
    review_directory: Path,
    expected_input: Path,
    expected_ids: list[str],
    findings_by_id: dict[str, dict[str, Any]],
    expected_snapshot_root: Path,
    config: dict[str, Any],
    label: str,
    role: str,
) -> dict[str, Any]:
    identity_path = run_directory / "run-identity.json"
    if identity_path.is_file():
        identity = _read_json(identity_path, f"{label} run identity")
        if identity.get("protocol") == "reviewer-composite-migration-v1":
            composite = _load_composite_run(
                run_directory=run_directory,
                review_directory=review_directory,
                role=role,
            )
            if composite["full_ids"] != expected_ids:
                raise MachineReviewError(f"{label} composite ordering differs")
            return composite
        if identity.get("protocol") == "reviewer-composite-supplement-v2":
            composite = _load_r7_composite_run(
                run_directory=run_directory,
                review_directory=review_directory,
                role=role,
            )
            if composite["full_ids"] != expected_ids:
                raise MachineReviewError(f"{label} r7 composite ordering differs")
            return composite
        if identity.get("protocol") == "reviewer-composite-adjudicator-migration-v3":
            composite = _load_r8_composite_run(
                run_directory=run_directory,
                review_directory=review_directory,
                role=role,
            )
            if composite["full_ids"] != expected_ids:
                raise MachineReviewError(f"{label} r8 composite ordering differs")
            return composite
    return _load_run(
        run_directory=run_directory,
        review_directory=review_directory,
        expected_input=expected_input,
        expected_ids=expected_ids,
        findings_by_id=findings_by_id,
        expected_snapshot_root=expected_snapshot_root,
        config=config,
        label=label,
    )


def _audit_ids(ids: list[str], fraction: float, seed: str) -> set[str]:
    if not ids:
        return set()
    count = min(len(ids), max(1, math.ceil(len(ids) * fraction)))
    ordered = sorted(
        ids,
        key=lambda finding_id: hashlib.sha256(
            f"{seed}\0{finding_id}".encode("utf-8")
        ).digest(),
    )
    return set(ordered[:count])


def _sanitized_opinion(
    row: dict[str, Any], *, evidence_valid: bool
) -> dict[str, Any]:
    return {
        "verdict": row["verdict"],
        "confidence": row["confidence"],
        "reason_codes": row["reason_codes"],
        "attacker_capability": row["attacker_capability"],
        "entry_point": row["entry_point"],
        "security_effect": row["security_effect"],
        "controls": row["controls"],
        "reasoning": row["reasoning"],
        "evidence": row["evidence"] if evidence_valid else [],
        "evidence_valid": evidence_valid,
        "abstain_reason": row.get("abstain_reason"),
    }


def _agreement_statistics(
    ids: list[str], a_rows: dict[str, dict[str, Any]], b_rows: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    if not ids:
        raise MachineReviewError("cannot measure reviewer agreement on an empty corpus")
    a_counts: Counter[str] = Counter()
    b_counts: Counter[str] = Counter()
    agreements = 0
    for finding_id in ids:
        a_verdict = str(a_rows[finding_id]["verdict"])
        b_verdict = str(b_rows[finding_id]["verdict"])
        a_counts[a_verdict] += 1
        b_counts[b_verdict] += 1
        agreements += a_verdict == b_verdict
    records = len(ids)
    observed = agreements / records
    expected = sum(
        (a_counts[verdict] / records) * (b_counts[verdict] / records)
        for verdict in VERDICTS
    )
    kappa = None if expected == 1.0 else (observed - expected) / (1.0 - expected)
    return {
        "records": records,
        "agreements": agreements,
        "raw_agreement": observed,
        "chance_expected_agreement": expected,
        "cohen_kappa": kappa,
        "reviewer_a_verdict_counts": dict(sorted(a_counts.items())),
        "reviewer_b_verdict_counts": dict(sorted(b_counts.items())),
    }


def reconcile_reviews(
    *,
    review_directory: Path,
    reviewer_a_run: Path,
    reviewer_b_run: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    review_directory = review_directory.resolve()
    manifest = _load_machine_manifest(review_directory)
    findings, packets = _frozen_rows(review_directory)
    original_ids = _ordered_ids(findings, "frozen sample")
    findings_by_id = {str(row["finding_id"]): row for row in findings}
    packet_by_id = {str(row["finding_id"]): row for row in packets}
    a_input = review_directory / "reviewer-a" / "blind-input.jsonl"
    b_input = review_directory / "reviewer-b" / "blind-input.jsonl"
    a_ids = _ordered_ids(_read_jsonl(a_input, "reviewer A input"), "reviewer A input")
    b_ids = _ordered_ids(_read_jsonl(b_input, "reviewer B input"), "reviewer B input")
    if set(a_ids) != set(original_ids) or set(b_ids) != set(original_ids):
        raise MachineReviewError("reviewer inputs no longer cover the frozen sample")
    a = _load_reviewer_run(
        run_directory=reviewer_a_run,
        review_directory=review_directory,
        expected_input=a_input,
        expected_ids=a_ids,
        findings_by_id=findings_by_id,
        expected_snapshot_root=_frozen_snapshot_root(manifest),
        config=_frozen_config(review_directory, "REVIEWER_A"),
        label="reviewer A",
        role="a",
    )
    b = _load_reviewer_run(
        run_directory=reviewer_b_run,
        review_directory=review_directory,
        expected_input=b_input,
        expected_ids=b_ids,
        findings_by_id=findings_by_id,
        expected_snapshot_root=_frozen_snapshot_root(manifest),
        config=_frozen_config(review_directory, "REVIEWER_B"),
        label="reviewer B",
        role="b",
    )
    if a["proof"]["frozen_components"] != b["proof"]["frozen_components"]:
        raise MachineReviewError("reviewer A/B source-review components differ")
    high_fp = [
        finding_id
        for finding_id in original_ids
        if a["rows"][finding_id]["verdict"] == "FALSE_POSITIVE"
        and b["rows"][finding_id]["verdict"] == "FALSE_POSITIVE"
        and a["rows"][finding_id]["confidence"] == "HIGH"
        and b["rows"][finding_id]["confidence"] == "HIGH"
        and finding_id not in a["evidence_errors"]
        and finding_id not in b["evidence_errors"]
    ]
    policy = manifest["routing_policy"]
    audited = _audit_ids(
        high_fp,
        float(policy["consensus_high_fp_audit_fraction"]),
        str(policy["consensus_high_fp_audit_seed"]),
    )
    reconciliation: list[dict[str, Any]] = []
    blind_queue: list[dict[str, Any]] = []
    reason_counts: Counter[str] = Counter()
    verdict_pairs: Counter[str] = Counter()
    for finding_id in original_ids:
        pa = a["rows"][finding_id]
        pb = b["rows"][finding_id]
        reasons: list[str] = []
        if pa["verdict"] != pb["verdict"]:
            reasons.append("MODEL_DISAGREEMENT")
        if "TRUE_POSITIVE" in {pa["verdict"], pb["verdict"]}:
            reasons.append("ANY_TRUE_POSITIVE")
        if "ABSTAIN" in {pa["verdict"], pb["verdict"]}:
            reasons.append("ANY_ABSTAIN")
        if pa["confidence"] != "HIGH" or pb["confidence"] != "HIGH":
            reasons.append("ANY_NON_HIGH_CONFIDENCE")
        if finding_id in a["evidence_errors"]:
            reasons.append("REVIEWER_A_INVALID_EVIDENCE")
        if finding_id in b["evidence_errors"]:
            reasons.append("REVIEWER_B_INVALID_EVIDENCE")
        if finding_id in audited:
            reasons.append("DETERMINISTIC_CONSENSUS_FP_AUDIT")
        verdict_pairs[f"{pa['verdict']}|{pb['verdict']}"] += 1
        reason_counts.update(reasons)
        row = {
            "schema_version": 1,
            "finding_id": finding_id,
            "routed_to_adjudicator": bool(reasons),
            "route_reasons": reasons,
            "reviewer_a": _sanitized_opinion(
                pa, evidence_valid=finding_id not in a["evidence_errors"]
            ),
            "reviewer_b": _sanitized_opinion(
                pb, evidence_valid=finding_id not in b["evidence_errors"]
            ),
            "prediction_sha256": {
                "reviewer_a": a["prediction_sha256"][finding_id],
                "reviewer_b": b["prediction_sha256"][finding_id],
            },
        }
        reconciliation.append(row)
        if reasons:
            packet_finding = packet_by_id[finding_id].get("finding")
            if not isinstance(packet_finding, dict):
                raise MachineReviewError(
                    f"frozen evidence packet has no finding: {finding_id}"
                )
            blind_queue.append(packet_finding)
    non_routed = [row for row in reconciliation if not row["routed_to_adjudicator"]]
    if any(
        row["reviewer_a"]["verdict"] != "FALSE_POSITIVE"
        or row["reviewer_b"]["verdict"] != "FALSE_POSITIVE"
        or row["reviewer_a"]["confidence"] != "HIGH"
        or row["reviewer_b"]["confidence"] != "HIGH"
        or not row["reviewer_a"]["evidence_valid"]
        or not row["reviewer_b"]["evidence_valid"]
        for row in non_routed
    ):
        raise MachineReviewError("routing policy left a non-HIGH/invalid/non-FP case unrouted")

    reconciliation_path = review_directory / "reconciliation" / "reconciliation.jsonl"
    blind_path = review_directory / "adjudicator-c" / "blind-input.jsonl"
    summary_path = review_directory / "reconciliation" / "reconciliation-summary.json"
    identity = {
        "machine_review_manifest_sha256": _sha256(
            review_directory / "machine-review-manifest.json"
        ),
        "reviewer_a_run_sha256": a["proof"]["verifier_run_sha256"],
        "reviewer_b_run_sha256": b["proof"]["verifier_run_sha256"],
        "reviewer_a_predictions_sha256": a["proof"]["predictions_sha256"],
        "reviewer_b_predictions_sha256": b["proof"]["predictions_sha256"],
        "policy": policy,
    }
    counts = {
        "routed_to_adjudicator": len(blind_queue),
        "consensus_high_fp_not_routed": len(non_routed),
        "consensus_high_fp_total": len(high_fp),
        "consensus_high_fp_audited": len(audited),
    }
    agreement = {
        **_agreement_statistics(original_ids, a["rows"], b["rows"]),
        "reviewer_a_evidence_valid": len(original_ids) - len(a["evidence_errors"]),
        "reviewer_b_evidence_valid": len(original_ids) - len(b["evidence_errors"]),
        "both_evidence_valid": sum(
            finding_id not in a["evidence_errors"]
            and finding_id not in b["evidence_errors"]
            for finding_id in original_ids
        ),
    }
    expected_status = (
        "AWAITING_ADJUDICATOR_C_BLIND_FIRST"
        if blind_queue
        else "READY_TO_FINALIZE_WITHOUT_ADJUDICATION"
    )
    if summary_path.exists():
        existing = _read_json(summary_path, "reconciliation summary")
        if existing.get("identity") != identity:
            raise MachineReviewError("existing reconciliation identity differs")
        _check_stage_outputs(review_directory, existing)
        expected_fields = {
            "status": expected_status,
            "records": len(original_ids),
            "counts": counts,
            "route_reasons": dict(sorted(reason_counts.items())),
            "verdict_pairs": dict(sorted(verdict_pairs.items())),
            "agreement": agreement,
            "reviewer_runs": {
                "reviewer_a": a["proof"],
                "reviewer_b": b["proof"],
            },
        }
        if any(existing.get(key) != value for key, value in expected_fields.items()):
            raise MachineReviewError(
                "existing reconciliation summary differs from reconstructed A/B runs"
            )
        if _read_jsonl(
            reconciliation_path, "existing reconciliation"
        ) != reconciliation or _read_jsonl(
            blind_path, "existing adjudicator blind input"
        ) != blind_queue:
            raise MachineReviewError(
                "existing reconciliation differs from reconstructed A/B predictions"
            )
        return existing
    if reconciliation_path.exists() or blind_path.exists():
        raise MachineReviewError("partial reconciliation exists without a summary")
    _write_jsonl(reconciliation_path, reconciliation)
    _write_jsonl(blind_path, blind_queue)
    created = created_at or _utc_now()
    summary = {
        "schema_version": 1,
        "created_at": created,
        "status": expected_status,
        "identity": identity,
        "records": len(original_ids),
        "counts": counts,
        "route_reasons": dict(sorted(reason_counts.items())),
        "verdict_pairs": dict(sorted(verdict_pairs.items())),
        "agreement": agreement,
        "reviewer_runs": {"reviewer_a": a["proof"], "reviewer_b": b["proof"]},
        "actual_model_version_limitation": (
            "Requested model IDs are distinct; server model_version equality is recorded "
            "as a correlated-model limitation, not silently treated as independence."
        ),
        "outputs": {
            "reconciliation": {
                "path": reconciliation_path.relative_to(review_directory).as_posix(),
                "sha256": _sha256(reconciliation_path),
                "records": len(reconciliation),
            },
            "adjudicator_blind_input": {
                "path": blind_path.relative_to(review_directory).as_posix(),
                "sha256": _sha256(blind_path),
                "records": len(blind_queue),
            },
        },
    }
    _write_json(summary_path, summary)
    return summary


def _load_reconciliation(review_directory: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    summary = _read_json(
        review_directory / "reconciliation" / "reconciliation-summary.json",
        "reconciliation summary",
    )
    if summary.get("status") not in {
        "AWAITING_ADJUDICATOR_C_BLIND_FIRST",
        "READY_TO_FINALIZE_WITHOUT_ADJUDICATION",
    }:
        raise MachineReviewError("reconciliation status is invalid")
    _check_stage_outputs(review_directory, summary)
    path = _verify_file_identity(
        review_directory,
        summary.get("outputs", {}).get("reconciliation"),
        "reconciliation",
    )
    rows = _read_jsonl(path, "reconciliation")
    if len(rows) != summary.get("records"):
        raise MachineReviewError("reconciliation record count differs")
    return summary, rows


def _anonymous_reviews(row: dict[str, Any], finding_id: str) -> list[dict[str, Any]]:
    values = [row["reviewer_a"], row["reviewer_b"]]
    if hashlib.sha256(f"anonymous-order\0{finding_id}".encode()).digest()[0] & 1:
        values.reverse()
    return [
        {"reviewer_token": f"REVIEWER_{index}", **value}
        for index, value in enumerate(values, 1)
    ]


def prepare_adjudication(
    *,
    review_directory: Path,
    blind_run: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    review_directory = review_directory.resolve()
    manifest = _load_machine_manifest(review_directory)
    reconciliation_summary, reconciliation = _load_reconciliation(review_directory)
    findings, packets = _frozen_rows(review_directory)
    findings_by_id = {str(row["finding_id"]): row for row in findings}
    packets_by_id = {str(row["finding_id"]): row for row in packets}
    routed = [row for row in reconciliation if row.get("routed_to_adjudicator") is True]
    routed_ids = _ordered_ids(routed, "routed reconciliation")
    blind_input = review_directory / "adjudicator-c" / "blind-input.jsonl"
    if _ordered_ids(_read_jsonl(blind_input, "adjudicator blind input"), "adjudicator blind input") != routed_ids:
        raise MachineReviewError("adjudicator blind input differs from routed IDs/order")
    if not routed_ids:
        raise MachineReviewError("no routed cases require adjudicator C")
    c = _load_adjudicator_blind_run(
        run_directory=blind_run,
        review_directory=review_directory,
        expected_input=blind_input,
        expected_ids=routed_ids,
        findings_by_id=findings_by_id,
        expected_snapshot_root=_frozen_snapshot_root(manifest),
        config=_frozen_config(review_directory, "ADJUDICATOR_C"),
        label="adjudicator C blind-first",
    )
    reviewer_components = reconciliation_summary["reviewer_runs"]["reviewer_a"][
        "frozen_components"
    ]
    if c["proof"]["frozen_components"] != reviewer_components:
        raise MachineReviewError(
            "adjudicator C blind-first source-review components differ from A/B"
        )
    reconciliation_by_id = {str(row["finding_id"]): row for row in routed}
    input_rows: list[dict[str, Any]] = []
    for finding_id in routed_ids:
        reconciliation_row = reconciliation_by_id[finding_id]
        blind = c["rows"][finding_id]
        input_rows.append(
            {
                "schema_version": 1,
                "finding_id": finding_id,
                "finding": packets_by_id[finding_id]["finding"],
                "route_reasons": reconciliation_row["route_reasons"],
                "blind_first_prediction": _sanitized_opinion(
                    blind,
                    evidence_valid=finding_id not in c["evidence_errors"],
                ),
                "anonymous_reviews": _anonymous_reviews(
                    reconciliation_row, finding_id
                ),
                "evidence_policy": {
                    "citations_must_be_copied_exactly_from_valid_exposed_evidence": True,
                    "invalid_reviewer_evidence_removed": True,
                    "no_new_source_navigation_in_final_adjudication": True,
                },
            }
        )
    input_path = review_directory / "adjudicator-c" / "adjudication-input.jsonl"
    manifest_path = review_directory / "adjudicator-c" / "adjudication-preparation.json"
    identity = {
        "reconciliation_summary_sha256": _sha256(
            review_directory / "reconciliation" / "reconciliation-summary.json"
        ),
        "reconciliation_sha256": reconciliation_summary["outputs"]["reconciliation"][
            "sha256"
        ],
        "blind_input_sha256": _sha256(blind_input),
        "blind_run_sha256": c["proof"]["verifier_run_sha256"],
        "blind_predictions_sha256": c["proof"]["predictions_sha256"],
        "blind_model_version": c["model_version"],
    }
    if manifest_path.exists():
        existing = _read_json(manifest_path, "adjudication preparation")
        if existing.get("identity") != identity:
            raise MachineReviewError("existing adjudication preparation identity differs")
        _check_stage_outputs(review_directory, existing)
        expected_fields = {
            "status": "BLIND_FIRST_FROZEN_READY_FOR_FINAL_ADJUDICATION",
            "records": len(input_rows),
            "blind_run": c["proof"],
            "blind_prediction_sha256_by_id": c["prediction_sha256"],
            "blind_evidence_invalid_ids": sorted(c["evidence_errors"]),
            "blindness_transition": {
                "blind_prediction_frozen_before_a_b_exposure": True,
                "reviewer_identities_removed": True,
                "evaluated_agent_prediction_exposed": False,
            },
        }
        if any(existing.get(key) != value for key, value in expected_fields.items()):
            raise MachineReviewError(
                "existing adjudication preparation differs from reconstructed C run"
            )
        if _read_jsonl(
            input_path, "existing adjudication input"
        ) != input_rows:
            raise MachineReviewError(
                "existing adjudication input differs from reconstructed A/B/C reviews"
            )
        return existing
    if input_path.exists():
        raise MachineReviewError("partial adjudication input exists without its manifest")
    _write_jsonl(input_path, input_rows)
    result = {
        "schema_version": 1,
        "created_at": created_at or _utc_now(),
        "status": "BLIND_FIRST_FROZEN_READY_FOR_FINAL_ADJUDICATION",
        "identity": identity,
        "records": len(input_rows),
        "blind_run": c["proof"],
        "blind_prediction_sha256_by_id": c["prediction_sha256"],
        "blind_evidence_invalid_ids": sorted(c["evidence_errors"]),
        "blindness_transition": {
            "blind_prediction_frozen_before_a_b_exposure": True,
            "reviewer_identities_removed": True,
            "evaluated_agent_prediction_exposed": False,
        },
        "outputs": {
            "adjudication_input": {
                "path": input_path.relative_to(review_directory).as_posix(),
                "sha256": _sha256(input_path),
                "records": len(input_rows),
            }
        },
    }
    _write_json(manifest_path, result)
    return result


def _load_adjudication_preparation(
    review_directory: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = review_directory / "adjudicator-c" / "adjudication-preparation.json"
    manifest = _read_json(path, "adjudication preparation")
    if manifest.get("status") != "BLIND_FIRST_FROZEN_READY_FOR_FINAL_ADJUDICATION":
        raise MachineReviewError("adjudication preparation status is invalid")
    _check_stage_outputs(review_directory, manifest)
    input_path = _verify_file_identity(
        review_directory,
        manifest.get("outputs", {}).get("adjudication_input"),
        "adjudication input",
    )
    rows = _read_jsonl(input_path, "adjudication input")
    if len(rows) != manifest.get("records"):
        raise MachineReviewError("adjudication input count differs from manifest")
    return manifest, rows


def _allowed_evidence(row: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    blind = row.get("blind_first_prediction")
    if isinstance(blind, dict) and blind.get("evidence_valid") is True:
        candidates.extend(blind.get("evidence") or [])
    reviews = row.get("anonymous_reviews")
    if isinstance(reviews, list):
        for review in reviews:
            if isinstance(review, dict) and review.get("evidence_valid") is True:
                candidates.extend(review.get("evidence") or [])
    unique: dict[bytes, dict[str, Any]] = {}
    for candidate in candidates:
        if isinstance(candidate, dict):
            unique.setdefault(_canonical_bytes(candidate), candidate)
    return list(unique.values())


def _validate_final_response(response: Any, context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise MachineReviewError("adjudicator response must be an object")
    expected_keys = {
        "finding_id",
        "verdict",
        "confidence",
        "reason_codes",
        "reasoning",
        "evidence",
        "uncertainty_reason",
    }
    if set(response) != expected_keys:
        raise MachineReviewError("adjudicator response keys differ from the frozen schema")
    finding_id = context["finding_id"]
    if response.get("finding_id") != finding_id:
        raise MachineReviewError("adjudicator response finding_id differs")
    verdict = response.get("verdict")
    confidence = response.get("confidence")
    if verdict not in {"TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"}:
        raise MachineReviewError(f"adjudicator verdict is invalid: {finding_id}")
    if confidence not in CONFIDENCES:
        raise MachineReviewError(f"adjudicator confidence is invalid: {finding_id}")
    reasoning = response.get("reasoning")
    if not isinstance(reasoning, str) or not reasoning.strip() or len(reasoning) > 16_000:
        raise MachineReviewError(f"adjudicator reasoning is invalid: {finding_id}")
    reason_codes = response.get("reason_codes")
    if (
        not isinstance(reason_codes, list)
        or any(not isinstance(code, str) for code in reason_codes)
        or len(reason_codes) != len(set(reason_codes))
        or set(reason_codes) - FP_REASON_CODES
    ):
        raise MachineReviewError(f"adjudicator reason_codes are invalid: {finding_id}")
    evidence = response.get("evidence")
    if not isinstance(evidence, list) or len(evidence) > 12:
        raise MachineReviewError(f"adjudicator evidence is invalid: {finding_id}")
    allowed = {_canonical_bytes(node) for node in _allowed_evidence(context)}
    if any(not isinstance(node, dict) or _canonical_bytes(node) not in allowed for node in evidence):
        raise MachineReviewError(
            f"adjudicator cited evidence not exposed in A/B/C: {finding_id}"
        )
    if len({_canonical_bytes(node) for node in evidence}) != len(evidence):
        raise MachineReviewError(f"adjudicator evidence contains duplicates: {finding_id}")
    uncertainty_reason = response.get("uncertainty_reason")
    if verdict == "FALSE_POSITIVE":
        if not reason_codes or not evidence or uncertainty_reason is not None:
            raise MachineReviewError(f"adjudicator FP semantics are invalid: {finding_id}")
    elif verdict == "TRUE_POSITIVE":
        if reason_codes or not evidence or uncertainty_reason is not None:
            raise MachineReviewError(f"adjudicator TP semantics are invalid: {finding_id}")
    else:
        if reason_codes or not isinstance(uncertainty_reason, str) or not uncertainty_reason.strip():
            raise MachineReviewError(
                f"adjudicator UNCERTAIN semantics are invalid: {finding_id}"
            )
    return response


def _normalize_final_response_evidence(
    response: Any, context: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Canonicalize verdict fields and restore frozen evidence identities.

    Structured output guarantees the JSON shape but cannot express every
    cross-field verdict invariant in the provider-supported schema subset.  The
    provider response remains immutable.  The normalized decision discards only
    fields forbidden by the selected verdict and restores evidence only when an
    already-exposed frozen node can be selected unambiguously.  It never invents
    a required reason code, uncertainty explanation, or evidence node.
    """

    if not isinstance(response, dict):
        raise MachineReviewError("adjudicator response must be an object")
    normalized = copy.deepcopy(response)
    returned_finding_id = normalized.get("finding_id")
    expected_finding_id = context.get("finding_id")
    normalizations: list[dict[str, str]] = []
    if (
        isinstance(returned_finding_id, str)
        and isinstance(expected_finding_id, str)
        and returned_finding_id != expected_finding_id
    ):
        normalizations.append(
            {
                "operation": "RESTORE_FROZEN_CONTEXT_FINDING_ID_V1",
                "json_pointer": "/finding_id",
                "returned_sha256": _value_sha256(returned_finding_id),
                "canonical_sha256": _value_sha256(expected_finding_id),
                "match_keys": "case-context-sha256,frozen-finding-id",
            }
        )
        normalized["finding_id"] = expected_finding_id
    verdict = normalized.get("verdict")
    reason_codes = normalized.get("reason_codes")
    if (
        verdict in {"TRUE_POSITIVE", "UNCERTAIN"}
        and isinstance(reason_codes, list)
        and reason_codes
    ):
        normalizations.append(
            {
                "operation": "CLEAR_NON_FP_REASON_CODES_V1",
                "json_pointer": "/reason_codes",
                "returned_sha256": _value_sha256(reason_codes),
                "canonical_sha256": _value_sha256([]),
                "match_keys": "verdict",
            }
        )
        normalized["reason_codes"] = []
    uncertainty_reason = normalized.get("uncertainty_reason")
    if verdict in {"FALSE_POSITIVE", "TRUE_POSITIVE"} and uncertainty_reason is not None:
        normalizations.append(
            {
                "operation": "CLEAR_NON_UNCERTAIN_REASON_V1",
                "json_pointer": "/uncertainty_reason",
                "returned_sha256": _value_sha256(uncertainty_reason),
                "canonical_sha256": _value_sha256(None),
                "match_keys": "verdict",
            }
        )
        normalized["uncertainty_reason"] = None
    evidence = normalized.get("evidence")
    if not isinstance(evidence, list):
        return _validate_final_response(normalized, context), normalizations
    allowed = _allowed_evidence(context)
    allowed_bytes = {_canonical_bytes(node) for node in allowed}

    def sequential_numbered_code(value: Any) -> list[tuple[int, str]] | None:
        if not isinstance(value, str):
            return None
        parsed: list[tuple[int, str]] = []
        for line in value.splitlines():
            match = re.fullmatch(r"([1-9][0-9]*):(.*)", line)
            if match is None:
                return None
            parsed.append((int(match.group(1)), match.group(2).strip()))
        if not parsed or [number for number, _ in parsed] != list(
            range(parsed[0][0], parsed[-1][0] + 1)
        ):
            return None
        return parsed

    def numbered_code(
        value: Any, *, expected_start: int, expected_end: int
    ) -> list[tuple[int, str]] | None:
        parsed = sequential_numbered_code(value)
        if parsed is None:
            return None
        if [number for number, _ in parsed] != list(
            range(expected_start, expected_end + 1)
        ):
            return None
        return parsed

    for index, node in enumerate(evidence):
        if not isinstance(node, dict) or _canonical_bytes(node) in allowed_bytes:
            continue
        candidates = [
            candidate
            for candidate in allowed
            if all(
                node.get(key) == candidate.get(key)
                for key in ("file", "line", "description")
            )
        ]
        operation = "RESTORE_UNIQUE_FROZEN_EVIDENCE_NODE_V1"
        match_keys = "file,line,description"
        if len(candidates) != 1 and isinstance(node, dict):
            source_identity_candidates = [
                candidate
                for candidate in allowed
                if candidate.get("file") == node.get("file")
                and candidate.get("line") == node.get("line")
            ]
            frozen_codes = {
                candidate.get("code") for candidate in source_identity_candidates
            }
            if source_identity_candidates and len(frozen_codes) == 1:
                candidates = [source_identity_candidates[0]]
                operation = "RESTORE_UNAMBIGUOUS_FROZEN_SOURCE_IDENTITY_NODE_V1"
                match_keys = "file,line,unique-frozen-code,first-exposed-representative"
        if len(candidates) != 1 and isinstance(node, dict):
            frozen_code_candidates = [
                candidate
                for candidate in allowed
                if candidate.get("file") == node.get("file")
                and candidate.get("code") == node.get("code")
            ]
            if len(frozen_code_candidates) == 1:
                candidates = frozen_code_candidates
                operation = "RESTORE_UNIQUE_FROZEN_CODE_IDENTITY_NODE_V1"
                match_keys = "file,exact-frozen-code"
        if len(candidates) != 1 and isinstance(node, dict):
            returned_numbered_code = sequential_numbered_code(node.get("code"))
            numbered_code_candidates = []
            if returned_numbered_code is not None:
                numbered_code_candidates = [
                    candidate
                    for candidate in allowed
                    if candidate.get("file") == node.get("file")
                    and sequential_numbered_code(candidate.get("code"))
                    == returned_numbered_code
                ]
            if len(numbered_code_candidates) == 1:
                candidates = numbered_code_candidates
                operation = "RESTORE_UNIQUE_NUMBERED_FROZEN_CODE_NODE_V1"
                match_keys = "file,sequential-numbered-code-trimmed"
        if len(candidates) != 1 and isinstance(node, dict):
            try:
                returned_start, returned_end = parse_trace_line(
                    node.get("line"), "returned adjudicator evidence"
                )
            except ValueError:
                returned_start, returned_end = 0, -1
            returned_code = numbered_code(
                node.get("code"),
                expected_start=returned_start,
                expected_end=returned_end,
            )
            containing: list[tuple[int, dict[str, Any]]] = []
            if returned_code is not None:
                for candidate in allowed:
                    if candidate.get("file") != node.get("file"):
                        continue
                    try:
                        candidate_start, candidate_end = parse_trace_line(
                            candidate.get("line"), "frozen adjudicator evidence"
                        )
                    except ValueError:
                        continue
                    if not (
                        candidate_start <= returned_start
                        and candidate_end >= returned_end
                    ):
                        continue
                    candidate_code = numbered_code(
                        candidate.get("code"),
                        expected_start=candidate_start,
                        expected_end=candidate_end,
                    )
                    if candidate_code is None:
                        continue
                    sliced = [
                        pair
                        for pair in candidate_code
                        if returned_start <= pair[0] <= returned_end
                    ]
                    if sliced == returned_code:
                        containing.append(
                            (candidate_end - candidate_start, candidate)
                        )
            if containing:
                tightest_width = min(width for width, _ in containing)
                candidates = [
                    candidate
                    for width, candidate in containing
                    if width == tightest_width
                ]
                operation = (
                    "RESTORE_UNIQUE_TIGHTEST_CONTAINING_FROZEN_EVIDENCE_NODE_V1"
                )
                match_keys = (
                    "file,contained-line-range,numbered-code-trimmed,tightest-span"
                )
        if len(candidates) != 1 and verdict == "UNCERTAIN":
            normalizations.append(
                {
                    "operation": "CLEAR_UNEXPOSED_UNCERTAIN_EVIDENCE_NODE_V1",
                    "json_pointer": f"/evidence/{index}",
                    "returned_sha256": _value_sha256(node),
                    "canonical_sha256": _value_sha256(None),
                    "match_keys": "verdict,not-in-frozen-A-B-C-evidence",
                }
            )
            evidence[index] = None
            continue
        if len(candidates) != 1:
            raise MachineReviewError(
                "adjudicator cited evidence not exposed in A/B/C: "
                f"{context['finding_id']}"
            )
        canonical = copy.deepcopy(candidates[0])
        normalizations.append(
            {
                "operation": operation,
                "json_pointer": f"/evidence/{index}",
                "returned_sha256": _value_sha256(node),
                "canonical_sha256": _value_sha256(canonical),
                "match_keys": match_keys,
            }
        )
        evidence[index] = canonical
    evidence[:] = [node for node in evidence if node is not None]
    return _validate_final_response(normalized, context), normalizations


def _new_adjudicator_provider(*, provider_id: str, **kwargs: Any) -> Any:
    if provider_id == GEMINI_PROVIDER_ID:
        from .gemini_verifier_agent import GeminiApiProvider

        return GeminiApiProvider(**kwargs)
    if provider_id == OPENAI_PROVIDER_ID:
        from .openai_verifier_agent import OpenAIResponsesProvider

        return OpenAIResponsesProvider(
            response_schema=kwargs["response_schema"],
            prompt_text=kwargs["prompt_text"],
            timeout_seconds=kwargs["timeout_seconds"],
            model=kwargs["model"],
            reasoning_effort=kwargs["thinking_level"],
            max_attempts=kwargs["max_attempts"],
        )
    raise MachineReviewError("unsupported adjudicator provider")


def _case_key(finding_id: str) -> str:
    return hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:20]


def _adjudication_case_identity(
    context: dict[str, Any], *, run_identity_sha256: str
) -> dict[str, Any]:
    return {
        "finding_id": context["finding_id"],
        "context_sha256": _value_sha256(context),
        "run_identity_sha256": run_identity_sha256,
    }


def _adjudication_metadata(
    provider: Any, case_directory: Path, expected_model_version: str
) -> dict[str, Any]:
    metadata = provider.response_metadata(case_directory, 1)
    if metadata.get("model_version") != expected_model_version:
        raise MachineReviewError(
            "adjudicator C final model_version differs from its blind-first run"
        )
    return metadata


def adjudicate(
    *,
    review_directory: Path,
    prompt_path: Path,
    response_schema_path: Path,
    model: str,
    thinking_level: str,
    temperature: float,
    seed: int,
    timeout_seconds: int = 180,
    max_attempts: int = 3,
) -> dict[str, Any]:
    review_directory = review_directory.resolve()
    _load_machine_manifest(review_directory)
    preparation, contexts = _load_adjudication_preparation(review_directory)
    config = _frozen_config(review_directory, "ADJUDICATOR_C")
    if (
        model != config["model"]
        or thinking_level.casefold() != config["thinking_level"]
        or float(temperature) != config["temperature"]
        or seed != config["seed"]
    ):
        raise MachineReviewError("final adjudicator settings differ from frozen config")
    prompt_path = prompt_path.resolve(strict=True)
    response_schema_path = response_schema_path.resolve(strict=True)
    if (
        _sha256(prompt_path)
        != _sha256(IMPLEMENTATION_SOURCES["machine-adjudicator-prompt-v1.md"])
        or _sha256(response_schema_path)
        != _sha256(
            IMPLEMENTATION_SOURCES["machine-adjudicator-response.schema.json"]
        )
    ):
        raise MachineReviewError(
            "final adjudicator prompt/schema differ from the frozen methodology"
        )
    input_path = _verify_file_identity(
        review_directory,
        preparation["outputs"]["adjudication_input"],
        "adjudication input",
    )
    prompt_text = prompt_path.read_text(encoding="utf-8")
    provider = _new_adjudicator_provider(
        provider_id=config["provider"],
        response_schema=response_schema_path,
        prompt_text=prompt_text,
        timeout_seconds=timeout_seconds,
        model=model,
        thinking_level=thinking_level,
        seed=seed,
        temperature=temperature,
        max_attempts=max_attempts,
    )
    provider_sdk_version = getattr(provider, "sdk_version", None)
    if (
        provider.provider_id != config["provider"]
        or provider_sdk_version != config["provider_version"]
        or provider.model != config["model"]
    ):
        raise MachineReviewError("final adjudicator provider differs from frozen config")
    final_directory = review_directory / "adjudicator-c" / "final"
    run_identity = {
        "schema_version": 1,
        "protocol": "machine-adjudication-final-v1",
        "input_sha256": _sha256(input_path),
        "records": len(contexts),
        "prompt_sha256": _sha256(prompt_path),
        "response_schema_sha256": _sha256(response_schema_path),
        "provider": {
            "id": provider.provider_id,
            "version": provider.version,
            "sdk_version": provider_sdk_version,
            "model": provider.model,
            "configuration": getattr(provider, "configuration", None),
            "configuration_sha256": getattr(provider, "configuration_sha256", None),
        },
        "blind_first_model_version": preparation["identity"]["blind_model_version"],
    }
    identity_path = final_directory / "run-identity.json"
    if identity_path.exists():
        if _read_json(identity_path, "final adjudicator run identity") != run_identity:
            raise MachineReviewError("final adjudicator run identity differs")
    elif final_directory.exists() and any(final_directory.iterdir()):
        raise MachineReviewError("non-empty final adjudicator run has no identity")
    else:
        _write_json(identity_path, run_identity)
    run_identity_sha256 = _sha256(identity_path)
    context_ids = _ordered_ids(contexts, "adjudication contexts")
    decisions: dict[str, dict[str, Any]] = {}
    statuses: list[dict[str, Any]] = []
    actual_versions: set[str] = set()
    response_ids: set[str] = set()
    usage: defaultdict[str, int] = defaultdict(int)
    for position, context in enumerate(contexts, 1):
        finding_id = str(context["finding_id"])
        case_directory = final_directory / "cases" / _case_key(finding_id)
        status_path = case_directory / "status.json"
        decision_path = case_directory / "decision.json"
        case_identity = _adjudication_case_identity(
            context, run_identity_sha256=run_identity_sha256
        )
        if status_path.exists():
            status = _read_json(status_path, "final adjudicator case status")
            if status.get("identity") != case_identity:
                raise MachineReviewError(
                    f"final adjudicator case identity differs: {finding_id}"
                )
            if status.get("status") == "SUCCESS":
                response_path = case_directory / "step-01-response.json"
                if (
                    not decision_path.is_file()
                    or _sha256(decision_path) != status.get("decision_sha256")
                    or not response_path.is_file()
                    or _sha256(response_path) != status.get("response_sha256")
                ):
                    raise MachineReviewError(
                        f"final adjudicator decision proof differs: {finding_id}"
                    )
                provider_response = _read_json(
                    response_path, "final adjudicator provider response"
                )
                expected_decision, expected_normalizations = (
                    _normalize_final_response_evidence(provider_response, context)
                )
                decision = _validate_final_response(
                    _read_json(decision_path, "final adjudicator decision"), context
                )
                if (
                    expected_decision != decision
                    or status.get("evidence_normalizations", [])
                    != expected_normalizations
                ):
                    raise MachineReviewError(
                        f"final adjudicator response normalization proof differs: {finding_id}"
                    )
                metadata = _adjudication_metadata(
                    provider,
                    case_directory,
                    preparation["identity"]["blind_model_version"],
                )
                if _sha256(case_directory / "step-01-provider-metadata.json") != status.get(
                    "provider_metadata_sha256"
                ):
                    raise MachineReviewError(
                        f"final adjudicator metadata proof differs: {finding_id}"
                    )
                decisions[finding_id] = decision
                statuses.append(status)
                actual_versions.add(metadata["model_version"])
                if metadata["response_id"] in response_ids:
                    raise MachineReviewError("duplicate final adjudicator response_id")
                response_ids.add(metadata["response_id"])
                for key, value in (metadata.get("normalized_usage") or {}).items():
                    if isinstance(value, int) and not isinstance(value, bool):
                        usage[str(key)] += value
                print(f"[{position}/{len(contexts)}] reuse {finding_id}")
                continue
        case_directory.mkdir(parents=True, exist_ok=True)
        running = {
            "schema_version": 1,
            "status": "RUNNING",
            "identity": case_identity,
            "started_at": _utc_now(),
        }
        _write_json(status_path, running)
        print(f"[{position}/{len(contexts)}] adjudicate {finding_id}")
        try:
            response = provider.complete(
                {
                    "protocol_version": 1,
                    "task": "finalize_blind_first_machine_adjudication",
                    "finding_id": finding_id,
                    "untrusted_adjudication_context": context,
                    "rules": {
                        "output_must_match_response_schema": True,
                        "cite_only_exact_exposed_evidence": True,
                        "uncertainty_is_preserved": True,
                        "known_or_novel_linkage_forbidden": True,
                    },
                },
                case_directory=case_directory,
                step=1,
            )
            decision, evidence_normalizations = _normalize_final_response_evidence(
                response, context
            )
            metadata = _adjudication_metadata(
                provider,
                case_directory,
                preparation["identity"]["blind_model_version"],
            )
            if metadata["response_id"] in response_ids:
                raise MachineReviewError("duplicate final adjudicator response_id")
            response_ids.add(metadata["response_id"])
            actual_versions.add(metadata["model_version"])
            _write_json(decision_path, decision)
            status = {
                "schema_version": 1,
                "status": "SUCCESS",
                "identity": case_identity,
                "started_at": running["started_at"],
                "completed_at": _utc_now(),
                "decision_sha256": _sha256(decision_path),
                "response_sha256": _sha256(
                    case_directory / "step-01-response.json"
                ),
                "provider_metadata_sha256": _sha256(
                    case_directory / "step-01-provider-metadata.json"
                ),
                "raw_response_sha256": _sha256(
                    case_directory / "step-01-raw-response.json"
                ),
                "response_id": metadata["response_id"],
                "model_version": metadata["model_version"],
                "usage": metadata.get("normalized_usage") or {},
                "evidence_normalizations": evidence_normalizations,
            }
            _write_json(status_path, status)
            decisions[finding_id] = decision
            statuses.append(status)
            for key, value in (metadata.get("normalized_usage") or {}).items():
                if isinstance(value, int) and not isinstance(value, bool):
                    usage[str(key)] += value
        except BaseException as exc:
            _write_json(
                status_path,
                {
                    **running,
                    "status": "FAILED",
                    "completed_at": _utc_now(),
                    "error_type": type(exc).__name__,
                    "error_code": "FINAL_ADJUDICATION_FAILED",
                },
            )
            raise
        finally:
            close_case = getattr(provider, "close_case", None)
            if callable(close_case):
                close_case(case_directory)
    if set(decisions) != set(context_ids) or len(statuses) != len(contexts):
        raise MachineReviewError("final adjudicator decisions do not exactly cover input")
    if actual_versions != {preparation["identity"]["blind_model_version"]}:
        raise MachineReviewError("final adjudicator model_version is inconsistent")
    decisions_path = final_directory / "machine-adjudication-decisions.jsonl"
    _write_jsonl(decisions_path, [decisions[finding_id] for finding_id in context_ids])
    run_manifest = {
        "schema_version": 1,
        "created_at": _utc_now(),
        "status": "COMPLETE",
        "complete": True,
        "input": {
            "path": _portable_path(input_path, review_directory),
            "sha256": _sha256(input_path),
            "records": len(contexts),
        },
        "run_identity": {"path": identity_path.name, "sha256": run_identity_sha256},
        "prompt": {"path": str(prompt_path), "sha256": _sha256(prompt_path)},
        "response_schema": {
            "path": str(response_schema_path),
            "sha256": _sha256(response_schema_path),
        },
        "provider": {
            "id": provider.provider_id,
            "version": provider.version,
            "sdk_version": provider_sdk_version,
            "requested_model": provider.model,
            "model_version": next(iter(actual_versions)),
            "thinking_level": thinking_level.casefold(),
            "temperature": float(temperature),
            "seed": seed,
            "usage": dict(sorted(usage.items())),
        },
        "case_counts": {"total": len(contexts), "success": len(contexts), "failed": 0},
        "decisions": {
            "path": decisions_path.name,
            "sha256": _sha256(decisions_path),
            "records": len(contexts),
        },
        "artifacts": _artifact_inventory(final_directory),
    }
    _write_json(final_directory / "machine-adjudication-run.json", run_manifest)
    return run_manifest


def _participant(config: dict[str, Any], proof: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": config["id"],
        "provider": config["provider"],
        "provider_version": proof["provider_version"],
        "model": config["model"],
        "model_version": proof["model_version"],
    }


def _consensus_reviewer(
    a_config: dict[str, Any],
    b_config: dict[str, Any],
    a_proof: dict[str, Any],
    b_proof: dict[str, Any],
) -> dict[str, Any]:
    participants = [_participant(a_config, a_proof), _participant(b_config, b_proof)]
    return {
        "id": "reviewer-a+reviewer-b",
        "kind": "MODEL",
        "role": "CONSENSUS_A_B",
        "provider": "MULTIPLE_MODELS",
        "provider_version": _value_sha256(
            [participant["provider_version"] for participant in participants]
        ),
        "model": "+".join(participant["model"] for participant in participants),
        "model_version": "+".join(
            participant["model_version"] for participant in participants
        ),
        "participants": participants,
    }


def _adjudicator_reviewer(config: dict[str, Any], proof: dict[str, Any]) -> dict[str, Any]:
    participant = _participant(config, proof)
    return {
        **participant,
        "kind": "MODEL",
        "role": "ADJUDICATOR_C",
        "participants": [participant],
    }


def _final_decisions(
    final_directory: Path,
    expected_ids: list[str],
    contexts: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, str]]:
    run_path = final_directory / "machine-adjudication-run.json"
    run = _read_json(run_path, "machine adjudication run")
    counts = run.get("case_counts")
    if (
        run.get("status") != "COMPLETE"
        or run.get("complete") is not True
        or not isinstance(counts, dict)
        or counts.get("total") != len(expected_ids)
        or counts.get("success") != len(expected_ids)
        or counts.get("failed") != 0
    ):
        raise MachineReviewError("machine adjudication run is not complete")
    proof = run.get("decisions")
    if not isinstance(proof, dict):
        raise MachineReviewError("machine adjudication run has no decisions proof")
    path = final_directory / str(proof.get("path") or "")
    if (
        not path.is_file()
        or _sha256(path) != proof.get("sha256")
        or proof.get("records") != len(expected_ids)
    ):
        raise MachineReviewError("machine adjudication decisions proof is invalid")
    rows = _read_jsonl(path, "machine adjudication decisions")
    if _ordered_ids(rows, "machine adjudication decisions") != expected_ids:
        raise MachineReviewError("machine adjudication decisions do not exactly cover routed IDs")
    decisions: dict[str, dict[str, Any]] = {}
    hashes: dict[str, str] = {}
    provider = run.get("provider")
    if not isinstance(provider, dict):
        raise MachineReviewError("machine adjudication provider proof is missing")
    identity_proof = run.get("run_identity")
    if not isinstance(identity_proof, dict) or identity_proof.get("path") != "run-identity.json":
        raise MachineReviewError("machine adjudication run identity proof is invalid")
    identity_path = final_directory / "run-identity.json"
    if (
        not identity_path.is_file()
        or identity_proof.get("sha256") != _sha256(identity_path)
    ):
        raise MachineReviewError("machine adjudication run identity changed")
    identity = _read_json(identity_path, "machine adjudication run identity")
    identity_provider = identity.get("provider")
    if (
        identity.get("schema_version") != 1
        or identity.get("protocol") != "machine-adjudication-final-v1"
        or identity.get("records") != len(expected_ids)
        or not isinstance(identity_provider, dict)
        or identity_provider.get("id") != provider.get("id")
        or identity_provider.get("version") != provider.get("version")
        or identity_provider.get("sdk_version") != provider.get("sdk_version")
        or identity_provider.get("model") != provider.get("requested_model")
    ):
        raise MachineReviewError("machine adjudication immutable identity differs")
    provider_sidecar_name = {
        GEMINI_PROVIDER_ID: "gemini-provider-configuration.json",
        OPENAI_PROVIDER_ID: "openai-provider-configuration.json",
    }.get(str(provider.get("id")))
    if provider_sidecar_name is None:
        raise MachineReviewError("final adjudicator provider is unsupported")
    provider_sidecar_path = final_directory / provider_sidecar_name
    provider_sidecar = _read_json(
        provider_sidecar_path, "final adjudicator provider configuration"
    )
    if (
        provider_sidecar.get("provider") != provider.get("id")
        or provider_sidecar.get("provider_version") != provider.get("version")
        or provider_sidecar.get("sdk_version") != provider.get("sdk_version")
        or provider_sidecar.get("configuration")
        != identity_provider.get("configuration")
        or provider_sidecar.get("configuration_sha256")
        != identity_provider.get("configuration_sha256")
        or provider_sidecar.get("configuration_sha256")
        != _value_sha256(provider_sidecar.get("configuration"))
    ):
        raise MachineReviewError("final adjudicator provider configuration differs")
    response_ids: set[str] = set()
    aggregate_usage: defaultdict[str, int] = defaultdict(int)
    contexts_by_id = {str(context["finding_id"]): context for context in contexts}
    if set(contexts_by_id) != set(expected_ids):
        raise MachineReviewError("final adjudicator contexts differ from expected IDs")
    for row in rows:
        finding_id = str(row["finding_id"])
        case_directory = final_directory / "cases" / _case_key(finding_id)
        status = _read_json(case_directory / "status.json", "final case status")
        decision_path = case_directory / "decision.json"
        response_path = case_directory / "step-01-response.json"
        metadata_path = case_directory / "step-01-provider-metadata.json"
        raw_path = case_directory / "step-01-raw-response.json"
        metadata = _read_json(metadata_path, "final provider metadata")
        provider_response = _read_json(response_path, "final provider response")
        expected_decision, expected_normalizations = _normalize_final_response_evidence(
            provider_response, contexts_by_id[finding_id]
        )
        if (
            status.get("status") != "SUCCESS"
            or status.get("identity", {}).get("finding_id") != finding_id
            or not decision_path.is_file()
            or _sha256(decision_path) != status.get("decision_sha256")
            or _read_json(decision_path, "final case decision") != row
            or not response_path.is_file()
            or _sha256(response_path) != status.get("response_sha256")
            or expected_decision != row
            or status.get("evidence_normalizations", []) != expected_normalizations
            or _sha256(metadata_path) != status.get("provider_metadata_sha256")
            or not raw_path.is_file()
            or _sha256(raw_path) != status.get("raw_response_sha256")
            or metadata.get("provider") != provider.get("id")
            or metadata.get("provider_version") != provider.get("version")
            or metadata.get("sdk_version") != provider.get("sdk_version")
            or metadata.get("configured_model") != provider.get("requested_model")
            or metadata.get("configuration") != provider_sidecar.get("configuration")
            or metadata.get("configuration_sha256")
            != provider_sidecar.get("configuration_sha256")
            or metadata.get("model_version") != provider.get("model_version")
            or metadata.get("response_id") != status.get("response_id")
            or metadata.get("normalized_usage") != status.get("usage")
        ):
            raise MachineReviewError(
                f"final adjudicator case/provider proof is invalid: {finding_id}"
            )
        raw_proof = metadata.get("raw_response")
        if (
            not isinstance(raw_proof, dict)
            or raw_proof.get("path") != raw_path.name
            or raw_proof.get("bytes") != raw_path.stat().st_size
            or raw_proof.get("sha256") != _sha256(raw_path)
        ):
            raise MachineReviewError(
                f"final adjudicator raw-response proof is invalid: {finding_id}"
            )
        response_id = metadata.get("response_id")
        if not isinstance(response_id, str) or not response_id or response_id in response_ids:
            raise MachineReviewError("final adjudicator response IDs are invalid/duplicate")
        response_ids.add(response_id)
        for usage_name, usage_value in (
            metadata.get("normalized_usage") or {}
        ).items():
            if (
                isinstance(usage_value, int)
                and not isinstance(usage_value, bool)
                and usage_value >= 0
            ):
                aggregate_usage[str(usage_name)] += usage_value
        decisions[finding_id] = row
        hashes[finding_id] = _value_sha256(row)
    if run.get("artifacts") != _artifact_inventory(final_directory):
        raise MachineReviewError("final adjudicator artifact inventory changed")
    if provider.get("usage") != dict(sorted(aggregate_usage.items())):
        raise MachineReviewError("final adjudicator aggregate provider usage differs")
    return run, decisions, hashes


def _run_directory_from_proof(
    review_directory: Path, proof: dict[str, Any], label: str
) -> Path:
    relative = proof.get("run_directory")
    if (
        not isinstance(relative, str)
        or not relative
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
    ):
        raise MachineReviewError(f"{label} frozen run path is invalid")
    run_directory = (review_directory / relative).resolve()
    _safe_relative_to(run_directory, review_directory, label)
    return run_directory


def _verify_run_proof_current(
    review_directory: Path, proof: dict[str, Any], label: str
) -> None:
    run_directory = _run_directory_from_proof(review_directory, proof, label)
    provider_configuration_name = {
        GEMINI_PROVIDER_ID: "gemini-provider-configuration.json",
        OPENAI_PROVIDER_ID: "openai-provider-configuration.json",
        "MIGRATED_GEMINI_SUPPLEMENT_COMPOSITE": "gemini-provider-configuration.json",
        "IMPORTED_R7_COMPOSITE": "gemini-provider-configuration.json",
        "MIGRATED_OPENAI_ADJUDICATOR_COMPOSITE": "openai-provider-configuration.json",
        "IMPORTED_R9_ADJUDICATOR_COMPOSITE": "openai-provider-configuration.json",
    }.get(str(proof.get("provider")))
    if provider_configuration_name is None:
        raise MachineReviewError(f"{label} provider proof is unsupported")
    checks = {
        "verifier-run.json": "verifier_run_sha256",
        "run-identity.json": "run_identity_sha256",
        provider_configuration_name: "provider_configuration_sha256",
        "blind-verifier-input.jsonl": "input_sha256",
        "verifier-predictions.jsonl": "predictions_sha256",
    }
    for name, key in checks.items():
        path = run_directory / name
        if not path.is_file() or _sha256(path) != proof.get(key):
            raise MachineReviewError(f"{label} changed after it was frozen: {name}")
    if proof.get("artifacts") != _artifact_inventory(run_directory):
        raise MachineReviewError(f"{label} raw/provider artifact inventory changed")


def _validate_machine_labels_schema(rows: list[dict[str, Any]], schema_path: Path) -> None:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:
        raise MachineReviewError("jsonschema is required to finalize machine labels") from exc
    schema = _read_json(schema_path, "machine-reference schema")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for row in rows:
        error = next(validator.iter_errors(row), None)
        if error is not None:
            raise MachineReviewError(
                f"machine-reference schema error for {row.get('finding_id')}: {error.message}"
            )


def finalize_review(
    *,
    review_directory: Path,
    final_run: Path | None = None,
    reviewed_at: str | None = None,
) -> dict[str, Any]:
    review_directory = review_directory.resolve()
    labels_path = review_directory / "machine-reference-labels.jsonl"
    summary_path = review_directory / "machine-review-summary.json"
    existing_summary = (
        _read_json(summary_path, "machine-review summary")
        if summary_path.is_file()
        else None
    )
    manifest = _load_machine_manifest(review_directory)
    reconciliation_summary, reconciliation = _load_reconciliation(review_directory)
    reviewer_runs = reconciliation_summary.get("reviewer_runs")
    if not isinstance(reviewer_runs, dict):
        raise MachineReviewError("reconciliation has no reviewer run proofs")
    a_stage_proof = reviewer_runs.get("reviewer_a")
    b_stage_proof = reviewer_runs.get("reviewer_b")
    if not isinstance(a_stage_proof, dict) or not isinstance(b_stage_proof, dict):
        raise MachineReviewError("reconciliation reviewer run proofs are invalid")
    # Re-run the deterministic reconciliation gate.  When its summary already
    # exists this is read-only and compares the stored queue byte-for-value with
    # a fresh reconstruction from the frozen A/B runs.
    reconcile_reviews(
        review_directory=review_directory,
        reviewer_a_run=_run_directory_from_proof(
            review_directory, a_stage_proof, "reviewer A run"
        ),
        reviewer_b_run=_run_directory_from_proof(
            review_directory, b_stage_proof, "reviewer B run"
        ),
    )
    reconciliation_summary, reconciliation = _load_reconciliation(review_directory)
    findings, _ = _frozen_rows(review_directory)
    original_ids = _ordered_ids(findings, "frozen sample")
    reconciliation_by_id = {str(row["finding_id"]): row for row in reconciliation}
    if set(reconciliation_by_id) != set(original_ids):
        raise MachineReviewError("reconciliation no longer covers the frozen sample")
    routed_ids = [
        finding_id
        for finding_id in original_ids
        if reconciliation_by_id[finding_id]["routed_to_adjudicator"] is True
    ]
    a_config = _frozen_config(review_directory, "REVIEWER_A")
    b_config = _frozen_config(review_directory, "REVIEWER_B")
    c_config = _frozen_config(review_directory, "ADJUDICATOR_C")
    a_proof = reconciliation_summary["reviewer_runs"]["reviewer_a"]
    b_proof = reconciliation_summary["reviewer_runs"]["reviewer_b"]
    _verify_run_proof_current(review_directory, a_proof, "reviewer A run")
    _verify_run_proof_current(review_directory, b_proof, "reviewer B run")

    preparation: dict[str, Any] | None = None
    final_manifest: dict[str, Any] | None = None
    decisions: dict[str, dict[str, Any]] = {}
    decision_hashes: dict[str, str] = {}
    c_proof: dict[str, Any] | None = None
    final_directory: Path | None = None
    if routed_ids:
        preparation, contexts = _load_adjudication_preparation(review_directory)
        blind_stage_proof = preparation.get("blind_run")
        if not isinstance(blind_stage_proof, dict):
            raise MachineReviewError("adjudication preparation has no blind-run proof")
        # Likewise reconstruct the post-blind A/B exposure input from the
        # immutable C prediction before trusting it during finalization.
        prepare_adjudication(
            review_directory=review_directory,
            blind_run=_run_directory_from_proof(
                review_directory,
                blind_stage_proof,
                "adjudicator C blind run",
            ),
        )
        preparation, contexts = _load_adjudication_preparation(review_directory)
        _verify_run_proof_current(
            review_directory, preparation["blind_run"], "adjudicator C blind run"
        )
        if _ordered_ids(contexts, "adjudication contexts") != routed_ids:
            raise MachineReviewError("adjudication input differs from routed IDs/order")
        final_directory = (final_run or review_directory / "adjudicator-c" / "final").resolve()
        _safe_relative_to(final_directory, review_directory, "final adjudicator run")
        final_manifest, decisions, decision_hashes = _final_decisions(
            final_directory, routed_ids, contexts
        )
        final_input = final_manifest.get("input")
        final_prompt = final_manifest.get("prompt")
        final_schema = final_manifest.get("response_schema")
        expected_input = preparation["outputs"]["adjudication_input"]
        if (
            not isinstance(final_input, dict)
            or final_input.get("path") != expected_input.get("path")
            or final_input.get("sha256") != expected_input.get("sha256")
            or final_input.get("records") != len(routed_ids)
            or not isinstance(final_prompt, dict)
            or final_prompt.get("sha256")
            != _sha256(IMPLEMENTATION_SOURCES["machine-adjudicator-prompt-v1.md"])
            or not isinstance(final_schema, dict)
            or final_schema.get("sha256")
            != _sha256(
                IMPLEMENTATION_SOURCES[
                    "machine-adjudicator-response.schema.json"
                ]
            )
        ):
            raise MachineReviewError(
                "final adjudicator input/prompt/schema proof differs"
            )
        final_identity_document = _read_json(
            final_directory / "run-identity.json",
            "final adjudicator run identity",
        )
        if (
            final_identity_document.get("input_sha256")
            != expected_input.get("sha256")
            or final_identity_document.get("records") != len(routed_ids)
            or final_identity_document.get("prompt_sha256")
            != final_prompt.get("sha256")
            or final_identity_document.get("response_schema_sha256")
            != final_schema.get("sha256")
            or final_identity_document.get("blind_first_model_version")
            != preparation["identity"]["blind_model_version"]
        ):
            raise MachineReviewError("final adjudicator run identity is inconsistent")
        provider = final_manifest.get("provider")
        if not isinstance(provider, dict):
            raise MachineReviewError("final adjudicator has no provider proof")
        if (
            provider.get("id") != c_config["provider"]
            or provider.get("sdk_version") != c_config["provider_version"]
            or provider.get("requested_model") != c_config["model"]
            or provider.get("model_version")
            != preparation["identity"]["blind_model_version"]
            or provider.get("thinking_level") != c_config["thinking_level"]
            or provider.get("temperature") != c_config["temperature"]
            or provider.get("seed") != c_config["seed"]
        ):
            raise MachineReviewError("final adjudicator provider/actual model proof differs")
        contexts_by_id = {str(row["finding_id"]): row for row in contexts}
        for finding_id, decision in decisions.items():
            _validate_final_response(decision, contexts_by_id[finding_id])
        c_proof = {
            **preparation["blind_run"],
            "provider_version": provider["version"],
            "model_version": provider["model_version"],
            "final_run_sha256": _sha256(
                final_directory / "machine-adjudication-run.json"
            ),
            "final_decisions_sha256": final_manifest["decisions"]["sha256"],
            "final_prompt_sha256": final_manifest["prompt"]["sha256"],
            "final_response_schema_sha256": final_manifest["response_schema"][
                "sha256"
            ],
        }

    frozen_timestamp = (
        existing_summary.get("created_at")
        if isinstance(existing_summary, dict)
        else None
    )
    timestamp = reviewed_at or frozen_timestamp or _utc_now()
    if not isinstance(timestamp, str) or not timestamp:
        raise MachineReviewError("reviewed_at must be a non-empty timestamp")
    parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed_timestamp.tzinfo is None:
        raise MachineReviewError("reviewed_at must include a timezone")
    consensus_reviewer = _consensus_reviewer(
        a_config, b_config, a_proof, b_proof
    )
    adjudicator_reviewer = (
        _adjudicator_reviewer(c_config, c_proof) if c_proof is not None else None
    )
    labels: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for finding_id in original_ids:
        reconciliation_row = reconciliation_by_id[finding_id]
        pa_hash = reconciliation_row["prediction_sha256"]["reviewer_a"]
        pb_hash = reconciliation_row["prediction_sha256"]["reviewer_b"]
        reasons = reconciliation_row["route_reasons"]
        if reasons:
            decision = decisions[finding_id]
            verdict = decision["verdict"]
            label = {
                "TRUE_POSITIVE": "MACHINE_TRUE_POSITIVE",
                "FALSE_POSITIVE": "MACHINE_FALSE_POSITIVE",
                "UNCERTAIN": "MACHINE_UNCERTAIN",
            }[verdict]
            confidence = decision["confidence"]
            reason_codes = decision["reason_codes"]
            reasoning = decision["reasoning"]
            evidence = decision["evidence"]
            uncertainty_reason = decision["uncertainty_reason"]
            reviewer = adjudicator_reviewer
            assert reviewer is not None and preparation is not None
            blind_hash = preparation["blind_prediction_sha256_by_id"][finding_id]
            final_hash = decision_hashes[finding_id]
            blind_first = True
        else:
            pa = reconciliation_row["reviewer_a"]
            pb = reconciliation_row["reviewer_b"]
            if (
                pa["verdict"] != "FALSE_POSITIVE"
                or pb["verdict"] != "FALSE_POSITIVE"
                or pa["confidence"] != "HIGH"
                or pb["confidence"] != "HIGH"
                or not pa["evidence_valid"]
                or not pb["evidence_valid"]
            ):
                raise MachineReviewError(f"invalid non-routed consensus: {finding_id}")
            label = "MACHINE_FALSE_POSITIVE"
            confidence = "HIGH"
            reason_codes = sorted(set(pa["reason_codes"]) | set(pb["reason_codes"]))
            reasoning = (
                "Two independently ordered model reviewers reached a HIGH-confidence "
                "FALSE_POSITIVE consensus with source-verified evidence. Reviewer A: "
                f"{pa['reasoning']} Reviewer B: {pb['reasoning']}"
            )
            evidence = []
            seen: set[bytes] = set()
            for node in [*pa["evidence"], *pb["evidence"]]:
                encoded = _canonical_bytes(node)
                if encoded not in seen:
                    evidence.append(node)
                    seen.add(encoded)
            if len(evidence) > 12:
                evidence = evidence[:12]
            uncertainty_reason = None
            reviewer = consensus_reviewer
            blind_hash = None
            final_hash = None
            blind_first = False
        row = {
            "schema_version": 1,
            "finding_id": finding_id,
            "label": label,
            "confidence": confidence,
            "reason_codes": reason_codes,
            "reasoning": reasoning,
            "evidence": evidence,
            "uncertainty_reason": uncertainty_reason,
            "reviewer": reviewer,
            "reviewed_at": timestamp,
            "provenance": {
                "method": "LLM_ADJUDICATED",
                "source_scanner": "opengrep",
                "blind_first": blind_first,
                "route_reasons": reasons,
                "reviewer_a_prediction_sha256": pa_hash,
                "reviewer_b_prediction_sha256": pb_hash,
                "adjudicator_blind_prediction_sha256": blind_hash,
                "adjudicator_final_prediction_sha256": final_hash,
            },
            "linked_entry_ids": [],
        }
        labels.append(row)
        counts[label] += 1
    frozen_schema = review_directory / "frozen-inputs" / "machine-reference-label.schema.json"
    _validate_machine_labels_schema(labels, frozen_schema)
    from .machine_evaluator import validate_machine_reference_classification_inputs

    validation_predictions = [
        {
            "finding_id": row["finding_id"],
            "verdict": {
                "MACHINE_TRUE_POSITIVE": "TRUE_POSITIVE",
                "MACHINE_FALSE_POSITIVE": "FALSE_POSITIVE",
                "MACHINE_UNCERTAIN": "ABSTAIN",
            }[row["label"]],
        }
        for row in labels
    ]
    validate_machine_reference_classification_inputs(labels, validation_predictions)

    final_identity = {
        "machine_review_manifest_sha256": _sha256(
            review_directory / "machine-review-manifest.json"
        ),
        "reconciliation_summary_sha256": _sha256(
            review_directory / "reconciliation" / "reconciliation-summary.json"
        ),
        "reconciliation_sha256": reconciliation_summary["outputs"]["reconciliation"][
            "sha256"
        ],
        "adjudication_preparation_sha256": (
            _sha256(review_directory / "adjudicator-c" / "adjudication-preparation.json")
            if preparation is not None
            else None
        ),
        "final_adjudication_run_sha256": (
            c_proof["final_run_sha256"] if c_proof is not None else None
        ),
        "schema_sha256": _sha256(frozen_schema),
        "records": len(labels),
    }
    reviewers = {
        "reviewer_a": a_proof,
        "reviewer_b": b_proof,
        "adjudicator_c": c_proof,
    }
    actual_model_versions = {
        "reviewer_a": a_proof["model_version"],
        "reviewer_b": b_proof["model_version"],
        "adjudicator_c": c_proof["model_version"] if c_proof else None,
    }
    limitations = [
        "MODEL_AUTHORED_REFERENCE_NOT_HUMAN_GOLD",
        "REVIEWERS_A_B_SHARE_THE_GEMINI_MODEL_FAMILY",
        "ADJUDICATOR_C_USES_THE_OPENAI_MODEL_FAMILY",
        "ACTUAL_MODEL_VERSIONS_MAY_HAVE_CORRELATED_FAILURES",
        "TRUE_POSITIVE_LABELS_DO_NOT_CLAIM_KNOWN_OR_NOVEL_STATUS",
    ]
    audited_ids = [
        finding_id
        for finding_id in routed_ids
        if "DETERMINISTIC_CONSENSUS_FP_AUDIT"
        in reconciliation_by_id[finding_id]["route_reasons"]
    ]
    audit_verdicts = Counter(
        decisions[finding_id]["verdict"] for finding_id in audited_ids
    )
    audit_not_confirmed_rate = (
        None
        if not audited_ids
        else (len(audited_ids) - audit_verdicts["FALSE_POSITIVE"])
        / len(audited_ids)
    )
    audit_fraction = float(
        manifest["routing_policy"]["consensus_high_fp_audit_fraction"]
    )
    audit_failure_threshold = float(
        manifest["routing_policy"][
            "consensus_high_fp_audit_failure_threshold"
        ]
    )
    expansion_required = bool(
        audit_fraction < 1.0
        and audit_not_confirmed_rate is not None
        and audit_not_confirmed_rate > audit_failure_threshold
    )
    method_quality = {
        "reviewer_a_b_agreement": reconciliation_summary.get("agreement"),
        "adjudication": {
            "routed_records": len(routed_ids),
            "total_records": len(original_ids),
            "route_fraction": len(routed_ids) / len(original_ids),
        },
        "consensus_high_fp_audit": {
            "audited_records": len(audited_ids),
            "final_verdict_counts": dict(sorted(audit_verdicts.items())),
            "not_confirmed_as_false_positive_rate": audit_not_confirmed_rate,
            "failure_threshold": audit_failure_threshold,
            "full_consensus_fp_audit_required": expansion_required,
        },
    }
    if expansion_required:
        raise MachineReviewError(
            "consensus-FP audit exceeded its frozen failure threshold; create a "
            "new review release with MACHINE_AUDIT_FRACTION=1 before publishing "
            "a machine reference"
        )
    expected_summary_fields = {
        "status": "MACHINE_REFERENCE_READY_WITH_UNCERTAINTY",
        "reference_tier": "LLM_ADJUDICATED_MACHINE_REFERENCE",
        "records": len(labels),
        "counts": dict(sorted(counts.items())),
        "reviewers": reviewers,
        "actual_model_versions": actual_model_versions,
        "method_quality": method_quality,
        "limitations": limitations,
        "publication_policy": manifest["publication_policy"],
    }
    if existing_summary is not None:
        if existing_summary.get("identity") != final_identity:
            raise MachineReviewError("existing machine-reference identity differs")
        _check_stage_outputs(review_directory, existing_summary)
        if any(
            existing_summary.get(key) != value
            for key, value in expected_summary_fields.items()
        ):
            raise MachineReviewError(
                "existing machine-reference summary differs from reconstructed review"
            )
        existing_labels = _read_jsonl(labels_path, "machine-reference labels")
        if existing_labels != labels:
            raise MachineReviewError(
                "machine-reference labels differ from reconstructed frozen decisions"
            )
        return existing_summary
    if labels_path.exists():
        raise MachineReviewError("machine-reference labels exist without a summary")
    _write_jsonl(labels_path, labels)
    summary = {
        "schema_version": 1,
        "created_at": timestamp,
        "identity": final_identity,
        **expected_summary_fields,
        "outputs": {
            "machine_reference_labels": {
                "path": labels_path.name,
                "sha256": _sha256(labels_path),
                "records": len(labels),
            },
            "machine_reference_schema": {
                "path": frozen_schema.relative_to(review_directory).as_posix(),
                "sha256": _sha256(frozen_schema),
            },
        },
    }
    _write_json(summary_path, summary)
    return summary


def status(review_directory: Path) -> dict[str, Any]:
    review_directory = review_directory.resolve()
    result: dict[str, Any] = {
        "review_directory": str(review_directory),
        "prepared": False,
        "reviewer_a": "NOT_STARTED",
        "reviewer_b": "NOT_STARTED",
        "reconciliation": "NOT_STARTED",
        "adjudicator_blind": "NOT_STARTED",
        "adjudicator_final": "NOT_STARTED",
        "machine_reference": "NOT_READY",
    }
    manifest_path = review_directory / "machine-review-manifest.json"
    if not manifest_path.is_file():
        return result
    try:
        manifest = _load_machine_manifest(review_directory)
        result["prepared"] = True
        result["expected_records"] = manifest["identity"]["records"]
    except (OSError, ValueError) as exc:
        result["error"] = str(exc)
        return result
    r20_migration_path = review_directory / "migration-r20.json"
    r19_migration_path = review_directory / "migration-r19.json"
    r18_migration_path = review_directory / "migration-r18.json"
    r17_migration_path = review_directory / "migration-r17.json"
    r16_migration_path = review_directory / "migration-r16.json"
    r15_migration_path = review_directory / "migration-r15.json"
    r14_migration_path = review_directory / "migration-r14.json"
    r13_migration_path = review_directory / "migration-r13.json"
    r12_migration_path = review_directory / "migration-r12.json"
    r11_migration_path = review_directory / "migration-r11.json"
    r10_migration_path = review_directory / "migration-r10.json"
    r9_migration_path = review_directory / "migration-r9.json"
    r8_migration_path = review_directory / "migration-r8.json"
    r7_migration_path = review_directory / "migration-r7.json"
    migration_path = review_directory / "migration-r6.json"
    if r20_migration_path.is_file():
        try:
            migration = _load_r20_migration(review_directory)
            staging = _load_r12_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r20-reviewer-family-provenance"
            r8 = _load_r8_migration(review_directory)
            for role in ("a", "b"):
                records = r8["roles"][f"reviewer_{role}"]["imported"]["records"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": records,
                    "total": records,
                    "failed": 0,
                    "reused_r7_success": records,
                }
            result["adjudicator_blind"] = {
                "status": "COMPLETE",
                "success": 112,
                "total": 112,
                "failed": 0,
                "reused_r9_success": 112,
            }
            result["recovered_r19_final_success"] = len(
                staging.get("recovered_cases") or []
            )
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r19_migration_path.is_file():
        try:
            migration = _load_r19_migration(review_directory)
            staging = _load_r12_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r19-uncertain-evidence-normalization"
            r8 = _load_r8_migration(review_directory)
            for role in ("a", "b"):
                records = r8["roles"][f"reviewer_{role}"]["imported"]["records"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": records,
                    "total": records,
                    "failed": 0,
                    "reused_r7_success": records,
                }
            result["adjudicator_blind"] = {
                "status": "COMPLETE",
                "success": 112,
                "total": 112,
                "failed": 0,
                "reused_r9_success": 112,
            }
            result["recovered_r18_final_success"] = len(
                staging.get("recovered_cases") or []
            )
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r18_migration_path.is_file():
        try:
            migration = _load_r18_migration(review_directory)
            staging = _load_r12_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r18-numbered-code-normalization"
            r8 = _load_r8_migration(review_directory)
            for role in ("a", "b"):
                records = r8["roles"][f"reviewer_{role}"]["imported"]["records"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": records,
                    "total": records,
                    "failed": 0,
                    "reused_r7_success": records,
                }
            result["adjudicator_blind"] = {
                "status": "COMPLETE",
                "success": 112,
                "total": 112,
                "failed": 0,
                "reused_r9_success": 112,
            }
            result["recovered_r17_final_success"] = len(
                staging.get("recovered_cases") or []
            )
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r17_migration_path.is_file():
        try:
            migration = _load_r17_migration(review_directory)
            staging = _load_r12_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r17-frozen-code-normalization"
            r8 = _load_r8_migration(review_directory)
            for role in ("a", "b"):
                records = r8["roles"][f"reviewer_{role}"]["imported"]["records"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": records,
                    "total": records,
                    "failed": 0,
                    "reused_r7_success": records,
                }
            result["adjudicator_blind"] = {
                "status": "COMPLETE",
                "success": 112,
                "total": 112,
                "failed": 0,
                "reused_r9_success": 112,
            }
            result["recovered_r16_final_success"] = len(
                staging.get("recovered_cases") or []
            )
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r16_migration_path.is_file():
        try:
            migration = _load_r16_migration(review_directory)
            staging = _load_r12_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r16-context-identifier-normalization"
            r8 = _load_r8_migration(review_directory)
            for role in ("a", "b"):
                records = r8["roles"][f"reviewer_{role}"]["imported"]["records"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": records,
                    "total": records,
                    "failed": 0,
                    "reused_r7_success": records,
                }
            result["adjudicator_blind"] = {
                "status": "COMPLETE",
                "success": 112,
                "total": 112,
                "failed": 0,
                "reused_r9_success": 112,
            }
            result["recovered_r15_final_success"] = len(
                staging.get("recovered_cases") or []
            )
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r15_migration_path.is_file():
        try:
            migration = _load_r15_migration(review_directory)
            staging = _load_r12_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r15-verdict-field-normalization"
            r8 = _load_r8_migration(review_directory)
            for role in ("a", "b"):
                records = r8["roles"][f"reviewer_{role}"]["imported"]["records"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": records,
                    "total": records,
                    "failed": 0,
                    "reused_r7_success": records,
                }
            result["adjudicator_blind"] = {
                "status": "COMPLETE",
                "success": 112,
                "total": 112,
                "failed": 0,
                "reused_r9_success": 112,
            }
            result["recovered_r14_final_success"] = len(
                staging.get("recovered_cases") or []
            )
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r14_migration_path.is_file():
        try:
            migration = _load_r14_migration(review_directory)
            staging = _load_r12_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r14-source-identity-normalization"
            r8 = _load_r8_migration(review_directory)
            for role in ("a", "b"):
                records = r8["roles"][f"reviewer_{role}"]["imported"]["records"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": records,
                    "total": records,
                    "failed": 0,
                    "reused_r7_success": records,
                }
            result["adjudicator_blind"] = {
                "status": "COMPLETE",
                "success": 112,
                "total": 112,
                "failed": 0,
                "reused_r9_success": 112,
            }
            result["recovered_r13_final_success"] = len(
                staging.get("recovered_cases") or []
            )
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r13_migration_path.is_file():
        try:
            migration = _load_r13_migration(review_directory)
            staging = _load_r12_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r13-contained-evidence-normalization"
            r8 = _load_r8_migration(review_directory)
            for role in ("a", "b"):
                records = r8["roles"][f"reviewer_{role}"]["imported"]["records"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": records,
                    "total": records,
                    "failed": 0,
                    "reused_r7_success": records,
                }
            result["adjudicator_blind"] = {
                "status": "COMPLETE",
                "success": 112,
                "total": 112,
                "failed": 0,
                "reused_r9_success": 112,
            }
            result["recovered_r12_final_success"] = len(
                staging.get("recovered_cases") or []
            )
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r12_migration_path.is_file():
        try:
            migration = _load_r12_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r12-final-semantics-normalization"
            r8 = _load_r8_migration(review_directory)
            for role in ("a", "b"):
                records = r8["roles"][f"reviewer_{role}"]["imported"]["records"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": records,
                    "total": records,
                    "failed": 0,
                    "reused_r7_success": records,
                }
            result["adjudicator_blind"] = {
                "status": "COMPLETE",
                "success": 112,
                "total": 112,
                "failed": 0,
                "reused_r9_success": 112,
            }
            result["recovered_r11_final_success"] = len(
                migration.get("recovered_cases") or []
            )
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r11_migration_path.is_file():
        try:
            migration = _load_r11_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r11-final-evidence-normalization"
            r8 = _load_r8_migration(review_directory)
            for role in ("a", "b"):
                records = r8["roles"][f"reviewer_{role}"]["imported"]["records"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": records,
                    "total": records,
                    "failed": 0,
                    "reused_r7_success": records,
                }
            result["adjudicator_blind"] = {
                "status": "COMPLETE",
                "success": 112,
                "total": 112,
                "failed": 0,
                "reused_r9_success": 112,
            }
            result["recovered_r10_final_success"] = len(
                migration.get("recovered_cases") or []
            )
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r10_migration_path.is_file():
        try:
            migration = _load_r10_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r10-final-only-schema-projection"
            r8 = _load_r8_migration(review_directory)
            for role in ("a", "b"):
                records = r8["roles"][f"reviewer_{role}"]["imported"]["records"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": records,
                    "total": records,
                    "failed": 0,
                    "reused_r7_success": records,
                }
            result["adjudicator_blind"] = {
                "status": "COMPLETE",
                "success": 112,
                "total": 112,
                "failed": 0,
                "reused_r9_success": 112,
            }
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r9_migration_path.is_file():
        try:
            migration = _load_r9_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r9-adjudicator-supplement"
            r8 = _load_r8_migration(review_directory)
            for role in ("a", "b"):
                records = r8["roles"][f"reviewer_{role}"]["imported"]["records"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": records,
                    "total": records,
                    "failed": 0,
                    "reused_r7_success": records,
                }
            retry_state_path = (
                review_directory / "adjudicator-c" / "retry-run" / "run-state.json"
            )
            retry_status = "NOT_STARTED"
            retry_success = 0
            retry_failed = 0
            if retry_state_path.is_file():
                retry_state = _read_json(retry_state_path, "r9 C retry state")
                counts = retry_state.get("case_counts") or {}
                retry_status = str(retry_state.get("status") or "UNKNOWN")
                retry_success = int(counts.get("success", 0))
                retry_failed = int(counts.get("failed", 0))
            composite_ready = (
                review_directory / "adjudicator-c" / "blind" / "verifier-run.json"
            ).is_file()
            result["adjudicator_blind"] = {
                "status": "COMPLETE" if composite_ready else retry_status,
                "success": int(migration["reused_success"]) + retry_success,
                "total": int(migration["reused_success"]) + int(migration["retry_records"]),
                "failed": retry_failed,
                "reused_r8_success": int(migration["reused_success"]),
                "r9_retry_success": retry_success,
                "r9_retry_total": int(migration["retry_records"]),
            }
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r8_migration_path.is_file():
        try:
            migration = _load_r8_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r8-adjudicator-only-openai"
            for role in ("a", "b"):
                role_proof = migration["roles"][f"reviewer_{role}"]["imported"]
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE",
                    "success": role_proof["records"],
                    "total": role_proof["records"],
                    "failed": 0,
                    "reused_r7_success": role_proof["records"],
                }
            result["adjudicator_provider"] = migration["identity"][
                "adjudicator_provider"
            ]
            result["adjudicator_model"] = migration["identity"][
                "adjudicator_model"
            ]
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif r7_migration_path.is_file():
        try:
            migration = _load_r7_migration(review_directory)
            result["migration"] = migration.get("status")
            result["migration_release"] = "r7-supplement"
            for role in ("a", "b"):
                role_proof = migration["roles"][f"reviewer_{role}"]
                reused = int(role_proof["reused_success"])
                retry_total = int(role_proof["retry_records"])
                retry_success = 0
                retry_failed = 0
                retry_status = "NOT_STARTED"
                retry_state_path = (
                    review_directory
                    / f"reviewer-{role}"
                    / "retry-run"
                    / "run-state.json"
                )
                if not retry_state_path.is_file():
                    retry_state_path = retry_state_path.with_name("verifier-run.json")
                if retry_state_path.is_file():
                    retry_state = _read_json(
                        retry_state_path, f"reviewer {role} r7 retry state"
                    )
                    retry_counts = retry_state.get("case_counts") or {}
                    retry_success = int(retry_counts.get("success", 0))
                    retry_failed = int(retry_counts.get("failed", 0))
                    retry_status = str(retry_state.get("status") or "UNKNOWN")
                composite_path = review_directory / f"reviewer-{role}" / "run"
                composite_ready = (composite_path / "verifier-run.json").is_file()
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE" if composite_ready else retry_status,
                    "success": reused + retry_success,
                    "total": reused + retry_total,
                    "failed": retry_failed,
                    "reused_r5_r6_success": reused,
                    "r7_retry_success": retry_success,
                    "r7_retry_total": retry_total,
                }
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    elif migration_path.is_file():
        try:
            migration = _load_r6_migration(review_directory)
            result["migration"] = migration.get("status")
            for role in ("a", "b"):
                role_proof = migration["roles"][f"reviewer_{role}"]
                reused = int(role_proof["reused_success"])
                retry_total = int(role_proof["retry_records"])
                retry_success = 0
                retry_failed = 0
                retry_status = "NOT_STARTED"
                retry_state_path = (
                    review_directory
                    / f"reviewer-{role}"
                    / "retry-run"
                    / "run-state.json"
                )
                if retry_state_path.is_file():
                    retry_state = _read_json(
                        retry_state_path, f"reviewer {role} retry state"
                    )
                    retry_counts = retry_state.get("case_counts") or {}
                    retry_success = int(retry_counts.get("success", 0))
                    retry_failed = int(retry_counts.get("failed", 0))
                    retry_status = str(retry_state.get("status") or "UNKNOWN")
                composite_path = review_directory / f"reviewer-{role}" / "run"
                composite_ready = (composite_path / "verifier-run.json").is_file()
                result[f"reviewer_{role}"] = {
                    "status": "COMPLETE" if composite_ready else retry_status,
                    "success": reused + retry_success,
                    "total": reused + retry_total,
                    "failed": retry_failed,
                    "reused_r5_success": reused,
                    "r6_retry_success": retry_success,
                    "r6_retry_total": retry_total,
                }
        except (OSError, ValueError) as exc:
            result["migration_error"] = str(exc)
    for role in ("a", "b"):
        state_path = review_directory / f"reviewer-{role}" / "run" / "run-state.json"
        if state_path.is_file():
            state = _read_json(state_path, f"reviewer {role} run state")
            counts = state.get("case_counts") or {}
            result[f"reviewer_{role}"] = {
                "status": state.get("status"),
                "success": counts.get("success", 0),
                "total": counts.get("total", 0),
                "failed": counts.get("failed", 0),
            }
    reconciliation_path = review_directory / "reconciliation" / "reconciliation-summary.json"
    if reconciliation_path.is_file():
        summary = _read_json(reconciliation_path, "reconciliation summary")
        result["reconciliation"] = summary.get("status")
        result["routed"] = summary.get("counts", {}).get("routed_to_adjudicator")
    blind_path = review_directory / "adjudicator-c" / "blind" / "run-state.json"
    if blind_path.is_file():
        state = _read_json(blind_path, "adjudicator blind state")
        result["adjudicator_blind"] = state.get("status")
    elif (review_directory / "adjudicator-c" / "blind" / "verifier-run.json").is_file():
        result["adjudicator_blind"] = "COMPLETE"
    final_path = review_directory / "adjudicator-c" / "final" / "machine-adjudication-run.json"
    if final_path.is_file():
        result["adjudicator_final"] = _read_json(
            final_path, "final adjudicator run"
        ).get("status")
    else:
        final_directory = final_path.parent
        case_statuses = sorted(final_directory.glob("cases/*/status.json"))
        if case_statuses:
            values = [
                _read_json(path, "final adjudicator case status")
                for path in case_statuses
            ]
            final_counts = {
                "success": sum(value.get("status") == "SUCCESS" for value in values),
                "failed": sum(value.get("status") == "FAILED" for value in values),
                "running": sum(value.get("status") == "RUNNING" for value in values),
                "total": result.get("routed", len(values)),
            }
            result["adjudicator_final_counts"] = final_counts
            if any(value.get("status") == "FAILED" for value in values):
                result["adjudicator_final"] = "INCOMPLETE"
                result["adjudicator_final_blockers"] = sorted(
                    {
                        str(value.get("error_code") or "FINAL_ADJUDICATION_FAILED")
                        for value in values
                        if value.get("status") == "FAILED"
                    }
                )
            elif any(value.get("status") == "RUNNING" for value in values):
                result["adjudicator_final"] = "RUNNING"
            elif final_counts["success"] < final_counts["total"]:
                result["adjudicator_final"] = "RUNNING"
    summary_path = review_directory / "machine-review-summary.json"
    if summary_path.is_file():
        final = _read_json(summary_path, "machine-review summary")
        result["machine_reference"] = final.get("status")
        result["counts"] = final.get("counts")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a frozen LLM-adjudicated OpenGrep machine reference."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--sample-dir", type=Path, required=True)
    prepare.add_argument("--evidence-packets", type=Path, required=True)
    prepare.add_argument(
        "--snapshot-root",
        type=Path,
        default=Path("worktrees/opengrep-linux-lf"),
    )
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--reviewer-a-config", type=Path, required=True)
    prepare.add_argument("--reviewer-b-config", type=Path, required=True)
    prepare.add_argument("--adjudicator-config", type=Path, required=True)
    prepare.add_argument("--evaluated-agent-model", required=True)
    prepare.add_argument("--expected-records", type=int, default=400)
    prepare.add_argument("--audit-fraction", type=float, default=0.20)
    prepare.add_argument("--audit-failure-threshold", type=float, default=0.10)
    prepare.add_argument(
        "--audit-seed", default="opengrep-machine-fp-audit-r1-20260813"
    )
    prepare.add_argument(
        "--reviewer-a-seed",
        default="opengrep-machine-review-a-order-r1-20260813",
    )
    prepare.add_argument(
        "--reviewer-b-seed",
        default="opengrep-machine-review-b-order-r1-20260813",
    )
    prepare.add_argument("--created-at")

    migrate = commands.add_parser("migrate-r6")
    migrate.add_argument("--base-review-dir", type=Path, required=True)
    migrate.add_argument("--review-dir", type=Path, required=True)
    migrate.add_argument("--created-at")

    supplement = commands.add_parser("migrate-r7")
    supplement.add_argument("--base-review-dir", type=Path, required=True)
    supplement.add_argument("--review-dir", type=Path, required=True)
    supplement.add_argument("--created-at")

    adjudicator_migration = commands.add_parser("migrate-r8")
    adjudicator_migration.add_argument("--base-review-dir", type=Path, required=True)
    adjudicator_migration.add_argument("--review-dir", type=Path, required=True)
    adjudicator_migration.add_argument("--created-at")

    adjudicator_supplement = commands.add_parser("migrate-r9")
    adjudicator_supplement.add_argument("--base-review-dir", type=Path, required=True)
    adjudicator_supplement.add_argument("--review-dir", type=Path, required=True)
    adjudicator_supplement.add_argument("--created-at")

    final_migration = commands.add_parser("migrate-r10")
    final_migration.add_argument("--base-review-dir", type=Path, required=True)
    final_migration.add_argument("--review-dir", type=Path, required=True)
    final_migration.add_argument("--created-at")

    final_recovery = commands.add_parser("migrate-r11")
    final_recovery.add_argument("--base-review-dir", type=Path, required=True)
    final_recovery.add_argument("--review-dir", type=Path, required=True)
    final_recovery.add_argument("--created-at")

    final_semantics = commands.add_parser("migrate-r12")
    final_semantics.add_argument("--base-review-dir", type=Path, required=True)
    final_semantics.add_argument("--review-dir", type=Path, required=True)
    final_semantics.add_argument("--created-at")

    contained_evidence = commands.add_parser("migrate-r13")
    contained_evidence.add_argument("--base-review-dir", type=Path, required=True)
    contained_evidence.add_argument("--review-dir", type=Path, required=True)
    contained_evidence.add_argument("--created-at")

    source_identity = commands.add_parser("migrate-r14")
    source_identity.add_argument("--base-review-dir", type=Path, required=True)
    source_identity.add_argument("--review-dir", type=Path, required=True)
    source_identity.add_argument("--created-at")

    verdict_fields = commands.add_parser("migrate-r15")
    verdict_fields.add_argument("--base-review-dir", type=Path, required=True)
    verdict_fields.add_argument("--review-dir", type=Path, required=True)
    verdict_fields.add_argument("--created-at")

    context_id = commands.add_parser("migrate-r16")
    context_id.add_argument("--base-review-dir", type=Path, required=True)
    context_id.add_argument("--review-dir", type=Path, required=True)
    context_id.add_argument("--created-at")

    frozen_code = commands.add_parser("migrate-r17")
    frozen_code.add_argument("--base-review-dir", type=Path, required=True)
    frozen_code.add_argument("--review-dir", type=Path, required=True)
    frozen_code.add_argument("--created-at")

    numbered_code = commands.add_parser("migrate-r18")
    numbered_code.add_argument("--base-review-dir", type=Path, required=True)
    numbered_code.add_argument("--review-dir", type=Path, required=True)
    numbered_code.add_argument("--created-at")

    uncertain_evidence = commands.add_parser("migrate-r19")
    uncertain_evidence.add_argument("--base-review-dir", type=Path, required=True)
    uncertain_evidence.add_argument("--review-dir", type=Path, required=True)
    uncertain_evidence.add_argument("--created-at")

    provenance = commands.add_parser("migrate-r20")
    provenance.add_argument("--base-review-dir", type=Path, required=True)
    provenance.add_argument("--review-dir", type=Path, required=True)
    provenance.add_argument("--created-at")

    seal_adjudicator = commands.add_parser("seal-adjudicator-supplement")
    seal_adjudicator.add_argument("--review-dir", type=Path, required=True)
    seal_adjudicator.add_argument("--created-at")

    seal = commands.add_parser("seal-migration")
    seal.add_argument("--review-dir", type=Path, required=True)
    seal.add_argument("--created-at")

    reconcile = commands.add_parser("reconcile")
    reconcile.add_argument("--review-dir", type=Path, required=True)
    reconcile.add_argument("--reviewer-a-run", type=Path, required=True)
    reconcile.add_argument("--reviewer-b-run", type=Path, required=True)
    reconcile.add_argument("--created-at")

    preparation = commands.add_parser("prepare-adjudication")
    preparation.add_argument("--review-dir", type=Path, required=True)
    preparation.add_argument("--blind-run", type=Path, required=True)
    preparation.add_argument("--created-at")

    adjudication = commands.add_parser("adjudicate")
    adjudication.add_argument("--review-dir", type=Path, required=True)
    adjudication.add_argument(
        "--prompt",
        type=Path,
        default=Path("config/machine-adjudicator-prompt-v1.md"),
    )
    adjudication.add_argument(
        "--response-schema",
        type=Path,
        default=Path("schemas/machine-adjudicator-response.schema.json"),
    )
    adjudication.add_argument("--model", required=True)
    adjudication.add_argument(
        "--thinking-level",
        choices=("minimal", "low", "medium", "high"),
        default="high",
    )
    adjudication.add_argument("--temperature", type=float, default=0.0)
    adjudication.add_argument("--seed", type=int, default=47017)
    adjudication.add_argument("--timeout-seconds", type=int, default=180)
    adjudication.add_argument("--max-attempts", type=int, default=3)

    finalize = commands.add_parser("finalize")
    finalize.add_argument("--review-dir", type=Path, required=True)
    finalize.add_argument("--final-run", type=Path)
    finalize.add_argument("--reviewed-at")

    status_parser = commands.add_parser("status")
    status_parser.add_argument("--review-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare_review(
                sample_directory=args.sample_dir,
                evidence_packets_path=args.evidence_packets,
                snapshot_root=args.snapshot_root,
                output_directory=args.output_dir,
                reviewer_a_config_path=args.reviewer_a_config,
                reviewer_b_config_path=args.reviewer_b_config,
                adjudicator_config_path=args.adjudicator_config,
                evaluated_agent_model=args.evaluated_agent_model,
                expected_records=args.expected_records,
                audit_fraction=args.audit_fraction,
                audit_failure_threshold=args.audit_failure_threshold,
                audit_seed=args.audit_seed,
                reviewer_a_seed=args.reviewer_a_seed,
                reviewer_b_seed=args.reviewer_b_seed,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r6":
            result = prepare_r6_migration(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r7":
            result = prepare_r7_supplement(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r8":
            result = prepare_r8_adjudicator_migration(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r9":
            result = prepare_r9_adjudicator_supplement(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r10":
            result = prepare_r10_final_migration(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r11":
            result = prepare_r11_final_recovery(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r12":
            result = prepare_r12_final_semantics_migration(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r13":
            result = prepare_r13_contained_evidence_migration(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r14":
            result = prepare_r14_source_identity_migration(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r15":
            result = prepare_r15_verdict_field_migration(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r16":
            result = prepare_r16_context_id_migration(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r17":
            result = prepare_r17_frozen_code_migration(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r18":
            result = prepare_r18_numbered_code_migration(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r19":
            result = prepare_r19_uncertain_evidence_migration(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "migrate-r20":
            result = prepare_r20_provenance_migration(
                base_review_directory=args.base_review_dir,
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "seal-adjudicator-supplement":
            result = seal_r9_adjudicator_supplement(
                review_directory=args.review_dir,
                created_at=args.created_at,
            )
        elif args.command == "seal-migration":
            if (args.review_dir / "migration-r7.json").is_file():
                result = seal_r7_supplement(
                    review_directory=args.review_dir,
                    created_at=args.created_at,
                )
            else:
                result = seal_r6_migration(
                    review_directory=args.review_dir,
                    created_at=args.created_at,
                )
        elif args.command == "reconcile":
            result = reconcile_reviews(
                review_directory=args.review_dir,
                reviewer_a_run=args.reviewer_a_run,
                reviewer_b_run=args.reviewer_b_run,
                created_at=args.created_at,
            )
        elif args.command == "prepare-adjudication":
            result = prepare_adjudication(
                review_directory=args.review_dir,
                blind_run=args.blind_run,
                created_at=args.created_at,
            )
        elif args.command == "adjudicate":
            result = adjudicate(
                review_directory=args.review_dir,
                prompt_path=args.prompt,
                response_schema_path=args.response_schema,
                model=args.model,
                thinking_level=args.thinking_level,
                temperature=args.temperature,
                seed=args.seed,
                timeout_seconds=args.timeout_seconds,
                max_attempts=args.max_attempts,
            )
        elif args.command == "finalize":
            result = finalize_review(
                review_directory=args.review_dir,
                final_run=args.final_run,
                reviewed_at=args.reviewed_at,
            )
        else:
            result = status(args.review_dir)
    except (OSError, VerifierError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
