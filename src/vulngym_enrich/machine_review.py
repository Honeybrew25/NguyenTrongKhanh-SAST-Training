from __future__ import annotations

import argparse
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
LOCAL_PROVIDER_ID = "local-openai-compatible-isolated-json"
SUPPORTED_REVIEW_PROVIDERS = {GEMINI_PROVIDER_ID, LOCAL_PROVIDER_ID}
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
) -> dict[str, Any]:
    run_directory = run_directory.resolve()
    _safe_relative_to(run_directory, review_directory, label)
    manifest_path = run_directory / "verifier-run.json"
    run = _read_json(manifest_path, f"{label} verifier run")
    counts = run.get("case_counts")
    if (
        run.get("status") != "COMPLETE"
        or run.get("complete") is not True
        or not isinstance(counts, dict)
        or counts.get("total") != len(expected_ids)
        or counts.get("success") != len(expected_ids)
        or counts.get("failed") != 0
    ):
        raise MachineReviewError(f"{label} run is not complete for the exact corpus")
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
        or predictions_proof.get("records") != len(expected_ids)
    ):
        raise MachineReviewError(f"{label} prediction proof is invalid")
    rows = _read_jsonl(predictions_path, f"{label} predictions")
    if _ordered_ids(rows, f"{label} predictions") != expected_ids:
        raise MachineReviewError(f"{label} predictions do not exactly cover its input")

    identity_path = run_directory / "run-identity.json"
    identity = _read_json(identity_path, f"{label} run identity")
    identity_provider = identity.get("provider")
    if not isinstance(identity_provider, dict):
        raise MachineReviewError(f"{label} run identity has no provider")
    provider_configuration_name = (
        "gemini-provider-configuration.json"
        if config["provider"] == GEMINI_PROVIDER_ID
        else "local-provider-configuration.json"
    )
    provider_configuration_path = run_directory / provider_configuration_name
    provider_configuration = _read_json(
        provider_configuration_path, f"{label} provider configuration"
    )
    configuration = provider_configuration.get("configuration")
    if not isinstance(configuration, dict):
        raise MachineReviewError(f"{label} run has no immutable provider configuration")
    expected_configuration = {
        "model": config["model"],
        "seed": config["seed"],
        "temperature": config["temperature"],
    }
    if config["provider"] == GEMINI_PROVIDER_ID:
        expected_configuration["thinking_level"] = config["thinking_level"]
    else:
        expected_configuration.update(
            {
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
    for status_path in sorted((run_directory / "cases").glob("*/status.json")):
        status = _read_json(status_path, f"{label} case status")
        finding_id = status.get("identity", {}).get("finding_id")
        if (
            status.get("status") != "SUCCESS"
            or not isinstance(finding_id, str)
            or finding_id in case_by_id
        ):
            raise MachineReviewError(f"{label} has an invalid/duplicate case status")
        case_by_id[finding_id] = status_path.parent
        case_status_by_id[finding_id] = status
    if set(case_by_id) != set(expected_ids):
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
    if manifest_case_by_id != case_status_by_id:
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
            for usage_name, usage_value in (
                metadata.get("normalized_usage") or {}
            ).items():
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
    if run.get("provider", {}).get("usage") != dict(sorted(aggregate_usage.items())):
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
    a = _load_run(
        run_directory=reviewer_a_run,
        review_directory=review_directory,
        expected_input=a_input,
        expected_ids=a_ids,
        findings_by_id=findings_by_id,
        expected_snapshot_root=_frozen_snapshot_root(manifest),
        config=_frozen_config(review_directory, "REVIEWER_A"),
        label="reviewer A",
    )
    b = _load_run(
        run_directory=reviewer_b_run,
        review_directory=review_directory,
        expected_input=b_input,
        expected_ids=b_ids,
        findings_by_id=findings_by_id,
        expected_snapshot_root=_frozen_snapshot_root(manifest),
        config=_frozen_config(review_directory, "REVIEWER_B"),
        label="reviewer B",
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
    c = _load_run(
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


def _new_adjudicator_provider(**kwargs: Any) -> Any:
    from .gemini_verifier_agent import GeminiApiProvider

    return GeminiApiProvider(**kwargs)


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
                decision = _validate_final_response(
                    _read_json(decision_path, "final adjudicator decision"), context
                )
                if _read_json(
                    response_path, "final adjudicator provider response"
                ) != decision:
                    raise MachineReviewError(
                        f"final adjudicator response differs from decision: {finding_id}"
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
            decision = _validate_final_response(response, context)
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


def _final_decisions(final_directory: Path, expected_ids: list[str]) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, str]]:
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
    provider_sidecar_path = final_directory / "gemini-provider-configuration.json"
    provider_sidecar = _read_json(
        provider_sidecar_path, "final Gemini provider configuration"
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
        raise MachineReviewError("final Gemini provider configuration differs")
    response_ids: set[str] = set()
    aggregate_usage: defaultdict[str, int] = defaultdict(int)
    for row in rows:
        finding_id = str(row["finding_id"])
        case_directory = final_directory / "cases" / _case_key(finding_id)
        status = _read_json(case_directory / "status.json", "final case status")
        decision_path = case_directory / "decision.json"
        response_path = case_directory / "step-01-response.json"
        metadata_path = case_directory / "step-01-provider-metadata.json"
        raw_path = case_directory / "step-01-raw-response.json"
        metadata = _read_json(metadata_path, "final provider metadata")
        if (
            status.get("status") != "SUCCESS"
            or status.get("identity", {}).get("finding_id") != finding_id
            or not decision_path.is_file()
            or _sha256(decision_path) != status.get("decision_sha256")
            or _read_json(decision_path, "final case decision") != row
            or not response_path.is_file()
            or _sha256(response_path) != status.get("response_sha256")
            or _read_json(response_path, "final provider response") != row
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
            final_directory, routed_ids
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
        "THREE_REVIEWERS_SHARE_THE_GEMINI_MODEL_FAMILY",
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
