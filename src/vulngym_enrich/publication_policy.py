from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ATTESTATION = (
    PROJECT_ROOT
    / "data/releases/opengrep-machine-reference-publication-r1-20260814.json"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _project_path(raw: Any) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("publication proof path is invalid")
    relative = PurePosixPath(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"publication proof path is unsafe: {raw}")
    path = PROJECT_ROOT.joinpath(*relative.parts).resolve(strict=True)
    try:
        path.relative_to(PROJECT_ROOT)
    except ValueError as exc:
        raise ValueError(f"publication proof path escapes project: {raw}") from exc
    return path


def validate_publication_attestation(path: Path = DEFAULT_ATTESTATION) -> dict[str, Any]:
    path = path.resolve(strict=True)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("publication attestation is invalid JSON") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("publication attestation schema is invalid")
    if value.get("status") != "PROJECT_APPROVED_MACHINE_REFERENCE":
        raise ValueError("publication attestation is not approved")
    policy = value.get("policy")
    expected_policy = {
        "human_review_required": False,
        "human_gold": False,
        "publish_as_official_within_project": True,
        "official_claim_name": (
            "project-approved metrics against frozen LLM-adjudicated reference labels"
        ),
        "universal_ground_truth_claim_allowed": False,
        "novel_vulnerability_claim_allowed": False,
        "uncertain_is_false_positive": False,
    }
    if policy != expected_policy:
        raise ValueError("publication policy is invalid")
    basis = value.get("approval_basis")
    if (
        not isinstance(basis, dict)
        or basis.get("verification_method")
        != "DUAL_BLIND_LLM_PLUS_BLIND_FIRST_ADJUDICATOR"
        or basis.get("candidate_generator_independent_from_labelers") is not True
        or basis.get("repository_split_required") is not True
    ):
        raise ValueError("publication approval basis is invalid")
    policy_document = _project_path(basis.get("policy_document"))
    if policy_document.name != "machine-reference-publication-policy.md":
        raise ValueError("publication policy document is invalid")

    proofs = value.get("frozen_inputs")
    if not isinstance(proofs, dict) or not proofs:
        raise ValueError("publication frozen-input proofs are missing")
    verified: dict[str, dict[str, str]] = {}
    for name, proof in sorted(proofs.items()):
        if not isinstance(proof, dict) or set(proof) != {"path", "sha256"}:
            raise ValueError(f"publication proof is invalid: {name}")
        source = _project_path(proof["path"])
        observed = _sha256(source)
        if proof["sha256"] != observed:
            raise ValueError(f"publication proof checksum differs: {name}")
        verified[name] = {"path": proof["path"], "sha256": observed}
    return {
        "status": value["status"],
        "decision_id": value.get("decision_id"),
        "official_claim_name": policy["official_claim_name"],
        "human_review_required": False,
        "verified_inputs": len(verified),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the project-approved machine-reference publication policy."
    )
    parser.add_argument("--attestation", type=Path, default=DEFAULT_ATTESTATION)
    args = parser.parse_args(argv)
    print(json.dumps(validate_publication_attestation(args.attestation), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

