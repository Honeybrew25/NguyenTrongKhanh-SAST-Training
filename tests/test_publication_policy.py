from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulngym_enrich.publication_policy import (
    DEFAULT_ATTESTATION,
    validate_publication_attestation,
)


def test_project_approved_machine_reference_policy_is_fully_proven() -> None:
    result = validate_publication_attestation()
    assert result == {
        "status": "PROJECT_APPROVED_MACHINE_REFERENCE",
        "decision_id": "opengrep-machine-reference-publication-r1-20260814",
        "official_claim_name": (
            "project-approved metrics against frozen LLM-adjudicated reference labels"
        ),
        "human_review_required": False,
        "verified_inputs": 7,
    }


def test_publication_policy_fails_closed_on_tampered_proof(tmp_path: Path) -> None:
    value = json.loads(DEFAULT_ATTESTATION.read_text(encoding="utf-8"))
    value["frozen_inputs"]["enriched_dataset"]["sha256"] = "0" * 64
    path = tmp_path / "attestation.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="checksum differs"):
        validate_publication_attestation(path)

