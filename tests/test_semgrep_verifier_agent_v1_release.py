from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
RELEASE_PATHS = (
    ROOT / "config" / "semgrep-verifier-agent-v1.json",
    ROOT / "config" / "semgrep-verifier-agent-v5.json",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@pytest.mark.parametrize("release_path", RELEASE_PATHS)
def test_semgrep_agent_release_identity_is_complete(release_path: Path) -> None:
    release = json.loads(release_path.read_text(encoding="utf-8"))

    assert release["release_id"] == release_path.stem
    assert release["scope"]["scanner"] == "semgrep"
    assert release["run"]["evaluation_mode"] == "OFFICIAL"
    assert release["run"]["force_allowed"] is False
    assert "codeql" not in release_path.read_text(encoding="utf-8").casefold()
    assert "opengrep" not in release_path.read_text(encoding="utf-8").casefold()

    identities = release["identity"]["files"]
    assert identities
    assert len({row["path"] for row in identities}) == len(identities)
    for identity in identities:
        path = ROOT / identity["path"]
        assert path.is_file(), identity["path"]
        assert _sha256(path) == identity["sha256"], identity["path"]


@pytest.mark.parametrize("release_path", RELEASE_PATHS)
def test_semgrep_agent_corpus_is_blind_semgrep_only(release_path: Path) -> None:
    release = json.loads(release_path.read_text(encoding="utf-8"))
    input_path = ROOT / release["corpus"]["input"]["path"]
    summary_path = ROOT / release["corpus"]["summary"]["path"]
    schema = json.loads(
        (ROOT / "schemas" / "blind-verifier-input.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)

    assert _sha256(input_path) == release["corpus"]["input"]["sha256"]
    assert _sha256(summary_path) == release["corpus"]["summary"]["sha256"]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["complete"] is True
    assert summary["scope"]["scanner"] == "semgrep"

    records = [json.loads(line) for line in input_path.read_text(encoding="utf-8").splitlines() if line]
    assert len(records) == release["corpus"]["input"]["records"] == 16
    assert len({row["finding_id"] for row in records}) == len(records)
    assert {row["scanner"]["name"] for row in records} == {"semgrep"}
    assert {row["scanner"]["version"] for row in records} == {
        release["scope"]["scanner_version"]
    }
    assert len({(row["repo_url"], row["commit"]) for row in records}) == 9
    for record in records:
        errors = list(validator.iter_errors(record))
        assert not errors, errors[0].message if errors else ""
