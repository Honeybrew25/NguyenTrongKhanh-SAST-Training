from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_PATH = ROOT / "data" / "releases" / "opengrep-security-r1-20260812.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_opengrep_release_manifest_identity_and_gates() -> None:
    release = json.loads(RELEASE_PATH.read_text(encoding="utf-8"))

    assert release["release_id"] == RELEASE_PATH.stem
    assert release["status"] == "SCAN_AND_CORPUS_READY"
    assert release["scope"]["scanner"] == "opengrep"
    assert release["coverage"] == {
        "jobs_expected": 166,
        "jobs_accounted": 166,
        "status_counts": {"SUCCESS": 166},
        "complete": True,
    }
    assert release["evaluation"]["status"] == "NOT_RUN"
    assert release["evaluation"]["precision"] is None
    assert release["evaluation"]["recall"] is None
    assert release["evaluation"]["f1"] is None
    assert release["gates"]["unmatched_is_false_positive"] is False

    identities = release["identity"]["files"]
    assert identities
    assert len({row["path"] for row in identities}) == len(identities)
    for identity in identities:
        path = ROOT / identity["path"]
        assert path.is_file(), identity["path"]
        assert _sha256(path) == identity["sha256"], identity["path"]
