from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from vulngym_enrich import verifier_agent


ROOT = Path(__file__).resolve().parents[1]


def _profile() -> verifier_agent.AgentProfile:
    return verifier_agent.AgentProfile(
        profile_id="lifecycle-v1-test",
        max_steps=3,
        max_tool_calls_per_step=2,
        max_context_chars=20_000,
        max_read_lines=40,
        max_source_file_bytes=100_000,
        max_search_results=10,
        max_directory_entries=20,
        initial_context_radius=2,
        trace_context_radius=1,
        max_initial_trace_nodes=4,
        max_evidence_lines=10,
        search_timeout_seconds=5,
        provider_timeout_seconds=30,
        threat_model=(
            "Attacker control, reachability, security effect, and effective controls "
            "must be established from source evidence."
        ),
    )


def _record(finding_id: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "finding_id": finding_id,
        "repo_url": "https://github.com/example/semgrep-fixture",
        "commit": "a" * 40,
        "scanner": {"name": "semgrep", "version": "1.171.0"},
        "rule": {
            "id": "python.lang.security.audit.subprocess-shell-true",
            "ruleset_commit": "b" * 40,
            "cwe": ["CWE-78"],
            "category": "security",
            "severity": "warning",
        },
        "message": "Potential command execution",
        "location": {
            "file": "src/app.py",
            "start_line": 4,
            "end_line": 4,
        },
        "dataflow_trace": [],
        "snippet": "clean = ALLOWED.get(value)",
        "fingerprint": f"fingerprint-{finding_id}",
        "provenance": {
            "raw_result_ref": f"raw.json#finding/{finding_id}",
            "scan_id": "semgrep-lifecycle-fixture",
        },
    }


def _final_response() -> dict[str, Any]:
    return {
        "action": "FINAL",
        "working_hypothesis": "A strict lookup replaces input with a constant.",
        "tool_requests": [],
        "verdict": "FALSE_POSITIVE",
        "confidence": "HIGH",
        "reason_codes": ["CONSTANT_VALUE"],
        "attacker_capability": "A caller can choose an untrusted action name.",
        "entry_point": "handler receives the caller-controlled action name.",
        "security_effect": "The scanner models arbitrary command execution.",
        "controls": "Only a fixed command from ALLOWED can reach the sink.",
        "reasoning": "The lookup rejects unknown values and returns a constant command.",
        "evidence": [
            {
                "file": "src/app.py",
                "start_line": 2,
                "end_line": 5,
                "description": "The allowlist lookup gates the command passed to run.",
            }
        ],
        "abstain_reason": None,
    }


class FakeProvider:
    provider_id = "fake-provider"
    model = "fake-model-v1"
    version = "1.0"
    stateful = False

    def __init__(self, responses: list[dict[str, Any] | BaseException]):
        self.responses = list(responses)
        self.calls = 0
        self.response_schema = (
            ROOT / "schemas" / "verifier-agent-response.schema.json"
        )
        self.response_schema_sha256 = verifier_agent.sha256_file(
            self.response_schema
        )

    def complete(
        self,
        request: dict[str, Any],
        *,
        case_directory: Path,
        step: int,
    ) -> dict[str, Any]:
        del request, case_directory, step
        self.calls += 1
        if not self.responses:
            raise AssertionError("fake provider received an unexpected call")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class BlockingProvider(FakeProvider):
    def __init__(
        self,
        response: dict[str, Any],
        *,
        entered: threading.Event,
        release: threading.Event,
    ):
        super().__init__([response])
        self.entered = entered
        self.release = release

    def complete(
        self,
        request: dict[str, Any],
        *,
        case_directory: Path,
        step: int,
    ) -> dict[str, Any]:
        self.entered.set()
        if not self.release.wait(timeout=10):
            raise AssertionError("test did not release the blocking provider")
        return super().complete(
            request,
            case_directory=case_directory,
            step=step,
        )


def _run_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    snapshot = tmp_path / "snapshot"
    source = snapshot / "src" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "def handler(value):\n"
        "    ALLOWED = {'status': 'echo-status'}\n"
        "    clean = ALLOWED.get(value)\n"
        "    if clean is None:\n"
        "        return None\n"
        "    return run(clean)\n",
        encoding="utf-8",
    )

    snapshot_root = tmp_path / "snapshots"
    snapshot_root.mkdir()
    monkeypatch.setattr(
        verifier_agent.SnapshotResolver,
        "resolve",
        lambda self, record: snapshot,
    )

    input_path = tmp_path / "blind-verifier-input.jsonl"
    input_path.write_text(
        "".join(
            json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )

    profile = _profile()
    profile_path = tmp_path / "verifier-profile.json"
    profile_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "profile_id": profile.profile_id,
                "threat_model": profile.threat_model,
                "limits": {
                    field: getattr(profile, field)
                    for field in profile.__dataclass_fields__
                    if field not in {"profile_id", "threat_model"}
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    prompt_path = tmp_path / "verifier-prompt.md"
    prompt_path.write_text("Pinned lifecycle-v1 test prompt.\n", encoding="utf-8")

    return {
        "records": records,
        "input_path": input_path,
        "snapshot_root": snapshot_root,
        "run_directory": tmp_path / "run",
        "profile": profile,
        "profile_path": profile_path,
        "prompt_path": prompt_path,
        "evaluation_mode": "DEVELOPMENT",
    }


@pytest.mark.parametrize(
    ("diagnostic", "expected"),
    [
        (
            "You've hit your usage limit; purchase more credits or try again later.",
            "PROVIDER_USAGE_LIMIT",
        ),
        (
            "401 Unauthorized: invalidated oauth token; auth error code: token_revoked",
            "PROVIDER_TOKEN_REVOKED",
        ),
    ],
)
def test_terminal_provider_failure_classification_contract(
    diagnostic: str, expected: str
) -> None:
    assert verifier_agent._classify_provider_failure(diagnostic) == expected
    error = verifier_agent.TerminalProviderError(expected)
    assert error.code == expected
    assert expected in str(error)


def test_unknown_provider_failure_is_not_terminal() -> None:
    assert (
        verifier_agent._classify_provider_failure(
            "The model returned JSON that does not match the response schema."
        )
        is None
    )


def test_provider_diagnostics_redact_credentials_but_keep_failure_code() -> None:
    diagnostic = (
        "Authorization: Bearer secret-bearer-token\n"
        "https://example.invalid/list?pageToken=secret-page-token&scope=GLOBAL\n"
        'access_token="secret-access-token" refresh_token=secret-refresh-token\n'
        "auth error code: token_revoked\n"
    )

    redacted = verifier_agent._redact_provider_diagnostics(diagnostic)

    for secret in (
        "secret-bearer-token",
        "secret-page-token",
        "secret-access-token",
        "secret-refresh-token",
    ):
        assert secret not in redacted
    assert "token_revoked" in redacted


def test_execute_run_writes_identity_and_terminal_complete_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = _run_arguments(tmp_path, monkeypatch, [_record("finding-one")])

    manifest = verifier_agent.execute_run(
        provider=FakeProvider([_final_response()]), **arguments
    )

    run_directory = arguments["run_directory"]
    identity_path = run_directory / "run-identity.json"
    state_path = run_directory / "run-state.json"
    assert identity_path.is_file()
    assert state_path.is_file()
    assert isinstance(json.loads(identity_path.read_text(encoding="utf-8")), dict)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "COMPLETE"
    assert manifest["complete"] is True


def test_same_run_directory_is_single_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = _run_arguments(tmp_path, monkeypatch, [_record("finding-one")])
    entered = threading.Event()
    release = threading.Event()
    first_provider = BlockingProvider(
        _final_response(), entered=entered, release=release
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        first_run = executor.submit(
            verifier_agent.execute_run,
            provider=first_provider,
            **arguments,
        )
        assert entered.wait(timeout=10), "first run did not reach the provider"
        try:
            with pytest.raises(verifier_agent.VerifierError, match="(?i)busy"):
                verifier_agent.execute_run(
                    provider=FakeProvider([_final_response()]), **arguments
                )
        finally:
            release.set()
        assert first_run.result(timeout=10)["complete"] is True


def test_terminal_provider_error_stops_batch_and_blocks_run_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = [_record("finding-one"), _record("finding-two")]
    arguments = _run_arguments(tmp_path, monkeypatch, records)
    code = "PROVIDER_USAGE_LIMIT"
    provider = FakeProvider(
        [verifier_agent.TerminalProviderError(code), _final_response()]
    )

    manifest = verifier_agent.execute_run(provider=provider, **arguments)

    assert provider.calls == 1
    assert manifest["complete"] is False
    run_directory = arguments["run_directory"]
    state = json.loads(
        (run_directory / "run-state.json").read_text(encoding="utf-8")
    )
    assert state["status"] == "BLOCKED_PROVIDER"
    assert code in json.dumps(state, ensure_ascii=False)
    case_directories = list((run_directory / "cases").iterdir())
    assert len(case_directories) == 1
    case_status = json.loads(
        (case_directories[0] / "status.json").read_text(encoding="utf-8")
    )
    assert case_status["status"] == "FAILED"


def test_retry_archives_previous_case_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = _run_arguments(tmp_path, monkeypatch, [_record("finding-one")])
    run_directory = arguments["run_directory"]

    first_manifest = verifier_agent.execute_run(
        provider=FakeProvider([verifier_agent.ProviderError("transient failure")]),
        **arguments,
    )
    assert first_manifest["complete"] is False
    identity_before = (run_directory / "run-identity.json").read_bytes()
    case_directory = next((run_directory / "cases").iterdir())
    first_status = json.loads(
        (case_directory / "status.json").read_text(encoding="utf-8")
    )
    assert first_status["status"] == "FAILED"

    second_manifest = verifier_agent.execute_run(
        provider=FakeProvider([_final_response()]), **arguments
    )

    assert second_manifest["complete"] is True
    assert (run_directory / "run-identity.json").read_bytes() == identity_before
    archived_status_path = case_directory / "attempts" / "0001" / "status.json"
    assert archived_status_path.is_file()
    archived_status = json.loads(archived_status_path.read_text(encoding="utf-8"))
    assert archived_status["status"] == "FAILED"
    current_status = json.loads(
        (case_directory / "status.json").read_text(encoding="utf-8")
    )
    assert current_status["status"] == "SUCCESS"
    state = json.loads(
        (run_directory / "run-state.json").read_text(encoding="utf-8")
    )
    assert state["status"] == "COMPLETE"


def test_keyboard_interrupt_leaves_no_stale_running_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = _run_arguments(tmp_path, monkeypatch, [_record("finding-one")])
    run_directory = arguments["run_directory"]

    with pytest.raises(KeyboardInterrupt):
        verifier_agent.execute_run(
            provider=FakeProvider([KeyboardInterrupt()]), **arguments
        )

    case_directory = next((run_directory / "cases").iterdir())
    status = json.loads((case_directory / "status.json").read_text(encoding="utf-8"))
    state = json.loads((run_directory / "run-state.json").read_text(encoding="utf-8"))
    assert status["status"] == "INTERRUPTED"
    assert state["status"] == "INTERRUPTED"
    assert state["case_counts"]["running"] == 0

    manifest = verifier_agent.execute_run(
        provider=FakeProvider([_final_response()]), **arguments
    )
    assert manifest["complete"] is True
    assert (case_directory / "attempts" / "0001" / "status.json").is_file()


def test_changed_run_identity_fails_before_mutating_existing_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = _run_arguments(tmp_path, monkeypatch, [_record("finding-one")])
    run_directory = arguments["run_directory"]
    assert verifier_agent.execute_run(
        provider=FakeProvider([_final_response()]), **arguments
    )["complete"] is True
    before = {
        path.relative_to(run_directory).as_posix(): path.read_bytes()
        for path in run_directory.rglob("*")
        if path.is_file()
    }

    changed_provider = FakeProvider([_final_response()])
    changed_provider.model = "different-model"
    with pytest.raises(verifier_agent.VerifierError, match="identity mismatch"):
        verifier_agent.execute_run(provider=changed_provider, **arguments)

    after = {
        path.relative_to(run_directory).as_posix(): path.read_bytes()
        for path in run_directory.rglob("*")
        if path.is_file()
    }
    assert changed_provider.calls == 0
    assert after == before


def test_official_validate_only_requires_adjacent_complete_corpus_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = _run_arguments(tmp_path, monkeypatch, [_record("finding-one")])
    input_path = arguments["input_path"]
    cli = [
        "--input",
        str(input_path),
        "--snapshot-root",
        str(arguments["snapshot_root"]),
        "--run-dir",
        str(arguments["run_directory"]),
        "--profile",
        str(arguments["profile_path"]),
        "--prompt",
        str(arguments["prompt_path"]),
        "--response-schema",
        str(ROOT / "schemas" / "verifier-agent-response.schema.json"),
        "--validate-only",
    ]

    with pytest.raises(SystemExit) as exc_info:
        verifier_agent.main(cli)
    assert exc_info.value.code == 2

    (input_path.parent / "summary.json").write_text(
        json.dumps(
            {
                "complete": True,
                "blind_verifier_input": {
                    "path": input_path.name,
                    "sha256": verifier_agent.sha256_file(input_path),
                    "records": 1,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    assert verifier_agent.main(cli) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["official_corpus_verified"] is True
