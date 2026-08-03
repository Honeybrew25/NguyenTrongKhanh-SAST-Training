from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from vulngym_enrich import scanner

_REAL_RUN_SCANNER_PROCESS = scanner._run_scanner_process


@pytest.fixture(autouse=True)
def _route_scanner_process_through_mockable_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(argv: list[str], *, cwd: Path, timeout: int | float | None):
        return scanner._run_process(
            argv,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    monkeypatch.setattr(scanner, "_run_scanner_process", run)

BENCHMARK_COMMIT = "b" * 40
RULESET_COMMIT = "c" * 40
PYTHON_COMMIT = "1" * 40
TYPESCRIPT_COMMIT = "2" * 40
PYTHON_REPO = "https://github.com/example/python-project"
TYPESCRIPT_REPO = "https://github.com/example/typescript-project"


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _frozen_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    rules_root = tmp_path / "rules" / "semgrep-rules"
    python_rules = rules_root / "python"
    typescript_rules = rules_root / "typescript"
    python_rules.mkdir(parents=True)
    typescript_rules.mkdir(parents=True)
    (python_rules / "python.yml").write_text("rules: []\n", encoding="utf-8")
    (typescript_rules / "typescript.yml").write_text("rules: []\n", encoding="utf-8")

    tools = tmp_path / "tools"
    tools.mkdir(parents=True)
    semgrep = tools / "semgrep.exe"
    semgrep.write_bytes(b"mock semgrep executable")
    opengrep = tools / "opengrep.exe"
    opengrep.write_bytes(b"mock executable")

    manifest = {
        "schema_version": 1,
        "benchmark": {
            "name": "Tencent/VulnGym",
            "tag": "v0.1.4",
            "commit": BENCHMARK_COMMIT,
        },
        "snapshots": [
            {"repo_url": TYPESCRIPT_REPO, "commit": TYPESCRIPT_COMMIT},
            {"repo_url": PYTHON_REPO, "commit": PYTHON_COMMIT},
        ],
    }
    scanner_lock = {
        "schema_version": 1,
        "benchmark": {
            "name": "Tencent/VulnGym",
            "tag": "v0.1.4",
            "commit": BENCHMARK_COMMIT,
        },
        "ruleset": {
            "name": "semgrep/semgrep-rules",
            "commit": RULESET_COMMIT,
            "path": "rules/semgrep-rules",
        },
        "scanners": {
            "semgrep": {
                "version": "1.171.0",
                "local_path": "tools/semgrep.exe",
                "local_executable_sha256": hashlib.sha256(semgrep.read_bytes()).hexdigest(),
            },
            "opengrep": {
                "version": "1.26.0",
                "local_path": "tools/opengrep.exe",
                "local_executable_sha256": hashlib.sha256(opengrep.read_bytes()).hexdigest(),
            },
        },
    }
    profile = {
        "schema_version": 1,
        "rules": {
            "root": "rules/semgrep-rules",
            "commit": RULESET_COMMIT,
            "engines_share_rules": True,
            "language_configs": {
                "python": "python",
                "typescript": ["typescript"],
            },
            "language_extensions": {
                "python": [".py", ".pyi"],
                "typescript": [".ts", ".tsx", ".mts", ".cts"],
            },
        },
        "scan": {
            "timeout_seconds_per_rule": 30,
            "max_target_bytes": 1_000_000,
            "jobs": 4,
            "respect_git_ignore": True,
            "semgrep_oss_only": True,
            "metrics": "off",
            "opengrep_taint_intrafile": True,
            "exclude": ["**/node_modules/**", "**/vendor/**"],
            "outputs": ["json", "sarif"],
        },
        "policy": {
            "scan_exact_vulnerable_commit": True,
            "preserve_raw_output": True,
            "unmatched_is_not_false_positive": True,
        },
    }

    manifest_path = tmp_path / "manifest.json"
    lock_path = tmp_path / "scanner-lock.json"
    profile_path = tmp_path / "scan-profile.json"
    _write_json(manifest_path, manifest)
    _write_json(lock_path, scanner_lock)
    _write_json(profile_path, profile)
    return manifest_path, lock_path, profile_path, rules_root, python_rules


def _completed(argv: list[str], returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)


def _git_completed(argv: list[str]) -> subprocess.CompletedProcess[str]:
    stdout = RULESET_COMMIT + "\n" if "rev-parse" in argv else ""
    return _completed(argv, 0, stdout)


def _write_scanner_outputs(argv: list[str]) -> None:
    json_path = Path(argv[argv.index("--json-output") + 1])
    sarif_path = Path(argv[argv.index("--sarif-output") + 1])
    json_path.write_text(json.dumps({"results": []}), encoding="utf-8")
    sarif_path.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")


def _assert_safe_process_call(argv: list[str], kwargs: dict[str, Any]) -> None:
    assert isinstance(argv, list)
    assert all(isinstance(value, str) for value in argv)
    assert kwargs["shell"] is False
    assert kwargs["env"]["PYTHONUTF8"] == "1"


def test_successful_job_routes_language_and_records_complete_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path, lock_path, profile_path, rules_root, python_rules = _frozen_inputs(tmp_path)
    snapshot_path = tmp_path / "checked-out-python"
    snapshot_path.mkdir()
    (snapshot_path / "app.py").write_text("print('safe')\n", encoding="utf-8")

    checkout_calls: list[tuple[Any, ...]] = []
    process_calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_checkout(*args: Any, **kwargs: Any) -> Path:
        checkout_calls.append((*args, kwargs))
        return snapshot_path

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        _assert_safe_process_call(argv, kwargs)
        process_calls.append((argv, kwargs))
        if argv[0] == "git":
            return _git_completed(argv)
        if argv[-1] == "--version":
            return _completed(argv, 0, "1.171.0\n")
        _write_scanner_outputs(argv)
        return _completed(argv, 0, stdout="scan complete\n")

    monkeypatch.setattr(scanner, "checkout_snapshot", fake_checkout)
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    output_root = tmp_path / "scan-artifacts"
    report = scanner.run_batch(
        manifest_path=manifest_path,
        scanner_lock_path=lock_path,
        scan_profile_path=profile_path,
        scan_id="pilot-001",
        project_root=tmp_path,
        cache_root=Path("cache"),
        work_root=Path("worktrees"),
        output_root=output_root,
        repo_urls=[PYTHON_REPO],
        commits=[PYTHON_COMMIT],
        scanners=["semgrep"],
        limit=1,
        job_timeout_seconds=600,
    )

    assert report["jobs_total"] == 1
    assert report["status_counts"] == {"SUCCESS": 1}
    assert checkout_calls == [
        (
            PYTHON_REPO,
            PYTHON_COMMIT,
            (tmp_path / "cache").resolve(),
            (tmp_path / "worktrees").resolve(),
            {"refresh": False},
        )
    ]

    scanner_directory = (
        output_root
        / "pilot-001"
        / "example__python-project"
        / PYTHON_COMMIT
        / "semgrep"
    )
    attempt = scanner_directory / "attempts" / "0001"
    status = json.loads((attempt / "status.json").read_text(encoding="utf-8"))
    assert status["status"] == "SUCCESS"
    assert status["attempt"] == 1
    assert status["exit_code"] == 0
    assert status["started_at"]
    assert status["ended_at"]
    assert status["duration_seconds"] >= 0
    assert status["scanner"]["name"] == "semgrep"
    assert status["scanner"]["expected_version"] == "1.171.0"
    assert status["scanner"]["observed_version"] == "1.171.0"
    assert status["scanner"]["executable_sha256"] == hashlib.sha256(
        b"mock semgrep executable"
    ).hexdigest()
    assert status["ruleset_commit"] == RULESET_COMMIT
    assert status["rule_selection"] == {
        "source": "language-routing",
        "languages": ["python"],
        "configs": [str(python_rules.resolve())],
        "config_sha256": {
            str(python_rules.resolve()): scanner._rule_config_sha256(python_rules.resolve())
        },
    }
    assert set(status["checksums"]) == {"raw.json", "raw.sarif", "stdout.log", "stderr.log"}
    assert all(len(checksum) == 64 for checksum in status["checksums"].values())
    assert set(status["inputs"]) == {"manifest", "scanner_lock", "scan_profile"}
    for input_name, original in {
        "manifest": manifest_path,
        "scanner_lock": lock_path,
        "scan_profile": profile_path,
    }.items():
        frozen_path = attempt / status["inputs"][input_name]["frozen_path"]
        assert frozen_path.is_file()
        assert frozen_path.read_bytes() == original.read_bytes()
        assert status["inputs"][input_name]["sha256"] == hashlib.sha256(
            frozen_path.read_bytes()
        ).hexdigest()

    argv = status["argv"]
    assert argv[0:2] == [str((tmp_path / "tools" / "semgrep.exe").resolve()), "scan"]
    assert argv[argv.index("--config") + 1] == str(python_rules.resolve())
    assert str(rules_root.resolve()) not in [
        argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "--config"
    ]
    assert "--dataflow-traces" in argv
    assert "--oss-only" in argv
    assert argv[argv.index("--metrics") + 1] == "off"
    assert argv[argv.index("--timeout") + 1] == "30"
    assert argv[argv.index("--max-target-bytes") + 1] == "1000000"
    assert argv[argv.index("--jobs") + 1] == "4"
    assert "--use-git-ignore" in argv
    assert argv.count("--exclude") == 2
    assert "--json-output" in argv and "--sarif-output" in argv
    assert argv[-1] == "."

    scan_calls = [call for call in process_calls if len(call[0]) > 1 and call[0][1] == "scan"]
    assert len(scan_calls) == 1
    assert scan_calls[0][1]["cwd"] == snapshot_path.resolve()
    assert scan_calls[0][1]["timeout"] == 600
    assert not list(attempt.glob("*.tmp"))


def test_failed_attempt_retries_immutably_success_resumes_and_force_reruns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path, lock_path, profile_path, _, python_rules = _frozen_inputs(tmp_path)
    snapshot_path = tmp_path / "snapshot"
    snapshot_path.mkdir()
    (snapshot_path / "module.py").write_text("value = 1\n", encoding="utf-8")
    scan_return_codes = iter([7, 0, 0])
    scan_count = 0
    checkout_count = 0

    def fake_checkout(*args: Any, **kwargs: Any) -> Path:
        nonlocal checkout_count
        checkout_count += 1
        return snapshot_path

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal scan_count
        _assert_safe_process_call(argv, kwargs)
        if argv[0] == "git":
            return _git_completed(argv)
        if argv[-1] == "--version":
            return _completed(argv, 0, "OpenGrep 1.26.0\n")
        scan_count += 1
        _write_scanner_outputs(argv)
        return_code = next(scan_return_codes)
        return _completed(argv, return_code, stderr="scanner error\n" if return_code else "")

    monkeypatch.setattr(scanner, "checkout_snapshot", fake_checkout)
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    arguments = {
        "manifest_path": manifest_path,
        "scanner_lock_path": lock_path,
        "scan_profile_path": profile_path,
        "scan_id": "retry-test",
        "project_root": tmp_path,
        "output_root": tmp_path / "outputs",
        "repo_urls": [PYTHON_REPO],
        "scanners": ["opengrep"],
        "rule_configs": [python_rules],
    }

    first = scanner.run_batch(**arguments)
    scanner_directory = (
        tmp_path
        / "outputs"
        / "retry-test"
        / "example__python-project"
        / PYTHON_COMMIT
        / "opengrep"
    )
    first_status_path = scanner_directory / "attempts" / "0001" / "status.json"
    first_status_bytes = first_status_path.read_bytes()
    first_status = json.loads(first_status_bytes)
    first_frozen_profile = (
        first_status_path.parent / first_status["inputs"]["scan_profile"]["frozen_path"]
    )
    first_frozen_profile_bytes = first_frozen_profile.read_bytes()
    assert first["status_counts"] == {"FAILED": 1}
    assert json.loads(first_status_bytes)["exit_code"] == 7

    second = scanner.run_batch(**arguments)
    assert second["status_counts"] == {"SUCCESS": 1}
    assert json.loads(
        (scanner_directory / "attempts" / "0002" / "status.json").read_text(encoding="utf-8")
    )["status"] == "SUCCESS"

    resumed = scanner.run_batch(**arguments)
    assert resumed["status_counts"] == {"SKIPPED": 1}
    assert resumed["jobs"][0]["reason"] == "existing_success"
    assert resumed["jobs"][0]["attempt"] == 2

    changed_profile = json.loads(profile_path.read_text(encoding="utf-8"))
    changed_profile["scan"]["jobs"] = 3
    _write_json(profile_path, changed_profile)
    assert first_frozen_profile.read_bytes() == first_frozen_profile_bytes
    with pytest.raises(RuntimeError, match="already bound to different frozen inputs"):
        scanner.run_batch(**arguments)
    with pytest.raises(RuntimeError, match="already bound to different frozen inputs"):
        scanner.run_batch(**arguments, force=True)

    _write_json(profile_path, json.loads(first_frozen_profile_bytes))
    forced = scanner.run_batch(**arguments, force=True)
    third_status = json.loads(
        (scanner_directory / "attempts" / "0003" / "status.json").read_text(encoding="utf-8")
    )
    assert forced["status_counts"] == {"SUCCESS": 1}
    assert third_status["forced"] is True
    assert "--taint-intrafile" in third_status["argv"]
    assert third_status["argv"].count("-f") == 1
    assert third_status["argv"][third_status["argv"].index("-f") + 1] == str(
        python_rules.resolve()
    )

    assert scan_count == 3
    assert checkout_count == 3
    assert first_status_path.read_bytes() == first_status_bytes
    assert sorted(path.name for path in (scanner_directory / "attempts").iterdir()) == [
        "0001",
        "0002",
        "0003",
    ]
    pointer = json.loads((scanner_directory / "status.json").read_text(encoding="utf-8"))
    assert pointer["latest_attempt"] == 3
    assert pointer["status"] == "SUCCESS"
    assert pointer["attempt_status"] == "attempts/0003/status.json"


def test_timeout_is_finalized_with_logs_and_next_run_uses_a_new_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path, lock_path, profile_path, _, python_rules = _frozen_inputs(tmp_path)
    snapshot_path = tmp_path / "snapshot"
    snapshot_path.mkdir()
    (snapshot_path / "module.py").write_text("value = 1\n", encoding="utf-8")

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        _assert_safe_process_call(argv, kwargs)
        if argv[0] == "git":
            return _git_completed(argv)
        if argv[-1] == "--version":
            return _completed(argv, 0, "1.171.0\n")
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output="partial stdout", stderr="deadline")

    monkeypatch.setattr(scanner, "checkout_snapshot", lambda *args, **kwargs: snapshot_path)
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    common = {
        "manifest_path": manifest_path,
        "scanner_lock_path": lock_path,
        "scan_profile_path": profile_path,
        "scan_id": "timeout-test",
        "project_root": tmp_path,
        "output_root": tmp_path / "outputs",
        "repo_urls": [PYTHON_REPO],
        "scanners": ["semgrep"],
        "rule_configs": [python_rules],
        "job_timeout_seconds": 5,
    }
    first = scanner.run_batch(**common)
    second = scanner.run_batch(**common)
    assert first["status_counts"] == {"TIMEOUT": 1}
    assert second["status_counts"] == {"TIMEOUT": 1}

    attempts = (
        tmp_path
        / "outputs"
        / "timeout-test"
        / "example__python-project"
        / PYTHON_COMMIT
        / "semgrep"
        / "attempts"
    )
    first_status = json.loads((attempts / "0001" / "status.json").read_text(encoding="utf-8"))
    assert first_status["status"] == "TIMEOUT"
    assert first_status["exit_code"] is None
    assert first_status["error"]["type"] == "TimeoutExpired"
    assert (attempts / "0001" / "stdout.log").read_text(encoding="utf-8") == "partial stdout"
    assert (attempts / "0001" / "stderr.log").read_text(encoding="utf-8") == "deadline"
    assert sorted(path.name for path in attempts.iterdir()) == ["0001", "0002"]


def test_validation_rejects_cross_file_pin_mismatch_and_entire_ruleset_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path, lock_path, profile_path, rules_root, _ = _frozen_inputs(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["benchmark"]["commit"] = "d" * 40
    _write_json(manifest_path, manifest)

    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("subprocess must not run for invalid frozen inputs"),
    )
    monkeypatch.setattr(
        scanner,
        "checkout_snapshot",
        lambda *args, **kwargs: pytest.fail("checkout must not run for invalid frozen inputs"),
    )
    with pytest.raises(ValueError, match="benchmark commit mismatch"):
        scanner.run_batch(
            manifest_path=manifest_path,
            scanner_lock_path=lock_path,
            scan_profile_path=profile_path,
            scan_id="invalid",
            project_root=tmp_path,
            scanners=["semgrep"],
        )

    manifest["benchmark"]["commit"] = BENCHMARK_COMMIT
    _write_json(manifest_path, manifest)
    _, _, profile = scanner.load_configuration(manifest_path, lock_path, profile_path)
    with pytest.raises(ValueError, match="entire ruleset root"):
        scanner.resolve_rule_configs(profile, tmp_path, [rules_root])


def test_scanner_version_is_verified_before_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path, lock_path, profile_path, _, python_rules = _frozen_inputs(tmp_path)
    checkout_called = False

    def fake_checkout(*args: Any, **kwargs: Any) -> Path:
        nonlocal checkout_called
        checkout_called = True
        return tmp_path

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        _assert_safe_process_call(argv, kwargs)
        if argv[0] == "git":
            return _git_completed(argv)
        return _completed(argv, 0, "1.170.0\n")

    monkeypatch.setattr(scanner, "checkout_snapshot", fake_checkout)
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="scanner version mismatch"):
        scanner.run_batch(
            manifest_path=manifest_path,
            scanner_lock_path=lock_path,
            scan_profile_path=profile_path,
            scan_id="wrong-version",
            project_root=tmp_path,
            repo_urls=[PYTHON_REPO],
            scanners=["semgrep"],
            rule_configs=[python_rules],
        )
    assert checkout_called is False
    assert not (tmp_path / "artifacts" / "scans" / "wrong-version").exists()


def test_resume_reuses_no_applicable_rule_skip_without_new_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path, lock_path, profile_path, _, _ = _frozen_inputs(tmp_path)
    snapshot_path = tmp_path / "checked-out-unsupported"
    snapshot_path.mkdir()
    (snapshot_path / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    checkout_calls = 0

    def fake_checkout(*args: Any, **kwargs: Any) -> Path:
        nonlocal checkout_calls
        checkout_calls += 1
        return snapshot_path

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        _assert_safe_process_call(argv, kwargs)
        if argv[0] == "git":
            return _git_completed(argv)
        if argv[-1] == "--version":
            return _completed(argv, 0, "1.171.0\n")
        pytest.fail("scanner must not run without an applicable rule config")

    monkeypatch.setattr(scanner, "checkout_snapshot", fake_checkout)
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    arguments = {
        "manifest_path": manifest_path,
        "scanner_lock_path": lock_path,
        "scan_profile_path": profile_path,
        "scan_id": "unsupported-language",
        "project_root": tmp_path,
        "output_root": tmp_path / "scan-artifacts",
        "repo_urls": [PYTHON_REPO],
        "commits": [PYTHON_COMMIT],
        "scanners": ["semgrep"],
    }

    first = scanner.run_batch(**arguments)
    resumed = scanner.run_batch(**arguments)

    assert first["status_counts"] == {"SKIPPED": 1}
    assert first["jobs"][0]["reason"] == "no_applicable_rule_config"
    assert resumed["status_counts"] == {"SKIPPED": 1}
    assert resumed["jobs"][0]["reason"] == "existing_no_applicable_rule_config"
    assert checkout_calls == 1
    attempts = (
        tmp_path
        / "scan-artifacts"
        / "unsupported-language"
        / "example__python-project"
        / PYTHON_COMMIT
        / "semgrep"
        / "attempts"
    )
    assert [path.name for path in attempts.iterdir()] == ["0001"]


def test_gitignore_parser_failure_retries_clean_snapshot_without_gitignore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path, lock_path, profile_path, _, _ = _frozen_inputs(tmp_path)
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    profile["scan"]["git_ignore_parse_failure_fallback"] = (
        "no_git_ignore_on_clean_snapshot"
    )
    _write_json(profile_path, profile)
    snapshot_path = tmp_path / "checked-out-python"
    snapshot_path.mkdir()
    (snapshot_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    scan_calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        _assert_safe_process_call(argv, kwargs)
        if argv[0] == "git":
            return _git_completed(argv)
        if argv[-1] == "--version":
            return _completed(argv, 0, "1.171.0\n")
        scan_calls.append(argv)
        if len(scan_calls) == 1:
            _write_scanner_outputs(argv)
            return _completed(
                argv,
                2,
                stderr=(
                    "lexing: empty token\n"
                    "Called from Parse_gitignore.parse_line\n"
                    "[ERROR] Failed to obtain target files from semgrep-core\n"
                ),
            )
        _write_scanner_outputs(argv)
        return _completed(argv, 0, stdout="fallback complete\n")

    monkeypatch.setattr(scanner, "checkout_snapshot", lambda *args, **kwargs: snapshot_path)
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    output_root = tmp_path / "scan-artifacts"

    report = scanner.run_batch(
        manifest_path=manifest_path,
        scanner_lock_path=lock_path,
        scan_profile_path=profile_path,
        scan_id="gitignore-fallback",
        project_root=tmp_path,
        output_root=output_root,
        repo_urls=[PYTHON_REPO],
        commits=[PYTHON_COMMIT],
        scanners=["semgrep"],
    )

    assert report["status_counts"] == {"SUCCESS": 1}
    assert len(scan_calls) == 2
    assert "--use-git-ignore" in scan_calls[0]
    assert "--no-git-ignore" in scan_calls[1]
    attempt = (
        output_root
        / "gitignore-fallback"
        / "example__python-project"
        / PYTHON_COMMIT
        / "semgrep"
        / "attempts"
        / "0001"
    )
    status = json.loads((attempt / "status.json").read_text(encoding="utf-8"))
    assert status["targeting"] == {
        "respect_git_ignore_requested": True,
        "respect_git_ignore_effective": False,
        "git_ignore_fallback_used": True,
        "git_ignore_fallback_reason": "scanner_git_ignore_parser_failure",
    }
    assert [item["mode"] for item in status["argv_attempts"]] == [
        "configured",
        "fallback_no_git_ignore",
    ]
    assert "initial-git-ignore-stderr.log" in status["checksums"]
    assert status["initial_git_ignore_outputs"] == {
        "raw.json": "initial-git-ignore-raw.json",
        "raw.sarif": "initial-git-ignore-raw.sarif",
    }
    assert "initial-git-ignore-raw.json" in status["checksums"]
    assert "initial-git-ignore-raw.sarif" in status["checksums"]


def test_scanner_timeout_kills_a_real_descendant_process(tmp_path: Path) -> None:
    sentinel = tmp_path / "descendant-survived.txt"
    child_code = (
        "import pathlib,time; time.sleep(1.5); "
        f"pathlib.Path({str(sentinel)!r}).write_text('alive', encoding='utf-8')"
    )
    parent_code = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        "time.sleep(30)"
    )

    with pytest.raises(subprocess.TimeoutExpired):
        _REAL_RUN_SCANNER_PROCESS(
            [sys.executable, "-c", parent_code], cwd=tmp_path, timeout=0.2
        )
    time.sleep(2)
    assert not sentinel.exists()


def test_select_snapshots_rejects_partially_matched_filters() -> None:
    manifest = {
        "snapshots": [{"repo_url": PYTHON_REPO, "commit": PYTHON_COMMIT}]
    }
    with pytest.raises(ValueError, match="commit filters did not match"):
        scanner.select_snapshots(manifest, commits=[PYTHON_COMMIT, "f" * 40])
