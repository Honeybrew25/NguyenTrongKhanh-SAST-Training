from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .checkout import (
    checkout_snapshot,
    interprocess_lock,
    repo_slug,
    verify_snapshot_state,
)

SUPPORTED_LANGUAGES = {
    "actions",
    "go",
    "javascript-typescript",
    "python",
}

LANGUAGE_EXTENSIONS = {
    ".cjs": "javascript-typescript",
    ".cts": "javascript-typescript",
    ".go": "go",
    ".js": "javascript-typescript",
    ".jsx": "javascript-typescript",
    ".mjs": "javascript-typescript",
    ".mts": "javascript-typescript",
    ".py": "python",
    ".svelte": "javascript-typescript",
    ".ts": "javascript-typescript",
    ".tsx": "javascript-typescript",
    ".vue": "javascript-typescript",
}

PILOT_JOBS = {
    (
        "https://github.com/nltk/nltk",
        "40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e",
        "python",
    ),
    (
        "https://github.com/modelcontextprotocol/typescript-sdk",
        "50d9fa3cd12e807e7963bcb9e1548786d3d5d941",
        "javascript-typescript",
    ),
    (
        "https://github.com/ollama/ollama",
        "7325791599409de52534429897481918717a9e85",
        "go",
    ),
}

ESCALATION_REPOSITORIES = {
    "FlowiseAI__Flowise",
    "NVIDIA__NeMo",
    "google__adk-python",
    "mlflow__mlflow",
    "openclaw__openclaw",
    "paperclipai__paperclip",
}


@dataclass(frozen=True)
class CodeQLJob:
    repo_url: str
    commit: str
    language: str
    routing_reason: str
    priority: int

    @property
    def repo_slug(self) -> str:
        return repo_slug(self.repo_url)

    @property
    def job_id(self) -> str:
        raw = f"{self.repo_url}\0{self.commit}\0{self.language}".encode()
        return hashlib.sha256(raw).hexdigest()[:20]

    def as_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "repo_url": self.repo_url,
            "repo_slug": self.repo_slug,
            "commit": self.commit,
            "language": self.language,
            "routing_reason": self.routing_reason,
            "priority": self.priority,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected JSON object")
            rows.append(value)
    return rows


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_path(project_root: Path, value: str | Path) -> Path:
    expanded = Path(os.path.expandvars(os.path.expanduser(str(value))))
    if not expanded.is_absolute():
        expanded = project_root / expanded
    return expanded.resolve()


def _apply_runtime_resource_overrides(
    profile: dict[str, Any],
    *,
    analyze_threads: int | None,
    analyze_ram_mb: int | None,
) -> dict[str, int]:
    """Apply operational limits without changing the immutable profile file.

    Runtime overrides are intentionally excluded from ``profile_sha256`` so a
    resource-only safety adjustment can resume successful results produced by
    the same scanner, queries, and extraction profile. Every new plan and
    attempt records both the override and the effective resources.
    """
    overrides = {
        key: value
        for key, value in (
            ("analyze_threads", analyze_threads),
            ("analyze_ram_mb", analyze_ram_mb),
        )
        if value is not None
    }
    if any(value < 1 for value in overrides.values()):
        raise ValueError("runtime resource overrides must be positive")
    profile["resources"].update(overrides)
    return overrides


def _apply_runtime_go_override(
    profile: dict[str, Any],
    *,
    version: str | None,
    executable: str | None,
    executable_sha256: str | None,
    godebug: str | None = None,
    goflags: str | None = None,
) -> dict[str, str]:
    identity = (version, executable, executable_sha256)
    if (
        all(value is None for value in identity)
        and godebug is None
        and goflags is None
    ):
        return {}
    if any(value is None for value in identity):
        raise ValueError(
            "runtime Go override requires version, executable, and executable SHA-256"
        )
    assert version is not None
    assert executable is not None
    assert executable_sha256 is not None
    if not version.strip() or not executable.strip():
        raise ValueError("runtime Go override values must be non-empty")
    if not re.fullmatch(r"[0-9a-f]{64}", executable_sha256):
        raise ValueError("runtime Go executable SHA-256 must be lowercase hexadecimal")
    if godebug not in (None, "http2client=0"):
        raise ValueError(
            "runtime Go GODEBUG override currently supports only http2client=0"
        )
    if goflags not in (None, "-mod=mod"):
        raise ValueError(
            "runtime Go GOFLAGS override currently supports only -mod=mod"
        )
    runtime = profile.get("go_runtime")
    if not isinstance(runtime, dict):
        raise ValueError("profile does not define a Go runtime")
    overrides = {
        "version": version,
        "executable": executable,
        "executable_sha256": executable_sha256,
    }
    if godebug is not None:
        overrides["godebug"] = godebug
    if goflags is not None:
        overrides["goflags"] = goflags
    runtime.update(overrides)
    return overrides


def _verified_executable(
    project_root: Path, runtime: dict[str, Any], label: str
) -> Path:
    executable = _resolve_path(project_root, runtime["executable"])
    if not executable.is_file():
        raise RuntimeError(f"{label} executable does not exist: {executable}")
    actual_sha256 = _sha256(executable)
    if actual_sha256 != runtime["executable_sha256"]:
        raise RuntimeError(
            f"{label} executable checksum mismatch: {executable} "
            f"(expected {runtime['executable_sha256']}, got {actual_sha256})"
        )
    return executable


def _normalize_repo_url(value: str) -> str:
    return value.removesuffix(".git").rstrip("/")


def _evidence_files(entry: dict[str, Any]) -> Iterable[str]:
    for field in ("entry_point", "critical_operation"):
        node = entry.get(field)
        if isinstance(node, dict) and isinstance(node.get("file"), str):
            yield node["file"]
    for node in entry.get("trace", []):
        if isinstance(node, dict) and isinstance(node.get("file"), str):
            yield node["file"]


def language_for_file(path: str) -> str | None:
    normalized = path.replace("\\", "/").lower()
    if normalized.startswith(".github/workflows/") and normalized.endswith(
        (".yaml", ".yml")
    ):
        return "actions"
    return LANGUAGE_EXTENSIONS.get(Path(normalized).suffix)


def build_job_plan(
    manifest: dict[str, Any], entries: list[dict[str, Any]]
) -> list[CodeQLJob]:
    languages_by_snapshot: dict[tuple[str, str], set[str]] = defaultdict(set)
    repository_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for entry in entries:
        repo_url = _normalize_repo_url(str(entry["repo_url"]))
        commit = str(entry["commit"]).lower()
        entry_languages = {
            language
            for file_path in _evidence_files(entry)
            if (language := language_for_file(file_path)) is not None
        }
        languages_by_snapshot[(repo_url, commit)].update(entry_languages)
        repository_counts[repo_url].update(entry_languages)

    jobs: list[CodeQLJob] = []
    for snapshot in manifest["snapshots"]:
        repo_url = _normalize_repo_url(str(snapshot["repo_url"]))
        commit = str(snapshot["commit"]).lower()
        languages = set(languages_by_snapshot.get((repo_url, commit), set()))
        routing_reason = "vulngym-entry-trace"
        if not languages:
            counts = repository_counts.get(repo_url, Counter())
            if counts:
                languages = {counts.most_common(1)[0][0]}
                routing_reason = "repository-dominant-fallback"
        if not languages:
            raise ValueError(f"cannot route CodeQL language for {repo_url}@{commit}")

        for language in sorted(languages):
            key = (repo_url, commit, language)
            slug = repo_slug(repo_url)
            if key in PILOT_JOBS:
                priority = 0
            elif slug in ESCALATION_REPOSITORIES:
                priority = 10
            elif language == "python":
                priority = 20
            elif language == "javascript-typescript":
                priority = 30
            elif language == "actions":
                priority = 40
            else:
                priority = 50
            jobs.append(
                CodeQLJob(
                    repo_url=repo_url,
                    commit=commit,
                    language=language,
                    routing_reason=routing_reason,
                    priority=priority,
                )
            )

    jobs.sort(
        key=lambda job: (
            job.priority,
            job.repo_slug.casefold(),
            job.commit,
            job.language,
        )
    )
    return jobs


def _suite_reference(profile: dict[str, Any], language: str) -> str:
    pack = profile["query_packs"][language]["name"]
    stem = "javascript" if language == "javascript-typescript" else language
    return f"{pack}:codeql-suites/{stem}-{profile['query_suite']}.qls"


def _database_config(profile: dict[str, Any], language: str) -> dict[str, Any]:
    runtime_key = {
        "javascript-typescript": "node_runtime",
        "python": "python_runtime",
        "go": "go_runtime",
    }.get(language)
    runtime = profile.get(runtime_key, {}) if runtime_key else {}
    return {
        "tool": {
            "version": profile["tool"]["version"],
            "executable_sha256": profile["tool"]["executable_sha256"],
        },
        "runtime": {
            key: runtime[key]
            for key in ("version", "executable_sha256", "goflags")
            if key in runtime
        },
        "build_mode": profile["policy"]["build_modes"][language],
    }


def _database_marker(
    job: CodeQLJob, profile: dict[str, Any]
) -> dict[str, Any]:
    extraction_config = _database_config(profile, job.language)
    extraction_config_sha256 = hashlib.sha256(
        json.dumps(
            extraction_config,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": 2,
        "repo_url": job.repo_url,
        "commit": job.commit,
        "language": job.language,
        "extraction_config_sha256": extraction_config_sha256,
        "extraction_config": extraction_config,
    }


def _query_rerun_flag(database_reused: bool) -> str:
    return "--no-rerun" if database_reused else "--rerun"


def _kill_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            capture_output=True,
        )
    else:
        os.killpg(process.pid, signal.SIGKILL)


def _run_logged(
    argv: list[str],
    *,
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: int,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    start_new_session = os.name != "nt"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            creationflags=creationflags,
            start_new_session=start_new_session,
            env=env,
        )
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_tree(process)
            returncode = process.wait(timeout=60)
    return {
        "argv": argv,
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
    }


def _next_attempt(scanner_directory: Path) -> tuple[int, Path]:
    attempts = scanner_directory / "attempts"
    attempts.mkdir(parents=True, exist_ok=True)
    numbers = [
        int(path.name)
        for path in attempts.iterdir()
        if path.is_dir() and path.name.isdigit()
    ]
    number = max(numbers, default=0) + 1
    directory = attempts / f"{number:04d}"
    directory.mkdir()
    return number, directory


def _write_pointer(scanner_directory: Path, status: dict[str, Any]) -> None:
    _atomic_write_json(
        scanner_directory / "status.json",
        {
            "schema_version": 1,
            "scan_id": status["scan_id"],
            "repo_url": status["repo_url"],
            "commit": status["commit"],
            "scanner": "codeql",
            "language": status["language"],
            "profile_sha256": status["profile_sha256"],
            "latest_attempt": status["attempt"],
            "status": status["status"],
            "attempt_status": f"attempts/{status['attempt']:04d}/status.json",
            "updated_at": _utc_now(),
        },
    )


def _result_summary(sarif_path: Path) -> dict[str, Any]:
    sarif = _read_json(sarif_path)
    results = [
        result
        for run in sarif.get("runs", [])
        if isinstance(run, dict)
        for result in run.get("results", [])
        if isinstance(result, dict)
    ]
    rules = {str(result.get("ruleId")) for result in results if result.get("ruleId")}
    with_code_flows = sum(bool(result.get("codeFlows")) for result in results)
    return {
        "findings": len(results),
        "unique_rules": len(rules),
        "findings_with_code_flows": with_code_flows,
    }


def run_job(
    job: CodeQLJob,
    *,
    project_root: Path,
    profile_path: Path,
    profile: dict[str, Any],
    scan_root: Path,
    database_root: Path,
    work_root: Path,
    checkout_cache_root: Path | None,
    retry_failed: bool,
    runtime_resource_overrides: dict[str, int] | None = None,
    runtime_go_override: dict[str, str] | None = None,
) -> dict[str, Any]:
    scanner_directory = (
        scan_root / job.repo_slug / job.commit / "codeql" / job.language
    )
    lock_path = scanner_directory / ".job.lock"
    with interprocess_lock(lock_path, timeout_seconds=1):
        profile_sha256 = _sha256(profile_path)
        pointer_path = scanner_directory / "status.json"
        if pointer_path.exists():
            pointer = _read_json(pointer_path)
            if pointer.get("status") == "SUCCESS":
                attempt_status = scanner_directory / str(pointer["attempt_status"])
                previous = _read_json(attempt_status)
                expected_go_override = (
                    (runtime_go_override or {}) if job.language == "go" else {}
                )
                if (
                    previous.get("profile_sha256") == profile_sha256
                    and previous.get("runtime_go_override", {})
                    == expected_go_override
                ):
                    return {"state": "REUSED", **job.as_dict()}
                if not retry_failed:
                    return {"state": "SKIPPED_PROFILE_MISMATCH", **job.as_dict()}
            if not retry_failed:
                return {"state": "SKIPPED_FAILED", **job.as_dict()}

        attempt, attempt_directory = _next_attempt(scanner_directory)
        executable = _verified_executable(project_root, profile["tool"], "CodeQL")
        command_env = os.environ.copy()
        runtimes: dict[str, dict[str, str]] = {}
        if job.language == "javascript-typescript" and profile.get("node_runtime"):
            node_runtime = profile["node_runtime"]
            node_executable = _verified_executable(
                project_root, node_runtime, "Node.js"
            )
            command_env["PATH"] = (
                str(node_executable.parent) + os.pathsep + command_env["PATH"]
            )
            runtimes["node"] = {
                "version": node_runtime["version"],
                "executable": str(node_executable),
                "executable_sha256": node_runtime["executable_sha256"],
            }
        if job.language == "python":
            python_runtime = profile["python_runtime"]
            python_executable = _verified_executable(
                project_root, python_runtime, "Python"
            )
            command_env[
                "CODEQL_EXTRACTOR_PYTHON_OPTION_PYTHON_EXECUTABLE_NAME"
            ] = str(python_executable)
            runtimes["python"] = {
                "version": python_runtime["version"],
                "executable": str(python_executable),
                "executable_sha256": python_runtime["executable_sha256"],
            }
        if job.language == "go":
            go_runtime = profile["go_runtime"]
            go_executable = _verified_executable(project_root, go_runtime, "Go")
            go_root = go_executable.parent.parent
            go_cache_root = _resolve_path(project_root, go_runtime["cache_root"])
            module_cache = go_cache_root / "pkg" / "mod"
            build_cache = go_cache_root / "build"
            module_cache.mkdir(parents=True, exist_ok=True)
            build_cache.mkdir(parents=True, exist_ok=True)
            command_env["GOROOT"] = str(go_root)
            command_env["GOMODCACHE"] = str(module_cache)
            command_env["GOCACHE"] = str(build_cache)
            command_env["GOTOOLCHAIN"] = "local"
            if go_runtime.get("godebug"):
                command_env["GODEBUG"] = str(go_runtime["godebug"])
            if go_runtime.get("goflags"):
                command_env["GOFLAGS"] = str(go_runtime["goflags"])
            command_env["PATH"] = (
                str(go_executable.parent) + os.pathsep + command_env["PATH"]
            )
            runtimes["go"] = {
                "version": go_runtime["version"],
                "executable": str(go_executable),
                "executable_sha256": go_runtime["executable_sha256"],
            }
            if go_runtime.get("godebug"):
                runtimes["go"]["godebug"] = str(go_runtime["godebug"])
            if go_runtime.get("goflags"):
                runtimes["go"]["goflags"] = str(go_runtime["goflags"])

        source_root = work_root / job.repo_slug / job.commit
        if not source_root.exists():
            if checkout_cache_root is None:
                raise RuntimeError(
                    f"snapshot does not exist and no checkout cache was configured: "
                    f"{source_root}"
                )
            checkout_snapshot(
                job.repo_url,
                job.commit,
                checkout_cache_root,
                work_root,
            )
        verify_snapshot_state(source_root, job.commit)
        database = database_root / job.repo_slug / job.commit / job.language
        database.parent.mkdir(parents=True, exist_ok=True)
        marker_path = database / ".vulngym-codeql-db.json"
        expected_marker = _database_marker(job, profile)
        database_reused = False
        if marker_path.exists() and _read_json(marker_path) == expected_marker:
            database_reused = True

        status: dict[str, Any] = {
            "schema_version": 1,
            "scan_id": profile["scan_id"],
            "attempt": attempt,
            "status": "RUNNING",
            "started_at": _utc_now(),
            "repo_url": job.repo_url,
            "repo_slug": job.repo_slug,
            "commit": job.commit,
            "language": job.language,
            "routing_reason": job.routing_reason,
            "source_root": str(source_root.resolve()),
            "database": str(database.resolve()),
            "database_reused": database_reused,
            "profile": str(profile_path.resolve()),
            "profile_sha256": profile_sha256,
            "runtime_resource_overrides": runtime_resource_overrides or {},
            "runtime_go_override": (
                (runtime_go_override or {}) if job.language == "go" else {}
            ),
            "effective_resources": dict(profile["resources"]),
            "execution_environment": profile.get("execution_environment"),
            "tool": {
                "name": "codeql",
                "version": profile["tool"]["version"],
                "executable": str(executable),
                "executable_sha256": profile["tool"]["executable_sha256"],
            },
            "runtimes": runtimes,
            "query_pack": profile["query_packs"][job.language],
            "query_suite": profile["query_suite"],
            "commands": [],
        }
        _atomic_write_json(attempt_directory / "status.json", status)
        _write_pointer(scanner_directory, status)

        try:
            resources = profile["resources"]
            if not database_reused:
                create_argv = [
                    str(executable),
                    "database",
                    "create",
                    str(database.resolve()),
                    f"--language={job.language}",
                    f"--source-root={source_root.resolve()}",
                    f"--build-mode={profile['policy']['build_modes'][job.language]}",
                    f"--threads={resources['create_threads']}",
                    f"--ram={resources['create_ram_mb']}",
                    "--overwrite",
                ]
                create_timeout = (
                    resources["compiled_create_timeout_seconds"]
                    if job.language == "go"
                    else resources["interpreted_create_timeout_seconds"]
                )
                create_result = _run_logged(
                    create_argv,
                    cwd=source_root,
                    stdout_path=attempt_directory / "create.stdout.log",
                    stderr_path=attempt_directory / "create.stderr.log",
                    timeout_seconds=create_timeout,
                    env=command_env,
                )
                status["commands"].append({"phase": "create", **create_result})
                if create_result["timed_out"]:
                    raise TimeoutError("CodeQL database creation timed out")
                if create_result["returncode"] != 0:
                    raise RuntimeError(
                        f"CodeQL database create exited {create_result['returncode']}"
                    )
                _atomic_write_json(marker_path, expected_marker)

            analyze_argv = [
                str(executable),
                "database",
                "analyze",
                str(database.resolve()),
                _suite_reference(profile, job.language),
                "--format=sarifv2.1.0",
                f"--output={(attempt_directory / 'raw.sarif').resolve()}",
                f"--threads={resources['analyze_threads']}",
                f"--ram={resources['analyze_ram_mb']}",
                f"--sarif-category=codeql/{job.language}",
                "--sarif-add-snippets",
                f"--max-paths={profile['policy'].get('sarif_max_paths_per_result', 4)}",
                "--no-download",
                _query_rerun_flag(database_reused),
            ]
            analyze_result = _run_logged(
                analyze_argv,
                cwd=project_root,
                stdout_path=attempt_directory / "analyze.stdout.log",
                stderr_path=attempt_directory / "analyze.stderr.log",
                timeout_seconds=resources["analyze_timeout_seconds"],
                env=command_env,
            )
            status["commands"].append({"phase": "analyze", **analyze_result})
            if analyze_result["timed_out"]:
                raise TimeoutError("CodeQL database analysis timed out")
            if analyze_result["returncode"] != 0:
                raise RuntimeError(
                    f"CodeQL database analyze exited {analyze_result['returncode']}"
                )
            status["result_summary"] = _result_summary(
                attempt_directory / "raw.sarif"
            )
            status["checksums"] = {
                name: _sha256(attempt_directory / name)
                for name in (
                    "raw.sarif",
                    "create.stdout.log",
                    "create.stderr.log",
                    "analyze.stdout.log",
                    "analyze.stderr.log",
                )
                if (attempt_directory / name).exists()
            }
            status["status"] = "SUCCESS"
        except TimeoutError as exc:
            status["status"] = "TIMEOUT"
            status["error"] = {"type": type(exc).__name__, "message": str(exc)}
        except Exception as exc:
            status["status"] = "FAILED"
            status["error"] = {"type": type(exc).__name__, "message": str(exc)}

        status["finished_at"] = _utc_now()
        status["duration_seconds"] = round(
            sum(command["duration_seconds"] for command in status["commands"]), 3
        )
        _atomic_write_json(attempt_directory / "status.json", status)
        _write_pointer(scanner_directory, status)
        return {"state": status["status"], **job.as_dict(), "status": status}


def _filter_jobs(jobs: list[CodeQLJob], args: argparse.Namespace) -> list[CodeQLJob]:
    selected = jobs
    if args.pilot:
        selected = [
            job
            for job in selected
            if (job.repo_url, job.commit, job.language) in PILOT_JOBS
        ]
    if args.repo_url:
        normalized = _normalize_repo_url(args.repo_url)
        selected = [job for job in selected if job.repo_url == normalized]
    excluded_repo_urls = {
        _normalize_repo_url(value)
        for value in (getattr(args, "exclude_repo_url", None) or [])
    }
    if excluded_repo_urls:
        selected = [
            job for job in selected if job.repo_url not in excluded_repo_urls
        ]
    if args.commit:
        selected = [job for job in selected if job.commit == args.commit]
    if args.language:
        selected = [job for job in selected if job.language == args.language]
    if args.max_jobs is not None:
        selected = selected[: args.max_jobs]
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan and run reproducible CodeQL security-extended jobs."
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("artifacts/manifests/vulngym-v0.1.4.json"),
    )
    parser.add_argument(
        "--entries",
        type=Path,
        default=Path("benchmark/VulnGym/data/entries.jsonl"),
    )
    parser.add_argument(
        "--profile", type=Path, default=Path("config/codeql-profile.json")
    )
    parser.add_argument("--scan-root", type=Path)
    parser.add_argument("--database-root", type=Path)
    parser.add_argument("--work-root", type=Path, default=Path("worktrees"))
    parser.add_argument("--checkout-cache-root", type=Path)
    parser.add_argument("--plan-output", type=Path)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--repo-url")
    parser.add_argument(
        "--exclude-repo-url",
        action="append",
        default=[],
        help="Skip a repository for this run; may be repeated.",
    )
    parser.add_argument("--commit")
    parser.add_argument("--language", choices=sorted(SUPPORTED_LANGUAGES))
    parser.add_argument("--max-jobs", type=int)
    parser.add_argument("--retry-failed", action="store_true")
    parser.add_argument(
        "--runtime-analyze-threads",
        type=int,
        help=(
            "Operational analyze thread override recorded in provenance but "
            "excluded from the immutable profile checksum."
        ),
    )
    parser.add_argument(
        "--runtime-analyze-ram-mb",
        type=int,
        help=(
            "Operational analyze RAM override recorded in provenance but "
            "excluded from the immutable profile checksum."
        ),
    )
    parser.add_argument("--runtime-go-version")
    parser.add_argument("--runtime-go-executable")
    parser.add_argument("--runtime-go-executable-sha256")
    parser.add_argument(
        "--runtime-go-godebug",
        choices=("http2client=0",),
        help="Recorded Go network compatibility override for unstable WSL HTTP/2.",
    )
    parser.add_argument(
        "--runtime-go-goflags",
        choices=("-mod=mod",),
        help="Recorded Go module mode used during database extraction.",
    )
    args = parser.parse_args(argv)

    if args.max_jobs is not None and args.max_jobs < 1:
        parser.error("--max-jobs must be positive")
    project_root = Path.cwd().resolve()
    manifest_path = _resolve_path(project_root, args.manifest)
    entries_path = _resolve_path(project_root, args.entries)
    profile_path = _resolve_path(project_root, args.profile)
    profile = _read_json(profile_path)
    try:
        runtime_resource_overrides = _apply_runtime_resource_overrides(
            profile,
            analyze_threads=args.runtime_analyze_threads,
            analyze_ram_mb=args.runtime_analyze_ram_mb,
        )
        runtime_go_override = _apply_runtime_go_override(
            profile,
            version=args.runtime_go_version,
            executable=args.runtime_go_executable,
            executable_sha256=args.runtime_go_executable_sha256,
            godebug=args.runtime_go_godebug,
            goflags=args.runtime_go_goflags,
        )
    except ValueError as exc:
        parser.error(str(exc))
    all_jobs = build_job_plan(_read_json(manifest_path), _read_jsonl(entries_path))
    jobs = _filter_jobs(all_jobs, args)
    scan_root = (
        _resolve_path(project_root, args.scan_root)
        if args.scan_root
        else project_root / "artifacts" / "scans" / profile["scan_id"]
    )
    database_root = (
        _resolve_path(project_root, args.database_root)
        if args.database_root
        else project_root / "artifacts" / "codeql" / profile["scan_id"] / "databases"
    )
    work_root = _resolve_path(project_root, args.work_root)
    checkout_cache_root = (
        _resolve_path(project_root, args.checkout_cache_root)
        if args.checkout_cache_root
        else None
    )
    plan = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "scan_id": profile["scan_id"],
        "profile": str(profile_path),
        "profile_sha256": _sha256(profile_path),
        "runtime_resource_overrides": runtime_resource_overrides,
        "runtime_go_override": runtime_go_override,
        "effective_resources": dict(profile["resources"]),
        "manifest": str(manifest_path),
        "manifest_sha256": _sha256(manifest_path),
        "entries": str(entries_path),
        "entries_sha256": _sha256(entries_path),
        "scan_root": str(scan_root),
        "database_root": str(database_root),
        "work_root": str(work_root),
        "checkout_cache_root": (
            str(checkout_cache_root) if checkout_cache_root else None
        ),
        "job_count": len(jobs),
        "language_counts": dict(sorted(Counter(job.language for job in jobs).items())),
        "jobs": [job.as_dict() for job in jobs],
    }
    filtered_plan = bool(
        args.pilot
        or args.repo_url
        or args.exclude_repo_url
        or args.commit
        or args.language
        or args.max_jobs
    )
    default_plan_name = f"{profile['scan_id']}{'-selection' if filtered_plan else ''}.json"
    if args.pilot:
        default_plan_name = f"{profile['scan_id']}-pilot.json"
    plan_output = (
        _resolve_path(project_root, args.plan_output)
        if args.plan_output
        else project_root / "artifacts" / "manifests" / default_plan_name
    )
    _atomic_write_json(plan_output, plan)
    print(f"planned {len(jobs)} CodeQL jobs: {plan_output}")
    if args.plan_only:
        return 0

    counts: Counter[str] = Counter()
    for index, job in enumerate(jobs, 1):
        print(
            f"[{index}/{len(jobs)}] {job.repo_slug}@{job.commit[:12]} {job.language}",
            flush=True,
        )
        result = run_job(
            job,
            project_root=project_root,
            profile_path=profile_path,
            profile=profile,
            scan_root=scan_root,
            database_root=database_root,
            work_root=work_root,
            checkout_cache_root=checkout_cache_root,
            retry_failed=args.retry_failed,
            runtime_resource_overrides=runtime_resource_overrides,
            runtime_go_override=runtime_go_override,
        )
        counts[result["state"]] += 1
        print(f"  {result['state']}", flush=True)
    print(json.dumps(dict(sorted(counts.items())), ensure_ascii=False))
    return 1 if counts["FAILED"] or counts["TIMEOUT"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
