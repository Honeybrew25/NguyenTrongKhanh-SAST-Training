from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from .checkout import (
    InterprocessLockTimeout,
    checkout_snapshot,
    ensure_mirror,
    interprocess_lock,
    repo_slug,
)

SUPPORTED_SCANNERS = ("semgrep", "opengrep")
DEFAULT_SCANNERS = ("opengrep",)

_RETRY_POLICY_SCHEMA_VERSION = 1
_MAX_COMPLETED_TIMEOUT_ATTEMPTS = 2
_JOB_LOCK_TIMEOUT_SECONDS = 1

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ATTEMPT_DIRECTORY = re.compile(r"^\d{4,}$")
_NESTED_DIRECTORY_EXCLUDE = re.compile(r"^\*\*/([^*?\[\]/\\]+)/\*\*$")
_FROZEN_INPUT_FILENAMES = {
    "manifest": "manifest.json",
    "scanner_lock": "scanner-lock.json",
    "scan_profile": "scan-profile.json",
}

# VulnGym is currently dominated by these languages. A manifest may also carry
# an explicit ``languages`` list; that takes precedence over suffix detection.
_LANGUAGE_SUFFIXES: dict[str, frozenset[str]] = {
    "python": frozenset({".py", ".pyi"}),
    "javascript": frozenset({".js", ".jsx", ".mjs", ".cjs"}),
    "typescript": frozenset({".ts", ".tsx", ".mts", ".cts"}),
    "go": frozenset({".go"}),
    "java": frozenset({".java"}),
    "c": frozenset({".c", ".h"}),
    "csharp": frozenset({".cs"}),
    "php": frozenset({".php"}),
    "ruby": frozenset({".rb"}),
    "rust": frozenset({".rs"}),
    "kotlin": frozenset({".kt", ".kts"}),
    "scala": frozenset({".scala"}),
}
_LANGUAGE_ALIASES = {
    "js": "javascript",
    "node": "javascript",
    "ts": "typescript",
    "py": "python",
    "golang": "go",
    "c#": "csharp",
}
_PRUNED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    "coverage",
    "generated",
    "third_party",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _atomic_write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_bytes(value)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _canonical_json_text(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"{label} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return value


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} must be a non-empty string")
    return value


def _positive_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{context} must be a positive integer")
    return value


def _positive_number(value: Any, context: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"{context} must be a positive number")
    return value


def _normalized_config_path(value: str) -> str:
    return value.replace("\\", "/").rstrip("/")


def validate_configuration(
    manifest: dict[str, Any], scanner_lock: dict[str, Any], scan_profile: dict[str, Any]
) -> None:
    """Validate the three frozen inputs and their cross-file pins.

    This is deliberately stricter than merely checking that expected keys are
    present. A batch must not silently scan a different benchmark or ruleset.
    """

    for value, context in (
        (manifest, "manifest"),
        (scanner_lock, "scanner lock"),
        (scan_profile, "scan profile"),
    ):
        if value.get("schema_version") != 1:
            raise ValueError(f"{context}.schema_version must be 1")

    manifest_benchmark = _object(manifest.get("benchmark"), "manifest.benchmark")
    lock_benchmark = _object(scanner_lock.get("benchmark"), "scanner_lock.benchmark")
    manifest_commit = _string(manifest_benchmark.get("commit"), "manifest.benchmark.commit")
    lock_commit = _string(lock_benchmark.get("commit"), "scanner_lock.benchmark.commit")
    if not _SHA40.fullmatch(manifest_commit) or not _SHA40.fullmatch(lock_commit):
        raise ValueError("benchmark commits must be full lowercase SHA-1 values")
    if manifest_commit != lock_commit:
        raise ValueError(
            f"benchmark commit mismatch: manifest={manifest_commit}, scanner_lock={lock_commit}"
        )
    for field in ("name", "tag"):
        if field in manifest_benchmark and field in lock_benchmark:
            if manifest_benchmark[field] != lock_benchmark[field]:
                raise ValueError(f"benchmark {field} mismatch between manifest and scanner lock")

    snapshots = manifest.get("snapshots")
    if not isinstance(snapshots, list):
        raise ValueError("manifest.snapshots must be a list")
    seen_snapshots: set[tuple[str, str]] = set()
    for index, snapshot_value in enumerate(snapshots):
        snapshot = _object(snapshot_value, f"manifest.snapshots[{index}]")
        repo_url = _string(snapshot.get("repo_url"), f"manifest.snapshots[{index}].repo_url")
        commit = _string(snapshot.get("commit"), f"manifest.snapshots[{index}].commit")
        repo_slug(repo_url)
        if not _SHA40.fullmatch(commit):
            raise ValueError(f"manifest.snapshots[{index}].commit must be a full lowercase SHA-1")
        key = (repo_url, commit)
        if key in seen_snapshots:
            raise ValueError(f"duplicate snapshot in manifest: {repo_url}@{commit}")
        seen_snapshots.add(key)
        if "languages" in snapshot:
            languages = snapshot["languages"]
            if not isinstance(languages, list) or not all(
                isinstance(language, str) and language.strip() for language in languages
            ):
                raise ValueError(f"manifest.snapshots[{index}].languages must be a list of strings")

    lock_rules = _object(scanner_lock.get("ruleset"), "scanner_lock.ruleset")
    profile_rules = _object(scan_profile.get("rules"), "scan_profile.rules")
    lock_rules_commit = _string(lock_rules.get("commit"), "scanner_lock.ruleset.commit")
    profile_rules_commit = _string(profile_rules.get("commit"), "scan_profile.rules.commit")
    if not _SHA40.fullmatch(lock_rules_commit) or not _SHA40.fullmatch(profile_rules_commit):
        raise ValueError("ruleset commits must be full lowercase SHA-1 values")
    if lock_rules_commit != profile_rules_commit:
        raise ValueError("ruleset commit mismatch between scanner lock and scan profile")
    lock_rules_path = _string(lock_rules.get("path"), "scanner_lock.ruleset.path")
    profile_rules_root = _string(profile_rules.get("root"), "scan_profile.rules.root")
    if _normalized_config_path(lock_rules_path) != _normalized_config_path(profile_rules_root):
        raise ValueError("ruleset path mismatch between scanner lock and scan profile")
    if profile_rules.get("engines_share_rules") is not True:
        raise ValueError("scan_profile.rules.engines_share_rules must be true")

    language_configs = profile_rules.get("language_configs")
    if language_configs is not None:
        if not isinstance(language_configs, dict) or not language_configs:
            raise ValueError("scan_profile.rules.language_configs must be a non-empty object")
        for language, config_values in language_configs.items():
            if not isinstance(language, str) or not language.strip():
                raise ValueError("language config names must be non-empty strings")
            values = [config_values] if isinstance(config_values, str) else config_values
            if not isinstance(values, list) or not values or not all(
                isinstance(item, str) and item.strip() for item in values
            ):
                raise ValueError(
                    f"scan_profile.rules.language_configs.{language} must be a path or list of paths"
                )
    language_extensions = profile_rules.get("language_extensions")
    if language_extensions is not None:
        if not isinstance(language_extensions, dict) or not language_extensions:
            raise ValueError("scan_profile.rules.language_extensions must be a non-empty object")
        for language, suffixes in language_extensions.items():
            if not isinstance(language, str) or not language.strip():
                raise ValueError("language extension names must be non-empty strings")
            if not isinstance(suffixes, list) or not suffixes or not all(
                isinstance(suffix, str) and suffix.startswith(".") and len(suffix) > 1
                for suffix in suffixes
            ):
                raise ValueError(
                    f"scan_profile.rules.language_extensions.{language} must be a list of suffixes"
                )

    scanner_configs = _object(scanner_lock.get("scanners"), "scanner_lock.scanners")
    if not scanner_configs:
        raise ValueError("scanner_lock.scanners must contain at least one scanner")
    unsupported_scanner_configs = sorted(set(scanner_configs) - set(SUPPORTED_SCANNERS))
    if unsupported_scanner_configs:
        raise ValueError(
            f"scanner_lock.scanners contains unsupported scanners: {unsupported_scanner_configs}"
        )
    for scanner_name in scanner_configs:
        scanner_config = _object(
            scanner_configs.get(scanner_name), f"scanner_lock.scanners.{scanner_name}"
        )
        if "enabled" in scanner_config and not isinstance(
            scanner_config["enabled"], bool
        ):
            raise ValueError(
                f"scanner_lock.scanners.{scanner_name}.enabled must be a boolean"
            )
        _string(scanner_config.get("version"), f"scanner_lock.scanners.{scanner_name}.version")
        if "local_path" in scanner_config:
            _string(
                scanner_config["local_path"],
                f"scanner_lock.scanners.{scanner_name}.local_path",
            )
        executable_checksum = scanner_config.get("local_executable_sha256")
        fallback_checksum = scanner_config.get("windows_asset_sha256")
        if executable_checksum is None and fallback_checksum is None:
            raise ValueError(
                f"scanner_lock.scanners.{scanner_name} must pin local_executable_sha256 "
                "or windows_asset_sha256"
            )
        for field, checksum in (
            ("local_executable_sha256", executable_checksum),
            ("windows_asset_sha256", fallback_checksum),
        ):
            if checksum is not None and (
                not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum)
            ):
                raise ValueError(
                    f"scanner_lock.scanners.{scanner_name}.{field} must be a lowercase SHA-256"
                )

    scan = _object(scan_profile.get("scan"), "scan_profile.scan")
    _positive_number(scan.get("timeout_seconds_per_rule"), "scan_profile.scan.timeout_seconds_per_rule")
    _positive_int(scan.get("max_target_bytes"), "scan_profile.scan.max_target_bytes")
    _positive_int(scan.get("max_memory_mb"), "scan_profile.scan.max_memory_mb")
    _positive_int(scan.get("jobs"), "scan_profile.scan.jobs")
    if not isinstance(scan.get("respect_git_ignore"), bool):
        raise ValueError("scan_profile.scan.respect_git_ignore must be a boolean")
    git_ignore_fallback = scan.get("git_ignore_parse_failure_fallback", "disabled")
    if git_ignore_fallback not in {"disabled", "no_git_ignore_on_clean_snapshot"}:
        raise ValueError(
            "scan_profile.scan.git_ignore_parse_failure_fallback must be disabled "
            "or no_git_ignore_on_clean_snapshot"
        )
    excludes = scan.get("exclude")
    if not isinstance(excludes, list) or not all(
        isinstance(pattern, str) and pattern.strip() for pattern in excludes
    ):
        raise ValueError("scan_profile.scan.exclude must be a list of non-empty strings")
    outputs = scan.get("outputs")
    if not isinstance(outputs, list) or not {"json", "sarif"}.issubset(outputs):
        raise ValueError("scan_profile.scan.outputs must include json and sarif")
    if "job_timeout_seconds" in scan:
        _positive_number(scan["job_timeout_seconds"], "scan_profile.scan.job_timeout_seconds")
    if not isinstance(scan.get("semgrep_oss_only"), bool):
        raise ValueError("scan_profile.scan.semgrep_oss_only must be a boolean")
    if scan.get("metrics") not in {"on", "off", "auto"}:
        raise ValueError("scan_profile.scan.metrics must be one of: on, off, auto")
    policy = _object(scan_profile.get("policy"), "scan_profile.policy")
    for field in (
        "scan_exact_vulnerable_commit",
        "preserve_raw_output",
        "unmatched_is_not_false_positive",
    ):
        if policy.get(field) is not True:
            raise ValueError(f"scan_profile.policy.{field} must be true")


def load_configuration(
    manifest_path: Path, scanner_lock_path: Path, scan_profile_path: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    manifest = _read_json_object(manifest_path, "manifest")
    scanner_lock = _read_json_object(scanner_lock_path, "scanner lock")
    scan_profile = _read_json_object(scan_profile_path, "scan profile")
    validate_configuration(manifest, scanner_lock, scan_profile)
    return manifest, scanner_lock, scan_profile


def select_snapshots(
    manifest: dict[str, Any],
    repo_urls: Sequence[str] | None = None,
    commits: Sequence[str] | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    if limit is not None:
        _positive_int(limit, "limit")
    repo_filter = set(repo_urls or ())
    for repo_url in repo_filter:
        repo_slug(repo_url)
    commit_filter = set(commits or ())
    for commit in commit_filter:
        if not _SHA40.fullmatch(commit):
            raise ValueError(f"commit filter must be a full lowercase SHA-1: {commit}")

    selected = [
        snapshot
        for snapshot in manifest["snapshots"]
        if (not repo_filter or snapshot["repo_url"] in repo_filter)
        and (not commit_filter or snapshot["commit"] in commit_filter)
    ]
    if repo_filter:
        matched_repositories = {snapshot["repo_url"] for snapshot in selected}
        missing_repositories = sorted(repo_filter - matched_repositories)
        if missing_repositories:
            raise ValueError(
                "repository filters did not match the selected manifest entries: "
                + ", ".join(missing_repositories)
            )
    if commit_filter:
        matched_commits = {snapshot["commit"] for snapshot in selected}
        missing_commits = sorted(commit_filter - matched_commits)
        if missing_commits:
            raise ValueError(
                "commit filters did not match the selected manifest entries: "
                + ", ".join(missing_commits)
            )
    selected.sort(key=lambda item: (item["repo_url"], item["commit"]))
    if limit is not None:
        selected = selected[:limit]
    if not selected:
        raise ValueError("snapshot filters matched no manifest entries")
    return selected


def _resolve_path(path: Path, project_root: Path) -> Path:
    return (path if path.is_absolute() else project_root / path).resolve()


def _ensure_rule_config(config_path: Path, rules_root: Path) -> Path:
    resolved = config_path.resolve()
    root = rules_root.resolve()
    if resolved == root:
        raise ValueError(
            "refusing to scan the entire ruleset root; use language_configs or --rule-config"
        )
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"rule config is outside the pinned ruleset: {resolved}") from exc
    if not resolved.exists():
        raise ValueError(f"rule config does not exist: {resolved}")
    if resolved.is_file() and resolved.suffix.lower() not in {".yml", ".yaml"}:
        raise ValueError(f"rule config file must be YAML: {resolved}")
    if resolved.is_dir() and not any(
        candidate.is_file() and candidate.suffix.lower() in {".yml", ".yaml"}
        for candidate in resolved.rglob("*")
    ):
        raise ValueError(f"rule config directory contains no YAML rules: {resolved}")
    return resolved


def resolve_rule_configs(
    scan_profile: dict[str, Any],
    project_root: Path,
    overrides: Sequence[Path] | None = None,
) -> tuple[
    Path,
    dict[str, tuple[Path, ...]],
    tuple[Path, ...],
    dict[str, frozenset[str]],
]:
    """Resolve and validate the pinned root and either routed or CLI configs."""

    rules = scan_profile["rules"]
    rules_root = _resolve_path(Path(rules["root"]), project_root)
    if not rules_root.is_dir():
        raise ValueError(f"ruleset root does not exist or is not a directory: {rules_root}")

    override_configs: list[Path] = []
    for override in overrides or ():
        raw_override = Path(override)
        if raw_override.is_absolute():
            override_path = raw_override.resolve()
        else:
            # Project-root-relative paths remain supported for an explicit CLI
            # override. A short path such as ``python`` is relative to the
            # pinned rules root.
            project_candidate = (project_root / raw_override).resolve()
            override_path = (
                project_candidate
                if project_candidate.exists()
                else (rules_root / raw_override).resolve()
            )
        config = _ensure_rule_config(override_path, rules_root)
        if config not in override_configs:
            override_configs.append(config)

    routed: dict[str, tuple[Path, ...]] = {}
    raw_mapping = rules.get("language_configs") or {}
    for raw_language, raw_values in raw_mapping.items():
        language = _LANGUAGE_ALIASES.get(raw_language.strip().lower(), raw_language.strip().lower())
        values = [raw_values] if isinstance(raw_values, str) else raw_values
        configs: list[Path] = []
        for raw_value in values:
            config = _ensure_rule_config(
                (
                    Path(raw_value).resolve()
                    if Path(raw_value).is_absolute()
                    else (rules_root / raw_value).resolve()
                ),
                rules_root,
            )
            if config not in configs:
                configs.append(config)
        routed[language] = tuple(configs)

    if not override_configs and not routed:
        raise ValueError(
            "no applicable rule configs configured; add scan_profile.rules.language_configs "
            "or pass --rule-config"
        )
    configured_extensions: dict[str, frozenset[str]] = {}
    for raw_language, raw_suffixes in (rules.get("language_extensions") or {}).items():
        language = _LANGUAGE_ALIASES.get(raw_language.strip().lower(), raw_language.strip().lower())
        configured_extensions[language] = frozenset(
            suffix.lower() for suffix in raw_suffixes
        )
    for language in routed:
        if language not in configured_extensions and language in _LANGUAGE_SUFFIXES:
            configured_extensions[language] = _LANGUAGE_SUFFIXES[language]
    return rules_root, routed, tuple(override_configs), configured_extensions


def detect_languages(
    snapshot_path: Path,
    configured_languages: Sequence[str],
    language_extensions: dict[str, frozenset[str]] | None = None,
) -> list[str]:
    candidates = {
        _LANGUAGE_ALIASES.get(language.lower(), language.lower()) for language in configured_languages
    }
    suffixes_by_language = language_extensions or _LANGUAGE_SUFFIXES
    detected: set[str] = set()
    for directory, directory_names, file_names in os.walk(snapshot_path):
        directory_names[:] = [
            name for name in directory_names if name not in _PRUNED_DIRECTORIES
        ]
        for file_name in file_names:
            suffix = Path(file_name).suffix.lower()
            for language in candidates - detected:
                if suffix in suffixes_by_language.get(language, frozenset()):
                    detected.add(language)
        if detected == candidates:
            break
    return sorted(detected)


def _rule_configs_for_snapshot(
    snapshot: dict[str, Any],
    snapshot_path: Path,
    routed_configs: dict[str, tuple[Path, ...]],
    override_configs: tuple[Path, ...],
    language_extensions: dict[str, frozenset[str]],
) -> tuple[list[str], tuple[Path, ...], str]:
    if override_configs:
        return [], override_configs, "cli"

    if "languages" in snapshot:
        languages = sorted(
            {
                _LANGUAGE_ALIASES.get(language.strip().lower(), language.strip().lower())
                for language in snapshot["languages"]
            }
        )
    else:
        languages = detect_languages(
            snapshot_path, tuple(routed_configs), language_extensions
        )

    configs: list[Path] = []
    for language in languages:
        for config in routed_configs.get(language, ()):
            if config not in configs:
                configs.append(config)
    return languages, tuple(configs), "language-routing"


def _subprocess_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "1"
    return environment


def _run_process(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise TypeError("subprocess argv must be a list of strings")
    if kwargs.get("text") is True:
        kwargs.setdefault("encoding", "utf-8")
        kwargs.setdefault("errors", "replace")
    return subprocess.run(
        argv,
        shell=False,
        env=_subprocess_environment(),
        **kwargs,
    )


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    """Best-effort hard stop for a scanner and every descendant it spawned."""

    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _run_scanner_process(
    argv: list[str], *, cwd: Path, timeout: int | float | None
) -> subprocess.CompletedProcess[str]:
    """Run one scanner in its own process group and reap its tree on timeout."""

    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise TypeError("subprocess argv must be a list of strings")
    popen_kwargs: dict[str, Any] = {
        "cwd": cwd,
        "shell": False,
        "env": _subprocess_environment(),
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True
    process = subprocess.Popen(argv, **popen_kwargs)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        partial_stdout = _as_text(exc.stdout or exc.output)
        partial_stderr = _as_text(exc.stderr)
        _terminate_process_tree(process)
        try:
            final_stdout, final_stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            final_stdout, final_stderr = process.communicate()
        raise subprocess.TimeoutExpired(
            argv,
            timeout,
            output=_as_text(final_stdout) or partial_stdout,
            stderr=_as_text(final_stderr) or partial_stderr,
        ) from exc
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def verify_ruleset_pin(rules_root: Path, expected_commit: str) -> str:
    result = _run_process(
        ["git", "-C", str(rules_root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    actual = result.stdout.strip()
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit code {result.returncode}"
        raise RuntimeError(f"cannot verify ruleset commit at {rules_root}: {detail}")
    if actual != expected_commit:
        raise RuntimeError(f"ruleset commit mismatch: expected {expected_commit}, got {actual}")
    status = _run_process(
        [
            "git",
            "-C",
            str(rules_root),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if status.returncode != 0:
        detail = status.stderr.strip() or f"exit code {status.returncode}"
        raise RuntimeError(f"cannot verify ruleset worktree at {rules_root}: {detail}")
    dirty = status.stdout.splitlines()
    if dirty:
        raise RuntimeError(
            f"ruleset worktree is dirty at {rules_root}: " + "; ".join(dirty[:10])
        )
    return actual


def scanner_executable(scanner_name: str, scanner_lock: dict[str, Any], project_root: Path) -> str:
    if scanner_name not in SUPPORTED_SCANNERS:
        raise ValueError(f"unsupported scanner: {scanner_name}")
    scanner_config = scanner_lock["scanners"][scanner_name]
    if "local_path" not in scanner_config:
        return scanner_config.get("executable", scanner_name)
    executable = _resolve_path(Path(scanner_config["local_path"]), project_root)
    if not executable.is_file():
        raise RuntimeError(f"scanner executable does not exist: {executable}")
    return str(executable)


def verify_scanner_executable_checksum(
    executable: str, scanner_config: dict[str, Any]
) -> str:
    expected = scanner_config.get("local_executable_sha256") or scanner_config.get(
        "windows_asset_sha256"
    )
    if not isinstance(expected, str):
        raise RuntimeError(f"no executable SHA-256 is pinned for {executable}")
    executable_path = Path(executable)
    if not executable_path.is_file():
        discovered = shutil.which(executable)
        if discovered is None:
            raise RuntimeError(f"cannot locate scanner executable for checksum verification: {executable}")
        executable_path = Path(discovered)
    actual = _sha256_file(executable_path.resolve())
    if actual != expected:
        raise RuntimeError(
            f"scanner executable checksum mismatch for {executable_path}: "
            f"expected {expected}, got {actual}"
        )
    return actual


def verify_scanner_version(executable: str, expected_version: str) -> str:
    try:
        result = _run_scanner_process(
            [executable, "--version"], cwd=Path.cwd(), timeout=30
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"scanner version check timed out for {executable}") from exc
    except OSError as exc:
        raise RuntimeError(f"cannot execute scanner {executable}: {exc}") from exc
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    if result.returncode != 0:
        raise RuntimeError(
            f"scanner version check failed for {executable}: {output or result.returncode}"
        )
    version_pattern = re.compile(
        rf"(?<![0-9A-Za-z.]){re.escape(expected_version)}(?![0-9A-Za-z.])"
    )
    if not version_pattern.search(output):
        raise RuntimeError(
            f"scanner version mismatch for {executable}: expected {expected_version}, got {output!r}"
        )
    return expected_version


def _number_argument(value: int | float) -> str:
    return str(int(value)) if isinstance(value, float) and value.is_integer() else str(value)


def build_scan_argv(
    scanner_name: str,
    executable: str,
    rule_configs: Sequence[Path],
    scan_profile: dict[str, Any],
    attempt_directory: Path,
    respect_git_ignore: bool | None = None,
    exclude_patterns: Sequence[str] | None = None,
) -> list[str]:
    if scanner_name not in SUPPORTED_SCANNERS:
        raise ValueError(f"unsupported scanner: {scanner_name}")
    if not rule_configs:
        raise ValueError("at least one applicable rule config is required")

    argv = [executable, "scan"]
    config_flag = "--config" if scanner_name == "semgrep" else "-f"
    for config in rule_configs:
        argv.extend([config_flag, str(config)])

    scan = scan_profile["scan"]
    if scan["semgrep_oss_only"]:
        argv.append("--oss-only")
    # OpenGrep removed Semgrep's telemetry/metrics option in v1.6.0. Keep the
    # pinned profile value for comparable provenance, but only pass it to the
    # engine that implements the flag.
    if scanner_name == "semgrep":
        argv.extend(["--metrics", scan["metrics"]])
    else:
        # Each snapshot is an isolated, pinned invocation. Avoid one network
        # version check and a potentially very large human-readable finding
        # stream per job; JSON and SARIF remain the authoritative raw outputs.
        argv.extend(["--disable-version-check", "--output", os.devnull])
    argv.extend(
        [
            "--dataflow-traces",
            "--timeout",
            _number_argument(scan["timeout_seconds_per_rule"]),
            "--max-target-bytes",
            str(scan["max_target_bytes"]),
            "--max-memory",
            str(scan["max_memory_mb"]),
            "--jobs",
            str(scan["jobs"]),
            (
                "--use-git-ignore"
                if (
                    scan["respect_git_ignore"]
                    if respect_git_ignore is None
                    else respect_git_ignore
                )
                else "--no-git-ignore"
            ),
        ]
    )
    for pattern in exclude_patterns if exclude_patterns is not None else scan["exclude"]:
        argv.extend(["--exclude", pattern])
    argv.extend(
        [
            "--json-output",
            str((attempt_directory / "raw.json").resolve()),
            "--sarif-output",
            str((attempt_directory / "raw.sarif").resolve()),
            ".",
        ]
    )
    return argv


def _semgrep_compatible_exclude_patterns(patterns: Sequence[str]) -> list[str]:
    """Use equivalent directory-name globs that Semgrep 1.171.0 can parse.

    Semgrep documents ``--exclude=tests`` as matching that directory at any
    depth.  The pinned Windows build can nevertheless fail with
    ``lexing: empty token`` for the equivalent ``**/tests/**`` spelling on
    some snapshots.  This projection is used only after that exact parser
    failure and is recorded in the immutable attempt status.
    """

    compatible: list[str] = []
    for pattern in patterns:
        match = _NESTED_DIRECTORY_EXCLUDE.fullmatch(pattern)
        compatible.append(match.group(1) if match is not None else pattern)
    return compatible


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _is_git_ignore_parser_failure(stderr: str) -> bool:
    text = stderr.casefold()
    return "failed to obtain target files" in text and (
        "parse_gitignore" in text
        or "semgrepignore" in text
        or "lexing: empty token" in text
    )


def _validate_raw_outputs(attempt_directory: Path) -> list[str]:
    errors: list[str] = []
    for name in ("raw.json", "raw.sarif"):
        path = attempt_directory / name
        if not path.is_file():
            errors.append(f"missing scanner output: {name}")
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            errors.append(f"invalid {name}: {exc}")
            continue
        if not isinstance(value, dict):
            errors.append(f"invalid {name}: top-level value must be an object")
    return errors


def _raw_json_diagnostics(attempt_directory: Path) -> dict[str, Any]:
    """Summarize non-fatal scanner errors without changing SUCCESS semantics."""

    raw = _read_json_object(attempt_directory / "raw.json", "raw scanner JSON")
    raw_errors = raw.get("errors") or []
    if not isinstance(raw_errors, list):
        raise ValueError("raw scanner JSON errors must be a list")
    error_types: Counter[str] = Counter()
    partial_paths: set[str] = set()
    for raw_error in raw_errors:
        error = raw_error if isinstance(raw_error, dict) else {"message": str(raw_error)}
        error_type: Any = error.get("type") or error.get("error_type") or "unknown"
        if isinstance(error_type, list) and error_type:
            error_type = error_type[0]
        normalized_type = str(error_type)
        error_types[normalized_type] += 1
        if normalized_type == "PartialParsing":
            path = str(error.get("path") or "").replace("\\", "/")
            if path:
                partial_paths.add(path)
    results = raw.get("results") or []
    scanned = (raw.get("paths") or {}).get("scanned") or []
    return {
        "errors_total": len(raw_errors),
        "error_types": dict(sorted(error_types.items())),
        "partial_parsing_files": sorted(partial_paths),
        "findings": len(results) if isinstance(results, list) else None,
        "scanned_paths": len(scanned) if isinstance(scanned, list) else None,
    }


def _attempt_numbers(scanner_directory: Path) -> list[int]:
    attempts_directory = scanner_directory / "attempts"
    if not attempts_directory.is_dir():
        return []
    return sorted(
        int(candidate.name)
        for candidate in attempts_directory.iterdir()
        if candidate.is_dir() and _ATTEMPT_DIRECTORY.fullmatch(candidate.name)
    )


def _latest_attempt(scanner_directory: Path) -> tuple[int, Path, dict[str, Any] | None] | None:
    numbers = _attempt_numbers(scanner_directory)
    if not numbers:
        return None
    number = numbers[-1]
    directory = scanner_directory / "attempts" / f"{number:04d}"
    status_path = directory / "status.json"
    try:
        status = _read_json_object(status_path, "attempt status")
    except ValueError:
        status = None
    return number, directory, status


def _attempt_statuses(
    scanner_directory: Path,
) -> list[tuple[int, Path, dict[str, Any]]]:
    """Read every attempt status, failing closed for retry-budget accounting."""

    statuses: list[tuple[int, Path, dict[str, Any]]] = []
    for number in _attempt_numbers(scanner_directory):
        directory = scanner_directory / "attempts" / f"{number:04d}"
        status = _read_json_object(directory / "status.json", "attempt status")
        if status.get("attempt") != number:
            raise ValueError(
                f"attempt number mismatch in {directory / 'status.json'}: "
                f"{status.get('attempt')!r} != {number}"
            )
        statuses.append((number, directory, status))
    return statuses


def _is_reusable_terminal_status(status: dict[str, Any]) -> bool:
    error = status.get("error") or {}
    return status.get("status") == "SUCCESS" or (
        status.get("status") == "SKIPPED"
        and isinstance(error, dict)
        and error.get("type") == "NoApplicableRuleConfig"
    )


def _completed_timeout_count(statuses: Sequence[tuple[int, Path, dict[str, Any]]]) -> int:
    return sum(status.get("status") == "TIMEOUT" for _, _, status in statuses)


def _write_scanner_pointer(
    scanner_directory: Path,
    attempt_directory: Path,
    status: dict[str, Any],
    scheduling: dict[str, Any] | None = None,
) -> None:
    pointer = {
        "schema_version": 2 if scheduling is not None else 1,
        "scan_id": status["scan_id"],
        "repo_url": status["repo_url"],
        "commit": status["commit"],
        "scanner": status["scanner"]["name"],
        "latest_attempt": status["attempt"],
        "status": status["status"],
        "attempt_status": str(
            (attempt_directory / "status.json").relative_to(scanner_directory)
        ).replace("\\", "/"),
        "updated_at": _utc_now(),
    }
    if scheduling is not None:
        pointer["scheduling"] = scheduling
    _atomic_write_json(scanner_directory / "status.json", pointer)


def _write_attempt_status(
    scanner_directory: Path,
    attempt_directory: Path,
    status: dict[str, Any],
) -> None:
    _atomic_write_json(attempt_directory / "status.json", status)
    _write_scanner_pointer(scanner_directory, attempt_directory, status)


def _quarantine_scheduling(
    *, timeout_count: int, limit: int, policy_sha256: str
) -> dict[str, Any]:
    return {
        "state": "QUARANTINED",
        "reason": "timeout_budget_exhausted",
        "matching_timeout_attempts": timeout_count,
        "limit": limit,
        "policy_sha256": policy_sha256,
        "decided_at": _utc_now(),
    }


def _write_quarantine_pointer(
    scanner_directory: Path,
    attempt_directory: Path,
    status: dict[str, Any],
    *,
    timeout_count: int,
    limit: int,
    policy_sha256: str,
) -> dict[str, Any]:
    scheduling = _quarantine_scheduling(
        timeout_count=timeout_count,
        limit=limit,
        policy_sha256=policy_sha256,
    )
    _write_scanner_pointer(
        scanner_directory,
        attempt_directory,
        status,
        scheduling=scheduling,
    )
    return scheduling


def _reconcile_orphaned_running_attempt(
    scanner_directory: Path,
    attempt_directory: Path,
    status: dict[str, Any],
    *,
    update_pointer: bool = True,
) -> dict[str, Any]:
    """Finalize a lock-free RUNNING attempt as interrupted, never as a timeout."""

    if status.get("status") != "RUNNING":
        return status
    message = (
        "attempt was left RUNNING after its job lock was released; "
        "the owning scanner process was interrupted"
    )
    stdout_path = attempt_directory / "stdout.log"
    stderr_path = attempt_directory / "stderr.log"
    if not stdout_path.exists():
        _atomic_write_text(stdout_path, "")
    if not stderr_path.exists():
        _atomic_write_text(stderr_path, message + "\n")
    interrupted = dict(status)
    interrupted.update(
        {
            "status": "INTERRUPTED",
            "ended_at": _utc_now(),
            "duration_seconds": None,
            "exit_code": None,
            "error": {"type": "OrphanedAttempt", "message": message},
            "checksums": _file_checksums(attempt_directory),
        }
    )
    _atomic_write_json(attempt_directory / "status.json", interrupted)
    if update_pointer:
        _write_scanner_pointer(scanner_directory, attempt_directory, interrupted)
    return interrupted


def _successful_resume_conflicts(
    latest_status: dict[str, Any],
    attempt_directory: Path,
    input_provenance: dict[str, dict[str, str]],
    ruleset_commit: str,
    observed_version: str,
    executable_sha256: str,
    override_configs: Sequence[Path],
) -> list[str]:
    conflicts: list[str] = []
    latest_inputs = latest_status.get("inputs")
    if not isinstance(latest_inputs, dict):
        conflicts.append("missing prior input provenance")
    else:
        for input_name, current in input_provenance.items():
            previous = latest_inputs.get(input_name)
            if not isinstance(previous, dict) or previous.get("sha256") != current["sha256"]:
                conflicts.append(f"{input_name} checksum changed")
    if latest_status.get("ruleset_commit") != ruleset_commit:
        conflicts.append("ruleset commit changed")
    latest_scanner = latest_status.get("scanner")
    if not isinstance(latest_scanner, dict):
        conflicts.append("missing prior scanner provenance")
    else:
        if latest_scanner.get("observed_version") != observed_version:
            conflicts.append("scanner version changed")
        if latest_scanner.get("executable_sha256") != executable_sha256:
            conflicts.append("scanner executable checksum changed")
    selection = latest_status.get("rule_selection")
    if not isinstance(selection, dict):
        conflicts.append("missing prior rule selection")
    elif override_configs:
        expected_configs = [str(path) for path in override_configs]
        if selection.get("source") != "cli" or selection.get("configs") != expected_configs:
            conflicts.append("CLI rule config selection changed")
    elif selection.get("source") == "cli":
        conflicts.append("CLI rule config selection changed")
    checksums = latest_status.get("checksums")
    if not isinstance(checksums, dict):
        conflicts.append("missing prior artifact checksums")
    else:
        required = {"stdout.log", "stderr.log"}
        if latest_status.get("status") == "SUCCESS":
            required.update({"raw.json", "raw.sarif"})
        missing = required - set(checksums)
        if missing:
            conflicts.append("missing prior artifact checksums: " + ", ".join(sorted(missing)))
        for name, expected in checksums.items():
            if not isinstance(name, str) or Path(name).name != name:
                conflicts.append(f"invalid prior artifact checksum path: {name!r}")
                continue
            path = attempt_directory / name
            if (
                not isinstance(expected, str)
                or not path.is_file()
                or _sha256_file(path) != expected
            ):
                conflicts.append(f"prior artifact checksum mismatch: {name}")
    return conflicts


def _ensure_scan_run_metadata(scan_root: Path, metadata: dict[str, Any]) -> None:
    run_path = scan_root / "run.json"
    with interprocess_lock(scan_root / ".run.lock", timeout_seconds=300):
        if run_path.exists():
            existing = _read_json_object(run_path, "scan run metadata")
            if existing != metadata:
                raise RuntimeError(
                    f"scan-id {scan_root.name} is already bound to different frozen inputs "
                    "or execution settings"
                )
            return
        _atomic_write_json(run_path, metadata)


def _runner_provenance(project_root: Path) -> dict[str, Any]:
    """Identify the code and Git state that controls scan execution."""

    controller_paths = [
        Path(__file__).resolve(),
        Path(__file__).with_name("checkout.py").resolve(),
    ]
    wrapper = (project_root / "scripts" / "opengrep_scan_wsl.sh").resolve()
    if wrapper.is_file():
        controller_paths.append(wrapper)
    files: dict[str, str] = {}
    for path in controller_paths:
        try:
            label = path.relative_to(project_root).as_posix()
        except ValueError:
            label = str(path)
        files[label] = _sha256_file(path)

    commit_result = _run_process(
        ["git", "-C", str(project_root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    status_result = _run_process(
        ["git", "-C", str(project_root), "status", "--porcelain=v1", "--untracked-files=all"],
        check=False,
        capture_output=True,
        text=True,
    )
    git_available = commit_result.returncode == 0 and status_result.returncode == 0
    status_lines = status_result.stdout.splitlines() if git_available else []
    return {
        "git_commit": commit_result.stdout.strip() if git_available else None,
        "worktree_clean": not status_lines if git_available else None,
        "worktree_status_sha256": (
            hashlib.sha256(("\n".join(status_lines) + "\n").encode("utf-8")).hexdigest()
            if status_lines
            else None
        ),
        "files": dict(sorted(files.items())),
    }


def _retry_policy(scan_id: str) -> dict[str, Any]:
    return {
        "schema_version": _RETRY_POLICY_SCHEMA_VERSION,
        "scan_id": scan_id,
        "policy": "bounded-timeout-retry",
        "max_completed_timeout_attempts": _MAX_COMPLETED_TIMEOUT_ATTEMPTS,
        "job_lock_timeout_seconds": _JOB_LOCK_TIMEOUT_SECONDS,
        "manual_override_requires_exact_job": True,
    }


def _ensure_retry_policy(scan_root: Path, scan_id: str) -> tuple[dict[str, Any], str]:
    """Create or validate the scan-local immutable retry scheduling policy."""

    policy_path = scan_root / "retry-policy.json"
    expected = _retry_policy(scan_id)
    expected_text = _canonical_json_text(expected)
    expected_bytes = expected_text.encode("utf-8")
    with interprocess_lock(scan_root / ".retry-policy.lock", timeout_seconds=300):
        if policy_path.exists():
            try:
                observed_bytes = policy_path.read_bytes()
            except OSError as exc:
                raise RuntimeError(f"could not read retry policy: {policy_path}: {exc}") from exc
            if observed_bytes != expected_bytes:
                raise RuntimeError(
                    f"retry policy changed for scan-id {scan_id}; use a new scan-id "
                    "instead of modifying retry-policy.json"
                )
            observed = _read_json_object(policy_path, "retry policy")
            if observed != expected:
                raise RuntimeError(f"retry policy is invalid for scan-id {scan_id}")
        else:
            _atomic_write_bytes(policy_path, expected_bytes)
    return expected, hashlib.sha256(expected_bytes).hexdigest()


def _file_checksums(attempt_directory: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for name in (
        "raw.json",
        "raw.sarif",
        "stdout.log",
        "stderr.log",
        "initial-git-ignore-stdout.log",
        "initial-git-ignore-stderr.log",
        "initial-git-ignore-raw.json",
        "initial-git-ignore-raw.sarif",
    ):
        path = attempt_directory / name
        if path.is_file():
            checksums[name] = _sha256_file(path)
    return checksums


def _rule_config_sha256(path: Path) -> str:
    """Hash a rule file or a deterministic set of YAML files in a rule directory."""

    if path.is_file():
        return _sha256_file(path)
    digest = hashlib.sha256()
    files = sorted(
        candidate
        for candidate in path.rglob("*")
        if candidate.is_file() and candidate.suffix.lower() in {".yml", ".yaml"}
    )
    if not files:
        raise RuntimeError(f"rule config directory contains no YAML rules: {path}")
    for candidate in files:
        relative = candidate.relative_to(path).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(_sha256_file(candidate)))
    return digest.hexdigest()


def _freeze_inputs(
    input_provenance: dict[str, dict[str, str]], attempt_directory: Path
) -> dict[str, dict[str, str]]:
    """Copy each configuration input into the immutable attempt directory.

    The original path remains useful diagnostic provenance, while
    ``frozen_path`` keeps the exact bytes available after the working copy is
    edited. The checksum is verified both before and after the copy so a file
    changing during attempt creation cannot be silently accepted.
    """

    if set(input_provenance) != set(_FROZEN_INPUT_FILENAMES):
        raise ValueError("input provenance must contain manifest, scanner_lock, and scan_profile")
    frozen: dict[str, dict[str, str]] = {}
    inputs_directory = attempt_directory / "inputs"
    inputs_directory.mkdir(parents=True, exist_ok=False)
    for name in sorted(input_provenance):
        provenance = input_provenance[name]
        source = Path(provenance["path"])
        expected = provenance["sha256"]
        if not source.is_file() or _sha256_file(source) != expected:
            raise RuntimeError(f"frozen input changed before attempt creation: {name}")
        destination = inputs_directory / _FROZEN_INPUT_FILENAMES[name]
        temporary = destination.with_name(
            f".{destination.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        )
        try:
            shutil.copyfile(source, temporary)
            if _sha256_file(temporary) != expected:
                raise RuntimeError(f"frozen input changed while copying: {name}")
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
        frozen[name] = {
            **provenance,
            "frozen_path": str(destination.relative_to(attempt_directory)).replace("\\", "/"),
        }
    return frozen


def _finish_status(
    status: dict[str, Any],
    scanner_directory: Path,
    attempt_directory: Path,
    started_monotonic: float,
    final_status: str,
    exit_code: int | None,
    error: dict[str, str] | None,
) -> dict[str, Any]:
    finished = dict(status)
    finished.update(
        {
            "status": final_status,
            "ended_at": _utc_now(),
            "duration_seconds": round(max(0.0, time.monotonic() - started_monotonic), 6),
            "exit_code": exit_code,
            "error": error,
            "checksums": _file_checksums(attempt_directory),
        }
    )
    _write_attempt_status(scanner_directory, attempt_directory, finished)
    return finished


def _run_job(
    *,
    snapshot: dict[str, Any],
    scanner_name: str,
    executable: str,
    observed_version: str,
    executable_sha256: str,
    ruleset_commit: str,
    scan_profile: dict[str, Any],
    routed_configs: dict[str, tuple[Path, ...]],
    override_configs: tuple[Path, ...],
    language_extensions: dict[str, frozenset[str]],
    scan_id: str,
    cache_root: Path,
    work_root: Path,
    output_root: Path,
    input_provenance: dict[str, dict[str, str]],
    runner_provenance: dict[str, Any],
    force: bool,
    refresh: bool,
    job_timeout_seconds: int | float | None,
    retry_override_reason: str | None = None,
    retry_policy_sha256: str | None = None,
) -> dict[str, Any]:
    scanner_directory = (
        output_root
        / scan_id
        / repo_slug(snapshot["repo_url"])
        / snapshot["commit"]
        / scanner_name
    )
    latest = _latest_attempt(scanner_directory)
    if latest is not None and latest[2] is not None:
        number, directory, latest_status = latest
        latest_error = latest_status.get("error") or {}
        reusable_no_config_skip = (
            latest_status.get("status") == "SKIPPED"
            and isinstance(latest_error, dict)
            and latest_error.get("type") == "NoApplicableRuleConfig"
        )
        if (
            latest_status.get("status") == "SUCCESS" or reusable_no_config_skip
        ) and not force:
            conflicts = _successful_resume_conflicts(
                latest_status,
                directory,
                input_provenance,
                ruleset_commit,
                observed_version,
                executable_sha256,
                override_configs,
            )
            if conflicts:
                raise RuntimeError(
                    "refusing to reuse successful attempt with changed frozen inputs: "
                    + "; ".join(conflicts)
                    + "; use a new scan-id or --force"
                )
            _write_scanner_pointer(scanner_directory, directory, latest_status)
            return {
                "repo_url": snapshot["repo_url"],
                "commit": snapshot["commit"],
                "scanner": scanner_name,
                "status": "SKIPPED",
                "reason": (
                    "existing_no_applicable_rule_config"
                    if reusable_no_config_skip
                    else "existing_success"
                ),
                "attempt": number,
                "status_path": str(directory / "status.json"),
            }

    next_attempt = (latest[0] + 1) if latest is not None else 1
    attempt_directory = scanner_directory / "attempts" / f"{next_attempt:04d}"
    attempt_directory.mkdir(parents=True, exist_ok=False)
    started_monotonic = time.monotonic()
    status: dict[str, Any] = {
        "schema_version": 1,
        "scan_id": scan_id,
        "status": "RUNNING",
        "attempt": next_attempt,
        "forced": force,
        "repo_url": snapshot["repo_url"],
        "commit": snapshot["commit"],
        "scanner": {
            "name": scanner_name,
            "expected_version": observed_version,
            "observed_version": observed_version,
            "executable_sha256": executable_sha256,
        },
        "ruleset_commit": ruleset_commit,
        "rule_selection": {"source": None, "languages": [], "configs": []},
        "argv": [],
        "argv_attempts": [],
        "targeting": {
            "respect_git_ignore_requested": scan_profile["scan"]["respect_git_ignore"],
            "respect_git_ignore_effective": scan_profile["scan"]["respect_git_ignore"],
            "git_ignore_fallback_used": False,
            "git_ignore_fallback_reason": None,
        },
        "cwd": None,
        "started_at": _utc_now(),
        "ended_at": None,
        "duration_seconds": None,
        "exit_code": None,
        "outputs": {"json": "raw.json", "sarif": "raw.sarif"},
        "logs": {"stdout": "stdout.log", "stderr": "stderr.log"},
        "checksums": {},
        "inputs": input_provenance,
        "runner": runner_provenance,
        "diagnostics": None,
        "error": None,
        "retry_override": (
            {
                "reason": retry_override_reason,
                "policy_sha256": retry_policy_sha256,
            }
            if retry_override_reason is not None
            else None
        ),
    }
    _write_attempt_status(scanner_directory, attempt_directory, status)

    try:
        status["inputs"] = _freeze_inputs(input_provenance, attempt_directory)
        _write_attempt_status(scanner_directory, attempt_directory, status)
        snapshot_path = checkout_snapshot(
            snapshot["repo_url"],
            snapshot["commit"],
            cache_root,
            work_root,
            refresh=refresh,
        ).resolve()
        languages, configs, selection_source = _rule_configs_for_snapshot(
            snapshot,
            snapshot_path,
            routed_configs,
            override_configs,
            language_extensions,
        )
        status["cwd"] = str(snapshot_path)
        status["rule_selection"] = {
            "source": selection_source,
            "languages": languages,
            "configs": [str(config) for config in configs],
            "config_sha256": {
                str(config): _rule_config_sha256(config) for config in configs
            },
        }
        if not configs:
            reason = "no applicable language-specific rule config"
            _atomic_write_text(attempt_directory / "stdout.log", "")
            _atomic_write_text(attempt_directory / "stderr.log", reason + "\n")
            finished = _finish_status(
                status,
                scanner_directory,
                attempt_directory,
                started_monotonic,
                "SKIPPED",
                None,
                {"type": "NoApplicableRuleConfig", "message": reason},
            )
            return {
                "repo_url": snapshot["repo_url"],
                "commit": snapshot["commit"],
                "scanner": scanner_name,
                "status": finished["status"],
                "reason": "no_applicable_rule_config",
                "attempt": next_attempt,
                "status_path": str(attempt_directory / "status.json"),
            }

        argv = build_scan_argv(
            scanner_name, executable, configs, scan_profile, attempt_directory
        )
        status["argv"] = argv
        status["argv_attempts"] = [{"mode": "configured", "argv": argv}]
        _write_attempt_status(scanner_directory, attempt_directory, status)

        configured_scanner_timeout = (
            None if job_timeout_seconds is None else float(job_timeout_seconds)
        )
        scanner_deadline = (
            None
            if configured_scanner_timeout is None
            else time.monotonic() + configured_scanner_timeout
        )

        def remaining_scanner_timeout() -> float | None:
            if scanner_deadline is None:
                return None
            return max(0.001, scanner_deadline - time.monotonic())

        try:
            result = _run_scanner_process(
                argv,
                cwd=snapshot_path,
                timeout=configured_scanner_timeout,
            )
            stdout = result.stdout
            stderr = result.stderr
            exit_code: int | None = result.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            stdout = _as_text(exc.stdout or exc.output)
            stderr = _as_text(exc.stderr)
            exit_code = None
            timed_out = True

        fallback_mode = scan_profile["scan"].get(
            "git_ignore_parse_failure_fallback", "disabled"
        )
        if (
            not timed_out
            and exit_code != 0
            and scan_profile["scan"]["respect_git_ignore"]
            and fallback_mode == "no_git_ignore_on_clean_snapshot"
            and _is_git_ignore_parser_failure(_as_text(stderr))
        ):
            _atomic_write_text(
                attempt_directory / "initial-git-ignore-stdout.log", _as_text(stdout)
            )
            _atomic_write_text(
                attempt_directory / "initial-git-ignore-stderr.log", _as_text(stderr)
            )
            initial_outputs: dict[str, str] = {}
            for output_name in ("raw.json", "raw.sarif"):
                output_path = attempt_directory / output_name
                if output_path.exists():
                    preserved_name = f"initial-git-ignore-{output_name}"
                    os.replace(output_path, attempt_directory / preserved_name)
                    initial_outputs[output_name] = preserved_name
            fallback_argv = build_scan_argv(
                scanner_name,
                executable,
                configs,
                scan_profile,
                attempt_directory,
                respect_git_ignore=False,
                exclude_patterns=(
                    _semgrep_compatible_exclude_patterns(
                        scan_profile["scan"]["exclude"]
                    )
                    if scanner_name == "semgrep"
                    else None
                ),
            )
            status["argv"] = fallback_argv
            status["argv_attempts"].append(
                {"mode": "fallback_no_git_ignore", "argv": fallback_argv}
            )
            status["targeting"] = {
                "respect_git_ignore_requested": True,
                "respect_git_ignore_effective": False,
                "git_ignore_fallback_used": True,
                "git_ignore_fallback_reason": "scanner_git_ignore_parser_failure",
                "exclude_glob_fallback_used": scanner_name == "semgrep",
                "effective_excludes": (
                    _semgrep_compatible_exclude_patterns(
                        scan_profile["scan"]["exclude"]
                    )
                    if scanner_name == "semgrep"
                    else list(scan_profile["scan"]["exclude"])
                ),
            }
            status["logs"].update(
                {
                    "initial_git_ignore_stdout": "initial-git-ignore-stdout.log",
                    "initial_git_ignore_stderr": "initial-git-ignore-stderr.log",
                }
            )
            status["initial_git_ignore_outputs"] = initial_outputs
            _write_attempt_status(scanner_directory, attempt_directory, status)
            try:
                result = _run_scanner_process(
                    fallback_argv,
                    cwd=snapshot_path,
                    timeout=remaining_scanner_timeout(),
                )
                stdout = result.stdout
                stderr = result.stderr
                exit_code = result.returncode
                timed_out = False
            except subprocess.TimeoutExpired as exc:
                stdout = _as_text(exc.stdout or exc.output)
                stderr = _as_text(exc.stderr)
                exit_code = None
                timed_out = True

        _atomic_write_text(attempt_directory / "stdout.log", _as_text(stdout))
        _atomic_write_text(attempt_directory / "stderr.log", _as_text(stderr))

        if timed_out:
            final_status = "TIMEOUT"
            error = {
                "type": "TimeoutExpired",
                "message": f"scanner exceeded job timeout of {job_timeout_seconds} seconds",
            }
        elif exit_code != 0:
            final_status = "FAILED"
            error = {"type": "ScannerExitError", "message": f"scanner exited with code {exit_code}"}
        else:
            output_errors = _validate_raw_outputs(attempt_directory)
            if output_errors:
                final_status = "FAILED"
                error = {"type": "OutputValidationError", "message": "; ".join(output_errors)}
            else:
                status["diagnostics"] = _raw_json_diagnostics(attempt_directory)
                final_status = "SUCCESS"
                error = None

        finished = _finish_status(
            status,
            scanner_directory,
            attempt_directory,
            started_monotonic,
            final_status,
            exit_code,
            error,
        )
    except Exception as exc:
        _atomic_write_text(attempt_directory / "stdout.log", "")
        _atomic_write_text(attempt_directory / "stderr.log", f"{type(exc).__name__}: {exc}\n")
        finished = _finish_status(
            status,
            scanner_directory,
            attempt_directory,
            started_monotonic,
            "FAILED",
            None,
            {"type": type(exc).__name__, "message": str(exc)},
        )

    return {
        "repo_url": snapshot["repo_url"],
        "commit": snapshot["commit"],
        "scanner": scanner_name,
        "status": finished["status"],
        "diagnostics": finished.get("diagnostics"),
        "attempt": next_attempt,
        "status_path": str(attempt_directory / "status.json"),
    }


def _job_priority(
    scanner_directory: Path,
    *,
    force: bool,
    retry_quarantined: bool,
    timeout_limit: int,
) -> int:
    """Return an advisory priority; state is re-evaluated after locking."""

    try:
        statuses = _attempt_statuses(scanner_directory)
    except (OSError, ValueError):
        # Planning is advisory and may race with the short interval between an
        # owner creating an attempt directory and atomically writing status.json.
        # The strict read is repeated after acquiring the job lock.
        return 3
    if not statuses:
        return 0
    latest_status = statuses[-1][2]
    if _is_reusable_terminal_status(latest_status):
        return 1 if force else 4
    timeout_count = _completed_timeout_count(statuses)
    if timeout_count >= timeout_limit:
        return 2 if retry_quarantined else 3
    latest_value = latest_status.get("status")
    if latest_value in {"FAILED", "INTERRUPTED"}:
        return 1
    if latest_value == "TIMEOUT":
        return 2
    if latest_value == "RUNNING":
        return 3
    return 1


def _run_job_with_retry_policy(
    *,
    snapshot: dict[str, Any],
    scanner_name: str,
    retry_policy: dict[str, Any],
    retry_policy_sha256: str,
    retry_quarantined: bool,
    retry_reason: str | None,
    run_job_arguments: dict[str, Any],
) -> dict[str, Any]:
    """Re-evaluate one job under its lock and enforce its timeout budget."""

    scanner_directory = (
        run_job_arguments["output_root"]
        / run_job_arguments["scan_id"]
        / repo_slug(snapshot["repo_url"])
        / snapshot["commit"]
        / scanner_name
    )
    statuses = _attempt_statuses(scanner_directory)
    last_index = len(statuses) - 1
    for index, (number, directory, attempt_status) in enumerate(statuses):
        if attempt_status.get("status") != "RUNNING":
            continue
        reconciled = _reconcile_orphaned_running_attempt(
            scanner_directory,
            directory,
            attempt_status,
            update_pointer=index == last_index,
        )
        statuses[index] = (number, directory, reconciled)

    timeout_limit = int(retry_policy["max_completed_timeout_attempts"])
    timeout_count = _completed_timeout_count(statuses)
    latest = statuses[-1] if statuses else None
    latest_is_complete = latest is not None and _is_reusable_terminal_status(latest[2])

    if retry_quarantined:
        if latest_is_complete or timeout_count < timeout_limit:
            raise RuntimeError(
                "--retry-quarantined selected a job that is not currently quarantined"
            )
    elif latest is not None and not latest_is_complete and timeout_count >= timeout_limit:
        scheduling = _write_quarantine_pointer(
            scanner_directory,
            latest[1],
            latest[2],
            timeout_count=timeout_count,
            limit=timeout_limit,
            policy_sha256=retry_policy_sha256,
        )
        return {
            "repo_url": snapshot["repo_url"],
            "commit": snapshot["commit"],
            "scanner": scanner_name,
            "status": "QUARANTINED",
            "attempt_status": latest[2].get("status"),
            "reason": scheduling["reason"],
            "attempt": latest[0],
            "status_path": str(latest[1] / "status.json"),
            "scheduling_state": scheduling["state"],
        }

    result = _run_job(
        snapshot=snapshot,
        scanner_name=scanner_name,
        retry_override_reason=retry_reason if retry_quarantined else None,
        retry_policy_sha256=retry_policy_sha256 if retry_quarantined else None,
        **run_job_arguments,
    )
    statuses = _attempt_statuses(scanner_directory)
    latest = statuses[-1]
    timeout_count = _completed_timeout_count(statuses)
    if not _is_reusable_terminal_status(latest[2]) and timeout_count >= timeout_limit:
        scheduling = _write_quarantine_pointer(
            scanner_directory,
            latest[1],
            latest[2],
            timeout_count=timeout_count,
            limit=timeout_limit,
            policy_sha256=retry_policy_sha256,
        )
        quarantined = dict(result)
        quarantined.update(
            {
                "status": "QUARANTINED",
                "attempt_status": latest[2].get("status"),
                "reason": scheduling["reason"],
                "scheduling_state": scheduling["state"],
            }
        )
        return quarantined

    completed = result.get("status") == "SUCCESS" or (
        result.get("status") == "SKIPPED"
        and result.get("reason")
        in {"existing_success", "existing_no_applicable_rule_config", "no_applicable_rule_config"}
    )
    result["scheduling_state"] = "COMPLETE" if completed else "RETRYABLE"
    return result


def run_batch(
    *,
    manifest_path: Path,
    scanner_lock_path: Path,
    scan_profile_path: Path,
    scan_id: str,
    cache_root: Path = Path("cache"),
    work_root: Path = Path("worktrees"),
    output_root: Path = Path("artifacts/scans"),
    repo_urls: Sequence[str] | None = None,
    commits: Sequence[str] | None = None,
    scanners: Sequence[str] | None = None,
    limit: int | None = None,
    rule_configs: Sequence[Path] | None = None,
    force: bool = False,
    refresh: bool = False,
    prefetch: bool = False,
    prefetch_workers: int = 1,
    batch_workers: int = 1,
    job_timeout_seconds: int | float | None = None,
    project_root: Path | None = None,
    retry_quarantined: bool = False,
    retry_reason: str | None = None,
    require_clean_runner: bool = False,
) -> dict[str, Any]:
    if not _SCAN_ID.fullmatch(scan_id):
        raise ValueError(
            "scan_id must start with an alphanumeric character and contain only letters, "
            "digits, dot, underscore, or hyphen"
        )
    if job_timeout_seconds is not None:
        _positive_number(job_timeout_seconds, "job_timeout_seconds")
    _positive_int(prefetch_workers, "prefetch_workers")
    _positive_int(batch_workers, "batch_workers")
    if retry_quarantined:
        if force:
            raise ValueError("--retry-quarantined cannot be combined with --force")
        if not isinstance(retry_reason, str) or not retry_reason.strip():
            raise ValueError("--retry-reason is required with --retry-quarantined")
        if (
            repo_urls is None
            or len(repo_urls) != 1
            or commits is None
            or len(commits) != 1
            or scanners is None
            or len(scanners) != 1
        ):
            raise ValueError(
                "--retry-quarantined requires exactly one --repo-url, --commit, and --scanner"
            )
        retry_reason = retry_reason.strip()
    elif retry_reason is not None:
        raise ValueError("--retry-reason requires --retry-quarantined")

    root = (project_root or Path.cwd()).resolve()
    manifest_path = _resolve_path(Path(manifest_path), root)
    scanner_lock_path = _resolve_path(Path(scanner_lock_path), root)
    scan_profile_path = _resolve_path(Path(scan_profile_path), root)
    cache_root = _resolve_path(Path(cache_root), root)
    work_root = _resolve_path(Path(work_root), root)
    output_root = _resolve_path(Path(output_root), root)

    manifest, scanner_lock, scan_profile = load_configuration(
        manifest_path, scanner_lock_path, scan_profile_path
    )
    selected_snapshots = select_snapshots(manifest, repo_urls, commits, limit)

    if scanners is None:
        selected_scanners = [
            scanner_name
            for scanner_name in SUPPORTED_SCANNERS
            if scanner_name in scanner_lock["scanners"]
            and scanner_lock["scanners"][scanner_name].get("enabled", True)
        ]
    else:
        selected_scanners = list(scanners)
    if not selected_scanners:
        raise ValueError("at least one scanner must be selected")
    if len(set(selected_scanners)) != len(selected_scanners):
        raise ValueError("scanner selection contains duplicates")
    unsupported = sorted(set(selected_scanners) - set(SUPPORTED_SCANNERS))
    if unsupported:
        raise ValueError(f"unsupported scanners: {unsupported}")
    missing = sorted(set(selected_scanners) - set(scanner_lock["scanners"]))
    if missing:
        raise ValueError(f"selected scanners are missing from scanner lock: {missing}")
    disabled = sorted(
        scanner_name
        for scanner_name in selected_scanners
        if not scanner_lock["scanners"][scanner_name].get("enabled", True)
    )
    if disabled:
        raise ValueError(f"disabled scanners cannot be selected: {disabled}")

    rules_root, routed_configs, override_configs, language_extensions = (
        resolve_rule_configs(scan_profile, root, rule_configs)
    )
    ruleset_commit = scanner_lock["ruleset"]["commit"]
    observed_ruleset_commit = verify_ruleset_pin(rules_root, ruleset_commit)

    executables: dict[str, str] = {}
    observed_versions: dict[str, str] = {}
    executable_checksums: dict[str, str] = {}
    for scanner_name in selected_scanners:
        executable = scanner_executable(scanner_name, scanner_lock, root)
        scanner_config = scanner_lock["scanners"][scanner_name]
        expected_version = scanner_config["version"]
        executables[scanner_name] = executable
        executable_checksums[scanner_name] = verify_scanner_executable_checksum(
            executable, scanner_config
        )
        observed_versions[scanner_name] = verify_scanner_version(executable, expected_version)

    input_provenance = {
        "manifest": {"path": str(manifest_path), "sha256": _sha256_file(manifest_path)},
        "scanner_lock": {
            "path": str(scanner_lock_path),
            "sha256": _sha256_file(scanner_lock_path),
        },
        "scan_profile": {
            "path": str(scan_profile_path),
            "sha256": _sha256_file(scan_profile_path),
        },
    }
    effective_job_timeout = (
        job_timeout_seconds
        if job_timeout_seconds is not None
        else scan_profile["scan"].get("job_timeout_seconds")
    )
    runner_provenance = _runner_provenance(root)
    if require_clean_runner and (
        not runner_provenance["git_commit"] or runner_provenance["worktree_clean"] is not True
    ):
        raise RuntimeError(
            "official scan requires a committed, clean project worktree; "
            "commit the runner/configuration changes or omit --require-clean-runner for a pilot"
        )

    scanner_pins = {}
    for scanner_name in selected_scanners:
        scanner_config = scanner_lock["scanners"][scanner_name]
        scanner_pins[scanner_name] = {
            "version": scanner_config["version"],
            "executable_sha256": scanner_config.get("local_executable_sha256")
            or scanner_config.get("windows_asset_sha256"),
        }
    _ensure_scan_run_metadata(
        output_root / scan_id,
        {
            "schema_version": 2,
            "scan_id": scan_id,
            "inputs": input_provenance,
            "ruleset_commit": observed_ruleset_commit,
            "scanner_pins": scanner_pins,
            "runner": runner_provenance,
            "execution": {
                "job_timeout_seconds": effective_job_timeout,
                "max_memory_mb": scan_profile["scan"]["max_memory_mb"],
                "scanner_internal_jobs": scan_profile["scan"]["jobs"],
                "batch_workers": batch_workers,
                "prefetch_selected_snapshots": prefetch,
                "prefetch_workers": prefetch_workers if prefetch else 0,
                "rule_config_override": [str(path) for path in override_configs],
            },
        },
    )
    retry_policy, retry_policy_sha256 = _ensure_retry_policy(
        output_root / scan_id, scan_id
    )

    if prefetch:
        commits_by_repo: dict[str, list[str]] = {}
        for snapshot in selected_snapshots:
            commits_by_repo.setdefault(snapshot["repo_url"], []).append(snapshot["commit"])
        prefetch_items = sorted(commits_by_repo.items())

        def prefetch_repository(item: tuple[str, list[str]]) -> None:
            repo_url, required_commits = item
            ensure_mirror(
                repo_url,
                cache_root,
                refresh=refresh,
                required_commits=required_commits,
            )

        if prefetch_workers == 1:
            for item in prefetch_items:
                prefetch_repository(item)
        else:
            with ThreadPoolExecutor(
                max_workers=min(prefetch_workers, len(prefetch_items)),
                thread_name_prefix="vulngym-prefetch",
            ) as executor:
                list(executor.map(prefetch_repository, prefetch_items))

    job_specs: list[tuple[int, str, str, str, dict[str, Any]]] = []
    for snapshot in selected_snapshots:
        for scanner_name in selected_scanners:
            scanner_directory = (
                output_root
                / scan_id
                / repo_slug(snapshot["repo_url"])
                / snapshot["commit"]
                / scanner_name
            )
            priority = _job_priority(
                scanner_directory,
                force=force,
                retry_quarantined=retry_quarantined,
                timeout_limit=int(retry_policy["max_completed_timeout_attempts"]),
            )
            job_specs.append(
                (
                    priority,
                    snapshot["repo_url"],
                    snapshot["commit"],
                    scanner_name,
                    snapshot,
                )
            )

    ordered_job_specs = sorted(job_specs, key=lambda item: item[:4])

    def execute_job(
        job_spec: tuple[int, str, str, str, dict[str, Any]],
    ) -> dict[str, Any]:
        _, _, _, scanner_name, snapshot = job_spec
        scanner_directory = (
            output_root
            / scan_id
            / repo_slug(snapshot["repo_url"])
            / snapshot["commit"]
            / scanner_name
        )
        job_lock_path = scanner_directory / ".job.lock"
        try:
            with interprocess_lock(
                job_lock_path,
                timeout_seconds=int(retry_policy["job_lock_timeout_seconds"]),
            ):
                return _run_job_with_retry_policy(
                    snapshot=snapshot,
                    scanner_name=scanner_name,
                    retry_policy=retry_policy,
                    retry_policy_sha256=retry_policy_sha256,
                    retry_quarantined=retry_quarantined,
                    retry_reason=retry_reason,
                    run_job_arguments={
                        "executable": executables[scanner_name],
                        "observed_version": observed_versions[scanner_name],
                        "executable_sha256": executable_checksums[scanner_name],
                        "ruleset_commit": observed_ruleset_commit,
                        "scan_profile": scan_profile,
                        "routed_configs": routed_configs,
                        "override_configs": override_configs,
                        "language_extensions": language_extensions,
                        "scan_id": scan_id,
                        "cache_root": cache_root,
                        "work_root": work_root,
                        "output_root": output_root,
                        "input_provenance": input_provenance,
                        "runner_provenance": runner_provenance,
                        "force": force,
                        "refresh": refresh,
                        "job_timeout_seconds": effective_job_timeout,
                    },
                )
        except InterprocessLockTimeout as exc:
            if exc.path.resolve() != job_lock_path.resolve():
                raise
            latest = _latest_attempt(scanner_directory)
            return {
                "repo_url": snapshot["repo_url"],
                "commit": snapshot["commit"],
                "scanner": scanner_name,
                "status": "BUSY",
                "reason": "job_lock_held",
                "attempt": latest[0] if latest is not None else None,
                "status_path": str(latest[1] / "status.json") if latest is not None else None,
                "scheduling_state": "BUSY",
            }

    if batch_workers == 1:
        jobs = [execute_job(job_spec) for job_spec in ordered_job_specs]
    else:
        with ThreadPoolExecutor(
            max_workers=min(batch_workers, len(ordered_job_specs)),
            thread_name_prefix="vulngym-scan",
        ) as executor:
            # executor.map preserves the deterministic job ordering in the report.
            jobs = list(executor.map(execute_job, ordered_job_specs))

    counts = Counter(job["status"] for job in jobs)
    scheduling_counts = Counter(job.get("scheduling_state", "UNKNOWN") for job in jobs)
    return {
        "schema_version": 1,
        "scan_id": scan_id,
        "snapshots_selected": len(selected_snapshots),
        "batch_workers": batch_workers,
        "jobs_total": len(jobs),
        "status_counts": dict(sorted(counts.items())),
        "scheduling_counts": dict(sorted(scheduling_counts.items())),
        "retry_policy": {
            "path": str(output_root / scan_id / "retry-policy.json"),
            "sha256": retry_policy_sha256,
            "max_completed_timeout_attempts": retry_policy[
                "max_completed_timeout_attempts"
            ],
        },
        "jobs": jobs,
    }


def _argparse_positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run pinned Semgrep-compatible scanner jobs over exact VulnGym snapshots."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--scanner-lock",
        type=Path,
        default=Path("config/scanners.opengrep-security-wsl.lock.json"),
    )
    parser.add_argument(
        "--scan-profile",
        type=Path,
        default=Path("config/scan-profile.opengrep-security-wsl-fast.json"),
    )
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--cache-root", type=Path, default=Path("cache"))
    parser.add_argument("--work-root", type=Path, default=Path("worktrees"))
    parser.add_argument("--output-root", type=Path, default=Path("artifacts/scans"))
    parser.add_argument("--repo-url", action="append", dest="repo_urls")
    parser.add_argument("--commit", action="append", dest="commits")
    parser.add_argument("--scanner", action="append", choices=SUPPORTED_SCANNERS, dest="scanners")
    parser.add_argument(
        "--rule-config",
        action="append",
        type=Path,
        dest="rule_configs",
        help="repeatable path beneath the pinned ruleset; bypasses automatic language routing",
    )
    parser.add_argument("--limit", type=_argparse_positive_int)
    parser.add_argument("--job-timeout-seconds", type=_argparse_positive_int)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument(
        "--prefetch",
        action="store_true",
        help="fetch every selected commit per repository before creating scan attempts",
    )
    parser.add_argument(
        "--prefetch-workers",
        type=_argparse_positive_int,
        default=1,
        help="repository mirrors to prefetch concurrently (default: 1)",
    )
    parser.add_argument(
        "--batch-workers",
        type=_argparse_positive_int,
        default=1,
        help="snapshot/scanner jobs to execute concurrently (default: 1)",
    )
    parser.add_argument(
        "--require-clean-runner",
        action="store_true",
        help="refuse to scan unless the project runner is committed and the worktree is clean",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="create a new immutable attempt even when the latest attempt succeeded",
    )
    parser.add_argument(
        "--retry-quarantined",
        action="store_true",
        help="manually retry one explicitly selected quarantined job",
    )
    parser.add_argument(
        "--retry-reason",
        help="required audit reason for --retry-quarantined",
    )
    args = parser.parse_args(argv)

    try:
        report = run_batch(
            manifest_path=args.manifest,
            scanner_lock_path=args.scanner_lock,
            scan_profile_path=args.scan_profile,
            scan_id=args.scan_id,
            project_root=args.project_root,
            cache_root=args.cache_root,
            work_root=args.work_root,
            output_root=args.output_root,
            repo_urls=args.repo_urls,
            commits=args.commits,
            scanners=args.scanners,
            limit=args.limit,
            rule_configs=args.rule_configs,
            force=args.force,
            refresh=args.refresh,
            prefetch=args.prefetch,
            prefetch_workers=args.prefetch_workers,
            batch_workers=args.batch_workers,
            job_timeout_seconds=args.job_timeout_seconds,
            retry_quarantined=args.retry_quarantined,
            retry_reason=args.retry_reason,
            require_clean_runner=args.require_clean_runner,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report, ensure_ascii=False, indent=2))
    statuses = report["status_counts"]
    if any(status in statuses for status in ("FAILED", "TIMEOUT", "INTERRUPTED")):
        return 1
    if "BUSY" in statuses:
        return 4
    if "QUARANTINED" in statuses:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
