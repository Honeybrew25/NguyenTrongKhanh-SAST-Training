from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_RULE_ID = re.compile(r"^\s*-\s+id\s*:\s*(?P<value>[^#]+?)\s*(?:#.*)?$")
_YAML_SUFFIXES = {".yaml", ".yml"}


class RuleInventoryError(RuntimeError):
    """Raised when rule provenance or path containment cannot be verified."""


def _git(root: Path, *args: str, binary: bool = False) -> str | bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=not binary,
    )
    if completed.returncode != 0:
        stderr = completed.stderr if isinstance(completed.stderr, str) else completed.stderr.decode("utf-8", "replace")
        raise RuleInventoryError(f"git {' '.join(args)} failed for {root}: {stderr.strip()}")
    return completed.stdout


def _git_root_and_head(root: Path) -> tuple[Path, str]:
    resolved = root.resolve(strict=True)
    top_level = Path(str(_git(resolved, "rev-parse", "--show-toplevel")).strip()).resolve(strict=True)
    if top_level != resolved:
        raise RuleInventoryError(f"expected a Git repository root, got {resolved} (root is {top_level})")
    head = str(_git(resolved, "rev-parse", "--verify", "HEAD")).strip().lower()
    if not _SHA40.fullmatch(head):
        raise RuleInventoryError(f"Git HEAD is not a full lowercase commit: {head}")
    return resolved, head


def verify_rules_head(rules_root: Path, expected_commit: str) -> str:
    """Verify that ``rules_root`` is exactly at the pinned Git commit."""
    if not _SHA40.fullmatch(expected_commit):
        raise RuleInventoryError(f"expected rules commit must be a full lowercase SHA-1: {expected_commit}")
    _, actual = _git_root_and_head(rules_root)
    if actual != expected_commit:
        raise RuleInventoryError(f"rules HEAD mismatch: expected {expected_commit}, got {actual}")
    return actual


def _tracked_paths(snapshot_root: Path) -> list[str]:
    root, _ = _git_root_and_head(snapshot_root)
    raw = bytes(_git(root, "ls-files", "-z", "--cached", binary=True))
    try:
        paths = [item.decode("utf-8") for item in raw.split(b"\0") if item]
    except UnicodeDecodeError as exc:
        raise RuleInventoryError("tracked Git paths must be UTF-8") from exc
    return sorted(path.replace("\\", "/") for path in paths)


def _matches_exclude(path: str, patterns: Sequence[str]) -> bool:
    for original in patterns:
        pattern = str(original).replace("\\", "/").removeprefix("./")
        candidates = [pattern]
        while candidates[-1].startswith("**/"):
            candidates.append(candidates[-1][3:])
        if any(fnmatch.fnmatchcase(path, candidate) for candidate in candidates):
            return True
    return False


def detect_languages(
    snapshot_root: Path,
    language_extensions: Mapping[str, Sequence[str]],
    exclude_globs: Sequence[str] = (),
) -> dict[str, list[str]]:
    """Return detected languages and their non-excluded, Git-tracked source paths."""
    extension_to_language: dict[str, str] = {}
    for language, extensions in language_extensions.items():
        for extension in extensions:
            normalized = str(extension).lower()
            if not normalized.startswith("."):
                raise RuleInventoryError(f"language extension must start with '.': {extension}")
            previous = extension_to_language.setdefault(normalized, language)
            if previous != language:
                raise RuleInventoryError(f"extension {normalized} is assigned to both {previous} and {language}")

    detected: dict[str, list[str]] = defaultdict(list)
    for path in _tracked_paths(snapshot_root):
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or any(part.lower() == ".git" for part in pure.parts):
            continue
        if _matches_exclude(path, exclude_globs):
            continue
        language = extension_to_language.get(pure.suffix.lower())
        if language is not None:
            detected[language].append(path)
    return {language: sorted(detected[language]) for language in sorted(detected)}


def _safe_config_directory(rules_root: Path, configured_path: str) -> Path:
    raw = str(configured_path).replace("\\", "/")
    relative = PurePosixPath(raw)
    if not raw or relative.is_absolute() or re.match(r"^[A-Za-z]:", raw) or ".." in relative.parts:
        raise RuleInventoryError(f"unsafe rule config directory: {configured_path}")
    candidate = rules_root.joinpath(*relative.parts).resolve(strict=True)
    try:
        candidate.relative_to(rules_root)
    except ValueError as exc:
        raise RuleInventoryError(f"rule config escapes rules root: {configured_path}") from exc
    if candidate == rules_root:
        raise RuleInventoryError("the rules root itself cannot be used as a language config directory")
    if not candidate.is_dir():
        raise RuleInventoryError(f"rule config is not a directory: {configured_path}")
    return candidate


def resolve_language_configs(
    rules_root: Path,
    languages: Sequence[str],
    language_configs: Mapping[str, Sequence[str]],
) -> list[Path]:
    """Resolve only configured language directories, rejecting traversal and root scans."""
    root = rules_root.resolve(strict=True)
    resolved: dict[str, Path] = {}
    for language in sorted(set(languages)):
        if language not in language_configs:
            raise RuleInventoryError(f"no rule config mapping for detected language: {language}")
        for configured_path in language_configs[language]:
            directory = _safe_config_directory(root, str(configured_path))
            resolved[directory.relative_to(root).as_posix()] = directory
    return [resolved[path] for path in sorted(resolved)]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_rule_ids(path: Path) -> list[tuple[str, int]]:
    occurrences: list[tuple[str, int]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = _RULE_ID.match(line)
        if not match:
            continue
        value = match.group("value").strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1].strip()
        if value:
            occurrences.append((value, line_number))
    return occurrences


def inventory_rule_configs(rules_root: Path, config_directories: Sequence[Path]) -> dict[str, object]:
    """Inventory YAML configs in safe language directories deterministically."""
    root = rules_root.resolve(strict=True)
    files_by_relative_path: dict[str, Path] = {}
    for directory in config_directories:
        resolved_directory = directory.resolve(strict=True)
        try:
            resolved_directory.relative_to(root)
        except ValueError as exc:
            raise RuleInventoryError(f"config directory escapes rules root: {directory}") from exc
        for candidate in resolved_directory.rglob("*"):
            if not candidate.is_file() or candidate.suffix.lower() not in _YAML_SUFFIXES:
                continue
            if candidate.name.lower().endswith((".test.yaml", ".test.yml")):
                continue
            resolved_candidate = candidate.resolve(strict=True)
            try:
                relative = resolved_candidate.relative_to(root).as_posix()
            except ValueError as exc:
                raise RuleInventoryError(f"rule file escapes rules root: {candidate}") from exc
            files_by_relative_path[relative] = resolved_candidate

    files: list[dict[str, object]] = []
    occurrences_by_id: dict[str, list[dict[str, object]]] = defaultdict(list)
    occurrence_count = 0
    for relative in sorted(files_by_relative_path):
        path = files_by_relative_path[relative]
        occurrences = _parse_rule_ids(path)
        rule_ids = [rule_id for rule_id, _ in occurrences]
        occurrence_count += len(rule_ids)
        for rule_id, line in occurrences:
            occurrences_by_id[rule_id].append({"path": relative, "line": line})
        files.append(
            {
                "path": relative,
                "sha256": _sha256(path),
                "rule_ids": rule_ids,
                "rule_count": len(rule_ids),
            }
        )

    duplicates = [
        {"id": rule_id, "occurrences": occurrences_by_id[rule_id]}
        for rule_id in sorted(occurrences_by_id)
        if len(occurrences_by_id[rule_id]) > 1
    ]
    unique_ids = sorted(occurrences_by_id)
    return {
        "files": files,
        "rule_ids": unique_ids,
        "duplicates": duplicates,
        "counts": {
            "config_files": len(files),
            "rule_id_occurrences": occurrence_count,
            "unique_rule_ids": len(unique_ids),
            "duplicate_rule_ids": len(duplicates),
        },
    }


def build_rule_inventory(
    snapshot_root: Path,
    rules_root: Path,
    expected_rules_commit: str,
    language_configs: Mapping[str, Sequence[str]],
    language_extensions: Mapping[str, Sequence[str]],
    exclude_globs: Sequence[str] = (),
) -> dict[str, object]:
    rules_root = rules_root.resolve(strict=True)
    actual_commit = verify_rules_head(rules_root, expected_rules_commit)
    sources = detect_languages(snapshot_root, language_extensions, exclude_globs)
    config_directories = resolve_language_configs(rules_root, list(sources), language_configs)
    inventory = inventory_rule_configs(rules_root, config_directories)
    return {
        "schema_version": 1,
        "snapshot_commit": _git_root_and_head(snapshot_root)[1],
        "ruleset_commit": actual_commit,
        "languages": list(sources),
        "source_files": sources,
        "config_paths": [path.relative_to(rules_root).as_posix() for path in config_directories],
        **inventory,
    }


def _rules_root_from_profile(profile_path: Path, configured_root: str) -> Path:
    project_root = profile_path.resolve(strict=True).parent.parent
    raw = str(configured_root).replace("\\", "/")
    relative = PurePosixPath(raw)
    if relative.is_absolute() or re.match(r"^[A-Za-z]:", raw) or ".." in relative.parts:
        raise RuleInventoryError(f"unsafe rules root in profile: {configured_root}")
    candidate = project_root.joinpath(*relative.parts).resolve(strict=True)
    try:
        candidate.relative_to(project_root)
    except ValueError as exc:
        raise RuleInventoryError(f"rules root escapes project root: {configured_root}") from exc
    return candidate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a deterministic inventory of applicable pinned rules.")
    parser.add_argument(
        "--profile",
        type=Path,
        default=Path("config/scan-profile.opengrep-security-wsl-fast.json"),
    )
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    rules = profile["rules"]
    rules_root = _rules_root_from_profile(args.profile, rules["root"])
    manifest = build_rule_inventory(
        snapshot_root=args.snapshot,
        rules_root=rules_root,
        expected_rules_commit=rules["commit"],
        language_configs=rules["language_configs"],
        language_extensions=rules["language_extensions"],
        exclude_globs=profile["scan"].get("exclude", []),
    )
    rendered = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(rendered, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
