from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


EXPECTED_PYYAML_VERSION = "6.0.2"
FIXED_GIT_DATE = "2000-01-01T00:00:00+00:00"
YAML_SUFFIXES = {".yaml", ".yml"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(root: Path, *args: str, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed for {root}: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def rule_categories(path: Path) -> list[str]:
    categories: list[str] = []
    for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
        if not isinstance(document, dict):
            continue
        for rule in document.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            rule_id = str(rule.get("id") or "").strip()
            if not rule_id:
                raise ValueError(f"rule without id: {path}")
            metadata = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
            categories.append(str(metadata.get("category") or "MISSING").strip().casefold())
    return categories


def build(source_root: Path, base_profile_path: Path, output_root: Path) -> dict[str, Any]:
    if yaml.__version__ != EXPECTED_PYYAML_VERSION:
        raise RuntimeError(
            f"PyYAML version mismatch: expected {EXPECTED_PYYAML_VERSION}, got {yaml.__version__}"
        )
    source_root = source_root.resolve(strict=True)
    base_profile_path = base_profile_path.resolve(strict=True)
    output_root = output_root.resolve(strict=False)
    source_commit = git(source_root, "rev-parse", "HEAD")
    if git(source_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError(f"source ruleset is dirty: {source_root}")

    profile = load_object(base_profile_path)
    expected_commit = str(profile["rules"]["commit"])
    if source_commit != expected_commit:
        raise RuntimeError(
            f"source ruleset commit mismatch: expected {expected_commit}, got {source_commit}"
        )

    if output_root.exists():
        manifest_path = output_root / "SOURCE.json"
        if manifest_path.is_file():
            existing = load_object(manifest_path)
            if (
                existing.get("source_ruleset_commit") == source_commit
                and existing.get("base_profile_sha256") == sha256(base_profile_path)
                and git(output_root, "status", "--porcelain=v1", "--untracked-files=all") == ""
            ):
                return {
                    "status": "REUSED",
                    "path": str(output_root),
                    "commit": git(output_root, "rev-parse", "HEAD"),
                    "manifest": existing,
                }
        raise RuntimeError(f"output ruleset already exists with different provenance: {output_root}")

    output_root.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=output_root.parent)
    )
    try:
        configured_directories = sorted(
            {
                str(directory)
                for values in profile["rules"]["language_configs"].values()
                for directory in values
            }
        )
        selected_files: list[dict[str, Any]] = []
        category_counts: Counter[str] = Counter()
        selected_rule_counts: Counter[str] = Counter()
        skipped_rule_counts: Counter[str] = Counter()

        for configured_directory in configured_directories:
            config_root = (source_root / configured_directory).resolve(strict=True)
            config_root.relative_to(source_root)
            for source in sorted(config_root.rglob("*")):
                if (
                    not source.is_file()
                    or source.suffix.lower() not in YAML_SUFFIXES
                    or source.name.lower().endswith((".test.yaml", ".test.yml"))
                ):
                    continue
                categories = rule_categories(source)
                if not categories:
                    continue
                category_counts.update(categories)
                unique_categories = set(categories)
                if "security" in unique_categories and unique_categories != {"security"}:
                    raise RuntimeError(f"mixed security/non-security rule file: {source}")
                if unique_categories != {"security"}:
                    skipped_rule_counts[configured_directory] += len(categories)
                    continue
                relative = source.relative_to(source_root)
                destination = temporary / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                os.chmod(destination, 0o644)
                selected_rule_counts[configured_directory] += len(categories)
                selected_files.append(
                    {
                        "path": relative.as_posix(),
                        "sha256": sha256(destination),
                        "rules": len(categories),
                    }
                )

        manifest = {
            "schema_version": 1,
            "selection": {"metadata.category": "security"},
            "source_ruleset": "semgrep/semgrep-rules",
            "source_ruleset_commit": source_commit,
            "base_profile_sha256": sha256(base_profile_path),
            "generator": "scripts/build_opengrep_security_ruleset.py",
            "pyyaml_version": yaml.__version__,
            "configured_directories": configured_directories,
            "selected_rule_counts": dict(sorted(selected_rule_counts.items())),
            "skipped_rule_counts": dict(sorted(skipped_rule_counts.items())),
            "category_counts": dict(sorted(category_counts.items())),
            "selected_files": selected_files,
        }
        (temporary / "SOURCE.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary / "SOURCE.json", 0o644)

        git(temporary, "init", "--initial-branch=main")
        git(temporary, "config", "user.name", "VulnGym Ruleset Builder")
        git(temporary, "config", "user.email", "vulngym-ruleset@example.invalid")
        git(temporary, "add", "--all")
        commit_environment = os.environ.copy()
        commit_environment.update(
            {
                "GIT_AUTHOR_DATE": FIXED_GIT_DATE,
                "GIT_COMMITTER_DATE": FIXED_GIT_DATE,
            }
        )
        git(
            temporary,
            "commit",
            "-m",
            f"Derive security-only rules from {source_commit}",
            env=commit_environment,
        )
        commit = git(temporary, "rev-parse", "HEAD")
        temporary.rename(output_root)
        return {
            "status": "BUILT",
            "path": str(output_root),
            "commit": commit,
            "manifest": manifest,
        }
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic byte-preserving security-only OpenGrep ruleset."
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--base-profile", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.source_root, args.base_profile, args.output_root)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
