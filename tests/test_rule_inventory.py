from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vulngym_enrich.rule_inventory import (
    RuleInventoryError,
    build_rule_inventory,
    detect_languages,
    inventory_rule_configs,
    resolve_language_configs,
)


EXTENSIONS = {
    "python": [".py"],
    "javascript": [".js", ".jsx"],
    "typescript": [".ts", ".tsx"],
    "go": [".go"],
}
CONFIGS = {
    "python": ["python"],
    "javascript": ["javascript"],
    "typescript": ["javascript", "typescript"],
    "go": ["go"],
}


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, text=True, capture_output=True
    ).stdout.strip()


def _repository(root: Path, files: dict[str, str]) -> str:
    root.mkdir(parents=True)
    _git("init", "-q", cwd=root)
    _git("config", "user.name", "Rule Inventory Test", cwd=root)
    _git("config", "user.email", "rules@example.invalid", cwd=root)
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git("add", ".", cwd=root)
    _git("commit", "-q", "-m", "fixture", cwd=root)
    return _git("rev-parse", "HEAD", cwd=root)


def _rule_repositories(tmp_path: Path) -> tuple[Path, str, Path]:
    rules = tmp_path / "rules"
    commit = _repository(
        rules,
        {
            "javascript/js.yml": "rules:\n  - id: javascript.rule\n",
            "javascript/ignored.test.yaml": "rules:\n  - id: ignored.test\n",
            "typescript/ts.yaml": "rules:\n  - id: typescript.rule\n",
            ".github/workflows/ci.yml": "name: CI\n",
        },
    )
    snapshot = tmp_path / "snapshot"
    _repository(snapshot, {"src/app.ts": "const value: string = 'x';\n"})
    return rules, commit, snapshot


def test_typescript_routes_to_javascript_and_typescript_and_prunes_excludes(tmp_path: Path) -> None:
    rules, commit, snapshot = _rule_repositories(tmp_path)
    ignored = snapshot / "node_modules/dependency.py"
    ignored.parent.mkdir(parents=True)
    ignored.write_text("print('ignored')\n", encoding="utf-8")
    _git("add", ".", cwd=snapshot)
    _git("commit", "-q", "-m", "ignored source", cwd=snapshot)

    manifest = build_rule_inventory(
        snapshot,
        rules,
        commit,
        CONFIGS,
        EXTENSIONS,
        ["**/node_modules/**"],
    )

    assert manifest["languages"] == ["typescript"]
    assert manifest["config_paths"] == ["javascript", "typescript"]
    assert [item["path"] for item in manifest["files"]] == [
        "javascript/js.yml",
        "typescript/ts.yaml",
    ]
    assert manifest["rule_ids"] == ["javascript.rule", "typescript.rule"]


def test_resolve_language_configs_rejects_traversal_and_rules_root(tmp_path: Path) -> None:
    rules, _, snapshot = _rule_repositories(tmp_path)
    languages = list(detect_languages(snapshot, EXTENSIONS))
    with pytest.raises(RuleInventoryError, match="unsafe"):
        resolve_language_configs(rules, languages, {"typescript": ["../outside"]})
    with pytest.raises(RuleInventoryError, match="root itself"):
        resolve_language_configs(rules, languages, {"typescript": ["."]})


def test_manifest_is_deterministic(tmp_path: Path) -> None:
    rules, commit, snapshot = _rule_repositories(tmp_path)
    first = build_rule_inventory(snapshot, rules, commit, CONFIGS, EXTENSIONS)
    second = build_rule_inventory(snapshot, rules, commit, CONFIGS, EXTENSIONS)
    assert first == second


def test_duplicate_rule_ids_are_reported(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    _repository(
        rules,
        {
            "javascript/a.yml": "rules:\n  - id: shared.rule\n",
            "typescript/b.yaml": "rules:\n  - id: 'shared.rule' # duplicate\n",
        },
    )
    config_dirs = resolve_language_configs(rules, ["typescript"], CONFIGS)
    inventory = inventory_rule_configs(rules, config_dirs)

    assert inventory["counts"]["duplicate_rule_ids"] == 1
    assert inventory["duplicates"] == [
        {
            "id": "shared.rule",
            "occurrences": [
                {"path": "javascript/a.yml", "line": 2},
                {"path": "typescript/b.yaml", "line": 2},
            ],
        }
    ]


def test_no_tracked_source_means_no_applicable_configs(tmp_path: Path) -> None:
    rules, commit, _ = _rule_repositories(tmp_path)
    snapshot = tmp_path / "docs-only"
    _repository(snapshot, {"README.md": "documentation only\n"})
    manifest = build_rule_inventory(snapshot, rules, commit, CONFIGS, EXTENSIONS)
    assert manifest["languages"] == []
    assert manifest["config_paths"] == []
    assert manifest["counts"]["config_files"] == 0


def test_rules_head_must_match_pin(tmp_path: Path) -> None:
    rules, _, snapshot = _rule_repositories(tmp_path)
    with pytest.raises(RuleInventoryError, match="HEAD mismatch"):
        build_rule_inventory(snapshot, rules, "0" * 40, CONFIGS, EXTENSIONS)
