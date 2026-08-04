from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vulngym_enrich import checkout


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def test_run_git_keeps_stderr_in_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args, **kwargs):
        assert kwargs["encoding"] == "utf-8"
        assert kwargs["errors"] == "replace"
        return subprocess.CompletedProcess(args[0], 128, stdout="", stderr="network reset")

    monkeypatch.setattr(checkout.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="network reset"):
        checkout.run_git(["clone", "--mirror", "https://github.com/example/repo"])


def test_temporary_cleanup_is_scoped_to_expected_parent(tmp_path: Path) -> None:
    temporary = tmp_path / ".repo.clone-test"
    temporary.mkdir()
    (temporary / "partial").write_text("x", encoding="utf-8")

    checkout._remove_task_temporary_tree(temporary, tmp_path)

    assert not temporary.exists()
    outside = tmp_path / "ordinary-directory"
    outside.mkdir()
    with pytest.raises(RuntimeError, match="refusing to remove"):
        checkout._remove_task_temporary_tree(outside, tmp_path)
    assert outside.exists()


def test_temporary_cleanup_removes_readonly_git_pack(tmp_path: Path) -> None:
    temporary = tmp_path / ".repo.clone-readonly"
    pack = temporary / "objects" / "pack" / "tmp_pack_test"
    pack.parent.mkdir(parents=True)
    pack.write_bytes(b"partial")
    pack.chmod(0o444)

    checkout._remove_task_temporary_tree(temporary, tmp_path)

    assert not temporary.exists()


def test_targeted_mirror_and_alternate_checkout_materialize_exact_commits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init")
    _git(source, "config", "user.name", "Test")
    _git(source, "config", "user.email", "test@example.invalid")
    tracked = source / "value.txt"
    tracked.write_text("one\n", encoding="utf-8")
    _git(source, "add", "value.txt")
    _git(source, "commit", "-m", "one")
    first = _git(source, "rev-parse", "HEAD")
    tracked.write_text("two\n", encoding="utf-8")
    _git(source, "commit", "-am", "two")
    second = _git(source, "rev-parse", "HEAD")

    monkeypatch.setattr(checkout, "repo_slug", lambda _: "example__target")
    cache_root = tmp_path / "cache"
    mirror = checkout.ensure_mirror(
        str(source), cache_root, required_commits=[first, second]
    )

    assert _git(mirror, "rev-parse", "--is-bare-repository") == "true"
    assert _git(mirror, "rev-parse", f"refs/vulngym/{first}") == first
    assert _git(mirror, "rev-parse", f"refs/vulngym/{second}") == second

    snapshot = checkout.checkout_snapshot(
        str(source), first, cache_root, tmp_path / "worktrees"
    )
    assert (snapshot / "value.txt").read_text(encoding="utf-8") == "one\n"
    assert _git(snapshot, "rev-parse", "HEAD") == first
    alternates = snapshot / ".git" / "objects" / "info" / "alternates"
    assert alternates.read_text(encoding="utf-8").strip() == str(
        (mirror / "objects").resolve()
    ).replace("\\", "/")
