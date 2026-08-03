from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vulngym_enrich import checkout


def test_run_git_keeps_stderr_in_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args, **kwargs):
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
