from __future__ import annotations

import json
from argparse import Namespace

from vulngym_enrich.codeql_runner import (
    CodeQLJob,
    _apply_runtime_go_override,
    _apply_runtime_resource_overrides,
    _database_marker,
    _filter_jobs,
    _query_rerun_flag,
    _resolve_path,
    build_job_plan,
    language_for_file,
)


def test_runtime_resource_overrides_are_applied_separately_from_profile_file() -> None:
    profile = {
        "resources": {
            "analyze_threads": 2,
            "analyze_ram_mb": 20480,
        }
    }

    overrides = _apply_runtime_resource_overrides(
        profile,
        analyze_threads=1,
        analyze_ram_mb=12288,
    )

    assert overrides == {"analyze_threads": 1, "analyze_ram_mb": 12288}
    assert profile["resources"] == {
        "analyze_threads": 1,
        "analyze_ram_mb": 12288,
    }


def test_runtime_go_override_is_complete_and_changes_extraction_identity() -> None:
    profile = {
        "tool": {"version": "2.25.5", "executable_sha256": "tool-sha"},
        "go_runtime": {
            "version": "1.24.1",
            "executable": "/tools/go1/bin/go",
            "executable_sha256": "a" * 64,
        },
        "policy": {"build_modes": {"go": "autobuild"}},
    }
    job = CodeQLJob(
        repo_url="https://github.com/acme/project",
        commit="a" * 40,
        language="go",
        routing_reason="test",
        priority=1,
    )
    original_marker = _database_marker(job, json.loads(json.dumps(profile)))

    overrides = _apply_runtime_go_override(
        profile,
        version="1.24.11",
        executable="/tools/go11/bin/go",
        executable_sha256="b" * 64,
        godebug="http2client=0",
        goflags="-mod=mod",
    )

    assert overrides == {
        "version": "1.24.11",
        "executable": "/tools/go11/bin/go",
        "executable_sha256": "b" * 64,
        "godebug": "http2client=0",
        "goflags": "-mod=mod",
    }
    assert profile["go_runtime"]["version"] == "1.24.11"
    assert profile["go_runtime"]["godebug"] == "http2client=0"
    assert profile["go_runtime"]["goflags"] == "-mod=mod"
    assert _database_marker(job, profile) != original_marker


def test_runtime_go_override_requires_all_identity_fields() -> None:
    profile = {"go_runtime": {}}
    try:
        _apply_runtime_go_override(
            profile,
            version="1.24.11",
            executable=None,
            executable_sha256="b" * 64,
        )
    except ValueError as exc:
        assert "requires version, executable" in str(exc)
    else:
        raise AssertionError("partial Go runtime override was accepted")


def test_runtime_go_override_rejects_unrecorded_debug_modes() -> None:
    profile = {"go_runtime": {}}
    try:
        _apply_runtime_go_override(
            profile,
            version="1.24.11",
            executable="/tools/go11/bin/go",
            executable_sha256="b" * 64,
            godebug="gocacheverify=1",
        )
    except ValueError as exc:
        assert "supports only http2client=0" in str(exc)
    else:
        raise AssertionError("an unsupported Go debug mode was accepted")


def test_runtime_go_override_rejects_unrecorded_module_modes() -> None:
    profile = {"go_runtime": {}}
    try:
        _apply_runtime_go_override(
            profile,
            version="1.24.11",
            executable="/tools/go11/bin/go",
            executable_sha256="b" * 64,
            goflags="-mod=vendor",
        )
    except ValueError as exc:
        assert "supports only -mod=mod" in str(exc)
    else:
        raise AssertionError("an unsupported Go module mode was accepted")


def test_database_marker_tracks_go_module_mode() -> None:
    job = CodeQLJob(
        repo_url="https://github.com/acme/project",
        commit="a" * 40,
        language="go",
        routing_reason="test",
        priority=1,
    )
    profile = {
        "tool": {"version": "2.25.5", "executable_sha256": "tool-sha"},
        "go_runtime": {"version": "1.24.11", "executable_sha256": "go-sha"},
        "policy": {"build_modes": {"go": "autobuild"}},
    }
    changed = json.loads(json.dumps(profile))
    changed["go_runtime"]["goflags"] = "-mod=mod"

    assert _database_marker(job, changed) != _database_marker(job, profile)


def test_language_for_file_routes_supported_codeql_extractors() -> None:
    assert language_for_file("src/app.py") == "python"
    assert language_for_file("src/app.ts") == "javascript-typescript"
    assert language_for_file("src/view.vue") == "javascript-typescript"
    assert language_for_file("cmd/main.go") == "go"
    assert language_for_file(".github/workflows/scan.yml") == "actions"
    assert language_for_file("config/settings.yml") is None


def test_build_job_plan_routes_by_trace_and_falls_back_by_repository() -> None:
    manifest = {
        "snapshots": [
            {"repo_url": "https://github.com/acme/project", "commit": "a" * 40},
            {"repo_url": "https://github.com/acme/project", "commit": "b" * 40},
        ]
    }
    entries = [
        {
            "repo_url": "https://github.com/acme/project",
            "commit": "a" * 40,
            "entry_point": {"file": "src/app.py"},
            "critical_operation": {"file": "src/sink.py"},
            "trace": [],
        },
        {
            "repo_url": "https://github.com/acme/project",
            "commit": "b" * 40,
            "entry_point": {"file": "scripts/run.sh"},
            "critical_operation": {"file": "scripts/run.sh"},
            "trace": [],
        },
    ]

    jobs = build_job_plan(manifest, entries)

    assert [(job.commit, job.language, job.routing_reason) for job in jobs] == [
        ("a" * 40, "python", "vulngym-entry-trace"),
        ("b" * 40, "python", "repository-dominant-fallback"),
    ]


def test_filter_jobs_limits_execution_without_changing_full_plan() -> None:
    manifest = {
        "snapshots": [
            {"repo_url": "https://github.com/acme/project", "commit": "a" * 40},
            {"repo_url": "https://github.com/acme/project", "commit": "b" * 40},
        ]
    }
    entries = [
        {
            "repo_url": "https://github.com/acme/project",
            "commit": "a" * 40,
            "entry_point": {"file": "src/app.py"},
            "critical_operation": {"file": "src/sink.py"},
            "trace": [],
        }
    ]
    jobs = build_job_plan(manifest, entries)
    args = Namespace(
        pilot=False,
        repo_url=None,
        commit=None,
        language=None,
        max_jobs=1,
    )

    selected = _filter_jobs(jobs, args)

    assert len(jobs) == 2
    assert len(selected) == 1


def test_filter_jobs_can_defer_a_heavy_repository() -> None:
    jobs = [
        CodeQLJob(
            repo_url="https://github.com/openclaw/openclaw",
            commit="a" * 40,
            language="javascript-typescript",
            routing_reason="test",
            priority=1,
        ),
        CodeQLJob(
            repo_url="https://github.com/acme/project",
            commit="b" * 40,
            language="python",
            routing_reason="test",
            priority=2,
        ),
    ]
    args = Namespace(
        pilot=False,
        repo_url=None,
        exclude_repo_url=["https://github.com/openclaw/openclaw.git"],
        commit=None,
        language=None,
        max_jobs=None,
    )

    assert _filter_jobs(jobs, args) == [jobs[1]]


def test_resolve_path_expands_environment_and_preserves_relative_paths(
    tmp_path, monkeypatch
) -> None:
    home = tmp_path / "home"
    project = tmp_path / "project"
    monkeypatch.setenv("CODEQL_TEST_HOME", str(home))

    assert _resolve_path(project, "${CODEQL_TEST_HOME}/tools/codeql") == (
        home / "tools" / "codeql"
    ).resolve()
    assert _resolve_path(project, "config/profile.json") == (
        project / "config" / "profile.json"
    ).resolve()


def test_query_rerun_flag_resumes_existing_database_without_rework() -> None:
    assert _query_rerun_flag(database_reused=False) == "--rerun"
    assert _query_rerun_flag(database_reused=True) == "--no-rerun"


def test_database_marker_ignores_analysis_only_profile_changes() -> None:
    job = CodeQLJob(
        repo_url="https://github.com/acme/project",
        commit="a" * 40,
        language="javascript-typescript",
        routing_reason="test",
        priority=1,
    )
    profile = {
        "tool": {"version": "2.25.5", "executable_sha256": "tool-sha"},
        "node_runtime": {"version": "22.16.0", "executable_sha256": "node-sha"},
        "query_suite": "security-extended",
        "resources": {"analyze_ram_mb": 12288},
        "policy": {"build_modes": {"javascript-typescript": "none"}},
    }
    changed = json.loads(json.dumps(profile))
    changed["query_suite"] = "security-and-quality"
    changed["resources"]["analyze_ram_mb"] = 20480

    assert _database_marker(job, changed) == _database_marker(job, profile)


def test_database_marker_changes_when_extraction_runtime_changes() -> None:
    job = CodeQLJob(
        repo_url="https://github.com/acme/project",
        commit="a" * 40,
        language="python",
        routing_reason="test",
        priority=1,
    )
    profile = {
        "tool": {"version": "2.25.5", "executable_sha256": "tool-sha"},
        "python_runtime": {"version": "3.11.15", "executable_sha256": "python-a"},
        "policy": {"build_modes": {"python": "none"}},
    }
    changed = json.loads(json.dumps(profile))
    changed["python_runtime"]["executable_sha256"] = "python-b"

    assert _database_marker(job, changed) != _database_marker(job, profile)
