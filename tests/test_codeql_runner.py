from __future__ import annotations

import hashlib
import json
from argparse import Namespace
from pathlib import Path

from vulngym_enrich.codeql_runner import (
    CodeQLJob,
    _apply_runtime_go_override,
    _apply_runtime_resource_overrides,
    _database_marker,
    _database_marker_matches,
    _filter_jobs,
    _job_plan_record,
    _query_inventory_sha256,
    _query_rerun_flag,
    _query_selection_matches,
    _resolve_path,
    _validated_query_lanes,
    build_job_plan,
    language_for_file,
)


def test_database_marker_matches_valid_marker(tmp_path: Path) -> None:
    marker = tmp_path / ".vulngym-codeql-db.json"
    expected = {"schema_version": 1, "commit": "a" * 40}
    marker.write_text(json.dumps(expected), encoding="utf-8")

    assert _database_marker_matches(marker, expected)
    assert not _database_marker_matches(marker, {**expected, "commit": "b" * 40})


def test_database_marker_treats_interrupted_write_as_cache_miss(
    tmp_path: Path, capsys
) -> None:
    marker = tmp_path / ".vulngym-codeql-db.json"
    marker.write_text("", encoding="utf-8")

    assert not _database_marker_matches(marker, {"schema_version": 1})
    assert "INVALID_DATABASE_MARKER" in capsys.readouterr().out


def test_database_marker_treats_non_object_json_as_cache_miss(
    tmp_path: Path, capsys
) -> None:
    marker = tmp_path / ".vulngym-codeql-db.json"
    marker.write_text("[]", encoding="utf-8")

    assert not _database_marker_matches(marker, {"schema_version": 1})
    assert "INVALID_DATABASE_MARKER" in capsys.readouterr().out


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
        max_disk_cache_mb=512,
        analyze_timeout_seconds=7200,
    )

    assert overrides == {
        "analyze_threads": 1,
        "analyze_ram_mb": 12288,
        "max_disk_cache_mb": 512,
        "analyze_timeout_seconds": 7200,
    }
    assert profile["resources"] == {
        "analyze_threads": 1,
        "analyze_ram_mb": 12288,
        "max_disk_cache_mb": 512,
        "analyze_timeout_seconds": 7200,
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
        exclude_repo_url=[],
        commit=None,
        language=None,
        exclude_language=[],
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
        exclude_language=[],
        max_jobs=None,
    )

    assert _filter_jobs(jobs, args) == [jobs[1]]


def test_filter_jobs_can_split_compiled_language_queue() -> None:
    jobs = [
        CodeQLJob(
            repo_url="https://github.com/acme/project",
            commit="a" * 40,
            language="javascript-typescript",
            routing_reason="test",
            priority=1,
        ),
        CodeQLJob(
            repo_url="https://github.com/acme/project",
            commit="a" * 40,
            language="go",
            routing_reason="test",
            priority=2,
        ),
    ]
    args = Namespace(
        pilot=False,
        repo_url=None,
        exclude_repo_url=[],
        commit=None,
        language=None,
        exclude_language=["go"],
        max_jobs=None,
    )

    assert _filter_jobs(jobs, args) == [jobs[0]]


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


def test_query_lane_plan_record_has_lane_specific_identity() -> None:
    job = CodeQLJob(
        repo_url="https://github.com/openclaw/openclaw",
        commit="a" * 40,
        language="javascript-typescript",
        routing_reason="test",
        priority=1,
    )
    selection = {"lane": "fast", "inventory_sha256": "b" * 64}

    record = _job_plan_record(job, selection)

    assert record["base_job_id"] == job.job_id
    assert record["job_id"] != job.job_id
    assert record["query_lane"] == "fast"
    assert record["query_inventory_sha256"] == "b" * 64


def test_query_selection_resume_requires_exact_lane_identity() -> None:
    selection = {
        "selection_id": "lanes-v1",
        "config_sha256": "a" * 64,
        "language": "javascript-typescript",
        "lane": "fast",
        "suite_sha256": "b" * 64,
        "query_count": 44,
        "inventory_sha256": "c" * 64,
        "base_inventory_sha256": "d" * 64,
    }

    assert _query_selection_matches(dict(selection), selection)
    changed = dict(selection)
    changed["lane"] = "heavy"
    assert not _query_selection_matches(changed, selection)
    assert _query_selection_matches({}, None)


def test_query_lane_config_proves_disjoint_complete_union(
    tmp_path: Path, monkeypatch
) -> None:
    profile_path = tmp_path / "profile.json"
    profile = {
        "query_packs": {
            "javascript-typescript": {
                "name": "codeql/javascript-queries",
                "version": "2.3.10",
            }
        }
    }
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    fast_suite = tmp_path / "fast.qls"
    heavy_suite = tmp_path / "heavy.qls"
    fast_suite.write_text("fast", encoding="utf-8")
    heavy_suite.write_text("heavy", encoding="utf-8")
    inventories = {
        "base-suite": ["A.ql", "B.ql", "C.ql"],
        str(fast_suite.resolve()): ["A.ql"],
        str(heavy_suite.resolve()): ["B.ql", "C.ql"],
    }

    def fake_resolve(**kwargs):
        return inventories[kwargs["suite"]]

    monkeypatch.setattr(
        "vulngym_enrich.codeql_runner._resolve_query_inventory", fake_resolve
    )
    def file_sha(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    config = {
        "schema_version": 1,
        "selection_id": "lanes-v1",
        "profile_sha256": file_sha(profile_path),
        "language": "javascript-typescript",
        "query_pack": profile["query_packs"]["javascript-typescript"],
        "base": {
            "suite": "base-suite",
            "query_count": 3,
            "inventory_sha256": _query_inventory_sha256(inventories["base-suite"]),
        },
        "lanes": {
            "fast": {
                "suite": str(fast_suite),
                "suite_sha256": file_sha(fast_suite),
                "query_count": 1,
                "inventory_sha256": _query_inventory_sha256(["A.ql"]),
            },
            "heavy": {
                "suite": str(heavy_suite),
                "suite_sha256": file_sha(heavy_suite),
                "query_count": 2,
                "inventory_sha256": _query_inventory_sha256(["B.ql", "C.ql"]),
            },
        },
        "invariants": {
            "required_lanes": ["fast", "heavy"],
            "union_query_count": 3,
            "overlap_query_count": 0,
            "missing_query_count": 0,
            "extra_query_count": 0,
        },
    }
    config_path = tmp_path / "lanes.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    lanes = _validated_query_lanes(
        project_root=tmp_path,
        profile_path=profile_path,
        profile=profile,
        executable=tmp_path / "codeql",
        config_path=config_path,
    )

    assert set(lanes) == {"fast", "heavy"}
    assert lanes["fast"]["coverage_invariants"] == {
        "union_query_count": 3,
        "overlap_query_count": 0,
        "missing_query_count": 0,
        "extra_query_count": 0,
    }
