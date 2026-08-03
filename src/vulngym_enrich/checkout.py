from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_GIT_TIMEOUT_SECONDS = 3600
_CLONE_ATTEMPTS = 3


@contextmanager
def interprocess_lock(path: Path, timeout_seconds: int = _GIT_TIMEOUT_SECONDS):
    """Hold an OS-released lock shared by scanner/checkouts across processes."""

    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    if path.stat().st_size == 0:
        handle.write(b"\0")
        handle.flush()
    deadline = time.monotonic() + timeout_seconds
    acquired = False
    try:
        while not acquired:
            handle.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"timed out waiting for interprocess lock: {path}") from exc
                time.sleep(0.1)
        yield
    finally:
        if acquired:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def repo_slug(repo_url: str) -> str:
    parsed = urlparse(repo_url)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise ValueError(f"only public GitHub HTTPS URLs are accepted: {repo_url}")
    parts = [part for part in parsed.path.removesuffix(".git").split("/") if part]
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        raise ValueError(f"invalid GitHub repository URL: {repo_url}")
    return "__".join(parts)


def run_git(
    args: list[str], cwd: Path | None = None, timeout_seconds: int = _GIT_TIMEOUT_SECONDS
) -> subprocess.CompletedProcess[str]:
    command = [
        "git",
        "-c",
        "core.longpaths=true",
        "-c",
        "http.lowSpeedLimit=1024",
        "-c",
        "http.lowSpeedTime=120",
        *args,
    ]
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or exc.output or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        detail = (stderr or stdout or "no partial diagnostic output").strip()
        if len(detail) > 4000:
            detail = detail[-4000:]
        raise RuntimeError(
            f"git command exceeded {timeout_seconds}s: {' '.join(command)}: {detail}"
        ) from exc
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        detail = stderr or stdout or "no diagnostic output"
        if len(detail) > 4000:
            detail = detail[-4000:]
        raise RuntimeError(
            f"git command exited {result.returncode}: {' '.join(command)}: {detail}"
        )
    return result


def _remove_task_temporary_tree(path: Path, expected_parent: Path) -> None:
    resolved = path.resolve()
    parent = expected_parent.resolve()
    if resolved.parent != parent or not path.name.startswith("."):
        raise RuntimeError(f"refusing to remove non-temporary checkout path: {resolved}")
    if path.exists():
        shutil.rmtree(path)


def verify_snapshot_state(destination: Path, expected_commit: str) -> None:
    actual = run_git(["rev-parse", "HEAD"], cwd=destination).stdout.strip()
    if actual != expected_commit:
        raise RuntimeError(f"cached snapshot HEAD mismatch: expected {expected_commit}, got {actual}")
    status = run_git(
        ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"],
        cwd=destination,
    ).stdout.splitlines()
    unexpected = [line for line in status if line != "?? .vulngym-snapshot.json"]
    if unexpected:
        preview = "; ".join(unexpected[:5])
        raise RuntimeError(f"cached snapshot is dirty: {preview}")


def ensure_mirror(repo_url: str, cache_root: Path, refresh: bool = False) -> Path:
    slug = repo_slug(repo_url)
    mirror = cache_root / "mirrors" / f"{slug}.git"
    lock = cache_root / "locks" / f"mirror-{slug}.lock"
    with interprocess_lock(lock):
        mirror.parent.mkdir(parents=True, exist_ok=True)
        if not mirror.exists():
            failures: list[str] = []
            for attempt in range(1, _CLONE_ATTEMPTS + 1):
                temporary = mirror.with_name(f".{mirror.name}.clone-{uuid.uuid4().hex}")
                try:
                    run_git(["clone", "--mirror", repo_url, str(temporary)])
                    temporary.replace(mirror)
                    break
                except RuntimeError as exc:
                    failures.append(f"attempt {attempt}: {exc}")
                    _remove_task_temporary_tree(temporary, mirror.parent)
                    if attempt < _CLONE_ATTEMPTS:
                        time.sleep(min(2**attempt, 10))
            else:
                raise RuntimeError(
                    f"failed to clone mirror after {_CLONE_ATTEMPTS} attempts: "
                    + " | ".join(failures)
                )
        elif refresh:
            run_git(["remote", "update", "--prune"], cwd=mirror)
        if run_git(["rev-parse", "--is-bare-repository"], cwd=mirror).stdout.strip() != "true":
            raise RuntimeError(f"cached mirror is not a valid bare repository: {mirror}")
    return mirror


def checkout_snapshot(repo_url: str, commit: str, cache_root: Path, work_root: Path, refresh: bool = False) -> Path:
    if not _SHA40.fullmatch(commit):
        raise ValueError(f"commit must be a full lowercase SHA-1: {commit}")
    slug = repo_slug(repo_url)
    mirror = ensure_mirror(repo_url, cache_root, refresh=refresh)
    destination = work_root / slug / commit
    lock = work_root / ".locks" / f"snapshot-{slug}-{commit}.lock"
    with interprocess_lock(lock):
        marker = destination / ".vulngym-snapshot.json"
        if marker.exists():
            metadata = json.loads(marker.read_text(encoding="utf-8"))
            if metadata.get("repo_url") == repo_url and metadata.get("commit") == commit:
                verify_snapshot_state(destination, commit)
                return destination
            raise RuntimeError(f"snapshot marker mismatch: {marker}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise RuntimeError(f"refusing to overwrite unmarked destination: {destination}")
        temporary = destination.with_name(f".{commit}.checkout-{uuid.uuid4().hex}")
        try:
            run_git(["clone", "--no-checkout", "--shared", str(mirror), str(temporary)])
            run_git(["checkout", "--detach", commit], cwd=temporary)
            actual = run_git(["rev-parse", "HEAD"], cwd=temporary).stdout.strip()
            if actual != commit:
                raise RuntimeError(f"checkout mismatch: expected {commit}, got {actual}")
            (temporary / ".vulngym-snapshot.json").write_text(
                json.dumps(
                    {"repo_url": repo_url, "commit": commit, "mirror": str(mirror)},
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            verify_snapshot_state(temporary, commit)
            temporary.replace(destination)
        except Exception:
            _remove_task_temporary_tree(temporary, destination.parent)
            raise
        verify_snapshot_state(destination, commit)
        return destination


def prefetch_manifest(manifest_path: Path, cache_root: Path, refresh: bool = False) -> int:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    repo_urls = sorted({snapshot["repo_url"] for snapshot in manifest["snapshots"]})
    for index, repo_url in enumerate(repo_urls, 1):
        print(f"[{index}/{len(repo_urls)}] mirror {repo_url}")
        ensure_mirror(repo_url, cache_root, refresh=refresh)
    return len(repo_urls)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cache target repositories and materialize exact VulnGym snapshots.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prefetch = subparsers.add_parser("prefetch", help="cache one mirror per repository from a manifest")
    prefetch.add_argument("--manifest", type=Path, required=True)
    prefetch.add_argument("--cache-root", type=Path, default=Path("cache"))
    prefetch.add_argument("--refresh", action="store_true")

    checkout = subparsers.add_parser("checkout", help="materialize one exact vulnerable snapshot")
    checkout.add_argument("--repo-url", required=True)
    checkout.add_argument("--commit", required=True)
    checkout.add_argument("--cache-root", type=Path, default=Path("cache"))
    checkout.add_argument("--work-root", type=Path, default=Path("worktrees"))
    checkout.add_argument("--refresh", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "prefetch":
        count = prefetch_manifest(args.manifest, args.cache_root, refresh=args.refresh)
        print(f"cached {count} repository mirror(s)")
    else:
        destination = checkout_snapshot(
            args.repo_url, args.commit, args.cache_root, args.work_root, refresh=args.refresh
        )
        print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
