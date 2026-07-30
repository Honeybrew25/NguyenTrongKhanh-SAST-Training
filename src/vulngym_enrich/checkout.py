from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

_SHA40 = re.compile(r"^[0-9a-f]{40}$")


def repo_slug(repo_url: str) -> str:
    parsed = urlparse(repo_url)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise ValueError(f"only public GitHub HTTPS URLs are accepted: {repo_url}")
    parts = [part for part in parsed.path.removesuffix(".git").split("/") if part]
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        raise ValueError(f"invalid GitHub repository URL: {repo_url}")
    return "__".join(parts)


def run_git(args: list[str], cwd: Path | None = None) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True)


def ensure_mirror(repo_url: str, cache_root: Path, refresh: bool = False) -> Path:
    slug = repo_slug(repo_url)
    mirror = cache_root / "mirrors" / f"{slug}.git"
    mirror.parent.mkdir(parents=True, exist_ok=True)
    if not mirror.exists():
        run_git(["clone", "--mirror", repo_url, str(mirror)])
    elif refresh:
        run_git(["remote", "update", "--prune"], cwd=mirror)
    return mirror


def checkout_snapshot(repo_url: str, commit: str, cache_root: Path, work_root: Path, refresh: bool = False) -> Path:
    if not _SHA40.fullmatch(commit):
        raise ValueError(f"commit must be a full lowercase SHA-1: {commit}")
    slug = repo_slug(repo_url)
    mirror = ensure_mirror(repo_url, cache_root, refresh=refresh)
    destination = work_root / slug / commit
    marker = destination / ".vulngym-snapshot.json"
    if marker.exists():
        metadata = json.loads(marker.read_text(encoding="utf-8"))
        if metadata.get("repo_url") == repo_url and metadata.get("commit") == commit:
            return destination
        raise RuntimeError(f"snapshot marker mismatch: {marker}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise RuntimeError(f"refusing to overwrite unmarked destination: {destination}")
    run_git(["clone", "--no-checkout", "--shared", str(mirror), str(destination)])
    run_git(["checkout", "--detach", commit], cwd=destination)
    actual = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=destination, check=True, text=True, capture_output=True
    ).stdout.strip()
    if actual != commit:
        raise RuntimeError(f"checkout mismatch: expected {commit}, got {actual}")
    marker.write_text(
        json.dumps({"repo_url": repo_url, "commit": commit, "mirror": str(mirror)}, indent=2) + "\n",
        encoding="utf-8",
    )
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
