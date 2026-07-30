from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_LEADING_DOT_SLASH = re.compile(r"^(?:\./)+")
_MULTI_SLASH = re.compile(r"/+")
_RANGE = re.compile(r"^(\d+)-(\d+)$")


@dataclass(frozen=True, order=True)
class LineSpan:
    """Inclusive, one-based source line interval."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 1 or self.end < self.start:
            raise ValueError(f"invalid one-based line span: {self.start}-{self.end}")

    @classmethod
    def parse(cls, value: Any) -> "LineSpan":
        if isinstance(value, bool):
            raise ValueError("boolean is not a line")
        if isinstance(value, int):
            return cls(value, value)
        if isinstance(value, str):
            value = value.strip()
            if value.isdigit():
                line = int(value)
                return cls(line, line)
            match = _RANGE.fullmatch(value)
            if match:
                return cls(int(match.group(1)), int(match.group(2)))
        raise ValueError(f"unsupported line value: {value!r}")

    def distance(self, other: "LineSpan") -> int:
        """Zero for overlapping spans; otherwise number of lines between edges."""
        if self.end < other.start:
            return other.start - self.end
        if other.end < self.start:
            return self.start - other.end
        return 0


def normalize_path(path: Any) -> str:
    if not isinstance(path, str):
        return ""
    path = path.replace("\\", "/")
    path = _LEADING_DOT_SLASH.sub("", path)
    return _MULTI_SLASH.sub("/", path)


def normalize_repo(url: Any) -> str:
    if not isinstance(url, str):
        return ""
    value = url.strip().rstrip("/")
    if value.endswith(".git"):
        value = value[:-4]
    return value


def normalize_commit(commit: Any) -> str:
    return commit.strip().lower() if isinstance(commit, str) else ""


def endpoint_match(candidate: dict[str, Any], truth: dict[str, Any], tolerance: int = 5) -> bool:
    if tolerance < 0:
        raise ValueError("tolerance must be non-negative")
    candidate_path = normalize_path(candidate.get("file"))
    truth_path = normalize_path(truth.get("file"))
    if not candidate_path or candidate_path != truth_path:
        return False
    try:
        candidate_span = LineSpan.parse(candidate.get("line"))
        truth_span = LineSpan.parse(truth.get("line"))
    except ValueError:
        return False
    return candidate_span.distance(truth_span) <= tolerance


def finding_matches_entry(finding: dict[str, Any], entry: dict[str, Any], tolerance: int = 5) -> bool:
    if normalize_repo(finding.get("repo_url")) != normalize_repo(entry.get("repo_url")):
        return False
    if normalize_commit(finding.get("commit")) != normalize_commit(entry.get("commit")):
        return False
    return endpoint_match(finding.get("entry_point", {}), entry.get("entry_point", {}), tolerance) and endpoint_match(
        finding.get("critical_operation", {}), entry.get("critical_operation", {}), tolerance
    )
