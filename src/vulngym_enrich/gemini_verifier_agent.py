from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

from .verifier_agent import (
    AgentProfile,
    EvidenceToolbox,
    Provider,
    ProviderError,
    SnapshotResolver,
    TerminalProviderError,
    VerifierError,
    _CONTROLLER_PATH,
    _atomic_write_text,
    _load_official_corpus_proof,
    _select_records,
    audit_provider_events,
    execute_run,
    load_jsonl,
    sha256_bytes,
    sha256_file,
    validate_blind_input,
)


class _GeminiResponseSchemaError(ProviderError):
    """Internal marker for a bounded Gemini structured-output retry."""


_RAW_SECRET_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bAQ[._-][0-9A-Za-z._-]{16,}\b"),
    re.compile(
        r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|authorization)"
        r"(\s*[\"']?\s*[:=]\s*[\"']?)([^\s\"',;}{]{6,})"
    ),
)


class GeminiApiProvider:
    """Gemini Developer API adapter for the controller-owned source-review loop.

    The provider deliberately exposes no Gemini tools.  Source navigation remains
    controller-owned, while the full Gemini content objects are carried between
    turns so model thought signatures are preserved when the selected model emits
    them.
    """

    provider_id = "google-gemini-api-isolated-json"
    stateful = True
    _RETRYABLE_HTTP_CODES = {408, 409, 429, 500, 502, 503, 504}
    _THINKING_LEVELS = {"minimal", "low", "medium", "high"}

    def __init__(
        self,
        *,
        response_schema: Path,
        prompt_text: str,
        timeout_seconds: int,
        model: str,
        thinking_level: str = "high",
        seed: int = 0,
        temperature: float = 0.0,
        max_attempts: int = 3,
        max_event_bytes: int = 16_777_216,
        max_response_bytes: int = 1_048_576,
        client: Any | None = None,
        sdk_version: str | None = None,
        retry_delay_seconds: float = 1.0,
        rate_limit_retry_delay_seconds: float = 30.0,
        max_rate_limit_wait_seconds: float = 90.0,
        min_request_interval_seconds: float = 4.0,
    ):
        if not isinstance(model, str) or not model.strip():
            raise ProviderError("Gemini API provider requires an explicit model")
        normalized_model = model.strip().casefold()
        if (
            normalized_model == "latest"
            or normalized_model.endswith(("/latest", "-latest", ":latest"))
        ):
            raise ProviderError("Gemini API provider rejects mutable latest model aliases")
        normalized_thinking = str(thinking_level).casefold()
        if normalized_thinking not in self._THINKING_LEVELS:
            raise ProviderError(f"invalid Gemini thinking level: {thinking_level!r}")
        if (
            not isinstance(seed, int)
            or isinstance(seed, bool)
            or not -(2**31) <= seed < 2**31
        ):
            raise ProviderError("Gemini seed must be a signed 32-bit integer")
        if (
            not isinstance(temperature, (int, float))
            or isinstance(temperature, bool)
            or not 0.0 <= float(temperature) <= 2.0
        ):
            raise ProviderError("Gemini temperature must be between 0 and 2")
        if (
            not isinstance(max_attempts, int)
            or isinstance(max_attempts, bool)
            or not 1 <= max_attempts <= 5
        ):
            raise ProviderError("Gemini max attempts must be between 1 and 5")
        if timeout_seconds < 1:
            raise ProviderError("Gemini timeout must be positive")
        if retry_delay_seconds < 0:
            raise ProviderError("Gemini retry delay cannot be negative")
        if rate_limit_retry_delay_seconds < 0:
            raise ProviderError("Gemini rate-limit retry delay cannot be negative")
        if max_rate_limit_wait_seconds < 0:
            raise ProviderError("Gemini maximum rate-limit wait cannot be negative")
        if min_request_interval_seconds < 0:
            raise ProviderError("Gemini minimum request interval cannot be negative")

        google_key = os.environ.get("GOOGLE_API_KEY", "").strip()
        gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
        api_key = google_key or gemini_key
        if not api_key:
            raise ProviderError(
                "Gemini API credentials are missing; set GOOGLE_API_KEY or GEMINI_API_KEY"
            )
        credential_source = "GOOGLE_API_KEY" if google_key else "GEMINI_API_KEY"

        try:
            from google import genai
            from google.genai import errors as genai_errors
        except ImportError as exc:
            raise ProviderError(
                "Google Gen AI SDK is unavailable; install the google-genai dependency"
            ) from exc
        try:
            from jsonschema import Draft202012Validator
        except ImportError as exc:
            raise ProviderError(
                "JSON Schema validation is unavailable; install the jsonschema dependency"
            ) from exc

        self.model = model.strip()
        self.thinking_level = normalized_thinking
        self.seed = seed
        self.temperature = float(temperature)
        self.max_attempts = max_attempts
        self.retry_delay_seconds = float(retry_delay_seconds)
        self.rate_limit_retry_delay_seconds = float(rate_limit_retry_delay_seconds)
        self.max_rate_limit_wait_seconds = float(max_rate_limit_wait_seconds)
        self.min_request_interval_seconds = float(min_request_interval_seconds)
        self.response_schema = response_schema.resolve(strict=True)
        self.response_schema_sha256 = sha256_file(self.response_schema)
        self.prompt_text = prompt_text
        self.timeout_seconds = timeout_seconds
        self.max_event_bytes = max_event_bytes
        self.max_response_bytes = max_response_bytes
        try:
            schema = json.loads(self.response_schema.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProviderError("Gemini response schema is not valid JSON") from exc
        if not isinstance(schema, dict):
            raise ProviderError("Gemini response schema must be a JSON object")
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            raise ProviderError("Gemini response schema is invalid") from exc
        self._response_validator = Draft202012Validator(schema)
        # The Gemini endpoint accepts standard JSON Schema but not dialect identity
        # annotations.  Keep the frozen on-disk schema unchanged for local validation.
        self._api_response_schema = json.loads(json.dumps(schema))
        self._api_response_schema.pop("$schema", None)
        self._api_response_schema.pop("$id", None)

        discovered_version: str | None = sdk_version
        if discovered_version is None:
            try:
                discovered_version = importlib.metadata.version("google-genai")
            except importlib.metadata.PackageNotFoundError:
                candidate = getattr(genai, "__version__", None)
                discovered_version = candidate if isinstance(candidate, str) else None
        self.sdk_version = discovered_version or "google-genai-version-unknown"
        api_error_type = getattr(genai_errors, "APIError", None)
        self._api_error_type: type[BaseException] | tuple[()] = (
            api_error_type if isinstance(api_error_type, type) else ()
        )
        self.configuration = {
            "api": "gemini-developer-api",
            "sdk_version": self.sdk_version,
            "credential_source": credential_source,
            "model": self.model,
            "thinking_level": self.thinking_level,
            "seed": self.seed,
            "temperature": self.temperature,
            "structured_output": "response_json_schema",
            "response_schema_sha256": self.response_schema_sha256,
            "retry_policy": {
                "max_attempts": self.max_attempts,
                "retryable_causes": [
                    "transport",
                    "response_schema",
                    "response_semantics",
                ],
                "transport_base_delay_seconds": self.retry_delay_seconds,
                "rate_limit_base_delay_seconds": self.rate_limit_retry_delay_seconds,
                "max_rate_limit_wait_seconds": self.max_rate_limit_wait_seconds,
                "min_request_interval_seconds": self.min_request_interval_seconds,
            },
        }
        self.configuration_sha256 = sha256_bytes(
            json.dumps(
                self.configuration,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        self.adapter_path = Path(__file__).resolve(strict=True)
        self.adapter_sha256 = sha256_file(self.adapter_path)
        # The frozen controller includes provider.version and model in every run
        # and case identity.  This deterministic composite therefore locks the
        # adapter implementation and every non-secret generation setting.
        self.version = (
            f"{self.sdk_version}+adapter.sha256.{self.adapter_sha256}"
            f".config.sha256.{self.configuration_sha256}"
        )
        self._client = (
            client
            if client is not None
            else genai.Client(
                api_key=api_key,
                http_options={
                    "timeout": timeout_seconds * 1000,
                    # Retries are controller-visible and bounded below.  Disable hidden
                    # SDK retries so one configured attempt means one billable request.
                    "retry_options": {"attempts": 1},
                },
            )
        )
        self._histories: dict[str, list[Any]] = {}
        self._session_ids: dict[str, str] = {}
        self._cumulative_usage: dict[str, dict[str, int]] = {}
        self._exposed_ranges: dict[str, dict[str, list[tuple[int, int]]]] = {}
        self._last_request_started_at: float | None = None
        self._observed_model_versions: set[str] = set()
        self._observed_response_ids: set[str] = set()

    @property
    def observed_model_versions(self) -> tuple[str, ...]:
        """Actual server-reported model versions observed by this provider."""

        return tuple(sorted(self._observed_model_versions))

    @property
    def observed_response_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._observed_response_ids))

    def _provider_identity(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "provider": self.provider_id,
            "provider_version": self.version,
            "sdk_version": self.sdk_version,
            "adapter": {
                "path": str(self.adapter_path),
                "sha256": self.adapter_sha256,
            },
            "configuration": self.configuration,
            "configuration_sha256": self.configuration_sha256,
        }

    @classmethod
    def _redact_raw_secrets(cls, value: Any, *, depth: int = 0) -> Any:
        if depth > 32:
            raise ProviderError("Gemini raw response exceeds the nesting limit")
        if isinstance(value, str):
            redacted = value
            for index, pattern in enumerate(_RAW_SECRET_PATTERNS):
                redacted = (
                    pattern.sub(r"\1\2[REDACTED]", redacted)
                    if index == 3
                    else pattern.sub("[REDACTED]", redacted)
                )
            return redacted
        if isinstance(value, dict):
            return {
                str(key): cls._redact_raw_secrets(item, depth=depth + 1)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._redact_raw_secrets(item, depth=depth + 1) for item in value]
        return value

    def _write_run_configuration(self, case_directory: Path) -> None:
        run_directory = (
            case_directory.parent.parent
            if case_directory.parent.name == "cases"
            else case_directory
        )
        path = run_directory / "gemini-provider-configuration.json"
        expected = self._provider_identity()
        if path.is_file():
            if path.stat().st_size > self.max_response_bytes:
                raise ProviderError("Gemini run configuration exceeds its byte budget")
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ProviderError("Gemini run configuration is invalid JSON") from exc
            if existing != expected:
                raise ProviderError("Gemini run configuration identity mismatch")
            return
        self._write_bounded_json(
            path,
            expected,
            max_bytes=self.max_response_bytes,
            artifact="run configuration",
        )

    @staticmethod
    def _archive_stale_provider_artifacts(case_directory: Path) -> None:
        patterns = (
            "step-*-raw-response.json",
            "step-*-response.json",
            "step-*-events.jsonl",
            "step-*-provider-metadata.json",
            "step-*-schema-retry-*-raw-response.json",
            "provider-session.json",
        )
        stale: list[Path] = []
        seen: set[Path] = set()
        for pattern in patterns:
            for path in sorted(case_directory.glob(pattern)):
                if path.is_file() and path not in seen:
                    stale.append(path)
                    seen.add(path)
        if not stale:
            return
        attempts = case_directory / "attempts"
        numeric = sorted(
            (
                path
                for path in attempts.iterdir()
                if path.is_dir() and re.fullmatch(r"[0-9]{4}", path.name)
            ),
            key=lambda path: int(path.name),
        ) if attempts.is_dir() else []
        archive = numeric[-1] if numeric else attempts / "0001"
        if any((archive / path.name).exists() for path in stale):
            next_number = (int(numeric[-1].name) if numeric else 0) + 1
            archive = attempts / f"{next_number:04d}"
        archive.mkdir(parents=True, exist_ok=True)
        for path in stale:
            path.replace(archive / path.name)

    def response_metadata(
        self, case_directory: Path, step: int
    ) -> dict[str, Any]:
        """Load and verify persisted server identity/usage for one completed call."""

        metadata_path = case_directory / f"step-{step:02d}-provider-metadata.json"
        if not metadata_path.is_file():
            raise ProviderError(f"Gemini metadata is missing for step {step}")
        if metadata_path.stat().st_size > self.max_response_bytes:
            raise ProviderError("Gemini provider metadata exceeds its byte budget")
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProviderError("Gemini provider metadata is invalid JSON") from exc
        if (
            not isinstance(metadata, dict)
            or metadata.get("schema_version") != 1
            or metadata.get("status") != "SUCCESS"
            or metadata.get("provider") != self.provider_id
            or metadata.get("sdk_version") != self.sdk_version
            or metadata.get("provider_version") != self.version
            or metadata.get("adapter")
            != {"path": str(self.adapter_path), "sha256": self.adapter_sha256}
            or metadata.get("configuration") != self.configuration
            or metadata.get("configuration_sha256") != self.configuration_sha256
            or metadata.get("configured_model") != self.model
            or metadata.get("step") != step
            or not isinstance(metadata.get("model_version"), str)
            or not metadata["model_version"]
            or not isinstance(metadata.get("response_id"), str)
            or not metadata["response_id"]
        ):
            raise ProviderError("Gemini provider metadata identity is invalid")
        raw_identity = metadata.get("raw_response")
        expected_raw_path = case_directory / f"step-{step:02d}-raw-response.json"
        if (
            not isinstance(raw_identity, dict)
            or raw_identity.get("path") != expected_raw_path.name
            or not expected_raw_path.is_file()
            or raw_identity.get("bytes") != expected_raw_path.stat().st_size
            or raw_identity.get("sha256") != sha256_file(expected_raw_path)
        ):
            raise ProviderError("Gemini raw-response identity is invalid")
        return metadata

    @staticmethod
    def _case_key(case_directory: Path) -> str:
        return str(case_directory.resolve())

    @staticmethod
    def _json_value(value: Any, *, depth: int = 0) -> Any:
        if depth > 32:
            raise ProviderError("Gemini raw response exceeds the nesting limit")
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, dict):
            return {
                str(key): GeminiApiProvider._json_value(item, depth=depth + 1)
                for key, item in value.items()
                if str(key) != "sdk_http_response"
            }
        if isinstance(value, (list, tuple)):
            return [
                GeminiApiProvider._json_value(item, depth=depth + 1)
                for item in value
            ]
        dumper = getattr(value, "model_dump", None)
        if callable(dumper):
            try:
                dumped = dumper(
                    mode="json",
                    exclude_none=True,
                    exclude={"sdk_http_response"},
                )
            except TypeError:
                dumped = dumper()
            if dumped is value:
                raise ProviderError("Gemini response could not be serialized safely")
            return GeminiApiProvider._json_value(dumped, depth=depth + 1)
        enum_value = getattr(value, "value", None)
        if isinstance(enum_value, (str, int, float, bool)):
            return enum_value
        isoformat = getattr(value, "isoformat", None)
        if callable(isoformat):
            rendered = isoformat()
            if isinstance(rendered, str):
                return rendered
        raise ProviderError(
            f"Gemini response contains unsupported metadata type: {type(value).__name__}"
        )

    def _write_bounded_json(
        self,
        path: Path,
        value: Any,
        *,
        max_bytes: int,
        artifact: str,
    ) -> None:
        rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        if len(rendered.encode("utf-8")) > max_bytes:
            raise ProviderError(f"Gemini {artifact} exceeds its byte budget")
        _atomic_write_text(path, rendered)

    def _write_attempt_audit(
        self,
        case_directory: Path,
        *,
        step: int,
        session_id: str,
        attempt_history: list[dict[str, Any]],
        status: str,
    ) -> None:
        self._write_bounded_json(
            case_directory / f"step-{step:02d}-provider-metadata.json",
            {
                **self._provider_identity(),
                "status": status,
                "configured_model": self.model,
                "session_id": session_id,
                "step": step,
                "attempts": len(attempt_history),
                "attempt_history": attempt_history,
            },
            max_bytes=self.max_response_bytes,
            artifact="provider attempt metadata",
        )

    def _is_retryable_transport_error(self, exc: Exception) -> bool:
        if self._api_error_type and isinstance(exc, self._api_error_type):
            code = getattr(exc, "code", None)
            return isinstance(code, int) and code in self._RETRYABLE_HTTP_CODES
        if isinstance(exc, (TimeoutError, ConnectionError)):
            return True
        return any(
            cls.__module__.split(".", 1)[0] in {"httpx", "httpcore"}
            and cls.__name__
            in {
                "TransportError",
                "TimeoutException",
                "ConnectError",
                "ReadError",
                "WriteError",
                "PoolTimeout",
            }
            for cls in type(exc).__mro__
        )

    @staticmethod
    def _retry_after_seconds(exc: Exception) -> float | None:
        """Extract a bounded RetryInfo/header delay without persisting provider text."""

        candidates: list[float] = []

        def visit(value: Any, *, depth: int = 0) -> None:
            if depth > 12:
                return
            if isinstance(value, dict):
                for key, item in value.items():
                    normalized = str(key).replace("_", "").casefold()
                    if normalized in {"retrydelay", "retryafter"}:
                        if isinstance(item, (int, float)) and not isinstance(item, bool):
                            candidates.append(float(item))
                        elif isinstance(item, str):
                            match = re.fullmatch(
                                r"\s*([0-9]+(?:\.[0-9]+)?)\s*s?\s*", item
                            )
                            if match:
                                candidates.append(float(match.group(1)))
                    visit(item, depth=depth + 1)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    visit(item, depth=depth + 1)

        visit(getattr(exc, "details", None))
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", None)
        if headers is not None:
            try:
                retry_after = headers.get("retry-after")
            except (AttributeError, TypeError):
                retry_after = None
            if isinstance(retry_after, str):
                match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*", retry_after)
                if match:
                    candidates.append(float(match.group(1)))
        valid = [value for value in candidates if 0 <= value < float("inf")]
        return max(valid) if valid else None

    def _transport_retry_delay(self, exc: Exception, attempt: int) -> float:
        code = getattr(exc, "code", None)
        if code == 429:
            provider_delay = self._retry_after_seconds(exc) or 0.0
            return max(
                provider_delay,
                self.rate_limit_retry_delay_seconds * attempt,
            )
        return self.retry_delay_seconds * attempt

    def _throttle_request(self) -> None:
        if self._last_request_started_at is not None:
            remaining = (
                self._last_request_started_at
                + self.min_request_interval_seconds
                - time.monotonic()
            )
            if remaining > 0:
                time.sleep(remaining)
        self._last_request_started_at = time.monotonic()

    @staticmethod
    def _add_exposed_result(
        exposed: dict[str, list[tuple[int, int]]], result: Any
    ) -> None:
        if not isinstance(result, dict) or result.get("ok") is not True:
            return
        if result.get("tool") == "read_file":
            path = result.get("path")
            start = result.get("start_line")
            end = result.get("end_line")
            if (
                isinstance(path, str)
                and isinstance(start, int)
                and not isinstance(start, bool)
                and isinstance(end, int)
                and not isinstance(end, bool)
                and start >= 1
                and end >= start
            ):
                exposed.setdefault(path, []).append((start, end))
        elif result.get("tool") == "search_code":
            for match in result.get("matches") or []:
                if not isinstance(match, dict):
                    continue
                path = match.get("path")
                line = match.get("line")
                if (
                    isinstance(path, str)
                    and isinstance(line, int)
                    and not isinstance(line, bool)
                    and line >= 1
                ):
                    exposed.setdefault(path, []).append((line, line))

    def _record_exposed_ranges(
        self, key: str, request: dict[str, Any]
    ) -> dict[str, list[tuple[int, int]]]:
        exposed = self._exposed_ranges.setdefault(key, {})
        observations = request.get("initial_observations")
        if isinstance(observations, list):
            for result in observations:
                self._add_exposed_result(exposed, result)
        exchange = request.get("latest_controller_exchange")
        if isinstance(exchange, dict):
            results = exchange.get("results")
            if isinstance(results, list):
                for result in results:
                    self._add_exposed_result(exposed, result)
        return exposed

    @staticmethod
    def _response_semantic_defect(
        response: dict[str, Any], exposed: dict[str, list[tuple[int, int]]]
    ) -> str | None:
        if response.get("action") != "FINAL":
            return None
        verdict = response.get("verdict")
        reason_codes = response.get("reason_codes")
        if isinstance(reason_codes, list):
            if len(set(reason_codes)) != len(reason_codes):
                return "reason_codes must be unique"
            if verdict == "FALSE_POSITIVE" and not reason_codes:
                return "FALSE_POSITIVE requires at least one reason code"
            if verdict != "FALSE_POSITIVE" and reason_codes:
                return "only FALSE_POSITIVE may contain false-positive reason codes"
        evidence = response.get("evidence")
        if not isinstance(evidence, list):
            return None
        if verdict in {"TRUE_POSITIVE", "FALSE_POSITIVE"} and not evidence:
            if not any(exposed.values()):
                return (
                    f"{verdict} requires source evidence; no source range has been "
                    "exposed by the controller, so return ABSTAIN with empty evidence "
                    "and abstain_reason INSUFFICIENT_CONTEXT"
                )
            return f"{verdict} requires source evidence"
        for citation in evidence:
            if not isinstance(citation, dict):
                continue
            path = citation.get("file")
            start = citation.get("start_line")
            end = citation.get("end_line")
            if not (
                isinstance(path, str)
                and isinstance(start, int)
                and not isinstance(start, bool)
                and isinstance(end, int)
                and not isinstance(end, bool)
            ):
                continue
            ranges = sorted(exposed.get(path, []))
            if not any(
                exposed_start <= start and end <= exposed_end
                for exposed_start, exposed_end in ranges
            ):
                rendered_ranges = ", ".join(
                    f"{exposed_start}-{exposed_end}"
                    for exposed_start, exposed_end in ranges
                )
                if ranges:
                    return (
                        f"evidence citation {path}:{start}-{end} crosses or falls "
                        "outside controller source-range boundaries; split or narrow "
                        "it so every citation is fully contained in one of these "
                        f"exposed ranges: {rendered_ranges}"
                    )
                return (
                    f"evidence citation {path}:{start}-{end} has no exposed source "
                    "range; request bounded source through the controller, or return "
                    "ABSTAIN with empty evidence when source cannot be exposed"
                )
        return None

    def _raise_transport_failure(self, exc: Exception) -> None:
        code = getattr(exc, "code", None)
        if code in {401, 403}:
            raise TerminalProviderError("PROVIDER_AUTHENTICATION_FAILED") from None
        if code == 404:
            raise TerminalProviderError("PROVIDER_MODEL_UNAVAILABLE") from None
        if code == 429:
            raise TerminalProviderError("PROVIDER_RATE_LIMIT") from None
        raise ProviderError("GEMINI_API_TRANSPORT_OR_REQUEST_FAILED") from None

    @staticmethod
    def _response_attribute(response: Any, name: str, raw: dict[str, Any]) -> Any:
        value = getattr(response, name, None)
        if value is not None:
            return value
        if name in raw:
            return raw[name]
        camel = re.sub(r"_([a-z])", lambda match: match.group(1).upper(), name)
        return raw.get(camel)

    @classmethod
    def _normalized_usage(
        cls, response: Any, raw_response: dict[str, Any]
    ) -> tuple[dict[str, int], Any]:
        usage_value = cls._response_attribute(
            response, "usage_metadata", raw_response
        )
        raw_usage = cls._json_value(usage_value) if usage_value is not None else {}
        if not isinstance(raw_usage, dict):
            raw_usage = {}
        aliases = {
            "input_tokens": ("prompt_token_count", "promptTokenCount"),
            "output_tokens": ("candidates_token_count", "candidatesTokenCount"),
            "cached_input_tokens": (
                "cached_content_token_count",
                "cachedContentTokenCount",
            ),
            "reasoning_tokens": ("thoughts_token_count", "thoughtsTokenCount"),
            "tool_input_tokens": (
                "tool_use_prompt_token_count",
                "toolUsePromptTokenCount",
            ),
            "total_tokens": ("total_token_count", "totalTokenCount"),
        }
        normalized: dict[str, int] = {}
        for target, candidates in aliases.items():
            for candidate in candidates:
                value = raw_usage.get(candidate)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    normalized[target] = value
                    break
        return normalized, raw_usage

    def _parse_structured_response(
        self,
        response: Any,
        *,
        exposed_ranges: dict[str, list[tuple[int, int]]] | None = None,
    ) -> dict[str, Any]:
        try:
            response_text = getattr(response, "text", None)
        except Exception as exc:
            raise _GeminiResponseSchemaError(
                "Gemini response has no readable structured text"
            ) from exc
        parsed: Any
        if isinstance(response_text, str) and response_text.strip():
            if len(response_text.encode("utf-8")) > self.max_response_bytes:
                raise ProviderError("Gemini provider response exceeds its byte budget")
            try:
                parsed = json.loads(response_text)
            except json.JSONDecodeError as exc:
                raise _GeminiResponseSchemaError(
                    "Gemini response is not valid JSON"
                ) from exc
        else:
            parsed = getattr(response, "parsed", None)
            if parsed is not None:
                parsed = self._json_value(parsed)
            if parsed is None:
                raise _GeminiResponseSchemaError(
                    "Gemini response contains no structured JSON"
                )
        if not isinstance(parsed, dict):
            raise _GeminiResponseSchemaError(
                "Gemini structured response must be an object"
            )
        sanitized = self._redact_raw_secrets(parsed)
        if not isinstance(sanitized, dict):
            raise _GeminiResponseSchemaError(
                "Gemini sanitized structured response must be an object"
            )
        parsed = sanitized
        if next(self._response_validator.iter_errors(parsed), None) is not None:
            raise _GeminiResponseSchemaError(
                "Gemini response does not conform to the frozen response schema"
            )
        if parsed.get("action") == "FINAL" and any(
            not isinstance(parsed.get(field), str) or not parsed[field].strip()
            for field in (
                "attacker_capability",
                "entry_point",
                "security_effect",
                "controls",
                "reasoning",
            )
        ):
            raise _GeminiResponseSchemaError(
                "Gemini FINAL response has an empty required decision field"
            )
        if exposed_ranges is not None:
            defect = self._response_semantic_defect(parsed, exposed_ranges)
            if defect:
                raise _GeminiResponseSchemaError(defect)
        return parsed

    @staticmethod
    def _candidate_content(response: Any, response_text: str) -> Any:
        candidates = getattr(response, "candidates", None)
        if isinstance(candidates, (list, tuple)) and candidates:
            content = getattr(candidates[0], "content", None)
            if content is not None:
                return content
        return {"role": "model", "parts": [{"text": response_text}]}

    def close_case(self, case_directory: Path) -> None:
        key = self._case_key(case_directory)
        self._histories.pop(key, None)
        self._session_ids.pop(key, None)
        self._cumulative_usage.pop(key, None)
        self._exposed_ranges.pop(key, None)

    def complete(
        self,
        request: dict[str, Any],
        *,
        case_directory: Path,
        step: int,
    ) -> dict[str, Any]:
        case_directory.mkdir(parents=True, exist_ok=True)
        key = self._case_key(case_directory)
        history = self._histories.setdefault(key, [])
        enforce_controller_semantics = request.get("task") in {
            "blind_security_finding_verification",
            "blind_security_finding_verification_continuation",
        }
        exposed_ranges = (
            self._record_exposed_ranges(key, request)
            if enforce_controller_semantics
            else None
        )
        expected_step = len(history) // 2 + 1
        if step != expected_step:
            raise ProviderError(
                f"Gemini controller step is out of sequence: expected {expected_step}, got {step}"
            )
        if step == 1:
            self._archive_stale_provider_artifacts(case_directory)
        self._write_run_configuration(case_directory)
        session_id = self._session_ids.setdefault(key, f"gemini-{uuid.uuid4().hex}")
        cumulative_usage = self._cumulative_usage.setdefault(key, {})
        request_text = (
            "<controller_request>\n"
            + json.dumps(request, ensure_ascii=False, indent=2)
            + "\n</controller_request>\n"
        )
        user_content: dict[str, Any] = {
            "role": "user",
            "parts": [{"text": request_text}],
        }
        generation_config = {
            "system_instruction": self.prompt_text,
            "response_mime_type": "application/json",
            "response_json_schema": self._api_response_schema,
            "temperature": self.temperature,
            "seed": self.seed,
            "thinking_config": {
                "thinking_level": self.thinking_level,
                "include_thoughts": False,
            },
        }
        response: Any | None = None
        raw_response: dict[str, Any] | None = None
        structured: dict[str, Any] | None = None
        successful_user_content: dict[str, Any] | None = None
        attempt_history: list[dict[str, Any]] = []
        used_attempt = 0
        retry_feedback = (
            "The previous call failed transport or local response-schema validation. "
            "Return exactly one JSON object conforming to the configured schema; "
            "do not add prose."
        )
        for attempt in range(1, self.max_attempts + 1):
            used_attempt = attempt
            attempt_content = user_content
            if attempt > 1:
                attempt_content = {
                    "role": "user",
                    "parts": [
                        {"text": request_text},
                        {"text": retry_feedback},
                    ],
                }
            try:
                self._throttle_request()
                response = self._client.models.generate_content(
                    model=self.model,
                    contents=[*history, attempt_content],
                    config=generation_config,
                )
            except Exception as exc:
                retryable = self._is_retryable_transport_error(exc)
                code = getattr(exc, "code", None)
                retry_delay = self._transport_retry_delay(exc, attempt)
                retry_within_budget = (
                    code != 429
                    or retry_delay <= self.max_rate_limit_wait_seconds
                )
                will_retry = (
                    retryable
                    and retry_within_budget
                    and attempt < self.max_attempts
                )
                attempt_history.append(
                    {
                        "attempt": attempt,
                        "outcome": "RETRY" if will_retry else "FAILED",
                        "cause": "TRANSPORT",
                        "provider_code": code if isinstance(code, int) else None,
                        "raw_response": None,
                        **(
                            {"retry_delay_seconds": retry_delay}
                            if will_retry and retry_delay > 0
                            else {}
                        ),
                    }
                )
                self._write_attempt_audit(
                    case_directory,
                    step=step,
                    session_id=session_id,
                    attempt_history=attempt_history,
                    status=(
                        "RETRYING" if will_retry else "FAILED"
                    ),
                )
                if will_retry:
                    if retry_delay:
                        time.sleep(retry_delay)
                    continue
                self._raise_transport_failure(exc)
            dumped = self._json_value(response)
            if not isinstance(dumped, dict):
                raise ProviderError("Gemini raw response must be an object")
            sanitized = self._redact_raw_secrets(dumped)
            if not isinstance(sanitized, dict):
                raise ProviderError("Gemini sanitized raw response must be an object")
            raw_response = sanitized
            try:
                structured = self._parse_structured_response(
                    response, exposed_ranges=exposed_ranges
                )
            except _GeminiResponseSchemaError as exc:
                defect = str(exc)
                retry_normalized_usage, retry_raw_usage = self._normalized_usage(
                    response, raw_response
                )
                for name, value in retry_normalized_usage.items():
                    cumulative_usage[name] = cumulative_usage.get(name, 0) + value
                semantic_defects = {
                        "reason_codes must be unique",
                        "FALSE_POSITIVE requires at least one reason code",
                        "only FALSE_POSITIVE may contain false-positive reason codes",
                    }
                cause = (
                    "RESPONSE_SEMANTICS"
                    if defect in semantic_defects
                    or defect.startswith("evidence citation ")
                    or defect.endswith("requires source evidence")
                    or " requires source evidence; " in defect
                    else "RESPONSE_SCHEMA"
                )
                retry_path = (
                    case_directory
                    / f"step-{step:02d}-schema-retry-{attempt:02d}-raw-response.json"
                )
                self._write_bounded_json(
                    retry_path,
                    raw_response,
                    max_bytes=self.max_event_bytes,
                    artifact="raw response",
                )
                attempt_history.append(
                    {
                        "attempt": attempt,
                        "outcome": (
                            "RETRY" if attempt < self.max_attempts else "FAILED"
                        ),
                        "cause": cause,
                        "validation_feedback": defect,
                        "provider_code": None,
                        "usage": retry_raw_usage,
                        "normalized_usage": retry_normalized_usage,
                        "raw_response": {
                            "path": retry_path.name,
                            "sha256": sha256_file(retry_path),
                            "bytes": retry_path.stat().st_size,
                        },
                    }
                )
                self._write_attempt_audit(
                    case_directory,
                    step=step,
                    session_id=session_id,
                    attempt_history=attempt_history,
                    status=(
                        "RETRYING" if attempt < self.max_attempts else "FAILED"
                    ),
                )
                if attempt < self.max_attempts:
                    retry_feedback = (
                        "The previous JSON response was rejected by local validation: "
                        f"{defect}. Correct that defect using only the controller request, "
                        "then return exactly one JSON object conforming to the configured "
                        "schema; do not add prose."
                    )
                    if self.retry_delay_seconds:
                        time.sleep(self.retry_delay_seconds * attempt)
                    continue
                raise ProviderError("GEMINI_RESPONSE_SCHEMA_INVALID") from None
            attempt_history.append(
                {
                    "attempt": attempt,
                    "outcome": "ACCEPTED",
                    "cause": None,
                    "provider_code": None,
                    "raw_response": None,
                }
            )
            successful_user_content = attempt_content
            break
        if (
            response is None
            or raw_response is None
            or structured is None
            or successful_user_content is None
        ):
            raise ProviderError("Gemini provider exhausted its bounded retry budget")

        raw_path = case_directory / f"step-{step:02d}-raw-response.json"
        response_path = case_directory / f"step-{step:02d}-response.json"
        metadata_path = case_directory / f"step-{step:02d}-provider-metadata.json"
        events_path = case_directory / f"step-{step:02d}-events.jsonl"
        self._write_bounded_json(
            raw_path,
            raw_response,
            max_bytes=self.max_event_bytes,
            artifact="raw response",
        )
        self._write_bounded_json(
            response_path,
            structured,
            max_bytes=self.max_response_bytes,
            artifact="provider response",
        )
        normalized_usage, raw_usage = self._normalized_usage(response, raw_response)
        for name, value in normalized_usage.items():
            cumulative_usage[name] = cumulative_usage.get(name, 0) + value
        response_id_value = self._response_attribute(
            response, "response_id", raw_response
        )
        model_version_value = self._response_attribute(
            response, "model_version", raw_response
        )
        response_id = response_id_value if isinstance(response_id_value, str) else None
        model_version = (
            model_version_value if isinstance(model_version_value, str) else None
        )
        if not model_version:
            raise ProviderError("GEMINI_MODEL_VERSION_MISSING")
        if not response_id:
            raise ProviderError("GEMINI_RESPONSE_ID_MISSING")
        if self._observed_model_versions and model_version not in self._observed_model_versions:
            raise ProviderError("GEMINI_MODEL_VERSION_CHANGED_DURING_RUN")
        if response_id in self._observed_response_ids:
            raise ProviderError("GEMINI_RESPONSE_ID_REUSED_DURING_RUN")
        self._observed_model_versions.add(model_version)
        self._observed_response_ids.add(response_id)
        metadata = {
            "schema_version": 1,
            "provider": self.provider_id,
            "provider_version": self.version,
            "sdk_version": self.sdk_version,
            "adapter": {
                "path": str(self.adapter_path),
                "sha256": self.adapter_sha256,
            },
            "configuration": self.configuration,
            "configuration_sha256": self.configuration_sha256,
            "configured_model": self.model,
            "status": "SUCCESS",
            "model_version": model_version,
            "response_id": response_id,
            "session_id": session_id,
            "step": step,
            "attempts": used_attempt,
            "attempt_history": attempt_history,
            "usage": raw_usage,
            "normalized_usage": normalized_usage,
            "raw_response": {
                "path": raw_path.name,
                "sha256": sha256_file(raw_path),
                "bytes": raw_path.stat().st_size,
            },
        }
        self._write_bounded_json(
            metadata_path,
            metadata,
            max_bytes=self.max_response_bytes,
            artifact="provider metadata",
        )
        response_text = json.dumps(
            structured, ensure_ascii=False, separators=(",", ":")
        )
        events = [
            {"type": "thread.started", "thread_id": session_id},
            {"type": "turn.started"},
            {
                "type": "item.completed",
                "item": {
                    "id": response_id,
                    "type": "agent_message",
                    "text": response_text,
                },
            },
            {"type": "turn.completed", "usage": dict(cumulative_usage)},
        ]
        rendered_events = "".join(
            json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
            for event in events
        )
        if len(rendered_events.encode("utf-8")) > self.max_event_bytes:
            raise ProviderError("Gemini provider event log exceeds its byte budget")
        _atomic_write_text(events_path, rendered_events)
        audit = audit_provider_events(events_path, max_bytes=self.max_event_bytes)
        if json.loads(str(audit["final_agent_message"])) != structured:
            raise ProviderError("Gemini structured response does not match its audit event")

        history.extend(
            [
                successful_user_content,
                self._candidate_content(response, response_text),
            ]
        )
        self._write_bounded_json(
            case_directory / "provider-session.json",
            {
                **self._provider_identity(),
                "session_id": session_id,
                "completed_steps": step,
            },
            max_bytes=self.max_response_bytes,
            artifact="session metadata",
        )
        return structured



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the frozen blind source-review controller through Gemini API."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, default=Path("worktrees"))
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument(
        "--profile", type=Path, default=Path("config/verifier-profile-v1.json")
    )
    parser.add_argument(
        "--prompt", type=Path, default=Path("config/verifier-prompt-v1.md")
    )
    parser.add_argument(
        "--response-schema",
        type=Path,
        default=Path("schemas/verifier-agent-response.schema.json"),
    )
    parser.add_argument(
        "--provider",
        choices=("gemini-api",),
        default="gemini-api",
        help="compatibility selector; this entrypoint only supports gemini-api",
    )
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--gemini-thinking-level",
        choices=("minimal", "low", "medium", "high"),
        default="high",
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument(
        "--gemini-max-attempts",
        type=int,
        default=3,
        help="bounded total attempts for transport/schema failures only",
    )
    parser.add_argument(
        "--gemini-min-request-interval-seconds",
        type=float,
        default=4.0,
        help="minimum start-to-start interval used to stay below small RPM quotas",
    )
    parser.add_argument(
        "--gemini-rate-limit-retry-delay-seconds",
        type=float,
        default=30.0,
        help="base backoff for HTTP 429; provider RetryInfo may increase it",
    )
    parser.add_argument(
        "--gemini-max-rate-limit-wait-seconds",
        type=float,
        default=90.0,
        help="fail closed instead of sleeping past this provider-requested delay",
    )
    parser.add_argument(
        "--development-run",
        action="store_true",
        help="mark predictions ineligible; required for partial input",
    )
    parser.add_argument("--finding-id", action="append")
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate blind input and exact snapshots without invoking Gemini",
    )
    args = parser.parse_args(argv)

    try:
        profile = AgentProfile.load(args.profile)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.finding_id and not args.development_run:
        parser.error("--finding-id is forbidden for official verifier runs")
    if args.force and not args.development_run:
        parser.error("--force is forbidden for official verifier runs; use a new run directory")
    try:
        all_records = load_jsonl(args.input, profile)
        records = _select_records(all_records, args.finding_id)
        validate_blind_input(records, profile)
    except (OSError, VerifierError, ValueError) as exc:
        parser.error(str(exc))

    if args.validate_only:
        corpus_proof = None
        if not args.development_run:
            try:
                corpus_proof = _load_official_corpus_proof(args.input, records)
            except VerifierError as exc:
                parser.error(str(exc))
        try:
            resolver = SnapshotResolver(args.snapshot_root)
            snapshots: set[Path] = set()
            for record in records:
                snapshot = resolver.resolve(record)
                snapshots.add(snapshot)
                EvidenceToolbox(snapshot, profile).initial_observations(record)
            result = {
                "status": "VALID",
                "records": len(records),
                "snapshots": len(snapshots),
                "profile_id": profile.profile_id,
                "evaluation_mode": (
                    "DEVELOPMENT" if args.development_run else "OFFICIAL"
                ),
                "official_corpus_verified": corpus_proof is not None,
                "input_sha256": sha256_file(args.input),
                "profile_sha256": sha256_file(args.profile),
                "prompt_sha256": sha256_file(args.prompt),
                "response_schema_sha256": sha256_file(args.response_schema),
                "controller_sha256": sha256_file(_CONTROLLER_PATH),
            }
        except (OSError, VerifierError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if not args.development_run:
        try:
            _load_official_corpus_proof(args.input, records)
        except VerifierError as exc:
            parser.error(str(exc))
    try:
        provider: Provider = GeminiApiProvider(
            response_schema=args.response_schema,
            prompt_text=args.prompt.read_text(encoding="utf-8"),
            timeout_seconds=profile.provider_timeout_seconds,
            model=args.model,
            thinking_level=args.gemini_thinking_level,
            seed=args.seed,
            temperature=args.temperature,
            max_attempts=args.gemini_max_attempts,
            min_request_interval_seconds=args.gemini_min_request_interval_seconds,
            rate_limit_retry_delay_seconds=args.gemini_rate_limit_retry_delay_seconds,
            max_rate_limit_wait_seconds=args.gemini_max_rate_limit_wait_seconds,
            max_event_bytes=profile.max_provider_event_bytes,
            max_response_bytes=profile.max_provider_response_bytes,
        )
        manifest = execute_run(
            records=records,
            input_path=args.input,
            snapshot_root=args.snapshot_root,
            run_directory=args.run_dir,
            profile=profile,
            profile_path=args.profile,
            prompt_path=args.prompt,
            provider=provider,
            evaluation_mode="DEVELOPMENT" if args.development_run else "OFFICIAL",
            force=args.force,
        )
    except (OSError, VerifierError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(manifest["case_counts"], ensure_ascii=False, indent=2))
    return 0 if manifest["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
