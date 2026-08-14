from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from jsonschema import Draft202012Validator

from .gemini_verifier_agent import GeminiApiProvider
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


OPENAI_PROVIDER_ID = "openai-responses-api-isolated-json"
OPENAI_DIALECT_VERSION = "openai-responses-rest-v1"


class _OpenAIResponseSchemaError(ProviderError):
    pass


class OpenAIResponsesProvider:
    """Stateful Responses API adapter with controller-owned source navigation."""

    provider_id = OPENAI_PROVIDER_ID
    stateful = True
    _RETRYABLE_HTTP_CODES = {408, 409, 429, 500, 502, 503, 504}

    def __init__(
        self,
        *,
        response_schema: Path,
        prompt_text: str,
        timeout_seconds: int,
        model: str,
        reasoning_effort: str = "low",
        max_attempts: int = 3,
        max_output_tokens: int = 16_384,
        max_event_bytes: int = 16_777_216,
        max_response_bytes: int = 1_048_576,
        retry_delay_seconds: float = 2.0,
        api_key: str | None = None,
        http_json: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ):
        if not isinstance(model, str) or not model.strip():
            raise ProviderError("OpenAI provider requires an exact model ID")
        normalized_model = model.strip().casefold()
        if normalized_model == "latest" or normalized_model.endswith(
            ("/latest", "-latest", ":latest")
        ):
            raise ProviderError("OpenAI provider rejects mutable latest aliases")
        if reasoning_effort.casefold() not in {
            "none",
            "low",
            "medium",
            "high",
            "xhigh",
            "max",
        }:
            raise ProviderError("OpenAI reasoning effort is invalid")
        if timeout_seconds < 1:
            raise ProviderError("OpenAI timeout must be positive")
        if not 1 <= max_attempts <= 5:
            raise ProviderError("OpenAI max attempts must be between 1 and 5")
        if not 256 <= max_output_tokens <= 131_072:
            raise ProviderError("OpenAI max output tokens are outside the allowed range")
        if retry_delay_seconds < 0:
            raise ProviderError("OpenAI retry delay cannot be negative")
        secret = api_key or os.environ.get("OPENAI_API_KEY")
        if not isinstance(secret, str) or not secret.strip():
            raise TerminalProviderError("OPENAI_API_KEY_MISSING")

        self._api_key = secret.strip()
        self._http_json_override = http_json
        self.model = model.strip()
        self.reasoning_effort = reasoning_effort.casefold()
        self.max_attempts = max_attempts
        self.max_output_tokens = max_output_tokens
        self.timeout_seconds = timeout_seconds
        self.retry_delay_seconds = float(retry_delay_seconds)
        self.max_event_bytes = max_event_bytes
        self.max_response_bytes = max_response_bytes
        self.response_schema = response_schema.resolve(strict=True)
        self.response_schema_sha256 = sha256_file(self.response_schema)
        self.prompt_text = prompt_text
        try:
            schema = json.loads(self.response_schema.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProviderError("OpenAI response schema is not valid JSON") from exc
        if not isinstance(schema, dict):
            raise ProviderError("OpenAI response schema must be an object")
        Draft202012Validator.check_schema(schema)
        self._response_validator = Draft202012Validator(schema)
        self._api_response_schema = json.loads(json.dumps(schema))
        self._api_response_schema.pop("$schema", None)
        self._api_response_schema.pop("$id", None)
        self._api_schema_removed_keywords: list[str] = []
        self._project_openai_schema_subset(self._api_response_schema)
        self.api_response_schema_sha256 = sha256_bytes(
            json.dumps(
                self._api_response_schema,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )

        self.sdk_version = OPENAI_DIALECT_VERSION
        self.adapter_path = Path(__file__).resolve(strict=True)
        self.adapter_sha256 = sha256_file(self.adapter_path)
        self.configuration = {
            "api": "openai-responses",
            "sdk_version": self.sdk_version,
            "base_url": "https://api.openai.com/v1",
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "max_output_tokens": self.max_output_tokens,
            "store": False,
            "structured_output": "responses.text.format.json_schema",
            "response_schema_sha256": self.response_schema_sha256,
            "api_response_schema_sha256": self.api_response_schema_sha256,
            "api_schema_projection": {
                "protocol": "openai-structured-output-subset-v1",
                "removed_keywords": self._api_schema_removed_keywords,
            },
            "retry_policy": {
                "max_attempts": self.max_attempts,
                "retryable_causes": ["transport", "response_schema", "response_semantics"],
            },
            "contract_normalization": "remove-forbidden-non-decision-fields-v1",
        }
        self.configuration_sha256 = sha256_bytes(
            json.dumps(
                self.configuration,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        self.version = (
            f"{self.sdk_version}+adapter.sha256.{self.adapter_sha256}"
            f".config.sha256.{self.configuration_sha256}"
        )
        self._histories: dict[str, list[dict[str, str]]] = {}
        self._session_ids: dict[str, str] = {}
        self._cumulative_usage: dict[str, dict[str, int]] = {}
        self._exposed_ranges: dict[str, dict[str, list[tuple[int, int]]]] = {}
        self._observed_model_versions: set[str] = set()
        self._observed_response_ids: set[str] = set()

    def _project_openai_schema_subset(self, node: Any, pointer: str = "") -> None:
        """Remove constraints unsupported by OpenAI while retaining local validation."""

        if isinstance(node, dict):
            if "uniqueItems" in node:
                node.pop("uniqueItems")
                self._api_schema_removed_keywords.append(f"{pointer}/uniqueItems")
            for key, value in list(node.items()):
                escaped = str(key).replace("~", "~0").replace("/", "~1")
                self._project_openai_schema_subset(value, f"{pointer}/{escaped}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                self._project_openai_schema_subset(value, f"{pointer}/{index}")

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

    @staticmethod
    def _write_json(path: Path, value: Any, max_bytes: int) -> None:
        rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        if len(rendered.encode("utf-8")) > max_bytes:
            raise ProviderError("OpenAI provider artifact exceeds its byte budget")
        _atomic_write_text(path, rendered)

    def _write_run_configuration(self, case_directory: Path) -> None:
        run_directory = (
            case_directory.parent.parent
            if case_directory.parent.name == "cases"
            else case_directory
        )
        path = run_directory / "openai-provider-configuration.json"
        expected = self._provider_identity()
        if path.is_file():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ProviderError("OpenAI run configuration is invalid") from exc
            if existing != expected:
                raise ProviderError("OpenAI run configuration identity mismatch")
            return
        self._write_json(path, expected, self.max_response_bytes)

    @staticmethod
    def _archive_stale(case_directory: Path) -> None:
        patterns = (
            "step-*-raw-response.json",
            "step-*-response.json",
            "step-*-events.jsonl",
            "step-*-provider-metadata.json",
            "step-*-schema-retry-*-raw-response.json",
            "provider-session.json",
        )
        stale = [
            path
            for pattern in patterns
            for path in sorted(case_directory.glob(pattern))
            if path.is_file()
        ]
        if not stale:
            return
        attempts = case_directory / "attempts"
        numbers = [
            int(path.name)
            for path in attempts.iterdir()
            if path.is_dir() and path.name.isdigit()
        ] if attempts.is_dir() else []
        archive = attempts / f"{max(numbers, default=0) + 1:04d}"
        archive.mkdir(parents=True, exist_ok=False)
        for path in stale:
            path.replace(archive / path.name)

    def _http_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._http_json_override is not None:
            value = self._http_json_override(payload)
            if not isinstance(value, dict):
                raise ProviderError("OpenAI test transport returned a non-object")
            return value
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = Request(
            "https://api.openai.com/v1/responses",
            data=data,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_event_bytes + 1)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise TerminalProviderError("OPENAI_AUTHENTICATION_FAILED") from None
            if exc.code == 404:
                raise TerminalProviderError("OPENAI_MODEL_OR_ENDPOINT_UNAVAILABLE") from None
            if exc.code in self._RETRYABLE_HTTP_CODES:
                raise ProviderError(f"OPENAI_RETRYABLE_HTTP_{exc.code}") from None
            raise ProviderError(f"OPENAI_HTTP_{exc.code}") from None
        except (URLError, TimeoutError, ConnectionError):
            raise ProviderError("OPENAI_CONNECTION_FAILED") from None
        if len(raw) > self.max_event_bytes:
            raise ProviderError("OpenAI response exceeds its byte budget")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError("OpenAI returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise ProviderError("OpenAI response must be an object")
        return value

    @staticmethod
    def _output_text(response: dict[str, Any]) -> str:
        texts: list[str] = []
        output = response.get("output")
        if isinstance(output, list):
            for item in output:
                if not isinstance(item, dict) or item.get("type") != "message":
                    continue
                content = item.get("content")
                if not isinstance(content, list):
                    continue
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    if part.get("type") == "refusal":
                        raise ProviderError("OPENAI_RESPONSE_REFUSED")
                    if part.get("type") == "output_text" and isinstance(part.get("text"), str):
                        texts.append(part["text"])
        if not texts:
            raise _OpenAIResponseSchemaError("response has no output_text JSON")
        return "".join(texts)

    @staticmethod
    def _normalized_usage(response: dict[str, Any]) -> tuple[dict[str, int], dict[str, Any]]:
        usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
        details_in = usage.get("input_tokens_details")
        details_out = usage.get("output_tokens_details")
        normalized: dict[str, int] = {}
        aliases = {
            "input_tokens": usage.get("input_tokens"),
            "output_tokens": usage.get("output_tokens"),
            "total_tokens": usage.get("total_tokens"),
            "cached_input_tokens": (
                details_in.get("cached_tokens") if isinstance(details_in, dict) else None
            ),
            "reasoning_tokens": (
                details_out.get("reasoning_tokens") if isinstance(details_out, dict) else None
            ),
        }
        for name, value in aliases.items():
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                normalized[name] = value
        return normalized, usage

    @staticmethod
    def _add_exposed_result(
        exposed: dict[str, list[tuple[int, int]]], result: Any
    ) -> None:
        if not isinstance(result, dict) or result.get("ok") is not True:
            return
        path = result.get("path")
        start = result.get("start_line")
        end = result.get("end_line")
        if (
            isinstance(path, str)
            and isinstance(start, int)
            and not isinstance(start, bool)
            and isinstance(end, int)
            and not isinstance(end, bool)
        ):
            exposed.setdefault(path, []).append((start, end))

    def _record_exposed_ranges(
        self, key: str, request: dict[str, Any]
    ) -> dict[str, list[tuple[int, int]]]:
        exposed = self._exposed_ranges.setdefault(key, {})
        observations = request.get("initial_observations")
        if isinstance(observations, list):
            for result in observations:
                self._add_exposed_result(exposed, result)
        exchange = request.get("latest_controller_exchange")
        if isinstance(exchange, dict) and isinstance(exchange.get("results"), list):
            for result in exchange["results"]:
                self._add_exposed_result(exposed, result)
        return exposed

    def _parse_response(
        self,
        response: dict[str, Any],
        exposed_ranges: dict[str, list[tuple[int, int]]] | None,
    ) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
        text = self._output_text(response)
        if len(text.encode("utf-8")) > self.max_response_bytes:
            raise ProviderError("OpenAI structured output exceeds its byte budget")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise _OpenAIResponseSchemaError("output_text is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise _OpenAIResponseSchemaError("structured response must be an object")
        normalizations: list[dict[str, Any]] = []
        if parsed.get("action") == "FINAL":
            verdict = parsed.get("verdict")
            reason_codes = parsed.get("reason_codes")
            if verdict != "FALSE_POSITIVE" and isinstance(reason_codes, list) and reason_codes:
                normalizations.append(
                    {
                        "operation": "CLEARED_FP_REASON_CODES_FOR_NON_FP_VERDICT",
                        "original_value_sha256": sha256_bytes(
                            json.dumps(
                                reason_codes,
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ),
                    }
                )
                parsed["reason_codes"] = []
            evidence = parsed.get("evidence")
            if verdict == "ABSTAIN" and isinstance(evidence, list) and evidence:
                normalizations.append(
                    {
                        "operation": "CLEARED_OPTIONAL_EVIDENCE_FOR_ABSTAIN",
                        "original_value_sha256": sha256_bytes(
                            json.dumps(
                                evidence,
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ),
                    }
                )
                parsed["evidence"] = []
        if next(self._response_validator.iter_errors(parsed), None) is not None:
            raise _OpenAIResponseSchemaError(
                "response does not conform to the frozen JSON schema"
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
            raise _OpenAIResponseSchemaError(
                "FINAL response has an empty required decision field"
            )
        if exposed_ranges is not None:
            defect = GeminiApiProvider._response_semantic_defect(parsed, exposed_ranges)
            if defect:
                raise _OpenAIResponseSchemaError(defect)
        return parsed, text, normalizations

    def _write_failed_attempt_audit(
        self,
        *,
        case_directory: Path,
        step: int,
        session_id: str,
        attempt_history: list[dict[str, Any]],
        error_code: str,
        cumulative_usage: dict[str, int],
    ) -> None:
        self._write_json(
            case_directory / f"step-{step:02d}-provider-metadata.json",
            {
                **self._provider_identity(),
                "configured_model": self.model,
                "status": "FAILED",
                "error_code": error_code,
                "session_id": session_id,
                "step": step,
                "attempts": len(attempt_history),
                "attempt_history": attempt_history,
                "cumulative_normalized_usage": dict(sorted(cumulative_usage.items())),
            },
            self.max_response_bytes,
        )

    def response_metadata(self, case_directory: Path, step: int) -> dict[str, Any]:
        path = case_directory / f"step-{step:02d}-provider-metadata.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderError("OpenAI provider metadata is missing or invalid") from exc
        raw = case_directory / f"step-{step:02d}-raw-response.json"
        raw_proof = value.get("raw_response")
        if (
            value.get("status") != "SUCCESS"
            or value.get("provider") != self.provider_id
            or value.get("provider_version") != self.version
            or value.get("sdk_version") != self.sdk_version
            or value.get("configuration") != self.configuration
            or value.get("configuration_sha256") != self.configuration_sha256
            or value.get("configured_model") != self.model
            or value.get("step") != step
            or not isinstance(value.get("model_version"), str)
            or not value["model_version"]
            or not isinstance(value.get("response_id"), str)
            or not value["response_id"]
            or not isinstance(raw_proof, dict)
            or raw_proof.get("path") != raw.name
            or not raw.is_file()
            or raw_proof.get("bytes") != raw.stat().st_size
            or raw_proof.get("sha256") != sha256_file(raw)
        ):
            raise ProviderError("OpenAI provider metadata identity is invalid")
        return value

    def close_case(self, case_directory: Path) -> None:
        key = str(case_directory.resolve())
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
        key = str(case_directory.resolve())
        history = self._histories.setdefault(key, [])
        expected_step = len(history) // 2 + 1
        if step != expected_step:
            raise ProviderError(
                f"OpenAI controller step is out of sequence: expected {expected_step}, got {step}"
            )
        if step == 1:
            self._archive_stale(case_directory)
        self._write_run_configuration(case_directory)
        enforce_semantics = request.get("task") in {
            "blind_security_finding_verification",
            "blind_security_finding_verification_continuation",
        }
        exposed = self._record_exposed_ranges(key, request) if enforce_semantics else None
        session_id = self._session_ids.setdefault(key, f"openai-{uuid.uuid4().hex}")
        cumulative = self._cumulative_usage.setdefault(key, {})
        request_text = (
            "<controller_request>\n"
            + json.dumps(request, ensure_ascii=False, indent=2)
            + "\n</controller_request>\n"
        )
        base_input = [
            {"role": "developer", "content": self.prompt_text},
            *history,
            {"role": "user", "content": request_text},
        ]
        accepted: dict[str, Any] | None = None
        accepted_text = ""
        accepted_normalizations: list[dict[str, Any]] = []
        raw_response: dict[str, Any] | None = None
        attempt_history: list[dict[str, Any]] = []
        feedback = ""
        prior_invalid = ""
        used_attempt = 0
        for attempt in range(1, self.max_attempts + 1):
            used_attempt = attempt
            input_messages = list(base_input)
            if attempt > 1:
                if prior_invalid:
                    input_messages.append({"role": "assistant", "content": prior_invalid})
                input_messages.append(
                    {
                        "role": "user",
                        "content": (
                            "The prior JSON was rejected by deterministic validation: "
                            f"{feedback}. Correct only that defect using the supplied "
                            "context. Return one schema-conforming JSON object and no prose."
                        ),
                    }
                )
            payload = {
                "model": self.model,
                "input": input_messages,
                "reasoning": {"effort": self.reasoning_effort},
                "max_output_tokens": self.max_output_tokens,
                "store": False,
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "vulngym_structured_response",
                        "strict": True,
                        "schema": self._api_response_schema,
                    }
                },
            }
            try:
                candidate = self._http_json(payload)
            except ProviderError as exc:
                retryable = str(exc).startswith("OPENAI_RETRYABLE_") or str(exc) == "OPENAI_CONNECTION_FAILED"
                attempt_history.append(
                    {
                        "attempt": attempt,
                        "outcome": "RETRY" if retryable and attempt < self.max_attempts else "FAILED",
                        "cause": "TRANSPORT",
                        "error_code": str(exc),
                        "raw_response": None,
                    }
                )
                if retryable and attempt < self.max_attempts:
                    time.sleep(self.retry_delay_seconds * attempt)
                    continue
                self._write_failed_attempt_audit(
                    case_directory=case_directory,
                    step=step,
                    session_id=session_id,
                    attempt_history=attempt_history,
                    error_code=str(exc),
                    cumulative_usage=cumulative,
                )
                raise
            try:
                parsed, response_text, normalizations = self._parse_response(candidate, exposed)
            except _OpenAIResponseSchemaError as exc:
                feedback = str(exc)
                try:
                    prior_invalid = self._output_text(candidate)
                except ProviderError:
                    prior_invalid = ""
                normalized_retry, raw_retry_usage = self._normalized_usage(candidate)
                for name, value in normalized_retry.items():
                    cumulative[name] = cumulative.get(name, 0) + value
                retry_path = case_directory / f"step-{step:02d}-schema-retry-{attempt:02d}-raw-response.json"
                self._write_json(retry_path, candidate, self.max_event_bytes)
                semantic = (
                    feedback.startswith("evidence citation ")
                    or feedback.endswith("requires source evidence")
                    or " requires source evidence; " in feedback
                    or "reason_codes" in feedback
                )
                attempt_history.append(
                    {
                        "attempt": attempt,
                        "outcome": "RETRY" if attempt < self.max_attempts else "FAILED",
                        "cause": "RESPONSE_SEMANTICS" if semantic else "RESPONSE_SCHEMA",
                        "validation_feedback": feedback,
                        "usage": raw_retry_usage,
                        "normalized_usage": normalized_retry,
                        "raw_response": {
                            "path": retry_path.name,
                            "sha256": sha256_file(retry_path),
                            "bytes": retry_path.stat().st_size,
                        },
                    }
                )
                if attempt < self.max_attempts:
                    time.sleep(self.retry_delay_seconds * attempt)
                    continue
                self._write_failed_attempt_audit(
                    case_directory=case_directory,
                    step=step,
                    session_id=session_id,
                    attempt_history=attempt_history,
                    error_code="OPENAI_RESPONSE_SCHEMA_INVALID",
                    cumulative_usage=cumulative,
                )
                raise ProviderError("OPENAI_RESPONSE_SCHEMA_INVALID") from None
            accepted = parsed
            accepted_text = response_text
            accepted_normalizations = normalizations
            raw_response = candidate
            attempt_history.append(
                {"attempt": attempt, "outcome": "ACCEPTED", "cause": None, "raw_response": None}
            )
            break
        if accepted is None or raw_response is None:
            raise ProviderError("OpenAI provider exhausted its retry budget")

        response_id = raw_response.get("id")
        model_version = raw_response.get("model")
        if not isinstance(response_id, str) or not response_id:
            raise ProviderError("OPENAI_RESPONSE_ID_MISSING")
        if not isinstance(model_version, str) or not model_version:
            raise ProviderError("OPENAI_MODEL_VERSION_MISSING")
        if self._observed_model_versions and model_version not in self._observed_model_versions:
            raise ProviderError("OPENAI_MODEL_VERSION_CHANGED_DURING_RUN")
        if response_id in self._observed_response_ids:
            raise ProviderError("OPENAI_RESPONSE_ID_REUSED_DURING_RUN")
        self._observed_model_versions.add(model_version)
        self._observed_response_ids.add(response_id)
        normalized_usage, raw_usage = self._normalized_usage(raw_response)
        for name, value in normalized_usage.items():
            cumulative[name] = cumulative.get(name, 0) + value

        raw_path = case_directory / f"step-{step:02d}-raw-response.json"
        response_path = case_directory / f"step-{step:02d}-response.json"
        metadata_path = case_directory / f"step-{step:02d}-provider-metadata.json"
        events_path = case_directory / f"step-{step:02d}-events.jsonl"
        self._write_json(raw_path, raw_response, self.max_event_bytes)
        self._write_json(response_path, accepted, self.max_response_bytes)
        metadata = {
            **self._provider_identity(),
            "configured_model": self.model,
            "status": "SUCCESS",
            "model_version": model_version,
            "response_id": response_id,
            "session_id": session_id,
            "step": step,
            "attempts": used_attempt,
            "attempt_history": attempt_history,
            "contract_normalizations": accepted_normalizations,
            "usage": raw_usage,
            "normalized_usage": normalized_usage,
            "raw_response": {
                "path": raw_path.name,
                "sha256": sha256_file(raw_path),
                "bytes": raw_path.stat().st_size,
            },
        }
        self._write_json(metadata_path, metadata, self.max_response_bytes)
        events = (
            {"type": "thread.started", "thread_id": session_id},
            {"type": "turn.started"},
            {
                "type": "item.completed",
                "item": {
                    "id": response_id,
                    "type": "agent_message",
                    "text": json.dumps(accepted, ensure_ascii=False, separators=(",", ":")),
                },
            },
            {"type": "turn.completed", "usage": dict(cumulative)},
        )
        rendered = "".join(
            json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
            for row in events
        )
        if len(rendered.encode("utf-8")) > self.max_event_bytes:
            raise ProviderError("OpenAI event log exceeds its byte budget")
        _atomic_write_text(events_path, rendered)
        audit = audit_provider_events(events_path, max_bytes=self.max_event_bytes)
        if json.loads(str(audit["final_agent_message"])) != accepted:
            raise ProviderError("OpenAI structured response differs from audit event")
        history.extend(
            [
                {"role": "user", "content": request_text},
                {"role": "assistant", "content": accepted_text},
            ]
        )
        self._write_json(
            case_directory / "provider-session.json",
            {**self._provider_identity(), "session_id": session_id, "completed_steps": step},
            self.max_response_bytes,
        )
        return accepted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the frozen blind source-review controller through OpenAI Responses API."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, default=Path("worktrees"))
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--profile", type=Path, default=Path("config/verifier-profile-v1.json"))
    parser.add_argument("--prompt", type=Path, default=Path("config/verifier-prompt-local-v1.md"))
    parser.add_argument(
        "--response-schema",
        type=Path,
        default=Path("schemas/verifier-agent-response.schema.json"),
    )
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--reasoning-effort",
        choices=("none", "low", "medium", "high", "xhigh", "max"),
        default="low",
    )
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--max-output-tokens", type=int, default=16_384)
    parser.add_argument("--development-run", action="store_true")
    parser.add_argument("--finding-id", action="append")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        profile = AgentProfile.load(args.profile)
        records = _select_records(load_jsonl(args.input, profile), args.finding_id)
        validate_blind_input(records, profile)
    except (OSError, VerifierError, ValueError) as exc:
        parser.error(str(exc))
    if args.finding_id and not args.development_run:
        parser.error("--finding-id is forbidden for official verifier runs")
    if args.force and not args.development_run:
        parser.error("--force is forbidden for official verifier runs")
    if args.validate_only:
        try:
            resolver = SnapshotResolver(args.snapshot_root)
            for record in records:
                EvidenceToolbox(resolver.resolve(record), profile).initial_observations(record)
        except (OSError, VerifierError, ValueError) as exc:
            parser.error(str(exc))
        print(json.dumps({"status": "VALID", "records": len(records)}, indent=2))
        return 0
    if not args.development_run:
        try:
            _load_official_corpus_proof(args.input, records)
        except VerifierError as exc:
            parser.error(str(exc))
    try:
        provider: Provider = OpenAIResponsesProvider(
            response_schema=args.response_schema,
            prompt_text=args.prompt.read_text(encoding="utf-8"),
            timeout_seconds=profile.provider_timeout_seconds,
            model=args.model,
            reasoning_effort=args.reasoning_effort,
            max_attempts=args.max_attempts,
            max_output_tokens=args.max_output_tokens,
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
