from __future__ import annotations

import argparse
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from jsonschema import Draft202012Validator

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


LOCAL_PROVIDER_ID = "local-openai-compatible-isolated-json"
LOCAL_DIALECT_VERSION = "openai-chat-completions-json-schema-v1"
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}", re.IGNORECASE)


class _LocalResponseSchemaError(ProviderError):
    pass


class LocalOpenAICompatibleProvider:
    """Loopback-only OpenAI-compatible provider for controller-owned source review."""

    provider_id = LOCAL_PROVIDER_ID
    stateful = True
    _RETRYABLE_HTTP_CODES = {408, 409, 429, 500, 502, 503, 504}

    def __init__(
        self,
        *,
        response_schema: Path,
        prompt_text: str,
        timeout_seconds: int,
        base_url: str,
        model: str,
        model_revision: str,
        seed: int = 0,
        temperature: float = 0.0,
        max_attempts: int = 3,
        max_tokens: int = 8192,
        max_event_bytes: int = 16_777_216,
        max_response_bytes: int = 1_048_576,
        retry_delay_seconds: float = 1.0,
    ):
        parsed = urlparse(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ProviderError(
                "local provider base URL must be an unauthenticated loopback HTTP URL"
            )
        if not isinstance(model, str) or not model.strip():
            raise ProviderError("local provider requires an exact served model ID")
        normalized_model = model.strip().casefold()
        if normalized_model == "latest" or normalized_model.endswith(
            ("/latest", "-latest", ":latest")
        ):
            raise ProviderError("local provider rejects mutable latest model aliases")
        revision = model_revision.strip().lower()
        if revision.startswith("sha256:"):
            revision = revision[7:]
        if not _HEX_SHA256.fullmatch(revision):
            raise ProviderError(
                "local model revision must be the 64-character SHA-256 of the exact model artifact"
            )
        if timeout_seconds < 1:
            raise ProviderError("local provider timeout must be positive")
        if not isinstance(seed, int) or isinstance(seed, bool):
            raise ProviderError("local provider seed must be an integer")
        if not 0 <= float(temperature) <= 2:
            raise ProviderError("local provider temperature must be between 0 and 2")
        if not 1 <= max_attempts <= 5:
            raise ProviderError("local provider max attempts must be between 1 and 5")
        if not 256 <= max_tokens <= 131072:
            raise ProviderError("local provider max tokens is outside the allowed range")

        self.base_url = base_url.rstrip("/")
        self.model = model.strip()
        self.model_revision = revision
        self.seed = seed
        self.temperature = float(temperature)
        self.max_attempts = max_attempts
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds
        self.retry_delay_seconds = retry_delay_seconds
        self.max_event_bytes = max_event_bytes
        self.max_response_bytes = max_response_bytes
        self.response_schema = response_schema.resolve(strict=True)
        self.response_schema_sha256 = sha256_file(self.response_schema)
        self.prompt_text = prompt_text
        try:
            schema = json.loads(self.response_schema.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProviderError("local response schema is not valid JSON") from exc
        if not isinstance(schema, dict):
            raise ProviderError("local response schema must be a JSON object")
        Draft202012Validator.check_schema(schema)
        self._response_validator = Draft202012Validator(schema)
        self._api_response_schema = self._grammar_safe_schema(schema)
        self._api_response_schema.pop("$schema", None)
        self._api_response_schema.pop("$id", None)

        self.sdk_version = LOCAL_DIALECT_VERSION
        self.adapter_path = Path(__file__).resolve(strict=True)
        self.adapter_sha256 = sha256_file(self.adapter_path)
        self.configuration = {
            "api": "loopback-openai-compatible",
            "sdk_version": self.sdk_version,
            "base_url": self.base_url,
            "model": self.model,
            "model_revision_sha256": self.model_revision,
            "seed": self.seed,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "structured_output": "chat_completions.response_format.json_schema",
            "response_schema_sha256": self.response_schema_sha256,
            "retry_policy": {
                "max_attempts": self.max_attempts,
                "retryable_causes": ["transport", "response_schema"],
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
        self.version = (
            f"{self.sdk_version}+adapter.sha256.{self.adapter_sha256}"
            f".config.sha256.{self.configuration_sha256}"
        )
        self._histories: dict[str, list[dict[str, str]]] = {}
        self._session_ids: dict[str, str] = {}
        self._cumulative_usage: dict[str, dict[str, int]] = {}
        self._observed_response_ids: set[str] = set()
        self._verify_served_model()

    @classmethod
    def _grammar_safe_schema(cls, value: Any) -> Any:
        """Remove large repetition bounds unsupported by llama.cpp grammars.

        The complete frozen schema remains active in ``_response_validator``.
        This projection changes only constrained decoding at the local server;
        byte budgets and all original length limits are still enforced locally.
        """

        if isinstance(value, dict):
            return {
                str(key): cls._grammar_safe_schema(item)
                for key, item in value.items()
                if key not in {"maxLength"}
            }
        if isinstance(value, list):
            return [cls._grammar_safe_schema(item) for item in value]
        return value

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

    def _http_json(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None
        method = "GET"
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            method = "POST"
            headers["Content-Type"] = "application/json"
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_event_bytes + 1)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise TerminalProviderError("LOCAL_PROVIDER_AUTHENTICATION_REQUIRED") from None
            if exc.code == 404:
                raise TerminalProviderError(
                    "LOCAL_PROVIDER_ENDPOINT_OR_MODEL_UNAVAILABLE"
                ) from None
            if exc.code in self._RETRYABLE_HTTP_CODES:
                raise ProviderError(f"LOCAL_PROVIDER_RETRYABLE_HTTP_{exc.code}") from None
            raise ProviderError(f"LOCAL_PROVIDER_HTTP_{exc.code}") from None
        except (URLError, TimeoutError, ConnectionError):
            raise ProviderError("LOCAL_PROVIDER_CONNECTION_FAILED") from None
        if len(raw) > self.max_event_bytes:
            raise ProviderError("local provider response exceeds its byte budget")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError("local provider returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise ProviderError("local provider response must be a JSON object")
        return value

    def _verify_served_model(self) -> None:
        result = self._http_json("/models")
        rows = result.get("data")
        ids = {
            row.get("id")
            for row in rows
            if isinstance(rows, list) and isinstance(row, dict) and isinstance(row.get("id"), str)
        } if isinstance(rows, list) else set()
        if self.model not in ids:
            raise TerminalProviderError("LOCAL_PROVIDER_MODEL_NOT_SERVED")

    @staticmethod
    def _write_json(path: Path, value: Any, max_bytes: int) -> None:
        rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        if len(rendered.encode("utf-8")) > max_bytes:
            raise ProviderError("local provider artifact exceeds its byte budget")
        _atomic_write_text(path, rendered)

    def _write_run_configuration(self, case_directory: Path) -> None:
        run_directory = case_directory.parent.parent
        path = run_directory / "local-provider-configuration.json"
        expected = self._provider_identity()
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ProviderError("local provider configuration is invalid") from exc
            if existing != expected:
                raise ProviderError("local provider configuration identity mismatch")
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

    def response_metadata(self, case_directory: Path, step: int) -> dict[str, Any]:
        path = case_directory / f"step-{step:02d}-provider-metadata.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderError("local provider metadata is missing or invalid") from exc
        if (
            value.get("status") != "SUCCESS"
            or value.get("provider") != self.provider_id
            or value.get("provider_version") != self.version
            or value.get("configuration_sha256") != self.configuration_sha256
            or value.get("configured_model") != self.model
            or value.get("model_version") != f"sha256:{self.model_revision}"
            or value.get("step") != step
        ):
            raise ProviderError("local provider metadata identity is invalid")
        return value

    def close_case(self, case_directory: Path) -> None:
        key = str(case_directory.resolve())
        self._histories.pop(key, None)
        self._session_ids.pop(key, None)
        self._cumulative_usage.pop(key, None)

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
                f"local controller step is out of sequence: expected {expected_step}, got {step}"
            )
        if step == 1:
            self._archive_stale(case_directory)
        self._write_run_configuration(case_directory)
        session_id = self._session_ids.setdefault(key, f"local-{uuid.uuid4().hex}")
        request_text = (
            "<controller_request>\n"
            + json.dumps(request, ensure_ascii=False, indent=2)
            + "\n</controller_request>\n"
        )
        base_messages = [
            {"role": "system", "content": self.prompt_text},
            *history,
            {"role": "user", "content": request_text},
        ]
        accepted: dict[str, Any] | None = None
        raw_response: dict[str, Any] | None = None
        response_text = ""
        attempt_history: list[dict[str, Any]] = []
        prior_invalid_content: str | None = None
        prior_validation_feedback = ""
        used_attempt = 0
        for attempt in range(1, self.max_attempts + 1):
            used_attempt = attempt
            messages = list(base_messages)
            if attempt > 1:
                if prior_invalid_content:
                    messages.append(
                        {"role": "assistant", "content": prior_invalid_content}
                    )
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "The prior JSON was rejected by deterministic validation: "
                            f"{prior_validation_feedback} Correct those defects while "
                            "preserving the source-backed verdict. Return exactly one "
                            "complete JSON object and no prose."
                        ),
                    }
                )
            payload = {
                "model": self.model,
                "messages": messages,
                "temperature": self.temperature,
                "seed": self.seed,
                "max_tokens": self.max_tokens,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "verifier_agent_response",
                        "strict": True,
                        "schema": self._api_response_schema,
                    },
                },
            }
            try:
                candidate = self._http_json("/chat/completions", payload)
            except ProviderError as exc:
                retryable = str(exc).startswith(
                    "LOCAL_PROVIDER_RETRYABLE_"
                ) or str(exc) == "LOCAL_PROVIDER_CONNECTION_FAILED"
                attempt_history.append(
                    {
                        "attempt": attempt,
                        "outcome": (
                            "RETRY"
                            if retryable and attempt < self.max_attempts
                            else "FAILED"
                        ),
                        "cause": "TRANSPORT",
                        "error_code": str(exc),
                    }
                )
                if retryable and attempt < self.max_attempts:
                    time.sleep(self.retry_delay_seconds * attempt)
                    continue
                raise
            choices = candidate.get("choices")
            message = (
                choices[0].get("message", {})
                if isinstance(choices, list) and choices and isinstance(choices[0], dict)
                else {}
            )
            content = message.get("content") if isinstance(message, dict) else None
            if not isinstance(content, str) or not content.strip():
                reasoning_content = (
                    message.get("reasoning_content")
                    if isinstance(message, dict)
                    else None
                )
                if isinstance(reasoning_content, str) and reasoning_content.strip():
                    content = reasoning_content
            validation_errors: list[str] = []
            if not isinstance(content, str) or not content.strip():
                validation_errors.append("response has no assistant JSON content")
                parsed = None
            else:
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    parsed = None
                    validation_errors.append("assistant content is not valid JSON")
                schema_error = (
                    next(self._response_validator.iter_errors(parsed), None)
                    if isinstance(parsed, dict)
                    else None
                )
                if schema_error is not None:
                    validation_errors.append(
                        "response does not conform to the frozen JSON schema"
                    )
                if isinstance(parsed, dict) and parsed.get("action") == "FINAL":
                    verdict = parsed.get("verdict")
                    confidence = parsed.get("confidence")
                    reason_codes = parsed.get("reason_codes")
                    abstain_reason = parsed.get("abstain_reason")
                    if verdict not in {"TRUE_POSITIVE", "FALSE_POSITIVE", "ABSTAIN"}:
                        validation_errors.append("FINAL requires a valid verdict")
                    if confidence not in {"HIGH", "MEDIUM", "LOW"}:
                        validation_errors.append(
                            "FINAL requires confidence HIGH, MEDIUM, or LOW"
                        )
                    if verdict == "FALSE_POSITIVE" and not reason_codes:
                        validation_errors.append(
                            "FALSE_POSITIVE requires at least one reason_code"
                        )
                    if verdict != "FALSE_POSITIVE" and reason_codes:
                        validation_errors.append(
                            "only FALSE_POSITIVE may contain reason_codes"
                        )
                    if verdict == "ABSTAIN" and abstain_reason is None:
                        validation_errors.append(
                            "ABSTAIN requires a valid abstain_reason"
                        )
                    if verdict != "ABSTAIN" and abstain_reason is not None:
                        validation_errors.append(
                            "non-ABSTAIN verdict requires abstain_reason=null"
                        )
                    empty_fields = [
                        field
                        for field in (
                            "attacker_capability",
                            "entry_point",
                            "security_effect",
                            "controls",
                            "reasoning",
                        )
                        if (
                        not isinstance(parsed.get(field), str) or not parsed[field].strip()
                        )
                    ]
                    if empty_fields:
                        validation_errors.append(
                            "FINAL requires non-empty strings for: "
                            + ", ".join(empty_fields)
                        )
                    oversized_ranges = []
                    for evidence in parsed.get("evidence", []):
                        if not isinstance(evidence, dict):
                            continue
                        start = evidence.get("start_line")
                        end = evidence.get("end_line")
                        if isinstance(start, int) and isinstance(end, int) and (
                            end < start or end - start > 24
                        ):
                            oversized_ranges.append(f"{start}-{end}")
                    if oversized_ranges:
                        validation_errors.append(
                            "each evidence range must be ordered and at most 25 lines; "
                            "split or narrow: " + ", ".join(oversized_ranges)
                        )
            if validation_errors:
                prior_invalid_content = content if isinstance(content, str) else None
                prior_validation_feedback = "; ".join(validation_errors)
                retry_path = (
                    case_directory
                    / f"step-{step:02d}-schema-retry-{attempt:02d}-raw-response.json"
                )
                self._write_json(retry_path, candidate, self.max_event_bytes)
                attempt_history.append(
                    {
                        "attempt": attempt,
                        "outcome": "RETRY" if attempt < self.max_attempts else "FAILED",
                        "cause": "RESPONSE_SCHEMA",
                        "error_code": prior_validation_feedback,
                    }
                )
                if attempt < self.max_attempts:
                    time.sleep(self.retry_delay_seconds * attempt)
                    continue
                raise ProviderError("LOCAL_RESPONSE_SCHEMA_INVALID")
            accepted = parsed
            raw_response = candidate
            response_text = content
            attempt_history.append(
                {"attempt": attempt, "outcome": "ACCEPTED", "cause": None, "error_code": None}
            )
            break
        if accepted is None or raw_response is None:
            raise ProviderError("local provider exhausted its retry budget")

        raw_path = case_directory / f"step-{step:02d}-raw-response.json"
        response_path = case_directory / f"step-{step:02d}-response.json"
        metadata_path = case_directory / f"step-{step:02d}-provider-metadata.json"
        events_path = case_directory / f"step-{step:02d}-events.jsonl"
        self._write_json(raw_path, raw_response, self.max_event_bytes)
        self._write_json(response_path, accepted, self.max_response_bytes)
        usage = raw_response.get("usage") if isinstance(raw_response.get("usage"), dict) else {}
        aliases = {
            "input_tokens": "prompt_tokens",
            "output_tokens": "completion_tokens",
            "total_tokens": "total_tokens",
        }
        normalized_usage = {
            target: usage[source]
            for target, source in aliases.items()
            if isinstance(usage.get(source), int) and usage[source] >= 0
        }
        cumulative = self._cumulative_usage.setdefault(key, {})
        for name, value in normalized_usage.items():
            cumulative[name] = cumulative.get(name, 0) + value
        server_id = raw_response.get("id")
        response_id = (
            server_id
            if isinstance(server_id, str) and server_id
            else f"local-{uuid.uuid4().hex}"
        )
        if response_id in self._observed_response_ids:
            raise ProviderError("LOCAL_RESPONSE_ID_REUSED_DURING_RUN")
        self._observed_response_ids.add(response_id)
        metadata = {
            **self._provider_identity(),
            "configured_model": self.model,
            "status": "SUCCESS",
            "model_version": f"sha256:{self.model_revision}",
            "server_reported_model": raw_response.get("model"),
            "response_id": response_id,
            "session_id": session_id,
            "step": step,
            "attempts": used_attempt,
            "attempt_history": attempt_history,
            "usage": usage,
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
                    "text": json.dumps(
                        accepted, ensure_ascii=False, separators=(",", ":")
                    ),
                },
            },
            {"type": "turn.completed", "usage": dict(cumulative)},
        )
        rendered = "".join(
            json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
            for row in events
        )
        if len(rendered.encode("utf-8")) > self.max_event_bytes:
            raise ProviderError("local event log exceeds its byte budget")
        _atomic_write_text(events_path, rendered)
        audit = audit_provider_events(events_path, max_bytes=self.max_event_bytes)
        if json.loads(str(audit["final_agent_message"])) != accepted:
            raise ProviderError("local structured response differs from audit event")
        history.extend(
            [
                {"role": "user", "content": request_text},
                {"role": "assistant", "content": response_text},
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
        description=(
            "Run the frozen blind source-review controller through a loopback "
            "OpenAI-compatible server."
        )
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, default=Path("worktrees"))
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--profile", type=Path, default=Path("config/verifier-profile-v1.json"))
    parser.add_argument("--prompt", type=Path, default=Path("config/verifier-prompt-v3.md"))
    parser.add_argument(
        "--response-schema",
        type=Path,
        default=Path("schemas/verifier-agent-response.schema.json"),
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-revision-sha256", required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--max-tokens", type=int, default=8192)
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
        provider: Provider = LocalOpenAICompatibleProvider(
            response_schema=args.response_schema,
            prompt_text=args.prompt.read_text(encoding="utf-8"),
            timeout_seconds=profile.provider_timeout_seconds,
            base_url=args.base_url,
            model=args.model,
            model_revision=args.model_revision_sha256,
            seed=args.seed,
            temperature=args.temperature,
            max_attempts=args.max_attempts,
            max_tokens=args.max_tokens,
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
