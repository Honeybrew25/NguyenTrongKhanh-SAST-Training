from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from vulngym_enrich.local_verifier_agent import LocalOpenAICompatibleProvider
from vulngym_enrich.verifier_agent import ProviderError, TerminalProviderError


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "verifier-agent-response.schema.json"


def _tool_response() -> dict[str, object]:
    return {
        "action": "REQUEST_TOOLS",
        "working_hypothesis": "Need one source range.",
        "tool_requests": [
            {
                "tool": "read_file",
                "path": "src/example.py",
                "query": None,
                "start_line": 1,
                "end_line": 10,
                "case_sensitive": None,
            }
        ],
        "verdict": None,
        "confidence": None,
        "reason_codes": [],
        "attacker_capability": None,
        "entry_point": None,
        "security_effect": None,
        "controls": None,
        "reasoning": None,
        "evidence": [],
        "abstain_reason": None,
    }


class _Handler(BaseHTTPRequestHandler):
    served_model = "local-test-model"
    requests: list[dict[str, object]] = []
    reasoning_only = False

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, value: dict[str, object]) -> None:
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        assert self.path == "/v1/models"
        self._send({"object": "list", "data": [{"id": self.served_model}]})

    def do_POST(self) -> None:
        assert self.path == "/v1/chat/completions"
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length))
        self.requests.append(payload)
        message = {"role": "assistant", "content": json.dumps(_tool_response())}
        if self.reasoning_only:
            message = {
                "role": "assistant",
                "content": "",
                "reasoning_content": json.dumps(_tool_response()),
            }
        self._send(
            {
                "id": "chatcmpl-local-1",
                "model": self.served_model,
                "choices": [
                    {"message": message}
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
            }
        )


@pytest.fixture
def local_server():
    _Handler.requests = []
    _Handler.reasoning_only = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1"
    finally:
        server.shutdown()
        thread.join()


def test_local_provider_structured_round_trip(tmp_path: Path, local_server: str) -> None:
    provider = LocalOpenAICompatibleProvider(
        response_schema=SCHEMA,
        prompt_text="system prompt",
        timeout_seconds=5,
        base_url=local_server,
        model="local-test-model",
        model_revision="a" * 64,
        seed=7,
        temperature=0,
        retry_delay_seconds=0,
    )
    case = tmp_path / "run" / "cases" / "case-1"
    result = provider.complete({"finding": "blind"}, case_directory=case, step=1)

    assert result["action"] == "REQUEST_TOOLS"
    metadata = provider.response_metadata(case, 1)
    assert metadata["model_version"] == f"sha256:{'a' * 64}"
    assert metadata["normalized_usage"] == {
        "input_tokens": 10,
        "output_tokens": 20,
        "total_tokens": 30,
    }
    assert _Handler.requests[0]["response_format"]["type"] == "json_schema"
    assert (tmp_path / "run" / "local-provider-configuration.json").is_file()


def test_local_server_schema_removes_only_large_string_repetition_bounds(
    tmp_path: Path, local_server: str
) -> None:
    provider = LocalOpenAICompatibleProvider(
        response_schema=SCHEMA,
        prompt_text="system prompt",
        timeout_seconds=5,
        base_url=local_server,
        model="local-test-model",
        model_revision="d" * 64,
        retry_delay_seconds=0,
    )
    provider.complete(
        {"finding": "blind"},
        case_directory=tmp_path / "run" / "cases" / "case-1",
        step=1,
    )
    api_schema = _Handler.requests[0]["response_format"]["json_schema"]["schema"]
    serialized = json.dumps(api_schema)
    assert "maxLength" not in serialized
    assert '"maxItems": 12' in serialized


def test_local_provider_accepts_json_in_reasoning_content(
    tmp_path: Path, local_server: str
) -> None:
    _Handler.reasoning_only = True
    provider = LocalOpenAICompatibleProvider(
        response_schema=SCHEMA,
        prompt_text="system prompt",
        timeout_seconds=5,
        base_url=local_server,
        model="local-test-model",
        model_revision="e" * 64,
        retry_delay_seconds=0,
    )
    result = provider.complete(
        {"finding": "blind"},
        case_directory=tmp_path / "run" / "cases" / "case-1",
        step=1,
    )
    assert result["action"] == "REQUEST_TOOLS"


def test_local_provider_rejects_non_loopback() -> None:
    with pytest.raises(ProviderError, match="loopback"):
        LocalOpenAICompatibleProvider(
            response_schema=SCHEMA,
            prompt_text="prompt",
            timeout_seconds=5,
            base_url="https://example.com/v1",
            model="model",
            model_revision="b" * 64,
        )


def test_local_provider_requires_exact_served_model(local_server: str) -> None:
    with pytest.raises(TerminalProviderError, match="LOCAL_PROVIDER_MODEL_NOT_SERVED"):
        LocalOpenAICompatibleProvider(
            response_schema=SCHEMA,
            prompt_text="prompt",
            timeout_seconds=5,
            base_url=local_server,
            model="different-model",
            model_revision="c" * 64,
        )
