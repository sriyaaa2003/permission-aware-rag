"""The real provider clients, exercised against a local HTTP server that speaks the OpenAI and
Anthropic wire formats. This verifies request shape, response parsing, auth headers and error
classification. It does not prove anything about a live provider's behaviour."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from permrag.llm import AnthropicProvider, LLMError, OpenAICompatProvider, build_provider


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        self.server.requests.append(
            {"path": self.path, "headers": dict(self.headers), "body": body}
        )
        status, payload = self.server.responses.pop(0)
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    srv.requests, srv.responses = [], []
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv, f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_openai_compat_request_and_response(server):
    srv, url = server
    srv.responses.append(
        (
            200,
            {
                "choices": [{"message": {"content": "hi [1]"}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 3},
            },
        )
    )
    out = OpenAICompatProvider("m-1", "sk-test", base_url=url, timeout=5).generate(
        "sys", "user q", max_tokens=50, temperature=0.0
    )
    assert (out.text, out.input_tokens, out.output_tokens) == ("hi [1]", 12, 3)
    req = srv.requests[0]
    assert req["path"] == "/chat/completions"
    assert req["headers"]["authorization"] == "Bearer sk-test"
    assert req["body"]["model"] == "m-1" and req["body"]["max_tokens"] == 50
    assert [m["role"] for m in req["body"]["messages"]] == ["system", "user"]


def test_openai_compat_without_key_sends_no_auth_header(server):
    srv, url = server
    srv.responses.append((200, {"choices": [{"message": {"content": "x"}}]}))
    OpenAICompatProvider("m", None, base_url=url, timeout=5).generate(
        "s", "u", max_tokens=5, temperature=0.0
    )
    assert "authorization" not in {k.lower() for k in srv.requests[0]["headers"]}


def test_anthropic_request_and_response(server):
    srv, url = server
    srv.responses.append(
        (
            200,
            {
                "content": [{"type": "text", "text": "answer [1]"}],
                "usage": {"input_tokens": 20, "output_tokens": 4},
            },
        )
    )
    out = AnthropicProvider("claude-x", "key-1", base_url=url, timeout=5).generate(
        "sys prompt", "question", max_tokens=100, temperature=0.0
    )
    assert (out.text, out.input_tokens, out.output_tokens) == ("answer [1]", 20, 4)
    req = srv.requests[0]
    assert req["path"] == "/v1/messages"
    h = {k.lower(): v for k, v in req["headers"].items()}
    assert h["x-api-key"] == "key-1" and h["anthropic-version"]
    assert req["body"]["system"] == "sys prompt"
    assert req["body"]["messages"] == [{"role": "user", "content": "question"}]


@pytest.mark.parametrize(
    ("status", "retryable"), [(429, True), (500, True), (503, True), (400, False), (401, False)]
)
def test_error_classification(server, status, retryable):
    srv, url = server
    srv.responses.append((status, {"error": "nope"}))
    with pytest.raises(LLMError) as exc:
        OpenAICompatProvider("m", "k", base_url=url, timeout=5).generate(
            "s", "u", max_tokens=5, temperature=0.0
        )
    assert exc.value.retryable is retryable


def test_malformed_success_body_is_not_retryable(server):
    srv, url = server
    srv.responses.append((200, {"unexpected": True}))
    with pytest.raises(LLMError) as exc:
        OpenAICompatProvider("m", "k", base_url=url, timeout=5).generate(
            "s", "u", max_tokens=5, temperature=0.0
        )
    assert exc.value.retryable is False


def test_connection_failure_is_retryable():
    with pytest.raises(LLMError) as exc:
        OpenAICompatProvider("m", "k", base_url="http://127.0.0.1:1", timeout=1).generate(
            "s", "u", max_tokens=5, temperature=0.0
        )
    assert exc.value.retryable is True


def test_build_provider_reads_key_from_named_env_variable(monkeypatch):
    monkeypatch.delenv("MY_KEY_VAR", raising=False)
    with pytest.raises(LLMError, match="MY_KEY_VAR"):
        build_provider("anthropic", "m", base_url=None, api_key_env="MY_KEY_VAR", timeout=5)
    monkeypatch.setenv("MY_KEY_VAR", "secret")
    assert build_provider("anthropic", "m", base_url=None, api_key_env="MY_KEY_VAR", timeout=5)
    with pytest.raises(LLMError):
        build_provider("nope", "m", base_url=None, api_key_env=None, timeout=5)
