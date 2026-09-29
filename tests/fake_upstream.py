"""In-process OpenAI-shaped fake provider for tests and smoke (loopback only).

Records every request (method, path, full Authorization header, body bytes),
returns 401 with a body that ECHOES the Authorization value for values in
``fail_auth_values`` (the deliberate key-in-error-string plant for the
redaction tests), else a valid chat.completion JSON echoing the request's
model with configurable usage. ``echo_auth_in_success_body`` plants the
bearer value inside the 200 body (the body-position plant).
"""

from __future__ import annotations

import dataclasses
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclasses.dataclass(frozen=True)
class RecordedRequest:
    method: str
    path: str  # e.g. '/v1/chat/completions'
    authorization: str  # FULL header value, e.g. 'Bearer sk-test-AAA'
    body: bytes


def ok_completion_body(request_body: bytes, usage: tuple[int, int, int]) -> bytes:
    """Valid non-streaming chat.completion JSON echoing the request's model,
    with the given (prompt, completion, total) usage. The completion content
    also echoes the last user message content (used by round-trip tests)."""
    prompt_tokens, completion_tokens, total_tokens = usage
    model = "fake-upstream-model"
    content = "Hello from the fake upstream."
    try:
        payload = json.loads(request_body.decode("utf-8"))
        if isinstance(payload, dict):
            if isinstance(payload.get("model"), str):
                model = payload["model"]
            messages = payload.get("messages")
            if isinstance(messages, list) and messages:
                last = messages[-1]
                if isinstance(last, dict) and isinstance(last.get("content"), str):
                    content = f"echo: {last['content']}"
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    completion = {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "created": 1700000000,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        },
    }
    return json.dumps(completion).encode("utf-8")


def auth_error_body(authorization: str) -> bytes:
    """401 body ECHOING the Authorization value — the deliberate
    key-in-error-string plant for the redaction tests."""
    error = {
        "error": {
            "message": f"Incorrect API key provided: {authorization}.",
            "type": "invalid_request_error",
            "code": "invalid_api_key",
        }
    }
    return json.dumps(error).encode("utf-8")


class _FakeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30

    @property
    def fake(self) -> "FakeUpstream":
        return self.server.fake

    def _emit(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.wfile.write(payload)

    def do_POST(self) -> None:
        try:
            raw_length = self.headers.get("Content-Length", "0") or "0"
            try:
                length = int(raw_length)
            except ValueError:
                length = 0
            body = self.rfile.read(length) if length > 0 else b""
            authorization = self.headers.get("Authorization", "")
            self.fake._record(RecordedRequest("POST", self.path, authorization, body))
            if authorization in self.fake._fail_auth_values:
                self._emit(self.fake._fail_auth_status, auth_error_body(authorization), "application/json")
                return
            payload = ok_completion_body(body, self.fake._usage)
            if self.fake._echo_auth_in_success_body and authorization.startswith("Bearer "):
                data = json.loads(payload.decode("utf-8"))
                bearer_value = authorization[len("Bearer "):]
                data["choices"][0]["message"]["content"] += f" [bearer was {bearer_value}]"
                payload = json.dumps(data).encode("utf-8")
            self._emit(200, payload, "application/json")
        except Exception:
            self.close_connection = True

    # Test scaffolding: never write request logs to any stream.
    def log_message(self, format, *args) -> None:  # noqa: A002 - stdlib signature
        return

    def log_request(self, code="-", size="-") -> None:
        return

    def log_error(self, format, *args) -> None:  # noqa: A002 - stdlib signature
        return

    def version_string(self) -> str:
        return "fake-upstream"


class _FakeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler_class, fake: "FakeUpstream") -> None:
        self.fake = fake
        super().__init__(address, handler_class)

    def handle_error(self, request, client_address) -> None:
        # Swallow: test scaffolding must never spray tracebacks.
        return


class FakeUpstream:
    """Threaded OpenAI-shaped fake provider on 127.0.0.1:0. Loopback only.

    Uses the same single-writer / swallow-handle_error discipline as the
    product server.
    """

    def __init__(
        self,
        *,
        fail_auth_values: frozenset[str] = frozenset(),
        fail_auth_status: int = 401,
        usage: tuple[int, int, int] = (11, 7, 18),
        echo_auth_in_success_body: bool = False,
    ) -> None:
        self._fail_auth_values = frozenset(fail_auth_values)
        self._fail_auth_status = int(fail_auth_status)
        self._usage = tuple(usage)
        self._echo_auth_in_success_body = bool(echo_auth_in_success_body)
        self._lock = threading.Lock()
        self._requests: list[RecordedRequest] = []
        self._httpd: _FakeHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._httpd is not None:
            raise RuntimeError("FakeUpstream already started")
        httpd = _FakeHTTPServer(("127.0.0.1", 0), _FakeHandler, self)
        self._httpd = httpd
        thread = threading.Thread(
            target=httpd.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="fake-upstream",
            daemon=True,
        )
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        httpd, self._httpd = self._httpd, None
        thread, self._thread = self._thread, None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if thread is not None:
            thread.join(timeout=10)

    @property
    def url(self) -> str:
        """config base_url pointing at this fake: http://127.0.0.1:<port>/v1"""
        if self._httpd is None:
            raise RuntimeError("FakeUpstream not started")
        return f"http://127.0.0.1:{self.port}/v1"

    @property
    def port(self) -> int:
        if self._httpd is None:
            raise RuntimeError("FakeUpstream not started")
        return self._httpd.server_address[1]

    def _record(self, request: RecordedRequest) -> None:
        with self._lock:
            self._requests.append(request)

    def requests(self) -> tuple[RecordedRequest, ...]:
        with self._lock:
            return tuple(self._requests)

    def auth_hits(self, authorization: str) -> int:
        with self._lock:
            return sum(1 for r in self._requests if r.authorization == authorization)

    def clear(self) -> None:
        with self._lock:
            self._requests.clear()
