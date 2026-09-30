"""The keysmith HTTP server: routing, auth, rotation, spend logging.

Egress laws implemented in this module (see the approved HTTP-layer
contract):

* ONE writer — every response goes through
  :meth:`KeysmithRequestHandler._emit`, which vault-redacts the payload
  before computing Content-Length. No other method writes to ``wfile``.
* Nothing is ever written to the standard error stream —
  ``log_message``/``log_error``/``log_request`` feed the diagnostics
  collector, ``send_error`` emits an OpenAI-shaped JSON envelope instead of
  the stock HTML page, and :meth:`KeysmithHTTPServer.handle_error` turns
  escaping tracebacks into vault-redacted diagnostics and writes to no
  stream at all.
* Drain-or-close keep-alive — any response emitted before the request body
  was fully read sets ``Connection: close`` so unread body bytes cannot
  desync the next request on a persistent connection.
"""

from __future__ import annotations

import dataclasses
import datetime
import hmac
import json
import os
import threading
import time
import traceback
import urllib.parse
from collections.abc import Mapping, Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import MappingProxyType

from . import keys, ui_api, ui_page, upstream, wizard
from . import ui_strings
from .config import Config, ProviderConfig
from .redact import SecretVault
from .spendlog import SpendLog, SpendLogError, SpendRecord

AUTH_FAILURE_STATUSES: frozenset[int] = frozenset({401, 403})
MAX_BODY_BYTES: int = 10_000_000

_DIAGNOSTIC_LIMIT = 100
_TRACEBACK_CHAR_LIMIT = 4000
_LOCAL_JSON = "application/json"


@dataclasses.dataclass(frozen=True)
class Route:
    provider_id: str
    public_model: str  # 'glm/glm-4.8'
    upstream_model: str
    provider: ProviderConfig


def split_model(model: str) -> tuple[str, str]:
    """'glm/glm-4.8' -> ('glm', 'glm-4.8'); ValueError unless the string has
    exactly one '/' and both halves are nonempty.

    NO-REPR LAW: client-controlled strings are embedded with plain quotes,
    never ``{...!r}``. repr() pre-escapes (a backslash becomes ``\\\\``),
    and json.dumps then escapes AGAIN — a second escaping layer the vault's
    escaped-twin redaction cannot match (the decoded-walk tests pin this)."""
    parts = model.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"model must look like '<provider>/<model>', got '{model}'")
    return parts[0], parts[1]


def resolve_route(cfg: Config, model: str) -> Route:
    """Deny-by-default: split, require the provider id in cfg.providers,
    require the model half in the provider's model map. Never guesses or
    falls back. NO-REPR LAW applies to every embedded
    client-controlled string (see split_model)."""
    provider_id, model_name = split_model(model)
    provider = cfg.providers.get(provider_id)
    if provider is None:
        raise ValueError(f"unknown provider '{provider_id}' in model '{model}'")
    upstream_model = provider.models.get(model_name)
    if upstream_model is None:
        raise ValueError(f"unknown model '{model_name}' for provider '{provider_id}'")
    return Route(
        provider_id=provider_id,
        public_model=model,
        upstream_model=upstream_model,
        provider=provider,
    )


def error_json(
    status: int,
    message: str,
    err_type: str,
    *,
    code: str | None = None,
    upstream_status: int | None = None,
    error_kind: str | None = None,
) -> bytes:
    """OpenAI-shaped error envelope as UTF-8 bytes.

    Structural redaction law: client-facing envelopes NEVER embed
    upstream-derived payloads — only the numeric ``upstream_status`` plus a
    fixed, key-free message. There is deliberately no parameter for an
    upstream error body: embedding one re-serializes attacker/upstream
    text, and any escaping that differs from the raw secret value (non-ASCII
    ``\\uXXXX``, ``\\"``, ``\\\\``) sails past the vault's raw-substring
    redaction (the envelope-level adversarial test pins this).
    """
    err: dict[str, object] = {"message": message, "type": err_type}
    if code is not None:
        err["code"] = code
    if upstream_status is not None:
        err["upstream_status"] = upstream_status
    if error_kind is not None:
        err["error_kind"] = error_kind
    return json.dumps({"error": err}, separators=(",", ":")).encode("utf-8")


class _Diagnostics:
    """Thread-safe ring of the last ``limit`` already-redacted lines."""

    def __init__(self, limit: int) -> None:
        self._lock = threading.Lock()
        self._limit = limit
        self._lines: list[str] = []

    def append(self, line: str) -> None:
        with self._lock:
            self._lines.append(line)
            if len(self._lines) > self._limit:
                del self._lines[: len(self._lines) - self._limit]

    def snapshot(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._lines)


class KeysmithHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server carrying the shared KeysmithServer state.

    http.server.ThreadingHTTPServer is socketserver.ThreadingMixIn over
    HTTPServer — the stdlib threading HTTP server the charter names.
    """

    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        keysmith: "KeysmithServer",
        diagnostics: _Diagnostics,
    ) -> None:
        self.keysmith = keysmith
        self.diagnostics = diagnostics
        super().__init__(address, handler_class)

    def handle_error(self, request, client_address) -> None:
        """Turn an escaping handler exception into a redacted diagnostic.

        The stock socketserver behaviour writes a raw traceback to the
        standard error stream; this override writes to no stream at all.

        Order matters: REDACT first, truncate after. Truncating
        first can cut a secret in half and leave a partial fragment that
        redact() can no longer match.
        """
        text = self.keysmith.vault.redact(traceback.format_exc())
        if len(text) > _TRACEBACK_CHAR_LIMIT:
            text = text[:_TRACEBACK_CHAR_LIMIT]
        self.diagnostics.append(text)


class KeysmithRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60
    server_version = "keysmith/0.1"

    # Per-request state; reset at the top of every do_* method.
    _body_read: bool = False
    _emitted: bool = False

    # ------------------------------------------------------------------
    # Method dispatch: 405 for everything except GET and POST. Returning
    # _method_not_allowed from __getattr__ for any 'do_*' name makes the
    # stock 501-with-HTML-page path in http.server unreachable, because
    # hasattr-based dispatch always finds a handler for real verbs.
    # ------------------------------------------------------------------

    def __getattr__(self, name: str):
        if name.startswith("do_"):
            return self._method_not_allowed
        raise AttributeError(name)

    def do_GET(self) -> None:
        self._reset_request_state()
        try:
            self._handle_get()
        except Exception:
            self._internal_error()

    def do_POST(self) -> None:
        self._reset_request_state()
        try:
            self._handle_post()
        except Exception:
            self._internal_error()

    def _reset_request_state(self) -> None:
        self._body_read = False
        self._emitted = False

    def _method_not_allowed(self) -> None:
        self._reset_request_state()
        try:
            if not self._check_token():
                self._emit(
                    401,
                    error_json(401, "missing or invalid local token", "keysmith_auth"),
                    _LOCAL_JSON,
                    body_drained=False,
                )
                return
            self._emit(
                405,
                error_json(
                    405,
                    "method not allowed",
                    "keysmith_request_error",
                    code="method_not_allowed",
                ),
                _LOCAL_JSON,
                body_drained=False,
                extra_headers=(("Allow", "GET, POST"),),
            )
        except Exception:
            self._internal_error()

    # ------------------------------------------------------------------
    # THE single writer. No other method writes to self.wfile.
    # ------------------------------------------------------------------

    def _emit(
        self,
        status: int,
        payload: bytes,
        content_type: str,
        *,
        body_drained: bool,
        extra_headers: Sequence[tuple[str, str]] = (),
    ) -> None:
        """Emit one response.

        (a) vault-redact the payload, and only then compute Content-Length;
        (b) send the status; (c) drain-or-close keep-alive: when the request
        body was not fully read, send 'Connection: close' and mark the
        connection to close so unread bytes cannot corrupt the next
        pipelined request; (d) send Content-Type and Content-Length;
        (e) write the payload.
        """
        vault = self.server.keysmith.vault
        payload = vault.redact(payload.decode("utf-8", "replace")).encode("utf-8")
        self._emitted = True
        self.send_response(status)
        if not body_drained:
            self.send_header("Connection", "close")
            self.close_connection = True
        for name, value in extra_headers:
            self.send_header(name, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        # send_response/send_header only buffer into _headers_buffer;
        # end_headers() flushes them to the socket before the body.
        self.end_headers()
        self.wfile.write(payload)

    # ------------------------------------------------------------------
    # Standard-error-stream law: all three stdlib log emitters are
    # overridden to feed the diagnostics collector instead.
    # ------------------------------------------------------------------

    def log_message(self, format: str, *args: object) -> None:
        try:
            line = format % args
        except Exception:
            line = repr(args)
        self.server.diagnostics.append(self.server.keysmith.vault.redact(line))

    def log_error(self, format: str, *args: object) -> None:
        self.log_message(format, *args)

    def log_request(self, code: object = "-", size: object = "-") -> None:
        self.log_message('"%s" %s %s', self.requestline, code, size)

    def send_error(self, code, message=None, explain=None) -> None:
        """Route the stock error path through _emit with an OpenAI-shaped
        envelope — the stdlib HTML error page is unreachable."""
        try:
            numeric = int(code)
        except (TypeError, ValueError):
            numeric = 500
        # Parse failures leave request_version at the HTTP/0.9 default,
        # which suppresses the status line and headers in http.server's
        # writers. keysmith always answers HTTP/1.1.
        if self.request_version == "HTTP/0.9":
            self.request_version = "HTTP/1.1"
        text = str(message) if message else "bad request"
        self._emit(
            numeric,
            error_json(numeric, text, "keysmith_request_error", code=str(numeric)),
            _LOCAL_JSON,
            body_drained=False,
        )

    def version_string(self) -> str:
        return self.server_version

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_token(self) -> bool:
        """True iff the request carries 'Bearer <token>' (RFC 7235: the
        auth-scheme production is case-insensitive, so 'bearer'/'BEARER'/
        'BeArEr' are equivalent; the token comparison itself stays exact).
        A scheme with no space or no credentials never authenticates."""
        header = self.headers.get("Authorization")
        if not header:
            return False
        scheme, space, provided = header.partition(" ")
        if not space or scheme.lower() != "bearer":
            return False
        expected = self.server.keysmith.token
        return hmac.compare_digest(
            expected.encode("utf-8"), provided.encode("utf-8")
        )

    def _unread_body(self) -> bool:
        if self._body_read:
            return False
        if self.headers is None:
            return False
        raw = self.headers.get("Content-Length")
        if raw is None:
            return False
        try:
            return int(raw) > 0
        except ValueError:
            return False

    def _path(self) -> str:
        return urllib.parse.urlsplit(self.path).path

    def _internal_error(self) -> None:
        """Catch-all for do_GET/do_POST bodies: redacted diagnostic plus a
        500 JSON envelope (or nothing, if a response already went out).

        Order matters: REDACT first, truncate after. Truncating
        first can cut a secret in half and leave a partial fragment that
        redact() can no longer match.
        """
        text = self.server.keysmith.vault.redact(traceback.format_exc())
        if len(text) > _TRACEBACK_CHAR_LIMIT:
            text = text[:_TRACEBACK_CHAR_LIMIT]
        self.server.diagnostics.append(text)
        if self._emitted:
            self.close_connection = True
            return
        try:
            self._emit(
                500,
                error_json(500, "internal error", "keysmith_internal"),
                _LOCAL_JSON,
                body_drained=not self._unread_body(),
            )
        except Exception:
            self.close_connection = True

    # ------------------------------------------------------------------
    # Spend logging: exactly ONE record per POST /v1/chat/completions,
    # written BEFORE the response is emitted so a client that has seen the
    # response can safely read the log.
    # ------------------------------------------------------------------

    def _now_iso(self) -> str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    def _latency_ms(self, start: float) -> float:
        return round((time.monotonic() - start) * 1000.0, 3)

    def _write_record(self, record: SpendRecord) -> None:
        keysmith = self.server.keysmith
        keysmith.spend_log.append(record, keysmith.vault.redact)

    def _spend_pre_route(self, start: float, *, status: int, model: str = "") -> None:
        self._write_record(
            SpendRecord(
                ts=self._now_iso(),
                provider="",
                model=model,
                upstream_model="",
                key_alias="",
                status=int(status),
                error_kind=None,
                latency_ms=self._latency_ms(start),
                prompt_tokens=None,
                completion_tokens=None,
                total_tokens=None,
            )
        )

    def _spend_routed(
        self,
        start: float,
        *,
        route: Route,
        model: str,
        key_alias: str,
        status: int,
        error_kind: str | None,
        tokens: tuple[int | None, int | None, int | None],
    ) -> None:
        prompt, completion, total = tokens
        self._write_record(
            SpendRecord(
                ts=self._now_iso(),
                provider=route.provider_id,
                model=model,
                upstream_model=route.upstream_model,
                key_alias=key_alias,
                status=int(status),
                error_kind=error_kind,
                latency_ms=self._latency_ms(start),
                prompt_tokens=prompt,
                completion_tokens=completion,
                total_tokens=total,
            )
        )

    def _respond_pre_route(
        self, start: float, status: int, message: str, *, code: str | None = None, model: str = ""
    ) -> None:
        self._spend_pre_route(start, status=status, model=model)
        self._emit(
            status,
            error_json(status, message, "invalid_request_error", code=code),
            _LOCAL_JSON,
            body_drained=True,
        )

    # ------------------------------------------------------------------
    # GET endpoints
    # ------------------------------------------------------------------

    def _handle_get(self) -> None:
        path = self._path()
        if path == "/":
            # THE one pre-auth route: the static dashboard shell. A
            # browser cannot attach a Bearer header to the navigation
            # that first loads a page, so the login page itself must be
            # reachable without one. The shell is byte-identical for
            # every client and every server (zero config, spend, token
            # or URL data; pinned by tests) and every dashboard API
            # route below stays behind the token gate: no endpoint that
            # carries data ever answers an unauthenticated request.
            # Everything still flows through _emit, so even these bytes
            # pass the redact() choke point.
            self._emit(
                200,
                ui_page.DOCUMENT_BYTES,
                ui_page.CONTENT_TYPE,
                body_drained=not self._unread_body(),
            )
            return
        if not self._check_token():
            # GETs never write spend records (spend scope is POST-only).
            self._emit(
                401,
                error_json(401, "missing or invalid local token", "keysmith_auth"),
                _LOCAL_JSON,
                body_drained=not self._unread_body(),
            )
            return
        if path == "/v1/models":
            self._emit_models()
            return
        if path == "/api/status":
            self._emit_api_status()
            return
        if path == "/api/spend":
            self._emit_api_spend()
            return
        if path == "/api/connections":
            self._emit_api_connections()
            return
        if path == "/api/wizard/current":
            self._emit_api_wizard_current()
            return
        self._emit(
            404,
            error_json(404, f"unknown path '{path}'", "invalid_request_error", code="path_not_found"),
            _LOCAL_JSON,
            body_drained=not self._unread_body(),
        )

    # ------------------------------------------------------------------
    # Dashboard JSON endpoints. Pure payload builders live in ui_api;
    # every response goes through _emit like everything else.
    # ------------------------------------------------------------------

    def _emit_json_payload(self, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._emit(200, body, _LOCAL_JSON, body_drained=not self._unread_body())

    def _emit_api_status(self) -> None:
        keysmith = self.server.keysmith
        payload = ui_api.status_payload(
            keysmith.config, keysmith.pools, time.monotonic()
        )
        self._emit_json_payload(payload)

    def _emit_api_spend(self) -> None:
        keysmith = self.server.keysmith
        try:
            records = keysmith.spend_log.read_all()
        except SpendLogError as exc:
            self._emit(
                500,
                error_json(
                    500,
                    ui_strings.SPEND_LOG_UNREADABLE + str(exc),
                    "keysmith_internal",
                ),
                _LOCAL_JSON,
                body_drained=not self._unread_body(),
            )
            return
        self._emit_json_payload(ui_api.spend_payload(records))

    def _emit_api_connections(self) -> None:
        keysmith = self.server.keysmith
        self._emit_json_payload(
            ui_api.connections_payload(keysmith.config, keysmith.url)
        )

    def _emit_api_wizard_current(self) -> None:
        keysmith = self.server.keysmith
        document = wizard.read_current_document(keysmith.config_path)
        self._emit_json_payload(
            wizard.current_state_payload(keysmith.config_path, document)
        )

    def _emit_models(self) -> None:
        providers = self.server.keysmith.config.providers
        ids = sorted(
            f"{name}/{model}"
            for name, provider in providers.items()
            for model in provider.models
        )
        data = [
            {"id": identifier, "object": "model", "owned_by": "keysmith"}
            for identifier in ids
        ]
        payload = json.dumps({"object": "list", "data": data}, separators=(",", ":")).encode("utf-8")
        self._emit(200, payload, _LOCAL_JSON, body_drained=not self._unread_body())

    # ------------------------------------------------------------------
    # POST endpoints
    # ------------------------------------------------------------------

    def _handle_post(self) -> None:
        start = time.monotonic()
        if not self._check_token():
            # Auth before logging: unauthenticated 401s write NO
            # spend record — aligned with GET 401 and unknown-path 404, and
            # never persisted before the caller proves it holds the token.
            self._emit(
                401,
                error_json(401, "missing or invalid local token", "keysmith_auth"),
                _LOCAL_JSON,
                body_drained=not self._unread_body(),
            )
            return
        path = self._path()
        if path == "/api/wizard/preview":
            # Wizard POSTs obey the chat body laws (Content-Length
            # required, MAX_BODY_BYTES cap, drain-or-close) and never
            # write a spend record: spend scope stays chat-only.
            document = self._read_wizard_body()
            if document is None:
                return
            result = wizard.preview_document(document)
            self._emit_json_payload(result.payload)
            return
        if path == "/api/wizard/write":
            document = self._read_wizard_body()
            if document is None:
                return
            result = wizard.write_document(self.server.keysmith.config_path, document)
            self._emit_json_payload(result.payload)
            return
        if path != "/v1/chat/completions":
            # Diagnostics-only: unknown paths never write a spend record.
            self._emit(
                404,
                error_json(404, f"unknown path '{path}'", "invalid_request_error", code="path_not_found"),
                _LOCAL_JSON,
                body_drained=not self._unread_body(),
            )
            return
        self._handle_chat(start)

    def _read_wizard_body(self) -> object | None:
        """Read one JSON POST body for the wizard routes under the SAME
        body laws as chat (Content-Length required, invalid length 400,
        over-limit 413 without reading, UTF-8 JSON object required).
        Emits the matching error envelope and returns None on failure;
        returns the parsed object otherwise. Writes no spend record.

        The duplicated checks (instead of refactoring _handle_chat to
        share them) are deliberate: the v0.1 chat path is tested,
        released machinery and this build must not perturb it."""
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._emit(
                411,
                error_json(
                    411,
                    "Length Required: POST requests must carry a Content-Length (chunked bodies are not supported in v0.1)",
                    "invalid_request_error",
                    code="length_required",
                ),
                _LOCAL_JSON,
                body_drained=False,
            )
            return None
        try:
            length = int(raw_length)
        except ValueError:
            self._emit(
                400,
                error_json(400, "invalid Content-Length header", "invalid_request_error"),
                _LOCAL_JSON,
                body_drained=False,
            )
            return None
        if length > MAX_BODY_BYTES:
            self._emit(
                413,
                error_json(
                    413,
                    f"request body exceeds the v0.1 limit of {MAX_BODY_BYTES} bytes",
                    "invalid_request_error",
                    code="body_too_large",
                ),
                _LOCAL_JSON,
                body_drained=False,
            )
            return None
        body = self.rfile.read(length) if length > 0 else b""
        self._body_read = True
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._emit(
                400,
                error_json(400, "request body must be valid UTF-8 JSON", "invalid_request_error", code="invalid_json"),
                _LOCAL_JSON,
                body_drained=True,
            )
            return None
        return payload

    def _handle_chat(self, start: float) -> None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            # v0.1 does not decode chunked bodies: without Content-Length we
            # cannot know how much to drain, so we close the connection.
            self._spend_pre_route(start, status=411)
            self._emit(
                411,
                error_json(
                    411,
                    "Length Required: POST requests must carry a Content-Length (chunked bodies are not supported in v0.1)",
                    "invalid_request_error",
                    code="length_required",
                ),
                _LOCAL_JSON,
                body_drained=False,
            )
            return
        try:
            length = int(raw_length)
        except ValueError:
            self._spend_pre_route(start, status=400)
            self._emit(
                400,
                error_json(400, "invalid Content-Length header", "invalid_request_error"),
                _LOCAL_JSON,
                body_drained=False,
            )
            return
        if length > MAX_BODY_BYTES:
            # Deliberately does NOT read the oversized body.
            self._spend_pre_route(start, status=413)
            self._emit(
                413,
                error_json(
                    413,
                    f"request body exceeds the v0.1 limit of {MAX_BODY_BYTES} bytes",
                    "invalid_request_error",
                    code="body_too_large",
                ),
                _LOCAL_JSON,
                body_drained=False,
            )
            return
        body = self.rfile.read(length) if length > 0 else b""
        self._body_read = True

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._respond_pre_route(start, 400, "request body must be valid UTF-8 JSON", code="invalid_json")
            return
        if not isinstance(payload, dict):
            self._respond_pre_route(start, 400, "request body must be a JSON object")
            return
        model = payload.get("model")
        if not isinstance(model, str) or not model:
            self._respond_pre_route(start, 400, "request body must include a nonempty string 'model'")
            return
        if payload.get("stream"):
            self._respond_pre_route(
                start, 400,
                "streaming is on the roadmap, not supported in v0.1: resend with stream omitted or false",
                code="streaming_not_supported",
            )
            return

        try:
            route = resolve_route(self.server.keysmith.config, model)
        except ValueError as exc:
            self._respond_pre_route(start, 404, str(exc), code="model_not_found", model=model)
            return

        # Rewrite the model to the upstream id and re-serialize compactly.
        payload["model"] = route.upstream_model
        forward_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        pool = self.server.keysmith.pools[route.provider_id]
        limit = self.server.keysmith.max_attempts
        if limit is None:
            limit = len(route.provider.key_env_vars)  # one attempt per configured key

        attempts = 0
        made_attempt = False
        last_alias = ""
        last_auth_result: upstream.UpstreamResult | None = None
        while attempts < limit:
            alias = pool.next_available(time.monotonic())
            if alias is None:
                break
            key_value = keys.read_key_value(alias)
            if key_value is None:
                # TOCTOU: the env var vanished between next_available's check
                # and this read. Does NOT consume an attempt; next_available
                # already advanced the cursor, so the loop still ends within
                # <= N iterations.
                continue
            attempts += 1
            made_attempt = True
            last_alias = alias
            self.server.keysmith.vault.register(key_value)
            try:
                result = upstream.call_provider(route.provider, forward_body, key_value)
            except upstream.UpstreamError as exc:
                # v0.1: transport failures do NOT rotate to the next key —
                # the request fails immediately; retry-on-transport is a
                # stated roadmap item, not silent scope.
                self._spend_routed(
                    start, route=route, model=model, key_alias=alias,
                    status=0, error_kind=exc.kind, tokens=(None, None, None),
                )
                self._emit(
                    502,
                    error_json(502, "upstream unreachable", "keysmith_upstream", error_kind=exc.kind),
                    _LOCAL_JSON,
                    body_drained=True,
                )
                return
            if result.status in AUTH_FAILURE_STATUSES:
                pool.report_auth_failure(alias, time.monotonic())
                last_auth_result = result
                continue
            tokens = upstream.parse_usage(result.body)
            if result.status < 400:
                pool.report_success(alias)
            self._spend_routed(
                start, route=route, model=model, key_alias=alias,
                status=result.status, error_kind=None, tokens=tokens,
            )
            self._emit(result.status, result.body, result.content_type, body_drained=True)
            return

        if not made_attempt:
            self._spend_routed(
                start, route=route, model=model, key_alias="",
                status=0, error_kind="no_keys", tokens=(None, None, None),
            )
            self._emit(
                503,
                error_json(
                    503,
                    f"no keys available for provider {route.provider_id!r}",
                    "keysmith_upstream",
                    error_kind="no_keys",
                ),
                _LOCAL_JSON,
                body_drained=True,
            )
            return

        # Every attempt failed upstream authentication. The envelope carries
        # ONLY the numeric upstream status, a fixed, key-free message, and
        # a closed-vocabulary error_kind. The upstream 401 body (which may
        # echo the bearer value, escaped) IS parsed below — for the
        # allowlist-mapped error_kind and for the usage counts in the spend
        # record — but it is never embedded or re-serialized into
        # client-facing bytes.
        assert last_auth_result is not None
        error_kind = upstream.upstream_error_kind(last_auth_result.body)
        self._spend_routed(
            start, route=route, model=model, key_alias=last_alias,
            status=last_auth_result.status, error_kind=None,
            tokens=upstream.parse_usage(last_auth_result.body),
        )
        self._emit(
            502,
            error_json(
                502,
                "all configured keys failed authentication",
                "keysmith_upstream",
                upstream_status=last_auth_result.status,
                error_kind=error_kind,
            ),
            _LOCAL_JSON,
            body_drained=True,
        )


class KeysmithServer:
    """Facade owning config, pools, token, spend log, vault, diagnostics,
    and the listening socket."""

    def __init__(
        self,
        config: Config,
        token: str,
        spend_log: SpendLog,
        vault: SecretVault,
        host: str = "127.0.0.1",
        port: int = 0,
        max_attempts: int | None = None,
        config_path: str | os.PathLike[str] | None = None,
    ) -> None:
        # An empty or whitespace-only token is a
        # misconfiguration, not a security posture — with token='' a bare
        # 'Authorization: Bearer ' (empty credentials) would authenticate
        # because hmac.compare_digest("", "") is True. Reject at the class
        # level so such a server cannot exist.
        if not isinstance(token, str) or not token.strip():
            raise ValueError(
                "client token must be a nonempty string that is not "
                "whitespace-only: an empty token would make a bare "
                "'Bearer ' header authenticate"
            )
        self.config = config
        self.token = token
        self.spend_log = spend_log
        self.vault = vault
        self.host = host
        # The file the setup wizard writes. None (the default, and the
        # shape every pre-v0.2 caller uses) means the wizard write path
        # fails closed: nothing on this server can overwrite a config.
        self.config_path = os.fspath(config_path) if config_path is not None else None
        self._requested_port = int(port)
        self._max_attempts = max_attempts
        pools = {
            name: keys.KeyPool(provider.key_env_vars, provider.cooldown_seconds)
            for name, provider in config.providers.items()
        }
        self.pools: Mapping[str, keys.KeyPool] = MappingProxyType(pools)
        vault.register(token)
        self._diagnostics = _Diagnostics(limit=_DIAGNOSTIC_LIMIT)
        self._httpd: KeysmithHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_port: int | None = None

    @property
    def max_attempts(self) -> int | None:
        return self._max_attempts

    def start(self) -> None:
        if self._httpd is not None:
            raise RuntimeError("KeysmithServer.start() called while already running")
        httpd = KeysmithHTTPServer(
            (self.host, self._requested_port),
            KeysmithRequestHandler,
            self,
            self._diagnostics,
        )
        self._httpd = httpd
        self._bound_port = httpd.server_address[1]
        thread = threading.Thread(
            target=httpd.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="keysmith-http-server",
            daemon=True,
        )
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        """Idempotent."""
        httpd, self._httpd = self._httpd, None
        thread, self._thread = self._thread, None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if thread is not None:
            thread.join(timeout=10)

    @property
    def port(self) -> int:
        if self._bound_port is None:
            raise RuntimeError("server not started")
        return self._bound_port

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def diagnostics(self) -> tuple[str, ...]:
        """Last <=100 diagnostic lines, each ALREADY vault-redacted."""
        return self._diagnostics.snapshot()
