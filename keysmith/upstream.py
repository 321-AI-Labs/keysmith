"""Upstream HTTP calls via urllib.request (stdlib only)."""

from __future__ import annotations

import dataclasses
import json
import socket
import ssl
import urllib.error
import urllib.request

from .config import ProviderConfig

_UPSTREAM_ERROR_KINDS = ("timeout", "connection", "tls", "unknown")

# Fixed-vocabulary error kind derived from an upstream
# error body's ``error.code`` via an allowlist map. Preserves why-it-failed
# UX without re-serializing upstream data: the result is always one of the
# four enum values, never upstream text.
UPSTREAM_ERROR_KIND_ENUM = ("invalid_api_key", "quota", "rate_limited", "other")

_ERROR_CODE_KIND_MAP = {
    "invalid_api_key": "invalid_api_key",
    "insufficient_quota": "quota",
    "rate_limit_exceeded": "rate_limited",
    "rate_limited": "rate_limited",
}


def upstream_error_kind(body: bytes) -> str:
    """Map an upstream error body's ``error.code`` to a closed-vocabulary
    kind: one of UPSTREAM_ERROR_KIND_ENUM.

    Allowlist-only: an unknown, missing or non-string code — or a body that
    is not UTF-8 JSON of the expected shape — yields ``'other'``. The
    return value never embeds upstream data by construction.
    """
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "other"
    if not isinstance(data, dict):
        return "other"
    error = data.get("error")
    if not isinstance(error, dict):
        return "other"
    code = error.get("code")
    if not isinstance(code, str):
        return "other"
    return _ERROR_CODE_KIND_MAP.get(code, "other")


class UpstreamError(Exception):
    """Transport failure (DNS, refused, TLS, timeout).

    ``kind`` is one of 'timeout', 'connection', 'tls', 'unknown'. str(err)
    is generic ('upstream unreachable (timeout)') and never embeds key
    material by construction: the message is built from a fixed vocabulary.
    """

    def __init__(self, kind: str, message: str = "upstream unreachable") -> None:
        if kind not in _UPSTREAM_ERROR_KINDS:
            kind = "unknown"
        super().__init__(f"{message} ({kind})")
        self.kind = kind


@dataclasses.dataclass(frozen=True)
class UpstreamResult:
    status: int  # upstream HTTP status; 4xx/5xx are returned, not raised
    body: bytes
    content_type: str  # upstream Content-Type; octet-stream fallback if absent


def chat_completions_url(base_url: str) -> str:
    """base_url.rstrip('/') + '/chat/completions'."""
    return base_url.rstrip("/") + "/chat/completions"


def _kind_of(exc: BaseException | None) -> str:
    if isinstance(exc, ssl.SSLError):  # covers CertificateError / verification
        return "tls"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, OSError):  # gaierror, ConnectionRefused, resets, ...
        return "connection"
    return "unknown"


def call_provider(provider: ProviderConfig, body: bytes, key_value: str) -> UpstreamResult:
    """POST chat_completions_url(provider.base_url) with the Bearer key.

    Headers are exactly Authorization, Content-Type and Accept. Any HTTP
    status (including 401/429/500) is RETURNED as UpstreamResult, reading
    the body from urllib.error.HTTPError. Raises UpstreamError on any
    transport failure.
    """
    request = urllib.request.Request(
        chat_completions_url(provider.base_url),
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {key_value}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=provider.timeout_seconds) as response:
            return UpstreamResult(
                status=response.status,
                body=response.read(),
                content_type=response.headers.get("Content-Type", "application/octet-stream"),
            )
    except urllib.error.HTTPError as exc:
        try:
            error_body = exc.read()
        except Exception:
            error_body = b""
        content_type = "application/octet-stream"
        if exc.headers is not None:
            content_type = exc.headers.get("Content-Type", "application/octet-stream")
        return UpstreamResult(status=exc.code, body=error_body, content_type=content_type)
    except urllib.error.URLError as exc:
        raise UpstreamError(_kind_of(exc.reason)) from exc
    except Exception as exc:  # TimeoutError, ssl errors, raw OSErrors, ...
        raise UpstreamError(_kind_of(exc)) from exc


def parse_usage(body: bytes) -> tuple[int | None, int | None, int | None]:
    """(prompt_tokens, completion_tokens, total_tokens) from an OpenAI-style
    body's 'usage' object; (None, None, None) if the body is not JSON or
    lacks it."""
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return (None, None, None)
    if not isinstance(data, dict):
        return (None, None, None)
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return (None, None, None)

    def _count(name: str) -> int | None:
        value = usage.get(name)
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value

    return (_count("prompt_tokens"), _count("completion_tokens"), _count("total_tokens"))
