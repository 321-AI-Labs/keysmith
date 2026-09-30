"""Append-only JSONL spend log.

A SpendRecord holds timestamp, provider, model, key ALIAS,
status, latency and token counts — no other fields may ever exist. No
request bodies, no response bodies, no key values. The mandatory redact
callable on :meth:`SpendLog.append` is defense-in-depth on top of fields
that are non-secret by construction.
"""

from __future__ import annotations

import collections.abc
import dataclasses
import json
import pathlib
import threading

# The client-controlled model string is capped at
# record-build time so an unbounded model (a hostile client can send
# megabytes inside the JSON body) cannot write megabyte JSONL lines. The
# bound must comfortably exceed real '<provider>/<model>' identifiers
# (longest real ids are ~60 chars) while keeping lines short.
MAX_MODEL_CHARS: int = 256


class SpendLogError(ValueError):
    """A spend-log line could not be parsed back into a SpendRecord."""


@dataclasses.dataclass(frozen=True)
class SpendRecord:
    ts: str
    provider: str  # provider id, '' if the request never routed
    model: str  # client-requested model string, e.g. 'glm/glm-4.8'
    upstream_model: str  # mapped id, '' if the request never routed
    key_alias: str  # env var name of the FINAL attempt, '' if none
    status: int  # routed: upstream status of final attempt, 0 = no upstream
    # response. Pre-upstream failures (401/400/404/411/413): the
    # client-facing HTTP status keysmith returned.
    error_kind: str | None  # 'timeout'|'connection'|'tls'|'unknown'|'no_keys'|None
    latency_ms: float  # wall time of the whole request, milliseconds
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None

    def __post_init__(self) -> None:
        # Cap at RECORD-BUILD time: both the pre-route and
        # routed builders construct a SpendRecord, so the cap holds on every
        # path that writes a line. Idempotent for already-capped values.
        if len(self.model) > MAX_MODEL_CHARS:
            object.__setattr__(self, "model", self.model[:MAX_MODEL_CHARS])

    def to_json_line(self) -> str:
        return json.dumps(
            dataclasses.asdict(self), sort_keys=True, separators=(",", ":")
        )


_RECORD_FIELDS = frozenset(field.name for field in dataclasses.fields(SpendRecord))


class SpendLog:
    """Append-only JSONL spend log. Internally locked."""

    def __init__(self, path: str | pathlib.Path) -> None:
        self._path = pathlib.Path(path)
        self._lock = threading.Lock()

    @property
    def path(self) -> pathlib.Path:
        return self._path

    def append(self, record: SpendRecord, redact: collections.abc.Callable[[str], str]) -> None:
        """Append one record as a JSON line.

        The line is forced through the mandatory ``redact`` callable — no
        code path writes a line without passing it through redact first.
        Parent directories are created on first write; the file is flushed.
        """
        line = redact(record.to_json_line())
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()

    def read_all(self) -> list[SpendRecord]:
        """Parse every line; SpendLogError on a malformed line."""
        with self._lock:
            if not self._path.exists():
                return []
            text = self._path.read_text(encoding="utf-8")
        records: list[SpendRecord] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SpendLogError(f"malformed spend log line: {exc}: {line[:200]!r}") from exc
            if not isinstance(data, dict) or set(data) != _RECORD_FIELDS:
                raise SpendLogError(f"malformed spend log line (unexpected fields): {line[:200]!r}")
            try:
                records.append(SpendRecord(**data))
            except TypeError as exc:
                raise SpendLogError(f"malformed spend log line: {exc}: {line[:200]!r}") from exc
        return records

    def line_count(self) -> int:
        with self._lock:
            if not self._path.exists():
                return 0
            text = self._path.read_text(encoding="utf-8")
        return sum(1 for line in text.splitlines() if line.strip())
