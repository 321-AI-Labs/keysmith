"""Pure payload builders for the dashboard API routes.

Every function here is pure: config, pool states, spend records and the
listen URL go in, plain JSON-ready dicts come out. No I/O, no sockets, no
os.environ, and never a key VALUE: the status payload carries aliases,
auth-failure counters and cooldown timers only (charter scope item 2:
"names only").

Cooldown arithmetic note: ``KeyState.cooldown_until`` lives in the
time.monotonic() domain (keys.py), so callers must sample
``time.monotonic()`` themselves and pass it as ``now``. Keeping the clock
outside these functions is what makes them unit-testable with injected
times.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence

from . import ui_strings
from .config import Config
from .keys import KeyPool, KeyState
from .spendlog import SpendRecord

# Newest-first row cap for GET /api/spend. The log itself is unbounded;
# the payload must not be.
SPEND_MAX_ROWS: int = 2000


def _cooldown_view(state: KeyState, now: float) -> dict[str, object]:
    cooling = state.cooldown_until is not None and now < state.cooldown_until
    remaining: float | None = None
    if cooling:
        assert state.cooldown_until is not None
        remaining = round(state.cooldown_until - now, 1)
    return {
        "alias": state.alias,
        "auth_failures": state.auth_failures,
        "cooling": cooling,
        "cooldown_remaining_seconds": remaining,
    }


def status_payload(
    config: Config, pools: Mapping[str, KeyPool], now: float
) -> dict[str, object]:
    """Running-config summary: providers, models, key-pool state by alias
    with cooldown-remaining seconds. Never reads the environment."""
    providers: list[dict[str, object]] = []
    model_count = 0
    for name in sorted(config.providers):
        provider = config.providers[name]
        models = [
            {"public": public, "upstream": provider.models[public]}
            for public in sorted(provider.models)
        ]
        model_count += len(models)
        pool = pools.get(name)
        keys = (
            [_cooldown_view(state, now) for state in pool.states()]
            if pool is not None
            else []
        )
        providers.append(
            {
                "id": name,
                "base_url": provider.base_url,
                "cooldown_seconds": provider.cooldown_seconds,
                "timeout_seconds": provider.timeout_seconds,
                "allow_insecure": provider.allow_insecure,
                "models": models,
                "keys": keys,
            }
        )
    return {
        "provider_count": len(providers),
        "model_count": model_count,
        "providers": providers,
    }


def connections_payload(config: Config, listen_url: str) -> dict[str, object]:
    """One copy-paste card per configured provider/model pair: base URL,
    public model, token placeholder and a curl example pointing at THIS
    keysmith instance."""
    endpoint = listen_url.rstrip("/") + "/v1/chat/completions"
    cards: list[dict[str, str]] = []
    for name in sorted(config.providers):
        provider = config.providers[name]
        for public in sorted(provider.models):
            model = f"{name}/{public}"
            cards.append(
                {
                    "provider": name,
                    "model": model,
                    "base_url": provider.base_url,
                    "endpoint": endpoint,
                    "token_env_var": "KEYSMITH_TOKEN",
                    "token_placeholder": "$KEYSMITH_TOKEN",
                    "curl": _curl_example(endpoint, model),
                }
            )
    return {"listen_url": listen_url, "cards": cards}


def _curl_example(endpoint: str, model: str) -> str:
    """The copy-paste curl line for one model. The quoting (escaped double
    quotes inside a double-quoted -d argument) works in both POSIX shells
    and cmd.exe."""
    return ui_strings.CURL_EXAMPLE.format(endpoint=endpoint, model=model)


# ---------------------------------------------------------------------------
# Spend aggregation (charter scope item 3: its own pure function,
# unit-tested against a fixture JSONL with pinned totals)
# ---------------------------------------------------------------------------


def _empty_counters() -> dict[str, object]:
    return {
        "requests": 0,
        "ok": 0,
        "failed": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
    }


def _bump(counters: dict[str, object], record: SpendRecord) -> None:
    counters["requests"] = int(counters["requests"]) + 1
    if 200 <= record.status < 400:
        counters["ok"] = int(counters["ok"]) + 1
    else:
        counters["failed"] = int(counters["failed"]) + 1
    counters["prompt_tokens"] = int(counters["prompt_tokens"]) + (
        record.prompt_tokens or 0
    )
    counters["completion_tokens"] = int(counters["completion_tokens"]) + (
        record.completion_tokens or 0
    )
    counters["total_tokens"] = int(counters["total_tokens"]) + (
        record.total_tokens or 0
    )


def aggregate_spend(records: Sequence[SpendRecord]) -> dict[str, object]:
    """Pure aggregation: grand totals plus per-provider and per-model
    totals. ``ok`` means a 2xx/3xx status; anything else (4xx, 5xx, and
    status 0, which marks a request that never reached an upstream)
    counts as failed. Token counts treat None as 0. Deterministic output:
    groups sorted by requests descending, then by group key ascending."""
    totals = _empty_counters()
    by_provider: dict[str, dict[str, object]] = {}
    by_model: dict[str, dict[str, object]] = {}
    for record in records:
        _bump(totals, record)
        provider_bucket = by_provider.setdefault(record.provider, _empty_counters())
        _bump(provider_bucket, record)
        model_bucket = by_model.setdefault(record.model, _empty_counters())
        _bump(model_bucket, record)

    def _sorted_groups(
        groups: dict[str, dict[str, object]], key_name: str
    ) -> list[dict[str, object]]:
        rows = [{key_name: key, **bucket} for key, bucket in groups.items()]
        rows.sort(key=lambda row: (-int(row["requests"]), str(row[key_name])))
        return rows

    return {
        "totals": totals,
        "by_provider": _sorted_groups(by_provider, "provider"),
        "by_model": _sorted_groups(by_model, "model"),
    }


def spend_payload(
    records: Sequence[SpendRecord], max_rows: int = SPEND_MAX_ROWS
) -> dict[str, object]:
    """Rows newest first (capped), plus the aggregate_spend totals."""
    newest_first = list(reversed(records))
    shown = newest_first[:max_rows]
    return {
        "row_count": len(records),
        "capped": len(records) > max_rows,
        "rows": [dataclasses.asdict(record) for record in shown],
        **aggregate_spend(records),
    }
