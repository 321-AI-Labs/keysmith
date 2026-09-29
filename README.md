# keysmith

A local bring-your-own-key (BYOK) gateway that speaks the OpenAI
chat-completions API and routes each request to a provider you configure —
with key rotation, cooldown for failing keys, per-request spend logging,
and a single redaction choke point designed so key material never reaches a
client response, a log line, or a traceback.

keysmith is the open counterpart to — inspired by, not affiliated with —
subscription-portability plays like OpenAI's "Sign in with ChatGPT"
(DevDay 2026). The idea: your keys, your rules, any tool, any provider.

## What it is

A small local proxy. Tools that speak the OpenAI chat API point at keysmith
instead of a provider; you send a model like `glm/glm-4.8` or
`openai/gpt-4.1`, keysmith maps it to the provider you configured, attaches
the right key from your environment, forwards the request, and appends one
usage record per request to a JSONL spend log.

- Python 3.11+, **standard library only** — no third-party packages, at
  runtime or in the test suite (machine-checked by `tests/test_imports.py`).
- Windows-first, POSIX-honest. Binds `127.0.0.1` by default.
- One local token (env `KEYSMITH_TOKEN`) gates every endpoint, so random
  local processes cannot spend your keys.
- A key that fails authentication 3 times in a row cools down for a
  configurable period and is skipped; it recovers without a restart.
- Unknown provider or model → a 404 JSON error. keysmith never guesses and
  never falls back.

## What it is NOT (v0.1)

- Not a billing system, not budgets beyond the spend log.
- Not multi-tenant, not hosted, no admin UI.
- No streaming: `stream: true` is rejected with a clear 400. SSE
  passthrough is a roadmap item, not a claim.
- No embeddings or other endpoints (roadmap).
- Anthropic-native `/v1/messages` is not implemented;
  `templates/providers.anthropic-stub.json` says so and configures nothing.

## Quickstart

```sh
cd keysmith-repo
export KEYSMITH_TOKEN="some-long-random-string"   # your local client token
cp templates/providers.openai.json providers.json  # or any template
export OPENAI_API_KEY="sk-..."                     # the env vars named in your config
python -m keysmith                                 # serves http://127.0.0.1:8317
```

Point your tool at `http://127.0.0.1:8317/v1` with
`Authorization: Bearer $KEYSMITH_TOKEN` and a model of the form
`<provider>/<model>`, e.g. `openai/gpt-4.1`:

```sh
curl http://127.0.0.1:8317/v1/chat/completions \
  -H "Authorization: Bearer $KEYSMITH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "openai/gpt-4.1", "messages": [{"role": "user", "content": "hi"}]}'
```

`GET /v1/models` lists every configured `<provider>/<model>` pair.
CLI flags: `--config`, `--spend-log`, `--host`, `--port` (defaults
`providers.json`, `spend.jsonl`, `127.0.0.1`, 8317). Exit code 2 for a
missing `KEYSMITH_TOKEN` or an invalid config.

Windows note: in PowerShell use `$Env:KEYSMITH_TOKEN = "..."`; in cmd,
`set KEYSMITH_TOKEN=...`.

## Configuring providers

`providers.json` maps provider ids to settings. See
`example.providers.json` for a merged multi-provider example with every
field; `templates/` has one provider per file (OpenAI, GLM/Z.ai, Groq,
OpenRouter, vLLM, and the Anthropic stub). **Verify each base URL and model
id with your provider's current docs** — the shipped values are examples,
not guarantees.

| field | required | meaning |
| --- | --- | --- |
| `base_url` | yes | provider root, e.g. `https://api.openai.com/v1`; keysmith appends `/chat/completions` |
| `keys` | yes | env var NAMES holding keys (never key values), ≥ 1; round-robin across them |
| `models` | yes | public name → upstream model id; public names must not contain `/` |
| `cooldown_seconds` | no | rest period after 3 consecutive auth failures (default 60) |
| `timeout_seconds` | no | upstream call timeout (default 120) |
| `allow_insecure` | no | must be true for any `http://` base URL (default false) |

An optional top-level `"_comment"` string is allowed and ignored. Unknown
fields are rejected with a message naming their path, so typos fail loudly.

## Security notes

- Keys live only in environment variables, referenced by name in config;
  values are read at call time, once per attempt, in exactly one function.
- The spend log stores the env var NAME (alias) of the key used — never the
  value — plus timestamp, provider, models, status, latency and token
  counts. Nothing else, by construction.
- Every string keysmith emits — client responses, spend lines, diagnostics
  — passes through one `redact()` scrub against every secret it has seen.
  The test suite plants fake keys in header, body, error-message and
  traceback positions and sweeps every output surface for them.
- `allow_insecure` is only an escape hatch for local dev endpoints: an
  `http://` base URL is accepted only when the host is loopback (127.x.x.x,
  `::1`, `localhost`) **and** `allow_insecure` is true. A non-loopback
  cleartext URL would expose your bearer key on the wire, so config loading
  refuses it outright.
- HTTP/1.1 keep-alive is honored, but any early-error response (401/404/405/
  411/413 — emitted before the request body is read) closes the connection
  so unread body bytes cannot corrupt the next request on the socket.

## What the tests demonstrate

Run from the repo root (everything binds `127.0.0.1`; no real providers,
no real keys, no network beyond loopback):

```sh
python -m unittest discover -s tests   # the full suite
python scripts/smoke.py                # end-to-end smoke vs an in-process fake upstream
```

The suite covers: rotation (first key fails auth 3× → cooldown → second key
serves, recovery after cooldown), redaction in header/body/error/traceback
positions across client responses, the spend file and diagnostics, config
validation including every shipped template, the key-pool state machine
(with injected clocks, not sleeps), keep-alive drain-or-close behavior over
raw sockets, 405/400 JSON envelopes (no stdlib HTML pages), the handler
catch-all, and a machine check that no file imports anything outside the
standard library.

Claims in this README are limited to what those tests demonstrate; anything
untested is listed as roadmap, not behavior.

## Roadmap (not in v0.1)

SSE/streaming passthrough · embeddings and other endpoints ·
retry-on-transport-failure (v0.1 fails fast instead of silently retrying) ·
budgets on top of the spend log.

## License

MIT — see [LICENSE](LICENSE).
