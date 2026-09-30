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
usage record per authenticated chat request to a JSONL spend log.

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

## Known limitations

Honest hardening gaps, documented rather than silently implied away:

- **Unbounded upstream body reads (fix-later).** keysmith reads whatever
  body a configured provider returns with no size cap, and the call
  timeout does not bound a body that keeps flowing. A misbehaving,
  compromised, or hostile configured endpoint — including an
  `allow_insecure` loopback endpoint, which the product itself
  legitimizes for local dev — can exhaust keysmith's memory (RAM) or
  trickle bytes to pin a handler thread indefinitely.
- **Thread-per-connection, no cap.** The stdlib threaded server spawns one
  handler thread per connection with no limit. Many simultaneous
  connections, or stuck upstream reads, can pin threads and degrade the
  gateway.
- **Loopback is the perimeter.** keysmith is safe where it belongs: bound
  to loopback. `--host` beyond loopback prints a warning and then binds
  anyway — everything that can reach the host can spend your configured
  keys — and beyond loopback it combines badly with the limits above:
  threads are uncapped, there is no auth-failure backoff, and the
  request-header phase happens **before** the token check, so a client
  that drips headers slowly (a client-side slowloris) pins a handler
  thread without ever presenting a token.
- **Spend-log durability is per-record flush, not fsync.** Each spend line
  is written and flushed to the OS as it happens, so a crashed or killed
  process (`kill -9`) loses nothing already appended; power loss or an OS
  crash can still lose the tail sitting in the file system's buffers.
  Reconcile against your provider's invoice, not only the spend log.
- **The secret vault never evicts (wontfix).** Every key value and client
  token ever seen stays registered for redaction for the lifetime of the
  process, so redaction cost grows with the size of the key pool. Fine
  for small static pools; documented instead of fixed.
- **Redaction scope is UTF-8 plus the registered escape forms (v0.1).**
  Upstream bodies are assumed UTF-8: keysmith decodes every body it relays
  or logs as UTF-8 (with replacement) before scrubbing. Non-UTF-8 bytes
  are mangled by the scrub path — key material carried in them is out of
  redaction scope for v0.1. Within UTF-8 text, redaction covers every
  secret the vault has registered together with its registered escape
  forms, all derived per secret: the canonical JSON-escaped form
  (lowercase-hex `\uXXXX`, plus `\"`, `\\`), the uppercase-hex form of
  every `\uXXXX` escape (valid JSON per RFC 8259, decodes identically),
  and the double-escaped canonical form. Adversarial encoding variants
  beyond those registered forms (other escapings, encodings, or
  transformations of key material) are out of scope for v0.1.

## Quickstart

```sh
cd keysmith                                        # the cloned repo
export KEYSMITH_TOKEN="some-long-random-string"    # your local client token
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
`providers.json`, `spend.jsonl`, `127.0.0.1`, 8317). A missing
`KEYSMITH_TOKEN` or an invalid config aborts startup with a diagnostic.

Windows note: in PowerShell use `$Env:KEYSMITH_TOKEN = "..."`; in cmd,
`set KEYSMITH_TOKEN=...`. The `curl` example above uses POSIX quoting for
the JSON body; on Windows, run it from Git Bash/WSL or adapt the quoting
for your shell.

## Configuring providers

`providers.json` maps provider ids to settings. See
`example.providers.json` for a merged multi-provider example (its
`_comment` documents every field); `templates/` has one provider per file
(OpenAI, GLM/Z.ai, Groq, OpenRouter, vLLM, and the Anthropic stub). **Verify
each base URL and model id with your provider's current docs** — the
shipped values are examples, not guarantees.

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

- Provider keys live only in environment variables, referenced by name in
  config; their values are read in exactly one function,
  `keys.read_key_value`, at call time. The client token (`KEYSMITH_TOKEN`)
  is read separately at startup.
- The spend log stores the env var NAME (alias) of the key used — never the
  value — plus timestamp, provider, model ids, status, latency and token
  counts. Nothing else, by construction.
- Every string keysmith emits — client responses, spend lines, diagnostics
  — passes through one `redact()` scrub against every secret it has seen,
  in raw form and in every registered escape form derived from it: the
  canonical JSON-escaped form it takes inside a serialized body
  (lowercase-hex `\uXXXX`, `\"`, `\\`), its uppercase-hex variant, and the
  double-escaped form. The test suite plants fake keys in header, body,
  error-message and traceback positions — including non-ASCII,
  double-quote, backslash and CJK shapes, planted raw, lowercase-escaped,
  uppercase-hex-escaped and double-escaped through relaying 200 bodies and
  the all-keys-fail 502 path — walks every decoded string of every
  client-visible body, and sweeps every output surface for them.
- `allow_insecure` is only an escape hatch for local dev endpoints: an
  `http://` base URL is accepted only when the host is loopback (127.x.x.x,
  `::1`, `localhost`) **and** `allow_insecure` is true. A non-loopback
  cleartext URL would expose your bearer key on the wire, so config loading
  refuses it outright.
- `providers.json` is **trusted input**. The cleartext refusal above covers
  `http://` only: anyone who can write the config file can point a
  provider's `base_url` at their own `https://` host, and on the next start
  keysmith will send that provider's real bearer key there. The spend log
  stays clean (it stores the alias, never the value) and redaction never
  fires — the key was "legitimately" used. Write access to `providers.json`
  is write access to your keys; protect the file accordingly.
- HTTP/1.1 keep-alive is honored, but an error response emitted before the
  request body is read closes the connection so unread body bytes cannot
  corrupt the next request on the socket (demonstrated over raw sockets for
  the 401, 411 and 413 paths).

## What the tests demonstrate

Run from the repo root (everything binds `127.0.0.1`; no real providers,
no real keys, no network beyond loopback):

```sh
python -m unittest discover -s tests   # the full suite
python scripts/smoke.py                # end-to-end smoke vs an in-process fake upstream
```

The suite covers: rotation (first key fails auth 3× → cooldown → second key
serves, recovery after cooldown), redaction in header/body/error/traceback
positions across client responses, the spend log and diagnostics, config
validation including every shipped template, the key-pool state machine
(unit-tested with injected clocks; the end-to-end rotation test uses one
bounded 0.3 s sleep for cooldown recovery), keep-alive drain-or-close
behavior over raw sockets, 405/400 JSON envelopes (no stdlib HTML pages),
the handler catch-all, and a machine check that no file imports anything
outside the standard library.

The same command runs on every push via GitHub Actions
(`.github/workflows/ci.yml`, ubuntu-latest and windows-latest): the suite
is standard-library only, so CI provisions Python 3.11 and installs
nothing else.

Claims in this README are limited to what those tests demonstrate; anything
untested is listed as roadmap, not behavior. There is no CHANGELOG file;
the git log is the changelog.

## Roadmap (not in v0.1)

SSE/streaming passthrough · embeddings and other endpoints ·
retry-on-transport-failure (v0.1 fails fast instead of silently retrying) ·
budgets on top of the spend log.

## License

MIT — see [LICENSE](LICENSE).
