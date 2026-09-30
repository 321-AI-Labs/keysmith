"""The ONE module holding every NEW user-visible string (naming law,
UI-CHARTER-V02). The future owner rename sweep must be a single pass over
this file.

Rules for this module:

* Every string a user can read that did not already exist in keysmith v0.1
  lives here: dashboard page copy, wizard messages, API message templates,
  and the startup dashboard line. Other modules (ui_page, ui_api, wizard,
  server, __main__) IMPORT these constants; they must not grow their own
  prose.
* Existing v0.1 strings (error_json messages, validator messages, the
  startup banner) are NOT duplicated or renamed here; the callers reuse
  them verbatim.
* No em dashes (polish bar). Plain, honest microcopy, no hype.
* PAGE_TEXT is the page-copy block consumed by ui_page.DOCUMENT; the
  browser receives it as one JSON blob so page JavaScript also renders
  only strings from this module.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Startup (printed by __main__, the only legal print site)
# ---------------------------------------------------------------------------

STARTUP_DASHBOARD_LINE: str = (
    "Dashboard: {url} (open it in a browser and log in with the value of"
    " KEYSMITH_TOKEN)"
)

# ---------------------------------------------------------------------------
# Server/API message templates (used by server.py and wizard.py)
# ---------------------------------------------------------------------------

# Emitted by GET /api/spend when the JSONL log cannot be parsed back.
SPEND_LOG_UNREADABLE: str = "the spend log could not be read: "

# Wizard write results.
WIZARD_NO_CONFIG_PATH: str = (
    "the wizard cannot write: this server was started without a known"
    " config file path, so there is nothing safe to overwrite"
)
WIZARD_WRITE_FAILED: str = "cannot write the config file: "
WIZARD_RESTART_HINT: str = (
    "Config file written. Restart keysmith to load it. The running gateway"
    " keeps serving the previous config until it is restarted."
)
WIZARD_VERIFY_FAILED: str = (
    "the file was written but did not validate on re-read: "
)

# Connection-card curl example (ui_api formats {endpoint} and {model}).
# Escaped double quotes inside the double-quoted -d argument work in both
# POSIX shells and cmd.exe; $KEYSMITH_TOKEN stays a placeholder.
CURL_EXAMPLE: str = (
    'curl {endpoint} -H "Authorization: Bearer $KEYSMITH_TOKEN"'
    ' -H "Content-Type: application/json"'
    ' -d "{{\\"model\\": \\"{model}\\",'
    ' \\"messages\\": [{{\\"role\\": \\"user\\", \\"content\\": \\"hi\\"}}]}}"'
)

# ---------------------------------------------------------------------------
# Dashboard page copy (consumed by ui_page.DOCUMENT)
# ---------------------------------------------------------------------------

PAGE_TEXT: dict[str, str] = {
    # Shell
    "htmlLang": "en",
    "documentTitle": "keysmith dashboard",
    "skipToContent": "Skip to content",
    "headerTitle": "keysmith",
    "headerSubtitle": "local dashboard",
    "liveChip": "live",
    "liveChipError": "offline",
    "logoutButton": "Lock",
    "logoutHint": "Forget the token held by this page.",
    # Login card
    "loginHeading": "Unlock the dashboard",
    "loginLead": (
        "keysmith is gated by one local token. Enter the value of the"
        " KEYSMITH_TOKEN environment variable you started keysmith with."
    ),
    "loginLabel": "Local token",
    "loginPlaceholder": "value of KEYSMITH_TOKEN",
    "loginButton": "Unlock",
    "loginChecking": "Checking...",
    "loginBadToken": (
        "That token was not accepted. Check KEYSMITH_TOKEN and try again."
    ),
    "loginMemoryNote": (
        "The token stays in this page's memory only. It is sent as a header"
        " on every dashboard request and is never written to disk by the"
        " page."
    ),
    # Navigation
    "navStatus": "Status",
    "navSpend": "Spend",
    "navConnect": "Connect",
    "navSetup": "Setup",
    # Shared panel states
    "stateLoading": "Loading...",
    "stateErrorPrefix": "Could not load this panel: ",
    "stateRetry": "Retry",
    "updatesNote": "Updates every 3 seconds.",
    # Status panel
    "statusHeading": "Status",
    "statusLead": "The running configuration and the state of every key pool.",
    "statusEmpty": (
        "No providers are configured. Open the Setup tab to build a"
        " providers.json file."
    ),
    "statusProviderCount": "providers",
    "statusModelCount": "models",
    "statusBaseURLLabel": "base URL",
    "statusModelsLabel": "models",
    "statusKeysLabel": "key pool",
    "statusKeyReady": "ready",
    "statusKeyCooling": "cooling",
    "statusKeyFailures": "{n} auth failure",
    "statusKeyFailuresPlural": "{n} auth failures",
    "statusCooldownLeft": "cooldown {s}s left",
    "statusAliasNote": "names only; key values are never sent to this page",
    # Spend panel
    "spendHeading": "Spend",
    "spendLead": "One line per authenticated chat request, with totals.",
    "spendEmpty": (
        "No spend records yet. Every authenticated chat request appends"
        " one line to the log."
    ),
    "spendTotalRequests": "requests",
    "spendOk": "ok",
    "spendFailed": "failed",
    "spendPromptTokens": "prompt tokens",
    "spendCompletionTokens": "completion tokens",
    "spendTotalTokens": "total tokens",
    "spendFilterLabel": "Filter",
    "spendFilterPlaceholder": "provider or model",
    "spendStatusFilterLabel": "Status",
    "spendStatusAll": "all",
    "spendStatusOk": "ok",
    "spendStatusFailed": "failed",
    "spendTableWhen": "time",
    "spendTableProvider": "provider",
    "spendTableModel": "model",
    "spendTableAlias": "key",
    "spendTableStatus": "status",
    "spendTableLatency": "latency",
    "spendTableTokens": "tokens (prompt / completion / total)",
    "spendNoMatch": "No records match the current filter.",
    "spendCappedNote": "Showing the newest {shown} of {total} records.",
    "spendByProvider": "Totals by provider",
    "spendByModel": "Totals by model",
    "spendNoProvider": "(no provider)",
    "spendCountColumn": "requests",
    "spendOkColumn": "ok",
    "spendFailedColumn": "failed",
    "spendTokensColumn": "tokens (p / c / t)",
    # Connections panel
    "connectHeading": "Connect",
    "connectLead": (
        "Point any OpenAI-compatible tool at keysmith. Each card below is"
        " a copy-paste recipe for one configured model."
    ),
    "connectEmpty": (
        "No providers are configured, so there is nothing to connect to"
        " yet. Open the Setup tab first."
    ),
    "connectEndpointLabel": "endpoint",
    "connectTokenNote": (
        "The placeholder $KEYSMITH_TOKEN is the local token environment"
        " variable, not a provider key. Tools authenticate to keysmith"
        " with it; keysmith attaches the provider key from its own"
        " environment."
    ),
    "connectCurlLabel": "curl example",
    "connectCopy": "Copy",
    "connectCopied": "Copied.",
    "connectCopyFailed": "Copy failed. Select the text and copy manually.",
    # Wizard panel
    "setupHeading": "Setup",
    "setupLead": (
        "Build a providers.json file through the same validator keysmith"
        " uses at startup. Fields hold environment variable NAMES, never"
        " key values."
    ),
    "setupWritableFalse": (
        "This server was started without a known config file path, so the"
        " wizard cannot write. Preview still works; to write, start"
        " keysmith with the --config flag."
    ),
    "setupCurrentPath": "Config file",
    "setupNoCurrentFile": (
        "No existing config file was found. The form below starts empty."
    ),
    "setupCommentLabel": "Notes (optional _comment field)",
    "setupProvidersLabel": "Providers",
    "setupAddProvider": "Add provider",
    "setupRemoveProvider": "Remove",
    "setupIdLabel": "provider id",
    "setupIdHelp": "lowercase letters, digits, - and _",
    "setupBaseURLLabel": "base URL",
    "setupKeysLabel": "key env var names, one per line",
    "setupKeysHelp": (
        "NAMES of environment variables (for example OPENAI_API_KEY),"
        " never key values"
    ),
    "setupModelsLabel": "models, one per line as public = upstream",
    "setupCooldownLabel": "cooldown seconds (optional)",
    "setupTimeoutLabel": "timeout seconds (optional)",
    "setupInsecureLabel": (
        "allow_insecure (http base URL on a loopback host only)"
    ),
    "setupPreview": "Preview",
    "setupWrite": "Write providers.json",
    "setupPreviewOk": (
        "The document is valid. It defines {providers} provider(s) and"
        " {models} model(s)."
    ),
    "setupWriteDisabled": "Write is unavailable on this server.",
    "setupClientErrors": "Fix these before previewing:",
    "setupServerError": "The document was rejected:",
    # Client-side form checks. These exist only to stop silent data loss
    # (a malformed line being dropped); the server validator stays the
    # authority and reports anything that slips through.
    "setupErrIdEmpty": "provider id is empty",
    "setupErrIdDuplicate": "duplicate provider id {id}",
    "setupErrBaseURLEmpty": "base URL is empty for provider {id}",
    "setupErrKeysEmpty": (
        "at least one key env var name is required for provider {id}"
    ),
    "setupErrModelsEmpty": (
        "at least one model line is required for provider {id}"
    ),
    "setupErrModelLine": (
        "line {n} of the models list for provider {id} must look like"
        " public = upstream"
    ),
    "setupErrNumber": "{field} for provider {id} must be a number",
    "setupCooldownField": "cooldown seconds",
    "setupTimeoutField": "timeout seconds",
    # Footer
    "footerNote": (
        "keysmith serves this dashboard from the same local server, on"
        " loopback only."
    ),
}
