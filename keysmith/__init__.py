"""keysmith: a local BYOK OpenAI-compatible gateway.

Public API re-exports are listed in ``__all__``. See README.md for scope
and honest limitations.
"""

from .redact import REDACTED, SecretVault, redact
from .config import Config, ConfigError, ProviderConfig, load_config, validate_config_data
from .keys import AUTH_FAILURE_LIMIT, KeyPool, KeyState, read_key_value
from .upstream import (
    UpstreamError,
    UpstreamResult,
    call_provider,
    chat_completions_url,
    parse_usage,
)
from .spendlog import SpendLog, SpendLogError, SpendRecord
from .server import (
    AUTH_FAILURE_STATUSES,
    MAX_BODY_BYTES,
    KeysmithServer,
    Route,
    error_json,
    resolve_route,
    split_model,
)

__version__: str = "0.1.0"

__all__ = [
    "REDACTED",
    "redact",
    "SecretVault",
    "Config",
    "ConfigError",
    "ProviderConfig",
    "load_config",
    "validate_config_data",
    "AUTH_FAILURE_LIMIT",
    "KeyPool",
    "KeyState",
    "read_key_value",
    "UpstreamError",
    "UpstreamResult",
    "call_provider",
    "chat_completions_url",
    "parse_usage",
    "SpendLog",
    "SpendLogError",
    "SpendRecord",
    "KeysmithServer",
    "Route",
    "AUTH_FAILURE_STATUSES",
    "MAX_BODY_BYTES",
    "error_json",
    "resolve_route",
    "split_model",
]
