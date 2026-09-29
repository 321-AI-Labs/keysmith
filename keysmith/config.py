"""Loading and validation of providers.json.

The config stores env var NAMES, never key values, so every ConfigError
message is safe to render anywhere.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import os
import re
import urllib.parse

DEFAULT_COOLDOWN_SECONDS: float = 60.0
DEFAULT_TIMEOUT_SECONDS: float = 120.0

_PROVIDER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_ALLOWED_PROVIDER_FIELDS = frozenset(
    {
        "base_url",
        "keys",
        "models",
        "cooldown_seconds",
        "timeout_seconds",
        "allow_insecure",
    }
)
_ALLOWED_ROOT_FIELDS = frozenset({"providers", "_comment"})


class ConfigError(ValueError):
    """Invalid providers.json. The message is safe to render: the config
    file contains env var NAMES, never key values."""


@dataclasses.dataclass(frozen=True)
class ProviderConfig:
    name: str
    base_url: str
    key_env_vars: tuple[str, ...]
    models: dict[str, str]
    cooldown_seconds: float
    timeout_seconds: float
    allow_insecure: bool


@dataclasses.dataclass(frozen=True)
class Config:
    providers: dict[str, ProviderConfig]


def _is_loopback_host(hostname: str | None) -> bool:
    if not hostname:
        return False
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_base_url(field: str, base_url: object, allow_insecure: bool) -> str:
    where = f"{field}.base_url"
    if not isinstance(base_url, str) or not base_url:
        raise ConfigError(f"{where}: must be a nonempty string")
    parts = urllib.parse.urlsplit(base_url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ConfigError(f"{where}: scheme must be http or https (got {base_url!r})")
    hostname = parts.hostname
    if not hostname:
        raise ConfigError(f"{where}: URL has no host (got {base_url!r})")
    if scheme == "http" and not (allow_insecure and _is_loopback_host(hostname)):
        raise ConfigError(
            f"{where}: http base URLs are only allowed for loopback hosts when "
            f"allow_insecure is true; a non-loopback http URL would send the "
            f"bearer key in cleartext (got {base_url!r})"
        )
    return base_url


def _validate_keys(field: str, raw: object) -> tuple[str, ...]:
    where = f"{field}.keys"
    if not isinstance(raw, list) or not raw:
        raise ConfigError(f"{where}: must be a nonempty list of env var names")
    aliases: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item:
            raise ConfigError(f"{where}: every entry must be a nonempty string")
        if item not in aliases:
            aliases.append(item)
    return tuple(aliases)


def _validate_models(field: str, raw: object) -> dict[str, str]:
    where = f"{field}.models"
    if not isinstance(raw, dict) or not raw:
        raise ConfigError(
            f"{where}: must be a nonempty object mapping public model names to upstream model ids"
        )
    models: dict[str, str] = {}
    for public, upstream in raw.items():
        if not isinstance(public, str) or not public:
            raise ConfigError(f"{where}: public model names must be nonempty strings")
        if "/" in public:
            raise ConfigError(f"{where}: public model name {public!r} must not contain '/'")
        if not isinstance(upstream, str) or not upstream:
            raise ConfigError(
                f"{where}[{public!r}]: upstream model id must be a nonempty string"
            )
        models[public] = upstream
    return models


def _validate_number(field: str, raw: object) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ConfigError(f"{field}: must be a number")
    value = float(raw)
    if value <= 0:
        raise ConfigError(f"{field}: must be greater than 0 (got {raw!r})")
    return value


def load_config(path: str | os.PathLike[str]) -> Config:
    """Read and validate a providers.json file.

    Raises ConfigError (never a raw OSError or JSONDecodeError) for an
    unreadable file, invalid JSON, or any schema violation described in the
    public interface contract.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise ConfigError(f"cannot read config file {os.fspath(path)!r}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config file is not valid JSON: {exc}") from exc
    return _validate_root(data)


def _validate_root(data: object) -> Config:
    if not isinstance(data, dict):
        raise ConfigError("config top level must be a JSON object")
    for key in data:
        if key not in _ALLOWED_ROOT_FIELDS:
            raise ConfigError(f"{key}: unknown top-level field")
    raw_providers = data.get("providers")
    if not isinstance(raw_providers, dict):
        raise ConfigError(
            "providers: must be a JSON object mapping provider ids to provider configs"
        )
    providers: dict[str, ProviderConfig] = {}
    for name, raw in raw_providers.items():
        providers[name] = _validate_provider(name, raw)
    return Config(providers=providers)


def _validate_provider(name: str, raw: object) -> ProviderConfig:
    field = f"providers.{name}"
    if not isinstance(name, str) or not _PROVIDER_ID_RE.match(name):
        raise ConfigError(f"{field}: provider id must match ^[a-z0-9][a-z0-9_-]*$")
    if not isinstance(raw, dict):
        raise ConfigError(f"{field}: must be a JSON object")
    for key in raw:
        if key not in _ALLOWED_PROVIDER_FIELDS:
            raise ConfigError(f"{field}.{key}: unknown field")
    for required in ("base_url", "keys", "models"):
        if required not in raw:
            raise ConfigError(f"{field}.{required}: required")
    allow_insecure = raw.get("allow_insecure", False)
    if not isinstance(allow_insecure, bool):
        raise ConfigError(f"{field}.allow_insecure: must be true or false")
    base_url = _validate_base_url(field, raw["base_url"], allow_insecure)
    key_env_vars = _validate_keys(field, raw["keys"])
    models = _validate_models(field, raw["models"])
    cooldown = _validate_number(
        f"{field}.cooldown_seconds", raw.get("cooldown_seconds", DEFAULT_COOLDOWN_SECONDS)
    )
    timeout = _validate_number(
        f"{field}.timeout_seconds", raw.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    )
    return ProviderConfig(
        name=name,
        base_url=base_url,
        key_env_vars=key_env_vars,
        models=models,
        cooldown_seconds=cooldown,
        timeout_seconds=timeout,
        allow_insecure=allow_insecure,
    )
