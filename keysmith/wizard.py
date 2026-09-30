"""Setup wizard: validator-mediated providers.json assembly and atomic
write (charter scope item 5, the only write path).

Security shape, by construction:

* The wizard NEVER reads or writes environment variables and never calls
  ``keys.read_key_value``. It deals exclusively in the JSON document; the
  ``keys`` field holds env var NAMES, and no wizard surface has anywhere
  to put a key VALUE.
* Every document passes through ``config.validate_config_data`` (the
  exact validator ``load_config`` uses) BEFORE any byte is written.
* Writes are atomic: ``tempfile.mkstemp`` in the destination directory
  (unique name per POST, so concurrent writes cannot clobber each
  other's temp files), then ``os.replace``. On any failure the temp file
  is removed and the destination is untouched (fail closed: no partial
  file).
* After a successful replace the file is re-read with ``load_config`` as
  a belt-and-braces verification.
* ``config_path=None`` (a server started without a known config file)
  makes ``write_document`` fail closed with a fixed message; preview
  still works.
"""

from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import tempfile

from . import ui_strings
from .config import Config, ConfigError, load_config, validate_config_data


@dataclasses.dataclass(frozen=True)
class WizardResult:
    """One wizard outcome. ``payload`` is the JSON body the server emits;
    user-visible strings inside it come from ui_strings."""

    ok: bool
    payload: dict[str, object]


def read_current_document(
    config_path: str | os.PathLike[str] | None,
) -> dict[str, object] | None:
    """Best-effort read of the current config file as raw parsed JSON
    (including ``_comment``). None when there is no path, no file, or the
    file is not valid JSON (the wizard then starts from an empty form;
    startup errors belong to the CLI, not the page)."""
    if config_path is None:
        return None
    try:
        text = pathlib.Path(os.fspath(config_path)).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _summary(config: Config) -> dict[str, object]:
    providers: list[dict[str, object]] = []
    model_count = 0
    for name in sorted(config.providers):
        provider = config.providers[name]
        models = [
            {"public": public, "upstream": provider.models[public]}
            for public in sorted(provider.models)
        ]
        model_count += len(models)
        providers.append(
            {
                "id": name,
                "base_url": provider.base_url,
                "key_count": len(provider.key_env_vars),
                "models": models,
                "cooldown_seconds": provider.cooldown_seconds,
                "timeout_seconds": provider.timeout_seconds,
                "allow_insecure": provider.allow_insecure,
            }
        )
    return {
        "provider_count": len(providers),
        "model_count": model_count,
        "providers": providers,
    }


def _validate(document: object) -> WizardResult:
    """Validate through the existing config validator. A valid document
    yields ok=True plus a summary; an invalid one yields ok=False with
    the validator's path-naming messages (existing v0.1 behavior, reused
    verbatim)."""
    try:
        config = validate_config_data(document)
    except ConfigError as exc:
        return WizardResult(False, {"ok": False, "errors": [str(exc)]})
    return WizardResult(True, {"ok": True, "summary": _summary(config)})


def preview_document(document: object) -> WizardResult:
    """Validate a candidate document without touching disk."""
    return _validate(document)


def write_document(
    config_path: str | os.PathLike[str] | None,
    document: object,
) -> WizardResult:
    """Validate, atomically write, and re-verify ``document`` as the new
    providers.json at ``config_path``.

    Fails closed (no file is created or modified) when the path is None,
    the document is invalid, the write raises, or the re-read does not
    validate. The failed result's errors carry ui_strings messages.
    """
    if config_path is None:
        return WizardResult(
            False, {"ok": False, "errors": [ui_strings.WIZARD_NO_CONFIG_PATH]}
        )
    validated = _validate(document)
    if not validated.ok:
        return validated
    path = pathlib.Path(os.fspath(config_path))
    payload: dict[str, object]
    try:
        payload = _atomic_write(path, document)
    except OSError as exc:
        return WizardResult(
            False,
            {"ok": False, "errors": [ui_strings.WIZARD_WRITE_FAILED + str(exc)]},
        )
    # Belt and braces: the file on disk must load through the same
    # validator startup uses.
    try:
        load_config(path)
    except ConfigError as exc:
        return WizardResult(
            False,
            {"ok": False, "errors": [ui_strings.WIZARD_VERIFY_FAILED + str(exc)]},
        )
    return WizardResult(True, payload)


def _atomic_write(path: pathlib.Path, document: object) -> dict[str, object]:
    """Write ``document`` to ``path`` atomically; raises OSError on any
    failure after cleaning up its own temp file. Returns the success
    payload skeleton (message text from ui_strings)."""
    parent = path.parent if str(path.parent) else pathlib.Path(".")
    parent.mkdir(parents=True, exist_ok=True)
    handle_fd, temp_name = tempfile.mkstemp(
        dir=str(parent), prefix=path.name + ".", suffix=".wizard-tmp"
    )
    try:
        with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return {
        "ok": True,
        "message": ui_strings.WIZARD_RESTART_HINT,
        "config_path": str(path),
    }


def current_state_payload(
    config_path: str | os.PathLike[str] | None,
    document: dict[str, object] | None,
) -> dict[str, object]:
    """Payload for GET /api/wizard/current: the path the wizard would
    write, the seed document (or None), and whether writing is possible
    at all on this server."""
    return {
        "config_path": os.fspath(config_path) if config_path is not None else None,
        "document": document,
        "writable": config_path is not None,
    }
