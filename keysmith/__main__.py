"""Command-line entry point: ``python -m keysmith``.

All startup output goes to stdout only — the diagnostics collector does not
exist yet at CLI startup time, and the package never writes to the standard
error stream.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import time
from collections.abc import Sequence

from . import __version__
from .config import ConfigError, load_config
from .redact import SecretVault
from .server import KeysmithServer
from .spendlog import SpendLog

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8317


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keysmith", description="Local BYOK OpenAI-compatible gateway"
    )
    parser.add_argument("--config", default="providers.json", help="path to providers.json")
    parser.add_argument("--spend-log", default="spend.jsonl", help="path to the JSONL spend log")
    parser.add_argument("--host", default=DEFAULT_HOST, help="bind host (default: loopback)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="bind port")
    args = parser.parse_args(argv)

    token = os.environ.get("KEYSMITH_TOKEN")
    if not token:
        print(
            "keysmith: KEYSMITH_TOKEN is not set. Export a local client token first "
            "(any long random string) — clients must send it as "
            "'Authorization: Bearer <KEYSMITH_TOKEN>'."
        )
        return 2

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"keysmith: invalid config {args.config!r}: {exc}")
        return 2

    if not _is_loopback(args.host):
        print(
            f"WARNING: {args.host!r} is not a loopback address. Anything that can "
            f"reach this host will be able to spend your configured keys."
        )

    vault = SecretVault()
    spend_log = SpendLog(args.spend_log)
    server = KeysmithServer(cfg, token, spend_log, vault, host=args.host, port=args.port)
    try:
        server.start()
    except OSError as exc:
        print(f"keysmith: cannot bind {args.host}:{args.port}: {exc}")
        return 2
    print(
        f"keysmith {__version__} listening on {server.url} "
        f"(config: {args.config}; spend log: {args.spend_log})"
    )
    print("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
