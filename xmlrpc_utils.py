# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

from __future__ import annotations

import os
import time
import xmlrpc.client


def _env_debug_enabled() -> bool:
    return os.getenv("SCM_NETWORK_DEBUG", "").lower() in {"1", "true", "yes", "on"}


_xmlrpc_debug = _env_debug_enabled()


def set_xmlrpc_debug(enabled: bool) -> None:
    global _xmlrpc_debug
    _xmlrpc_debug = enabled


def _print_xmlrpc(message: str) -> None:
    if not _xmlrpc_debug:
        return
    print(f"[xmlrpc] {message}", flush=True)


class LoggingSafeTransport(xmlrpc.client.SafeTransport):
    def request(self, host, handler, request_body, verbose=False):  # type: ignore[override]
        url = f"https://{host}{handler}"
        _print_xmlrpc(f"-> POST {url}")
        start = time.perf_counter()
        try:
            result = super().request(host, handler, request_body, verbose)
            elapsed = time.perf_counter() - start
            _print_xmlrpc(f"<- OK POST {url} ({elapsed:.2f}s)")
            return result
        except Exception as exc:
            elapsed = time.perf_counter() - start
            _print_xmlrpc(f"!! POST {url} failed after {elapsed:.2f}s: {exc}")
            raise


def build_server_proxy(url: str) -> xmlrpc.client.ServerProxy:
    return xmlrpc.client.ServerProxy(url, transport=LoggingSafeTransport())
