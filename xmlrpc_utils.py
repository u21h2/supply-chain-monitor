# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

from __future__ import annotations

import time
import xmlrpc.client


class LoggingSafeTransport(xmlrpc.client.SafeTransport):
    def request(self, host, handler, request_body, verbose=False):  # type: ignore[override]
        url = f"https://{host}{handler}"
        print(f"[xmlrpc] -> POST {url}", flush=True)
        start = time.perf_counter()
        try:
            result = super().request(host, handler, request_body, verbose)
            elapsed = time.perf_counter() - start
            print(f"[xmlrpc] <- OK POST {url} ({elapsed:.2f}s)", flush=True)
            return result
        except Exception as exc:
            elapsed = time.perf_counter() - start
            print(f"[xmlrpc] !! POST {url} failed after {elapsed:.2f}s: {exc}", flush=True)
            raise


def build_server_proxy(url: str) -> xmlrpc.client.ServerProxy:
    return xmlrpc.client.ServerProxy(url, transport=LoggingSafeTransport())
