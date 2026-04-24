# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import requests  # type: ignore[import-untyped]


def _env_debug_enabled() -> bool:
    return os.getenv("SCM_NETWORK_DEBUG", "").lower() in {"1", "true", "yes", "on"}


_http_debug = _env_debug_enabled()


def set_http_debug(enabled: bool) -> None:
    global _http_debug
    _http_debug = enabled


def _print_http(message: str) -> None:
    if not _http_debug:
        return
    print(f"[http] {message}", flush=True)


def request(
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    data: Any = None,
    json_body: Any = None,
    files: Any = None,
    timeout: float | tuple[float, float] = 30,
    stream: bool = False,
) -> requests.Response:
    method = method.upper()
    _print_http(f"-> {method} {url}")
    start = time.perf_counter()
    try:
        response = requests.request(
            method,
            url,
            params=params,
            headers=headers,
            data=data,
            json=json_body,
            files=files,
            timeout=timeout,
            stream=stream,
        )
        elapsed = time.perf_counter() - start
        if stream:
            size_hint = response.headers.get("Content-Length", "?")
            if isinstance(size_hint, str) and size_hint.isdigit():
                size_hint = f"{int(size_hint):,}"
        else:
            size_hint = f"{len(response.content):,}"
        _print_http(
            f"<- {response.status_code} {method} {response.url} ({elapsed:.2f}s, {size_hint} bytes)"
        )
        response.raise_for_status()
        return response
    except Exception as exc:
        elapsed = time.perf_counter() - start
        _print_http(f"!! {method} {url} failed after {elapsed:.2f}s: {exc}")
        raise


def get_json(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float | tuple[float, float] = 30,
) -> Any:
    response = request(
        "GET",
        url,
        params=params,
        headers=headers,
        timeout=timeout,
    )
    return response.json()


def download_file(
    url: str,
    dest: Path,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float | tuple[float, float] = 60,
    chunk_size: int = 1024 * 1024,
) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    response = request(
        "GET",
        url,
        params=params,
        headers=headers,
        timeout=timeout,
        stream=True,
    )
    written = 0
    try:
        with dest.open("wb") as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if not chunk:
                    continue
                f.write(chunk)
                written += len(chunk)
    finally:
        response.close()

    _print_http(f".. saved {dest} ({written:,} bytes)")
    return dest
