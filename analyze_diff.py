# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

"""
Analyze a package diff report for supply chain compromise using an LLM backend.

Defaults to an OpenAI-compatible Chat Completions API, with Cursor Agent CLI
available as an optional backend.

Usage:
    python analyze_diff.py <diff_file>
    python analyze_diff.py telnyx_diff.md
    python analyze_diff.py telnyx_diff.md --model gpt-4.1-mini
    python analyze_diff.py telnyx_diff.md --backend cursor --model claude-4-opus
    python analyze_diff.py telnyx_diff.md --json

Can also be chained with package_diff.py:
    python package_diff.py requests 2.31.0 2.32.0 -o diff.md && python analyze_diff.py diff.md
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from http_utils import request as http_request

log = logging.getLogger("monitor.analyze")

OPENAI_BACKEND = "openai"
CURSOR_BACKEND = "cursor"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
DEFAULT_OPENAI_MODEL = "gpt-4.1-mini"
DEFAULT_CURSOR_MODEL = "composer-2-fast"
DEFAULT_DIFF_CHAR_LIMIT = 300000
DEFAULT_LLM_MAX_ATTEMPTS = 3

INSTRUCTIONS_TEMPLATE = """\
# Supply Chain Diff Review

Review the diff report for `{diff_name}` and determine if the changes are
highly likely to show evidence of a supply chain compromise.

## Response format

Start your response with exactly one of these lines:

    Verdict: malicious
    Verdict: benign

Then explain your reasoning briefly.

## What to look for

- Obfuscated code (base64, exec, eval, XOR, encoded strings)
- Network calls to unexpected hosts (non-package-related URLs)
- File system writes to startup/persistence locations
- Process spawning, shell commands
- Steganography or data hiding in media files
- Credential/token exfiltration
- Typosquatting indicators
- Suspicious npm lifecycle scripts (preinstall, install, postinstall) in package.json
- Dynamic require() or import() of obfuscated or encoded URLs
- Minified or bundled payloads added outside normal build artifacts

Only report "malicious" if you are highly confident malicious code has been added.
"""


def _env(*names: str, default: str | None = None) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return default


def _default_backend() -> str:
    return (_env("SCM_LLM_BACKEND", default=OPENAI_BACKEND) or OPENAI_BACKEND).lower()


def _default_model(backend: str) -> str:
    if backend == CURSOR_BACKEND:
        return _env("SCM_CURSOR_MODEL", default=DEFAULT_CURSOR_MODEL) or DEFAULT_CURSOR_MODEL
    return (
        _env("SCM_OPENAI_MODEL", "OPENAI_MODEL", default=DEFAULT_OPENAI_MODEL)
        or DEFAULT_OPENAI_MODEL
    )


def _default_openai_base_url() -> str:
    return (
        _env("SCM_OPENAI_BASE_URL", "OPENAI_BASE_URL", default=DEFAULT_OPENAI_BASE_URL)
        or DEFAULT_OPENAI_BASE_URL
    )


def _default_openai_api_key() -> str | None:
    return _env("SCM_OPENAI_API_KEY", "OPENAI_API_KEY")


def _diff_char_limit() -> int:
    raw_value = _env("SCM_DIFF_CHAR_LIMIT", default=str(DEFAULT_DIFF_CHAR_LIMIT))
    try:
        return max(0, int(raw_value or DEFAULT_DIFF_CHAR_LIMIT))
    except ValueError:
        return DEFAULT_DIFF_CHAR_LIMIT


def _llm_max_attempts() -> int:
    raw_value = _env("SCM_LLM_MAX_ATTEMPTS", default=str(DEFAULT_LLM_MAX_ATTEMPTS))
    try:
        return max(1, int(raw_value or DEFAULT_LLM_MAX_ATTEMPTS))
    except ValueError:
        return DEFAULT_LLM_MAX_ATTEMPTS


def _normalize_backend(backend: str | None) -> str:
    resolved = (backend or _default_backend()).strip().lower()
    if resolved not in {OPENAI_BACKEND, CURSOR_BACKEND}:
        raise ValueError(f"Unsupported backend: {backend}")
    return resolved


def _find_agent() -> str:
    agent = shutil.which("agent")
    if agent:
        return agent
    if platform.system() == "Windows":
        candidate = Path.home() / "AppData/Local/cursor-agent/agent.cmd"
        if candidate.exists():
            return str(candidate)
    raise FileNotFoundError(
        "Cursor Agent CLI not found. Install it or switch to --backend openai."
    )


def _chat_completions_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    if normalized.endswith("/v1"):
        return f"{normalized}/chat/completions"
    return f"{normalized}/v1/chat/completions"


def _excerpt_diff(diff_text: str) -> tuple[str, bool]:
    limit = _diff_char_limit()
    if limit <= 0 or len(diff_text) <= limit:
        return diff_text, False

    head_size = max(1, int(limit * 0.7))
    tail_size = max(1, limit - head_size)
    excerpt = (
        diff_text[:head_size]
        + "\n\n[... diff truncated to fit LLM request size ...]\n\n"
        + diff_text[-tail_size:]
    )
    return excerpt, True


def _build_openai_messages(diff_file: Path) -> list[dict[str, str]]:
    diff_text = diff_file.read_text(encoding="utf-8", errors="replace")
    diff_excerpt, truncated = _excerpt_diff(diff_text)
    truncation_note = ""
    if truncated:
        truncation_note = (
            "\n\nNote: the diff was truncated to fit the configured request size. "
            "Be explicit when the available evidence is insufficient."
        )

    return [
        {
            "role": "system",
            "content": INSTRUCTIONS_TEMPLATE.format(diff_name=diff_file.name),
        },
        {
            "role": "user",
            "content": (
                f"Review this package diff report from `{diff_file.name}`."
                f"{truncation_note}\n\n```diff\n{diff_excerpt}\n```"
            ),
        },
    ]


def _coerce_choice_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if not isinstance(item, dict):
                continue
            text = item.get("text")
            if isinstance(text, str):
                parts.append(text)
                continue
            nested_text = item.get("content")
            if isinstance(nested_text, str):
                parts.append(nested_text)
        return "\n".join(part for part in parts if part)
    return ""


def _extract_chat_output(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""

    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        return ""

    message = first_choice.get("message")
    if isinstance(message, dict):
        content = _coerce_choice_text(message.get("content"))
        if content:
            return content

    text = first_choice.get("text")
    if isinstance(text, str):
        return text

    delta = first_choice.get("delta")
    if isinstance(delta, dict):
        content = _coerce_choice_text(delta.get("content"))
        if content:
            return content

    return ""


def run_openai_compatible(
    diff_file: Path,
    model: str | None = None,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
) -> str:
    resolved_model = model or _default_model(OPENAI_BACKEND)
    resolved_base_url = base_url or _default_openai_base_url()
    resolved_api_key = api_key if api_key is not None else _default_openai_api_key()

    if not resolved_model:
        raise ValueError("No model configured for the OpenAI-compatible backend.")

    normalized_base = resolved_base_url.rstrip("/")
    if not resolved_api_key and normalized_base in {
        "https://api.openai.com",
        "https://api.openai.com/v1",
    }:
        raise ValueError(
            "OPENAI_API_KEY is required when using the default OpenAI API endpoint."
        )

    headers = {"Content-Type": "application/json"}
    if resolved_api_key:
        headers["Authorization"] = f"Bearer {resolved_api_key}"

    payload = {
        "model": resolved_model,
        "messages": _build_openai_messages(diff_file),
        "temperature": 0,
    }
    url = _chat_completions_url(resolved_base_url)
    max_attempts = _llm_max_attempts()
    last_error: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            log.debug(
                "POST %s with model=%s (attempt %d/%d)",
                url,
                resolved_model,
                attempt,
                max_attempts,
            )
            print(
                f"[*] LLM request attempt {attempt}/{max_attempts} "
                f"(backend=openai, model={resolved_model})",
                file=sys.stderr,
            )
            response = http_request(
                "POST",
                url,
                headers=headers,
                json_body=payload,
                timeout=(10, 300),
            )
            log.debug("OpenAI-compatible status=%s", response.status_code)

            data = response.json()
            output = _extract_chat_output(data)
            if output:
                return output
            raise RuntimeError("OpenAI-compatible API returned no message content.")
        except Exception as exc:
            last_error = exc
            if attempt >= max_attempts:
                break
            wait_seconds = min(2 ** (attempt - 1), 8)
            log.warning(
                "OpenAI-compatible request attempt %d/%d failed: %s; retrying in %ss",
                attempt,
                max_attempts,
                exc,
                wait_seconds,
            )
            print(
                f"[*] LLM request attempt {attempt}/{max_attempts} failed: {exc}; "
                f"retrying in {wait_seconds}s",
                file=sys.stderr,
            )
            time.sleep(wait_seconds)

    raise RuntimeError(
        f"OpenAI-compatible API failed after {max_attempts} attempt(s): {last_error}"
    )


def run_cursor_agent(diff_file: Path, model: str | None = None) -> str:
    agent_bin = _find_agent()
    workspace = diff_file.parent.resolve()

    instructions = workspace / "instructions.md"
    instructions.write_text(
        INSTRUCTIONS_TEMPLATE.format(diff_name=diff_file.name),
        encoding="utf-8",
    )

    cmd_parts = [
        agent_bin,
        "Follow instructions.md",
        "-p",
        "--mode",
        "ask",
        "--trust",
        "--workspace",
        str(workspace),
    ]
    resolved_model = model or _default_model(CURSOR_BACKEND)
    if resolved_model:
        cmd_parts.extend(["--model", resolved_model])

    result = subprocess.run(
        cmd_parts,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )

    log.debug("Agent stdout:\n%s", result.stdout or "(empty)")
    log.debug("Agent stderr:\n%s", result.stderr or "(empty)")

    if result.returncode != 0:
        log.error("Cursor agent exited %d: %s", result.returncode, result.stderr)
        return ""

    return result.stdout or ""


def run_diff_analysis(
    diff_file: Path,
    *,
    backend: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> str:
    resolved_backend = _normalize_backend(backend)
    if resolved_backend == CURSOR_BACKEND:
        return run_cursor_agent(diff_file, model=model)
    return run_openai_compatible(
        diff_file,
        model=model,
        base_url=base_url,
        api_key=api_key,
    )


def parse_verdict(output: str) -> tuple[str, str]:
    """Extract verdict and reasoning from LLM output."""
    verdict = "unknown"
    match = re.search(r"[Vv]erdict:\s*(malicious|benign)", output, re.IGNORECASE)
    if match:
        verdict = match.group(1).lower()
    return verdict, output.strip()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a package diff for supply chain compromise via an LLM backend",
    )
    parser.add_argument(
        "diff_file",
        type=Path,
        help="Path to diff markdown file (from package_diff.py)",
    )
    parser.add_argument(
        "--backend",
        choices=(OPENAI_BACKEND, CURSOR_BACKEND),
        default=_default_backend(),
        help=f"LLM backend to use (default: {_default_backend()})",
    )
    parser.add_argument("--model", help="Model to use (backend-specific default if omitted)")
    parser.add_argument(
        "--base-url",
        help="Base URL for the OpenAI-compatible API (defaults to OPENAI_BASE_URL)",
    )
    parser.add_argument(
        "--api-key",
        help="API key for the OpenAI-compatible API (defaults to OPENAI_API_KEY)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output as JSON",
    )
    args = parser.parse_args()

    if not args.diff_file.exists():
        parser.error(f"File not found: {args.diff_file}")

    print(
        f"[*] Analyzing {args.diff_file.name} with {args.backend} backend...",
        file=sys.stderr,
    )

    raw_output = run_diff_analysis(
        args.diff_file,
        backend=args.backend,
        model=args.model,
        base_url=args.base_url,
        api_key=args.api_key,
    )
    verdict, analysis = parse_verdict(raw_output)

    if args.json_output:
        print(
            json.dumps(
                {
                    "file": str(args.diff_file),
                    "backend": args.backend,
                    "verdict": verdict,
                    "analysis": analysis,
                },
                indent=2,
            )
        )
    else:
        print(f"\n{'=' * 60}")
        print(f"  FILE:    {args.diff_file.name}")
        print(f"  BACKEND: {args.backend}")
        print(f"  VERDICT: {verdict.upper()}")
        print(f"{'=' * 60}")
        print(f"\n{analysis}")

    sys.exit(0 if verdict == "benign" else 1 if verdict == "malicious" else 2)


if __name__ == "__main__":
    main()
