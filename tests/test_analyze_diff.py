from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import analyze_diff


class _FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> dict:
        return self._payload


class AnalyzeDiffTests(unittest.TestCase):
    def test_parse_verdict(self) -> None:
        verdict, analysis = analyze_diff.parse_verdict(
            "Verdict: malicious\nFound obfuscated downloader."
        )
        self.assertEqual(verdict, "malicious")
        self.assertIn("obfuscated downloader", analysis)

    def test_openai_backend_calls_chat_completions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            diff_file = Path(tmpdir) / "sample_diff.md"
            diff_file.write_text(
                "# Diff Report\n\n## Changed Files\n\n```diff\n+print('hello')\n```",
                encoding="utf-8",
            )

            with mock.patch("analyze_diff.http_request") as http_request:
                http_request.return_value = _FakeResponse(
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": "Verdict: benign\nLooks routine.",
                                }
                            }
                        ]
                    }
                )
                output = analyze_diff.run_diff_analysis(
                    diff_file,
                    backend="openai",
                    model="mock-model",
                    base_url="http://mock-llm.local",
                    api_key="test-key",
                )

        self.assertEqual(output, "Verdict: benign\nLooks routine.")
        http_request.assert_called_once()
        args, kwargs = http_request.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(args[1], "http://mock-llm.local/v1/chat/completions")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-key")
        self.assertEqual(kwargs["json_body"]["model"], "mock-model")
        self.assertEqual(kwargs["json_body"]["messages"][0]["role"], "system")

    def test_openai_backend_uses_environment_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            diff_file = Path(tmpdir) / "env_diff.md"
            diff_file.write_text("# Diff Report\n\n+eval(payload)\n", encoding="utf-8")

            with mock.patch("analyze_diff.http_request") as http_request:
                http_request.return_value = _FakeResponse(
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": "Verdict: malicious\nSuspicious loader added.",
                                }
                            }
                        ]
                    }
                )
                with mock.patch.dict(
                    os.environ,
                    {
                        "SCM_LLM_BACKEND": "openai",
                        "OPENAI_BASE_URL": "http://env-llm.local",
                        "OPENAI_MODEL": "env-model",
                    },
                    clear=False,
                ):
                    output = analyze_diff.run_diff_analysis(diff_file)

        verdict, _ = analyze_diff.parse_verdict(output)
        self.assertEqual(verdict, "malicious")
        args, kwargs = http_request.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(args[1], "http://env-llm.local/v1/chat/completions")
        self.assertEqual(kwargs["json_body"]["model"], "env-model")

    def test_openai_backend_retries_failed_requests(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            diff_file = Path(tmpdir) / "retry_diff.md"
            diff_file.write_text("# Diff Report\n\n+print('retry')\n", encoding="utf-8")

            with mock.patch("analyze_diff.http_request") as http_request:
                http_request.side_effect = [
                    RuntimeError("temporary outage"),
                    _FakeResponse(
                        {
                            "choices": [
                                {
                                    "message": {
                                        "content": "Verdict: benign\nRecovered.",
                                    }
                                }
                            ]
                        }
                    ),
                ]
                with mock.patch("analyze_diff.time.sleep") as sleep:
                    output = analyze_diff.run_diff_analysis(
                        diff_file,
                        backend="openai",
                        model="mock-model",
                        base_url="http://retry-llm.local",
                        api_key="test-key",
                    )

        self.assertEqual(output, "Verdict: benign\nRecovered.")
        self.assertEqual(http_request.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_openai_backend_respects_retry_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            diff_file = Path(tmpdir) / "retry_limit_diff.md"
            diff_file.write_text("# Diff Report\n\n+print('fail')\n", encoding="utf-8")

            with mock.patch("analyze_diff.http_request") as http_request:
                http_request.side_effect = RuntimeError("still down")
                with mock.patch("analyze_diff.time.sleep") as sleep:
                    with mock.patch.dict(
                        os.environ,
                        {"SCM_LLM_MAX_ATTEMPTS": "2"},
                        clear=False,
                    ):
                        with self.assertRaisesRegex(RuntimeError, "2 attempt"):
                            analyze_diff.run_diff_analysis(
                                diff_file,
                                backend="openai",
                                model="mock-model",
                                base_url="http://retry-llm.local",
                                api_key="test-key",
                            )

        self.assertEqual(http_request.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_default_openai_endpoint_requires_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            diff_file = Path(tmpdir) / "missing_key.md"
            diff_file.write_text("# Diff Report\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "OPENAI_API_KEY"):
                analyze_diff.run_diff_analysis(
                    diff_file,
                    backend="openai",
                    base_url="https://api.openai.com/v1",
                    api_key="",
                )


if __name__ == "__main__":
    unittest.main()
