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

            with mock.patch("analyze_diff.requests.post") as post:
                post.return_value = _FakeResponse(
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
        post.assert_called_once()
        args, kwargs = post.call_args
        self.assertEqual(args[0], "http://mock-llm.local/v1/chat/completions")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-key")
        self.assertEqual(kwargs["json"]["model"], "mock-model")
        self.assertEqual(kwargs["json"]["messages"][0]["role"], "system")

    def test_openai_backend_uses_environment_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            diff_file = Path(tmpdir) / "env_diff.md"
            diff_file.write_text("# Diff Report\n\n+eval(payload)\n", encoding="utf-8")

            with mock.patch("analyze_diff.requests.post") as post:
                post.return_value = _FakeResponse(
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
        args, kwargs = post.call_args
        self.assertEqual(args[0], "http://env-llm.local/v1/chat/completions")
        self.assertEqual(kwargs["json"]["model"], "env-model")

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
