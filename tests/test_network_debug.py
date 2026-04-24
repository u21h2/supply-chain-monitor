from __future__ import annotations

import unittest
from unittest import mock

import http_utils
import xmlrpc_utils


class _FakeResponse:
    status_code = 200
    url = "https://example.test/data"
    headers: dict[str, str] = {}
    content = b"{}"

    def raise_for_status(self) -> None:
        return None


class NetworkDebugTests(unittest.TestCase):
    def setUp(self) -> None:
        http_utils.set_http_debug(False)
        xmlrpc_utils.set_xmlrpc_debug(False)

    def tearDown(self) -> None:
        http_utils.set_http_debug(False)
        xmlrpc_utils.set_xmlrpc_debug(False)

    def test_http_diagnostics_are_silent_by_default(self) -> None:
        with mock.patch("http_utils.requests.request", return_value=_FakeResponse()):
            with mock.patch("builtins.print") as print_mock:
                http_utils.request("GET", "https://example.test/data")

        print_mock.assert_not_called()

    def test_http_diagnostics_print_when_debug_enabled(self) -> None:
        http_utils.set_http_debug(True)

        with mock.patch("http_utils.requests.request", return_value=_FakeResponse()):
            with mock.patch("builtins.print") as print_mock:
                http_utils.request("GET", "https://example.test/data")

        self.assertGreaterEqual(print_mock.call_count, 2)
        self.assertIn("[http] -> GET", print_mock.call_args_list[0].args[0])
        self.assertIn("[http] <- 200 GET", print_mock.call_args_list[1].args[0])

    def test_xmlrpc_diagnostics_are_silent_by_default(self) -> None:
        with mock.patch("builtins.print") as print_mock:
            xmlrpc_utils._print_xmlrpc("-> POST https://example.test/pypi")

        print_mock.assert_not_called()

    def test_xmlrpc_diagnostics_print_when_debug_enabled(self) -> None:
        xmlrpc_utils.set_xmlrpc_debug(True)

        with mock.patch("builtins.print") as print_mock:
            xmlrpc_utils._print_xmlrpc("-> POST https://example.test/pypi")

        print_mock.assert_called_once()
        self.assertIn("[xmlrpc] -> POST", print_mock.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
