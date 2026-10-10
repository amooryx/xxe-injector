import io
import json
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import xxe_injector


class FixtureHandler(BaseHTTPRequestHandler):
    request_count = 0
    request_body = b""
    request_headers = {}
    response_body = b'{"accepted": true}'
    response_status = 200
    redirect_location = None

    def do_POST(self):
        type(self).request_count += 1
        length = int(self.headers.get("Content-Length", "0"))
        type(self).request_body = self.rfile.read(length)
        type(self).request_headers = dict(self.headers.items())
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", self.redirect_location)
            self.end_headers()
            return
        self.send_response(type(self).response_status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(type(self).response_body)

    def log_message(self, format, *args):
        pass


class SafeBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()

    def setUp(self):
        FixtureHandler.request_count = 0
        FixtureHandler.request_body = b""
        FixtureHandler.request_headers = {}
        FixtureHandler.response_body = b'{"accepted": true}'
        FixtureHandler.response_status = 200

    def test_posts_only_the_fixed_benign_xml_and_reports_limited_observation(self):
        report = xxe_injector.run_check(self.base_url + "/xml", {}, 1)

        self.assertEqual(FixtureHandler.request_count, 1)
        self.assertEqual(FixtureHandler.request_body, xxe_injector.SAFE_XML)
        self.assertNotIn(b"<!DOCTYPE", FixtureHandler.request_body.upper())
        self.assertNotIn(b"<!ENTITY", FixtureHandler.request_body.upper())
        request_headers = {name.lower(): value for name, value in FixtureHandler.request_headers.items()}
        self.assertEqual(request_headers["content-type"], "application/xml")
        self.assertEqual(report["request_count"], 1)
        self.assertEqual(report["observation"]["status_code"], 200)
        self.assertEqual(report["observation"]["response_excerpt"], '{"accepted": true}')
        self.assertIn("does not test or prove", report["conclusion"])

    def test_response_body_is_bounded(self):
        FixtureHandler.response_body = b"x" * (xxe_injector.MAX_RESPONSE_BYTES + 100)

        report = xxe_injector.run_check(self.base_url, {}, 1)

        self.assertEqual(len(report["observation"]["response_excerpt"]), xxe_injector.MAX_RESPONSE_BYTES)
        self.assertTrue(report["observation"]["response_truncated"])

    def test_redirect_is_reported_without_following_it(self):
        FixtureHandler.redirect_location = self.base_url + "/elsewhere"

        report = xxe_injector.run_check(self.base_url + "/redirect", {}, 1)

        self.assertEqual(FixtureHandler.request_count, 1)
        self.assertEqual(report["observation"]["status_code"], 302)
        self.assertEqual(report["limits"]["redirects_followed"], 0)

    def test_http_error_response_is_recorded_as_observation(self):
        FixtureHandler.response_status = 415
        FixtureHandler.response_body = b"unsupported media type"

        report = xxe_injector.run_check(self.base_url, {}, 1)

        self.assertEqual(report["observation"]["status_code"], 415)
        self.assertEqual(report["observation"]["response_excerpt"], "unsupported media type")

    def test_rejects_non_http_target_credentials_and_fragment(self):
        for url in (
            "file:///tmp/example.xml",
            "http://user:pass@127.0.0.1/",
            self.base_url + "/path#fragment",
            self.base_url + "/" + "x" * xxe_injector.MAX_URL_BYTES,
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                xxe_injector.validate_target(url)

    def test_timeout_and_headers_have_explicit_bounds(self):
        with self.assertRaises(ValueError):
            xxe_injector.run_check(self.base_url, {}, xxe_injector.MAX_TIMEOUT_SECONDS + 1)
        with self.assertRaises(ValueError):
            xxe_injector.parse_headers(["Host: attacker.example"])
        with self.assertRaises(ValueError):
            xxe_injector.parse_headers(["X-Test: good\r\nHost: attacker.example"])
        with self.assertRaises(ValueError):
            xxe_injector.parse_headers(["X-Test: one", "x-test: two"])

    def test_cli_requires_consent_and_exact_scope_before_network_use(self):
        with patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                xxe_injector.main([
                    self.base_url, "--authorized-target", self.base_url,
                ])
        with patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                xxe_injector.main([
                    self.base_url, "--authorized-target", self.base_url + "/different",
                    "--i-have-authorization",
                ])
        self.assertEqual(FixtureHandler.request_count, 0)

    def test_cli_runs_one_scoped_request_and_emits_json_observation(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = xxe_injector.main([
                self.base_url,
                "--authorized-target", self.base_url,
                "--i-have-authorization",
            ])

        report = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(FixtureHandler.request_count, 1)
        self.assertEqual(report["target"], self.base_url)
        self.assertEqual(report["observation"]["status_code"], 200)


if __name__ == "__main__":
    unittest.main()
