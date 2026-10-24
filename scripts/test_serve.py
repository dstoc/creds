import unittest
from functools import partial
from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import urlopen

from serve import ProbeHandler, ROOT


class QuietProbeHandler(ProbeHandler):
    def log_message(self, format, *args):
        pass


class StaticServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            partial(QuietProbeHandler, directory=str(ROOT)),
        )
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_security_headers_and_javascript_module_mime_type(self):
        with urlopen(f"{self.base_url}/") as response:
            self.assertEqual(response.status, 200)
            self.assertIn("text/html", response.headers.get("Content-Type", ""))
            page = response.read().decode("utf-8")
            csp = response.headers["Content-Security-Policy"]

        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("style-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertNotIn("'unsafe-inline'", csp)
        self.assertNotIn("'unsafe-eval'", csp)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertIn('name="creds-dns-suffix"', page)

        with urlopen(f"{self.base_url}/js/main.mjs") as module:
            self.assertEqual(module.status, 200)
            self.assertTrue(
                module.headers.get("Content-Type", "").startswith("text/javascript"),
                module.headers.get("Content-Type"),
            )

    def test_missing_module_does_not_fall_back_to_html(self):
        with self.assertRaises(HTTPError) as raised:
            urlopen(f"{self.base_url}/js/missing.mjs")
        self.assertEqual(raised.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
