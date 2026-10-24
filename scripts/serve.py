#!/usr/bin/env python3
"""Serve the local browser probe on loopback with its restrictive response headers."""

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "web"


class ProbeHandler(SimpleHTTPRequestHandler):
    extensions_map = {**SimpleHTTPRequestHandler.extensions_map, ".mjs": "text/javascript"}

    def end_headers(self):
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
            "img-src 'self' data:; script-src 'self'; style-src 'self'; "
            "connect-src 'self' https://127.0.0.1:*; object-src 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()


def main():
    handler = partial(ProbeHandler, directory=str(ROOT))
    with ThreadingHTTPServer(("127.0.0.1", 8000), handler) as server:
        print("Serving the local probe at http://localhost:8000 (loopback only). Ctrl-C stops it.")
        server.serve_forever()


if __name__ == "__main__":
    main()
