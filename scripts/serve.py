#!/usr/bin/env python3
"""Serve local static files on loopback with restrictive headers."""

from functools import partial
import argparse
import ssl
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "web"


class StaticHandler(SimpleHTTPRequestHandler):
    extensions_map = {**SimpleHTTPRequestHandler.extensions_map, ".mjs": "text/javascript"}

    def end_headers(self):
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
            "img-src 'self' data:; script-src 'self'; style-src 'self'; "
            "connect-src https:; object-src 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--root", type=Path, default=ROOT, help="directory to serve (defaults to web/)")
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    arguments = parser.parse_args()
    if (arguments.tls_cert is None) != (arguments.tls_key is None):
        parser.error("--tls-cert and --tls-key must be used together")

    handler = partial(StaticHandler, directory=str(arguments.root.resolve()))
    with ThreadingHTTPServer(("127.0.0.1", arguments.port), handler) as server:
        scheme = "https" if arguments.tls_cert else "http"
        if arguments.tls_cert:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(arguments.tls_cert, arguments.tls_key)
            server.socket = tls_context.wrap_socket(server.socket, server_side=True)
        print(f"Serving {arguments.root.resolve()} at {scheme}://localhost:{arguments.port} (loopback only). Ctrl-C stops it.")
        server.serve_forever()


if __name__ == "__main__":
    main()
