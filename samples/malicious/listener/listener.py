"""
Test listener for Aegiscudo malicious fixture exfiltration.

Starts an HTTP server on localhost:9999 and prints every request body to stdout
so you can verify what a malicious package would have exfiltrated.

Usage:
    python samples/malicious/listener/listener.py
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class ExfilHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        print("\n=== EXFIL RECEIVED ===")
        print(f"Path : {self.path}")
        print(f"From : {self.client_address}")
        try:
            parsed = json.loads(body)
            print(json.dumps(parsed, indent=2))
        except Exception:
            print(body.decode(errors="replace"))
        print("======================\n")
        self.send_response(204)
        self.end_headers()

    def log_message(self, fmt, *args):  # silence default access log
        pass


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 9999), ExfilHandler)
    print("Aegiscudo exfil listener — http://localhost:9999  (Ctrl-C to stop)")
    server.serve_forever()
