#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
import json
import mimetypes
import tarfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


class FixtureRegistryHandler(BaseHTTPRequestHandler):
    ecosystem: str
    root: Path

    def do_GET(self) -> None:
        path = unquote(urlparse(self.path).path).strip("/")
        if self.ecosystem == "npm":
            self._handle_npm(path)
        elif self.ecosystem == "pypi":
            self._handle_pypi(path)
        else:
            self.send_error(500, "invalid fixture registry ecosystem")

    def log_message(self, format: str, *args: object) -> None:
        return

    def _handle_npm(self, path: str) -> None:
        if not path:
            self.send_error(404)
            return
        package_name = path.split("/-/", 1)[0]
        if "/-/" not in path:
            packument = self.root / "packuments" / f"{package_name}.json"
            self._send_file(packument, "application/json")
            return
        if path.endswith(".tgz"):
            self._send_npm_tarball()
            return
        self.send_error(404)

    def _send_npm_tarball(self) -> None:
        source_dir = self.root / "benign-package"
        if not source_dir.is_dir():
            self.send_error(404)
            return
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for item in source_dir.rglob("*"):
                archive.add(item, arcname=Path("package") / item.relative_to(source_dir))
        payload = buffer.getvalue()
        self._send_bytes(payload, "application/octet-stream")

    def _handle_pypi(self, path: str) -> None:
        if path.startswith("simple/"):
            parts = [part for part in path.split("/") if part]
            if len(parts) < 2:
                self.send_error(404)
                return
            project = parts[1]
            if path.endswith("index.v1.json"):
                self._send_file(self.root / "simple" / project / "index.v1.json", "application/vnd.pypi.simple.v1+json")
            else:
                self._send_file(self.root / "simple" / project / "index.html", "text/html")
            return
        if path.startswith("packages/") or path.startswith("provenance/"):
            self._send_file(self.root / path, mimetypes.guess_type(path)[0] or "application/octet-stream")
            return
        self.send_error(404)

    def _send_file(self, path: Path, content_type: str) -> None:
        resolved = path.resolve()
        if self.root.resolve() not in resolved.parents and resolved != self.root.resolve():
            self.send_error(403)
            return
        if not resolved.is_file():
            self.send_error(404)
            return
        self._send_bytes(resolved.read_bytes(), content_type)

    def _send_bytes(self, payload: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve Aegiscudo fixture registry testdata")
    parser.add_argument("--ecosystem", choices=("npm", "pypi"), required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    handler = type(
        "ConfiguredFixtureRegistryHandler",
        (FixtureRegistryHandler,),
        {"ecosystem": args.ecosystem, "root": args.root.resolve()},
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(json.dumps({"service": "fixture-registry", "ecosystem": args.ecosystem, "port": args.port}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()