#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import mimetypes
import tomllib
import tarfile
from typing import Any
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


class FixtureRegistryHandler(BaseHTTPRequestHandler):
    ecosystem: str
    root: Path

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path).strip("/")
        if self.ecosystem == "npm":
            self._handle_npm(path)
        elif self.ecosystem == "pypi":
            self._handle_pypi(path)
        elif self.ecosystem == "cargo":
            self._handle_cargo(path, parsed.query)
        elif self.ecosystem == "maven":
            self._handle_maven(path)
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
            base_url = fixture_registry_base_url(self.headers.get("host"))
            payload = render_npm_packument(self.root, packument, base_url)
            self._send_bytes(payload, "application/json")
            return
        if path.endswith(".tgz"):
            self._send_npm_tarball(path)
            return
        self.send_error(404)

    def _send_npm_tarball(self, path: str) -> None:
        package_name, version = parse_npm_tarball_request(path)
        try:
            payload = build_npm_tarball(self.root, package_name, version)
        except FileNotFoundError:
            self.send_error(404)
            return
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

    def _handle_cargo(self, path: str, query: str) -> None:
        if path == "config.json":
            self._send_bytes(render_cargo_registry_config(), "application/json")
            return

        parts = [part for part in path.split("/") if part]
        if parts[:3] == ["api", "v1", "crates"]:
            if len(parts) == 3:
                params = parse_qs(query)
                search_query = params.get("q", [""])[0]
                per_page = int(params.get("per_page", ["10"])[0])
                payload = render_cargo_search_results(self.root, search_query, per_page)
                self._send_bytes(payload, "application/json")
                return
            if len(parts) == 6 and parts[5] == "download":
                self._send_cargo_crate(parts[3], parts[4])
                return
            self.send_error(404)
            return

        crate_name = parse_cargo_sparse_index_request(self.root, path)
        if crate_name is None:
            self.send_error(404)
            return
        payload = render_cargo_sparse_index(self.root, crate_name)
        self._send_bytes(payload, "application/vnd.rust.crate-index")

    def _handle_maven(self, path: str) -> None:
        if not path:
            self.send_error(404)
            return
        self._send_file(self.root / path, mimetypes.guess_type(path)[0] or "application/octet-stream")

    def _send_cargo_crate(self, crate_name: str, version: str) -> None:
        try:
            payload = build_cargo_crate(self.root, crate_name, version)
        except FileNotFoundError:
            self.send_error(404)
            return
        self._send_bytes(payload, "application/octet-stream")

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
    parser.add_argument("--ecosystem", choices=("npm", "pypi", "cargo", "maven"), required=True)
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


def fixture_registry_base_url(host: str | None) -> str:
    return f"http://{host}" if host else "http://127.0.0.1"


def render_cargo_registry_config() -> bytes:
    return json.dumps({"dl": "api/v1/crates", "api": "."}).encode()


def render_cargo_search_results(root: Path, query: str, per_page: int) -> bytes:
    query = query.strip().lower()
    crates: list[dict[str, Any]] = []
    for package in list_cargo_fixture_packages(root):
        name = package["name"].lower()
        description = (package.get("description") or "").lower()
        if query and query not in name and query not in description:
            continue
        crates.append(
            {
                "name": package["name"],
                "max_version": package["version"],
                "description": package.get("description") or "",
            }
        )
    crates = crates[: max(per_page, 0)]
    return json.dumps({"crates": crates, "meta": {"total": len(crates)}}).encode()


def render_cargo_sparse_index(root: Path, crate_name: str) -> bytes:
    package = cargo_fixture_package(root, crate_name)
    crate_bytes = build_cargo_crate(root, package["name"], package["version"])
    entry = {
        "name": package["name"],
        "vers": package["version"],
        "deps": [],
        "cksum": hashlib.sha256(crate_bytes).hexdigest(),
        "features": {},
        "yanked": False,
        "links": None,
    }
    return (json.dumps(entry) + "\n").encode()


def build_cargo_crate(root: Path, crate_name: str, version: str) -> bytes:
    package = cargo_fixture_package(root, crate_name)
    if package["version"] != version:
        raise FileNotFoundError(version)
    source_dir = resolve_cargo_package_source_dir(root, crate_name)

    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            crate_root = Path(f"{crate_name}-{version}")
            for item in sorted(source_dir.rglob("*")):
                if not item.is_file():
                    continue
                archive.add(
                    item,
                    arcname=crate_root / item.relative_to(source_dir),
                    filter=_normalize_tarinfo,
                )

    return buffer.getvalue()


def parse_cargo_sparse_index_request(root: Path, path: str) -> str | None:
    for package in list_cargo_fixture_packages(root):
        if path == cargo_sparse_index_path(package["name"]):
            return package["name"]
    return None


def cargo_sparse_index_path(crate_name: str) -> str:
    if len(crate_name) == 1:
        return f"1/{crate_name}"
    if len(crate_name) == 2:
        return f"2/{crate_name}"
    if len(crate_name) == 3:
        return f"3/{crate_name[:1]}/{crate_name}"
    return f"{crate_name[:2]}/{crate_name[2:4]}/{crate_name}"


def list_cargo_fixture_packages(root: Path) -> list[dict[str, str]]:
    package_sources = root / "package-sources"
    if not package_sources.is_dir():
        return []

    packages: list[dict[str, str]] = []
    for source_dir in sorted(package_sources.iterdir()):
        if not source_dir.is_dir():
            continue
        package = cargo_fixture_package(root, source_dir.name)
        packages.append(package)
    return packages


def cargo_fixture_package(root: Path, crate_name: str) -> dict[str, str]:
    source_dir = resolve_cargo_package_source_dir(root, crate_name)
    manifest_path = source_dir / "Cargo.toml"
    if not manifest_path.is_file():
        raise FileNotFoundError(manifest_path)

    manifest = tomllib.loads(manifest_path.read_text())
    package = manifest.get("package") or {}
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise FileNotFoundError(manifest_path)

    description = package.get("description")
    return {
        "name": name,
        "version": version,
        "description": description if isinstance(description, str) else "",
    }


def resolve_cargo_package_source_dir(root: Path, crate_name: str) -> Path:
    source_dir = root / "package-sources" / crate_name
    if source_dir.is_dir():
        return source_dir
    raise FileNotFoundError(source_dir)


def parse_npm_tarball_request(path: str) -> tuple[str, str]:
    package_name, tarball_name = path.split("/-/", 1)
    filename = Path(tarball_name).name
    package_leaf = package_name.rsplit("/", 1)[-1]
    prefix = f"{package_leaf}-"
    if not filename.startswith(prefix) or not filename.endswith(".tgz"):
        raise FileNotFoundError(path)
    version = filename.removeprefix(prefix).removesuffix(".tgz")
    if not version:
        raise FileNotFoundError(path)
    return package_name, version


def render_npm_packument(root: Path, packument_path: Path, base_url: str) -> bytes:
    packument = json.loads(packument_path.read_text())
    package_name = packument["name"]
    for version, payload in packument.get("versions", {}).items():
        tarball = build_npm_tarball(root, package_name, version)
        dist = payload.setdefault("dist", {})
        dist["tarball"] = f"{base_url}/{package_name}/-/{package_name.split('/')[-1]}-{version}.tgz"
        dist["shasum"] = hashlib.sha1(tarball).hexdigest()
        dist["integrity"] = f"sha512-{base64.b64encode(hashlib.sha512(tarball).digest()).decode()}"
    return json.dumps(packument).encode()


def build_npm_tarball(root: Path, package_name: str, version: str) -> bytes:
    source_dir = resolve_npm_package_source_dir(root, package_name)

    package_json_path = source_dir / "package.json"
    package_json = json.loads(package_json_path.read_text())
    package_json["name"] = package_name
    package_json["version"] = version
    package_json_bytes = (json.dumps(package_json, indent=2) + "\n").encode()

    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            package_info = tarfile.TarInfo("package/package.json")
            package_info.size = len(package_json_bytes)
            package_info.mtime = 0
            package_info.mode = 0o644
            archive.addfile(package_info, io.BytesIO(package_json_bytes))

            for item in sorted(source_dir.rglob("*")):
                if item == package_json_path:
                    continue
                arcname = Path("package") / item.relative_to(source_dir)
                archive.add(item, arcname=arcname, filter=_normalize_tarinfo)

    return buffer.getvalue()


def resolve_npm_package_source_dir(root: Path, package_name: str) -> Path:
    explicit_source = root / "package-sources" / package_name.replace("/", "__")
    if explicit_source.is_dir():
        return explicit_source

    fallback_source = root / "benign-package"
    if fallback_source.is_dir():
        return fallback_source

    raise FileNotFoundError(fallback_source)


def _normalize_tarinfo(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info


if __name__ == "__main__":
    main()