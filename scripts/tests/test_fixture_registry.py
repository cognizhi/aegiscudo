from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import fixture_registry


def test_render_npm_packument_rewrites_tarball_host_and_hashes() -> None:
    root = ROOT / "testdata" / "npm"
    packument = root / "packuments" / "aegiscudo-benign-npm-fixture.json"

    payload = fixture_registry.render_npm_packument(
        root,
        packument,
        "http://127.0.0.1:18080",
    )

    rendered = json.loads(payload)
    version = rendered["versions"]["1.0.0"]["dist"]
    tarball = fixture_registry.build_npm_tarball(root, rendered["name"], "1.0.0")

    assert version["tarball"] == (
        "http://127.0.0.1:18080/aegiscudo-benign-npm-fixture/-/"
        "aegiscudo-benign-npm-fixture-1.0.0.tgz"
    )
    assert version["shasum"] == fixture_registry.hashlib.sha1(tarball).hexdigest()
    assert version["integrity"].startswith("sha512-")
    assert "AAAA" not in version["integrity"]


def test_build_npm_tarball_sets_requested_version_in_package_json() -> None:
    root = ROOT / "testdata" / "npm"

    tarball = fixture_registry.build_npm_tarball(
        root,
        "aegiscudo-benign-npm-fixture",
        "1.2.0",
    )

    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        package_json = json.loads(
            archive.extractfile("package/package.json").read().decode()
        )

    assert package_json["name"] == "aegiscudo-benign-npm-fixture"
    assert package_json["version"] == "1.2.0"


def test_build_npm_tarball_is_gzip_deterministic() -> None:
    root = ROOT / "testdata" / "npm"

    tarball = fixture_registry.build_npm_tarball(
        root,
        "aegiscudo-benign-npm-fixture",
        "1.0.0",
    )

    assert tarball[4:8] == b"\x00\x00\x00\x00"
    assert tarball == fixture_registry.build_npm_tarball(
        root,
        "aegiscudo-benign-npm-fixture",
        "1.0.0",
    )


def test_build_npm_tarball_uses_package_specific_source_dir() -> None:
    root = ROOT / "testdata" / "npm"

    tarball = fixture_registry.build_npm_tarball(
        root,
        "fresh-postinstall",
        "0.1.0",
    )

    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        package_json = json.loads(
            archive.extractfile("package/package.json").read().decode()
        )

    assert package_json["name"] == "fresh-postinstall"
    assert package_json["version"] == "0.1.0"
    assert package_json["scripts"]["postinstall"] == "node index.js"