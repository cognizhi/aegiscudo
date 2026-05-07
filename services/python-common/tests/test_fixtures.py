from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[3]
NPM_PACKUMENT = ROOT / "testdata/npm/packuments/aegiscudo-benign-npm-fixture.json"
WHEEL = ROOT / "testdata/pypi/packages/aegiscudo_benign_pypi_fixture-1.0.0-py3-none-any.whl"
PYPI_JSON = ROOT / "testdata/pypi/simple/aegiscudo-benign-pypi-fixture/index.v1.json"
PROVENANCE = ROOT / "testdata/pypi/provenance/aegiscudo_benign_pypi_fixture-1.0.0.intoto.jsonl"


def test_npm_packument_fixture_never_points_at_live_registry() -> None:
    packument = json.loads(NPM_PACKUMENT.read_text())

    for version in packument["versions"].values():
        dist = version["dist"]
        assert dist["tarball"].startswith("https://fixtures.aegiscudo.local/")
        assert "registry.npmjs.org" not in dist["tarball"]
        assert dist["integrity"].startswith("sha512-")


def test_benign_pypi_wheel_fixture_is_a_valid_zip_wheel() -> None:
    with ZipFile(WHEEL) as wheel:
        names = set(wheel.namelist())

    assert "aegiscudo_benign_pypi_fixture/__init__.py" in names
    assert "aegiscudo_benign_pypi_fixture-1.0.0.dist-info/METADATA" in names
    assert "aegiscudo_benign_pypi_fixture-1.0.0.dist-info/RECORD" in names


def test_pypi_provenance_fixture_matches_wheel_digest() -> None:
    digest = hashlib.sha256(WHEEL.read_bytes()).hexdigest()
    simple_api = json.loads(PYPI_JSON.read_text())
    provenance = json.loads(PROVENANCE.read_text())

    assert simple_api["files"][0]["hashes"]["sha256"] == digest
    assert provenance["subject"][0]["digest"]["sha256"] == digest
    assert simple_api["files"][0]["provenance"].startswith("https://fixtures.aegiscudo.local/")
    assert simple_api["files"][1]["provenance"].startswith("http://insecure.example.invalid/")
