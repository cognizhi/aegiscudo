# Fixture Strategy

Source PRD sections: Phase 0 testdata and Phase 1 validation.

Fixtures are deterministic, synthetic, and safe. Malicious fixtures must demonstrate indicators without real credential theft, destructive behavior, or live network exfiltration.

- `testdata/npm/benign-package`: harmless npm fixture.
- `testdata/npm/packuments/aegiscudo-benign-npm-fixture.json`: deterministic npm packument with synthetic signature-state cases: signed-shaped, unsigned, and invalid-signature versions.
- `testdata/pypi/benign-package`: harmless PyPI fixture.
- `testdata/pypi/packages/aegiscudo_benign_pypi_fixture-1.0.0-py3-none-any.whl`: deterministic benign wheel generated with `scripts/build-pypi-wheel-fixture.py`.
- `testdata/pypi/simple/aegiscudo-benign-pypi-fixture`: deterministic PEP 503 HTML and PEP 691 JSON Simple API fixtures with one digest-matched HTTPS provenance reference and one intentionally insecure/bad provenance reference.
- `testdata/pypi/provenance/aegiscudo_benign_pypi_fixture-1.0.0.intoto.jsonl`: synthetic in-toto provenance statement whose subject digest matches the generated wheel.
- `testdata/security`: adversarial static-analysis and sandbox fixtures.
- `testdata/security/canary-access-sandbox`: synthetic sandbox telemetry for canary credential and AI-agent canary access.
- `testdata/feeds/osv.json`: synthetic OSV response fixture.
- `testdata/feeds/ghsa.json`: synthetic GHSA GraphQL response fixture.
- `testdata/feeds/openssf-malicious-packages.json`: synthetic OpenSSF malicious packages fixture.
- `schemas/fixtures`: contract validation examples.

When regenerating the PyPI wheel, run `uv run python scripts/build-pypi-wheel-fixture.py`, update the Simple API size/hash and provenance subject digest if they change, then run `uv run pytest services/python-common/tests/test_fixtures.py`.
