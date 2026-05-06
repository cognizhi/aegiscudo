# Fixture Strategy

Source PRD sections: Phase 0 testdata and Phase 1 validation.

Fixtures are deterministic, synthetic, and safe. Malicious fixtures must demonstrate indicators without real credential theft, destructive behavior, or live network exfiltration.

- `testdata/npm/benign-package`: harmless npm fixture.
- `testdata/pypi/benign-package`: harmless PyPI fixture.
- `testdata/security`: adversarial static-analysis and sandbox fixtures.
- `schemas/fixtures`: contract validation examples.