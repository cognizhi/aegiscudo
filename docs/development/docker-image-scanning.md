# Docker Image Scanning In CI

Phase 3 Docker scanning uses a scanner-only first slice: `aedo` asks Syft to inspect an image, converts supported embedded package ecosystems into Aegiscudo findings, and can generate an image-level SBOM.

## Requirements

- `aedo` installed in the CI environment.
- `syft` installed and available on `PATH`.
- `cosign` installed and available on `PATH` when verifying image attestations.
- Docker Buildx or another image build step that produces a local image tag.
- A saved Aegiscudo CLI config when embedded npm or PyPI dependencies should be evaluated against request-time policy.

The current image SBOM contains the Docker/OCI image root plus supported embedded application package ecosystems: npm, PyPI, Cargo, and Maven. Syft OS packages such as apk, deb, and rpm are intentionally skipped until Aegiscudo has explicit OS package ecosystem contracts and policy semantics.

## GitHub Actions Example

```yaml
name: Docker image scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  docker-image-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write

    steps:
      - uses: actions/checkout@v4

      - name: Install Syft
        uses: anchore/sbom-action/download-syft@v0

      - name: Build image
        run: docker build --tag aegiscudo-demo:${{ github.sha }} .

      - name: Configure Aegiscudo CLI
        run: |
          aedo auth login \
            --api-url "$AEGISCUDO_API_URL" \
            --token "$AEGISCUDO_TOKEN" \
            --tenant-id "$AEGISCUDO_TENANT_ID" \
            --policy-profile-id "$AEGISCUDO_POLICY_PROFILE_ID"
        env:
          AEGISCUDO_API_URL: ${{ secrets.AEGISCUDO_API_URL }}
          AEGISCUDO_TOKEN: ${{ secrets.AEGISCUDO_TOKEN }}
          AEGISCUDO_TENANT_ID: ${{ secrets.AEGISCUDO_TENANT_ID }}
          AEGISCUDO_POLICY_PROFILE_ID: ${{ secrets.AEGISCUDO_POLICY_PROFILE_ID }}

      - name: Scan image
        run: |
          aedo scan docker \
            --image aegiscudo-demo:${{ github.sha }} \
            --output-format sarif \
            --fail-on block > aegiscudo-docker.sarif

      - name: Generate image SBOM
        run: |
          aedo sbom generate \
            --image aegiscudo-demo:${{ github.sha }} \
            --format cyclonedx-json \
            --output image-sbom.cdx.json
```

## Release Attestation Verification

Run attestation verification after the image has been pushed and attested. Prefer a digest-pinned image reference from the publish step.

```yaml
      - name: Verify published image attestation
        if: github.event_name == 'push'
        env:
          IMAGE_REF: ghcr.io/acme/demo@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        run: |
          cosign version

          aedo attest verify \
            --image "$IMAGE_REF" \
            --ecosystem docker \
            --certificate-identity "https://github.com/acme/demo/.github/workflows/release.yml@refs/heads/main" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

The attestation step intentionally requires a Cosign trust selector and uses `cosign verify-attestation`. Do not use broad regular expressions in production unless a tenant policy separately constrains the expected builder identity.