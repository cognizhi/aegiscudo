# Cargo Source Replacement With Mosquito Net

Source PRD sections: Phase 2 Cargo sparse registry proxy, Feature 4.5.

Use this runbook when you want Cargo to resolve crates through a Mosquito Net mount instead of talking to crates.io or another sparse registry directly.

## Preconditions

- A Cargo registry configuration is enabled in Aegiscudo with a mounted proxy path such as `/proxy/cargo/crates-io`.
- Every Mosquito Net instance serving that mount shares the same `MOSQUITO_NET_CARGO_DOWNLOAD_MAC_KEY` value.
- The upstream Cargo registry serves a registry-local default `dl` base.
- If the upstream Cargo registry uses an off-origin download host or redirects crate downloads to another host, that download origin must be explicitly allowlisted in the Aegiscudo registry configuration.
- If you need Cargo registry API flows such as search, publish, owner, yank, or unyank, the upstream `api` base must still resolve to the configured registry origin. Cross-origin Cargo `api` bases are not supported yet.

## Replace `crates.io`

Add this to a repository-local `.cargo/config.toml` or to your user-level Cargo config such as `~/.cargo/config.toml`:

```toml
[source.crates-io]
replace-with = "aegiscudo-crates-io"

[source.aegiscudo-crates-io]
registry = "sparse+https://aegiscudo.example.com/proxy/cargo/crates-io/"
```

- Use the exact Mosquito Net Cargo mount as the sparse index root, with a trailing `/` so Cargo resolves `config.json` and sparse index paths beneath that mount.
- Keep the `sparse+` prefix. Cargo uses it to select the sparse registry protocol.
- Point Cargo at the Mosquito Net mount, not at the upstream registry URL, the upstream `config.json` URL, or the rewritten `dl` URL returned by `config.json`.

If your mounted path is different, substitute that path directly:

```toml
[source.crates-io]
replace-with = "team-rust"

[source.team-rust]
registry = "sparse+https://aegiscudo.example.com/proxy/team-rust/"
```

## Configure A Named Registry

If you want to exercise explicit Cargo registry API commands such as `cargo search --registry <name> ...`, declare a named registry entry instead of only using source replacement:

```toml
[registries.aegiscudo-crates-io]
index = "sparse+https://aegiscudo.example.com/proxy/cargo/crates-io/"
```

Use the same proxy mount URL and trailing `/` rules as the source-replacement examples above.

## Rollout Notes

- Prefer repository-local `.cargo/config.toml` during pilot rollouts so you can scope the change to one workspace or CI job at a time.
- Keep `MOSQUITO_NET_CARGO_DOWNLOAD_MAC_KEY` stable across restarts. Rotating it intentionally invalidates previously issued Cargo download URLs until clients refetch `config.json`.
- Mosquito Net now rewrites the upstream Cargo `api` base under the same proxy mount for explicit Cargo registry endpoints such as search, publish, owners, yank, and unyank when that `api` base stays on the configured upstream origin.
- Cargo API passthrough forwards the caller's Cargo headers, request body, query string, and `Authorization` header when present, but it does not fall back to the registry-config upstream credential on that path.
- The rewritten Cargo `api` base is not a generic same-origin proxy. Only explicit Cargo registry endpoints are accepted; out-of-scope signed suffixes fail closed.

## Quick Validation

After applying the config, prefer smoke tests that exercise both the sparse index and the rewritten download or API paths from a disposable workspace:

```sh
cargo fetch
```

That should drive `config.json`, sparse index reads, and `.crate` downloads through the configured Mosquito Net mount.

To verify the Cargo registry API path, first configure a named registry entry as shown above, then run:

```sh
cargo search --registry aegiscudo-crates-io serde
```

That should produce a signed Cargo `api` request beneath the same Mosquito Net mount.

If you only need a lighter config-read probe, `cargo metadata --format-version 1 > /dev/null` still verifies `config.json` and sparse index reads, but it can succeed without exercising the download or API flows.

For registry-local default `dl` bases, locked Cargo installs preserve checksum semantics because Mosquito Net validates the sparse index `cksum` against the exact `.crate` bytes before serving them.

The local fixture compatibility suite in this repo now exercises both `cargo search` and `cargo fetch` against a sparse registry served through Mosquito Net, so those two commands are the preferred smoke tests when validating a new Cargo mount.

## Current Limitations

- Non-default markerized Cargo `dl` templates are rejected.
- Cross-origin Cargo `dl` bases and redirect targets must be explicitly allowlisted per registry configuration.
- Cross-origin Cargo `api` bases are still rejected.
- The rewritten Cargo `api` base only accepts explicit Cargo registry endpoints; it is not a general same-origin passthrough.