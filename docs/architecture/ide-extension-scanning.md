# IDE Extension Scanning

Phase 3 starts with a local, scanner-only CLI path for VS Code and OpenVSX-compatible extension artifacts. The scanner treats extension manifests and payload files as adversarial input, never executes extension code, and does not unpack VSIX archives to disk.

## First-Release Sources

- VS Code Marketplace extensions represented as downloaded `.vsix` archives or unpacked extension directories.
- OpenVSX extensions represented as downloaded `.vsix` archives or unpacked extension directories.
- Future Cursor/Windsurf/JetBrains extension sources remain extension points until their package formats and marketplace metadata contracts are defined.

Marketplace API ingestion is not part of the first local scanner slice. When added, it should fetch metadata asynchronously, normalize publisher and extension age signals, and keep request-time enforcement out of marketplace crawling.

## Package Format Handling

The CLI command `aedo scan vscode-extension --path <dir-or-vsix>` supports:

- Unpacked extension directories containing `package.json`.
- VSIX archives containing `extension/package.json` or another non-`node_modules` `package.json`.

The scanner bounds file count and text file size, skips symlinks in directories, rejects archive path traversal entries, and reads only text-like files for static pattern matching.

## Local Signals

The scanner emits `vscode-extension` package coordinates. The root extension coordinate is `ALLOW`; detected local signals become separate `.signal.<id>` coordinates so text, JSON, and SARIF output can preserve normal scan report behavior.

The `.signal.<id>` coordinates are a transitional local CLI output shape, not durable package identities. Persisted API and dashboard work should replace them with structured evidence records that include file paths, signal types, counts, and artifact locations.

Current local signals:

- AI agent instruction payload files such as `copilot-instructions.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`, and `.instructions.md`.
- Prompt-injection text such as attempts to ignore previous instructions or manipulate system/developer messages.
- Lifecycle scripts including `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, and `postpack`.
- Broad activation events such as `*` and `onStartupFinished`.
- Static network, credential, workspace file access, and process execution patterns in text payloads.

These are conservative static signals. They are evidence for policy and review, not a claim that the extension is definitively malicious.

## Blocked Follow-Up Work

- Publisher reputation and extension age policy signals require VS Code Marketplace/OpenVSX metadata ingestion and normalized publisher identity storage.
- Extension SBOM fragments require a contract for representing extension roots, bundled Node dependencies, and payload files in the SBOM service.
- Dashboard evidence requires a persisted extension scan read model and tenant-scoped API route.
- Marketplace crawling and live enrichment must run asynchronously; request-time services should not call marketplace APIs.