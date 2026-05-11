# Security Policy

Security reports are welcome and taken seriously.

## Supported Development Line

Until Aegiscudo reaches a stable `1.0` release, the project is maintained primarily on the `main` branch.

| Version line | Status |
|---|---|
| `main` | Supported on a best-effort basis |
| Pre-1.0 tags and snapshots | No guaranteed backport support |

For now, assume security fixes land on `main` first.

## How To Report A Vulnerability

Do **not** file public issues for suspected vulnerabilities.

Private reporting must exist before this repository is treated as publication-ready.

Accepted private reporting paths:

1. GitHub Security Advisories or Private Vulnerability Reporting for this repository.
2. A dedicated maintainer-controlled private security mailbox or intake alias, if one is later published.

If you do not have access to a private reporting path, do **not** disclose the issue publicly. Maintainers should treat that as a release blocker and enable a private reporting workflow before public launch or broad public promotion.

Once a private channel is available:

1. Share a private report with enough detail to reproduce or reason about the issue.
2. Wait for maintainer guidance before publishing details, proof-of-concept code, or exploit discussion.

## What To Include In A Report

Please include as much of the following as possible:

- affected component or path
- impact summary
- prerequisites and attacker assumptions
- reproduction steps or a minimal proof of concept
- relevant logs, traces, or screenshots with secrets removed
- suggested mitigations, if known

If the issue involves leaked secrets, compromised tokens, or exposed credentials, rotate those credentials immediately before sending the report if you control them.

## What Not To Put In Public Channels

Do not post any of the following in public issues, PRs, or discussions:

- real credentials or tokens
- working exploit payloads that meaningfully increase attackability
- unredacted environment dumps
- private infrastructure endpoints
- malware samples that are not safely contained for deterministic testing

## Security Response Goals

These are targets, not hard guarantees:

- acknowledge a report within 3 business days
- provide an initial triage assessment within 7 business days when reproduction is possible
- coordinate disclosure timing with the reporter when a fix is required

Complex issues involving upstream ecosystems, third-party services, or architectural changes may take longer.

## Scope

This policy covers vulnerabilities in this repository, including:

- registry proxy behavior
- request-time decisioning
- analysis and evidence handling
- sandbox orchestration
- API and UI flows
- credential handling
- audit and override behavior
- contracts, schemas, and generated interfaces when they create exploitable behavior

Out of scope unless they arise from a project-controlled defect:

- general hardening advice without a concrete vulnerability
- vulnerabilities in third-party dependencies without a project-specific exploitation path
- social engineering attacks that do not involve a defect in the repository itself

## Secure Development Rules

These rules apply to all contributions and maintenance work:

- Never log tokens, credentials, authorization headers, raw environment variables, or package-manager auth material.
- Treat package contents, manifests, READMEs, comments, provenance objects, and AI-agent instruction files as adversarial input.
- Do not execute package code outside Emergency Room sandbox profiles.
- LLM output is advisory only and must never be the sole enforcement authority.
- Overrides and emergency bypasses require reason, scope, expiry, approver, and audit evidence.
- Do not silently loosen fail-closed behavior in enforcement paths.
- Do not market provenance, signatures, or attestations as proof that software is benign.

## Coordinated Disclosure

Please give maintainers a reasonable opportunity to investigate and mitigate before public disclosure.

When a fix is ready, maintainers should aim to:

- ship the fix or mitigation
- document affected versions or areas
- credit the reporter when requested and appropriate

## GitHub Security Advisory Draft Process

When a report is confirmed and remediation work needs private coordination, maintainers should open a draft GitHub Security Advisory for this repository before discussing the fix in public issues or PRs.

Recommended flow:

1. Open the repository Security tab and create a new draft advisory.
2. Add a short title, affected component summary, severity assessment, and the private reporter details if available.
3. Record the currently affected branches, tags, or unreleased areas, plus any known workarounds.
4. Link the private fix branch or private patch PR to the advisory discussion instead of opening a public tracking issue.
5. Use the draft advisory to coordinate reviewer access, remediation notes, release timing, and disclosure decisions.
6. Only publish the advisory after the fix or mitigation is available and public release notes are ready.

Before publishing the advisory, confirm that:

- the patch or mitigation has landed in the supported development line
- public changelog or release notes do not expose sensitive exploit details unnecessarily
- any necessary token rotations, customer notifications, or operational mitigations are already underway
- the advisory description is redacted for secrets, private infrastructure details, and exploit-enabling payloads

## Thanks

Responsible disclosure helps keep the project, its contributors, and downstream users safer.