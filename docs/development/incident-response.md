# Incident Response Guide

This guide describes the standard response process for security incidents detected by
Aegiscudo components during normal operation.

## Severity definitions

| Level | Description | Response SLO |
|---|---|---|
| P0 — Critical | Active compromise or data exfiltration | 15 minutes |
| P1 — High | Blocked malicious package attempted by internal build | 1 hour |
| P2 — Medium | High-confidence static indicator or sandbox event requiring HITL | 4 hours |
| P3 — Low | Informational finding or policy near-miss | 24 hours |

## P0 / P1 — Immediate containment

1. **Quarantine the artifact.** Check Mosquito Net enforce-mode is `enforce` for all
   affected registry mounts. If not, switch via Command Center → **Registry Config → Mode**.

2. **Identify affected builds.** Query audit events for the artifact digest:
   ```bash
   aedo audit list --tenant-id <TENANT_ID> --filter artifact:<DIGEST>
   ```

3. **Revoke any active overrides** that permitted the package:
   ```bash
   aedo override list --tenant-id <TENANT_ID> --status approved
   aedo override deny <OVERRIDE_ID> --reason "Incident INC-XXXX containment"
   ```

4. **Notify the security team** with the artifact details, analysis job ID, and timeline.

5. **Preserve evidence.** Do not delete analysis jobs or audit events. Export if needed:
   ```bash
   aedo audit export --tenant-id <TENANT_ID> --format csv > incident-audit.csv
   ```

## P2 — HITL investigation

1. Review the AI Analyst explanation for the flagged artifact in Command Center →
   **Investigation → Analysis Jobs**.
2. If the explanation is advisory only (`advisory_only: true`), human review is required
   before any policy change.
3. Assign a security specialist reviewer. Document findings in the incident ticket.
4. If the package is safe, create a scoped `allow` override (not `emergency-bypass`).

## Communication

- Incidents must be reported to the security team within the SLO window.
- External disclosure follows the policy in [SECURITY.md](../../SECURITY.md).
- Do not log secrets, tokens, or credential values in any incident report.

## Post-incident

1. Add the indicator type to the static rule set if a new pattern was found.
2. Add a regression test in `services/surgeon/src/` or `services/ai-analyst/tests/`.
3. Update this guide if the response process changed.
