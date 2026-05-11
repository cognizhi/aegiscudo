# Runbook: Override — Emergency Bypass

**Scope:** Emergency-bypass overrides allow a package that would otherwise be blocked to
flow through the proxy immediately, bypassing normal policy enforcement. This runbook
covers how to create, approve, and revoke an emergency-bypass override during an incident.

## Prerequisites

- Access to the Aegiscudo Command Center with the `admin` or `security-specialist` role.
- The `aedo` CLI authenticated against the target tenant.
- Approval from a second `admin` or `security-specialist` user (four-eyes principle).

## Steps

### 1. Create the emergency-bypass override

**Via Command Center**

1. Navigate to **Overrides → Request Override**.
2. Set **Effect** to `emergency-bypass`.
3. Fill in **Scope** (ecosystem, name, version), a **Reason** (at least 8 characters), and an **Expiry** date in the future.
4. Submit. The override is created in `pending` status.

**Via CLI**

```bash
aedo override create \
  --tenant-id <TENANT_ID> \
  --scope '{"ecosystem":"npm","name":"<PKG>","version":"<VERSION>","effect":"emergency-bypass"}' \
  --reason "<Incident reference and business justification>" \
  --expires-at "2026-01-15T12:00:00Z"
```

### 2. Approve the override (second approver)

```bash
aedo override approve <OVERRIDE_ID> \
  --tenant-id <TENANT_ID> \
  --reason "Approved per incident INC-XXXX — reviewed build pipeline logs"
```

Once approved, the override becomes `approved` and Mosquito Net will allow matching
requests immediately. An `override.request.approved` audit event is recorded.

### 3. Verify the override is active

```bash
aedo override list --tenant-id <TENANT_ID> --status approved
```

### 4. Revoke or let it expire

- Override will auto-expire at the `expires_at` timestamp on the next Mosquito Net request.
- To deny/revoke before expiry:
  ```bash
  aedo override deny <OVERRIDE_ID> \
    --tenant-id <TENANT_ID> \
    --reason "Incident resolved — reverting emergency bypass"
  ```

## Audit trail

All override lifecycle events are recorded in `audit_events` with the following actions:

| Action | Trigger |
|---|---|
| `override.request.created` | Override submitted |
| `override.request.approved` | Override approved |
| `override.request.denied` | Override denied or revoked |
| `override.expired` | Override auto-expired |

Retrieve audit events via Command Center → **Audit Log** or:

```bash
aedo audit list --tenant-id <TENANT_ID> --filter override
```

## Security notes

- Emergency-bypass overrides bypass normal policy enforcement. Limit scope to the minimum
  required (specific `name` + `version`, not wildcard).
- Always set the shortest reasonable `expires_at` (hours, not weeks).
- Overrides require scope, reason, approver, and expiry as mandatory fields. Requests
  missing any of these fields are rejected with HTTP 422 or 400.
- LLM output is advisory only and does **not** grant automatic approval.
