# Outbound Webhooks

Source PRD sections: Phase 3 deferred notification and alerting integrations.

Aegiscudo webhook support is a Phase 3 integration contract, not a request-time enforcement dependency. Mosquito Net and Triage Counter continue to make authoritative request-time decisions; webhook delivery is asynchronous notification after an override event, critical detection, or policy violation has already been recorded.

## Event Contract

Outbound payloads use `webhook-event/v1`, defined in `schemas/webhook-event.schema.json`. The event envelope includes an event ID, event type, opaque tenant reference, timestamp, trace ID, severity, bounded summary, normalized subject, optional policy context, evidence references, safe metadata, and an explicit redaction profile.

Supported initial event types are:

- `override.requested`
- `override.approved`
- `override.revoked`
- `override.expired`
- `critical_detection.created`
- `policy_violation.detected`

Payloads must not include raw package contents, raw sandbox payloads, auth headers, secret values, environment dumps, unredacted audit metadata, or LLM prompt/response text. Evidence references point back to Aegiscudo records by ID and optional digest rather than embedding reports inline.

## Endpoint Registration

Tenant endpoint metadata uses `webhook-endpoint/v1`, defined in `schemas/webhook-endpoint.schema.json`. Endpoint registration records tenant ID, schema version, display name, destination type, encrypted HTTPS endpoint URL reference, non-sensitive destination host hint, enabled state, event type subscriptions, payload version, HMAC signing configuration by secret reference, optional auth credential reference, residency region, retry policy, creator, and timestamps. Provider webhook URLs, including Slack incoming webhook URLs, are treated as secrets and are never returned as plain endpoint metadata.

Slack, PagerDuty, Jira, and generic HTTPS endpoints share the same registration contract. Destination-specific adapters may transform `webhook-event/v1` into provider-native payloads, but the transformation must not add fields outside the event allowlist or fetch raw evidence.

## Delivery Model

Webhook delivery jobs are queued after the source event is committed. Delivery workers read only normalized event payloads, sign requests with HMAC-SHA256, apply tenant and endpoint quotas, and retry with bounded exponential backoff. Delivery attempts should be audit logged with endpoint ID, event ID, attempt number, outcome, status code class, and trace ID, never request bodies or credential values.

The HMAC signature covers the exact canonical request body bytes sent to the destination. Deliveries include an event ID header, delivery timestamp header, and signature header in the form `sha256=<hex-digest>`. Receivers should reject signatures outside the configured replay tolerance window, and Aegiscudo should not retry with a mutated body for the same event ID.

Endpoint URL validation happens at registration and again before delivery. The canonicalized destination must use HTTPS, must not contain userinfo, and must not resolve to loopback, link-local, RFC1918, reserved, multicast, documentation, or cloud metadata-service addresses.

The dispatch path must treat endpoint responses as untrusted. Response bodies are discarded or size-bounded and redacted before storage. Failed delivery cannot roll back the source policy decision, override state, evidence state, or request-time cache.

## Security Controls

- Use tenant-approved HTTPS endpoints only; reject URL userinfo, non-HTTPS schemes, local/private/reserved destinations, and metadata-service destinations.
- Store endpoint URLs, signing secrets, and destination auth values as credential references, never inline registration fields.
- Include only opaque tenant references in outbound payloads.
- Keep webhook generation asynchronous and isolated from request-time enforcement latency.
- Record endpoint create, update, disable, delete, test, delivery success, and delivery failure audit events.
- Enforce tenant RBAC for endpoint management and delivery history access.

## Current Blockers

Provider-specific Slack, PagerDuty, and Jira adapters cannot start until webhook endpoint persistence, delivery queue tables, secret rotation behavior, RBAC routes, and delivery attempt retention are implemented. Admin UI configuration forms also remain blocked on those API routes. The current Command Center integration panel shows a coming-soon placeholder only.