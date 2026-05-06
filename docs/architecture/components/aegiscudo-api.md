# Aegiscudo API

Source PRD sections: 3.3, 3.4.3, 3.4.4, 3.7.3, 4.5, 4.12.

Aegiscudo API is the backend surface for Command Center, `aedo-cli`, administration, audit, reports, and integrations.

## Responsibilities

- Serve dashboard and CLI APIs.
- Enforce RBAC for every admin and security-review action.
- Expose registry proxy CRUD, tenant namespace settings, policy simulator, override workflow, audit queries, AI provider configs, integration credentials, and reports.
- Validate credential format, store encrypted runtime credential material in PostgreSQL, expose metadata-only credential status in API responses, and trigger internal reload or test-connection workflows for affected services.
- Emit audit events for admin actions, credential changes, policy mutations, overrides, and report exports.

## Configuration Propagation

Aegiscudo API is the control-plane entry point for registry, feed, and AI provider configuration changes. It validates administrative updates, persists encrypted runtime overrides, and coordinates downstream service reloads without restart. See [External Integrations And Feeds](../external-integrations.md) for precedence and reload expectations.

## Boundaries

- UI hiding is not access control. Authorization is enforced in API and repository layers.
- API endpoints do not execute package code and do not perform request-time registry proxying.

## Current Implementation State

The Rust service placeholder and initial OpenAPI skeleton exist. Real API handlers, repositories, auth/RBAC, and contract tests remain Phase 1C work.