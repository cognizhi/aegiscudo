# Emergency Room

Source PRD sections: Feature 4, 3.3, 3.7.2, 4.4, 4.6.

Emergency Room is the sandbox orchestration component for dynamic package behavior analysis.

## Responsibilities

- Select sandbox profiles for npm and PyPI analysis jobs.
- Launch isolated executions with no customer secrets, no privileged mode, and no host mounts.
- Plant canary credentials and AI-agent configuration files.
- Capture process, filesystem, network, canary, stdout/stderr, timeout, and exit-code telemetry.
- Attribute behavior to root package, lifecycle phase, dependency, build tool, or import probe where practical.
- Persist telemetry with analysis job and artifact references.

## Sandbox Boundary

Sandboxes must be single-use execution environments with strict CPU, memory, egress, and timeout controls. They may write telemetry only to a narrow append-only ingestion endpoint and must not have write access to production databases.

## Current Implementation State

The Python FastAPI service shell exists with health/readiness/metrics routes, trace ID middleware, and shared log plus structured-event redaction utility. Profile registry, local mocked adapter, Cloud Run Jobs adapter, canary planting, telemetry ingestion, stdout/stderr redaction, and sandbox integration tests remain Phase 1B work.