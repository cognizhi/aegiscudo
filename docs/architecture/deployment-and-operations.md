# Deployment And Operations

Source PRD sections: 3.4, 4.7, 4.8, 5, Production Readiness Gate.

Aegiscudo runs as independently deployable services with shared storage, cache/queue infrastructure, telemetry, and controlled external integrations.

## Local Topology

Local development starts backing dependencies with `make up`:

- PostgreSQL for Aegiscudo application data.
- Separate PostgreSQL database for Langfuse.
- Redis for cache and queues.
- ClickHouse for Langfuse v3 trace and event storage.
- MinIO-compatible object storage.
- MinIO bucket bootstrap for Aegiscudo artifacts, reports, and Langfuse event uploads.
- OpenTelemetry collector.
- Langfuse web.
- Langfuse worker.

## Production Topology

Production deployments must provide managed PostgreSQL, managed object storage, managed secrets, container orchestration, observability, backup/restore, and controlled network egress. Docker images are built for `linux/amd64` and `linux/arm64`.

## Health And Observability

All services expose `/healthz`, `/readyz`, `/metrics`, structured JSON logs, and trace IDs across request, decision, analysis, sandbox, AI, and admin workflows.

## Degraded Operation

- Request-time decisions use last-successful feed snapshots when feeds are stale.
- AI Analyst and Langfuse outages degrade explanations only.
- Sandbox worker outages record missing sandbox evidence and follow tenant policy.
- Upstream registry outages may serve only verified cached metadata or artifacts.

## Current Implementation State

Docker Compose, service Dockerfiles, OpenTelemetry config, Langfuse v3 local dependencies, containerized migration targets, and CI/security/release scaffolds exist. Local boot verification now covers PostgreSQL, Redis, MinIO, ClickHouse, Langfuse web, and Langfuse worker. Production IaC, branch protection, release dry runs, and operational runbooks remain open.