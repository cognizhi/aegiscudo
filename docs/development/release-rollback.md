# Release Rollback Guide

This guide covers how to roll back an Aegiscudo release when a deployment introduces a
regression or production incident.

## Overview

Aegiscudo follows the release-please versioning workflow. Docker images are published with
three tags per service: `:<version>`, `:latest`, and `:sha-<short-sha>`. Rollback targets
the last known-good version tag.

## Step 1 — Identify the last known-good version

```bash
# List recent image tags (example for mosquito-net)
docker pull aegiscudo/mosquito-net --all-tags 2>/dev/null | grep -E '^[0-9]+\.[0-9]+'
```

Check the [release-please-config.json](../../release-please-config.json) changelog or the
CI run history to identify the last stable version tag.

## Step 2 — Roll back the affected service(s)

### Docker Compose (local / staging)

```bash
# Replace <SERVICE> with the affected service name and <VERSION> with the target version.
SERVICE=mosquito-net
VERSION=0.3.1

docker compose stop $SERVICE
docker compose rm -f $SERVICE
IMAGE=aegiscudo/$SERVICE:$VERSION docker compose up -d $SERVICE
```

### Kubernetes (production)

```bash
kubectl set image deployment/$SERVICE \
  $SERVICE=aegiscudo/$SERVICE:$VERSION \
  -n aegiscudo
kubectl rollout status deployment/$SERVICE -n aegiscudo
```

To use Helm:

```bash
helm upgrade aegiscudo ./infra/k8s/helm \
  --set services.$SERVICE.image.tag=$VERSION \
  --reuse-values
```

## Step 3 — Roll back the database migration (if applicable)

> **Warning:** Database rollbacks are destructive. Only proceed if the migration is the
> confirmed root cause and the data loss is acceptable.

```bash
# Dry-run first
bash scripts/migrate-dry-run.sh

# Revert by restoring from a pre-migration snapshot (preferred)
# or by running a compensating migration reviewed by the Tech Lead.
```

Do **not** run `git reset --hard` or `git push --force` on shared branches without
explicit Tech Lead approval.

## Step 4 — Verify service health

```bash
curl https://<API_HOST>/healthz
# Expected: { "status": "ok", "service": "aegiscudo-api", "version": "<VERSION>" }
```

Check Mosquito Net is enforcing policy:

```bash
curl -s https://<PROXY_HOST>/proxy/npm/left-pad/-/left-pad-1.3.0.tgz -I | grep x-aegiscudo
```

## Step 5 — Post-rollback

1. Open a post-mortem ticket and document the root cause.
2. Add a regression test covering the failure mode.
3. Update the changelog with a `[rollback]` note for the reverted release.
4. Notify affected tenants if their builds were disrupted.
