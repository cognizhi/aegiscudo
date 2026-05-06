#!/usr/bin/env sh
set -eu

mkdir -p infra/buckets/aegiscudo-artifacts-local infra/buckets/aegiscudo-reports-local
printf '%s\n' "local object storage bucket directories ready"