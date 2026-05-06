.PHONY: up down test lint fmt typecheck migrate migrate-check seed build docker-build integration-test e2e-test schema-validate

up:
	docker compose -f infra/docker-compose.yml up -d

down:
	docker compose -f infra/docker-compose.yml down

fmt:
	cargo fmt --all
	uv run ruff format services/emergency-room services/ai-analyst

lint:
	cargo clippy --workspace -- -D warnings
	pnpm lint
	uv run ruff check services/emergency-room services/ai-analyst

typecheck:
	pnpm typecheck
	uv run mypy services/emergency-room services/ai-analyst

test:
	cargo test --workspace
	pnpm test
	uv run pytest

schema-validate:
	pnpm schema:validate

migrate:
	set -a; [ ! -f .env ] || . ./.env; set +a; sh ./scripts/apply-migrations.sh

migrate-check:
	set -a; [ ! -f .env ] || . ./.env; set +a; sh ./scripts/migrate-dry-run.sh

seed:
	@echo "Seed data is tracked in testdata and schema fixtures."

build:
	cargo build --workspace
	pnpm build

docker-build:
	docker build -f infra/Dockerfile.mosquito-net -t aegiscudo/mosquito-net:local .
	docker build -f infra/Dockerfile.triage-counter -t aegiscudo/triage-counter:local .
	docker build -f infra/Dockerfile.surgeon -t aegiscudo/surgeon:local .
	docker build -f infra/Dockerfile.aegiscudo-api -t aegiscudo/aegiscudo-api:local .
	docker build -f infra/Dockerfile.ai-analyst -t aegiscudo/ai-analyst:local .
	docker build -f infra/Dockerfile.emergency-room -t aegiscudo/emergency-room:local .
	docker build -f infra/Dockerfile.command-center -t aegiscudo/command-center:local .

integration-test:
	docker compose -f infra/docker-compose.yml up -d postgres redis minio otel-collector
	cargo test --workspace
	uv run pytest

e2e-test:
	docker compose -f infra/docker-compose.yml up -d
	pnpm --filter @aegiscudo/command-center playwright