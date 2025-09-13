# -----------------------------
# Export all vars to env
# -----------------------------
.EXPORT_ALL_VARIABLES:

# -----------------------------
# Variables (defaults; override in shell or .env)
# -----------------------------
SVC                 ?= cmd/shelf-auth
BIN                 ?= bin/shelf-auth

# App env
ENV                 ?= dev
HTTP_ADDR           ?= :8080
LOG_LEVEL           ?= debug
JWT_ALG             ?= RS256
JWT_ISS             ?= shelf-auth
JWT_AUD             ?= shelf-api
ACCESS_TTL          ?= 15m
JWKS_MAX_AGE        ?= 300s
KEYS_DIR            ?= ./devkeys
SIGNING_KEY_KID     ?= k1-2025-08-30
CORS_ORIGINS=http://localhost:3000
COOKIE_SECURE=false
COOKIE_SAMESITE=None
COOKIE_DOMAIN=

# DB URLs:
# - host running app needs localhost
DATABASE_URL        ?= postgres://shelf:shelf@127.0.0.1:5432/shelf_auth?sslmode=disable
# - containers talk to the 'postgres' service by name
DOCKER_DATABASE_URL ?= postgres://shelf:shelf@postgres:5432/shelf_auth?sslmode=disable

# Tests
PKG           ?= ./...
RUN           ?=
TEST_FLAGS    ?= -count=1
COVERPROFILE  ?= coverage.unit.out

# Seed user defaults
SEED_EMAIL    ?= user@example.com
SEED_PASSWORD ?= abc12345

# -----------------------------
# Phony targets
# -----------------------------
.PHONY: tidy build run clean \
        test-unit test-unit-v test-unit-race test-unit-cover test-unit-run test-unit-pkg \
        migrate-up migrate-down migrate-force \
        compose-build compose-up compose-down compose-logs \
        seed-user

# -----------------------------
# Go basics
# -----------------------------
tidy:
	go mod tidy

build:
	go build -o $(BIN) ./$(SVC)

# For local run we use host DATABASE_URL (already exported).
run:
	go run ./$(SVC)

clean:
	rm -rf $(BIN)

# -----------------------------
# Tests
# -----------------------------
test-unit:
	go test -tags=unit $(TEST_FLAGS) $(PKG)

test-unit-v:
	go test -tags=unit -v $(TEST_FLAGS) $(PKG)

test-unit-race:
	go test -tags=unit -race $(TEST_FLAGS) $(PKG)

test-unit-cover:
	go test -tags=unit -cover -coverprofile=$(COVERPROFILE) $(TEST_FLAGS) $(PKG)
	go tool cover -func=$(COVERPROFILE)

# Usage: make test-unit-run RUN=TestNewUser
test-unit-run:
	@test -n "$(RUN)" || (echo "Usage: make test-unit-run RUN=Regex"; exit 1)
	go test -tags=unit -v -run "$(RUN)" $(TEST_FLAGS) $(PKG)

# Usage: make test-unit-pkg PKG=./internal/domain
test-unit-pkg:
	@test -n "$(PKG)" || (echo "Usage: make test-unit-pkg PKG=./path"; exit 1)
	go test -tags=unit -v $(TEST_FLAGS) $(PKG)

# -----------------------------
# Migrations (migrate/migrate:4)
# Run inside compose network; override DATABASE_URL to container URL
# -----------------------------
migrate-up:
	DATABASE_URL="$(DOCKER_DATABASE_URL)" \
	docker-compose run --rm migrate

migrate-down:
	DATABASE_URL="$(DOCKER_DATABASE_URL)" docker compose run --rm migrate /bin/sh -lc 'migrate -path=/migrations -database "$$DATABASE_URL" down 1'

migrate-force:
	@read -p "Enter version to force: " v; \
	DATABASE_URL="$(DOCKER_DATABASE_URL)" docker compose run --rm migrate /bin/sh -lc 'migrate -path=/migrations -database "$$DATABASE_URL" force '$$v

# -----------------------------
# Docker Compose helpers
# -----------------------------
compose-build:
	DATABASE_URL="$(DOCKER_DATABASE_URL)" docker compose build --no-cache

compose-up: compose-build
	DATABASE_URL="$(DOCKER_DATABASE_URL)" docker compose up -d

compose-down:
	docker compose down -v

compose-logs:
	docker compose logs -f

# -----------------------------
# Seed user (simple version; assumes no pepper)
# -----------------------------
seed-user:
	@hash=$$(go run ./tools/hashpw -password "$(SEED_PASSWORD)"); \
	docker exec shelf-auth-postgres psql -U shelf -d shelf_auth -c "\
		INSERT INTO users (email, password_hash, email_verified) \
		VALUES ('$(SEED_EMAIL)', '$$hash', true) \
		ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, email_verified = EXCLUDED.email_verified;"; \
	echo "Seeded/updated user: $(SEED_EMAIL)"
