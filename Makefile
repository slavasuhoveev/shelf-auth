# -----------------------------
# Variables
# -----------------------------
SVC=cmd/shelf-auth
BIN=bin/shelf-auth

# Default connection string for local dev
DATABASE_URL?=postgres://shelf:shelf@localhost:5432/shelf_auth?sslmode=disable

RUN_ENV=\
	HTTP_ADDR=:8080 \
	LOG_LEVEL=debug \
	JWT_ALG=RS256 \
	JWT_ISS=shelf-auth \
	JWT_AUD=shelf-api \
	ACCESS_TTL=15m \
	JWKS_MAX_AGE=300s \
	KEYS_DIR=./devkeys \
	SIGNING_KEY_KID=k1-2025-08-30 \
	DATABASE_URL=$(DATABASE_URL)

# Test configuration
PKG ?= ./...
RUN ?=
TEST_FLAGS ?= -count=1
COVERPROFILE ?= coverage.unit.out

# -----------------------------
# Phony targets
# -----------------------------
.PHONY: tidy build run test clean \
        migrate-up migrate-down migrate-force \
        compose-up compose-down compose-logs \
        test-unit test-unit-v test-unit-race \
		test-unit-cover test-unit-run test-unit-pkg
# -----------------------------
# Go basics
# -----------------------------
tidy:
	go mod tidy

build:
	go build -o $(BIN) ./$(SVC)

run:
	$(RUN_ENV) go run ./$(SVC)

clean:
	rm -rf $(BIN)

# -----------------------------
# Tests
# -----------------------------
# All unit tests (tagged with //go:build unit)
test-unit:
	go test -tags=unit $(TEST_FLAGS) $(PKG)

# Verbose
test-unit-v:
	go test -tags=unit -v $(TEST_FLAGS) $(PKG)

# With race detector
test-unit-race:
	go test -tags=unit -race $(TEST_FLAGS) $(PKG)

# Coverage (summary to stdout)
test-unit-cover:
	go test -tags=unit -cover -coverprofile=$(COVERPROFILE) $(TEST_FLAGS) $(PKG)
	go tool cover -func=$(COVERPROFILE)

# Run tests matching regex
# Usage: make test-unit-run RUN=TestNewUser
test-unit-run:
	@test -n "$(RUN)" || (echo "Usage: make test-unit-run RUN=Regex"; exit 1)
	go test -tags=unit -v -run "$(RUN)" $(TEST_FLAGS) $(PKG)

# Only a specific package
# Usage: make test-unit-pkg PKG=./internal/domain
test-unit-pkg:
	@test -n "$(PKG)" || (echo "Usage: make test-unit-pkg PKG=./path"; exit 1)
	go test -tags=unit -v $(TEST_FLAGS) $(PKG)

# -----------------------------
# Migrations (using migrate tool)
# -----------------------------
migrate-up:
	docker compose run --rm migrate

migrate-down:
	docker compose run --rm migrate /bin/sh -lc 'migrate -path=/migrations -database "$$DATABASE_URL" down 1'

migrate-force:
	@read -p "Enter version to force: " v; \
	docker compose run --rm migrate /bin/sh -lc 'migrate -path=/migrations -database "$$DATABASE_URL" force '$$v

# -----------------------------
# Docker Compose helpers
# -----------------------------
compose-up:
	docker compose up -d

compose-down:
	docker compose down -v

compose-logs:
	docker compose logs -f
