# -----------------------------
# Export all vars to env
# -----------------------------
.EXPORT_ALL_VARIABLES:

# -----------------------------
# Variables
# -----------------------------
PROJECT_NAME         = shelf-auth

REGISTRY ?= ghcr.io
IMAGE_NAME ?= $(REGISTRY)/slavasuhoveev/$(PROJECT_NAME)

# Default local tag
TAG ?= develop

ifdef CI
TAG = latest
endif

IMAGE = $(IMAGE_NAME):$(TAG)

SVC                 ?= cmd/$(PROJECT_NAME)
BIN                 ?= bin/$(PROJECT_NAME)

# -----------------------------
# App env
# -----------------------------
ENV                 ?= dev
HTTP_ADDR           ?= :8080
LOG_LEVEL           ?= debug

JWT_ALG             ?= RS256
JWT_ISS             ?= $(PROJECT_NAME)
JWT_AUD             ?= shelf-api

ACCESS_TTL          ?= 15m
JWKS_MAX_AGE        ?= 300s

KEYS_DIR            ?= ./devkeys
SIGNING_KEY_KID     ?= k1-2025-08-30

CORS_ORIGINS        ?= http://localhost:3000

COOKIE_SECURE       ?= false
COOKIE_SAMESITE     ?= Lax
COOKIE_DOMAIN       ?=

# -----------------------------
# Database
# -----------------------------
DATABASE_URL        ?= postgres://shelf:shelf@127.0.0.1:5432/shelf_auth?sslmode=disable
DOCKER_DATABASE_URL ?= postgres://shelf:shelf@postgres:5432/shelf_auth?sslmode=disable

# -----------------------------
# Tests
# -----------------------------
PKG           ?= ./...
RUN           ?=
TEST_FLAGS    ?= -count=1
COVERPROFILE  ?= coverage.unit.out

# -----------------------------
# Seed user
# -----------------------------
SEED_EMAIL    ?= user@example.com
SEED_PASSWORD ?= abc12345

# -----------------------------
# Phony targets
# -----------------------------
.PHONY: \
	tidy build build-bin push run clean \
	check test test-unit test-int \
	test-unit-v test-unit-race test-unit-cover \
	test-unit-run test-unit-pkg test-int-v \
	migrate-up migrate-down migrate-force \
	up down logs \
	seed-user

# =========================================================
# Go basics
# =========================================================

tidy:
	go mod tidy

# Local binary build
build-bin:
	go build -o $(BIN) ./$(SVC)

# Local app run
run:
	go run ./$(SVC)

clean:
	rm -rf $(BIN)

# =========================================================
# Quality checks
# =========================================================

check:
	go fmt ./...
	go vet ./...
	go test -tags=unit $(TEST_FLAGS) ./...

# =========================================================
# Tests
# =========================================================

test: test-unit-v test-int-v

test-build:
	@docker compose build test

# -----------------------------
# Unit tests
# -----------------------------

test-unit: test-build
	@docker compose run --rm test \
		go test -tags=unit $(TEST_FLAGS) \
		$(if $(RUN),-run $(RUN),) \
		$(PKG)

test-unit-v: test-build
	@docker compose run --rm test \
		gotestsum --format standard-verbose -- \
		-tags=unit $(TEST_FLAGS) \
		$(if $(RUN),-run $(RUN),) \
		$(PKG)

test-unit-race: test-build
	@docker compose run --rm test \
		go test -tags=unit -race $(TEST_FLAGS) $(PKG)

test-unit-cover: test-build
	@docker compose run --rm test \
		sh -c 'go test -tags=unit -cover -coverprofile=$(COVERPROFILE) $(TEST_FLAGS) $(PKG) && go tool cover -func=$(COVERPROFILE)'

# -----------------------------
# Integration tests
# -----------------------------

test-int: test-build
	@docker compose run --rm test \
		go test -tags=integration $(TEST_FLAGS) \
		$(if $(RUN),-run $(RUN),) \
		$(PKG)

test-int-v: test-build
	@docker compose run --rm test \
		gotestsum --format standard-verbose -- \
		-tags=integration $(TEST_FLAGS) \
		$(if $(RUN),-run $(RUN),) \
		$(PKG)
# =========================================================
# Docker / Compose
# =========================================================

# Build docker images
build:
	@docker compose build --no-cache

# Start services
up: build
	@docker compose up -d

# Stop services
down:
	@docker compose down -v

# Follow logs
logs:
	docker compose logs -f

# Push docker image
push:
	@docker push $(IMAGE)

# =========================================================
# Database migrations
# =========================================================

migrate-up:
	@docker compose run --rm migrate \
		-path=/migrations \
		-database "$(DOCKER_DATABASE_URL)" up

migrate-down:
	@docker compose run --rm migrate \
		-path=/migrations \
		-database "$(DOCKER_DATABASE_URL)" down 1

migrate-force:
	@read -p "Enter version to force: " v; \
	@docker compose run --rm migrate \
		-path=/migrations \
		-database "$(DOCKER_DATABASE_URL)" \
		force $$v

# =========================================================
# Seed user
# =========================================================

seed-user:
	@hash=$$(go run ./tools/hashpw -password "$(SEED_PASSWORD)"); \
	@docker exec $(PROJECT_NAME)-postgres psql -U shelf -d shelf_auth -c "\
		INSERT INTO users (email, password_hash, email_verified) \
		VALUES ('$(SEED_EMAIL)', '$$hash', true) \
		ON CONFLICT (email) DO UPDATE SET \
			password_hash = EXCLUDED.password_hash, \
			email_verified = EXCLUDED.email_verified;"; \
	echo "Seeded/updated user: $(SEED_EMAIL)"
