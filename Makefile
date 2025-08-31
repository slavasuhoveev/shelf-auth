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

# -----------------------------
# Phony targets
# -----------------------------
.PHONY: tidy build run test clean \
        migrate-up migrate-down migrate-force \
        compose-up compose-down compose-logs

# -----------------------------
# Go basics
# -----------------------------
tidy:
	go mod tidy

build:
	go build -o $(BIN) ./$(SVC)

run:
	$(RUN_ENV) go run ./$(SVC)

test:
	go test ./...

clean:
	rm -rf $(BIN)

# -----------------------------
# Migrations (using migrate tool)
# -----------------------------
migrate-up:
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is required" && exit 1)
	docker run --rm -v $$PWD/migrations:/migrations --network host migrate/migrate:4 \
		-path=/migrations -database "$(DATABASE_URL)" up

migrate-down:
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is required" && exit 1)
	docker run --rm -v $$PWD/migrations:/migrations --network host migrate/migrate:4 \
		-path=/migrations -database "$(DATABASE_URL)" down 1

migrate-force:
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is required" && exit 1)
	@read -p "Enter version to force: " v; \
	docker run --rm -v $$PWD/migrations:/migrations --network host migrate/migrate:4 \
		-path=/migrations -database "$(DATABASE_URL)" force $$v

# -----------------------------
# Docker Compose helpers
# -----------------------------
compose-up:
	docker compose up -d

compose-down:
	docker compose down

compose-logs:
	docker compose logs -f
