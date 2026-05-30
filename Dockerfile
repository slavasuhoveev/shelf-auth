# ============================================================
# Base Go image
# ============================================================

FROM golang:1.24 AS base

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# ============================================================
# Test image
# Used for unit/integration tests and local tooling
# ============================================================

FROM base AS test

RUN go install gotest.tools/gotestsum@v1.12.0

# ============================================================
# Production build
# ============================================================

FROM base AS builder

RUN CGO_ENABLED=0 GOOS=linux go build -o shelf-auth ./cmd/shelf-auth

# Install golang-migrate binary
RUN GOBIN=/tmp/bin go install -tags "postgres" \
    github.com/golang-migrate/migrate/v4/cmd/migrate@v4.19.0

# ============================================================
# Production runtime
# ============================================================

FROM gcr.io/distroless/base-debian12 AS production

WORKDIR /app

COPY --from=builder /app/shelf-auth /app/shelf-auth
COPY --from=builder /tmp/bin/migrate /usr/local/bin/migrate

COPY migrations /migrations

VOLUME ["/run/secrets/keys"]

EXPOSE 8080

ENTRYPOINT ["/app/shelf-auth"]
