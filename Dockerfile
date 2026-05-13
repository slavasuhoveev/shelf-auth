# ============================================================
# Base Go image
# ============================================================

FROM golang:1.23 AS base

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

# ============================================================
# Production runtime
# ============================================================

FROM gcr.io/distroless/base-debian12 AS production

WORKDIR /app

COPY --from=builder /app/shelf-auth /app/shelf-auth

VOLUME ["/run/secrets/keys"]

EXPOSE 8080

ENTRYPOINT ["/app/shelf-auth"]
