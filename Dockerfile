# ----------------------------
# 1. Build stage
# ----------------------------
FROM golang:1.23-alpine AS builder

# Enable go modules, install deps
RUN apk add --no-cache git make

WORKDIR /app

# Preload go.mod + go.sum first (caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o shelf-auth ./cmd/shelf-auth

# ----------------------------
# 2. Final stage
# ----------------------------
FROM gcr.io/distroless/base-debian12

WORKDIR /app

# Copy binary only
COPY --from=builder /app/shelf-auth /app/shelf-auth

# For dev: mount devkeys directory as volume
VOLUME ["/run/secrets/keys"]

# Listen on port 8080
EXPOSE 8080

ENTRYPOINT ["/app/shelf-auth"]
