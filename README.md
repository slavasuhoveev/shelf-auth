# shelf-auth

Authentication and authorization service for the **Shelf** microservice architecture.  
Provides JWT (RS256) access tokens, opaque refresh tokens with rotation & reuse detection, JWKS publishing, and session management.

---

## Features

- **Go** service (chi router) with structured logging (zerolog)
- **Config via env** (caarlos0/env)
- **JWT RS256** access tokens with `kid`, `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`
- **Refresh tokens**: opaque, HttpOnly cookie, rotation + reuse detection, device & IP/UA tracking
- **JWKS endpoint** (`/.well-known/jwks.json`) publishing all public keys (multi-key, rotation-friendly) with **ETag** and **Cache-Control**
- **CORS** (configurable origins) and **security headers**
- **Health** endpoint (`/healthz`)
- **Migrations** and **seed user** helper
- **Unit & Integration tests** (with build tags)

---

## Endpoints

- `GET /healthz` — liveness status
- `GET /.well-known/jwks.json` — JWKS (public keys for signature verification)
- `POST /register` — register user (email + password)
- `POST /login` — issue access token & set refresh cookie
- `POST /refresh` — rotate refresh + issue new access token
- `POST /logout` — revoke refresh session + clear cookie

### Examples

Health:
```bash
curl -i http://localhost:8081/healthz
# HTTP/1.1 200 OK
# {"status":"ok","service":"shelf-auth"}
```

JWKS (includes multiple keys during rotation):
```bash
curl -s http://localhost:8081/.well-known/jwks.json | jq
```

Login (returns access token JSON, sets HttpOnly refresh cookie):
```bash
curl -i -X POST http://localhost:8081/login \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"email":"user@example.com","password":"abc12345","device_id":"web-uuid"}'
```

Refresh (requires `refresh_token` cookie):
```bash
curl -i -X POST http://localhost:8081/refresh \
  -H 'Origin: http://localhost:3000' \
  --cookie "refresh_token=<value-from-login-set-cookie>"
```

Logout (clears cookie; idempotent):
```bash
curl -i -X POST http://localhost:8081/logout \
  -H 'Origin: http://localhost:3000' \
  --cookie "refresh_token=<value>"
```

> CORS tip: for browser apps, send `credentials: 'include'` and ensure `CORS_ORIGINS` allows your frontend origin.

---

## Getting Started

### 1) Generate dev keys
You need at least one RSA private key (PEM). The filename **without** `.pem` is the **KID**.

```bash
mkdir -p devkeys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out devkeys/k1-2025-08-30.pem
```

### 2) Run with Docker Compose (recommended)
```bash
make compose-up
# logs
make compose-logs
```

This starts:
- `postgres` on `localhost:5432`
- `shelf-auth` on `localhost:8081` (service listens on `:8080` inside container)
- mounts `./devkeys` into the container

Run migrations:
```bash
make migrate-up
```

Seed a user (for local testing):
```bash
make seed-user SEED_EMAIL=user@example.com SEED_PASSWORD=abc12345
```

### 3) Run locally (without Docker)
```bash
export HTTP_ADDR=":8080"
export LOG_LEVEL="debug"
export JWT_ALG="RS256"
export JWT_ISS="shelf-auth"
export JWT_AUD="shelf-api"
export ACCESS_TTL="15m"
export REFRESH_TTL="720h"
export JWKS_MAX_AGE="300s"
export KEYS_DIR="./devkeys"
export SIGNING_KEY_KID="k1-2025-08-30"
export DATABASE_URL="postgres://shelf:shelf@localhost:5432/shelf_auth?sslmode=disable"

# CORS & cookies for local SPA on :3000
export CORS_ORIGINS="http://localhost:3000"
export COOKIE_SECURE="false"
export COOKIE_SAMESITE="None"
export COOKIE_DOMAIN=""

# optional: key reloads & hot active kid override
export KEYS_RELOAD_INTERVAL="60s"
# export ACTIVE_KID_RUNTIME="k2-2025-09-07"

go run ./cmd/shelf-auth
```

---

## Configuration

All via environment variables (parsed with `caarlos0/env`):

| Variable               | Default       | Description |
|------------------------|---------------|-------------|
| `ENV`                  | `dev`         | Environment (`dev`/`prod`) |
| `HTTP_ADDR`            | `:8080`       | HTTP listen address |
| `LOG_LEVEL`            | `info`        | `debug` / `info` / `warn` / `error` |
| `JWT_ALG`              | `RS256`       | Signing algorithm (RS256 supported) |
| `JWT_ISS`              | `shelf-auth`  | JWT `iss` (issuer) |
| `JWT_AUD`              | `shelf-api`   | JWT `aud` (audience) |
| `ACCESS_TTL`           | `15m`         | Access token TTL |
| `REFRESH_TTL`          | `720h`        | Refresh token TTL (e.g. 30 days) |
| `JWKS_MAX_AGE`         | `300s`        | Cache max-age for JWKS |
| `KEYS_DIR`             | `./devkeys`   | Directory with RSA private keys (`*.pem`) |
| `SIGNING_KEY_KID`      | _(required)_  | Active signing key KID (matches PEM filename without `.pem`) |
| `DATABASE_URL`         | _(required)_  | Postgres conn string (e.g. `postgres://user:pass@host:5432/db?sslmode=disable`) |
| `CORS_ORIGINS`         | _(empty)_     | Comma-separated list of allowed origins (e.g. `http://localhost:3000`) |
| `COOKIE_SECURE`        | `true`        | `true/false`, must be `true` if `COOKIE_SAMESITE=None` in modern browsers |
| `COOKIE_SAMESITE`      | `Lax`         | `Lax` / `Strict` / `None` |
| `COOKIE_DOMAIN`        | _(empty)_     | Optional cookie domain |
| `KEYS_RELOAD_INTERVAL` | `60s`         | Periodic reload for signer & JWKS provider |
| `ACTIVE_KID_RUNTIME`   | _(empty)_     | Optional runtime override for active KID (used on hot rotation) |

---

## Project Structure

```
shelf-auth/
├─ cmd/shelf-auth/                # Main entrypoint
├─ internal/
│  ├─ auth/
│  │  ├─ signer/                  # Loads private keys, signs JWT with active KID
│  │  └─ jwks/                    # Publishes JWKS (public keys), ETag/max-age
│  ├─ config/                     # Env config loader
│  ├─ domain/                     # Core domain types
│  ├─ httpserver/
│  │  ├─ handlers/                # Handlers: healthz, jwks, login, refresh, logout
│  │  ├─ middleware/              # Security headers
│  │  └─ (router, samesite)       # Router wiring, SameSite parsing
│  ├─ logging/                    # Zerolog setup
│  ├─ repo/postgres/              # DB repositories (users, sessions)
│  ├─ security/                   # Password hashing & helpers
│  ├─ service/                    # Business logic (register/login/refresh/logout)
│  └─ tokens/                     # AccessClaims, token interfaces
├─ migrations/                    # SQL migrations
├─ devkeys/                       # Local private keys (ignored by git)
├─ tools/                         # Helpers (e.g., password hashing tool)
├─ .github/ISSUE_TEMPLATE/        # GitHub issue templates
└─ docker-compose.yml
```

---

## Makefile Targets

Common targets:

```bash
# Go basics
make tidy
make build
make run

# Docker Compose
make compose-up
make compose-logs
make compose-down
make compose-build

# Migrations
make migrate-up
make migrate-down
make migrate-force

# Seed user
make seed-user SEED_EMAIL=user@example.com SEED_PASSWORD=abc12345

# Tests (unit-only, tagged)
make test-unit
make test-unit-v
make test-unit-race
make test-unit-cover
make test-unit-run RUN=Regex
make test-unit-pkg PKG=./internal/domain

# Integration tests (tagged)
make test-int
make test-int-v
```

---

## Security

### Cookies
- Refresh token is stored in **HttpOnly** cookie (not accessible to JS).
- Flags configurable via env: `COOKIE_SECURE`, `COOKIE_SAMESITE`, `COOKIE_DOMAIN`.
- For cross-site SPA (`SameSite=None`), browsers **require** `Secure=true`.

### Headers
Applied globally:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'`

### CORS
- Allowed origins via `CORS_ORIGINS` (comma-separated).
- `Access-Control-Allow-Credentials: true` for cookie-based auth.

---

## Key Rotation (JWKS & signer)

The service supports **multi-key JWKS** and **safe active-key rotation**:

1. **Add** a new RSA private key:  
   `openssl genrsa -out devkeys/k2-YYYY-MM-DD.pem 2048`
2. **Deploy** the new PEM into `KEYS_DIR` on all instances.
3. **Switch** the active signing key:
   - Restart way: set `SIGNING_KEY_KID=k2-...` and restart.
   - Hot way: set `ACTIVE_KID_RUNTIME=k2-...` and send `SIGHUP` (if you enabled it) or wait for `KEYS_RELOAD_INTERVAL`.
4. **Keep** the old PEM(s) present for at least `ACCESS_TTL` (grace period) so old tokens remain verifiable (JWKS publishes both keys).
5. **Remove** old PEM(s) after grace and refresh JWKS (auto or on `SIGHUP`).

JWKS is served with `ETag` and `Cache-Control: max-age=...`. ETag changes whenever the key set changes.

---

## Database & Migrations

- Postgres schema includes `users` and `sessions`:
  - `users`: email (unique, `citext`), password hash (bcrypt), `email_verified`, timestamps
  - `sessions`: refresh token hash (SHA-256 hex), device_id, IP/UA, expiry, revoked flags
- Apply with `make migrate-up`.
- Seed with `make seed-user ...`.

---

## Tests

We use build tags:

- **Unit tests**: `//go:build unit`  
  Run: `make test-unit`

- **Integration tests**: `//go:build integration`  
  Run: `make test-int`

Coverage:
```bash
make test-unit-cover
```

---

## Error Format

Handlers return JSON errors in a consistent structure:
```json
{"error":"invalid credentials","code":"INVALID_CREDENTIALS"}
```
HTTP codes:
- `401` invalid credentials, missing/invalid refresh
- `409` reuse detected
- `500` internal errors

---

## Roadmap

- OpenAPI spec for endpoints
- `/readyz` readiness probe
- Rate limiting, bruteforce protection
- Email verification & password reset
- Helm charts, CI (lint/test/build/push), K8s manifests
- Observability (metrics/traces), Sentry

---

## License

MIT License.  
See [LICENSE](LICENSE) for details.
