# shelf-auth

Authentication and authorization service for the **Shelf** microservice architecture.  
It provides JWT-based access tokens, publishes JWKS for verification, and manages user sessions.

---

## Features

- **Go-based microservice** with chi router
- **Structured logging** (zerolog)
- **Environment-driven config** (caarlos0/env)
- **JWT RS256 access tokens** with `kid` header
- **JWKS endpoint** (`/.well-known/jwks.json`) for public key publishing
- **Health check endpoint** (`/healthz`) for liveness probes
- **Docker-ready** (multi-stage build + docker-compose for local development)
- Extensible: ready to add `/login`, `/refresh`, `/logout`, session management

---

## Endpoints

- `GET /healthz` → returns liveness status
- `GET /.well-known/jwks.json` → returns JWKS with public keys

Example:
```bash
curl http://localhost:8080/healthz
# {"status":"ok","service":"shelf-auth"}

curl http://localhost:8080/.well-known/jwks.json | jq
# {"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"k1-2025-08-30","n":"...","e":"AQAB"}]}
```

---

## Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/shelf-auth.git
cd shelf-auth
```

### 2. Generate dev keys
You need at least one RSA key pair for signing JWTs.

```bash
mkdir -p devkeys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out devkeys/k1-2025-08-30.pem
```

The filename (without `.pem`) becomes the **`kid`**.

### 3. Run locally
```bash
export HTTP_ADDR=":8080"
export LOG_LEVEL="debug"
export JWT_ALG="RS256"
export JWT_ISS="shelf-auth"
export JWT_AUD="shelf-api"
export ACCESS_TTL="15m"
export JWKS_MAX_AGE="300s"
export KEYS_DIR="./devkeys"
export SIGNING_KEY_KID="k1-2025-08-30"

go run ./cmd/shelf-auth
```

### 4. Run with Docker Compose
```bash
docker compose up --build
```

This will:
- Build `shelf-auth` container
- Mount `./devkeys` into the container
- Start the service on port `8080`

---

## Configuration

The service is configured via environment variables:

| Variable           | Default       | Description                                |
|--------------------|---------------|--------------------------------------------|
| `ENV`              | `dev`         | Environment (`dev` / `prod`)              |
| `HTTP_ADDR`        | `:8080`       | HTTP listen address                       |
| `LOG_LEVEL`        | `info`        | Log level (`debug`, `info`, `warn`, `error`) |
| `JWT_ALG`          | `RS256`       | Signing algorithm (currently only RS256)  |
| `JWT_ISS`          | `shelf-auth`  | JWT `iss` (issuer)                        |
| `JWT_AUD`          | `shelf-api`   | JWT `aud` (audience)                      |
| `ACCESS_TTL`       | `15m`         | Access token TTL                          |
| `REFRESH_TTL`      | `720h`        | Refresh token TTL (future use)            |
| `JWKS_MAX_AGE`     | `300s`        | Cache max-age for JWKS endpoint           |
| `KEYS_DIR`         | `./devkeys`   | Directory with RSA PEM keys               |
| `SIGNING_KEY_KID`  | _(required)_  | Active signing key id (matches PEM filename) |
| `DATABASE_URL`     | _(empty)_     | Postgres connection string (future use)   |

---

## Project Structure

```
shelf-auth/
├─ cmd/shelf-auth/        # Main entrypoint
├─ internal/
│  ├─ auth/               # Auth logic (signer, JWKS provider)
│  ├─ config/             # Config loader
│  ├─ httpserver/         # Router and handlers
│  ├─ logging/            # Structured logging
│  ├─ repo/postgres/      # DB layer (stub for now)
│  └─ service/            # Business logic (stub for now)
├─ devkeys/               # Local dev RSA keys (ignored in .git)
└─ .github/ISSUE_TEMPLATE # GitHub issue templates
```

---

## Development

- `go mod tidy` → sync dependencies
- `go test ./...` → run tests (to be added)
- `make build` / `make run` / `make test` → (planned Makefile tasks)

---

## Roadmap

- [ ] PostgreSQL integration and migrations  
- [ ] `/login` endpoint (bcrypt + JWT issuance)  
- [ ] Refresh tokens and `/refresh`  
- [ ] Logout endpoints  
- [ ] Unified error responses  
- [ ] `/readyz` endpoint (readiness checks)  
- [ ] Helm chart for Kubernetes deployment  
- [ ] Gateway (NGINX/Envoy) JWT validation examples  

---

## License

MIT License.  
See [LICENSE](LICENSE) for details.
