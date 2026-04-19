# server

The Vaultguard HTTP server binary. Wires together OIDC, the vault store, and policy enforcement behind a Chi router with TLS, rate-limiting, and Prometheus metrics.

## Endpoints

### OIDC / OAuth2
| Method | Path | Description |
|---|---|---|
| GET | `/.well-known/openid-configuration` | Discovery document |
| GET | `/.well-known/jwks.json` | Public JWK set |
| GET/POST | `/authorize` | Authorization endpoint (code + PKCE) |
| POST | `/token` | Token endpoint (all grant types) |
| POST | `/token/revoke` | RFC 7009 revocation |
| POST | `/token/introspect` | RFC 7662 introspection |
| GET/POST | `/userinfo` | OIDC userinfo |
| GET/POST | `/device/code` | Device authorization (RFC 8628) |
| GET/POST | `/device` | User-facing device verification page |

### Vault
| Method | Path | Description |
|---|---|---|
| GET | `/v1/{ns}/{mount}/{path}` | Read secret (latest or `?version=N`) |
| POST | `/v1/{ns}/{mount}/{path}` | Write secret |
| DELETE | `/v1/{ns}/{mount}/{path}` | Soft-delete secret |
| GET | `/v1/{ns}/{mount}` | List secret paths |
| GET | `/v1/{ns}/{mount}/{path}/versions` | List all versions |
| POST | `/v1/leases/renew` | Renew a lease |
| POST | `/v1/leases/revoke` | Revoke a lease |

Vault endpoints are deny-by-default and require a matching bound policy for the calling user or client.

### Admin (requires `admin` scope)
| Method | Path | Description |
|---|---|---|
| GET/POST | `/admin/users` | List / create users |
| GET/DELETE | `/admin/users/{id}` | Get / delete user |
| GET/POST | `/admin/clients` | List / register OAuth2 clients |
| GET/DELETE | `/admin/clients/{id}` | Get / delete client |
| GET/POST | `/admin/policies` | List / upsert policies |
| POST | `/admin/policies/{name}/bind` | Bind policy to subject |
| DELETE | `/admin/policies/{name}` | Delete policy |
| POST | `/admin/rotate-keys` | Trigger signing key rotation |
| GET | `/admin/audit-log` | Paginated audit log |
| GET | `/healthz` | Health check |

### Observability
| Path | Description |
|---|---|
| `:9090/metrics` | Prometheus metrics |
| `:9090/healthz` | Health probe |

## Building

```bash
go build -o bin/vaultguard-server ./server
```

## Configuration

All settings via environment variables (prefix `VAULTGUARD_`):

| Variable | Default | Description |
|---|---|---|
| `VAULTGUARD_DATABASE_DSN` | — | PostgreSQL DSN (required) |
| `VAULTGUARD_ROOT_KEY` | — | Base64 32-byte AES root key (required) |
| `VAULTGUARD_ISSUER_URL` | `http://localhost:8080` | OIDC issuer URL |
| `VAULTGUARD_REDIS_ADDR` | `localhost:6379` | Redis address |
| `VAULTGUARD_LISTEN_ADDR` | `:8080` | HTTP listen address |
| `VAULTGUARD_TLS_ADDR` | `:8443` | HTTPS listen address |
| `VAULTGUARD_METRICS_ADDR` | `:9090` | Prometheus metrics address |
| `VAULTGUARD_DEV_TLS` | `false` | Auto-generate self-signed TLS cert |
| `VAULTGUARD_TLS_CERT_FILE` | — | TLS certificate file |
| `VAULTGUARD_TLS_KEY_FILE` | — | TLS private key file |
| `VAULTGUARD_KEY_ROTATION_INTERVAL` | `24h` | Signing key rotation interval |
| `VAULTGUARD_ACCESS_TOKEN_TTL` | `900` | Access token TTL (seconds) |
| `VAULTGUARD_REFRESH_TOKEN_TTL` | `86400` | Refresh token TTL (seconds) |
| `VAULTGUARD_LOG_LEVEL` | `info` | Log level (debug/info/warn/error) |
| `VAULTGUARD_ALLOWED_ORIGINS` | `*` | CORS allowed origins |

## Running locally

```bash
export VAULTGUARD_DATABASE_DSN="postgres://vaultguard:vaultguard@localhost:5432/vaultguard?sslmode=disable"
export VAULTGUARD_ROOT_KEY=$(openssl rand -base64 32)
export VAULTGUARD_DEV_TLS=true

# Start backing services
docker compose -f deploy/docker-compose.yml up postgres redis -d

# Run the server
go run ./server
```
