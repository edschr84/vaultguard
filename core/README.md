# core

Core domain library for Vaultguard. All business logic lives here; it has no HTTP dependency.

## Packages

| Package | Purpose |
|---|---|
| `db` | PostgreSQL connection pool + golang-migrate runner (migrations embedded via `//go:embed`) |
| `vault` | AES-256-GCM envelope encryption, secrets CRUD, lease lifecycle |
| `identity` | User registration/auth (Argon2id), OAuth2 client registration, RBAC policies |
| `oidc` | RS256 JWT issuance, PKCE, authorization codes, device flow, key rotation |

## Building

```bash
cd core
go build ./...
go test ./...
```

## Configuration (consumed by `server`)

| Env var | Description |
|---|---|
| `VAULTGUARD_DATABASE_DSN` | PostgreSQL DSN (pgx format) |
| `VAULTGUARD_ROOT_KEY` | Base64-encoded 32-byte AES root key |

## Generating DB code

```bash
# from repo root
make generate
```

This runs `sqlc generate` inside `core/` and writes `core/db/dbgen/`.
The generated files are not committed — run `make generate` after schema changes.
