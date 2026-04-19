# Vaultguard Roadmap

Opinionated secret-access enforcement for containerised workloads. VaultGuard should deny access by default and only release secrets when the calling user or client matches an explicit policy.

---

## Completed

### Step 1 — Core domain packages (`core/`)
- **`core/db`** — pgx/v5 connection pool, embedded SQL migrations (10 tables), golang-migrate runner
- **`core/identity`** — UserService (Argon2id passwords), ClientService (OAuth2 clients), PolicyService (glob rule engine, allow/deny)
- **`core/vault`** — AES-256-GCM envelope encryption, versioned secret store, lease manager
- **`core/oidc`** — RS256 JWT issuance, PKCE (S256 only), authorization code flow, device flow (RFC 8628), token introspection (RFC 7662), revocation (RFC 7009), key rotation, OIDC discovery document

### Step 2 — HTTP server (`server/`)
- Chi router with TLS (auto self-signed in dev mode), Prometheus metrics, structured JSON logging
- **OIDC endpoints:** `/authorize`, `/token`, `/userinfo`, `/introspect`, `/revoke`, `/device/code`, `/device/verify`, `/.well-known/openid-configuration`, `/jwks.json`
- **Vault API:** `GET/POST/DELETE /v1/{ns}/{mount}/{path}`, list paths, list versions, lease renew/revoke
- **Admin API:** users CRUD, OAuth2 clients CRUD, policies CRUD, signing key rotation, paginated audit log
- Rate limiting per IP and per client_id, request ID middleware, CORS, graceful shutdown

### Step 3 — Operator CLI (`cli/`)
- `vaultguard login` — OIDC device flow, saves token to `~/.vaultguard/config.yaml`
- `vaultguard logout` / `whoami`
- `vaultguard token inspect [--verify]` / `token revoke`
- `vaultguard secret get/put/list/versions/delete`
- `vaultguard client create/list/get/delete`
- `vaultguard policy set/list/bind/delete`
- `vaultguard admin rotate-keys` / `audit-log [--tail]` / `users list/create/delete`

### Step 4 — Docker credential helper (`docker-plugin/`) + security hardening
- `docker-credential-vaultguard` binary implementing the Docker credential helper protocol
- `get`, `store`, `erase`, `list` commands via stdin/stdout
- Credentials stored in vault at `local/docker/<encoded-registry>`
- Reads auth token from `~/.vaultguard/config.yaml` (written by CLI login)
- Registry hostnames with ports safely percent-encoded as vault path segments
- **Security fixes applied:**
  - PKCE `plain` method rejected — S256 enforced at both validation and verification
  - `--insecure` TLS skip emits a loud warning to stderr
  - Vault secret reads audit-logged on success and failure
  - Root key length validated at encryptor initialisation

---

## In Progress / Pending

### Step 5 — Kubernetes controller (`k8s-controller/`)
- `VaultSecret` CRD — declarative secret sync from Vaultguard vault into Kubernetes Secrets
- controller-runtime reconciler: watches `VaultSecret` resources, fetches from vault, writes K8s Secret, re-syncs on expiry
- Mutating admission webhook: injects a sidecar or init container to pull secrets at pod startup
- Leader election for HA deployments
- RBAC manifests (ClusterRole, ServiceAccount, ClusterRoleBinding)

### Step 6 — Helm chart (`deploy/helm/`)
- Production-ready chart for `server` + `k8s-controller`
- Configurable replicas, resource limits, ingress, TLS via cert-manager
- Prometheus `ServiceMonitor` for scraping metrics
- `values.yaml` with sensible defaults; secrets via existing K8s Secret or external-secrets

---

## Design Principles

| Principle | Decision |
|---|---|
| No ORM | Raw SQL via pgx/v5; sqlc for query generation |
| No magic | Explicit wiring in `server/main.go`; no DI framework |
| Crypto | AES-256-GCM (secrets), Argon2id (passwords), RS256 (tokens) |
| Audit | Append-only audit log enforced by PostgreSQL triggers |
| Auth | OIDC-native; CLI uses device flow; K8s uses client credentials |
| Transport | TLS everywhere; self-signed cert generated in dev mode |

---

## Non-Goals (for now)

- UI / web console
- Dynamic secret backends (PostgreSQL, AWS IAM) — interfaces stubbed, not implemented
- Multi-tenancy beyond namespace/mount path prefixes
- LDAP / SAML federation
