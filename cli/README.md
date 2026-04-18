# cli

The `vaultguard` operator CLI — built with cobra + viper, talks to the server Admin API over HTTP/HTTPS.

## Installation

```bash
go install github.com/vaultguard/cli@latest
# Binary is installed as "vaultguard" (rename main binary in go install) 
# For local development:
go build -o bin/vaultguard ./cli
```

## Quick start

```bash
# Point at your server (saved to ~/.vaultguard/config.yaml)
vaultguard --server https://vault.example.com login

# Write a secret
vaultguard secret put ci/docker/registry-creds username=robot password=s3cr3t

# Read it back
vaultguard secret get ci/docker/registry-creds

# Register a CI bot client
vaultguard client create --name "CI Bot" --type confidential \
  --grants "client_credentials"
```

## Commands

### Authentication
| Command | Description |
|---|---|
| `vaultguard login` | OIDC device flow login — opens browser URL + polls for token |
| `vaultguard logout` | Clear stored credentials |
| `vaultguard whoami` | Show current identity (calls /userinfo) |

### Token
| Command | Description |
|---|---|
| `vaultguard token inspect <token>` | Decode JWT header + claims, show expiry |
| `vaultguard token inspect <token> --verify` | Also introspect against server |
| `vaultguard token revoke <token>` | Revoke a token |

### Secrets
| Command | Description |
|---|---|
| `vaultguard secret get <ns/mount/path>` | Read latest version |
| `vaultguard secret get <path> --version 2` | Read specific version |
| `vaultguard secret put <path> k=v [k=v ...]` | Write new version |
| `vaultguard secret list <ns/mount>` | List all paths |
| `vaultguard secret versions <path>` | Show all versions |
| `vaultguard secret delete <path>` | Soft-delete |

### OAuth2 Clients
| Command | Description |
|---|---|
| `vaultguard client create` | Register new client (prints secret once) |
| `vaultguard client list` | List all clients |
| `vaultguard client get <client-id>` | Get client details |
| `vaultguard client delete <uuid>` | Delete a client |

### Policies
| Command | Description |
|---|---|
| `vaultguard policy set <name> rules.json` | Create/update policy from JSON rules |
| `vaultguard policy set <name> policy.rego` | Create/update from Rego (OPA stub) |
| `vaultguard policy list` | List all policies |
| `vaultguard policy bind <name> user <user-id>` | Bind policy to user |
| `vaultguard policy bind <name> client <client-id>` | Bind policy to client |
| `vaultguard policy delete <name>` | Delete policy |

### Administration
| Command | Description |
|---|---|
| `vaultguard admin rotate-keys` | Trigger immediate signing key rotation |
| `vaultguard admin audit-log` | Paginated audit log |
| `vaultguard admin audit-log --tail` | Stream new entries (polls every 3s) |
| `vaultguard admin users list` | List all users |
| `vaultguard admin users create` | Create a user |
| `vaultguard admin users delete <id>` | Delete a user |

## Global flags

| Flag | Default | Description |
|---|---|---|
| `--server <url>` | From config | Override server URL |
| `--json` | `false` | Output raw JSON (machine-readable) |
| `--insecure` | `false` | Skip TLS verification (dev) |
| `--config <path>` | `~/.vaultguard/config.yaml` | Config file |

## Configuration file

`~/.vaultguard/config.yaml`:
```yaml
server_url: https://vault.example.com
access_token: eyJ...
access_token_expiry: 2024-01-01T15:00:00Z
refresh_token: ""
client_id: vaultguard-cli
```

All fields can be overridden with `VAULTGUARD_*` environment variables:
- `VAULTGUARD_SERVER_URL`
- `VAULTGUARD_ACCESS_TOKEN`
- `VAULTGUARD_CLIENT_ID`
