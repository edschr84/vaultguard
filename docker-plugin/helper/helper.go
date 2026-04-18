// Package helper implements the Docker credential helper protocol
// (https://github.com/docker/docker-credential-helpers) backed by Vaultguard.
//
// Credentials are stored at: /v1/<namespace>/<mount>/<encoded-registry>
// with fields "username" and "secret".
//
// Default vault path: local/docker/<registry-hostname>
// Override via VAULTGUARD_DOCKER_NAMESPACE and VAULTGUARD_DOCKER_MOUNT.
package helper

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// dockerCreds is the JSON shape Docker expects from a credential helper.
type dockerCreds struct {
	ServerURL string `json:"ServerURL"`
	Username  string `json:"Username"`
	Secret    string `json:"Secret"`
}

// Helper is the main credential helper implementation.
type Helper struct {
	ns     string
	mount  string
	client *vaultClient
}

// New loads config and returns a ready Helper.
func New() (*Helper, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	ns := os.Getenv("VAULTGUARD_DOCKER_NAMESPACE")
	if ns == "" {
		ns = DefaultNamespace
	}
	mount := os.Getenv("VAULTGUARD_DOCKER_MOUNT")
	if mount == "" {
		mount = DefaultMount
	}
	return &Helper{
		ns:     ns,
		mount:  mount,
		client: newVaultClient(cfg),
	}, nil
}

// Get reads credentials for the registry hostname written to stdin.
// Docker protocol: reads one line from stdin (the ServerURL), writes JSON to stdout.
func (h *Helper) Get() error {
	host, err := readLine()
	if err != nil {
		return err
	}
	host = normalizeHost(host)
	path := encodeHost(host)

	data, err := h.client.getSecret(h.ns, h.mount, path)
	if err != nil {
		return fmt.Errorf("credentials not found for %s: %w", host, err)
	}

	return json.NewEncoder(os.Stdout).Encode(dockerCreds{
		ServerURL: host,
		Username:  data["username"],
		Secret:    data["secret"],
	})
}

// Store saves credentials written as JSON to stdin into the vault.
// Docker protocol: reads {ServerURL, Username, Secret} JSON from stdin, writes nothing on success.
func (h *Helper) Store() error {
	var creds dockerCreds
	if err := json.NewDecoder(os.Stdin).Decode(&creds); err != nil {
		return fmt.Errorf("decode credentials: %w", err)
	}

	host := normalizeHost(creds.ServerURL)
	path := encodeHost(host)

	return h.client.putSecret(h.ns, h.mount, path, map[string]string{
		"username": creds.Username,
		"secret":   creds.Secret,
	})
}

// Erase removes credentials for the registry hostname written to stdin.
// Docker protocol: reads one line from stdin (the ServerURL), writes nothing on success.
func (h *Helper) Erase() error {
	host, err := readLine()
	if err != nil {
		return err
	}
	host = normalizeHost(host)
	path := encodeHost(host)

	if err := h.client.deleteSecret(h.ns, h.mount, path); err != nil {
		return fmt.Errorf("erase credentials for %s: %w", host, err)
	}
	return nil
}

// List returns all stored registries as a JSON map of {serverURL: username}.
// Docker protocol: reads nothing, writes JSON map to stdout.
func (h *Helper) List() error {
	paths, err := h.client.listSecrets(h.ns, h.mount)
	if err != nil {
		return fmt.Errorf("list credentials: %w", err)
	}

	result := make(map[string]string, len(paths))
	for _, p := range paths {
		host := decodeHost(p)
		data, err := h.client.getSecret(h.ns, h.mount, p)
		if err != nil {
			continue
		}
		result[host] = data["username"]
	}

	return json.NewEncoder(os.Stdout).Encode(result)
}

// ── helpers ───────────────────────────────────────────────────────────────────

// readLine reads a single line from stdin (strips trailing newline).
func readLine() (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text()), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("empty input")
}

// normalizeHost strips scheme and trailing slashes so "https://ghcr.io/" → "ghcr.io".
func normalizeHost(raw string) string {
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			raw = u.Host
		}
	}
	return strings.TrimRight(raw, "/")
}

// encodeHost percent-encodes a registry hostname so it is safe as a vault path segment.
// "registry.example.com:5000" → "registry.example.com%3A5000"
func encodeHost(host string) string {
	return url.PathEscape(host)
}

// decodeHost reverses encodeHost.
func decodeHost(encoded string) string {
	h, err := url.PathUnescape(encoded)
	if err != nil {
		return encoded
	}
	return h
}
