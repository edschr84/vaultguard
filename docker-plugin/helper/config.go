package helper

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the credentials loaded from ~/.vaultguard/config.yaml.
type Config struct {
	ServerURL   string `yaml:"server_url"`
	AccessToken string `yaml:"access_token"`
	Insecure    bool   `yaml:"-"`
}

// DefaultNamespace and DefaultMount define where docker credentials are stored.
const (
	DefaultNamespace = "local"
	DefaultMount     = "docker"
)

// LoadConfig reads ~/.vaultguard/config.yaml, then applies VAULTGUARD_* overrides.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		ServerURL: "http://localhost:8080",
	}

	home, err := os.UserHomeDir()
	if err == nil {
		path := filepath.Join(home, ".vaultguard", "config.yaml")
		if raw, err := os.ReadFile(path); err == nil {
			_ = yaml.Unmarshal(raw, cfg)
		}
	}

	if v := os.Getenv("VAULTGUARD_SERVER_URL"); v != "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("VAULTGUARD_ACCESS_TOKEN"); v != "" {
		cfg.AccessToken = v
	}
	if strings.EqualFold(os.Getenv("VAULTGUARD_INSECURE"), "true") {
		cfg.Insecure = true
	}

	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")

	if cfg.AccessToken == "" {
		return nil, fmt.Errorf("not logged in — run: vaultguard login")
	}
	return cfg, nil
}

// HTTPClient returns an http.Client respecting the Insecure flag.
func (c *Config) HTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{ //nolint:gosec
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: c.Insecure,
		},
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}
}
