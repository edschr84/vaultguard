package helper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// vaultClient talks to the Vaultguard server's vault API.
type vaultClient struct {
	cfg  *Config
	http *http.Client
}

func newVaultClient(cfg *Config) *vaultClient {
	return &vaultClient{cfg: cfg, http: cfg.HTTPClient()}
}

func (c *vaultClient) do(method, path string, body any, result any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		r = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.cfg.ServerURL+path, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.AccessToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("token expired or invalid — run: vaultguard login")
	}
	if resp.StatusCode >= 400 {
		var e map[string]string
		if json.Unmarshal(raw, &e) == nil && e["error"] != "" {
			return fmt.Errorf("%s", e["error"])
		}
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	if result != nil && len(raw) > 0 {
		return json.Unmarshal(raw, result)
	}
	return nil
}

func (c *vaultClient) getSecret(ns, mount, path string) (map[string]string, error) {
	var result struct {
		Data map[string]string `json:"data"`
	}
	if err := c.do(http.MethodGet, fmt.Sprintf("/v1/%s/%s/%s", ns, mount, path), nil, &result); err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *vaultClient) putSecret(ns, mount, path string, data map[string]string) error {
	body := map[string]any{"data": data}
	return c.do(http.MethodPost, fmt.Sprintf("/v1/%s/%s/%s", ns, mount, path), body, nil)
}

func (c *vaultClient) deleteSecret(ns, mount, path string) error {
	return c.do(http.MethodDelete, fmt.Sprintf("/v1/%s/%s/%s", ns, mount, path), nil, nil)
}

func (c *vaultClient) listSecrets(ns, mount string) ([]string, error) {
	var result struct {
		Paths []string `json:"paths"`
	}
	if err := c.do(http.MethodGet, fmt.Sprintf("/v1/%s/%s/", ns, mount), nil, &result); err != nil {
		return nil, err
	}
	return result.Paths, nil
}
