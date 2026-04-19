package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ── Config on disk ──────────────────────────────────────────────────────────

type Config struct {
	ServerURL         string    `mapstructure:"server_url"          yaml:"server_url"`
	AccessToken       string    `mapstructure:"access_token"        yaml:"access_token"`
	AccessTokenExpiry time.Time `mapstructure:"access_token_expiry" yaml:"access_token_expiry"`
	RefreshToken      string    `mapstructure:"refresh_token"       yaml:"refresh_token"`
	ClientID          string    `mapstructure:"client_id"           yaml:"client_id"`
}

var (
	cfgFile    string
	outputJSON bool
	skipVerify bool
	cfg        Config
)

// ── Root command ─────────────────────────────────────────────────────────────

var rootCmd = &cobra.Command{
	Use:   "vaultguard",
	Short: "Vaultguard — policy-gated secret access CLI",
	Long: `vaultguard is the operator CLI for Vaultguard, an opinionated tool that
denies secret access unless the caller matches an explicit Vaultguard policy.`,
	SilenceUsage: true,
}

// Execute is the main entry point called from main().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default ~/.vaultguard/config.yaml)")
	rootCmd.PersistentFlags().String("server", "", "Vaultguard server URL (overrides config)")
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "Output raw JSON")
	rootCmd.PersistentFlags().BoolVar(&skipVerify, "insecure", false, "Skip TLS certificate verification (dev mode)")

	_ = viper.BindPFlag("server_url", rootCmd.PersistentFlags().Lookup("server"))

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(tokenCmd)
	rootCmd.AddCommand(secretCmd)
	rootCmd.AddCommand(clientCmd)
	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(adminCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		viper.AddConfigPath(filepath.Join(home, ".vaultguard"))
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("VAULTGUARD")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Defaults
	viper.SetDefault("server_url", "http://localhost:8080")
	viper.SetDefault("client_id", "vaultguard-cli")

	_ = viper.ReadInConfig()
	_ = viper.Unmarshal(&cfg)
}

// saveConfig writes the current cfg back to disk.
func saveConfig() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".vaultguard")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	cfgPath := filepath.Join(dir, "config.yaml")

	viper.Set("server_url", cfg.ServerURL)
	viper.Set("access_token", cfg.AccessToken)
	viper.Set("access_token_expiry", cfg.AccessTokenExpiry)
	viper.Set("refresh_token", cfg.RefreshToken)
	viper.Set("client_id", cfg.ClientID)

	return viper.WriteConfigAs(cfgPath)
}

// ── API client ───────────────────────────────────────────────────────────────

type apiClient struct {
	base  string
	token string
	http  *http.Client
}

func newAPIClient() *apiClient {
	if skipVerify {
		fmt.Fprintln(os.Stderr, "WARNING: TLS verification disabled (--insecure). Do not use in production.")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify}, //nolint:gosec
	}
	return &apiClient{
		base:  strings.TrimRight(cfg.ServerURL, "/"),
		token: cfg.AccessToken,
		http:  &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}
}

func (c *apiClient) do(method, path string, body, result any) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.base+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		// Try to extract a JSON error message
		var errResp map[string]string
		if json.Unmarshal(rawBody, &errResp) == nil {
			if e, ok := errResp["error"]; ok {
				desc := errResp["error_description"]
				if desc != "" {
					return fmt.Errorf("%s: %s", e, desc)
				}
				return fmt.Errorf("%s", e)
			}
		}
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(rawBody)))
	}

	if result != nil && len(rawBody) > 0 {
		if err := json.Unmarshal(rawBody, result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func (c *apiClient) get(path string, result any) error {
	return c.do(http.MethodGet, path, nil, result)
}

func (c *apiClient) post(path string, body, result any) error {
	return c.do(http.MethodPost, path, body, result)
}

func (c *apiClient) postForm(path string, fields map[string]string, result any) error {
	// OAuth2 form-encoded POST
	sb := strings.Builder{}
	i := 0
	for k, v := range fields {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(k + "=" + v)
		i++
	}
	req, err := http.NewRequest(http.MethodPost, c.base+path, strings.NewReader(sb.String()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		var e map[string]string
		if json.Unmarshal(raw, &e) == nil {
			return fmt.Errorf("%s: %s", e["error"], e["error_description"])
		}
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	if result != nil {
		return json.Unmarshal(raw, result)
	}
	return nil
}

func (c *apiClient) delete(path string) error {
	return c.do(http.MethodDelete, path, nil, nil)
}

// ── Output helpers ────────────────────────────────────────────────────────────

func printResult(v any) {
	if outputJSON {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
		return
	}
	// For non-JSON mode, pretty-print as indented JSON for now
	// (a real CLI would have table formatters per command)
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func printSuccess(msg string) {
	fmt.Fprintln(os.Stdout, "✓ "+msg)
}

func die(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

// parsePath splits "namespace/mount/path" into three parts.
// path can contain slashes (everything after second "/").
func parsePath(full string) (ns, mount, path string, err error) {
	parts := strings.SplitN(full, "/", 3)
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("path must be namespace/mount/path, got %q", full)
	}
	return parts[0], parts[1], parts[2], nil
}
