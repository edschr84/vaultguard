package cmd

import (
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate via OIDC device flow and store credentials",
	Long: `Initiates the OAuth2 device authorization flow.
Vaultguard prints a URL and user code — open the URL in a browser,
enter the code, and the CLI will store the resulting token.`,
	RunE: runLogin,
}

func init() {
	loginCmd.Flags().String("client-id", "", "OAuth2 client ID (defaults to config value)")
	loginCmd.Flags().String("server", "", "Override server URL for this login")
}

func runLogin(cmd *cobra.Command, _ []string) error {
	clientID, _ := cmd.Flags().GetString("client-id")
	if clientID == "" {
		clientID = cfg.ClientID
	}
	if clientID == "" {
		clientID = "vaultguard-cli"
	}

	if s, _ := cmd.Flags().GetString("server"); s != "" {
		cfg.ServerURL = s
	}

	c := newAPIClient()

	// Step 1 — request device + user codes
	var dcResp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := c.postForm("/device/code", map[string]string{
		"client_id": clientID,
		"scope":     "openid profile email offline_access",
	}, &dcResp); err != nil {
		return fmt.Errorf("device code request: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n  Open this URL in your browser:\n\n    %s\n\n", dcResp.VerificationURIComplete)
	fmt.Fprintf(os.Stderr, "  Enter code: %s\n\n", dcResp.UserCode)
	fmt.Fprintf(os.Stderr, "Waiting for approval")

	// Step 2 — poll for token
	interval := time.Duration(dcResp.Interval) * time.Second
	if interval == 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(dcResp.ExpiresIn) * time.Second)

	for time.Now().Before(deadline) {
		time.Sleep(interval)
		fmt.Fprint(os.Stderr, ".")

		var tokResp struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
			Error        string `json:"error"`
		}
		err := c.postForm("/token", map[string]string{
			"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
			"device_code": dcResp.DeviceCode,
			"client_id":   clientID,
		}, &tokResp)
		if err != nil {
			errStr := err.Error()
			if isAuthPending(errStr) {
				continue
			}
			if isSlowDown(errStr) {
				interval += 5 * time.Second
				continue
			}
			// Fatal errors
			fmt.Fprintln(os.Stderr, "")
			return fmt.Errorf("token poll: %w", err)
		}

		// Success
		fmt.Fprintln(os.Stderr, " done!")

		cfg.AccessToken = tokResp.AccessToken
		cfg.RefreshToken = tokResp.RefreshToken
		cfg.ClientID = clientID
		if tokResp.ExpiresIn > 0 {
			cfg.AccessTokenExpiry = time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second)
		}
		if s, _ := cmd.Flags().GetString("server"); s != "" {
			cfg.ServerURL = s
		}

		if err := saveConfig(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not save config: %v\n", err)
		}

		fmt.Println("Logged in successfully.")
		fmt.Printf("Token expires: %s\n", cfg.AccessTokenExpiry.Format(time.RFC3339))
		return nil
	}

	fmt.Fprintln(os.Stderr, "")
	return fmt.Errorf("device code expired — please run 'vaultguard login' again")
}

func isAuthPending(e string) bool {
	return contains(e, "authorization_pending") || contains(e, "pending")
}

func isSlowDown(e string) bool {
	return contains(e, "slow_down")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}

// logoutCmd clears stored credentials.
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear stored credentials",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg.AccessToken = ""
		cfg.RefreshToken = ""
		cfg.AccessTokenExpiry = time.Time{}
		if err := saveConfig(); err != nil {
			return err
		}
		fmt.Println("Logged out.")
		return nil
	},
}

// whoamiCmd introspects the current token.
var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current authenticated identity",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if cfg.AccessToken == "" {
			return fmt.Errorf("not logged in — run 'vaultguard login'")
		}
		c := newAPIClient()
		var result map[string]any
		if err := c.get("/userinfo", &result); err != nil {
			return err
		}
		printResult(result)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(whoamiCmd)
}

// Keep url import used
var _ = url.QueryEscape
