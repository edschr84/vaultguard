package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Token management commands",
}

var tokenInspectCmd = &cobra.Command{
	Use:   "inspect <token>",
	Short: "Decode and display a JWT",
	Args:  cobra.ExactArgs(1),
	RunE:  runTokenInspect,
}

var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke <token>",
	Short: "Revoke a token",
	Args:  cobra.ExactArgs(1),
	RunE:  runTokenRevoke,
}

func init() {
	tokenInspectCmd.Flags().Bool("verify", false, "Verify signature against server JWKS")
	tokenCmd.AddCommand(tokenInspectCmd)
	tokenCmd.AddCommand(tokenRevokeCmd)
}

func runTokenInspect(cmd *cobra.Command, args []string) error {
	tokenStr := args[0]

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return fmt.Errorf("not a valid JWT (expected 3 dot-separated parts)")
	}

	// Decode header
	header, err := decodeJWTPart(parts[0])
	if err != nil {
		return fmt.Errorf("decode header: %w", err)
	}

	// Decode claims
	claims, err := decodeJWTPart(parts[1])
	if err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}

	if outputJSON {
		printResult(map[string]any{
			"header": header,
			"claims": claims,
		})
		return nil
	}

	// Human-readable output
	fmt.Println("─── Header ───────────────────────────────────")
	printMap(header)
	fmt.Println()
	fmt.Println("─── Claims ───────────────────────────────────")

	// Format known time fields
	for _, field := range []string{"exp", "iat", "nbf"} {
		if v, ok := claims[field]; ok {
			if f, ok := v.(float64); ok {
				t := time.Unix(int64(f), 0)
				claims[field+"_human"] = t.Format(time.RFC3339)
				if field == "exp" {
					if t.Before(time.Now()) {
						claims["_expired"] = true
					} else {
						claims["_expires_in"] = time.Until(t).Round(time.Second).String()
					}
				}
			}
		}
	}
	printMap(claims)

	// Verify flag
	if verify, _ := cmd.Flags().GetBool("verify"); verify {
		fmt.Println()
		fmt.Println("─── Verification ─────────────────────────────")
		if err := verifyTokenOnline(tokenStr); err != nil {
			fmt.Printf("  ✗ Invalid: %v\n", err)
		} else {
			fmt.Println("  ✓ Signature valid")
		}
	}

	return nil
}

func runTokenRevoke(_ *cobra.Command, args []string) error {
	c := newAPIClient()
	err := c.postForm("/token/revoke", map[string]string{
		"token": args[0],
	}, nil)
	if err != nil {
		return err
	}
	printSuccess("token revoked")
	return nil
}

// verifyTokenOnline introspects the token against the server.
func verifyTokenOnline(tokenStr string) error {
	c := newAPIClient()
	var result map[string]any
	if err := c.postForm("/token/introspect", map[string]string{
		"token": tokenStr,
	}, &result); err != nil {
		return err
	}
	active, _ := result["active"].(bool)
	if !active {
		return fmt.Errorf("token is not active")
	}
	return nil
}

func decodeJWTPart(part string) (map[string]any, error) {
	// JWT uses raw base64url (no padding)
	b, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func printMap(m map[string]any) {
	// Stable-ish ordering: put underscore-prefixed meta keys last
	keys := make([]string, 0, len(m))
	metaKeys := make([]string, 0)
	for k := range m {
		if strings.HasPrefix(k, "_") {
			metaKeys = append(metaKeys, k)
		} else {
			keys = append(keys, k)
		}
	}
	keys = append(keys, metaKeys...)

	for _, k := range keys {
		v := m[k]
		switch val := v.(type) {
		case string:
			fmt.Printf("  %-22s %s\n", k+":", val)
		case float64:
			fmt.Printf("  %-22s %v\n", k+":", int64(val))
		case bool:
			fmt.Printf("  %-22s %v\n", k+":", val)
		case []any:
			strs := make([]string, len(val))
			for i, e := range val {
				strs[i] = fmt.Sprint(e)
			}
			fmt.Printf("  %-22s [%s]\n", k+":", strings.Join(strs, ", "))
		default:
			b, _ := json.Marshal(val)
			fmt.Printf("  %-22s %s\n", k+":", string(b))
		}
	}
}
