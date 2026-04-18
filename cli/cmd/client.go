package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Manage OAuth2 client registrations",
}

func init() {
	clientCmd.AddCommand(clientCreateCmd)
	clientCmd.AddCommand(clientListCmd)
	clientCmd.AddCommand(clientGetCmd)
	clientCmd.AddCommand(clientDeleteCmd)
}

// ── create ───────────────────────────────────────────────────────────────────

var clientCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Register a new OAuth2 client",
	Example: `  vaultguard client create --name "My CI Bot" --type confidential \
    --redirect-uris https://ci.example.com/callback \
    --scopes "openid profile" --grants "authorization_code,refresh_token"`,
	RunE: runClientCreate,
}

func init() {
	clientCreateCmd.Flags().String("name", "", "Client name (required)")
	clientCreateCmd.Flags().String("type", "confidential", "Client type: confidential or public")
	clientCreateCmd.Flags().StringSlice("redirect-uris", nil, "Allowed redirect URIs")
	clientCreateCmd.Flags().String("scopes", "openid profile email", "Space-separated allowed scopes")
	clientCreateCmd.Flags().String("grants", "authorization_code,refresh_token", "Comma-separated allowed grant types")
	clientCreateCmd.Flags().Int32("access-token-ttl", 900, "Access token TTL in seconds")
	clientCreateCmd.Flags().Int32("refresh-token-ttl", 86400, "Refresh token TTL in seconds")
	_ = clientCreateCmd.MarkFlagRequired("name")
}

func runClientCreate(cmd *cobra.Command, _ []string) error {
	name, _ := cmd.Flags().GetString("name")
	clientType, _ := cmd.Flags().GetString("type")
	redirectURIs, _ := cmd.Flags().GetStringSlice("redirect-uris")
	scopesStr, _ := cmd.Flags().GetString("scopes")
	grantsStr, _ := cmd.Flags().GetString("grants")
	atTTL, _ := cmd.Flags().GetInt32("access-token-ttl")
	rtTTL, _ := cmd.Flags().GetInt32("refresh-token-ttl")

	scopes := strings.Fields(scopesStr)
	grants := strings.Split(grantsStr, ",")
	for i := range grants {
		grants[i] = strings.TrimSpace(grants[i])
	}

	c := newAPIClient()
	var result map[string]any
	if err := c.post("/admin/clients", map[string]any{
		"name":              name,
		"type":              clientType,
		"redirect_uris":     redirectURIs,
		"allowed_scopes":    scopes,
		"allowed_grants":    grants,
		"access_token_ttl":  atTTL,
		"refresh_token_ttl": rtTTL,
	}, &result); err != nil {
		return err
	}

	if outputJSON {
		printResult(result)
		return nil
	}

	client, _ := result["client"].(map[string]any)
	secret, _ := result["client_secret"].(string)

	fmt.Println("Client registered successfully.")
	fmt.Println()
	if client != nil {
		fmt.Printf("  %-20s %v\n", "Client ID:", client["client_id"])
		fmt.Printf("  %-20s %v\n", "Name:", client["name"])
		fmt.Printf("  %-20s %v\n", "Type:", client["type"])
	}
	if secret != "" {
		fmt.Println()
		fmt.Printf("  %-20s %s\n", "Client Secret:", secret)
		fmt.Println()
		fmt.Println("  ⚠  Save the client secret now — it will not be shown again.")
	}
	return nil
}

// ── list ─────────────────────────────────────────────────────────────────────

var clientListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered OAuth2 clients",
	RunE:  runClientList,
}

func runClientList(_ *cobra.Command, _ []string) error {
	c := newAPIClient()
	var result struct {
		Clients []map[string]any `json:"clients"`
	}
	if err := c.get("/admin/clients", &result); err != nil {
		return err
	}

	if outputJSON {
		printResult(result)
		return nil
	}

	if len(result.Clients) == 0 {
		fmt.Println("(no clients registered)")
		return nil
	}

	fmt.Printf("%-36s  %-24s  %-14s  %s\n", "Client ID", "Name", "Type", "Enabled")
	fmt.Println(strings.Repeat("─", 84))
	for _, cl := range result.Clients {
		fmt.Printf("%-36v  %-24v  %-14v  %v\n",
			cl["client_id"], cl["name"], cl["type"], cl["enabled"])
	}
	return nil
}

// ── get ──────────────────────────────────────────────────────────────────────

var clientGetCmd = &cobra.Command{
	Use:   "get <client-id>",
	Short: "Show details for a registered OAuth2 client",
	Args:  cobra.ExactArgs(1),
	RunE:  runClientGet,
}

func runClientGet(_ *cobra.Command, args []string) error {
	c := newAPIClient()
	var result map[string]any
	if err := c.get("/admin/clients/"+args[0], &result); err != nil {
		return err
	}
	printResult(result)
	return nil
}

// ── delete ───────────────────────────────────────────────────────────────────

var clientDeleteCmd = &cobra.Command{
	Use:   "delete <uuid>",
	Short: "Delete an OAuth2 client by its internal UUID",
	Args:  cobra.ExactArgs(1),
	RunE:  runClientDelete,
}

func runClientDelete(_ *cobra.Command, args []string) error {
	c := newAPIClient()
	if err := c.delete("/admin/clients/" + args[0]); err != nil {
		return err
	}
	printSuccess("client deleted")
	return nil
}
