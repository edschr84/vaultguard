package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage access policies",
}

func init() {
	policyCmd.AddCommand(policySetCmd)
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyBindCmd)
	policyCmd.AddCommand(policyDeleteCmd)
}

// ── set (upsert) ─────────────────────────────────────────────────────────────

var policySetCmd = &cobra.Command{
	Use:   "set <name> [rules.json]",
	Short: "Create or update a policy from a JSON rules file",
	Long: `Upload a policy to Vaultguard.

Rules file (JSON):
  [
    {"effect": "allow", "actions": ["secret.read"], "resources": ["ci/docker/*"]},
    {"effect": "deny",  "actions": ["secret.delete"], "resources": ["prod/*"]}
  ]`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runPolicySet,
}

func init() {
	policySetCmd.Flags().String("description", "", "Human-readable description")
}

func runPolicySet(cmd *cobra.Command, args []string) error {
	name := args[0]
	desc, _ := cmd.Flags().GetString("description")

	body := map[string]any{
		"name":        name,
		"description": desc,
		"rules":       []any{},
	}

	if len(args) == 2 {
		filePath := args[1]
		raw, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}

		if strings.HasSuffix(filePath, ".rego") {
			return fmt.Errorf("rego policies are not supported")
		}
		var rules []any
		if err := json.Unmarshal(raw, &rules); err != nil {
			return fmt.Errorf("parse rules JSON: %w", err)
		}
		body["rules"] = rules
	}

	c := newAPIClient()
	var result map[string]any
	if err := c.post("/admin/policies", body, &result); err != nil {
		return err
	}

	if outputJSON {
		printResult(result)
		return nil
	}
	printSuccess(fmt.Sprintf("policy %q saved", name))
	return nil
}

// ── list ─────────────────────────────────────────────────────────────────────

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all policies",
	RunE:  runPolicyList,
}

func runPolicyList(_ *cobra.Command, _ []string) error {
	c := newAPIClient()
	var result struct {
		Policies []map[string]any `json:"policies"`
	}
	if err := c.get("/admin/policies", &result); err != nil {
		return err
	}

	if outputJSON {
		printResult(result)
		return nil
	}

	if len(result.Policies) == 0 {
		fmt.Println("(no policies)")
		return nil
	}
	fmt.Printf("%-24s  %-8s  %s\n", "Name", "Enabled", "Description")
	fmt.Println(strings.Repeat("─", 60))
	for _, p := range result.Policies {
		fmt.Printf("%-24v  %-8v  %v\n", p["name"], p["enabled"], p["description"])
	}
	return nil
}

// ── bind ─────────────────────────────────────────────────────────────────────

var policyBindCmd = &cobra.Command{
	Use:   "bind <policy-name> <subject-type> <subject-id>",
	Short: "Bind a policy to a user or client",
	Example: `  vaultguard policy bind ci-read user 550e8400-e29b-41d4-a716-446655440000
  vaultguard policy bind ci-read client my-ci-client`,
	Args: cobra.ExactArgs(3),
	RunE: runPolicyBind,
}

func runPolicyBind(_ *cobra.Command, args []string) error {
	c := newAPIClient()
	if err := c.post(fmt.Sprintf("/admin/policies/%s/bind", args[0]), map[string]string{
		"subject_type": args[1],
		"subject_id":   args[2],
	}, nil); err != nil {
		return err
	}
	printSuccess(fmt.Sprintf("policy %q bound to %s %q", args[0], args[1], args[2]))
	return nil
}

// ── delete ───────────────────────────────────────────────────────────────────

var policyDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a policy by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyDelete,
}

func runPolicyDelete(_ *cobra.Command, args []string) error {
	c := newAPIClient()
	if err := c.delete("/admin/policies/" + args[0]); err != nil {
		return err
	}
	printSuccess(fmt.Sprintf("policy %q deleted", args[0]))
	return nil
}
