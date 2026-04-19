package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Administrative operations",
}

func init() {
	adminCmd.AddCommand(adminRotateKeysCmd)
	adminCmd.AddCommand(adminAuditLogCmd)
	adminCmd.AddCommand(adminUsersCmd)
}

// ── rotate-keys ───────────────────────────────────────────────────────────────

var adminRotateKeysCmd = &cobra.Command{
	Use:   "rotate-keys",
	Short: "Trigger immediate signing key rotation",
	RunE:  runAdminRotateKeys,
}

func runAdminRotateKeys(_ *cobra.Command, _ []string) error {
	c := newAPIClient()
	var result map[string]any
	if err := c.post("/admin/rotate-keys", nil, &result); err != nil {
		return err
	}
	printSuccess("signing keys rotated")
	return nil
}

// ── audit-log ─────────────────────────────────────────────────────────────────

var adminAuditLogCmd = &cobra.Command{
	Use:   "audit-log",
	Short: "Display the audit log",
	Example: `  vaultguard admin audit-log
  vaultguard admin audit-log --tail
  vaultguard admin audit-log --limit 20 --json`,
	RunE: runAdminAuditLog,
}

func init() {
	adminAuditLogCmd.Flags().Bool("tail", false, "Poll for new entries every 3 seconds")
	adminAuditLogCmd.Flags().Int("limit", 50, "Number of entries to fetch")
	adminAuditLogCmd.Flags().Int("offset", 0, "Offset for pagination")
}

func runAdminAuditLog(cmd *cobra.Command, _ []string) error {
	tail, _ := cmd.Flags().GetBool("tail")
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")

	if tail {
		return streamAuditLog(limit)
	}

	c := newAPIClient()
	return fetchAndPrintAuditLog(c, limit, offset)
}

func fetchAndPrintAuditLog(c *apiClient, limit, offset int) error {
	var result struct {
		Logs []map[string]any `json:"logs"`
	}
	url := fmt.Sprintf("/admin/audit-log?limit=%d&offset=%d", limit, offset)
	if err := c.get(url, &result); err != nil {
		return err
	}

	if outputJSON {
		printResult(result)
		return nil
	}

	if len(result.Logs) == 0 {
		fmt.Println("(no audit log entries)")
		return nil
	}

	fmt.Printf("%-20s  %-8s  %-10s  %-30s  %-40s  %s\n",
		"Time", "Outcome", "ActorType", "Actor", "Action", "Resource")
	fmt.Println(strings.Repeat("─", 120))
	for _, entry := range result.Logs {
		t := truncate(fmt.Sprint(entry["event_time"]), 19)
		outcome := sanitize(fmt.Sprint(entry["outcome"]))
		actorType := truncate(sanitize(fmt.Sprint(entry["actor_type"])), 8)
		actor := truncate(sanitize(fmt.Sprint(entry["actor_id"])), 30)
		action := truncate(sanitize(fmt.Sprint(entry["action"])), 40)
		resource := truncate(sanitize(fmt.Sprint(entry["resource"])), 40)
		fmt.Printf("%-20s  %-8s  %-10s  %-30s  %-40s  %s\n",
			t, outcome, actorType, actor, action, resource)
	}
	return nil
}

// streamAuditLog polls the audit log, printing new entries as they arrive.
func streamAuditLog(limit int) error {
	c := newAPIClient()
	fmt.Println("Tailing audit log (Ctrl-C to stop)...")
	fmt.Println()

	var lastID float64
	for {
		var result struct {
			Logs []map[string]any `json:"logs"`
		}
		url := fmt.Sprintf("/admin/audit-log?limit=%d&offset=0", limit)
		if err := c.get(url, &result); err != nil {
			fmt.Printf("poll error: %v\n", err)
		} else {
			for i := len(result.Logs) - 1; i >= 0; i-- {
				entry := result.Logs[i]
				id, _ := entry["id"].(float64)
				if id > lastID {
					lastID = id
					t := truncate(fmt.Sprint(entry["event_time"]), 19)
					fmt.Printf("[%s] %-8s %s → %s on %s\n",
						t,
						sanitize(fmt.Sprint(entry["outcome"])),
						sanitize(fmt.Sprint(entry["actor_id"])),
						sanitize(fmt.Sprint(entry["action"])),
						sanitize(fmt.Sprint(entry["resource"])),
					)
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
}

// ── users ────────────────────────────────────────────────────────────────────

var adminUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Manage users",
}

var adminUsersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	RunE:  runAdminUsersList,
}

var adminUsersCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	RunE:  runAdminUsersCreate,
}

var adminUsersDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a user by UUID",
	Args:  cobra.ExactArgs(1),
	RunE:  runAdminUsersDelete,
}

func init() {
	adminUsersCmd.AddCommand(adminUsersListCmd)
	adminUsersCmd.AddCommand(adminUsersCreateCmd)
	adminUsersCmd.AddCommand(adminUsersDeleteCmd)

	adminUsersCreateCmd.Flags().String("username", "", "Username (required)")
	adminUsersCreateCmd.Flags().String("email", "", "Email address (required)")
	adminUsersCreateCmd.Flags().String("password", "", "Password (required)")
	adminUsersCreateCmd.Flags().String("display-name", "", "Display name")
	_ = adminUsersCreateCmd.MarkFlagRequired("username")
	_ = adminUsersCreateCmd.MarkFlagRequired("email")
	_ = adminUsersCreateCmd.MarkFlagRequired("password")
}

func runAdminUsersList(_ *cobra.Command, _ []string) error {
	c := newAPIClient()
	var result struct {
		Users []map[string]any `json:"users"`
	}
	if err := c.get("/admin/users", &result); err != nil {
		return err
	}

	if outputJSON {
		printResult(result)
		return nil
	}

	if len(result.Users) == 0 {
		fmt.Println("(no users)")
		return nil
	}
	fmt.Printf("%-36s  %-20s  %-30s  %s\n", "ID", "Username", "Email", "Enabled")
	fmt.Println(strings.Repeat("─", 92))
	for _, u := range result.Users {
		fmt.Printf("%-36v  %-20v  %-30v  %v\n", u["id"], u["username"], u["email"], u["enabled"])
	}
	return nil
}

func runAdminUsersCreate(cmd *cobra.Command, _ []string) error {
	username, _ := cmd.Flags().GetString("username")
	email, _ := cmd.Flags().GetString("email")
	password, _ := cmd.Flags().GetString("password")
	displayName, _ := cmd.Flags().GetString("display-name")

	c := newAPIClient()
	var result map[string]any
	if err := c.post("/admin/users", map[string]string{
		"username":     username,
		"email":        email,
		"password":     password,
		"display_name": displayName,
	}, &result); err != nil {
		return err
	}

	if outputJSON {
		printResult(result)
		return nil
	}
	printSuccess(fmt.Sprintf("user %q created", username))
	return nil
}

func runAdminUsersDelete(_ *cobra.Command, args []string) error {
	c := newAPIClient()
	if err := c.delete("/admin/users/" + args[0]); err != nil {
		return err
	}
	printSuccess("user deleted")
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// sanitize strips ANSI escape sequences from server-returned strings to prevent
// terminal injection when printing audit log entries.
func sanitize(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\x1b' {
			if i+1 >= len(s) {
				break
			}
			i++
			switch s[i] {
			case '[':
				for i+1 < len(s) {
					i++
					if (s[i] >= '@' && s[i] <= '~') || (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') {
						break
					}
				}
			case ']':
				for i+1 < len(s) {
					i++
					if s[i] == '\a' || (s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '\\') {
						if s[i] == '\x1b' {
							i++
						}
						break
					}
				}
			default:
				// Drop single-character escape sequences as well.
			}
		} else if s[i] >= 0x20 || s[i] == '\n' || s[i] == '\r' || s[i] == '\t' {
			out.WriteByte(s[i])
		}
	}
	return out.String()
}
