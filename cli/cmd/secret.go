package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Read, write, and manage secrets",
}

func init() {
	secretCmd.AddCommand(secretGetCmd)
	secretCmd.AddCommand(secretPutCmd)
	secretCmd.AddCommand(secretListCmd)
	secretCmd.AddCommand(secretVersionsCmd)
	secretCmd.AddCommand(secretDeleteCmd)
}

// ── get ──────────────────────────────────────────────────────────────────────

var secretGetCmd = &cobra.Command{
	Use:   "get <namespace/mount/path>",
	Short: "Read a secret",
	Example: `  vaultguard secret get ci/docker/registry-creds
  vaultguard secret get ci/docker/registry-creds --version 2`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretGet,
}

func init() {
	secretGetCmd.Flags().Int("version", 0, "Specific version to fetch (0 = latest)")
}

func runSecretGet(cmd *cobra.Command, args []string) error {
	ns, mount, path, err := parsePath(args[0])
	if err != nil {
		return err
	}
	version, _ := cmd.Flags().GetInt("version")

	c := newAPIClient()
	url := fmt.Sprintf("/v1/%s/%s/%s", ns, mount, path)
	if version > 0 {
		url += fmt.Sprintf("?version=%d", version)
	}

	var result map[string]any
	if err := c.get(url, &result); err != nil {
		return err
	}

	if outputJSON {
		printResult(result)
		return nil
	}

	// Human-readable: show the data fields
	fmt.Printf("Path:    %s\n", args[0])
	if v, ok := result["version"]; ok {
		fmt.Printf("Version: %v\n", v)
	}
	if t, ok := result["created_at"]; ok {
		fmt.Printf("Created: %v\n", t)
	}
	fmt.Println()
	fmt.Println("Data:")
	if data, ok := result["data"].(map[string]any); ok {
		for k, v := range data {
			fmt.Printf("  %-20s = %v\n", k, v)
		}
	}
	return nil
}

// ── put ──────────────────────────────────────────────────────────────────────

var secretPutCmd = &cobra.Command{
	Use:   "put <namespace/mount/path> key=value [key=value ...]",
	Short: "Write a secret (creates a new version)",
	Example: `  vaultguard secret put ci/docker/registry-creds username=robot password=s3cr3t
  vaultguard secret put prod/db/creds host=db.prod.svc port=5432 password=pgpass`,
	Args: cobra.MinimumNArgs(2),
	RunE: runSecretPut,
}

func runSecretPut(_ *cobra.Command, args []string) error {
	ns, mount, path, err := parsePath(args[0])
	if err != nil {
		return err
	}

	data := make(map[string]string)
	for _, kv := range args[1:] {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid key=value pair: %q", kv)
		}
		data[parts[0]] = parts[1]
	}

	c := newAPIClient()
	var result map[string]any
	if err := c.post(fmt.Sprintf("/v1/%s/%s/%s", ns, mount, path),
		map[string]any{"data": data}, &result); err != nil {
		return err
	}

	if outputJSON {
		printResult(result)
		return nil
	}

	ver := "?"
	if v, ok := result["version"]; ok {
		ver = fmt.Sprint(v)
	}
	printSuccess(fmt.Sprintf("secret written at %s (version %s)", args[0], ver))
	return nil
}

// ── list ─────────────────────────────────────────────────────────────────────

var secretListCmd = &cobra.Command{
	Use:   "list <namespace/mount>",
	Short: "List secret paths under a namespace/mount",
	Example: `  vaultguard secret list ci/docker`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretList,
}

func runSecretList(_ *cobra.Command, args []string) error {
	parts := strings.SplitN(args[0], "/", 2)
	if len(parts) < 2 {
		return fmt.Errorf("specify namespace/mount, got %q", args[0])
	}
	ns, mount := parts[0], parts[1]

	c := newAPIClient()
	var result struct {
		Paths []string `json:"paths"`
	}
	if err := c.get(fmt.Sprintf("/v1/%s/%s", ns, mount), &result); err != nil {
		return err
	}

	if outputJSON {
		printResult(result)
		return nil
	}

	if len(result.Paths) == 0 {
		fmt.Println("(no secrets)")
		return nil
	}
	for _, p := range result.Paths {
		fmt.Printf("  %s/%s/%s\n", ns, mount, p)
	}
	return nil
}

// ── versions ─────────────────────────────────────────────────────────────────

var secretVersionsCmd = &cobra.Command{
	Use:   "versions <namespace/mount/path>",
	Short: "List all versions of a secret",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretVersions,
}

func runSecretVersions(_ *cobra.Command, args []string) error {
	ns, mount, path, err := parsePath(args[0])
	if err != nil {
		return err
	}

	c := newAPIClient()
	var result struct {
		Versions []map[string]any `json:"versions"`
	}
	if err := c.get(fmt.Sprintf("/v1/%s/%s/%s/versions", ns, mount, path), &result); err != nil {
		return err
	}

	if outputJSON {
		printResult(result)
		return nil
	}

	if len(result.Versions) == 0 {
		fmt.Println("(no versions)")
		return nil
	}
	fmt.Printf("%-8s  %-30s\n", "Version", "Created At")
	fmt.Println(strings.Repeat("─", 42))
	for _, v := range result.Versions {
		ver := fmt.Sprint(v["version"])
		created := fmt.Sprint(v["created_at"])
		fmt.Printf("%-8s  %-30s\n", ver, created)
	}
	return nil
}

// ── delete ───────────────────────────────────────────────────────────────────

var secretDeleteCmd = &cobra.Command{
	Use:   "delete <namespace/mount/path>",
	Short: "Soft-delete all versions of a secret",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretDelete,
}

func runSecretDelete(_ *cobra.Command, args []string) error {
	ns, mount, path, err := parsePath(args[0])
	if err != nil {
		return err
	}

	c := newAPIClient()
	if err := c.delete(fmt.Sprintf("/v1/%s/%s/%s", ns, mount, path)); err != nil {
		return err
	}
	printSuccess(fmt.Sprintf("secret %s deleted", args[0]))
	return nil
}

// keep strconv in scope
var _ = strconv.Itoa
