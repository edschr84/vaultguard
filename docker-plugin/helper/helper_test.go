package helper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// newTestHelper spins up a mock vault server and returns a Helper pointed at it.
func newTestHelper(t *testing.T, mux *http.ServeMux) *Helper {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := &Config{
		ServerURL:   srv.URL,
		AccessToken: "test-token",
	}
	return &Helper{
		ns:     "local",
		mount:  "docker",
		client: newVaultClient(cfg),
	}
}

func TestGet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/local/docker/registry.example.com", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"username":"robot","secret":"s3cr3t"}}`)
	})

	h := newTestHelper(t, mux)

	// Redirect stdin and stdout
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	t.Cleanup(func() { os.Stdin = oldStdin; os.Stdout = oldStdout })

	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	os.Stdin = inR
	os.Stdout = outW

	fmt.Fprintln(inW, "registry.example.com")
	inW.Close()

	if err := h.Get(); err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	outW.Close()

	var buf bytes.Buffer
	io.Copy(&buf, outR)

	var creds dockerCreds
	if err := json.Unmarshal(buf.Bytes(), &creds); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if creds.Username != "robot" {
		t.Errorf("Username = %q, want %q", creds.Username, "robot")
	}
	if creds.Secret != "s3cr3t" {
		t.Errorf("Secret = %q, want %q", creds.Secret, "s3cr3t")
	}
}

func TestStore(t *testing.T) {
	var gotBody map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/local/docker/ghcr.io", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})

	h := newTestHelper(t, mux)

	oldStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = oldStdin })

	inR, inW, _ := os.Pipe()
	os.Stdin = inR

	payload := dockerCreds{ServerURL: "ghcr.io", Username: "octocat", Secret: "ghp_token"}
	b, _ := json.Marshal(payload)
	fmt.Fprint(inW, string(b))
	inW.Close()

	if err := h.Store(); err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	data, ok := gotBody["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data field in request body, got: %v", gotBody)
	}
	if data["username"] != "octocat" {
		t.Errorf("username = %v, want octocat", data["username"])
	}
}

func TestErase(t *testing.T) {
	deleted := false
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/local/docker/registry.example.com", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		}
	})

	h := newTestHelper(t, mux)

	oldStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = oldStdin })

	inR, inW, _ := os.Pipe()
	os.Stdin = inR
	fmt.Fprintln(inW, "registry.example.com")
	inW.Close()

	if err := h.Erase(); err != nil {
		t.Fatalf("Erase() error: %v", err)
	}
	if !deleted {
		t.Error("expected DELETE to be called")
	}
}

func TestList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/local/docker/", func(w http.ResponseWriter, r *http.Request) {
		// Only handle the list endpoint (trailing slash, no extra path)
		if strings.TrimPrefix(r.URL.Path, "/v1/local/docker/") != "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"paths":["registry.example.com","ghcr.io"]}`)
	})
	mux.HandleFunc("/v1/local/docker/registry.example.com", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"username":"robot","secret":"s3"}}`)
	})
	mux.HandleFunc("/v1/local/docker/ghcr.io", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"username":"octocat","secret":"ghp"}}`)
	})

	h := newTestHelper(t, mux)

	oldStdout := os.Stdout
	t.Cleanup(func() { os.Stdout = oldStdout })

	outR, outW, _ := os.Pipe()
	os.Stdout = outW

	if err := h.List(); err != nil {
		t.Fatalf("List() error: %v", err)
	}
	outW.Close()

	var buf bytes.Buffer
	io.Copy(&buf, outR)

	var result map[string]string
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode list output: %v", err)
	}
	if result["registry.example.com"] != "robot" {
		t.Errorf("registry.example.com = %q, want robot", result["registry.example.com"])
	}
	if result["ghcr.io"] != "octocat" {
		t.Errorf("ghcr.io = %q, want octocat", result["ghcr.io"])
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"registry.example.com", "registry.example.com"},
		{"https://ghcr.io/", "ghcr.io"},
		{"https://registry:5000", "registry:5000"},
		{"http://localhost:5000/", "localhost:5000"},
	}
	for _, tc := range cases {
		got := normalizeHost(tc.in)
		if got != tc.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEncodeDecodeHost(t *testing.T) {
	hosts := []string{
		"registry.example.com",
		"registry:5000",
		"ghcr.io",
		"us-central1-docker.pkg.dev",
	}
	for _, h := range hosts {
		encoded := encodeHost(h)
		decoded := decodeHost(encoded)
		if decoded != h {
			t.Errorf("round-trip(%q): got %q via %q", h, decoded, encoded)
		}
	}
}
