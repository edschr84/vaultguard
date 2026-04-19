package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/vaultguard/core/identity"
	"github.com/vaultguard/core/vault"
	"github.com/vaultguard/server/middleware"
)

// VaultHandler handles all secret store endpoints.
type VaultHandler struct {
	store    *vault.Store
	leases   *vault.LeaseManager
	policies *identity.PolicyService
}

// NewVaultHandler creates a VaultHandler.
func NewVaultHandler(store *vault.Store, leases *vault.LeaseManager, policies *identity.PolicyService) *VaultHandler {
	return &VaultHandler{store: store, leases: leases, policies: policies}
}

// Routes registers vault routes on the given router.
// All routes require a valid bearer token.
func (h *VaultHandler) Routes(r chi.Router) {
	// Secrets CRUD
	r.Get("/v1/{namespace}/{mount}/{path}", h.GetSecret)
	r.Post("/v1/{namespace}/{mount}/{path}", h.PutSecret)
	r.Delete("/v1/{namespace}/{mount}/{path}", h.DeleteSecret)
	r.Get("/v1/{namespace}/{mount}", h.ListSecrets)

	// Versions
	r.Get("/v1/{namespace}/{mount}/{path}/versions", h.ListVersions)

	// Lease management
	r.Post("/v1/leases/renew", h.RenewLease)
	r.Post("/v1/leases/revoke", h.RevokeLease)
}

// GetSecret handles GET /v1/{namespace}/{mount}/{path}?version=N
func (h *VaultHandler) GetSecret(w http.ResponseWriter, r *http.Request) {
	ns := chi.URLParam(r, "namespace")
	mount := chi.URLParam(r, "mount")
	path := chi.URLParam(r, "path")
	resource := secretResource(ns, mount, path)
	actor, ok := h.authorize(w, r, "secret.read", resource)
	if !ok {
		return
	}

	var version int32
	if v := r.URL.Query().Get("version"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "bad version")
			return
		}
		version = int32(n)
	}

	secret, err := h.store.GetVersion(r.Context(), ns, mount, path, version, actor)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, secretResponse(secret))
}

// PutSecret handles POST /v1/{namespace}/{mount}/{path}
func (h *VaultHandler) PutSecret(w http.ResponseWriter, r *http.Request) {
	ns := chi.URLParam(r, "namespace")
	mount := chi.URLParam(r, "mount")
	path := chi.URLParam(r, "path")
	resource := secretResource(ns, mount, path)
	actor, ok := h.authorize(w, r, "secret.write", resource)
	if !ok {
		return
	}

	var body struct {
		Data     vault.SecretData `json:"data"`
		Metadata vault.SecretMeta `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "bad JSON body")
		return
	}
	if len(body.Data) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "data is required")
		return
	}

	secret, err := h.store.Put(r.Context(), ns, mount, path, body.Data, body.Metadata, actor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, secretResponse(secret))
}

// DeleteSecret handles DELETE /v1/{namespace}/{mount}/{path}
func (h *VaultHandler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	ns := chi.URLParam(r, "namespace")
	mount := chi.URLParam(r, "mount")
	path := chi.URLParam(r, "path")
	resource := secretResource(ns, mount, path)
	actor, ok := h.authorize(w, r, "secret.delete", resource)
	if !ok {
		return
	}

	if err := h.store.Delete(r.Context(), ns, mount, path, actor); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListSecrets handles GET /v1/{namespace}/{mount}
func (h *VaultHandler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	ns := chi.URLParam(r, "namespace")
	mount := chi.URLParam(r, "mount")
	if _, ok := h.authorize(w, r, "secret.list", fmt.Sprintf("%s/%s/*", ns, mount)); !ok {
		return
	}

	paths, err := h.store.List(r.Context(), ns, mount)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"paths": paths})
}

// ListVersions handles GET /v1/{namespace}/{mount}/{path}/versions
func (h *VaultHandler) ListVersions(w http.ResponseWriter, r *http.Request) {
	ns := chi.URLParam(r, "namespace")
	mount := chi.URLParam(r, "mount")
	path := chi.URLParam(r, "path")
	if _, ok := h.authorize(w, r, "secret.read", secretResource(ns, mount, path)); !ok {
		return
	}

	versions, err := h.store.Versions(r.Context(), ns, mount, path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}

// RenewLease handles POST /v1/leases/renew
func (h *VaultHandler) RenewLease(w http.ResponseWriter, r *http.Request) {
	var body struct {
		LeaseID   string `json:"lease_id"`
		Increment string `json:"increment"` // e.g. "1h"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "bad JSON")
		return
	}

	var increment time.Duration
	if body.Increment != "" {
		var err error
		increment, err = time.ParseDuration(body.Increment)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "bad increment")
			return
		}
	}
	if _, ok := h.authorize(w, r, "lease.renew", "leases/"+body.LeaseID); !ok {
		return
	}

	lease, err := h.leases.Renew(r.Context(), body.LeaseID, increment)
	if err != nil {
		writeError(w, http.StatusBadRequest, "lease_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, lease)
}

// RevokeLease handles POST /v1/leases/revoke
func (h *VaultHandler) RevokeLease(w http.ResponseWriter, r *http.Request) {
	var body struct {
		LeaseID string `json:"lease_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "bad JSON")
		return
	}
	if _, ok := h.authorize(w, r, "lease.revoke", "leases/"+body.LeaseID); !ok {
		return
	}
	if err := h.leases.Revoke(r.Context(), body.LeaseID); err != nil {
		writeError(w, http.StatusBadRequest, "lease_error", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *VaultHandler) authorize(w http.ResponseWriter, r *http.Request, action, resource string) (string, bool) {
	actor := middleware.SubjectFromCtx(r.Context())
	if actor == "" {
		writeError(w, http.StatusUnauthorized, "missing_token", "authenticated subject is required")
		return "", false
	}
	if h.policies == nil {
		writeError(w, http.StatusInternalServerError, "server_error", "vault policy enforcement is not configured")
		return "", false
	}

	clientID := middleware.ClientIDFromCtx(r.Context())
	allowed, err := h.policies.Evaluate(r.Context(), subjectType(actor, clientID), actor, action, resource)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "policy evaluation failed")
		return "", false
	}
	if clientID != "" && clientID != actor {
		clientAllowed, err := h.policies.Evaluate(r.Context(), "client", clientID, action, resource)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "policy evaluation failed")
			return "", false
		}
		allowed = allowed || clientAllowed
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "forbidden", "vault access denied by policy")
		return "", false
	}
	return actor, true
}

func subjectType(subject, clientID string) string {
	if clientID != "" && subject == clientID {
		return "client"
	}
	if _, err := uuid.Parse(subject); err == nil {
		return "user"
	}
	return "client"
}

func secretResource(ns, mount, path string) string {
	return fmt.Sprintf("%s/%s/%s", ns, mount, path)
}

func secretResponse(s *vault.Secret) map[string]any {
	return map[string]any{
		"id":         s.ID,
		"namespace":  s.Namespace,
		"mount":      s.Mount,
		"path":       s.Path,
		"version":    s.Version,
		"data":       s.Data,
		"metadata":   s.Meta,
		"created_at": s.CreatedAt,
	}
}
