package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/vaultguard/core/identity"
	"github.com/vaultguard/core/oidc"
	"github.com/vaultguard/core/vault"
	"github.com/vaultguard/server/middleware"
	"github.com/vaultguard/server/store"
)

// AdminHandler handles the management API used by the CLI and future UI.
type AdminHandler struct {
	users      *identity.UserService
	clients    *identity.ClientService
	policies   *identity.PolicyService
	keyManager *oidc.KeyManager
	audit      vault.AuditLogger
	db         *store.DB
}

// NewAdminHandler creates an AdminHandler.
func NewAdminHandler(
	users *identity.UserService,
	clients *identity.ClientService,
	policies *identity.PolicyService,
	km *oidc.KeyManager,
	audit vault.AuditLogger,
	db *store.DB,
) *AdminHandler {
	return &AdminHandler{
		users: users, clients: clients, policies: policies,
		keyManager: km, audit: audit, db: db,
	}
}

// Routes registers admin routes (all behind /admin prefix and auth middleware).
func (h *AdminHandler) Routes(r chi.Router) {
	// Health
	r.Get("/healthz", h.Health)
	r.Get("/readyz", h.Health)

	// Users
	r.Get("/admin/users", h.ListUsers)
	r.Post("/admin/users", h.CreateUser)
	r.Get("/admin/users/{id}", h.GetUser)
	r.Delete("/admin/users/{id}", h.DeleteUser)

	// OAuth2 clients
	r.Get("/admin/clients", h.ListClients)
	r.Post("/admin/clients", h.CreateClient)
	r.Get("/admin/clients/{id}", h.GetClient)
	r.Delete("/admin/clients/{id}", h.DeleteClient)

	// Policies
	r.Get("/admin/policies", h.ListPolicies)
	r.Post("/admin/policies", h.UpsertPolicy)
	r.Post("/admin/policies/{name}/bind", h.BindPolicy)
	r.Delete("/admin/policies/{name}", h.DeletePolicy)

	// Ops
	r.Post("/admin/rotate-keys", h.RotateKeys)
	r.Get("/admin/audit-log", h.AuditLog)
}

// Health serves a simple health check.
func (h *AdminHandler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ─── Users ────────────────────────────────────────────────────────────────────

func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginate(r)
	users, err := h.users.List(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users, "limit": limit, "offset": offset})
}

func (h *AdminHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var p identity.CreateUserParams
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "bad JSON")
		return
	}
	if len(p.Username) == 0 || len(p.Username) > 255 {
		writeError(w, http.StatusBadRequest, "invalid_request", "username must be between 1 and 255 characters")
		return
	}
	if len(p.Email) == 0 || len(p.Email) > 255 {
		writeError(w, http.StatusBadRequest, "invalid_request", "email must be between 1 and 255 characters")
		return
	}
	if len(p.Password) == 0 || len(p.Password) > 1024 {
		writeError(w, http.StatusBadRequest, "invalid_request", "password must be between 1 and 1024 characters")
		return
	}
	user, err := h.users.Create(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if h.audit != nil {
		_ = h.audit.Log(r.Context(), vault.AuditEvent{
			ActorType: "admin", ActorID: middleware.SubjectFromCtx(r.Context()),
			Action: "user.create", Resource: user.ID.String(), Outcome: "success",
		})
	}
	writeJSON(w, http.StatusCreated, user)
}

func (h *AdminHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "bad user id")
		return
	}
	user, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "bad user id")
		return
	}
	if err := h.users.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if h.audit != nil {
		_ = h.audit.Log(r.Context(), vault.AuditEvent{
			ActorType: "admin", ActorID: middleware.SubjectFromCtx(r.Context()),
			Action: "user.delete", Resource: id.String(), Outcome: "success",
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Clients ──────────────────────────────────────────────────────────────────

func (h *AdminHandler) ListClients(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginate(r)
	clients, err := h.clients.List(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

func (h *AdminHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name            string               `json:"name"`
		Type            identity.ClientType  `json:"type"`
		RedirectURIs    []string             `json:"redirect_uris"`
		AllowedScopes   []string             `json:"allowed_scopes"`
		AllowedGrants   []identity.GrantType `json:"allowed_grants"`
		AccessTokenTTL  int32                `json:"access_token_ttl"`
		RefreshTokenTTL int32                `json:"refresh_token_ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "bad JSON")
		return
	}
	if len(body.Name) == 0 || len(body.Name) > 255 {
		writeError(w, http.StatusBadRequest, "invalid_request", "name must be between 1 and 255 characters")
		return
	}
	for _, uri := range body.RedirectURIs {
		u, err := url.Parse(uri)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			writeError(w, http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("invalid redirect_uri %q: must be absolute http/https URL", uri))
			return
		}
	}
	if body.Type == "" {
		body.Type = identity.ClientTypeConfidential
	}

	reg, err := h.clients.Register(r.Context(), identity.CreateClientParams{
		Name:            body.Name,
		Type:            body.Type,
		RedirectURIs:    body.RedirectURIs,
		AllowedScopes:   body.AllowedScopes,
		AllowedGrants:   body.AllowedGrants,
		AccessTokenTTL:  body.AccessTokenTTL,
		RefreshTokenTTL: body.RefreshTokenTTL,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if h.audit != nil {
		_ = h.audit.Log(r.Context(), vault.AuditEvent{
			ActorType: "admin", ActorID: middleware.SubjectFromCtx(r.Context()),
			Action: "client.create", Resource: reg.Client.ID.String(), Outcome: "success",
		})
	}
	// Include plaintext secret only in this response
	writeJSON(w, http.StatusCreated, map[string]any{
		"client":        reg.Client,
		"client_secret": reg.ClientSecret,
	})
}

func (h *AdminHandler) GetClient(w http.ResponseWriter, r *http.Request) {
	client, err := h.clients.GetByClientID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "client not found")
		return
	}
	writeJSON(w, http.StatusOK, client)
}

func (h *AdminHandler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "bad client id")
		return
	}
	if err := h.clients.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if h.audit != nil {
		_ = h.audit.Log(r.Context(), vault.AuditEvent{
			ActorType: "admin", ActorID: middleware.SubjectFromCtx(r.Context()),
			Action: "client.delete", Resource: id.String(), Outcome: "success",
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Policies ────────────────────────────────────────────────────────────────

func (h *AdminHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginate(r)
	policies, err := h.policies.List(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies})
}

func (h *AdminHandler) UpsertPolicy(w http.ResponseWriter, r *http.Request) {
	var p identity.CreatePolicyParams
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "bad JSON")
		return
	}
	if len(p.Name) == 0 || len(p.Name) > 255 {
		writeError(w, http.StatusBadRequest, "invalid_request", "name must be between 1 and 255 characters")
		return
	}
	if p.RegoSource != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "rego_source is not supported")
		return
	}
	for i, rule := range p.Rules {
		if rule.Effect != "allow" && rule.Effect != "deny" {
			writeError(w, http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("rule %d: effect must be \"allow\" or \"deny\"", i))
			return
		}
		if len(rule.Actions) == 0 || len(rule.Resources) == 0 {
			writeError(w, http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("rule %d: actions and resources must be non-empty", i))
			return
		}
	}
	pol, err := h.policies.CreateOrUpdate(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if h.audit != nil {
		_ = h.audit.Log(r.Context(), vault.AuditEvent{
			ActorType: "admin", ActorID: middleware.SubjectFromCtx(r.Context()),
			Action: "policy.upsert", Resource: pol.ID.String(), Outcome: "success",
		})
	}
	writeJSON(w, http.StatusOK, pol)
}

func (h *AdminHandler) BindPolicy(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var body struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "bad JSON")
		return
	}
	if body.SubjectType != "user" && body.SubjectType != "client" {
		writeError(w, http.StatusBadRequest, "invalid_request", "subject_type must be \"user\" or \"client\"")
		return
	}
	if body.SubjectID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "subject_id is required")
		return
	}
	if err := h.policies.Bind(r.Context(), name, body.SubjectType, body.SubjectID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	pol, err := h.db.GetPolicyByName(r.Context(), chi.URLParam(r, "name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "policy not found")
		return
	}
	if err := h.db.DeletePolicy(r.Context(), pol.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if h.audit != nil {
		_ = h.audit.Log(r.Context(), vault.AuditEvent{
			ActorType: "admin", ActorID: middleware.SubjectFromCtx(r.Context()),
			Action: "policy.delete", Resource: pol.ID.String(), Outcome: "success",
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Operations ───────────────────────────────────────────────────────────────

func (h *AdminHandler) RotateKeys(w http.ResponseWriter, r *http.Request) {
	if err := h.keyManager.Rotate(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if h.audit != nil {
		_ = h.audit.Log(r.Context(), vault.AuditEvent{
			ActorType: "admin", ActorID: middleware.SubjectFromCtx(r.Context()),
			Action: "keys.rotate", Resource: "signing_keys", Outcome: "success",
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rotated"})
}

func (h *AdminHandler) AuditLog(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginate(r)
	logs, err := h.db.ListAuditLog(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs, "limit": limit, "offset": offset})
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func paginate(r *http.Request) (limit, offset int32) {
	limit = 50
	offset = 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 200 {
			limit = int32(n)
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = int32(n)
		}
	}
	return
}

// Ensure unused imports don't block compile
var _ = time.Now
var _ = vault.Store{}
