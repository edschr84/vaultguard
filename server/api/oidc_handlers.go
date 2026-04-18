package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/vaultguard/core/identity"
	"github.com/vaultguard/core/oidc"
)

// OIDCHandler handles all OIDC / OAuth2 endpoints.
type OIDCHandler struct {
	provider   *oidc.Provider
	keyManager *oidc.KeyManager
	issuer     *oidc.TokenIssuer
	users      *identity.UserService
	clients    *identity.ClientService
	devices    oidc.DeviceCodeStore
	issuerURL  string
}

// NewOIDCHandler creates an OIDCHandler.
func NewOIDCHandler(
	provider *oidc.Provider,
	km *oidc.KeyManager,
	issuer *oidc.TokenIssuer,
	users *identity.UserService,
	clients *identity.ClientService,
	devices oidc.DeviceCodeStore,
	issuerURL string,
) *OIDCHandler {
	return &OIDCHandler{
		provider:   provider,
		keyManager: km,
		issuer:     issuer,
		users:      users,
		clients:    clients,
		devices:    devices,
		issuerURL:  issuerURL,
	}
}

// Routes registers all OIDC routes on the given router.
func (h *OIDCHandler) Routes(r chi.Router) {
	r.Get("/.well-known/openid-configuration", h.Discovery)
	r.Get("/.well-known/jwks.json", h.JWKS)
	r.Get("/authorize", h.Authorize)
	r.Post("/authorize", h.AuthorizeSubmit)
	r.Post("/token", h.Token)
	r.Post("/token/revoke", h.Revoke)
	r.Post("/token/introspect", h.Introspect)
	r.Get("/userinfo", h.UserInfo)
	r.Post("/userinfo", h.UserInfo)
	r.Get("/device/code", h.DeviceCode)
	r.Post("/device/code", h.DeviceCode)
	r.Get("/device", h.DeviceVerify)
	r.Post("/device", h.DeviceVerifySubmit)
}

// Discovery serves /.well-known/openid-configuration.
func (h *OIDCHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	doc := oidc.BuildDiscovery(h.issuerURL)
	writeJSON(w, http.StatusOK, doc)
}

// JWKS serves /.well-known/jwks.json.
func (h *OIDCHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	set, err := h.keyManager.PublicKeySet(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	b, err := json.Marshal(set)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

// Authorize handles GET /authorize — shows the login form.
func (h *OIDCHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	if clientID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}

	// Validate client exists
	if _, err := h.clients.GetByClientID(r.Context(), clientID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_client", "unknown client")
		return
	}

	// Validate PKCE if provided
	if cc := q.Get("code_challenge"); cc != "" {
		if err := oidc.ValidateCodeChallenge(cc, q.Get("code_challenge_method")); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
	}

	// Render minimal HTML login form
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, loginFormHTML,
		clientID,
		q.Get("redirect_uri"),
		q.Get("scope"),
		q.Get("state"),
		q.Get("nonce"),
		q.Get("code_challenge"),
		q.Get("code_challenge_method"),
		q.Get("response_type"),
	)
}

// AuthorizeSubmit handles POST /authorize — processes login and issues the code.
func (h *OIDCHandler) AuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "bad form data")
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")

	user, err := h.users.Authenticate(r.Context(), email, password)
	if err != nil {
		// Re-render form with error
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `<p style="color:red">Invalid credentials. <a href="%s">Try again</a></p>`, r.Referer())
		return
	}

	req := oidc.AuthorizationRequest{
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         redirectURI,
		ResponseType:        r.FormValue("response_type"),
		Scope:               r.FormValue("scope"),
		State:               state,
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}

	code, retState, err := h.provider.Authorize(r.Context(), req, user.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "server_error", err.Error())
		return
	}

	// Redirect to client with code
	ru, _ := url.Parse(redirectURI)
	q := ru.Query()
	q.Set("code", code)
	if retState != "" {
		q.Set("state", retState)
	}
	ru.RawQuery = q.Encode()
	http.Redirect(w, r, ru.String(), http.StatusFound)
}

// Token handles POST /token — all grant types.
func (h *OIDCHandler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, "invalid_request", "bad form data")
		return
	}

	grantType := r.FormValue("grant_type")
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	client, err := h.clients.GetByClientID(r.Context(), clientID)
	if err != nil {
		writeOAuthError(w, "invalid_client", "unknown client")
		return
	}

	// Validate secret for confidential clients
	if client.Type == identity.ClientTypeConfidential && clientSecret != "" {
		if !h.clients.ValidateSecret(r.Context(), clientID, clientSecret) {
			writeOAuthError(w, "invalid_client", "bad client credentials")
			return
		}
	}

	ttls := oidc.ClientTTLs{
		AccessTokenTTL:  client.AccessTokenTTL,
		RefreshTokenTTL: client.RefreshTokenTTL,
	}

	switch grantType {
	case "authorization_code":
		h.tokenAuthCode(w, r, ttls)
	case "refresh_token":
		h.tokenRefresh(w, r, clientID, ttls)
	case "client_credentials":
		h.tokenClientCredentials(w, r, clientID, client.AllowedScopes, ttls)
	case "urn:ietf:params:oauth:grant-type:device_code":
		h.tokenDevice(w, r, ttls)
	default:
		writeOAuthError(w, "unsupported_grant_type", grantType)
	}
}

func (h *OIDCHandler) tokenAuthCode(w http.ResponseWriter, r *http.Request, ttls oidc.ClientTTLs) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	verifier := r.FormValue("code_verifier")

	resp, err := h.provider.ExchangeCode(r.Context(), code, redirectURI, verifier, ttls)
	if err != nil {
		writeOAuthError(w, "invalid_grant", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *OIDCHandler) tokenRefresh(w http.ResponseWriter, r *http.Request, clientID string, ttls oidc.ClientTTLs) {
	refreshToken := r.FormValue("refresh_token")
	rtRow, err := h.issuer.VerifyRefreshToken(r.Context(), refreshToken)
	if err != nil {
		writeOAuthError(w, "invalid_grant", err.Error())
		return
	}

	sub := clientID
	if rtRow.UserID != nil {
		sub = rtRow.UserID.String()
	}

	at, err := h.issuer.IssueAccessToken(r.Context(), sub, clientID,
		[]string{clientID}, rtRow.Scope,
		tokenTTL(ttls.AccessTokenTTL), nil)
	if err != nil {
		writeOAuthError(w, "server_error", err.Error())
		return
	}

	// Rotate refresh token
	_ = h.issuer.RevokeRefreshToken(r.Context(), refreshToken)
	newRT, err := h.issuer.IssueRefreshToken(r.Context(), clientID, rtRow.UserID, rtRow.Scope, tokenTTL(ttls.RefreshTokenTTL))
	if err != nil {
		writeOAuthError(w, "server_error", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, oidc.TokenResponse{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    int(ttls.AccessTokenTTL),
		RefreshToken: newRT,
		Scope:        rtRow.Scope,
	})
}

func (h *OIDCHandler) tokenClientCredentials(w http.ResponseWriter, r *http.Request, clientID string, scopes []string, ttls oidc.ClientTTLs) {
	scope := r.FormValue("scope")
	if scope == "" {
		scope = strings.Join(scopes, " ")
	}
	at, err := h.issuer.IssueAccessToken(r.Context(), clientID, clientID,
		[]string{clientID}, scope, tokenTTL(ttls.AccessTokenTTL), nil)
	if err != nil {
		writeOAuthError(w, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, oidc.TokenResponse{
		AccessToken: at,
		TokenType:   "Bearer",
		ExpiresIn:   int(ttls.AccessTokenTTL),
		Scope:       scope,
	})
}

func (h *OIDCHandler) tokenDevice(w http.ResponseWriter, r *http.Request, ttls oidc.ClientTTLs) {
	deviceCode := r.FormValue("device_code")
	resp, err := h.provider.PollDeviceToken(r.Context(), deviceCode, ttls)
	if err != nil {
		code := "authorization_pending"
		switch err.Error() {
		case "expired_token":
			code = "expired_token"
		case "access_denied":
			code = "access_denied"
		case "invalid_client":
			code = "invalid_client"
		}
		writeOAuthError(w, code, "")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Revoke handles POST /token/revoke (RFC 7009).
func (h *OIDCHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, "invalid_request", "")
		return
	}
	token := r.FormValue("token")
	// Best-effort revocation — always return 200 per RFC 7009
	_ = h.issuer.RevokeRefreshToken(r.Context(), token)
	w.WriteHeader(http.StatusOK)
}

// Introspect handles POST /token/introspect (RFC 7662).
func (h *OIDCHandler) Introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, "invalid_request", "")
		return
	}
	tokenStr := r.FormValue("token")
	tok, err := h.issuer.ParseAndVerify(r.Context(), tokenStr)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	scope, _ := tok.Get("scope")
	clientID, _ := tok.Get("client_id")
	writeJSON(w, http.StatusOK, map[string]any{
		"active":    true,
		"sub":       tok.Subject(),
		"iss":       tok.Issuer(),
		"aud":       tok.Audience(),
		"exp":       tok.Expiration().Unix(),
		"iat":       tok.IssuedAt().Unix(),
		"jti":       tok.JwtID(),
		"scope":     fmt.Sprint(scope),
		"client_id": fmt.Sprint(clientID),
	})
}

// UserInfo handles GET/POST /userinfo.
func (h *OIDCHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "missing_token", "")
		return
	}
	tok, err := h.issuer.ParseAndVerify(r.Context(), strings.TrimPrefix(hdr, "Bearer "))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}

	userID, parseErr := uuid.Parse(tok.Subject())
	if parseErr != nil {
		// Client credentials token — return minimal claims
		writeJSON(w, http.StatusOK, map[string]any{"sub": tok.Subject()})
		return
	}

	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sub":                user.ID.String(),
		"preferred_username": user.Username,
		"name":               user.DisplayName,
		"email":              user.Email,
		"email_verified":     user.EmailVerified,
	})
}

// DeviceCode handles GET/POST /device/code — initiates the device flow.
func (h *OIDCHandler) DeviceCode(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, "invalid_request", "")
		return
	}
	clientID := r.FormValue("client_id")
	scope := r.FormValue("scope")
	if scope == "" {
		scope = "openid"
	}

	resp, err := h.provider.InitiateDeviceFlow(r.Context(), clientID, scope)
	if err != nil {
		writeOAuthError(w, "server_error", err.Error())
		return
	}
	resp.VerificationURIComplete = resp.VerificationURI + "?user_code=" + url.QueryEscape(resp.UserCode)
	writeJSON(w, http.StatusOK, resp)
}

// DeviceVerify shows the user-facing device verification page.
func (h *OIDCHandler) DeviceVerify(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, deviceVerifyHTML, userCode, userCode)
}

// DeviceVerifySubmit processes the user approval/denial of a device code.
func (h *OIDCHandler) DeviceVerifySubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	userCode := r.FormValue("user_code")
	action := r.FormValue("action")
	email := r.FormValue("email")
	password := r.FormValue("password")

	user, err := h.users.Authenticate(r.Context(), email, password)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<p>Invalid credentials.</p><a href="/device?user_code=%s">Try again</a>`, userCode)
		return
	}

	switch action {
	case "approve":
		if err := h.devices.ApproveDeviceCode(r.Context(), userCode, user.ID); err != nil {
			http.Error(w, "approval failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<h2>Approved!</h2><p>You may close this window.</p>`)
	case "deny":
		_ = h.devices.DenyDeviceCode(r.Context(), userCode)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<h2>Denied.</h2><p>You may close this window.</p>`)
	default:
		http.Error(w, "invalid action", http.StatusBadRequest)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, errCode, desc string) {
	writeJSON(w, code, map[string]string{"error": errCode, "error_description": desc})
}

func writeOAuthError(w http.ResponseWriter, errCode, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": errCode, "error_description": desc})
}

func tokenTTL(seconds int32) time.Duration {
	return time.Duration(seconds) * time.Second
}

// ─── HTML templates ───────────────────────────────────────────────────────────

const loginFormHTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Vaultguard Login</title>
<style>body{font-family:sans-serif;max-width:400px;margin:80px auto}input{width:100%%;padding:8px;margin:4px 0}button{padding:10px 20px;background:#2563eb;color:#fff;border:0;border-radius:4px;cursor:pointer}</style>
</head><body>
<h2>Sign in to Vaultguard</h2>
<form method="post" action="/authorize">
  <input type="hidden" name="client_id"             value="%s">
  <input type="hidden" name="redirect_uri"           value="%s">
  <input type="hidden" name="scope"                  value="%s">
  <input type="hidden" name="state"                  value="%s">
  <input type="hidden" name="nonce"                  value="%s">
  <input type="hidden" name="code_challenge"         value="%s">
  <input type="hidden" name="code_challenge_method"  value="%s">
  <input type="hidden" name="response_type"          value="%s">
  <label>Email or username<br><input type="text" name="email" autocomplete="username" required></label><br>
  <label>Password<br><input type="password" name="password" autocomplete="current-password" required></label><br>
  <button type="submit">Sign in</button>
</form></body></html>`

const deviceVerifyHTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Device Verification</title>
<style>body{font-family:sans-serif;max-width:400px;margin:80px auto}input{width:100%%;padding:8px;margin:4px 0}button{padding:10px 20px;margin:4px;border:0;border-radius:4px;cursor:pointer}.approve{background:#16a34a;color:#fff}.deny{background:#dc2626;color:#fff}</style>
</head><body>
<h2>Device Authorization</h2>
<form method="post" action="/device">
  <input type="hidden" name="user_code" value="%s">
  <label>Email or username<br><input type="text" name="email" autocomplete="username" required></label><br>
  <label>Password<br><input type="password" name="password" autocomplete="current-password" required></label><br>
  <p>User code: <strong>%s</strong></p>
  <button type="submit" name="action" value="approve" class="approve">Approve</button>
  <button type="submit" name="action" value="deny"    class="deny">Deny</button>
</form></body></html>`

// ensure time is used
var _ time.Duration
