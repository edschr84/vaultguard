package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/vaultguard/core/oidc"
)

type ctxKeyToken struct{}
type ctxKeySub struct{}
type ctxKeyScope struct{}
type ctxKeyClientID struct{}

// BearerAuth validates the Authorization: Bearer <token> header using the
// OIDC token issuer and injects claims into the request context.
func BearerAuth(issuer *oidc.TokenIssuer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdr := r.Header.Get("Authorization")
			if hdr == "" || !strings.HasPrefix(hdr, "Bearer ") {
				http.Error(w, `{"error":"missing_token"}`, http.StatusUnauthorized)
				return
			}
			tokenStr := strings.TrimPrefix(hdr, "Bearer ")

			tok, err := issuer.ParseAndVerify(r.Context(), tokenStr)
			if err != nil {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			sub := tok.Subject()
			scope, _ := tok.Get("scope")
			clientID, _ := tok.Get("client_id")

			ctx := r.Context()
			ctx = context.WithValue(ctx, ctxKeyToken{}, tok)
			ctx = context.WithValue(ctx, ctxKeySub{}, sub)
			ctx = context.WithValue(ctx, ctxKeyScope{}, fmt.Sprint(scope))
			ctx = context.WithValue(ctx, ctxKeyClientID{}, fmt.Sprint(clientID))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SubjectFromCtx extracts the authenticated subject (user ID) from the context.
func SubjectFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeySub{}).(string)
	return v
}

// ScopeFromCtx extracts the token scope from the context.
func ScopeFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyScope{}).(string)
	return v
}

// ClientIDFromCtx extracts the client_id claim from the context.
func ClientIDFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyClientID{}).(string)
	return v
}

// HasScope returns true if the token scope contains the required scope.
func HasScope(ctx context.Context, required string) bool {
	s := ScopeFromCtx(ctx)
	for _, part := range strings.Fields(s) {
		if part == required {
			return true
		}
	}
	return false
}

// RequireScope returns a middleware that rejects requests missing a specific scope.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasScope(r.Context(), scope) {
				http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
