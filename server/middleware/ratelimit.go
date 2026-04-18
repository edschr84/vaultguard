package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/httprate"
)

// RateLimitPerIP returns a middleware that limits requests per client IP.
func RateLimitPerIP(reqs int, window time.Duration) func(http.Handler) http.Handler {
	return httprate.LimitByIP(reqs, window)
}

// RateLimitByClientID limits requests per OAuth2 client_id extracted from the
// context (requires BearerAuth to run first).
func RateLimitByClientID(reqs int, window time.Duration) func(http.Handler) http.Handler {
	limiter := httprate.NewRateLimiter(reqs, window,
		httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			cid := ClientIDFromCtx(r.Context())
			if cid == "" {
				return httprate.KeyByIP(r)
			}
			return "client:" + cid, nil
		}),
	)
	return limiter.Handler
}

// RequestID injects a unique request ID header for tracing.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-Id")
		if rid == "" {
			rid = generateRequestID()
		}
		w.Header().Set("X-Request-Id", rid)
		next.ServeHTTP(w, r)
	})
}

func generateRequestID() string {
	b := make([]byte, 8)
	// Use time-based ID as fallback — not cryptographic, just for correlation
	ts := time.Now().UnixNano()
	for i := range b {
		b[i] = byte(ts >> (i * 8))
	}
	return fmt.Sprintf("%x", b)
}
