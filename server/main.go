package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"

	coredb "github.com/vaultguard/core/db"
	"github.com/vaultguard/core/identity"
	"github.com/vaultguard/core/oidc"
	"github.com/vaultguard/core/vault"
	"github.com/vaultguard/server/api"
	"github.com/vaultguard/server/config"
	"github.com/vaultguard/server/middleware"
	servertls "github.com/vaultguard/server/tls"
	"github.com/vaultguard/server/store"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// ── Config ────────────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config load failed", "err", err)
		os.Exit(1)
	}

	setupLogging(cfg.LogLevel)

	// ── Postgres ──────────────────────────────────────────────────────────────
	pool, err := coredb.Open(ctx, coredb.Config{
		DSN:      cfg.DatabaseDSN,
		MaxConns: cfg.DBMaxConns,
		MinConns: cfg.DBMinConns,
	})
	if err != nil {
		slog.Error("database connect failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	// ── Redis ─────────────────────────────────────────────────────────────────
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Warn("redis ping failed — continuing without Redis", "err", err)
	}
	defer rdb.Close()

	// ── Core services ─────────────────────────────────────────────────────────
	enc, err := vault.NewEncryptor(cfg.RootKey)
	if err != nil {
		slog.Error("encryptor init failed", "err", err)
		os.Exit(1)
	}

	pg := store.New(pool)

	userSvc := identity.NewUserService(pg)
	clientSvc := identity.NewClientService(pg)
	policySvc := identity.NewPolicyService(pg)

	leaseManager := vault.NewLeaseManager(pg,
		time.Duration(cfg.AccessTokenTTL)*time.Second,
		24*time.Hour,
	)
	secretStore := vault.NewStore(pg, enc, leaseManager, pg)

	// ── OIDC ──────────────────────────────────────────────────────────────────
	km, err := oidc.NewKeyManager(pg, enc, cfg.KeyRotationInterval)
	if err != nil {
		slog.Error("key manager init failed", "err", err)
		os.Exit(1)
	}
	if err := km.Bootstrap(ctx); err != nil {
		slog.Error("key bootstrap failed", "err", err)
		os.Exit(1)
	}

	provider := oidc.NewProvider(cfg.IssuerURL, km, pg, pg, pg)
	tokenIssuer := oidc.NewTokenIssuer(cfg.IssuerURL, km, pg)

	// ── HTTP router ───────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimw.RealIP)
	r.Use(chimw.RequestID)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(corsMiddleware(cfg.AllowedOrigins))
	r.Use(middleware.RequestID)

	oidcH := api.NewOIDCHandler(provider, km, tokenIssuer, userSvc, clientSvc, pg, cfg.IssuerURL)
	oidcH.Routes(r)

	// Vault and Admin routes require auth
	r.Group(func(r chi.Router) {
		r.Use(middleware.BearerAuth(tokenIssuer))
		r.Use(middleware.RateLimitByClientID(200, time.Minute))

		vaultH := api.NewVaultHandler(secretStore, leaseManager)
		vaultH.Routes(r)

		adminH := api.NewAdminHandler(userSvc, clientSvc, policySvc, km, pg)
		adminH.Routes(r)
	})

	// Public health (no auth required)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Rate-limit OIDC auth/token endpoints
	r.With(middleware.RateLimitPerIP(60, time.Minute)).Post("/token", nil)
	r.With(middleware.RateLimitPerIP(30, time.Minute)).Get("/authorize", nil)

	// ── Metrics server ────────────────────────────────────────────────────────
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("ok"))
		})
		srv := &http.Server{Addr: cfg.MetricsAddr, Handler: mux}
		slog.Info("metrics server starting", "addr", cfg.MetricsAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server failed", "err", err)
		}
	}()

	// ── Key rotation goroutine ────────────────────────────────────────────────
	go func() {
		ticker := time.NewTicker(cfg.KeyRotationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := km.Rotate(ctx); err != nil {
					slog.Error("key rotation failed", "err", err)
				}
			}
		}
	}()

	// ── TLS / HTTP server ─────────────────────────────────────────────────────
	tlsCfg, err := servertls.Config(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.DevTLS)
	if err != nil {
		slog.Error("tls config failed", "err", err)
		os.Exit(1)
	}

	httpSrv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	httpsSrv := &http.Server{
		Addr:         cfg.TLSAddr,
		Handler:      r,
		TLSConfig:    tlsCfg,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("http server starting", "addr", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server failed", "err", err)
		}
	}()

	go func() {
		slog.Info("https server starting", "addr", cfg.TLSAddr)
		if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			slog.Error("https server failed", "err", err)
		}
	}()

	slog.Info("vaultguard server started",
		"issuer", cfg.IssuerURL,
		"http", cfg.ListenAddr,
		"https", cfg.TLSAddr,
		"metrics", cfg.MetricsAddr,
	)

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	<-ctx.Done()
	slog.Info("shutting down...")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutCancel()
	_ = httpSrv.Shutdown(shutCtx)
	_ = httpsSrv.Shutdown(shutCtx)
	slog.Info("goodbye")
}

func setupLogging(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}

func corsMiddleware(allowed []string) func(http.Handler) http.Handler {
	allowedMap := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		allowedMap[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if allowedMap["*"] || allowedMap[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Request-Id")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ensure net is used
var _ net.IP
