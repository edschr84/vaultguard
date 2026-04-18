package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all server configuration, loaded from env vars or a YAML file.
type Config struct {
	// Database
	DatabaseDSN string

	// Redis
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	// Crypto
	RootKey string // base64-encoded 32-byte AES root key

	// OIDC
	IssuerURL           string
	KeyRotationInterval time.Duration
	AccessTokenTTL      int32 // seconds
	RefreshTokenTTL     int32 // seconds

	// HTTP
	ListenAddr  string // HTTP listen address e.g. :8080
	TLSAddr     string // HTTPS listen address e.g. :8443
	MetricsAddr string // Prometheus /metrics e.g. :9090

	// TLS
	DevTLS      bool   // auto-generate self-signed cert
	TLSCertFile string
	TLSKeyFile  string

	// CORS
	AllowedOrigins []string

	// Logging
	LogLevel string

	// DB pool
	DBMaxConns int32
	DBMinConns int32
}

// Load reads configuration from environment variables (prefixed VAULTGUARD_)
// and optionally from a YAML config file at $VAULTGUARD_CONFIG_FILE.
func Load() (*Config, error) {
	v := viper.New()

	v.SetEnvPrefix("VAULTGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Defaults
	v.SetDefault("listen_addr", ":8080")
	v.SetDefault("tls_addr", ":8443")
	v.SetDefault("metrics_addr", ":9090")
	v.SetDefault("issuer_url", "http://localhost:8080")
	v.SetDefault("key_rotation_interval", "24h")
	v.SetDefault("access_token_ttl", 900)
	v.SetDefault("refresh_token_ttl", 86400)
	v.SetDefault("redis_addr", "localhost:6379")
	v.SetDefault("redis_db", 0)
	v.SetDefault("log_level", "info")
	v.SetDefault("dev_tls", false)
	v.SetDefault("db_max_conns", 20)
	v.SetDefault("db_min_conns", 2)
	v.SetDefault("allowed_origins", []string{"*"})

	// Optional config file
	if cf := v.GetString("config_file"); cf != "" {
		v.SetConfigFile(cf)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
	}

	rotDur, err := time.ParseDuration(v.GetString("key_rotation_interval"))
	if err != nil {
		return nil, fmt.Errorf("parse key_rotation_interval: %w", err)
	}

	cfg := &Config{
		DatabaseDSN:         v.GetString("database_dsn"),
		RedisAddr:           v.GetString("redis_addr"),
		RedisPassword:       v.GetString("redis_password"),
		RedisDB:             v.GetInt("redis_db"),
		RootKey:             v.GetString("root_key"),
		IssuerURL:           v.GetString("issuer_url"),
		KeyRotationInterval: rotDur,
		AccessTokenTTL:      int32(v.GetInt("access_token_ttl")),
		RefreshTokenTTL:     int32(v.GetInt("refresh_token_ttl")),
		ListenAddr:          v.GetString("listen_addr"),
		TLSAddr:             v.GetString("tls_addr"),
		MetricsAddr:         v.GetString("metrics_addr"),
		DevTLS:              v.GetBool("dev_tls"),
		TLSCertFile:         v.GetString("tls_cert_file"),
		TLSKeyFile:          v.GetString("tls_key_file"),
		AllowedOrigins:      v.GetStringSlice("allowed_origins"),
		LogLevel:            v.GetString("log_level"),
		DBMaxConns:          int32(v.GetInt("db_max_conns")),
		DBMinConns:          int32(v.GetInt("db_min_conns")),
	}

	if cfg.DatabaseDSN == "" {
		return nil, fmt.Errorf("VAULTGUARD_DATABASE_DSN is required")
	}
	if cfg.RootKey == "" {
		return nil, fmt.Errorf("VAULTGUARD_ROOT_KEY is required")
	}

	return cfg, nil
}
