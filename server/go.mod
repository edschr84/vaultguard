module github.com/vaultguard/server

go 1.23.0

require (
	github.com/go-chi/chi/v5 v5.0.12
	github.com/go-chi/httprate v0.9.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.6.0
	github.com/lestrrat-go/jwx/v2 v2.1.6
	github.com/prometheus/client_golang v1.19.1
	github.com/redis/go-redis/v9 v9.5.1
	github.com/spf13/viper v1.19.0
	github.com/vaultguard/core v0.0.0
)

replace github.com/vaultguard/core => ../core
