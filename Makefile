.PHONY: all build test test-integration lint generate docker-build helm-package clean

GOFLAGS ?= -trimpath
LDFLAGS := -w -s

# Binary output directory
BIN := bin

all: build

## build: Compile all binaries
build:
	@mkdir -p $(BIN)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/vaultguard-server    ./server/...
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/vaultguard           ./cli/...
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/docker-credential-vaultguard ./docker-plugin/...
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/vaultguard-controller ./k8s-controller/...

## test: Run unit tests for all modules
test:
	go test ./core/... ./server/... ./cli/... ./docker-plugin/...

## test-integration: Spin up Postgres+Redis via docker-compose and run integration tests
test-integration:
	docker compose -f deploy/docker-compose.test.yml up -d --wait
	go test -tags integration -count=1 -timeout 120s ./...
	docker compose -f deploy/docker-compose.test.yml down -v

## lint: Run golangci-lint across all modules
lint:
	golangci-lint run ./...

## generate: Run sqlc code generation + controller-gen for CRD manifests
generate:
	@which sqlc >/dev/null 2>&1 || (echo "sqlc not found; run: go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest" && exit 1)
	cd core && sqlc generate
	@which controller-gen >/dev/null 2>&1 || (echo "controller-gen not found; run: go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest" && exit 1)
	cd k8s-controller && controller-gen rbac:roleName=vaultguard-controller \
		crd:trivialVersions=true \
		object:headerFile="hack/boilerplate.go.txt" \
		paths="./..." \
		output:crd:artifacts:config=config/crd/bases \
		output:rbac:artifacts:config=config/rbac

## docker-build: Build Docker images for server and k8s-controller
docker-build:
	docker build -t vaultguard/server:dev       -f deploy/Dockerfile.server .
	docker build -t vaultguard/controller:dev   -f deploy/Dockerfile.controller .

## helm-package: Package the Helm chart
helm-package:
	helm lint deploy/helm
	helm package deploy/helm -d $(BIN)/

## clean: Remove build artefacts
clean:
	rm -rf $(BIN)/
