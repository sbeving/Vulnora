# Makefile for Vulnora

.PHONY: help build test clean deps proto docker release install lint fmt vet

# Variables
BINARY_NAME := vulnora
VERSION := $(shell git describe --tags --always --dirty)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT := $(shell git rev-parse HEAD)
LDFLAGS := -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.Commit=$(COMMIT)

# Go related variables
GOBASE := $(shell pwd)
GOPATH := $(GOBASE)/vendor
GOBIN := $(GOBASE)/bin
GOFILES := $(wildcard *.go)

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

## help: Show this help message
help:
	@echo "Available commands:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## deps: Install dependencies
deps:
	@echo "$(BLUE)Installing dependencies...$(NC)"
	go mod download
	go mod tidy
	@echo "$(GREEN)Dependencies installed$(NC)"

## proto: Generate protobuf code
proto:
	@echo "$(BLUE)Generating protobuf code...$(NC)"
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		pkg/protocol/*.proto
	@echo "$(GREEN)Protobuf code generated$(NC)"

## build: Build the application
build: deps
	@echo "$(BLUE)Building $(BINARY_NAME)...$(NC)"
	CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(GOBIN)/$(BINARY_NAME) cmd/main.go
	@echo "$(GREEN)Build completed: $(GOBIN)/$(BINARY_NAME)$(NC)"

## build-agent: Build the agent worker
build-agent: deps
	@echo "$(BLUE)Building vulnora-agent...$(NC)"
	CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(GOBIN)/vulnora-agent cmd/agent/main.go
	@echo "$(GREEN)Agent build completed: $(GOBIN)/vulnora-agent$(NC)"

## build-cli: Build the CLI tool
build-cli: deps
	@echo "$(BLUE)Building vulnora-cli...$(NC)"
	CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(GOBIN)/vulnora-cli cmd/cli/main.go
	@echo "$(GREEN)CLI build completed: $(GOBIN)/vulnora-cli$(NC)"

## build-all: Build all components
build-all: build build-agent build-cli

## test: Run all tests
test:
	@echo "$(BLUE)Running tests...$(NC)"
	go test -v -race -coverprofile=coverage.out ./...
	@echo "$(GREEN)Tests completed$(NC)"

## test-coverage: Run tests with coverage report
test-coverage: test
	@echo "$(BLUE)Generating coverage report...$(NC)"
	go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report: coverage.html$(NC)"

## test-integration: Run integration tests
test-integration:
	@echo "$(BLUE)Running integration tests...$(NC)"
	go test -v -tags=integration ./test/integration/...
	@echo "$(GREEN)Integration tests completed$(NC)"

## bench: Run benchmarks
bench:
	@echo "$(BLUE)Running benchmarks...$(NC)"
	go test -bench=. -benchmem ./...
	@echo "$(GREEN)Benchmarks completed$(NC)"

## lint: Run linter
lint:
	@echo "$(BLUE)Running linter...$(NC)"
	golangci-lint run
	@echo "$(GREEN)Linting completed$(NC)"

## fmt: Format code
fmt:
	@echo "$(BLUE)Formatting code...$(NC)"
	go fmt ./...
	@echo "$(GREEN)Code formatted$(NC)"

## vet: Run go vet
vet:
	@echo "$(BLUE)Running go vet...$(NC)"
	go vet ./...
	@echo "$(GREEN)Vet completed$(NC)"

## clean: Clean build artifacts
clean:
	@echo "$(BLUE)Cleaning...$(NC)"
	go clean
	rm -rf $(GOBIN)
	rm -rf dist/
	rm -f coverage.out coverage.html
	@echo "$(GREEN)Cleaned$(NC)"

## docker: Build Docker images
docker:
	@echo "$(BLUE)Building Docker images...$(NC)"
	docker build -t vulnora:$(VERSION) .
	docker build -t vulnora-agent:$(VERSION) -f deployments/docker/Dockerfile.agent .
	@echo "$(GREEN)Docker images built$(NC)"

## docker-compose: Start services with docker-compose
docker-compose:
	@echo "$(BLUE)Starting services with docker-compose...$(NC)"
	docker-compose -f deployments/docker/docker-compose.yml up -d
	@echo "$(GREEN)Services started$(NC)"

## release: Build release binaries
release: clean deps
	@echo "$(BLUE)Building release binaries...$(NC)"
	goreleaser build --snapshot --rm-dist
	@echo "$(GREEN)Release binaries built in dist/$(NC)"

## release-publish: Publish release (requires GITHUB_TOKEN)
release-publish:
	@echo "$(BLUE)Publishing release...$(NC)"
	goreleaser release
	@echo "$(GREEN)Release published$(NC)"

## install: Install the application
install: build
	@echo "$(BLUE)Installing $(BINARY_NAME)...$(NC)"
	sudo cp $(GOBIN)/$(BINARY_NAME) /usr/local/bin/
	@echo "$(GREEN)$(BINARY_NAME) installed to /usr/local/bin/$(NC)"

## uninstall: Uninstall the application
uninstall:
	@echo "$(BLUE)Uninstalling $(BINARY_NAME)...$(NC)"
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "$(GREEN)$(BINARY_NAME) uninstalled$(NC)"

## dev: Run in development mode
dev: build
	@echo "$(BLUE)Starting development server...$(NC)"
	$(GOBIN)/$(BINARY_NAME) --config configs/development.yaml

## certs: Generate development certificates
certs:
	@echo "$(BLUE)Generating development certificates...$(NC)"
	mkdir -p certs
	scripts/generate-certs.sh
	@echo "$(GREEN)Certificates generated in certs/$(NC)"

## assets: Bundle UI assets
assets:
	@echo "$(BLUE)Bundling UI assets...$(NC)"
	fyne bundle assets/icon.png > internal/gui/resource.go
	@echo "$(GREEN)Assets bundled$(NC)"

## mocks: Generate mocks for testing
mocks:
	@echo "$(BLUE)Generating mocks...$(NC)"
	mockery --all --output test/mocks
	@echo "$(GREEN)Mocks generated$(NC)"

## security: Run security checks
security:
	@echo "$(BLUE)Running security checks...$(NC)"
	gosec ./...
	@echo "$(GREEN)Security checks completed$(NC)"

## deps-update: Update dependencies
deps-update:
	@echo "$(BLUE)Updating dependencies...$(NC)"
	go get -u ./...
	go mod tidy
	@echo "$(GREEN)Dependencies updated$(NC)"

## check: Run all checks (lint, vet, test, security)
check: lint vet test security
	@echo "$(GREEN)All checks passed$(NC)"

## package-deb: Create Debian package
package-deb: release
	@echo "$(BLUE)Creating Debian package...$(NC)"
	# Implementation would go here
	@echo "$(GREEN)Debian package created$(NC)"

## package-rpm: Create RPM package
package-rpm: release
	@echo "$(BLUE)Creating RPM package...$(NC)"
	# Implementation would go here
	@echo "$(GREEN)RPM package created$(NC)"

## package-windows: Create Windows installer
package-windows: release
	@echo "$(BLUE)Creating Windows installer...$(NC)"
	# Implementation would go here (e.g., using NSIS or WiX)
	@echo "$(GREEN)Windows installer created$(NC)"

## run-proxy: Run only the proxy server
run-proxy: build
	@echo "$(BLUE)Starting proxy server...$(NC)"
	$(GOBIN)/$(BINARY_NAME) --proxy-only --proxy-port 8080

## run-agent: Run agent worker
run-agent: build-agent
	@echo "$(BLUE)Starting agent worker...$(NC)"
	$(GOBIN)/vulnora-agent --config configs/development.yaml

## run-cli: Run CLI tool
run-cli: build-cli
	@echo "$(BLUE)Running CLI tool...$(NC)"
	$(GOBIN)/vulnora-cli --help

## docs: Generate documentation
docs:
	@echo "$(BLUE)Generating documentation...$(NC)"
	godoc -http=:6060 &
	@echo "$(GREEN)Documentation server started at http://localhost:6060$(NC)"

## setup: Initial project setup
setup: deps certs assets mocks
	@echo "$(GREEN)Project setup completed$(NC)"

# Development convenience targets
## watch: Watch for changes and rebuild
watch:
	@echo "$(BLUE)Watching for changes...$(NC)"
	@command -v air >/dev/null 2>&1 || go install github.com/cosmtrek/air@latest
	air

## debug: Build with debug information
debug:
	@echo "$(BLUE)Building debug version...$(NC)"
	CGO_ENABLED=1 go build -gcflags="all=-N -l" -ldflags "$(LDFLAGS)" -o $(GOBIN)/$(BINARY_NAME)-debug cmd/main.go
	@echo "$(GREEN)Debug build completed: $(GOBIN)/$(BINARY_NAME)-debug$(NC)"

# Default target
all: check build-all

# Show current version
version:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Commit: $(COMMIT)"
