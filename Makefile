# SMB Server Makefile

# Build variables
# Build variables
BINARY_NAME=servesmb
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GO_VERSION=$(shell go version | cut -d' ' -f3)

# Build flags  
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GoVersion=$(GO_VERSION)"

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	go build $(LDFLAGS) -o $(BINARY_NAME) cmd/servesmb/main.go

# Build for multiple platforms
.PHONY: build-all
build-all:
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 cmd/servesmb/main.go
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 cmd/servesmb/main.go  
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe cmd/servesmb/main.go
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-arm64 cmd/servesmb/main.go
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 cmd/servesmb/main.go

# Install dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run integration tests
.PHONY: test-integration
test-integration:
	@echo "Running integration tests..."
	go test -v -run Integration ./test

# Run benchmarks
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./test

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Lint code  
.PHONY: lint
lint:
	@echo "Linting code..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

# Clean build artifacts
.PHONY: clean  
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)*
	rm -f coverage.out coverage.html
	go clean

# Development server (runs on port 8445)
.PHONY: dev
dev: build
	@echo "Starting development server on port 8445..."
	./$(BINARY_NAME) -port 8445 -shares ./dev-shares

# Setup development environment
.PHONY: dev-setup
dev-setup:
	@echo "Setting up development environment..."
	mkdir -p dev-shares/public dev-shares/test
	echo "Hello from SMB Server!" > dev-shares/public/hello.txt
	echo "Test file content" > dev-shares/test/test.txt
	@echo "Development environment ready!"

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	@which godoc > /dev/null || (echo "Installing godoc..." && go install golang.org/x/tools/cmd/godoc@latest)
	@echo "Run 'godoc -http=:6060' and visit http://localhost:6060/pkg/github.com/3xport/servesmb/"

# Security scan
.PHONY: security
security:
	@echo "Running security scan..."
	@which gosec > /dev/null || (echo "Installing gosec..." && go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest)
	gosec ./...

# Performance profile
.PHONY: profile
profile: build
	@echo "Running with CPU profiling..."
	./$(BINARY_NAME) -port 8445 -cpuprofile cpu.prof &
	sleep 5
	@echo "Server running with profiling. Stop with Ctrl+C and analyze with 'go tool pprof cpu.prof'"

# Release preparation
.PHONY: release
release: clean fmt lint test build-all
	@echo "Release artifacts ready:"
	@ls -la $(BINARY_NAME)-*

# Docker build
.PHONY: docker
docker:
	@echo "Building Docker image..."
	docker build -t servesmb:$(VERSION) -t servesmb:latest .

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build          - Build the binary"
	@echo "  build-all      - Build for multiple platforms" 
	@echo "  deps           - Install dependencies"
	@echo "  test           - Run all tests"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  test-integration - Run integration tests only"
	@echo "  bench          - Run benchmarks"
	@echo "  fmt            - Format code"
	@echo "  lint           - Lint code"
	@echo "  clean          - Clean build artifacts"
	@echo "  dev            - Start development server"
	@echo "  dev-setup      - Setup development environment"
	@echo "  docs           - Generate documentation"
	@echo "  security       - Run security scan"
	@echo "  profile        - Run with profiling"
	@echo "  release        - Prepare release"
	@echo "  docker         - Build Docker image"
	@echo "  help           - Show this help"