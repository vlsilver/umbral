# Umbral Pre-Go Makefile
# Version: v0.11.0-go

VERSION := v0.11.0-go

.PHONY: all build test clean install deps examples version

# Default target
all: deps build test

# Install dependencies
deps:
	@echo "🔧 Installing dependencies..."
	@if ! command -v cargo >/dev/null 2>&1; then \
		echo "❌ Rust not found. Please install Rust first:"; \
		echo "   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
		echo "   source ~/.cargo/env"; \
		exit 1; \
	fi
	@echo "✅ Dependencies ready"

# Build Rust library
build-rust:
	@echo "🦀 Building Rust library..."
	@cd ../umbral-pre && cargo build --release --features bindings-c
	@echo "✅ Rust library built"

# Note: Cross-platform builds are handled by GitHub Actions
# Use 'make build-rust' for local development only

# Build Go library
build-go:
	@echo "🐹 Building Go library..."
	@go mod tidy
	@go build -v
	@echo "✅ Go library built"

# Build everything
build: build-rust build-go

# Run tests
test:
	@echo "🧪 Running tests..."
	@go test -v -cover
	@echo "✅ Tests completed"

# Run specific test
test-e2e:
	@echo "🧪 Running E2E tests..."
	@go test -v -run TestE2EWorkflow
	@echo "✅ E2E tests completed"

# Run examples
examples:
	@echo "📚 Running examples..."
	@go run examples/basic_usage.go
	@echo "✅ Examples completed"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@cd ../umbral-pre && cargo clean
	@go clean
	@echo "✅ Clean completed"

# Install the library
install: build
	@echo "📦 Installing library..."
	@go install
	@echo "✅ Library installed"

# Development setup
dev-setup: deps build test examples
	@echo "🎉 Development setup completed!"

# Docker build
docker-build:
	@echo "🐳 Building Docker image..."
	@docker build -t umbral-pre-go .
	@echo "✅ Docker image built"

# Docker run
docker-run:
	@echo "🐳 Running Docker container..."
	@docker run --rm umbral-pre-go
	@echo "✅ Docker container completed"

# Show version
version:
	@echo "Umbral Pre-Go $(VERSION)"
	@echo "Based on umbral-pre v0.11.0"

# Note: Releases are handled by GitHub Actions
# Push to main branch or manually trigger workflow

# Clean everything
clean-all:
	@echo "🧹 Cleaning everything..."
	@cd ../umbral-pre && cargo clean
	@go clean
	@rm -rf lib/ release-temp/
	@rm -f *.exe *.dll *.so *.dylib
	@echo "✅ Everything cleaned"

# Help
help:
	@echo "Umbral Pre-Go $(VERSION) Makefile"
	@echo "======================"
	@echo ""
	@echo "Available targets:"
	@echo "  all          - Build and test everything"
	@echo "  deps         - Install dependencies"
	@echo "  build        - Build Rust and Go libraries"
	@echo "  build-rust   - Build Rust library (local dev only)"
	@echo "  build-go     - Build Go library only"
	@echo "  test         - Run all tests"
	@echo "  test-e2e     - Run E2E tests only"
	@echo "  examples     - Run examples"
	@echo "  clean        - Clean build artifacts"
	@echo "  clean-all    - Clean everything (including libs)"
	@echo "  install      - Install the library"
	@echo "  dev-setup    - Complete development setup"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo "  version      - Show version information"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Quick start:"
	@echo "  make dev-setup"
	@echo ""
	@echo "For users:"
	@echo "  go run github.com/vlsilver/umbral/install-libs.go"
	@echo "  go get github.com/vlsilver/umbral/umbral-pre-cgo"
	@echo ""
	@echo "For releases:"
	@echo "  Push to main branch or trigger GitHub Actions workflow"
	@echo "  go get github.com/vlsilver/umbral/umbral-pre-cgo"