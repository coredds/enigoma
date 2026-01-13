.PHONY: help test build install clean lint fmt vet coverage benchmark run-example run-demo all

# Default target
help:
	@echo "Enigoma - Makefile Commands"
	@echo ""
	@echo "Development:"
	@echo "  make test          - Run all tests"
	@echo "  make test-v        - Run tests with verbose output"
	@echo "  make test-race     - Run tests with race detector"
	@echo "  make coverage      - Generate test coverage report"
	@echo "  make benchmark     - Run benchmarks"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint          - Run golangci-lint"
	@echo "  make fmt           - Format code with gofmt"
	@echo "  make vet           - Run go vet"
	@echo "  make check         - Run fmt, vet, and lint"
	@echo ""
	@echo "Build:"
	@echo "  make build         - Build CLI binary"
	@echo "  make install       - Install CLI to GOPATH/bin"
	@echo "  make all           - Run check and test, then build"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make clean-all     - Remove all generated files"
	@echo ""
	@echo "Examples:"
	@echo "  make run-example   - Run example application"
	@echo "  make run-demo      - Run CLI demo"

# Test targets
test:
	@echo "Running tests..."
	@go test ./...

test-v:
	@echo "Running tests (verbose)..."
	@go test -v ./...

test-race:
	@echo "Running tests with race detector..."
	@go test -race ./...

coverage:
	@echo "Generating coverage report..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

benchmark:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./pkg/enigma

# Code quality targets
lint:
	@echo "Running golangci-lint..."
	@golangci-lint run

fmt:
	@echo "Formatting code..."
	@gofmt -s -w .
	@go fmt ./...

vet:
	@echo "Running go vet..."
	@go vet ./...

check: fmt vet lint
	@echo "All checks passed!"

# Build targets
build:
	@echo "Building enigoma CLI..."
	@go build -o bin/enigoma ./cmd/enigoma
	@echo "Binary built: bin/enigoma"

install:
	@echo "Installing enigoma..."
	@go install ./cmd/enigoma
	@echo "enigoma installed to GOPATH/bin"

all: check test build
	@echo "Build complete!"

# Cleanup targets
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@rm -f enigoma enigoma.exe
	@rm -f coverage.out coverage.html
	@echo "Clean complete!"

clean-all: clean
	@echo "Cleaning all generated files..."
	@go clean -cache -testcache -modcache
	@rm -rf dist/
	@echo "Deep clean complete!"

# Example targets
run-example:
	@echo "Running example application..."
	@go run ./cmd/example

run-demo:
	@echo "Running CLI demo..."
	@go run ./cmd/enigoma demo

# Go module management
tidy:
	@echo "Tidying go modules..."
	@go mod tidy

update-deps:
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy
	@echo "Dependencies updated!"

# Development helpers
dev: clean all
	@echo "Development build complete!"

watch-test:
	@echo "Watching for changes and running tests..."
	@while true; do \
		inotifywait -qq -r -e modify . && \
		clear && \
		make test; \
	done

# Version info
version:
	@go run ./cmd/enigoma --version
