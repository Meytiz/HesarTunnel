BINARY    := hesar-tunnel
VERSION   := 1.2.0
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE      := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GOFLAGS   := -trimpath
LDFLAGS   := -ldflags "-s -w \
	-X main.Version=$(VERSION) \
	-X main.BuildDate=$(DATE) \
	-X main.GitCommit=$(COMMIT)"

.PHONY: all build test clean release install uninstall lint

all: clean test build

build:
	@echo "Building $(BINARY) v$(VERSION)..."
	CGO_ENABLED=0 go build $(GOFLAGS) $(LDFLAGS) -o $(BINARY) main.go
	@echo "Done: ./$(BINARY)"

linux-amd64:
	@echo "Building for linux/amd64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(BINARY)-linux-amd64 main.go

linux-arm64:
	@echo "Building for linux/arm64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) $(LDFLAGS) -o $(BINARY)-linux-arm64 main.go

release: clean linux-amd64 linux-arm64
	@echo "Creating release archives..."
	tar -czf $(BINARY)-v$(VERSION)-linux-amd64.tar.gz $(BINARY)-linux-amd64 config.toml README.md LICENSE
	tar -czf $(BINARY)-v$(VERSION)-linux-arm64.tar.gz $(BINARY)-linux-arm64 config.toml README.md LICENSE
	sha256sum $(BINARY)-v$(VERSION)-*.tar.gz > checksums-v$(VERSION).txt
	@echo "Release files:"
	@ls -la $(BINARY)-v$(VERSION)-*.tar.gz checksums-v$(VERSION).txt

test:
	@echo "Running tests..."
	go test -v -race -count=1 ./...

lint:
	@echo "Running linter..."
	golangci-lint run ./... 2>/dev/null || echo "Install golangci-lint for linting"

clean:
	rm -f $(BINARY) $(BINARY)-linux-* $(BINARY)-v*.tar.gz checksums-*.txt

install: build
	@echo "Installing to /usr/local/bin/..."
	sudo cp $(BINARY) /usr/local/bin/$(BINARY)
	sudo chmod +x /usr/local/bin/$(BINARY)
	@echo "Installed: /usr/local/bin/$(BINARY)"

uninstall:
	sudo rm -f /usr/local/bin/$(BINARY)
	@echo "Uninstalled"

validate: build
	./$(BINARY) --validate --config config.toml
