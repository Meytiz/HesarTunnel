BINARY  := hesar-tunnel
VER     := 1.3.0
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LD      := -ldflags "-s -w -X main.Version=$(VER) -X main.BuildDate=$(DATE) -X main.GitCommit=$(COMMIT)"

.PHONY: all build test clean release install

all: clean build

build:
	CGO_ENABLED=0 go build -trimpath $(LD) -o $(BINARY) main.go

linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath $(LD) -o $(BINARY)-linux-amd64 main.go

linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath $(LD) -o $(BINARY)-linux-arm64 main.go

release: clean linux-amd64 linux-arm64
	tar -czf $(BINARY)-v$(VER)-linux-amd64.tar.gz $(BINARY)-linux-amd64 config.toml README.md LICENSE
	tar -czf $(BINARY)-v$(VER)-linux-arm64.tar.gz $(BINARY)-linux-arm64 config.toml README.md LICENSE
	sha256sum $(BINARY)-v$(VER)-*.tar.gz > checksums.txt

test:
	go test -v -race ./...

clean:
	rm -f $(BINARY) $(BINARY)-linux-* *.tar.gz checksums.txt

install: build
	sudo cp $(BINARY) /usr/local/bin/ && sudo chmod +x /usr/local/bin/$(BINARY)
