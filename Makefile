.PHONY: build test test-race lint integration clean

# cactus requires Go 1.27+ (built-in crypto/mldsa). Until 1.27 ships, the
# default is the gotip 1.27-devel toolchain; override with `make GO=go`
# once a 1.27 release is installed.
GO ?= gotip
BIN_DIR ?= bin

build:
	$(GO) build -tags mldsa -o $(BIN_DIR)/cactus ./cmd/cactus
	$(GO) build -tags mldsa -o $(BIN_DIR)/cactus-cli ./cmd/cactus-cli
	$(GO) build -tags mldsa -o $(BIN_DIR)/cactus-keygen ./cmd/cactus-keygen

test:
	$(GO) test -tags mldsa ./...

test-race:
	$(GO) test -race -tags mldsa ./...

vet:
	$(GO) vet -tags mldsa ./...

integration:
	$(GO) test -race -count=1 -tags=integration,mldsa ./integration/...

clean:
	rm -rf $(BIN_DIR)
