GO ?= go
VERSION ?= dev
LDFLAGS := -s -w -X github.com/Certseeds/rootvote/internal/buildinfo.Version=$(VERSION)

.PHONY: build test

build:
	$(GO) build -tags embeddata -trimpath $(LDFLAGS) -o bin/rootvote ./cmd/rootvote

test:
	$(GO) test ./...
