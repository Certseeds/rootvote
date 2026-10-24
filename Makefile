GO ?= go
VERSION ?= dev
COUNTRIES ?= CN:CN,IN
SNAPSHOT = $(shell cat internal/ccadb/snapshot.txt 2>/dev/null)
LDFLAGS = -s -w -X github.com/Certseeds/rootvote/internal/buildinfo.Version=$(VERSION) -X github.com/Certseeds/rootvote/internal/buildinfo.CCADBSnapshot=$(SNAPSHOT)

.PHONY: build test deps generate generate-data generate-nss dist

build:
	$(GO) build -tags embeddata -trimpath -ldflags "$(LDFLAGS)" -o bin/rootvote ./cmd/rootvote

deps:
	$(GO) mod download

test: deps
	$(GO) test ./...

generate: generate-data generate-nss

generate-data: deps
	$(GO) run ./tools/fetch-ccadb

generate-nss:
	$(GO) run ./tools/fetch-nss -lock tools/nss.lock -out dist/tools/nss

dist: generate
	$(GO) run -tags embeddata ./cmd/rootvote generate --countries "$(COUNTRIES)" --out dist/blacklist --force
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -tags embeddata -trimpath -ldflags "$(LDFLAGS)" -o dist/rootvote.exe ./cmd/rootvote
	cp LICENSE_AGPL_V3_0.md dist/LICENSE
	cp NOTICE readme.md dist/
	tar -czf dist/rootvote_$(VERSION)_windows_amd64.tgz -C dist rootvote.exe blacklist tools LICENSE NOTICE readme.md
