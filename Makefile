GO ?= go
VERSION ?= $(shell node -p "require('./package.json').version")
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
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -tags embeddata -trimpath -ldflags "$(LDFLAGS)" -o dist/rootvote-linux ./cmd/rootvote
	rm -rf "dist/rootvote-$(VERSION)" "dist/rootvote-$(VERSION)-linux-amd64"
	mkdir -p "dist/rootvote-$(VERSION)" "dist/rootvote-$(VERSION)-linux-amd64"
	cp dist/rootvote.exe "dist/rootvote-$(VERSION)/"
	cp -r dist/blacklist dist/tools "dist/rootvote-$(VERSION)/"
	cp LICENSE_AGPL_V3_0.md "dist/rootvote-$(VERSION)/LICENSE"
	cp NOTICE readme.md "dist/rootvote-$(VERSION)/"
	cp dist/rootvote-linux "dist/rootvote-$(VERSION)-linux-amd64/rootvote"
	cp -r dist/blacklist "dist/rootvote-$(VERSION)-linux-amd64/"
	cp LICENSE_AGPL_V3_0.md "dist/rootvote-$(VERSION)-linux-amd64/LICENSE"
	cp NOTICE readme.md "dist/rootvote-$(VERSION)-linux-amd64/"
	tar -czf "dist/rootvote_$(VERSION)_windows_amd64.tgz" -C dist "rootvote-$(VERSION)"
	tar -czf "dist/rootvote_$(VERSION)_linux_amd64.tgz" -C dist "rootvote-$(VERSION)-linux-amd64"
