# nhcx-adapter — build entry points. Pure Go, CGO off, no assets: the binary
# is the whole release.

SHELL := /bin/bash
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILT_AT ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.builtAt=$(BUILT_AT)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build ./nhcx-adapter for this machine
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o nhcx-adapter .
	@echo "built ./nhcx-adapter $(VERSION)"

.PHONY: test
test: ## Run the tests
	go test ./...

.PHONY: check
check: ## Everything CI runs: vet, race tests
	go vet ./...
	go test ./... -race

.PHONY: compile-all
compile-all: ## Cross-compile every platform without packaging (build check)
	MODE=compile ./scripts/build.sh

.PHONY: release
release: ## Cross-compile every platform into ./dist
	VERSION=$(VERSION) ./scripts/build.sh

IMAGE ?= nhcx-adapter

.PHONY: docker
docker: ## Build the container image $(IMAGE):$(VERSION)
	docker build \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILT_AT=$(BUILT_AT) \
		-t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

.PHONY: docker-run
docker-run: ## Run the image with ./.env and ./data
	docker run --rm -it --env-file .env -v "$(CURDIR)/data:/data" -p 8090:8090 $(IMAGE):latest

.PHONY: clean
clean: ## Remove build output
	rm -rf nhcx-adapter dist
