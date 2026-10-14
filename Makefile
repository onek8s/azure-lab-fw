GO        ?= go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
export CGO_ENABLED=0

.PHONY: build build-all test lint fmt test-netns clean

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/labfw ./cmd/labfw

build-all:
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/labfw_linux_amd64 ./cmd/labfw
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/labfw_linux_arm64 ./cmd/labfw

test:
	$(GO) test -race=false -count=1 ./...

lint:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt needed" && exit 1)
	$(GO) vet ./...
	golangci-lint run ./...

fmt:
	gofmt -w .

# Privileged network-namespace integration tests (PLAN §9.2). Requires root.
test-netns: build
	$(GO) test -count=1 -tags netns -v ./test/netns/...

clean:
	rm -rf bin dist
