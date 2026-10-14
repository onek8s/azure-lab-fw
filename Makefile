GO        ?= go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
export CGO_ENABLED=0

.PHONY: build build-all test lint fmt test-netns bench-b1ls clean

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

# Privileged network-namespace integration tests (PLAN §9.2). Requires root,
# iproute2, nftables and conntrack. NETNS_ARTIFACT_DIR keeps daemon logs.
test-netns: build
	$(GO) vet -tags netns ./test/netns/...
	$(GO) test -count=1 -timeout 20m -tags netns -v ./test/netns/...

# Resource budget for Standard_B1ls (PLAN §12.4, acceptance A29): the A29
# load test in a 512 MiB / 1 CPU cgroup (systemd-run --scope when systemd
# runs, else a cgroup created directly). Fails if idle RSS >= 40 MiB or peak
# RSS >= 100 MiB. Requires root; NETNS_LOAD_SECONDS (default 60) sets the
# hold time, NETNS_ARTIFACT_DIR keeps a29-summary.md and a29-samples.csv.
bench-b1ls: build
	$(GO) vet -tags netns ./test/netns/...
	NETNS_LOAD=1 $(GO) test -count=1 -timeout 20m -tags netns -v -run '^TestA29_LoadBudget$$' ./test/netns/...

clean:
	rm -rf bin dist
