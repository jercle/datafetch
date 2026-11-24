VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/jercle/datafetch/internal/version.Version=$(VERSION)

.PHONY: build windows linux test tidy

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o datafetch ./cmd/datafetch

windows:
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/datafetch.exe ./cmd/datafetch

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/datafetch ./cmd/datafetch

test:
	go vet ./...
	go test -race ./...

tidy:
	go mod tidy
