BIN := bin/l2-buckler
CONFIG ?= configs/dev.yaml

.PHONY: build test itest bench lint run clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BIN) ./cmd/l2-buckler

test:
	go test -race ./...

itest:
	go test -race -tags integration -run Integration ./...

bench:
	go test -run '^$$' -bench . -benchmem ./internal/proxy/ ./internal/waf/

lint:
	golangci-lint run

run:
	go run ./cmd/l2-buckler -config $(CONFIG)

clean:
	rm -rf bin
