#!/bin/bash
# The script does automatic checking on a Go package and its sub-packages, including:
# 1. go fmt        (http://golang.org/cmd/gofmt/)
# 2. golint        (https://github.com/golang/lint)
# 3. go vet        (http://golang.org/cmd/vet)
# 4. race detector (http://blog.golang.org/race-detector)

set -ex

env GORACE="history_size=7 halt_on_errors=1" go test -v -race ./...

# Automatic checks
golangci-lint run --deadline=10m --disable-all \
--enable=gofmt \
--enable=vet \
--enable=gosimple \
--enable=unconvert
