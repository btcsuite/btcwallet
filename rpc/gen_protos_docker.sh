#!/bin/sh

# golang docker image version used in this script.
GO_IMAGE=docker.io/library/golang:1.23.12-alpine

# protobuf generator version with legacy plugins=grpc support. Using v1.4.3 to
# maintain backward compatibility - generates single file instead of separate
# .pb.go and _grpc.pb.go files (modern approach).
PROTOC_GEN_GO_VERSION=v1.4.3

docker run --rm --volume "$(pwd):/workspace" --workdir /workspace \
    ${GO_IMAGE} sh -c "
    apk add --no-cache protobuf-dev && \
    go install github.com/golang/protobuf/protoc-gen-go@${PROTOC_GEN_GO_VERSION} && \
    protoc -I. api.proto --go_out=plugins=grpc:walletrpc && \
    chown -R $(id -u):$(id -g) walletrpc"
