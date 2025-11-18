FROM golang:1.24.6-alpine

ENV GOFLAGS="-buildvcs=false"

RUN apk update && apk add --no-cache git bash python3 py3-pip pgloader

WORKDIR /build

COPY tools/go.mod tools/go.sum ./

RUN go install -trimpath \
        github.com/golangci/golangci-lint/v2/cmd/golangci-lint \
        github.com/rinchsan/gosimports/cmd/gosimports \
        github.com/sqlc-dev/sqlc/cmd/sqlc \
    && rm -rf /go/pkg/mod \
    && rm -rf /root/.cache/go-build \
    && rm -rf /go/src \
    && rm -rf /tmp/*

RUN pip3 install --no-cache-dir sqlfluff --break-system-packages

RUN chmod -R 777 /build \
    && git config --global --add safe.directory /build
