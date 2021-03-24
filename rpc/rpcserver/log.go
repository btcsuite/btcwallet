// Copyright (c) 2015-2016 The btcsuite developers
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package rpcserver

import (
	"os"
	"strings"

	"google.golang.org/grpc/grpclog"

	"github.com/btcsuite/btclog"
)

// UseLogger sets the logger to use for the gRPC server.
func UseLogger(l btclog.Logger) {
	grpclog.SetLogger(logger{l}) // nolint:staticcheck
}

// logger uses a btclog.Logger to implement the grpclog.Logger interface.
type logger struct {
	btclog.Logger
}

// stripGrpcPrefix removes the package prefix for all logs made to the grpc
// logger, since these are already included as the btclog subsystem name.
func stripGrpcPrefix(logstr string) string {
	return strings.TrimPrefix(logstr, "grpc: ")
}

// stripGrpcPrefixArgs removes the package prefix from the first argument, if it
// exists and is a string, returning the same arg slice after reassigning the
// first arg.
func stripGrpcPrefixArgs(args ...interface{}) []interface{} {
	if len(args) == 0 {
		return args
	}
	firstArgStr, ok := args[0].(string)
	if ok {
		args[0] = stripGrpcPrefix(firstArgStr)
	}
	return args
}

func (l logger) Fatal(args ...interface{}) {
	l.Critical(stripGrpcPrefixArgs(args)...)
	os.Exit(1)
}

func (l logger) Fatalf(format string, args ...interface{}) {
	l.Criticalf(stripGrpcPrefix(format), args...)
	os.Exit(1)
}

func (l logger) Fatalln(args ...interface{}) {
	l.Critical(stripGrpcPrefixArgs(args)...)
	os.Exit(1)
}

func (l logger) Print(args ...interface{}) {
	l.Info(stripGrpcPrefixArgs(args)...)
}

func (l logger) Printf(format string, args ...interface{}) {
	l.Infof(stripGrpcPrefix(format), args...)
}

func (l logger) Println(args ...interface{}) {
	l.Info(stripGrpcPrefixArgs(args)...)
}
