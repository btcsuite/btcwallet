// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpcserver

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	pb "github.com/btcsuite/btcwallet/rpc/walletrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// serializedTxWithTrailingBytes returns a well-formed transaction (one input,
// no outputs) serialization with an extra stray byte appended. A non-zero
// input count avoids colliding with the segwit marker byte during
// deserialization.
func serializedTxWithTrailingBytes(t *testing.T) []byte {
	t.Helper()

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatalf("failed to serialize transaction: %v", err)
	}

	return append(buf.Bytes(), 0x00)
}

// assertTrailingBytesRejected verifies err is a gRPC InvalidArgument error that
// reports the trailing-bytes condition rather than being silently accepted.
func assertTrailingBytesRejected(t *testing.T, err error) {
	t.Helper()

	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
	if !strings.Contains(status.Convert(err).Message(), "trailing bytes") {
		t.Fatalf("expected trailing-bytes message, got %q",
			status.Convert(err).Message())
	}
}

// TestSignTransactionTrailingBytes ensures SignTransaction rejects a serialized
// transaction carrying extra trailing bytes. The check runs before the wallet
// is used, so a zero-value walletServer is sufficient.
func TestSignTransactionTrailingBytes(t *testing.T) {
	s := &walletServer{}
	req := &pb.SignTransactionRequest{
		SerializedTransaction: serializedTxWithTrailingBytes(t),
	}

	_, err := s.SignTransaction(context.Background(), req)
	assertTrailingBytesRejected(t, err)
}

// TestPublishTransactionTrailingBytes ensures PublishTransaction rejects a
// serialized transaction carrying extra trailing bytes.
func TestPublishTransactionTrailingBytes(t *testing.T) {
	s := &walletServer{}
	req := &pb.PublishTransactionRequest{
		SignedTransaction: serializedTxWithTrailingBytes(t),
	}

	_, err := s.PublishTransaction(context.Background(), req)
	assertTrailingBytesRejected(t, err)
}
