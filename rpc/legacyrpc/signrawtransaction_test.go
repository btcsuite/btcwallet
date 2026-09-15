// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacyrpc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/wire/v2"
)

// TestSignRawTransactionTrailingBytes ensures signRawTransaction rejects a
// serialized transaction that carries extra trailing bytes beyond the encoded
// transaction, matching Bitcoin Core's behaviour of failing to decode rather
// than silently ignoring the excess data.
func TestSignRawTransactionTrailingBytes(t *testing.T) {
	// Build a minimal, well-formed transaction (one input, no outputs) and
	// serialize it. A non-zero input count avoids colliding with the segwit
	// marker byte during deserialization.
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))

	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatalf("failed to serialize transaction: %v", err)
	}

	// Append a stray byte that is not part of the transaction encoding.
	serialized := append(buf.Bytes(), 0x00)

	flags := "ALL"
	cmd := &btcjson.SignRawTransactionCmd{
		RawTx: hex.EncodeToString(serialized),
		Flags: &flags,
	}

	// The trailing-bytes check runs before the wallet is touched, so nil
	// wallet and chain client arguments are safe here.
	_, err := signRawTransaction(cmd, nil, nil)
	if _, ok := err.(DeserializationError); !ok {
		t.Fatalf("expected DeserializationError for trailing bytes, got "+
			"%T: %v", err, err)
	}
}
