// Copyright (c) 2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// TestFetchInputInfo checks that the wallet can gather information about an
// output based on the address.
func TestFetchInputInfo(t *testing.T) {
	w, cleanup := testWallet(t)
	defer cleanup()

	// Create an address we can use to send some coins to.
	addr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	p2shAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to p2sh: %v", err)
	}

	// Add an output paying to the wallet's address to the database.
	utxOut := wire.NewTxOut(100000, p2shAddr)
	incomingTx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{utxOut},
	}
	addUtxo(t, w, incomingTx)

	// Look up the UTXO for the outpoint now and compare it to our
	// expectations.
	prevOut := &wire.OutPoint{
		Hash:  incomingTx.TxHash(),
		Index: 0,
	}
	tx, out, confirmations, err := w.FetchInputInfo(prevOut)
	if err != nil {
		t.Fatalf("error fetching input info: %v", err)
	}
	if !bytes.Equal(out.PkScript, utxOut.PkScript) || out.Value != utxOut.Value {
		t.Fatalf("unexpected TX out, got %v wanted %v", out, utxOut)
	}
	if !bytes.Equal(tx.TxOut[prevOut.Index].PkScript, utxOut.PkScript) {
		t.Fatalf("unexpected TX out, got %v wanted %v",
			tx.TxOut[prevOut.Index].PkScript, utxOut)
	}
	if confirmations != int64(0-testBlockHeight) {
		t.Fatalf("unexpected number of confirmations, got %d wanted %d",
			confirmations, 0-testBlockHeight)
	}
}
