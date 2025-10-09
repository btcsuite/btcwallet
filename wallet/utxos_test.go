// Copyright (c) 2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestFetchInputInfo checks that the wallet can gather information about an
// output based on the address.
func TestFetchInputInfo(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

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
	tx, out, derivationPath, confirmations, err := w.FetchInputInfo(prevOut)
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
	if len(derivationPath.Bip32Path) != 5 {
		t.Fatalf("expected derivation path of length %v, got %v", 3,
			len(derivationPath.Bip32Path))
	}
	if derivationPath.Bip32Path[0] !=
		waddrmgr.KeyScopeBIP0084.Purpose+hdkeychain.HardenedKeyStart {
		t.Fatalf("expected purpose %v, got %v",
			waddrmgr.KeyScopeBIP0084.Purpose,
			derivationPath.Bip32Path[0])
	}
	if derivationPath.Bip32Path[1] !=
		waddrmgr.KeyScopeBIP0084.Coin+hdkeychain.HardenedKeyStart {
		t.Fatalf("expected coin type %v, got %v",
			waddrmgr.KeyScopeBIP0084.Coin,
			derivationPath.Bip32Path[1])
	}
	if derivationPath.Bip32Path[2] != hdkeychain.HardenedKeyStart {
		t.Fatalf("expected account %v, got %v",
			hdkeychain.HardenedKeyStart, derivationPath.Bip32Path[2])
	}
	if derivationPath.Bip32Path[3] != 0 {
		t.Fatalf("expected branch %v, got %v", 0,
			derivationPath.Bip32Path[3])
	}
	if derivationPath.Bip32Path[4] != 0 {
		t.Fatalf("expected index %v, got %v", 0,
			derivationPath.Bip32Path[4])
	}
	if confirmations != int64(0-testBlockHeight) {
		t.Fatalf("unexpected number of confirmations, got %d wanted %d",
			confirmations, 0-testBlockHeight)
	}
}

// TestFetchOutpointInfo checks that the wallet can gather information about an
// output based on the outpoint.
func TestFetchOutpointInfo(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

	// Create an address we can use to send some coins to.
	addr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)
	p2shAddr, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

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
	tx, out, confirmations, err := w.FetchOutpointInfo(prevOut)
	require.NoError(t, err)

	require.Equal(t, utxOut.PkScript, out.PkScript)
	require.Equal(t, utxOut.Value, out.Value)
	require.Equal(t, utxOut.PkScript, tx.TxOut[prevOut.Index].PkScript)
	require.Equal(t, int64(0-testBlockHeight), confirmations)
}

// TestFetchOutpointInfoErr checks when the wallet cannot find an output, a
// proper error is returned.
func TestFetchOutpointInfoErr(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

	// Create an address we can use to send some coins to.
	addr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)
	p2shAddr, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Create a tx that has two outputs - output1 belongs to the wallet,
	// output2 is external.
	output1 := wire.NewTxOut(100000, p2shAddr)
	output2 := wire.NewTxOut(100000, p2shAddr)
	tx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{
			output1,
			output2,
		},
	}

	// Add the tx and its first output as the credit.
	addTxAndCredit(t, w, tx, 0)

	testCases := []struct {
		name    string
		prevOut *wire.OutPoint

		// TODO(yy): refator `FetchOutpointInfo` to return wrapped
		// errors.
		errExpected string
	}{
		{
			name: "no tx details",
			prevOut: &wire.OutPoint{
				Hash:  chainhash.Hash{1, 2, 3},
				Index: 0,
			},
			errExpected: "does not belong to the wallet",
		},
		{
			name: "invalid output index",
			prevOut: &wire.OutPoint{
				Hash:  tx.TxHash(),
				Index: 1000,
			},
			errExpected: "invalid output index",
		},
		{
			name: "no credit found",
			prevOut: &wire.OutPoint{
				Hash:  tx.TxHash(),
				Index: 1,
			},
			errExpected: "does not belong to the wallet",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Look up the UTXO for the outpoint now and compare it
			// to the expected error.
			tx, out, conf, err := w.FetchOutpointInfo(tc.prevOut)
			require.ErrorContains(t, err, tc.errExpected)
			require.Nil(t, tx)
			require.Nil(t, out)
			require.Zero(t, conf)
		})
	}
}

// TestFetchDerivationInfo checks that the wallet can gather the derivation
// info about an output based on the pkScript.
func TestFetchDerivationInfo(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

	// Create an address we can use to send some coins to.
	addr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)
	p2shAddr, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Add an output paying to the wallet's address to the database.
	utxOut := wire.NewTxOut(100000, p2shAddr)
	incomingTx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{utxOut},
	}
	addUtxo(t, w, incomingTx)

	info, err := w.FetchDerivationInfo(utxOut.PkScript)
	require.NoError(t, err)

	require.Len(t, info.Bip32Path, 5)
	require.Equal(t, waddrmgr.KeyScopeBIP0084.Purpose+
		hdkeychain.HardenedKeyStart, info.Bip32Path[0])
	require.Equal(t, waddrmgr.KeyScopeBIP0084.Coin+
		hdkeychain.HardenedKeyStart, info.Bip32Path[1])
	require.EqualValues(t, hdkeychain.HardenedKeyStart, info.Bip32Path[2])
	require.Equal(t, uint32(0), info.Bip32Path[3])
	require.Equal(t, uint32(0), info.Bip32Path[4])
}
