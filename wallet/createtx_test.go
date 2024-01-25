// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

var (
	testBlockHash, _ = chainhash.NewHashFromStr(
		"00000000000000017188b968a371bab95aa43522665353b646e41865abae" +
			"02a4",
	)
	testBlockHeight int32 = 276425
)

// TestTxToOutput checks that no new address is added to he database if we
// request a dry run of the txToOutputs call. It also makes sure a subsequent
// non-dry run call produces a similar transaction to the dry-run.
func TestTxToOutputsDryRun(t *testing.T) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	// Create an address we can use to send some coins to.
	keyScope := waddrmgr.KeyScopeBIP0049Plus
	addr, err := w.CurrentAddress(0, keyScope)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	p2shAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to p2sh: %v", err)
	}

	// Add an output paying to the wallet's address to the database.
	txOut := wire.NewTxOut(100000, p2shAddr)
	incomingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{},
		},
		TxOut: []*wire.TxOut{
			txOut,
		},
	}
	addUtxo(t, w, incomingTx)

	// Now tell the wallet to create a transaction paying to the specified
	// outputs.
	txOuts := []*wire.TxOut{
		{
			PkScript: p2shAddr,
			Value:    10000,
		},
		{
			PkScript: p2shAddr,
			Value:    20000,
		},
	}

	// First do a few dry-runs, making sure the number of addresses in the
	// database us not inflated.
	dryRunTx, err := w.txToOutputs(
		txOuts, nil, nil, 0, 1, 1000, CoinSelectionLargest, true,
	)
	if err != nil {
		t.Fatalf("unable to author tx: %v", err)
	}
	change := dryRunTx.Tx.TxOut[dryRunTx.ChangeIndex]

	addresses, err := w.AccountAddresses(0)
	if err != nil {
		t.Fatalf("unable to get addresses: %v", err)
	}

	if len(addresses) != 1 {
		t.Fatalf("expected 1 address, found %v", len(addresses))
	}

	dryRunTx2, err := w.txToOutputs(
		txOuts, nil, nil, 0, 1, 1000, CoinSelectionLargest, true,
	)
	if err != nil {
		t.Fatalf("unable to author tx: %v", err)
	}
	change2 := dryRunTx2.Tx.TxOut[dryRunTx2.ChangeIndex]

	addresses, err = w.AccountAddresses(0)
	if err != nil {
		t.Fatalf("unable to get addresses: %v", err)
	}

	if len(addresses) != 1 {
		t.Fatalf("expected 1 address, found %v", len(addresses))
	}

	// The two dry-run TXs should be invalid, since they don't have
	// signatures.
	err = validateMsgTx(
		dryRunTx.Tx, dryRunTx.PrevScripts, dryRunTx.PrevInputValues,
	)
	if err == nil {
		t.Fatalf("Expected tx to be invalid")
	}

	err = validateMsgTx(
		dryRunTx2.Tx, dryRunTx2.PrevScripts, dryRunTx2.PrevInputValues,
	)
	if err == nil {
		t.Fatalf("Expected tx to be invalid")
	}

	// Now we do a proper, non-dry run. This should add a change address
	// to the database.
	tx, err := w.txToOutputs(
		txOuts, nil, nil, 0, 1, 1000, CoinSelectionLargest, false,
	)
	if err != nil {
		t.Fatalf("unable to author tx: %v", err)
	}
	change3 := tx.Tx.TxOut[tx.ChangeIndex]

	addresses, err = w.AccountAddresses(0)
	if err != nil {
		t.Fatalf("unable to get addresses: %v", err)
	}

	if len(addresses) != 2 {
		t.Fatalf("expected 2 addresses, found %v", len(addresses))
	}

	err = validateMsgTx(tx.Tx, tx.PrevScripts, tx.PrevInputValues)
	if err != nil {
		t.Fatalf("Expected tx to be valid: %v", err)
	}

	// Finally, we check that all the transaction were using the same
	// change address.
	if !bytes.Equal(change.PkScript, change2.PkScript) {
		t.Fatalf("first dry-run using different change address " +
			"than second")
	}
	if !bytes.Equal(change2.PkScript, change3.PkScript) {
		t.Fatalf("dry-run using different change address " +
			"than wet run")
	}
}

// addUtxo add the given transaction to the wallet's database marked as a
// confirmed UTXO .
func addUtxo(t *testing.T, w *Wallet, incomingTx *wire.MsgTx) {
	var b bytes.Buffer
	if err := incomingTx.Serialize(&b); err != nil {
		t.Fatalf("unable to serialize tx: %v", err)
	}
	txBytes := b.Bytes()

	rec, err := wtxmgr.NewTxRecord(txBytes, time.Now())
	if err != nil {
		t.Fatalf("unable to create tx record: %v", err)
	}

	// The block meta will be inserted to tell the wallet this is a
	// confirmed transaction.
	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   *testBlockHash,
			Height: testBlockHeight,
		},
		Time: time.Unix(1387737310, 0),
	}

	if err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		err = w.TxStore.InsertTx(ns, rec, block)
		if err != nil {
			return err
		}
		// Add all tx outputs as credits.
		for i := 0; i < len(incomingTx.TxOut); i++ {
			err = w.TxStore.AddCredit(
				ns, rec, block, uint32(i), false,
			)
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("failed inserting tx: %v", err)
	}
}

// TestInputYield verifies the functioning of the inputYieldsPositively.
func TestInputYield(t *testing.T) {
	t.Parallel()

	addr, _ := btcutil.DecodeAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", &chaincfg.MainNetParams)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	credit := &wire.TxOut{
		Value:    1000,
		PkScript: pkScript,
	}

	// At 10 sat/b this input is yielding positively.
	require.True(t, inputYieldsPositively(credit, 10000))

	// At 20 sat/b this input is yielding negatively.
	require.False(t, inputYieldsPositively(credit, 20000))
}

// TestTxToOutputsRandom tests random coin selection.
func TestTxToOutputsRandom(t *testing.T) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	// Create an address we can use to send some coins to.
	keyScope := waddrmgr.KeyScopeBIP0049Plus
	addr, err := w.CurrentAddress(0, keyScope)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	p2shAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to p2sh: %v", err)
	}

	// Add a set of utxos to the wallet.
	incomingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{},
		},
		TxOut: []*wire.TxOut{},
	}
	for amt := int64(5000); amt <= 125000; amt += 10000 {
		incomingTx.AddTxOut(wire.NewTxOut(amt, p2shAddr))
	}

	addUtxo(t, w, incomingTx)

	// Now tell the wallet to create a transaction paying to the specified
	// outputs.
	txOuts := []*wire.TxOut{
		{
			PkScript: p2shAddr,
			Value:    50000,
		},
		{
			PkScript: p2shAddr,
			Value:    100000,
		},
	}

	const (
		feeSatPerKb   = 100000
		maxIterations = 100
	)

	createTx := func() *txauthor.AuthoredTx {
		tx, err := w.txToOutputs(
			txOuts, nil, nil, 0, 1, feeSatPerKb,
			CoinSelectionRandom, true,
		)
		require.NoError(t, err)
		return tx
	}

	firstTx := createTx()
	var isRandom bool
	for iteration := 0; iteration < maxIterations; iteration++ {
		tx := createTx()

		// Check to see if we are getting a total input value.
		// We consider this proof that the randomization works.
		if tx.TotalInput != firstTx.TotalInput {
			isRandom = true
		}

		// At the used fee rate of 100 sat/b, the 5000 sat input is
		// negatively yielding. We don't expect it to ever be selected.
		for _, inputValue := range tx.PrevInputValues {
			require.NotEqual(t, inputValue, btcutil.Amount(5000))
		}
	}

	require.True(t, isRandom)
}

// TestCreateSimpleCustomChange tests that it's possible to let the
// CreateSimpleTx use all coins for coin selection, but specify a custom scope
// that isn't the current default scope.
func TestCreateSimpleCustomChange(t *testing.T) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	// First, we'll make a P2TR and a P2WKH address to send some coins to
	// (two different coin scopes).
	p2wkhAddr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)

	p2trAddr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0086)
	require.NoError(t, err)

	// We'll now make a transaction that'll send coins to both outputs,
	// then "credit" the wallet for that send.
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)
	p2trScript, err := txscript.PayToAddrScript(p2trAddr)
	require.NoError(t, err)

	const testAmt = 1_000_000

	incomingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{},
		},
		TxOut: []*wire.TxOut{
			wire.NewTxOut(testAmt, p2wkhScript),
			wire.NewTxOut(testAmt, p2trScript),
		},
	}
	addUtxo(t, w, incomingTx)

	// With the amounts credited to the wallet, we'll now do a dry run coin
	// selection w/o any default args.
	targetTxOut := &wire.TxOut{
		Value:    1_500_000,
		PkScript: p2trScript,
	}
	tx1, err := w.txToOutputs(
		[]*wire.TxOut{targetTxOut}, nil, nil, 0, 1, 1000,
		CoinSelectionLargest, true,
	)
	require.NoError(t, err)

	// We expect that all inputs were used and also the change output is a
	// taproot output (the current default).
	require.Len(t, tx1.Tx.TxIn, 2)
	require.Len(t, tx1.Tx.TxOut, 2)
	for _, txOut := range tx1.Tx.TxOut {
		scriptType, _, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, w.chainParams,
		)
		require.NoError(t, err)

		require.Equal(t, scriptType, txscript.WitnessV1TaprootTy)
	}

	// Next, we'll do another dry run, but this time, specify a custom
	// change key scope. We'll also require that only inputs of P2TR are used.
	targetTxOut = &wire.TxOut{
		Value:    500_000,
		PkScript: p2trScript,
	}
	tx2, err := w.txToOutputs(
		[]*wire.TxOut{targetTxOut}, &waddrmgr.KeyScopeBIP0086,
		&waddrmgr.KeyScopeBIP0084, 0, 1, 1000, CoinSelectionLargest,
		true,
	)
	require.NoError(t, err)

	// The resulting transaction should spend a single input, and use P2WKH
	// as the output script.
	require.Len(t, tx2.Tx.TxIn, 1)
	require.Len(t, tx2.Tx.TxOut, 2)
	for i, txOut := range tx2.Tx.TxOut {
		if i != tx2.ChangeIndex {
			continue
		}

		scriptType, _, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, w.chainParams,
		)
		require.NoError(t, err)

		require.Equal(t, scriptType, txscript.WitnessV0PubKeyHashTy)
	}
}
