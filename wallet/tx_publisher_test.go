// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	errDummy           = errors.New("dummy")
	errInsufficientFee = errors.New("insufficient fee")
	errRpc             = errors.New("rpc error")
	errPublish         = errors.New("publish error")
	errRemove          = errors.New("remove error")
)

const testTxLabel = "test-tx"

// TestCheckMempoolAcceptance tests the CheckMempoolAcceptance method.
func TestCheckMempoolAcceptance(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tx := &wire.MsgTx{}

	mempoolAcceptResultAllowed := []*btcjson.TestMempoolAcceptResult{
		{Allowed: true},
	}
	mempoolAcceptResultRejected := []*btcjson.TestMempoolAcceptResult{
		{
			Allowed:      false,
			RejectReason: errInsufficientFee.Error(),
		},
	}

	testCases := []struct {
		name        string
		tx          *wire.MsgTx
		rpcResult   []*btcjson.TestMempoolAcceptResult
		rpcErr      error
		expectedErr error
	}{
		{
			name:        "nil tx",
			tx:          nil,
			expectedErr: ErrTxCannotBeNil,
		},
		{
			name:        "accepted",
			tx:          tx,
			rpcResult:   mempoolAcceptResultAllowed,
			rpcErr:      nil,
			expectedErr: nil,
		},
		{
			name:        "rejected",
			tx:          tx,
			rpcResult:   mempoolAcceptResultRejected,
			rpcErr:      nil,
			expectedErr: errInsufficientFee,
		},
		{
			name:        "rpc error",
			tx:          tx,
			rpcResult:   nil,
			rpcErr:      errRpc,
			expectedErr: errRpc,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w, m := testWalletWithMocks(t)

			if tc.tx != nil {
				m.chain.On("TestMempoolAccept",
					mock.Anything, mock.Anything,
				).Return(tc.rpcResult, tc.rpcErr)
			}

			// We only need to mock the MapRPCErr function if the
			// RPC call is expected to succeed but the tx is
			// rejected.
			if tc.rpcErr == nil && tc.rpcResult != nil &&
				!tc.rpcResult[0].Allowed {

				m.chain.On("MapRPCErr",
					mock.Anything,
				).Return(errInsufficientFee)
			}

			err := w.CheckMempoolAcceptance(ctx, tc.tx)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// testTxData is a helper struct to hold the results of createTestTx.
type testTxData struct {
	// tx is the generated transaction.
	tx *wire.MsgTx

	// addr1 is the P2WKH address used in the transaction.
	addr1 btcutil.Address

	// addr2 is the P2SH address used in the transaction.
	addr2 btcutil.Address

	// addr3 is the P2WSH address used in the transaction.
	addr3 btcutil.Address
}

// createTestTx is a helper function to create a transaction with various
// output types for testing. The created transaction has a single placeholder
// input and four outputs:
// - Output 0: A P2WKH (Pay-to-Witness-Key-Hash) output.
// - Output 1: A P2SH (Pay-to-Script-Hash) output.
// - Output 2: An OP_RETURN output for data embedding.
// - Output 3: A 2-of-2 multi-sig P2WSH (Pay-to-Witness-Script-Hash) output.
func createTestTx(t *testing.T, w *Wallet) *testTxData {
	t.Helper()

	// Create some keys and addresses for testing.
	privKey1, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey1 := privKey1.PubKey()
	addr1, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey1.SerializeCompressed()), w.chainParams,
	)
	require.NoError(t, err)

	privKey2, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey2 := privKey2.PubKey()

	// Create a transaction with various output types.
	tx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{},
		},
		TxOut: []*wire.TxOut{},
	}

	// Output 0: P2WKH
	pkScript1, err := txscript.PayToAddrScript(addr1)
	require.NoError(t, err)

	tx.TxOut = append(tx.TxOut, &wire.TxOut{PkScript: pkScript1, Value: 1})

	// Output 1: P2SH
	script2 := []byte{txscript.OP_1}
	addr2, err := btcutil.NewAddressScriptHash(
		script2, w.chainParams,
	)
	require.NoError(t, err)
	pkScript2, err := txscript.PayToAddrScript(addr2)
	require.NoError(t, err)

	tx.TxOut = append(tx.TxOut, &wire.TxOut{PkScript: pkScript2, Value: 1})

	// Output 2: OP_RETURN
	opReturnBuilder := txscript.NewScriptBuilder()
	opReturnBuilder.AddOp(txscript.OP_RETURN).AddData([]byte("test"))
	pkScript3, err := opReturnBuilder.Script()
	require.NoError(t, err)

	tx.TxOut = append(tx.TxOut, &wire.TxOut{PkScript: pkScript3, Value: 0})

	// Output 3: Multi-sig P2WSH
	builder := txscript.NewScriptBuilder()
	builder.AddInt64(2)
	builder.AddData(pubKey1.SerializeCompressed())
	builder.AddData(pubKey2.SerializeCompressed())
	builder.AddInt64(2)
	builder.AddOp(txscript.OP_CHECKMULTISIG)
	multiSigScript, err := builder.Script()
	require.NoError(t, err)

	scriptHash := sha256.Sum256(multiSigScript)
	addr3, err := btcutil.NewAddressWitnessScriptHash(
		scriptHash[:], w.chainParams,
	)
	require.NoError(t, err)
	pkScript4, err := txscript.PayToAddrScript(addr3)
	require.NoError(t, err)

	tx.TxOut = append(tx.TxOut, &wire.TxOut{PkScript: pkScript4, Value: 1})

	return &testTxData{
		tx:    tx,
		addr1: addr1,
		addr2: addr2,
		addr3: addr3,
	}
}

// TestExtractTxAddrs tests the extractTxAddrs method to ensure it correctly
// extracts all potential addresses from a transaction's outputs.
func TestExtractTxAddrs(t *testing.T) {
	t.Parallel()

	// Create a new test wallet.
	w, _ := testWalletWithMocks(t)

	// Create the test transaction.
	testData := createTestTx(t, w)

	// Extract addresses.
	extractedAddrs := w.extractTxAddrs(testData.tx)

	// Check the results.
	// We expect 4 entries in the map, one for each output.
	require.Len(t, extractedAddrs, 4, "expected 4 outputs")

	// Output 0 should have one address.
	require.Len(t, extractedAddrs[0], 1)
	require.Equal(t, testData.addr1.String(), extractedAddrs[0][0].String())

	// Output 1 should have one address.
	require.Len(t, extractedAddrs[1], 1)
	require.Equal(t, testData.addr2.String(), extractedAddrs[1][0].String())

	// Output 2 (OP_RETURN) should have no addresses.
	require.Empty(t, extractedAddrs[2], "OP_RETURN output should have "+
		"no addresses")

	// Output 3 should have one address (the script hash address).
	require.Len(t, extractedAddrs[3], 1)
	require.Equal(t, testData.addr3.String(), extractedAddrs[3][0].String())
}

// TestFilterOwnedAddresses tests the filterOwnedAddresses method to ensure it
// correctly identifies owned addresses and handles de-duplication.
func TestFilterOwnedAddresses(t *testing.T) {
	t.Parallel()

	// Create a new test wallet with mocks.
	w, mocks := testWalletWithMocks(t)

	// Create two addresses, one owned and one not.
	ownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownedAddr, err := btcutil.NewAddressPubKey(
		ownedPrivKey.PubKey().SerializeCompressed(), w.chainParams,
	)
	require.NoError(t, err)

	unownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	unownedAddr, err := btcutil.NewAddressPubKey(
		unownedPrivKey.PubKey().SerializeCompressed(), w.chainParams,
	)
	require.NoError(t, err)

	// Create an input map with both addresses, with the owned address
	// appearing twice.
	txOutAddrs := map[uint32][]btcutil.Address{
		0: {ownedAddr},
		1: {unownedAddr},
		2: {ownedAddr}, // Duplicate
	}

	// Set up the mock for the address store.
	mockManagedAddr := &mockManagedAddress{}
	errAddrNotFound := waddrmgr.ManagerError{
		ErrorCode: waddrmgr.ErrAddressNotFound,
	}

	mocks.addrStore.On("Address", mock.Anything, ownedAddr).
		Return(mockManagedAddr, nil).Once()
	mocks.addrStore.On("Address", mock.Anything, unownedAddr).
		Return(nil, errAddrNotFound).Once()

	// Filter the addresses.
	ownedAddrs, err := w.filterOwnedAddresses(txOutAddrs)
	require.NoError(t, err)

	// Check that the result contains only the owned address.
	require.Len(t, ownedAddrs, 1)
	_, ok := ownedAddrs[ownedAddr]
	require.True(t, ok)
}

// TestRecordTxAndCredits tests the recordTxAndCredits method to ensure it
// correctly records transactions and credits in the database.
func TestRecordTxAndCredits(t *testing.T) {
	t.Parallel()

	// Create a sample TxRecord from a transaction with one input and one
	// output with a value of 10000.
	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000}},
	}
	txRec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	require.NoError(t, err)

	// Create a sample credit for a P2PK address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addr, err := btcutil.NewAddressPubKey(
		privKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	mockManagedAddr := &mockManagedAddress{}
	mockManagedAddr.On("Internal").Return(false)
	credits := []creditInfo{{
		index: 0,
		ma:    mockManagedAddr,
		addr:  addr,
	}}

	testCases := []struct {
		name      string
		withLabel bool
		txExists  bool
	}{
		{
			name:      "new tx with label",
			withLabel: true,
			txExists:  false,
		},
		{
			name:      "existing tx",
			withLabel: true,
			txExists:  true,
		},
		{
			name:      "no label",
			withLabel: false,
			txExists:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w, mocks := testWalletWithMocks(t)
			txid := tx.TxHash()

			label := ""
			if tc.withLabel {
				label = testTxLabel
			}

			mocks.txStore.On("InsertTxCheckIfExists",
				mock.Anything, txRec, mock.Anything,
			).Return(tc.txExists, nil).Once()

			if tc.withLabel {
				mocks.txStore.On("PutTxLabel",
					mock.Anything, txid, label,
				).Return(nil).Once()
			}

			if !tc.txExists {
				mocks.txStore.On("AddCredit",
					mock.Anything, txRec, mock.Anything,
					uint32(0), false,
				).Return(nil).Once()
				mocks.addrStore.On("MarkUsed",
					mock.Anything, addr,
				).Return(nil).Once()
			}

			err := w.recordTxAndCredits(txRec, label, credits)
			require.NoError(t, err)
		})
	}
}

// TestAddTxToWallet tests the addTxToWallet method, which serves as an
// integration test for the transaction extraction, filtering, and recording
// process.
func TestAddTxToWallet(t *testing.T) {
	t.Parallel()

	// Create some addresses for testing.
	ownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownedAddr, err := btcutil.NewAddressPubKey(
		ownedPrivKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	unownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	unownedAddr, err := btcutil.NewAddressPubKey(
		unownedPrivKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	// Create a transaction with outputs to both owned and unowned
	// addresses.
	tx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{
			{
				Value:    10000,
				PkScript: mustPayToAddrScript(ownedAddr),
			},
			{
				Value:    20000,
				PkScript: mustPayToAddrScript(unownedAddr),
			},
			{
				Value:    30000,
				PkScript: mustPayToAddrScript(ownedAddr),
			},
		},
	}
	txid := tx.TxHash()
	label := testTxLabel

	t.Run("tx with owned outputs", func(t *testing.T) {
		t.Parallel()
		w, m := testWalletWithMocks(t)

		// This test case simulates the scenario where the
		// transaction has outputs owned by the wallet. We expect
		// the wallet to identify these outputs, record the
		// transaction, and credit the wallet with the new UTXOs.
		//
		// Set up the mock for the address store.
		mockManagedAddr := &mockManagedAddress{}
		mockManagedAddr.On("Internal").Return(false)

		errAddrNotFound := waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrAddressNotFound,
		}

		m.addrStore.On("Address",
			mock.Anything, ownedAddr,
		).Return(mockManagedAddr, nil)
		m.addrStore.On("Address",
			mock.Anything, unownedAddr,
		).Return(nil, errAddrNotFound)

		// Set up the mocks for the transaction store.
		m.txStore.On("PutTxLabel",
			mock.Anything, txid, label,
		).Return(nil).Once()
		m.txStore.On("InsertTxCheckIfExists",
			mock.Anything, mock.Anything,
			mock.Anything,
		).Return(false, nil).Once()

		// We expect two credits to be added for the two owned
		// outputs.
		m.txStore.On("AddCredit",
			mock.Anything, mock.Anything,
			mock.Anything, uint32(0), false,
		).Return(nil).Once()
		m.txStore.On("AddCredit",
			mock.Anything, mock.Anything,
			mock.Anything, uint32(2), false,
		).Return(nil).Once()
		m.addrStore.On("MarkUsed",
			mock.Anything, ownedAddr,
		).Return(nil).Twice()

		// Add the transaction to the wallet.
		ourAddrs, err := w.addTxToWallet(tx, label)
		require.NoError(t, err)

		// Check that the returned addresses are correct.
		require.Len(t, ourAddrs, 2)
		require.Equal(
			t, ownedAddr.String(),
			ourAddrs[0].String(),
		)
		require.Equal(
			t, ownedAddr.String(),
			ourAddrs[1].String(),
		)
	})

	t.Run("tx with no owned outputs", func(t *testing.T) {
		t.Parallel()
		w, m := testWalletWithMocks(t)

		// This test case simulates the scenario where the
		// transaction has no outputs owned by the wallet. We
		// expect the wallet to identify this and exit early
		// without recording the transaction.
		//
		// Set up the mock for the address store to own no
		// addresses.
		errAddrNotFound := waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrAddressNotFound,
		}
		m.addrStore.On("Address",
			mock.Anything, ownedAddr,
		).Return(nil, errAddrNotFound)
		m.addrStore.On("Address",
			mock.Anything, unownedAddr,
		).Return(nil, errAddrNotFound)

		// Add the transaction to the wallet.
		ourAddrs, err := w.addTxToWallet(tx, label)
		require.NoError(t, err)

		// We expect no addresses to be returned and no calls to the
		// transaction store.
		require.Nil(t, ourAddrs)
	})
}

// mustPayToAddrScript is a helper function to create a PkScript for a given
// address. It panics on error.
func mustPayToAddrScript(addr btcutil.Address) []byte {
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		panic(err)
	}

	return pkScript
}

// TestRemoveUnminedTx tests the removeUnminedTx method to ensure it correctly
// removes a transaction from the unconfirmed store.
func TestRemoveUnminedTx(t *testing.T) {
	t.Parallel()

	w, mocks := testWalletWithMocks(t)

	// Create a sample transaction with one input and one output.
	tx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{
			Value: 10000,
		}},
	}

	// Set up the mock for the transaction store.
	mocks.txStore.On(
		"RemoveUnminedTx", mock.Anything, mock.Anything,
	).Return(nil).Once()

	// Call the method under test.
	err := w.removeUnminedTx(tx)
	require.NoError(t, err)
}

// TestCheckMempool tests the checkMempool helper function.
func TestCheckMempool(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tx := &wire.MsgTx{}

	testCases := []struct {
		name             string
		mempoolAcceptErr error
		expectedErr      error
		expectWrappedErr bool
		rejectionReason  string
		mapRPCErr        func(error) error
	}{
		{
			name:             "accepted",
			mempoolAcceptErr: nil,
			expectedErr:      nil,
		},
		{
			name:             "already in mempool",
			mempoolAcceptErr: chain.ErrTxAlreadyInMempool,
			expectedErr:      errAlreadyBroadcasted,
		},
		{
			name:             "already known",
			mempoolAcceptErr: chain.ErrTxAlreadyKnown,
			expectedErr:      errAlreadyBroadcasted,
		},
		{
			name:             "already confirmed",
			mempoolAcceptErr: chain.ErrTxAlreadyConfirmed,
			expectedErr:      errAlreadyBroadcasted,
		},
		{
			name:             "backend version",
			mempoolAcceptErr: rpcclient.ErrBackendVersion,
			expectedErr:      nil,
		},
		{
			name:             "unimplemented",
			mempoolAcceptErr: chain.ErrUnimplemented,
			expectedErr:      nil,
		},
		{
			name:             "rejected",
			mempoolAcceptErr: errDummy,
			expectedErr:      errDummy,
			expectWrappedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, m := testWalletWithMocks(t)

			// Setup the mock for TestMempoolAccept.
			if tc.mempoolAcceptErr == nil {
				m.chain.On("TestMempoolAccept",
					mock.Anything, mock.Anything,
				).Return([]*btcjson.TestMempoolAcceptResult{
					{Allowed: true},
				}, nil)
			} else {
				m.chain.On("TestMempoolAccept",
					mock.Anything, mock.Anything,
				).Return(nil, tc.mempoolAcceptErr)
			}

			err := w.checkMempool(ctx, tx)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// TestPublishTx tests the publishTx helper function.
func TestPublishTx(t *testing.T) {
	t.Parallel()

	tx := &wire.MsgTx{}
	addrs := []btcutil.Address{&btcutil.AddressPubKey{}}

	testCases := []struct {
		name        string
		notifyErr   error
		sendErr     error
		expectedErr error
	}{
		{
			name:        "success",
			notifyErr:   nil,
			sendErr:     nil,
			expectedErr: nil,
		},
		{
			name:        "notify received fails",
			notifyErr:   errDummy,
			sendErr:     nil,
			expectedErr: errDummy,
		},
		{
			name:        "send raw transaction fails",
			notifyErr:   nil,
			sendErr:     errDummy,
			expectedErr: errDummy,
		},
		{
			name:        "already in mempool",
			notifyErr:   nil,
			sendErr:     chain.ErrTxAlreadyInMempool,
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w, m := testWalletWithMocks(t)

			m.chain.On("NotifyReceived",
				mock.Anything).Return(tc.notifyErr)

			// We only expect SendRawTransaction to be called if
			// NotifyReceived succeeds.
			if tc.notifyErr == nil {
				m.chain.On("SendRawTransaction",
					mock.Anything, mock.Anything,
				).Return(nil, tc.sendErr)
			}

			err := w.publishTx(tx, addrs)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// TestBroadcastSuccess tests the Broadcast method for a successful broadcast.
func TestBroadcastSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	label := testTxLabel
	w, m := testWalletWithMocks(t)

	// Create a transaction with an owned output.
	ownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownedAddr, err := btcutil.NewAddressPubKey(
		ownedPrivKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(ownedAddr)
	require.NoError(t, err)

	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: pkScript}},
	}

	// Mock checkMempool to succeed.
	m.chain.On("TestMempoolAccept",
		mock.Anything, mock.Anything,
	).Return([]*btcjson.TestMempoolAcceptResult{{Allowed: true}}, nil)

	// Mock addTxToWallet to succeed.
	mockManagedAddr := &mockManagedAddress{}
	mockManagedAddr.On("Internal").Return(false)
	m.addrStore.On("Address",
		mock.Anything, ownedAddr,
	).Return(mockManagedAddr, nil).Once()
	m.txStore.On("PutTxLabel",
		mock.Anything, tx.TxHash(), label,
	).Return(nil).Once()
	m.txStore.On("InsertTxCheckIfExists",
		mock.Anything, mock.Anything, mock.Anything,
	).Return(false, nil).Once()
	m.txStore.On("AddCredit",
		mock.Anything, mock.Anything, mock.Anything, uint32(0), false,
	).Return(nil).Once()
	m.addrStore.On("MarkUsed",
		mock.Anything, ownedAddr,
	).Return(nil).Once()

	// Mock publishTx to succeed.
	m.chain.On("NotifyReceived", mock.Anything).Return(nil)
	m.chain.On("SendRawTransaction",
		mock.Anything, mock.Anything,
	).Return(nil, nil)

	err = w.Broadcast(ctx, tx, label)
	require.NoError(t, err)
}

// TestBroadcastAlreadyBroadcasted tests the Broadcast method when the
// transaction has already been broadcasted.
func TestBroadcastAlreadyBroadcasted(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	label := testTxLabel
	w, m := testWalletWithMocks(t)

	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000}},
	}

	// Mock checkMempool to return already broadcasted.
	m.chain.On("TestMempoolAccept", mock.Anything, mock.Anything).
		Return(nil, chain.ErrTxAlreadyInMempool)

	err := w.Broadcast(ctx, tx, label)
	require.NoError(t, err)
}

// TestBroadcastPublishFailsRemoveSucceeds tests the Broadcast method when
// publishing fails but removing the transaction from the wallet succeeds.
func TestBroadcastPublishFailsRemoveSucceeds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	label := testTxLabel
	w, m := testWalletWithMocks(t)

	// Create a transaction with an owned output.
	ownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownedAddr, err := btcutil.NewAddressPubKey(
		ownedPrivKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(ownedAddr)
	require.NoError(t, err)

	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: pkScript}},
	}

	// Mock checkMempool to succeed.
	m.chain.On("TestMempoolAccept",
		mock.Anything, mock.Anything,
	).Return([]*btcjson.TestMempoolAcceptResult{{Allowed: true}}, nil)

	// Mock addTxToWallet to succeed.
	mockManagedAddr := &mockManagedAddress{}
	mockManagedAddr.On("Internal").Return(false)
	m.addrStore.On("Address",
		mock.Anything, ownedAddr,
	).Return(mockManagedAddr, nil).Once()
	m.txStore.On("PutTxLabel",
		mock.Anything, tx.TxHash(), label,
	).Return(nil).Once()
	m.txStore.On("InsertTxCheckIfExists",
		mock.Anything, mock.Anything, mock.Anything,
	).Return(false, nil).Once()
	m.txStore.On("AddCredit",
		mock.Anything, mock.Anything, mock.Anything, uint32(0), false,
	).Return(nil).Once()
	m.addrStore.On("MarkUsed",
		mock.Anything, ownedAddr,
	).Return(nil).Once()

	// Mock publishTx to fail.
	m.chain.On("NotifyReceived", mock.Anything).Return(nil)
	m.chain.On("SendRawTransaction",
		mock.Anything, mock.Anything,
	).Return(nil, errPublish)

	// Mock removeUnminedTx to succeed.
	m.txStore.On("RemoveUnminedTx",
		mock.Anything, mock.Anything,
	).Return(nil).Once()

	err = w.Broadcast(ctx, tx, label)
	require.ErrorIs(t, err, errPublish)
}

// TestBroadcastPublishFailsRemoveFails tests the Broadcast method when both
// publishing and removing the transaction from the wallet fail.
func TestBroadcastPublishFailsRemoveFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	label := testTxLabel
	w, m := testWalletWithMocks(t)

	// Create a transaction with an owned output.
	ownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownedAddr, err := btcutil.NewAddressPubKey(
		ownedPrivKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(ownedAddr)
	require.NoError(t, err)

	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: pkScript}},
	}

	// Mock checkMempool to succeed.
	m.chain.On("TestMempoolAccept",
		mock.Anything, mock.Anything,
	).Return([]*btcjson.TestMempoolAcceptResult{{Allowed: true}}, nil)

	// Mock addTxToWallet to succeed.
	mockManagedAddr := &mockManagedAddress{}
	mockManagedAddr.On("Internal").Return(false)
	m.addrStore.On("Address",
		mock.Anything, ownedAddr,
	).Return(mockManagedAddr, nil).Once()
	m.txStore.On("PutTxLabel",
		mock.Anything, tx.TxHash(), label,
	).Return(nil).Once()
	m.txStore.On("InsertTxCheckIfExists",
		mock.Anything, mock.Anything, mock.Anything,
	).Return(false, nil).Once()
	m.txStore.On("AddCredit",
		mock.Anything, mock.Anything, mock.Anything, uint32(0), false,
	).Return(nil).Once()
	m.addrStore.On("MarkUsed",
		mock.Anything, ownedAddr,
	).Return(nil).Once()

	// Mock publishTx to fail.
	m.chain.On("NotifyReceived", mock.Anything).Return(nil)
	m.chain.On("SendRawTransaction",
		mock.Anything, mock.Anything,
	).Return(nil, errPublish)

	// Mock removeUnminedTx to fail.
	m.txStore.On("RemoveUnminedTx",
		mock.Anything, mock.Anything,
	).Return(errRemove).Once()

	err = w.Broadcast(ctx, tx, label)
	require.Error(t, err)
	require.Contains(t, err.Error(), errPublish.Error())
	require.Contains(t, err.Error(), errRemove.Error())
}

// TestBroadcastNilTx tests that the Broadcast method returns an error when a
// nil transaction is passed.
func TestBroadcastNilTx(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	label := testTxLabel
	w, _ := testWalletWithMocks(t)

	err := w.Broadcast(ctx, nil, label)
	require.ErrorIs(t, err, ErrTxCannotBeNil)
}
