// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
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

// matchCreateTxParams returns a matcher for Store CreateTx parameters.
func matchCreateTxParams(walletID uint32, tx *wire.MsgTx, label string,
	credits map[uint32]address.Address) any {

	return mock.MatchedBy(func(params db.CreateTxParams) bool {
		return params.WalletID == walletID &&
			params.Tx == tx &&
			!params.Received.IsZero() &&
			params.Block == nil &&
			params.Status == db.TxStatusPublished &&
			params.Label == label &&
			addressCreditsEqual(params.Credits, credits)
	})
}

// addressCreditsEqual reports whether two credit maps contain the same encoded
// addresses for the same output indexes.
func addressCreditsEqual(a, b map[uint32]address.Address) bool {
	if len(a) != len(b) {
		return false
	}

	for index, addr := range a {
		otherAddr, ok := b[index]
		if !ok {
			return false
		}

		if addr.EncodeAddress() != otherAddr.EncodeAddress() {
			return false
		}
	}

	return true
}

// matchUpdateTxParams returns a matcher for Store tx metadata updates. The
// nil-handling branches for the optional label and state fields are inherent to
// the matcher and read clearer inline than split across helpers.
//
//nolint:cyclop // Inline nil-handling for optional matcher fields.
func matchUpdateTxParams(walletID uint32, txid chainhash.Hash,
	label *string, state *db.UpdateTxState) any {

	return mock.MatchedBy(func(params db.UpdateTxParams) bool {
		if params.WalletID != walletID || params.Txid != txid {
			return false
		}

		if label == nil {
			if params.Label != nil {
				return false
			}
		} else if params.Label == nil || *params.Label != *label {
			return false
		}

		if state == nil {
			return params.State == nil
		}

		if params.State == nil {
			return false
		}

		return params.State.Status == state.Status &&
			params.State.Block == nil && state.Block == nil
	})
}

// matchResolveOwnedAddressesQuery returns a matcher for the batched Store
// address lookup. The wallet builds the script set from a map, so the order is
// not deterministic; the matcher compares the scripts as a set.
func matchResolveOwnedAddressesQuery(walletID uint32, scripts ...[]byte) any {
	want := make(map[string]struct{}, len(scripts))
	for _, script := range scripts {
		want[string(script)] = struct{}{}
	}

	return mock.MatchedBy(func(query db.ResolveOwnedAddressesQuery) bool {
		if query.WalletID != walletID {
			return false
		}

		if len(query.ScriptPubKeys) != len(want) {
			return false
		}

		for _, script := range query.ScriptPubKeys {
			if _, ok := want[string(script)]; !ok {
				return false
			}
		}

		return true
	})
}

// ownedAddrsResult builds the owned-subset map returned by the batched Store
// address lookup, keyed by string(script) as the contract requires.
func ownedAddrsResult(scripts ...[]byte) map[string]*db.AddressInfo {
	owned := make(map[string]*db.AddressInfo, len(scripts))
	for _, script := range scripts {
		owned[string(script)] = &db.AddressInfo{ScriptPubKey: script}
	}

	return owned
}

// matchInvalidateUnminedTxParams returns a matcher for Store invalidation
// requests.
func matchInvalidateUnminedTxParams(walletID uint32, txid chainhash.Hash) any {
	return mock.MatchedBy(func(params db.InvalidateUnminedTxParams) bool {
		return params.WalletID == walletID && params.Txid == txid
	})
}

// TestCheckMempoolAcceptance tests the CheckMempoolAcceptance method.
func TestCheckMempoolAcceptance(t *testing.T) {
	t.Parallel()

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
			w, m := createStartedWalletWithMocks(t)

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

			err := w.CheckMempoolAcceptance(t.Context(), tc.tx)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// testTxData is a helper struct to hold the results of createTestTx.
type testTxData struct {
	// tx is the generated transaction.
	tx *wire.MsgTx

	// addr1 is the P2WKH address used in the transaction.
	addr1 address.Address

	// addr2 is the P2SH address used in the transaction.
	addr2 address.Address

	// addr3 is the P2WSH address used in the transaction.
	addr3 address.Address
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
	addr1, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey1.SerializeCompressed()),
		w.cfg.ChainParams,
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
	addr2, err := address.NewAddressScriptHash(
		script2, w.cfg.ChainParams,
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
	addr3, err := address.NewAddressWitnessScriptHash(
		scriptHash[:], w.cfg.ChainParams,
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
	w, _ := createStartedWalletWithMocks(t)

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
// correctly identifies owned addresses, handles de-duplication, and recognizes
// a wallet-owned member of a bare-multisig output.
func TestFilterOwnedAddresses(t *testing.T) {
	t.Parallel()

	t.Run("dedup single-address outputs", func(t *testing.T) {
		t.Parallel()

		w, mocks := createStartedWalletWithMocks(t)

		// Create two addresses, one owned and one not.
		ownedAddr := mustNewPubKeyAddr(t, w)
		unownedAddr := mustNewPubKeyAddr(t, w)

		ownedScript := mustPayToAddrScript(ownedAddr)
		unownedScript := mustPayToAddrScript(unownedAddr)

		// Create an input map with both addresses, with the owned
		// address appearing twice.
		txOutAddrs := map[uint32][]address.Address{
			0: {ownedAddr},
			1: {unownedAddr},
			2: {ownedAddr}, // Duplicate
		}

		// All addresses are resolved by their own scripts in a single
		// batched lookup; for a single-address output a script equals
		// the output script. Only the owned script comes back.
		mocks.store.On("ResolveOwnedAddresses", mock.Anything,
			matchResolveOwnedAddressesQuery(w.id, ownedScript, unownedScript),
		).Return(ownedAddrsResult(ownedScript), nil).Once()

		// Filter the addresses.
		ownedAddrs, err := w.filterOwnedAddresses(
			t.Context(), txOutAddrs,
		)
		require.NoError(t, err)

		// Check that the result contains only the owned address.
		require.Len(t, ownedAddrs, 1)
		info, ok := ownedAddrs[ownedAddr.EncodeAddress()]
		require.True(t, ok)
		require.ElementsMatch(t, []uint32{uint32(0), uint32(2)},
			info.outputIndices)
	})

	t.Run("bare multisig owned member", func(t *testing.T) {
		t.Parallel()

		w, mocks := createStartedWalletWithMocks(t)

		// A bare 1-of-2 multisig output yields two pubkey addresses;
		// the wallet owns only the first one.
		ownedAddr := mustNewPubKeyAddr(t, w)
		otherAddr := mustNewPubKeyAddr(t, w)

		// The extractor surfaces both members for the same output.
		txOutAddrs := map[uint32][]address.Address{
			0: {ownedAddr, otherAddr},
		}

		// Ownership is resolved by each member's own script, never the
		// whole multisig output script, which would match no address
		// row.
		ownedScript := mustPayToAddrScript(ownedAddr)
		otherScript := mustPayToAddrScript(otherAddr)

		mocks.store.On("ResolveOwnedAddresses", mock.Anything,
			matchResolveOwnedAddressesQuery(w.id, ownedScript, otherScript),
		).Return(ownedAddrsResult(ownedScript), nil).Once()

		ownedAddrs, err := w.filterOwnedAddresses(
			t.Context(), txOutAddrs,
		)
		require.NoError(t, err)

		// Only the owned member is recognized, mapped to output 0.
		require.Len(t, ownedAddrs, 1)
		info, ok := ownedAddrs[ownedAddr.EncodeAddress()]
		require.True(t, ok)
		require.ElementsMatch(t, []uint32{uint32(0)},
			info.outputIndices)
	})

	t.Run("single batched lookup for many outputs", func(t *testing.T) {
		t.Parallel()

		w, mocks := createStartedWalletWithMocks(t)

		// Build a many-output tx with distinct addresses, every other
		// one wallet-owned, to show the filter resolves the whole set
		// with a single Store lookup (N outputs -> 1 op).
		const numOutputs = 32

		txOutAddrs := make(map[uint32][]address.Address, numOutputs)
		scripts := make([][]byte, 0, numOutputs)
		ownedScripts := make([][]byte, 0, numOutputs/2)
		ownedKeys := make(map[string]struct{}, numOutputs/2)

		for i := range numOutputs {
			addr := mustNewPubKeyAddr(t, w)
			script := mustPayToAddrScript(addr)

			txOutAddrs[uint32(i)] = []address.Address{addr}

			scripts = append(scripts, script)

			// Mark every other address as wallet-owned.
			if i%2 != 0 {
				continue
			}

			ownedScripts = append(ownedScripts, script)
			ownedKeys[addr.EncodeAddress()] = struct{}{}
		}

		// The whole script set is resolved in exactly one call, which
		// .Once() plus AssertExpectations enforce.
		mocks.store.On("ResolveOwnedAddresses", mock.Anything,
			matchResolveOwnedAddressesQuery(w.id, scripts...),
		).Return(ownedAddrsResult(ownedScripts...), nil).Once()

		ownedAddrs, err := w.filterOwnedAddresses(
			t.Context(), txOutAddrs,
		)
		require.NoError(t, err)

		// Exactly the owned half is returned, and the filter issued a
		// single batched Store lookup regardless of the output count.
		require.Len(t, ownedAddrs, len(ownedKeys))

		for key := range ownedAddrs {
			_, ok := ownedKeys[key]
			require.True(t, ok)
		}

		mocks.store.AssertNumberOfCalls(t, "ResolveOwnedAddresses", 1)
	})
}

// mustNewPubKeyAddr returns a fresh P2PK address on the wallet's chain. It
// fails the test on error.
func mustNewPubKeyAddr(t *testing.T, w *Wallet) *address.AddressPubKey {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	addr, err := address.NewAddressPubKey(
		privKey.PubKey().SerializeCompressed(), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	return addr
}

// mustNewStandalonePubKeyAddr returns a fresh P2PK address on the test chain
// without needing a wallet instance. It fails the test on error.
func mustNewStandalonePubKeyAddr(t *testing.T) *address.AddressPubKey {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	addr, err := address.NewAddressPubKey(
		privKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	return addr
}

// TestRecordTxAndCredits tests the recordTxAndCredits method to ensure it
// correctly records transactions and credits in the database.
func TestRecordTxAndCredits(t *testing.T) {
	t.Parallel()

	// Create a sample transaction with one input and one output with a value
	// of 10000.
	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000}},
	}

	// Create a sample credit for a P2PK address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addr, err := address.NewAddressPubKey(
		privKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	mockManagedAddr := &bwmock.ManagedAddress{}
	mockManagedAddr.On("Internal").Return(false)

	credits := []creditInfo{{
		index: 0,
		addr:  addr,
	}}
	expectedCredits := map[uint32]address.Address{0: addr}

	testCases := []struct {
		name        string
		withLabel   bool
		createErr   error
		updateLabel bool
		updateState bool

		// existingStatus, when set via existingSet, is the status the
		// store reports for the colliding row on ErrTxAlreadyExists.
		existingStatus db.TxStatus
		existingSet    bool

		// wantErr is the sentinel the call must return, if any.
		wantErr error
	}{
		{
			name:      "new tx with label",
			withLabel: true,
		},
		{
			name:        "existing live tx",
			withLabel:   true,
			createErr:   db.ErrTxAlreadyExists,
			updateLabel: true,

			existingStatus: db.TxStatusPublished,
			existingSet:    true,
		},
		{
			name:        "existing pending tx",
			withLabel:   true,
			createErr:   db.ErrTxAlreadyExists,
			updateLabel: true,
			updateState: true,

			existingStatus: db.TxStatusPending,
			existingSet:    true,
		},
		{
			name:      "existing failed tx",
			withLabel: true,
			createErr: db.ErrTxAlreadyExists,

			existingStatus: db.TxStatusFailed,
			existingSet:    true,
			wantErr:        ErrTxRetainedInvalid,
		},
		{
			name:      "existing replaced tx",
			createErr: db.ErrTxAlreadyExists,

			existingStatus: db.TxStatusReplaced,
			existingSet:    true,
			wantErr:        ErrTxRetainedInvalid,
		},
		{
			name: "no label",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, mocks := createStartedWalletWithMocks(t)
			txid := tx.TxHash()

			label := ""
			if tc.withLabel {
				label = testTxLabel
			}

			mocks.store.On("CreateTx", mock.Anything,
				matchCreateTxParams(
					w.id, tx, label, expectedCredits,
				),
			).Return(tc.createErr).Once()

			// On a duplicate, recordTxAndCredits reads the
			// existing row's status to decide whether the
			// collision is a live idempotent duplicate or a
			// retained-invalid row it must refuse.
			if tc.existingSet {
				mocks.store.On("GetTx", mock.Anything,
					db.GetTxQuery{WalletID: w.id, Txid: txid},
				).Return(&db.TxInfo{
					Hash:   txid,
					Status: tc.existingStatus,
				}, nil).Once()
			}

			if tc.updateLabel || tc.updateState {
				var labelPtr *string
				if tc.updateLabel {
					labelPtr = &label
				}

				var state *db.UpdateTxState
				if tc.updateState {
					state = &db.UpdateTxState{
						Status: db.TxStatusPublished,
					}
				}

				mocks.store.On("UpdateTx", mock.Anything,
					matchUpdateTxParams(w.id, txid, labelPtr, state),
				).Return(nil).Once()
			}

			err := w.recordTxAndCredits(
				t.Context(), tx, label, credits,
			)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestRecordTxAndCreditsDeterministicMultiOwned verifies that when a single
// output index carries more than one wallet-owned credit address (as a
// bare-multisig output the wallet partly owns can), recordTxAndCredits records
// the lexicographically smallest EncodeAddress() as the canonical owner. The
// selection must not depend on credit slice or map iteration order.
func TestRecordTxAndCreditsDeterministicMultiOwned(t *testing.T) {
	t.Parallel()

	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000}},
	}

	// Build two distinct wallet-owned addresses and order them by encoded
	// form so the expected canonical (smallest) owner is unambiguous.
	addrA := mustNewStandalonePubKeyAddr(t)
	addrB := mustNewStandalonePubKeyAddr(t)

	smaller, larger := addrA, addrB
	if larger.EncodeAddress() < smaller.EncodeAddress() {
		smaller, larger = larger, smaller
	}

	expectedCredits := map[uint32]address.Address{0: smaller}

	// Feed the two owned members for the same output index in both orders;
	// the canonical pick must be the smaller-encoded address either way.
	testCases := []struct {
		name    string
		credits []creditInfo
	}{
		{
			name: "smaller first",
			credits: []creditInfo{
				{index: 0, addr: smaller},
				{index: 0, addr: larger},
			},
		},
		{
			name: "larger first",
			credits: []creditInfo{
				{index: 0, addr: larger},
				{index: 0, addr: smaller},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, mocks := createStartedWalletWithMocks(t)

			mocks.store.On("CreateTx", mock.Anything,
				matchCreateTxParams(w.id, tx, "", expectedCredits),
			).Return(nil).Once()

			err := w.recordTxAndCredits(
				t.Context(), tx, "", tc.credits,
			)
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
	ownedAddr, err := address.NewAddressPubKey(
		ownedPrivKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	unownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	unownedAddr, err := address.NewAddressPubKey(
		unownedPrivKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	ownedScript := mustPayToAddrScript(ownedAddr)
	unownedScript := mustPayToAddrScript(unownedAddr)

	// Create a transaction with outputs to both owned and unowned
	// addresses.
	tx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{
			{
				Value:    10000,
				PkScript: ownedScript,
			},
			{
				Value:    20000,
				PkScript: unownedScript,
			},
			{
				Value:    30000,
				PkScript: ownedScript,
			},
		},
	}
	label := testTxLabel

	t.Run("tx with owned outputs", func(t *testing.T) {
		t.Parallel()

		w, m := createStartedWalletWithMocks(t)

		// This test case simulates the scenario where the
		// transaction has outputs owned by the wallet. We expect
		// the wallet to identify these outputs, record the
		// transaction, and credit the wallet with the new UTXOs.
		//
		m.store.On("ResolveOwnedAddresses", mock.Anything,
			matchResolveOwnedAddressesQuery(w.id, ownedScript, unownedScript),
		).Return(ownedAddrsResult(ownedScript), nil).Once()

		expectedCredits := map[uint32]address.Address{
			0: ownedAddr,
			2: ownedAddr,
		}
		m.store.On("CreateTx", mock.Anything,
			matchCreateTxParams(w.id, tx, label, expectedCredits),
		).Return(nil).Once()

		// Add the transaction to the wallet.
		ourAddrs, recorded, err := w.addTxToWallet(
			t.Context(), tx, label,
		)
		require.NoError(t, err)

		// The tx was written, so recorded is true.
		require.True(t, recorded)

		// Check that the returned addresses are correct.
		require.Len(t, ourAddrs, 1)
		require.Equal(
			t, ownedAddr.String(),
			ourAddrs[0].String(),
		)
	})

	t.Run("tx with no owned outputs", func(t *testing.T) {
		t.Parallel()

		w, m := createStartedWalletWithMocks(t)

		// This test case simulates the scenario where the
		// transaction has neither outputs nor inputs owned by the
		// wallet. We expect the wallet to identify this and exit
		// early without recording the transaction.
		//
		// Set up the mock for the Store to own no
		// addresses.
		m.store.On("ResolveOwnedAddresses", mock.Anything,
			matchResolveOwnedAddressesQuery(w.id, ownedScript, unownedScript),
		).Return(ownedAddrsResult(), nil).Once()

		// With no owned outputs, addTxToWallet falls back to checking
		// the input side. The single input does not spend a current
		// wallet UTXO, so GetUtxo reports not-found.
		m.store.On("GetUtxo", mock.Anything, db.GetUtxoQuery{
			WalletID: w.id,
			OutPoint: tx.TxIn[0].PreviousOutPoint,
		}).Return((*db.UtxoInfo)(nil), db.ErrUtxoNotFound).Once()

		// The input's parent is not a wallet transaction either, so it
		// spends no already-spent wallet output and the tx is genuinely
		// wallet-unrelated.
		m.store.On("GetTxDetail", mock.Anything, db.GetTxDetailQuery{
			WalletID: w.id,
			Txid:     tx.TxIn[0].PreviousOutPoint.Hash,
		}).Return((*db.TxDetailInfo)(nil), db.ErrTxNotFound).Once()

		// Add the transaction to the wallet.
		ourAddrs, recorded, err := w.addTxToWallet(
			t.Context(), tx, label,
		)
		require.NoError(t, err)

		// We expect no addresses to be returned, no calls to the
		// transaction store, and recorded to be false because nothing
		// was written.
		require.Nil(t, ourAddrs)
		require.False(t, recorded)
	})

	t.Run("sweep tx (owned input, no owned outputs)", func(t *testing.T) {
		t.Parallel()

		w, m := createStartedWalletWithMocks(t)

		// A sweep pays no wallet-owned outputs but spends a wallet
		// UTXO, so it must still be recorded (with an empty credit
		// set) so it can be tracked and later invalidated.
		m.store.On("ResolveOwnedAddresses", mock.Anything,
			matchResolveOwnedAddressesQuery(w.id, ownedScript, unownedScript),
		).Return(ownedAddrsResult(), nil).Once()

		// The single input spends a wallet output, so GetUtxo returns
		// a UTXO.
		m.store.On("GetUtxo", mock.Anything, db.GetUtxoQuery{
			WalletID: w.id,
			OutPoint: tx.TxIn[0].PreviousOutPoint,
		}).Return(&db.UtxoInfo{
			OutPoint: tx.TxIn[0].PreviousOutPoint,
		}, nil).Once()

		// The tx is recorded with an empty credit map.
		m.store.On("CreateTx", mock.Anything,
			matchCreateTxParams(
				w.id, tx, label,
				map[uint32]address.Address{},
			),
		).Return(nil).Once()

		ourAddrs, recorded, err := w.addTxToWallet(
			t.Context(), tx, label,
		)
		require.NoError(t, err)

		// A debit-only sweep credits no wallet outputs, so no
		// addresses are returned, yet recorded is true because the tx
		// row was written.
		require.Nil(t, ourAddrs)
		require.True(t, recorded)
	})
}

// TestSpendsWalletOutputConflictingNoChangeSpend is the task-173 regression:
// a no-change transaction re-spends a wallet output that is already consumed by
// another unmined wallet transaction. That output is no longer in the current
// UTXO set, so GetUtxo misses it, but it remains a wallet-owned output of its
// recorded parent transaction.
//
// spendsWalletOutput must therefore derive wallet relevance from the parent's
// owned outputs, not from current-UTXO membership, and report the spend as
// ours. That is what keeps addTxToWallet from taking its wallet-unrelated
// early-out: the tx is instead recorded, and for SQL backends the store-level
// CreateTx / MarkInputsSpent path then arbitrates the double-spend before it
// can broadcast unrecorded.
func TestSpendsWalletOutputConflictingNoChangeSpend(t *testing.T) {
	t.Parallel()

	w, m := createStartedWalletWithMocks(t)

	// The no-change tx pays a single output to an address the wallet does
	// not own, and spends one prior outpoint O.
	unownedAddr := mustNewStandalonePubKeyAddr(t)
	unownedScript := mustPayToAddrScript(unownedAddr)

	spentOutPoint := wire.OutPoint{Hash: chainhash.Hash{0xcc}, Index: 1}
	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{PreviousOutPoint: spentOutPoint}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: unownedScript}},
	}

	// O is already spent by another unmined wallet tx, so it is not a
	// current UTXO and GetUtxo misses it.
	m.store.On("GetUtxo", mock.Anything, db.GetUtxoQuery{
		WalletID: w.id,
		OutPoint: spentOutPoint,
	}).Return((*db.UtxoInfo)(nil), db.ErrUtxoNotFound).Once()

	// O's parent is a recorded wallet tx that owns output index 1, so the
	// wallet still owns the now-spent output.
	m.store.On("GetTxDetail", mock.Anything, db.GetTxDetailQuery{
		WalletID: w.id,
		Txid:     spentOutPoint.Hash,
	}).Return(&db.TxDetailInfo{
		OwnedOutputs: []db.TxOwnedOutput{{Index: 1, Amount: 5000}},
	}, nil).Once()

	spendsOurs, err := w.spendsWalletOutput(t.Context(), tx)
	require.NoError(t, err)

	// The conflicting spend must not be classified as wallet-unrelated.
	require.True(t, spendsOurs)
}

// mustPayToAddrScript is a helper function to create a PkScript for a given
// address. It panics on error.
func mustPayToAddrScript(addr address.Address) []byte {
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		panic(err)
	}

	return pkScript
}

// TestInvalidateUnminedTx tests the invalidateUnminedTx method to ensure it
// correctly marks a transaction failed in the unconfirmed store.
func TestInvalidateUnminedTx(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	// Create a sample transaction with one input and one output.
	tx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{
			Value: 10000,
		}},
	}

	txid := tx.TxHash()
	mocks.store.On(
		"InvalidateUnminedTx", mock.Anything,
		matchInvalidateUnminedTxParams(w.id, txid),
	).Return(nil).Once()

	// Call the method under test.
	err := w.invalidateUnminedTx(t.Context(), tx)
	require.NoError(t, err)
}

// TestCheckMempool tests the checkMempool helper function.
func TestCheckMempool(t *testing.T) {
	t.Parallel()

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

			w, m := createStartedWalletWithMocks(t)

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

			err := w.checkMempool(t.Context(), tx)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// TestPublishTx tests the publishTx helper function.
func TestPublishTx(t *testing.T) {
	t.Parallel()

	tx := &wire.MsgTx{}
	addrs := []address.Address{&address.AddressPubKey{}}

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
			w, m := createStartedWalletWithMocks(t)

			m.chain.On("NotifyReceived",
				mock.Anything, mock.Anything,
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

	label := testTxLabel
	w, m := createStartedWalletWithMocks(t)

	// Create a transaction with an owned output.
	ownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownedAddr, err := address.NewAddressPubKey(
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

	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, pkScript),
	).Return(ownedAddrsResult(pkScript), nil).Once()
	m.store.On("CreateTx", mock.Anything,
		matchCreateTxParams(w.id, tx, label, map[uint32]address.Address{
			0: ownedAddr,
		}),
	).Return(nil).Once()

	// Mock publishTx to succeed.
	m.chain.On("NotifyReceived", mock.Anything).Return(nil)
	m.chain.On("SendRawTransaction",
		mock.Anything, mock.Anything,
	).Return(nil, nil)

	err = w.Broadcast(t.Context(), tx, label)
	require.NoError(t, err)
}

// TestBroadcastAlreadyBroadcasted tests the Broadcast method when the
// transaction has already been broadcasted.
func TestBroadcastAlreadyBroadcasted(t *testing.T) {
	t.Parallel()

	label := testTxLabel
	w, m := createStartedWalletWithMocks(t)

	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000}},
	}

	// Mock checkMempool to return already broadcasted.
	m.chain.On("TestMempoolAccept", mock.Anything, mock.Anything).
		Return(nil, chain.ErrTxAlreadyInMempool)

	err := w.Broadcast(t.Context(), tx, label)
	require.NoError(t, err)
}

// TestBroadcastPublishFailsRemoveSucceeds tests the Broadcast method when
// publishing fails but removing the transaction from the wallet succeeds.
func TestBroadcastPublishFailsRemoveSucceeds(t *testing.T) {
	t.Parallel()

	label := testTxLabel
	w, m := createStartedWalletWithMocks(t)

	// Create a transaction with an owned output.
	ownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownedAddr, err := address.NewAddressPubKey(
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

	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, pkScript),
	).Return(ownedAddrsResult(pkScript), nil).Once()
	m.store.On("CreateTx", mock.Anything,
		matchCreateTxParams(w.id, tx, label, map[uint32]address.Address{
			0: ownedAddr,
		}),
	).Return(nil).Once()

	// Mock publishTx to fail.
	m.chain.On("NotifyReceived", mock.Anything).Return(nil)
	m.chain.On("SendRawTransaction",
		mock.Anything, mock.Anything,
	).Return(nil, errPublish)

	m.store.On("InvalidateUnminedTx", mock.Anything,
		matchInvalidateUnminedTxParams(w.id, tx.TxHash()),
	).Return(nil).Once()

	err = w.Broadcast(t.Context(), tx, label)
	require.ErrorIs(t, err, errPublish)
}

// TestBroadcastSweepPublishFailsInvalidateSucceeds tests that a sweep tx (no
// owned outputs but an owned input) is recorded, and that when publishing fails
// the recorded tx is invalidated rather than hitting ErrTxNotFound.
func TestBroadcastSweepPublishFailsInvalidateSucceeds(t *testing.T) {
	t.Parallel()

	label := testTxLabel
	w, m := createStartedWalletWithMocks(t)

	// Create a tx whose only output pays an address the wallet does not
	// own, so it has no owned outputs.
	unownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	unownedAddr, err := address.NewAddressPubKey(
		unownedPrivKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(unownedAddr)
	require.NoError(t, err)

	prevOut := wire.OutPoint{Hash: chainhash.Hash{0xaa}, Index: 0}
	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{PreviousOutPoint: prevOut}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: pkScript}},
	}

	// Mock checkMempool to succeed.
	m.chain.On("TestMempoolAccept",
		mock.Anything, mock.Anything,
	).Return([]*btcjson.TestMempoolAcceptResult{{Allowed: true}}, nil)

	// The output is unowned.
	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, pkScript),
	).Return(ownedAddrsResult(), nil).Once()

	// The input spends a wallet UTXO, marking the tx as ours.
	m.store.On("GetUtxo", mock.Anything, db.GetUtxoQuery{
		WalletID: w.id,
		OutPoint: prevOut,
	}).Return(&db.UtxoInfo{OutPoint: prevOut}, nil).Once()

	// The sweep is recorded with no credits.
	m.store.On("CreateTx", mock.Anything,
		matchCreateTxParams(
			w.id, tx, label, map[uint32]address.Address{},
		),
	).Return(nil).Once()

	// Mock publishTx to fail.
	m.chain.On("NotifyReceived", mock.Anything).Return(nil)
	m.chain.On("SendRawTransaction",
		mock.Anything, mock.Anything,
	).Return(nil, errPublish)

	// The recorded sweep can be invalidated because a row exists.
	m.store.On("InvalidateUnminedTx", mock.Anything,
		matchInvalidateUnminedTxParams(w.id, tx.TxHash()),
	).Return(nil).Once()

	err = w.Broadcast(t.Context(), tx, label)
	require.ErrorIs(t, err, errPublish)
}

// TestBroadcastUnrelatedPublishFailsNoInvalidate tests that when a
// wallet-unrelated tx (no owned outputs and no owned inputs) fails to publish,
// Broadcast does not attempt to invalidate it and returns the original publish
// error unchanged. Invalidating a never-recorded tx would surface
// db.ErrTxNotFound and clobber the real broadcast error.
func TestBroadcastUnrelatedPublishFailsNoInvalidate(t *testing.T) {
	t.Parallel()

	label := testTxLabel
	w, m := createStartedWalletWithMocks(t)

	// Create a tx whose only output pays an address the wallet does not
	// own, so it has no owned outputs.
	unownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	unownedAddr, err := address.NewAddressPubKey(
		unownedPrivKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(unownedAddr)
	require.NoError(t, err)

	prevOut := wire.OutPoint{Hash: chainhash.Hash{0xbb}, Index: 0}
	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{PreviousOutPoint: prevOut}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: pkScript}},
	}

	// Mock checkMempool to succeed.
	m.chain.On("TestMempoolAccept",
		mock.Anything, mock.Anything,
	).Return([]*btcjson.TestMempoolAcceptResult{{Allowed: true}}, nil)

	// The output is unowned.
	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, pkScript),
	).Return(ownedAddrsResult(), nil).Once()

	// The input does not spend a wallet UTXO, so the tx is wallet-unrelated
	// and is never recorded.
	m.store.On("GetUtxo", mock.Anything, db.GetUtxoQuery{
		WalletID: w.id,
		OutPoint: prevOut,
	}).Return((*db.UtxoInfo)(nil), db.ErrUtxoNotFound).Once()

	// The input's parent is not a wallet transaction either, so the output
	// is not a wallet-owned output that is merely already spent. The tx is
	// therefore genuinely wallet-unrelated.
	m.store.On("GetTxDetail", mock.Anything, db.GetTxDetailQuery{
		WalletID: w.id,
		Txid:     prevOut.Hash,
	}).Return((*db.TxDetailInfo)(nil), db.ErrTxNotFound).Once()

	// Mock publishTx to fail.
	m.chain.On("NotifyReceived", mock.Anything).Return(nil)
	m.chain.On("SendRawTransaction",
		mock.Anything, mock.Anything,
	).Return(nil, errPublish)

	// We deliberately register no InvalidateUnminedTx expectation: it must
	// not be called for a never-recorded tx.

	err = w.Broadcast(t.Context(), tx, label)

	// The original publish error must be preserved and not clobbered with
	// cleanup context such as db.ErrTxNotFound.
	require.ErrorIs(t, err, errPublish)
	require.NotErrorIs(t, err, db.ErrTxNotFound)

	// No invalidation must have been attempted for the unrecorded tx.
	m.store.AssertNotCalled(t, "InvalidateUnminedTx", mock.Anything,
		mock.Anything)
}

// TestBroadcastPublishFailsRemoveFails tests the Broadcast method when both
// publishing and removing the transaction from the wallet fail.
func TestBroadcastPublishFailsRemoveFails(t *testing.T) {
	t.Parallel()

	label := testTxLabel
	w, m := createStartedWalletWithMocks(t)

	// Create a transaction with an owned output.
	ownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownedAddr, err := address.NewAddressPubKey(
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

	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, pkScript),
	).Return(ownedAddrsResult(pkScript), nil).Once()
	m.store.On("CreateTx", mock.Anything,
		matchCreateTxParams(w.id, tx, label, map[uint32]address.Address{
			0: ownedAddr,
		}),
	).Return(nil).Once()

	// Mock publishTx to fail.
	m.chain.On("NotifyReceived", mock.Anything).Return(nil)
	m.chain.On("SendRawTransaction",
		mock.Anything, mock.Anything,
	).Return(nil, errPublish)

	m.store.On("InvalidateUnminedTx", mock.Anything,
		matchInvalidateUnminedTxParams(w.id, tx.TxHash()),
	).Return(errRemove).Once()

	err = w.Broadcast(t.Context(), tx, label)
	require.Error(t, err)
	require.Contains(t, err.Error(), errPublish.Error())
	require.Contains(t, err.Error(), errRemove.Error())
}

// TestBroadcastNilTx tests that the Broadcast method returns an error when a
// nil transaction is passed.
func TestBroadcastNilTx(t *testing.T) {
	t.Parallel()

	label := testTxLabel
	w, _ := createStartedWalletWithMocks(t)

	err := w.Broadcast(t.Context(), nil, label)
	require.ErrorIs(t, err, ErrTxCannotBeNil)
}

// TestBroadcastRetryRetainedInvalidDoesNotPublish verifies the retained-invalid
// guard added in "wallet: route tx recording and ownership filtering through
// store": when a prior Broadcast recorded a tx, its publish failed, and cleanup
// invalidated the row, a later retry with the same tx hash hits
// ErrTxAlreadyExists in CreateTx. Because the only stored row is now in a
// terminal failed state, Broadcast must refuse to report the record step a
// success and must NOT publish the tx. The store's retained failed row is the
// source of truth; SendRawTransaction is never reached.
func TestBroadcastRetryRetainedInvalidDoesNotPublish(t *testing.T) {
	t.Parallel()

	label := testTxLabel
	w, m := createStartedWalletWithMocks(t)

	// Create a transaction with an owned output so it is classified as ours
	// and recording is attempted.
	ownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownedAddr, err := address.NewAddressPubKey(
		ownedPrivKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(ownedAddr)
	require.NoError(t, err)

	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: pkScript}},
	}
	txid := tx.TxHash()

	// Mock checkMempool to succeed so the flow reaches recording.
	m.chain.On("TestMempoolAccept",
		mock.Anything, mock.Anything,
	).Return([]*btcjson.TestMempoolAcceptResult{{Allowed: true}}, nil)

	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, pkScript),
	).Return(ownedAddrsResult(pkScript), nil).Once()

	// The prior attempt already inserted this tx, so CreateTx reports the
	// duplicate.
	m.store.On("CreateTx", mock.Anything,
		matchCreateTxParams(w.id, tx, label, map[uint32]address.Address{
			0: ownedAddr,
		}),
	).Return(db.ErrTxAlreadyExists).Once()

	// The retained row was invalidated by the prior cleanup and is now
	// failed, so the record step must refuse the duplicate.
	m.store.On("GetTx", mock.Anything,
		db.GetTxQuery{WalletID: w.id, Txid: txid},
	).Return(&db.TxInfo{Hash: txid, Status: db.TxStatusFailed}, nil).Once()

	// We deliberately register NO SendRawTransaction (and no NotifyReceived)
	// expectation: publishing must not happen while the only stored row is
	// failed. AssertExpectations would flag an unexpected publish call.
	err = w.Broadcast(t.Context(), tx, label)
	require.ErrorIs(t, err, ErrTxRetainedInvalid)
}

// TestBroadcastRetryLiveDuplicateIdempotent verifies the complementary case:
// when CreateTx reports a duplicate but the stored row is still live
// (TxStatusPublished), Broadcast treats the record step as an idempotent
// success and proceeds to (re)publish the tx, leaving the live row tracked.
func TestBroadcastRetryLiveDuplicateIdempotent(t *testing.T) {
	t.Parallel()

	label := testTxLabel
	w, m := createStartedWalletWithMocks(t)

	ownedPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ownedAddr, err := address.NewAddressPubKey(
		ownedPrivKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(ownedAddr)
	require.NoError(t, err)

	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: pkScript}},
	}
	txid := tx.TxHash()

	m.chain.On("TestMempoolAccept",
		mock.Anything, mock.Anything,
	).Return([]*btcjson.TestMempoolAcceptResult{{Allowed: true}}, nil)

	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, pkScript),
	).Return(ownedAddrsResult(pkScript), nil).Once()

	m.store.On("CreateTx", mock.Anything,
		matchCreateTxParams(w.id, tx, label, map[uint32]address.Address{
			0: ownedAddr,
		}),
	).Return(db.ErrTxAlreadyExists).Once()

	// The existing row is still live, so the duplicate is idempotent.
	m.store.On("GetTx", mock.Anything,
		db.GetTxQuery{WalletID: w.id, Txid: txid},
	).Return(&db.TxInfo{Hash: txid, Status: db.TxStatusPublished}, nil).Once()

	// A non-empty label still patches the stored label on the live row.
	m.store.On("UpdateTx", mock.Anything,
		matchUpdateTxParams(w.id, txid, &label, nil),
	).Return(nil).Once()

	// Recording succeeded idempotently, so publishing proceeds as normal.
	m.chain.On("NotifyReceived", mock.Anything).Return(nil)
	m.chain.On("SendRawTransaction",
		mock.Anything, mock.Anything,
	).Return(nil, nil)

	err = w.Broadcast(t.Context(), tx, label)
	require.NoError(t, err)
}
