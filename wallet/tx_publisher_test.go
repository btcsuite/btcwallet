// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
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

// matchDeleteUnminedTxParams returns a matcher for Store removal
// requests.
func matchDeleteUnminedTxParams(walletID uint32, txid chainhash.Hash) any {
	return mock.MatchedBy(func(params db.DeleteUnminedTxParams) bool {
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

// TestRecordTxAndCredits verifies recorded bytes and terminal duplicate refusal
// with the same Store call structure for fresh and retained rows.
func TestRecordTxAndCredits(t *testing.T) {
	t.Parallel()

	// Arrange: Vary only persisted metadata; none of these rows needs a
	// metadata write after CreateTx and the retained-byte read.
	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000}},
	}
	addr := mustNewStandalonePubKeyAddr(t)

	testCases := []struct {
		name      string
		label     string
		createErr error
		status    db.TxStatus
		wantErr   error
	}{
		{
			name:   "new with label",
			label:  testTxLabel,
			status: db.TxStatusPublished,
		},
		{
			name:   "new without label",
			status: db.TxStatusPublished,
		},
		{
			name:      "failed duplicate",
			createErr: db.ErrTxAlreadyExists,
			status:    db.TxStatusFailed,
			wantErr:   ErrTxRetainedInvalid,
		},
		{
			name:      "replaced duplicate",
			createErr: db.ErrTxAlreadyExists,
			status:    db.TxStatusReplaced,
			wantErr:   ErrTxRetainedInvalid,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Return the exact bytes and label retained by
			// recording; terminal statuses must stop reconciliation.
			w, m := createStartedWalletWithMocks(t)
			m.store.On("CreateTx", mock.Anything,
				matchCreateTxParams(w.id, tx, tc.label,
					map[uint32]address.Address{0: addr},
				),
			).Return(tc.createErr).Once()
			m.store.On("GetTx", mock.Anything, db.GetTxQuery{
				WalletID: w.id,
				Txid:     tx.TxHash(),
			}).Return(&db.TxInfo{
				SerializedTx: serializeTx(t, tx),
				Status:       tc.status,
				Label:        tc.label,
			}, nil).Once()

			// Act: Record one owned credit through the existing Store API.
			err := w.recordTxAndCredits(t.Context(), tx, tc.label,
				[]creditInfo{
					{
						index: 0,
						addr:  addr,
					},
				}, false,
			)

			// Assert: A live row needs no redundant update; terminal
			// history is refused. Fixture cleanup verifies calls once.
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestRecordTxAndCreditsUpdatesDuplicate preserves label reconciliation and
// pending promotion through the error-only duplicate contract.
func TestRecordTxAndCreditsUpdatesDuplicate(t *testing.T) {
	t.Parallel()

	// Arrange: Both duplicate states need the same metadata call; only the
	// state payload differs when a pending row enters publication tracking.
	testCases := []struct {
		name   string
		status db.TxStatus
		state  *db.UpdateTxState
	}{
		{
			name:   "published label",
			status: db.TxStatusPublished,
		},
		{
			name:   "pending promotion",
			status: db.TxStatusPending,
			state: &db.UpdateTxState{
				Status: db.TxStatusPublished,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: An older label forces one reconciliation after
			// validating the immutable serialization returned by GetTx.
			w, m := createStartedWalletWithMocks(t)
			tx := &wire.MsgTx{TxIn: []*wire.TxIn{{}}}
			label := testTxLabel
			m.store.On("CreateTx", mock.Anything,
				matchCreateTxParams(w.id, tx, label, nil),
			).Return(db.ErrTxAlreadyExists).Once()
			m.store.On("GetTx", mock.Anything, db.GetTxQuery{
				WalletID: w.id,
				Txid:     tx.TxHash(),
			}).Return(&db.TxInfo{
				SerializedTx: serializeTx(t, tx),
				Status:       tc.status,
			}, nil).Once()
			m.store.On("UpdateTx", mock.Anything,
				matchUpdateTxParams(w.id, tx.TxHash(), &label, tc.state),
			).Return(nil).Once()

			// Act: Retry recording through the legacy duplicate outcome.
			err := w.recordTxAndCredits(
				t.Context(), tx, label, nil, false,
			)

			// Assert: The unchanged Store API still supports both updates;
			// fixture cleanup checks each required call once.
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
				{
					index: 0,
					addr:  smaller,
				},
				{
					index: 0,
					addr:  larger,
				},
			},
		},
		{
			name: "larger first",
			credits: []creditInfo{
				{
					index: 0,
					addr:  larger,
				},
				{
					index: 0,
					addr:  smaller,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Configure the same canonical owner for both
			// orderings of the owned member credits.
			w, mocks := createStartedWalletWithMocks(t)

			mocks.store.On("CreateTx", mock.Anything,
				matchCreateTxParams(w.id, tx, "", expectedCredits),
			).Return(nil).Once()
			// Read the immutable bytes retained by the original Store API.
			mocks.store.On("GetTx", mock.Anything, db.GetTxQuery{
				WalletID: w.id,
				Txid:     tx.TxHash(),
			}).Return(&db.TxInfo{
				SerializedTx: serializeTx(t, tx),
				Status:       db.TxStatusPublished,
				Label:        "",
			}, nil).Once()

			// Act: Record the two members in the current table
			// ordering.
			err := w.recordTxAndCredits(
				t.Context(), tx, "", tc.credits, false,
			)

			// Assert: Require the same canonical credit mapping for
			// either input ordering.
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

		// Arrange: This test case simulates the scenario where the
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
		// Read the immutable bytes retained by the original Store API.
		m.store.On("GetTx", mock.Anything, db.GetTxQuery{
			WalletID: w.id,
			Txid:     tx.TxHash(),
		}).Return(&db.TxInfo{
			SerializedTx: serializeTx(t, tx),
			Status:       db.TxStatusPublished,
			Label:        label,
		}, nil).Once()

		// Act: Resolve wallet relevance and record the resulting owned
		// credits.
		ourAddrs, recorded, err := w.addTxToWallet(
			t.Context(), tx, label, false,
		)

		// Assert: Check recording and returned addresses while the
		// Store expectations verify the required credit writes.
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

		// Arrange: This test case simulates the scenario where the
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

		// Act: Resolve wallet relevance and record the resulting owned
		// credits.
		ourAddrs, recorded, err := w.addTxToWallet(
			t.Context(), tx, label, false,
		)

		// Assert: Check recording and returned addresses while the
		// Store expectations verify the required credit writes.
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

		// Arrange: A sweep pays no owned outputs but spends a wallet
		// UTXO, so it must still be recorded (with an empty credit
		// set) so it can be tracked and later removed.
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
		// Read the immutable bytes retained by the original Store API.
		m.store.On("GetTx", mock.Anything, db.GetTxQuery{
			WalletID: w.id,
			Txid:     tx.TxHash(),
		}).Return(&db.TxInfo{
			SerializedTx: serializeTx(t, tx),
			Status:       db.TxStatusPublished,
			Label:        label,
		}, nil).Once()

		// Act: Resolve wallet relevance and record the resulting owned
		// credits.
		ourAddrs, recorded, err := w.addTxToWallet(
			t.Context(), tx, label, false,
		)

		// Assert: Check recording and returned addresses while the
		// Store expectations verify the required credit writes.
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

// TestDeleteUnminedTx tests the deleteUnminedTx method to ensure it
// removes a transaction from the unconfirmed store.
func TestDeleteUnminedTx(t *testing.T) {
	t.Parallel()

	// Arrange: The existing Store fixture expects one branch removal for
	// the supplied transaction; fixture cleanup owns expectation checks.
	w, mocks := createStartedWalletWithMocks(t)
	tx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{
			Value: 10000,
		}},
	}

	txid := tx.TxHash()
	mocks.store.On(
		"DeleteUnminedTx", mock.Anything,
		matchDeleteUnminedTxParams(w.id, txid),
	).Return(nil).Once()

	// Act: Remove the branch through the existing deletion helper.
	err := w.deleteUnminedTx(t.Context(), tx)

	// Assert: Successful Store removal is reported without a new error.
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
		results          []*btcjson.TestMempoolAcceptResult
	}{
		{
			name:             "accepted",
			mempoolAcceptErr: nil,
			expectedErr:      nil,
			results: []*btcjson.TestMempoolAcceptResult{
				{
					Allowed: true,
				},
			},
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, m := createStartedWalletWithMocks(t)

			// Arrange: These native outcomes need no Store read. Public
			// preflight-failure tests cover rejection and retained claims.
			m.chain.On("TestMempoolAccept", mock.Anything, mock.Anything).
				Return(tc.results, tc.mempoolAcceptErr).Once()

			// Act: Interpret acceptance, known-success or unsupported checks.
			err := w.checkMempool(t.Context(), tx)

			// Assert: No lookup or write is permitted for these outcomes.
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// TestPublishTx verifies native send failures and known outcomes preserve
// their caller-visible identities through Manager-owned registration.
func TestPublishTx(t *testing.T) {
	t.Parallel()

	// Arrange: Use an encodable watch address so each existing result row
	// exercises registration ownership before the configured native outcome.
	addr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)

	tx := &wire.MsgTx{}
	addrs := []address.Address{addr}

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
		{
			name:        "already known",
			notifyErr:   nil,
			sendErr:     chain.ErrTxAlreadyKnown,
			expectedErr: nil,
		},
		{
			name:        "already confirmed",
			notifyErr:   nil,
			sendErr:     chain.ErrTxAlreadyConfirmed,
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Arrange: Expect one registration and, when it succeeds, one
			// native send. Fixture cleanup verifies the mock once.
			w, m := createStartedWalletWithMocks(t)

			m.chain.On("NotifyReceived", addrs).Return(tc.notifyErr).Once()

			m.chain.On("SendRawTransaction", tx, false).
				Return(nil, tc.sendErr).Once()

			// Act: Publish through the existing native delegation path.
			err := w.publishTx(tx, addrs)

			// Assert: Wrapping preserves causal failures while the existing
			// already-known results remain successful.
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// TestBroadcastSuccess tests the Broadcast method for a successful broadcast.
func TestBroadcastSuccess(t *testing.T) {
	t.Parallel()

	label := testTxLabel
	w, m := createStartedWalletWithMocks(t)

	// Arrange: An owned output makes publication tracking observable.
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
	).Return([]*btcjson.TestMempoolAcceptResult{{Allowed: true}}, nil).Once()

	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, pkScript),
	).Return(ownedAddrsResult(pkScript), nil).Once()
	m.store.On("CreateTx", mock.Anything,
		matchCreateTxParams(w.id, tx, label, map[uint32]address.Address{
			0: ownedAddr,
		}),
	).Return(nil).Once()
	// Read the immutable bytes retained by the original Store API.
	m.store.On("GetTx", mock.Anything, db.GetTxQuery{
		WalletID: w.id,
		Txid:     tx.TxHash(),
	}).Return(&db.TxInfo{
		SerializedTx: serializeTx(t, tx),
		Status:       db.TxStatusPublished,
		Label:        label,
	}, nil).Once()

	// Mock publishTx to succeed.
	m.chain.On("NotifyReceived", mock.Anything).Return(nil).Once()
	m.chain.On("SendRawTransaction",
		mock.Anything, mock.Anything,
	).Return(nil, nil).Once()

	// Act: Publish after recording returns the expected immutable bytes.
	err = w.Broadcast(t.Context(), tx, label)

	// Assert: Recording permits publication; fixture cleanup verifies calls.
	require.NoError(t, err)
}

// TestBroadcastAlreadyBroadcastedAtPublish tests that Broadcast treats an
// already-known or already-confirmed SendRawTransaction error as a successful
// publish: it returns nil and must not remove the recorded tx. This guards
// the path where mempool acceptance is unavailable, so the duplicate is only
// detected at publish time.
func TestBroadcastAlreadyBroadcastedAtPublish(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		sendErr error
	}{
		{
			name:    "already known",
			sendErr: chain.ErrTxAlreadyKnown,
		},
		{
			name:    "already confirmed",
			sendErr: chain.ErrTxAlreadyConfirmed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			label := testTxLabel
			w, m := createStartedWalletWithMocks(t)

			// Arrange: An owned output is recorded before the native
			// send reports an already-known result.
			ownedPrivKey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			ownedAddr, err := address.NewAddressPubKey(
				ownedPrivKey.PubKey().SerializeCompressed(),
				&chainParams,
			)
			require.NoError(t, err)
			pkScript, err := txscript.PayToAddrScript(ownedAddr)
			require.NoError(t, err)

			tx := &wire.MsgTx{
				TxIn: []*wire.TxIn{{}},
				TxOut: []*wire.TxOut{
					{Value: 10000, PkScript: pkScript},
				},
			}

			// Mempool acceptance is unavailable, so checkMempool
			// falls through to a direct publish.
			m.chain.On("TestMempoolAccept",
				mock.Anything, mock.Anything,
			).Return(
				[]*btcjson.TestMempoolAcceptResult(nil),
				chain.ErrUnimplemented,
			).Once()

			m.store.On("ResolveOwnedAddresses", mock.Anything,
				matchResolveOwnedAddressesQuery(w.id, pkScript),
			).Return(ownedAddrsResult(pkScript), nil).Once()
			m.store.On("CreateTx", mock.Anything,
				matchCreateTxParams(w.id, tx, label,
					map[uint32]address.Address{0: ownedAddr},
				),
			).Return(nil).Once()
			// Read the immutable bytes retained by the original Store API.
			m.store.On("GetTx", mock.Anything, db.GetTxQuery{
				WalletID: w.id,
				Txid:     tx.TxHash(),
			}).Return(&db.TxInfo{
				SerializedTx: serializeTx(t, tx),
				Status:       db.TxStatusPublished,
				Label:        label,
			}, nil).Once()

			// publishTx sees the duplicate only at send time.
			m.chain.On("NotifyReceived",
				mock.Anything).Return(nil).Once()
			m.chain.On("SendRawTransaction",
				mock.Anything, mock.Anything,
			).Return(nil, tc.sendErr).Once()

			// Act: Learn the known result during sending without preflight.
			err = w.Broadcast(t.Context(), tx, label)

			// Assert: The already-broadcast tx must be treated as a
			// success and kept tracked, never removed.
			require.NoError(t, err)
			m.store.AssertNotCalled(t, "DeleteUnminedTx",
				mock.Anything, mock.Anything)
		})
	}
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

// TestBroadcastPublishFailsRetainsTx verifies an uncertain send outcome keeps
// a recorded attempt and reports its input claims without losing the cause.
func TestBroadcastPublishFailsRetainsTx(t *testing.T) {
	t.Parallel()

	// Arrange: Skip preflight and record an owned output before the send
	// fails without a backend verdict. No deletion may follow that outcome.
	w, m := createStartedWalletWithMocks(t)
	addr := mustNewStandalonePubKeyAddr(t)
	script := mustPayToAddrScript(addr)
	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: script}},
	}

	m.chain.On("TestMempoolAccept", mock.Anything, mock.Anything).
		Return(nil, chain.ErrUnimplemented).Once()
	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, script),
	).Return(ownedAddrsResult(script), nil).Once()
	m.store.On("CreateTx", mock.Anything,
		matchCreateTxParams(w.id, tx, "", map[uint32]address.Address{0: addr}),
	).Return(nil).Once()
	m.store.On("GetTx", mock.Anything, db.GetTxQuery{
		WalletID: w.id,
		Txid:     tx.TxHash(),
	}).Return(&db.TxInfo{
		SerializedTx: serializeTx(t, tx),
		Status:       db.TxStatusPublished,
	}, nil).Once()
	m.chain.On("NotifyReceived", mock.Anything).Return(nil).Once()
	m.chain.On("SendRawTransaction", tx, false).
		Return(nil, errPublish).Once()

	// Act: Publish through the public API with no DeleteUnminedTx
	// expectation; the strict Store mock rejects any attempted cleanup.
	err := w.Broadcast(t.Context(), tx, "")

	// Assert: Keep the retained-input signal and the unknown send cause;
	// fixture cleanup verifies every required mock interaction once.
	require.ErrorIs(t, err, ErrTxRetained)
	require.ErrorIs(t, err, errPublish)
}

// TestBroadcastRegistrationFailsRetainsTx verifies tracking survives failure
// before sending, when notification registration cannot establish a verdict.
func TestBroadcastRegistrationFailsRetainsTx(t *testing.T) {
	t.Parallel()

	// Arrange: Record an owned output, then refuse notification registration.
	// No send or deletion is allowed after this failure.
	w, m := createStartedWalletWithMocks(t)
	addr := mustNewStandalonePubKeyAddr(t)
	script := mustPayToAddrScript(addr)
	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: script}},
	}

	m.chain.On("TestMempoolAccept", mock.Anything, mock.Anything).
		Return(nil, chain.ErrUnimplemented).Once()
	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, script),
	).Return(ownedAddrsResult(script), nil).Once()
	m.store.On("CreateTx", mock.Anything,
		matchCreateTxParams(w.id, tx, "", map[uint32]address.Address{0: addr}),
	).Return(nil).Once()
	m.store.On("GetTx", mock.Anything, db.GetTxQuery{
		WalletID: w.id,
		Txid:     tx.TxHash(),
	}).Return(&db.TxInfo{
		SerializedTx: serializeTx(t, tx),
		Status:       db.TxStatusPublished,
	}, nil).Once()
	m.chain.On("NotifyReceived", mock.Anything).Return(errDummy).Once()

	// Act: Fail publication before the chain send can run.
	err := w.Broadcast(t.Context(), tx, "")

	// Assert: Tracking and the registration cause remain caller-visible;
	// strict fixture-owned mocks reject send or cleanup attempts.
	require.ErrorIs(t, err, ErrTxRetained)
	require.ErrorIs(t, err, errDummy)
}

// TestBroadcastScriptRejectionRemovesTx preserves cleanup for recognized
// verification failures, including an already-removed branch.
func TestBroadcastScriptRejectionRemovesTx(t *testing.T) {
	t.Parallel()

	// Arrange: Both cleanup results mean the branch is absent. Keeping
	// identical calls separates idempotent absence from a retained claim.
	testCases := []struct {
		name       string
		cleanupErr error
	}{
		{
			name: "removed",
		},
		{
			name:       "already absent",
			cleanupErr: db.ErrTxNotFound,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Without preflight, script rejection is discovered
			// after recording and must reach the existing cleanup path.
			w, m := createStartedWalletWithMocks(t)
			addr := mustNewStandalonePubKeyAddr(t)
			script := mustPayToAddrScript(addr)
			tx := &wire.MsgTx{
				TxIn:  []*wire.TxIn{{}},
				TxOut: []*wire.TxOut{{Value: 10000, PkScript: script}},
			}

			m.chain.On("TestMempoolAccept", mock.Anything, mock.Anything).
				Return(nil, chain.ErrUnimplemented).Once()
			m.store.On("ResolveOwnedAddresses", mock.Anything,
				matchResolveOwnedAddressesQuery(w.id, script),
			).Return(ownedAddrsResult(script), nil).Once()
			m.store.On("CreateTx", mock.Anything,
				matchCreateTxParams(w.id, tx, "",
					map[uint32]address.Address{0: addr},
				),
			).Return(nil).Once()
			m.store.On("GetTx", mock.Anything, db.GetTxQuery{
				WalletID: w.id,
				Txid:     tx.TxHash(),
			}).Return(&db.TxInfo{
				SerializedTx: serializeTx(t, tx),
				Status:       db.TxStatusPublished,
			}, nil).Once()
			m.chain.On("NotifyReceived", mock.Anything).Return(nil).Once()
			m.chain.On("SendRawTransaction", tx, false).
				Return(nil, chain.ErrScriptVerifyFlag).Once()
			m.store.On("DeleteUnminedTx", mock.Anything,
				matchDeleteUnminedTxParams(w.id, tx.TxHash()),
			).Return(tc.cleanupErr).Once()

			// Act: Reject and complete cleanup before returning to caller.
			err := w.Broadcast(t.Context(), tx, "")

			// Assert: Neither successful nor already-finished cleanup
			// reports retained inputs or replaces the verification cause.
			require.ErrorIs(t, err, chain.ErrScriptVerifyFlag)
			require.NotErrorIs(t, err, ErrTxRetained)
			require.NotErrorIs(t, err, db.ErrTxNotFound)
		})
	}
}

// TestBroadcastCleanupFailsRetainsSweep verifies an unsuccessful removal keeps
// the input claim signal even for a debit-only transaction.
func TestBroadcastCleanupFailsRetainsSweep(t *testing.T) {
	t.Parallel()

	// Arrange: The transaction spends a wallet coin but pays no owned output.
	// A script rejection requests cleanup, and the Store fails that cleanup.
	w, m := createStartedWalletWithMocks(t)
	script := mustPayToAddrScript(mustNewStandalonePubKeyAddr(t))
	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: script}},
	}

	m.chain.On("TestMempoolAccept", mock.Anything, mock.Anything).
		Return(nil, chain.ErrUnimplemented).Once()
	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, script),
	).Return(ownedAddrsResult(), nil).Once()
	m.store.On("GetUtxo", mock.Anything, db.GetUtxoQuery{
		WalletID: w.id,
		OutPoint: tx.TxIn[0].PreviousOutPoint,
	}).Return(&db.UtxoInfo{}, nil).Once()
	m.store.On("CreateTx", mock.Anything,
		matchCreateTxParams(w.id, tx, "", map[uint32]address.Address{}),
	).Return(nil).Once()
	m.store.On("GetTx", mock.Anything, db.GetTxQuery{
		WalletID: w.id,
		Txid:     tx.TxHash(),
	}).Return(&db.TxInfo{
		SerializedTx: serializeTx(t, tx),
		Status:       db.TxStatusPublished,
	}, nil).Once()
	m.chain.On("NotifyReceived", mock.Anything).Return(nil).Once()
	m.chain.On("SendRawTransaction", tx, false).
		Return(nil, chain.ErrScriptVerifyFlag).Once()
	m.store.On("DeleteUnminedTx", mock.Anything,
		matchDeleteUnminedTxParams(w.id, tx.TxHash()),
	).Return(errDummy).Once()

	// Act: Attempt publication and cleanup through the public entry point.
	err := w.Broadcast(t.Context(), tx, "")

	// Assert: Expose the retained claim, send failure and Store failure;
	// fixture cleanup verifies each required dependency interaction once.
	require.ErrorIs(t, err, ErrTxRetained)
	require.ErrorIs(t, err, chain.ErrScriptVerifyFlag)
	require.ErrorIs(t, err, errDummy)
}

// TestBroadcastPreflightFailureReportsRetention distinguishes retained claims
// from absent, confirmed and terminal history without recording a new attempt.
func TestBroadcastPreflightFailureReportsRetention(t *testing.T) {
	t.Parallel()

	// Arrange: Every row has one rejection and one lookup. Only an active
	// unconfirmed row claims inputs; a failed lookup must preserve its cause.
	testCases := []struct {
		name        string
		existing    *db.TxInfo
		lookupErr   error
		retained    bool
		readFailure bool
	}{
		{
			name: "active unconfirmed",
			existing: &db.TxInfo{
				Status: db.TxStatusPublished,
			},
			retained: true,
		},
		{
			name:      "absent",
			lookupErr: db.ErrTxNotFound,
		},
		{
			name: "confirmed published",
			existing: &db.TxInfo{
				Status: db.TxStatusPublished,
				Block: &db.Block{
					Height: 1,
				},
			},
		},
		{
			name: "terminal failed",
			existing: &db.TxInfo{
				Status: db.TxStatusFailed,
			},
		},
		{
			name:        "read failure",
			lookupErr:   errDummy,
			readFailure: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: A native rejection prevents recording. Strict
			// mocks allow only the read needed for retained-state signaling.
			w, m := createStartedWalletWithMocks(t)
			tx := &wire.MsgTx{}

			m.chain.On("TestMempoolAccept", mock.Anything, mock.Anything).
				Return(nil, chain.ErrScriptVerifyFlag).Once()
			m.store.On("GetTx", mock.Anything, db.GetTxQuery{
				WalletID: w.id,
				Txid:     tx.TxHash(),
			}).Return(tc.existing, tc.lookupErr).Once()

			// Act: Fail preflight through Broadcast before any write/send.
			err := w.Broadcast(t.Context(), tx, "")

			// Assert: Preserve the rejection, report only known active
			// claims, and retain a lookup failure without leaking not-found.
			require.ErrorIs(t, err, chain.ErrScriptVerifyFlag)
			require.Equal(t, tc.retained, errors.Is(err, ErrTxRetained))
			require.Equal(t, tc.readFailure, errors.Is(err, errDummy))
			require.NotErrorIs(t, err, db.ErrTxNotFound)
		})
	}
}

// TestBroadcastUnrelatedPublishFailsNoRemove verifies a cleanup-eligible
// rejection of an unrecorded transaction performs no Store write: there are
// no wallet claims for publication cleanup to release.
func TestBroadcastUnrelatedPublishFailsNoRemove(t *testing.T) {
	t.Parallel()

	label := testTxLabel
	w, m := createStartedWalletWithMocks(t)

	// Arrange: Neither the output nor its input belongs to the wallet, so
	// even a cleanup-eligible rejection must not issue a Store write.
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
	).Return([]*btcjson.TestMempoolAcceptResult{{Allowed: true}}, nil).Once()

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

	// A script rejection would authorize cleanup of a recorded transaction.
	m.chain.On("NotifyReceived", mock.Anything).Return(nil).Once()
	m.chain.On("SendRawTransaction",
		mock.Anything, mock.Anything,
	).Return(nil, chain.ErrScriptVerifyFlag).Once()

	// We deliberately register no DeleteUnminedTx expectation: it must
	// not be called for a never-recorded tx.

	// Act: Refuse publication after determining the transaction is unrelated.
	err = w.Broadcast(t.Context(), tx, label)

	// Assert: Preserve the rejection without a retained-claims signal.
	// The strict Store mock rejects deletion; fixture cleanup verifies calls.
	require.ErrorIs(t, err, chain.ErrScriptVerifyFlag)
	require.NotErrorIs(t, err, ErrTxRetained)
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
// guard: when the stored row for a tx hash is terminal, left by conflict
// handling or a reorg, a retry hits ErrTxAlreadyExists in CreateTx and
// Broadcast must refuse to report the record step a success and must NOT
// publish the tx. The retained row is the source of truth;
// SendRawTransaction is never reached.
func TestBroadcastRetryRetainedInvalidDoesNotPublish(t *testing.T) {
	t.Parallel()

	label := testTxLabel
	w, m := createStartedWalletWithMocks(t)

	// Arrange: An owned output makes the retained terminal row relevant,
	// so recording must reject it before native publication.
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
	).Return([]*btcjson.TestMempoolAcceptResult{{Allowed: true}}, nil).Once()

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

	// The retained row is terminal, so the record step must refuse the
	// duplicate.
	m.store.On("GetTx", mock.Anything,
		db.GetTxQuery{WalletID: w.id, Txid: txid},
	).Return(&db.TxInfo{Hash: txid, Status: db.TxStatusFailed}, nil).Once()

	// We deliberately register NO SendRawTransaction (and no NotifyReceived)
	// expectation: publishing must not happen while the only stored row is
	// failed. AssertExpectations would flag an unexpected publish call.
	// Act: Retry against terminal history through the public API.
	err = w.Broadcast(t.Context(), tx, label)

	// Assert: Preserve the terminal-state error without any chain publication.
	require.ErrorIs(t, err, ErrTxRetainedInvalid)
	require.NotErrorIs(t, err, ErrTxRetained)
}

// TestBroadcastRetryLiveDuplicateIdempotent verifies the complementary case:
// when CreateTx reports a duplicate but the stored row is still live
// (TxStatusPublished), Broadcast treats the record step as an idempotent
// success and proceeds to (re)publish the tx, leaving the live row tracked.
func TestBroadcastRetryLiveDuplicateIdempotent(t *testing.T) {
	t.Parallel()

	// Arrange: A legacy duplicate retains matching bytes and an older label;
	// reconciliation must patch that label before publication.
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
	).Return([]*btcjson.TestMempoolAcceptResult{{Allowed: true}}, nil).Once()

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
	).Return(&db.TxInfo{
		Hash:         txid,
		SerializedTx: serializeTx(t, tx),
		Status:       db.TxStatusPublished,
	}, nil).Once()

	// A non-empty label still patches the stored label on the live row.
	m.store.On("UpdateTx", mock.Anything,
		matchUpdateTxParams(w.id, txid, &label, nil),
	).Return(nil).Once()

	// Recording succeeded idempotently, so publishing proceeds as normal.
	m.chain.On("NotifyReceived", mock.Anything).Return(nil).Once()
	m.chain.On("SendRawTransaction",
		mock.Anything, mock.Anything,
	).Return(nil, nil).Once()

	// Act: Retry through Broadcast using the error-only duplicate result.
	err = w.Broadcast(t.Context(), tx, label)

	// Assert: Reconciliation permits a successful send; fixture cleanup owns
	// the single verification of required metadata and chain interactions.
	require.NoError(t, err)
}

// TestBroadcastReadbackFailureReportsRetention ensures a failed read after
// recording cannot hide that the wallet may still reserve the transaction.
func TestBroadcastReadbackFailureReportsRetention(t *testing.T) {
	t.Parallel()

	// Arrange: Recording succeeds before readback fails. Strict mocks allow
	// no notification, send or deletion after this committed write.
	w, m := createStartedWalletWithMocks(t)
	addr := mustNewStandalonePubKeyAddr(t)
	script := mustPayToAddrScript(addr)
	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: script}},
	}

	m.chain.On("TestMempoolAccept", mock.Anything, mock.Anything).
		Return(nil, chain.ErrUnimplemented).Once()
	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, script),
	).Return(ownedAddrsResult(script), nil).Once()
	m.store.On("CreateTx", mock.Anything,
		matchCreateTxParams(w.id, tx, "", map[uint32]address.Address{0: addr}),
	).Return(nil).Once()
	m.store.On("GetTx", mock.Anything, db.GetTxQuery{
		WalletID: w.id,
		Txid:     tx.TxHash(),
	}).Return(nil, errDummy).Once()

	// Act: Publish through the public API until post-record readback fails.
	err := w.Broadcast(t.Context(), tx, "")

	// Assert: Expose the active tracking risk and the original read cause;
	// fixture cleanup verifies each required mock call once.
	require.ErrorIs(t, err, ErrTxRetained)
	require.ErrorIs(t, err, errDummy)
}

// TestBroadcastWitnessMismatchDoesNotPublish protects immutable stored bytes
// when SQL reports nil success for a same-txid, changed-witness observation.
func TestBroadcastWitnessMismatchDoesNotPublish(t *testing.T) {
	t.Parallel()

	// Arrange: Witnesses differ without changing txid. Nil CreateTx models
	// SQL replay, so the retained-byte lookup must reject before sending.
	w, m := createStartedWalletWithMocks(t)
	addr := mustNewStandalonePubKeyAddr(t)
	script := mustPayToAddrScript(addr)
	tx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{Value: 10000, PkScript: script}},
	}
	stored := tx.Copy()
	stored.TxIn[0].Witness = wire.TxWitness{[]byte{1}}

	m.chain.On("TestMempoolAccept", mock.Anything, mock.Anything).
		Return(nil, chain.ErrUnimplemented).Once()
	m.store.On("ResolveOwnedAddresses", mock.Anything,
		matchResolveOwnedAddressesQuery(w.id, script),
	).Return(ownedAddrsResult(script), nil).Once()
	m.store.On("CreateTx", mock.Anything,
		matchCreateTxParams(w.id, tx, "", map[uint32]address.Address{0: addr}),
	).Return(nil).Once()
	m.store.On("GetTx", mock.Anything, db.GetTxQuery{
		WalletID: w.id,
		Txid:     tx.TxHash(),
	}).Return(&db.TxInfo{
		SerializedTx: serializeTx(t, stored),
		Status:       db.TxStatusPublished,
	}, nil).Once()

	// Act: Attempt publication with bytes the wallet would not retain.
	err := w.Broadcast(t.Context(), tx, "")

	// Assert: Refuse without sending or deleting the existing record;
	// strict mocks enforce both boundaries and the fixture verifies calls once.
	require.ErrorIs(t, err, ErrTxWitnessMismatch)
	require.ErrorIs(t, err, ErrTxRetained)
}

// TestBroadcastReorgPublishFailureRetainsSpend verifies a failed retry keeps
// disconnected published history and its claimed input out of the UTXO set.
func TestBroadcastReorgPublishFailureRetainsSpend(t *testing.T) {
	t.Parallel()

	// These mapped errors can describe policy or temporary context. Only
	// their identities vary; every row checks real persisted input claims.
	// The coinbase variant models the mapped premature-spend response, not
	// coinbase validation by the generic funding fixture below.
	tests := []struct {
		name    string
		sendErr chain.RPCErr
	}{
		{
			name:    "fee refusal",
			sendErr: chain.ErrInsufficientFee,
		},
		{
			name:    "nonmandatory script flags",
			sendErr: chain.ErrNonMandatoryScriptVerifyFlag,
		},
		{
			name:    "nonstandard witness",
			sendErr: chain.ErrBadWitnessNonStandard,
		},
		{
			name:    "standard sigop limit",
			sendErr: chain.ErrTooManySigOps,
		},
		{
			name:    "premature coinbase mapping",
			sendErr: chain.ErrCoinbaseTx,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Reuse a real SQLite wallet with a mock chain
			// that is not current so this test owns the state
			// transitions. Confirm funding below the fork, lease
			// one output, then confirm and disconnect its published
			// spender.
			client := createTestChain(t)
			w := createSQLiteWallet(t, client)
			_, input, untouched := storeFundingCredits(t, w)
			fundingBlock := db.Block{
				Hash: *chainParams.GenesisHash,
				Timestamp: chainParams.GenesisBlock.Header.
					Timestamp,
			}

			// SyncedTo creates the block row needed by funding
			// confirmation.
			err := w.store.UpdateWallet(
				t.Context(), db.UpdateWalletParams{
					WalletID: w.id,
					SyncedTo: &fundingBlock,
				},
			)
			require.NoError(t, err)
			err = w.store.UpdateTx(t.Context(), db.UpdateTxParams{
				WalletID: w.id,
				Txid:     input.Hash,
				State: &db.UpdateTxState{
					Block:  &fundingBlock,
					Status: db.TxStatusPublished,
				},
			})
			require.NoError(t, err)

			// Give confirmation a lease to remove before the
			// rollback.
			_, err = w.store.LeaseOutput(
				t.Context(), db.LeaseOutputParams{
					WalletID: w.id,
					ID:       db.LockID{1},
					OutPoint: input,
					NoExpiry: true,
				},
			)
			require.NoError(t, err)

			// Spend the leased input and leave the other output as
			// a UTXO control.
			tx := wire.NewMsgTx(wire.TxVersion)
			tx.AddTxIn(wire.NewTxIn(&input, nil, nil))
			tx.AddTxOut(wire.NewTxOut(
				19_000, []byte{txscript.OP_TRUE},
			))
			txid := tx.TxHash()
			err = w.store.CreateTx(t.Context(), db.CreateTxParams{
				WalletID: w.id,
				Tx:       tx,
				Received: time.Now(),
				Status:   db.TxStatusPublished,
			})
			require.NoError(t, err)

			spendBlock := db.Block{
				Hash:   chainhash.Hash{1},
				Height: fundingBlock.Height + 1,
				Timestamp: fundingBlock.Timestamp.Add(
					time.Second,
				),
			}

			// SyncedTo also creates the block row used to confirm
			// the spender.
			err = w.store.UpdateWallet(
				t.Context(), db.UpdateWalletParams{
					WalletID: w.id,
					SyncedTo: &spendBlock,
				},
			)
			require.NoError(t, err)

			// Confirmation deletes the lease, so after rollback
			// only the retained spend link can keep the input
			// reserved.
			err = w.store.UpdateTx(t.Context(), db.UpdateTxParams{
				WalletID: w.id,
				Txid:     txid,
				State: &db.UpdateTxState{
					Block:  &spendBlock,
					Status: db.TxStatusPublished,
				},
			})
			require.NoError(t, err)
			require.NoError(t, w.store.RollbackToBlock(
				t.Context(), spendBlock.Height,
			))

			// Pin the unmined row and input claim before retrying;
			// lease listings hide spent outputs and cannot
			// establish this precondition.
			query := db.GetTxQuery{
				WalletID: w.id,
				Txid:     txid,
			}
			before, err := w.store.GetTx(t.Context(), query)
			require.NoError(t, err)
			require.Nil(t, before.Block)
			require.Equal(t, db.TxStatusPublished, before.Status)
			_, err = w.store.GetUtxo(t.Context(), db.GetUtxoQuery{
				WalletID: w.id,
				OutPoint: input,
			})
			require.ErrorIs(t, err, db.ErrUtxoNotFound)

			// Allow preflight so only the subsequent network send
			// fails.
			client.On(
				"TestMempoolAccept", mock.Anything, float64(0),
			).
				Return([]*btcjson.TestMempoolAcceptResult{
					{
						Allowed: true,
					},
				}, nil).Once()
			client.On("NotifyReceived", mock.Anything).
				Return(nil).Once()
			client.On("SendRawTransaction", mock.Anything, false).
				Return(nil, tc.sendErr).Once()

			// Act: Retry the disconnected spend with the mapped
			// refusal. Publication-policy refusal must preserve the
			// spend regardless of which call first recorded it; the
			// retained row is the only input exclusion.
			err = w.Broadcast(t.Context(), tx, "")

			// Assert: Preserve the published row and its input
			// exclusion. The untouched funding output proves UTXO
			// reads still work.
			require.ErrorIs(t, err, tc.sendErr)
			after, readErr := w.store.GetTx(t.Context(), query)
			require.NoError(t, readErr)
			require.ErrorIs(t, err, ErrTxRetained)
			require.Nil(t, after.Block)
			require.Equal(t, db.TxStatusPublished, after.Status)
			utxos, err := w.store.ListUTXOs(
				t.Context(), db.ListUtxosQuery{
					WalletID: w.id,
				},
			)
			require.NoError(t, err)
			require.Len(t, utxos, 1)
			require.Equal(t, untouched, utxos[0].OutPoint)
		})
	}
}
