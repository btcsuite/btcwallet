// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestListUnspent tests the ListUnspent method with various filters.
func TestListUnspent(t *testing.T) {
	t.Parallel()

	privKeyDefault, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addrDefault, err := btcutil.NewAddressPubKey(
		privKeyDefault.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	privKeyTest, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addrTest, err := btcutil.NewAddressPubKey(
		privKeyTest.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	pkScriptDefault, err := txscript.PayToAddrScript(addrDefault)
	require.NoError(t, err)
	pkScriptTest, err := txscript.PayToAddrScript(addrTest)
	require.NoError(t, err)

	utxoDefault := db.UtxoInfo{
		OutPoint: wire.OutPoint{Hash: [32]byte{1}, Index: 0},
		Amount:   100000,
		PkScript: pkScriptDefault,
		Height:   1,
	}
	utxoTest := db.UtxoInfo{
		OutPoint: wire.OutPoint{Hash: [32]byte{2}, Index: 0},
		Amount:   200000,
		PkScript: pkScriptTest,
		Height:   0,
	}

	testCases := []struct {
		name          string
		query         UtxoQuery
		storeRows     []db.UtxoInfo
		expectedAddrs map[string]bool
	}{
		{
			name:      "no filter",
			query:     UtxoQuery{MinConfs: 0, MaxConfs: 999999},
			storeRows: []db.UtxoInfo{utxoDefault, utxoTest},
			expectedAddrs: map[string]bool{
				addrDefault.String(): true,
				addrTest.String():    true,
			},
		},
		{
			name: "filter by default account",
			query: UtxoQuery{
				Account:  defaultAccountName,
				MinConfs: 0,
				MaxConfs: 999999,
			},
			storeRows: []db.UtxoInfo{utxoDefault, utxoTest},
			expectedAddrs: map[string]bool{
				addrDefault.String(): true,
			},
		},
		{
			name: "filter by test account",
			query: UtxoQuery{
				Account:  "test",
				MinConfs: 0,
				MaxConfs: 999999,
			},
			storeRows: []db.UtxoInfo{utxoDefault, utxoTest},
			expectedAddrs: map[string]bool{
				addrTest.String(): true,
			},
		},
		{
			name:      "filter by min confs",
			query:     UtxoQuery{MinConfs: 2, MaxConfs: 999999},
			storeRows: []db.UtxoInfo{utxoTest},
			expectedAddrs: map[string]bool{
				addrTest.String(): true,
			},
		},
		{
			name:      "filter by max confs",
			query:     UtxoQuery{MinConfs: 0, MaxConfs: 1},
			storeRows: []db.UtxoInfo{utxoDefault},
			expectedAddrs: map[string]bool{
				addrDefault.String(): true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, mocks := createStartedWalletWithMocks(t)

			minConfs := tc.query.MinConfs
			maxConfs := tc.query.MaxConfs

			mocks.store.On("ListUTXOs", mock.Anything, db.ListUtxosQuery{
				WalletID: w.id,
				MinConfs: &minConfs,
				MaxConfs: &maxConfs,
				Account:  nil,
			}).Return(tc.storeRows, nil).Once()
			mocks.store.On("ListLeasedOutputs", mock.Anything, w.id).Return(
				[]db.LeasedOutput{}, nil,
			).Once()

			for i := range tc.storeRows {
				row := tc.storeRows[i]

				switch {
				case string(row.PkScript) == string(pkScriptDefault):
					mocks.store.On(
						"GetAddress", mock.Anything,
						db.GetAddressQuery{
							WalletID:     w.id,
							ScriptPubKey: pkScriptDefault,
						},
					).Return(&db.AddressInfo{
						AccountName: defaultAccountName,
						AddrType:    db.WitnessPubKey,
						IsWatchOnly: true,
					}, nil).Once()

				case string(row.PkScript) == string(pkScriptTest):
					mocks.store.On(
						"GetAddress", mock.Anything,
						db.GetAddressQuery{
							WalletID:     w.id,
							ScriptPubKey: pkScriptTest,
						},
					).Return(&db.AddressInfo{
						AccountName: "test",
						AddrType:    db.NestedWitnessPubKey,
						IsWatchOnly: true,
					}, nil).Once()
				}
			}

			utxos, err := w.ListUnspent(t.Context(), tc.query)
			require.NoError(t, err)

			returnedAddrs := make(map[string]bool)
			for _, utxo := range utxos {
				returnedAddrs[utxo.Address.String()] = true
			}

			require.Equal(t, tc.expectedAddrs, returnedAddrs)

			for i := range len(utxos) - 1 {
				require.LessOrEqual(
					t, utxos[i].Amount, utxos[i+1].Amount,
				)
			}
		})
	}
}

// TestGetUtxo tests that the GetUtxo method can successfully retrieve a UTXO.
func TestGetUtxo(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	privKeyDefault, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addrDefault, err := btcutil.NewAddressPubKey(
		privKeyDefault.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	pkScriptDefault, err := txscript.PayToAddrScript(addrDefault)
	require.NoError(t, err)

	utxoInfo := &db.UtxoInfo{
		OutPoint: wire.OutPoint{Hash: [32]byte{1}, Index: 0},
		Amount:   100000,
		PkScript: pkScriptDefault,
		Height:   1,
	}

	mocks.store.On("GetUtxo", mock.Anything, db.GetUtxoQuery{
		WalletID: w.id,
		OutPoint: utxoInfo.OutPoint,
	}).Return(utxoInfo, nil).Once()
	mocks.store.On("ListLeasedOutputs", mock.Anything, w.id).Return(
		[]db.LeasedOutput{}, nil,
	).Once()
	mocks.store.On(
		"GetAddress", mock.Anything,
		db.GetAddressQuery{
			WalletID:     w.id,
			ScriptPubKey: pkScriptDefault,
		},
	).Return(&db.AddressInfo{
		AccountName: defaultAccountName,
		AddrType:    db.WitnessPubKey,
		IsWatchOnly: true,
	}, nil).Once()

	expectedUtxo := &Utxo{
		OutPoint:      utxoInfo.OutPoint,
		Amount:        utxoInfo.Amount,
		PkScript:      utxoInfo.PkScript,
		Confirmations: 1,
		Spendable:     false,
		Address:       addrDefault,
		Account:       defaultAccountName,
		AddressType:   waddrmgr.WitnessPubKey,
		Locked:        false,
	}

	utxo, err := w.GetUtxo(t.Context(), utxoInfo.OutPoint)
	require.NoError(t, err)
	require.Equal(t, expectedUtxo, utxo)
}

// TestGetUtxoErr tests the error conditions of the GetUtxo method.
func TestGetUtxoErr(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	utxoNotFound := wire.OutPoint{Hash: [32]byte{2}, Index: 0}
	mocks.store.On("GetUtxo", mock.Anything, db.GetUtxoQuery{
		WalletID: w.id,
		OutPoint: utxoNotFound,
	}).Return((*db.UtxoInfo)(nil), db.ErrUtxoNotFound).Once()

	utxo, err := w.GetUtxo(t.Context(), utxoNotFound)
	require.ErrorIs(t, err, wtxmgr.ErrUtxoNotFound)
	require.Nil(t, utxo)
}

// TestLeaseOutput tests the LeaseOutput method.
func TestLeaseOutput(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	outPoint := wire.OutPoint{Hash: [32]byte{1}, Index: 0}
	expiration := time.Now().Add(time.Hour).UTC()

	mocks.store.On("LeaseOutput", mock.Anything, db.LeaseOutputParams{
		WalletID: w.id,
		ID:       db.LockID{1},
		OutPoint: outPoint,
		Duration: time.Hour,
	}).Return(&db.LeasedOutput{
		OutPoint:   outPoint,
		LockID:     db.LockID{1},
		Expiration: expiration,
	}, nil).Once()

	actualExpiration, err := w.LeaseOutput(
		t.Context(), wtxmgr.LockID{1}, outPoint, time.Hour,
	)
	require.NoError(t, err)
	require.Equal(t, expiration, actualExpiration)
}

// TestReleaseOutput tests the ReleaseOutput method.
func TestReleaseOutput(t *testing.T) {
	t.Parallel()

	// Create a new test wallet with mocks.
	w, mocks := createStartedWalletWithID(t, 7)

	// Create a UTXO.
	utxo := wire.OutPoint{
		Hash:  [32]byte{1},
		Index: 0,
	}

	// Mock the UTXOStore ReleaseOutput method to return nil.
	mocks.store.On("ReleaseOutput", mock.Anything, db.ReleaseOutputParams{
		WalletID: 7,
		ID:       [32]byte{1},
		OutPoint: utxo,
	}).Return(nil)

	// Now, try to release the output.
	leaseID := wtxmgr.LockID{1}
	err := w.ReleaseOutput(t.Context(), leaseID, utxo)
	require.NoError(t, err)
}

// TestListLeasedOutputs tests the ListLeasedOutputs method.
func TestListLeasedOutputs(t *testing.T) {
	t.Parallel()

	// Create a new test wallet with mocks.
	w, mocks := createStartedWalletWithMocks(t)

	// Create a leased output.
	leasedOutput := &wtxmgr.LockedOutput{
		Outpoint: wire.OutPoint{
			Hash:  [32]byte{1},
			Index: 0,
		},
		LockID:     wtxmgr.LockID{1},
		Expiration: time.Now().Add(time.Hour),
	}

	mocks.store.On("ListLeasedOutputs", mock.Anything, w.id).Return(
		[]db.LeasedOutput{{
			OutPoint:   wire.OutPoint{Hash: [32]byte{1}, Index: 0},
			LockID:     db.LockID{1},
			Expiration: leasedOutput.Expiration,
		}}, nil,
	)

	leasedOutputs, err := w.ListLeasedOutputs(t.Context())
	require.NoError(t, err)
	require.Equal(t, []*LeasedOutput{{
		OutPoint:   wire.OutPoint{Hash: [32]byte{1}, Index: 0},
		LockID:     wtxmgr.LockID{1},
		Expiration: leasedOutput.Expiration,
	}}, leasedOutputs)
}
