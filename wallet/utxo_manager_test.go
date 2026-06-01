// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestListUnspent tests that ListUnspent composes store UTXO, lease, and
// address reads into sorted wallet-facing results.
func TestListUnspent(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	privKeyDefault, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addrDefault, err := address.NewAddressPubKey(
		privKeyDefault.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	privKeyTest, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addrTest, err := address.NewAddressPubKey(
		privKeyTest.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	pkScriptDefault, err := txscript.PayToAddrScript(addrDefault)
	require.NoError(t, err)
	pkScriptTest, err := txscript.PayToAddrScript(addrTest)
	require.NoError(t, err)

	utxoDefault := db.UtxoInfo{
		OutPoint:    wire.OutPoint{Hash: [32]byte{1}, Index: 0},
		Amount:      200000,
		PkScript:    pkScriptDefault,
		Height:      1,
		AccountName: defaultAccountName,
		Origin:      db.DerivedAccount,
		AddrType:    db.WitnessPubKey,
	}
	utxoTest := db.UtxoInfo{
		OutPoint:    wire.OutPoint{Hash: [32]byte{2}, Index: 0},
		Amount:      100000,
		PkScript:    pkScriptTest,
		Height:      1,
		AccountName: "test",
		Origin:      db.DerivedAccount,
		AddrType:    db.NestedWitnessPubKey,
		IsLocked:    true,
	}

	query := UtxoQuery{MinConfs: 0, MaxConfs: 999999}
	minConfs := query.MinConfs
	maxConfs := query.MaxConfs

	mocks.store.On("ListUTXOs", mock.Anything, db.ListUtxosQuery{
		WalletID: w.id,
		MinConfs: &minConfs,
		MaxConfs: &maxConfs,
	}).Return([]db.UtxoInfo{utxoDefault, utxoTest}, nil).Once()

	utxos, err := w.ListUnspent(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, utxos, 2)
	require.Equal(t, addrTest.String(), utxos[0].Address.String())
	require.Equal(t, btcutil.Amount(100000), utxos[0].Amount)
	require.True(t, utxos[0].Locked)
	require.Equal(t, addrDefault.String(), utxos[1].Address.String())
	require.False(t, utxos[1].Locked)
}

// TestListUnspentFiltersByAccount tests that ListUnspent applies the
// wallet-facing account-name filter after reading store UTXO rows.
func TestListUnspentFiltersByAccount(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	privKeyDefault, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addrDefault, err := address.NewAddressPubKey(
		privKeyDefault.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	privKeyTest, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addrTest, err := address.NewAddressPubKey(
		privKeyTest.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	pkScriptDefault, err := txscript.PayToAddrScript(addrDefault)
	require.NoError(t, err)
	pkScriptTest, err := txscript.PayToAddrScript(addrTest)
	require.NoError(t, err)

	utxoDefault := db.UtxoInfo{
		OutPoint:    wire.OutPoint{Hash: [32]byte{1}, Index: 0},
		Amount:      100000,
		PkScript:    pkScriptDefault,
		Height:      1,
		AccountName: defaultAccountName,
		Origin:      db.DerivedAccount,
		AddrType:    db.WitnessPubKey,
	}
	utxoTest := db.UtxoInfo{
		OutPoint:    wire.OutPoint{Hash: [32]byte{2}, Index: 0},
		Amount:      200000,
		PkScript:    pkScriptTest,
		Height:      1,
		AccountName: "test",
		Origin:      db.DerivedAccount,
		AddrType:    db.NestedWitnessPubKey,
	}

	query := UtxoQuery{
		Account:  "test",
		MinConfs: 0,
		MaxConfs: 999999,
	}
	minConfs := query.MinConfs
	maxConfs := query.MaxConfs

	mocks.store.On("ListUTXOs", mock.Anything, db.ListUtxosQuery{
		WalletID: w.id,
		MinConfs: &minConfs,
		MaxConfs: &maxConfs,
	}).Return([]db.UtxoInfo{utxoDefault, utxoTest}, nil).Once()

	utxos, err := w.ListUnspent(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, addrTest.String(), utxos[0].Address.String())
	require.Equal(t, btcutil.Amount(200000), utxos[0].Amount)
}

// TestGetUtxo tests that the GetUtxo method can successfully retrieve a UTXO.
func TestGetUtxo(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	privKeyDefault, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addrDefault, err := address.NewAddressPubKey(
		privKeyDefault.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	pkScriptDefault, err := txscript.PayToAddrScript(addrDefault)
	require.NoError(t, err)

	utxoInfo := &db.UtxoInfo{
		OutPoint:    wire.OutPoint{Hash: [32]byte{1}, Index: 0},
		Amount:      100000,
		PkScript:    pkScriptDefault,
		Height:      1,
		AccountName: defaultAccountName,
		Origin:      db.DerivedAccount,
		AddrType:    db.WitnessPubKey,
	}

	mocks.store.On("GetUtxo", mock.Anything, db.GetUtxoQuery{
		WalletID: w.id,
		OutPoint: utxoInfo.OutPoint,
	}).Return(utxoInfo, nil).Once()

	expectedUtxo := &Utxo{
		OutPoint:      utxoInfo.OutPoint,
		Amount:        utxoInfo.Amount,
		PkScript:      utxoInfo.PkScript,
		Confirmations: 1,
		Spendable:     true,
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
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
	require.Nil(t, utxo)
}

// TestLeaseOutput tests the LeaseOutput method.
func TestLeaseOutput(t *testing.T) {
	t.Parallel()

	// Create a new test wallet with mocks.
	w, mocks := createStartedWalletWithMocks(t)

	// Create a UTXO.
	utxo := wire.OutPoint{
		Hash:  [32]byte{1},
		Index: 0,
	}

	// Mock the LockOutput method to return a fixed expiration time.
	expiration := time.Now().Add(time.Hour)
	mocks.txStore.On("LockOutput", mock.Anything, mock.Anything, utxo,
		mock.Anything).Return(expiration, nil)

	// Now, try to lease the output.
	leaseID := wtxmgr.LockID{1}
	leaseDuration := time.Hour
	actualExpiration, err := w.LeaseOutput(
		t.Context(), leaseID, utxo, leaseDuration,
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

	// Mock the ListLockedOutputs method to return the leased output.
	mocks.txStore.On("ListLockedOutputs", mock.Anything).Return(
		[]*wtxmgr.LockedOutput{leasedOutput}, nil,
	)

	// Now, try to list the leased outputs.
	leasedOutputs, err := w.ListLeasedOutputs(t.Context())
	require.NoError(t, err)
	require.Len(t, leasedOutputs, 1)
	require.Equal(t, leasedOutput, leasedOutputs[0])
}
