package itest

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

type managerStoreHarness struct {
	conn              *sql.DB
	postgres          bool
	newStore          func(int64) db.Store
	newLifecycleStore func(string) db.LifecycleStore
}

// testManagerStore runs the shared manager-store conformance cases against one
// SQL backend.
func testManagerStore(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	t.Run("manager transaction", func(t *testing.T) {
		testManagerTransaction(t, harness)
	})
	t.Run("wallet lifecycle", func(t *testing.T) {
		testWalletLifecycle(t, harness)
	})
	t.Run("account zero sentinel", func(t *testing.T) {
		testAccountZeroSentinel(t, harness)
	})
	t.Run("address manager persistence", func(t *testing.T) {
		testAddressManagerPersistence(t, harness)
	})
	t.Run("rollback", func(t *testing.T) {
		testRollback(t, harness)
	})
	t.Run("rollback transaction", func(t *testing.T) {
		testRollbackTransaction(t, harness)
	})
	t.Run("wallet block isolation", func(t *testing.T) {
		testWalletBlockIsolation(t, harness)
	})
	t.Run("duplicate incidence", func(t *testing.T) {
		testDuplicateIncidence(t, harness)
	})
	t.Run("birthday verification", func(t *testing.T) {
		testBirthdayVerification(t, harness)
	})
	t.Run("wtxmgr compatibility", func(t *testing.T) {
		testWtxmgrCompatibility(t, harness)
	})
}

// testWalletLifecycle verifies name binding and single-attempt wallet creation
// against one SQL backend.
//
//nolint:noinlineerr // Each setup write retains operation-local context.
func testWalletLifecycle(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := t.Context()
	store := harness.newLifecycleStore("store-lifecycle")
	exists, err := store.WalletExists(ctx)
	require.NoError(t, err)
	require.False(t, exists)

	managerState := waddrmgr.ManagerState{
		Version:               9,
		CreatedAt:             time.Unix(7_001, 0),
		WatchOnly:             true,
		MasterPubParams:       []byte{1},
		EncryptedCryptoPubKey: []byte{2},
	}
	genesis := testBlock(0)
	syncState := waddrmgr.SyncState{
		StartBlock: genesis,
		SyncedTo:   genesis,
		Birthday:   time.Unix(7_002, 0),
	}
	msgTx := wire.NewMsgTx(2)
	msgTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash:  testHash(70),
		Index: 1,
	}})
	msgTx.AddTxOut(&wire.TxOut{Value: 70_000, PkScript: []byte{0x51}})
	record, err := wtxmgr.NewTxRecordFromMsgTx(msgTx, time.Unix(7_003, 0))
	require.NoError(t, err)

	var bodyCalls, resetCalls int
	err = store.Create(ctx, func(tx db.ReadWriteTx) error {
		bodyCalls++
		if err := tx.Addr().PutManagerState(managerState); err != nil {
			return err
		}

		if err := tx.Addr().PutSyncState(syncState); err != nil {
			return err
		}

		return tx.Tx().InsertTx(record, nil)
	}, func() {
		resetCalls++
	})
	require.NoError(t, err)
	require.Equal(t, 1, bodyCalls)
	require.Equal(t, 1, resetCalls)

	exists, err = store.WalletExists(ctx)
	require.NoError(t, err)
	require.True(t, exists)

	resolvedStore := harness.newLifecycleStore("store-lifecycle")
	exists, err = resolvedStore.WalletExists(ctx)
	require.NoError(t, err)
	require.True(t, exists)
	err = resolvedStore.View(ctx, func(tx db.ReadTx) error {
		gotManager, err := tx.Addr().ManagerState()
		require.NoError(t, err)
		require.Equal(t, managerState, gotManager)

		gotSync, err := tx.Addr().SyncState()
		require.NoError(t, err)
		require.Equal(t, syncState, gotSync)
		details, err := tx.Tx().TxDetails(&record.Hash)
		require.NoError(t, err)
		require.Equal(t, record.Hash, details.Hash)

		return nil
	}, nil)
	require.NoError(t, err)

	err = harness.newLifecycleStore("store-lifecycle").Create(
		ctx, func(db.ReadWriteTx) error {
			return nil
		}, nil,
	)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrAlreadyExists))
}

// testAccountZeroSentinel verifies SQL NULL round trips as the legacy
// unallocated-account sentinel so the first imported account remains zero.
func testAccountZeroSentinel(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	walletID := harness.createWallet(
		t, "account-zero-sentinel", testBlock(10), testBlock(10),
	)
	store := harness.newStore(walletID)
	scope := waddrmgr.KeyScope{Purpose: 1_017, Coin: 1}
	want := waddrmgr.KeyScopeState{
		Scope:       scope,
		AddrSchema:  waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084],
		LastAccount: waddrmgr.NoAccount,
	}

	err := store.Update(t.Context(), func(tx db.ReadWriteTx) error {
		return tx.Addr().PutKeyScope(want)
	}, nil)
	require.NoError(t, err)

	err = store.View(t.Context(), func(tx db.ReadTx) error {
		got, err := tx.Addr().KeyScope(scope)
		require.NoError(t, err)
		require.Equal(t, want, got)

		return nil
	}, nil)
	require.NoError(t, err)
}

// testWtxmgrCompatibility verifies the complete wtxmgr surface against one SQL
// backend.
//
//nolint:maintidx // One vector covers the full manager surface.
func testWtxmgrCompatibility(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(600)
	synced := testBlock(601)
	walletID := harness.createWallet(t, "wtxmgr-compatibility", start, synced)
	store := harness.newStore(walletID)

	fundingTx := wire.NewMsgTx(2)
	fundingTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash:  testHash(60),
		Index: 1,
	}})
	fundingTx.AddTxOut(&wire.TxOut{Value: 50_000, PkScript: []byte{0x51}})
	funding, err := wtxmgr.NewTxRecordFromMsgTx(
		fundingTx, time.Unix(3_000, 0),
	)
	require.NoError(t, err)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		exists, err := tx.Tx().InsertTxCheckIfExists(funding, nil)
		require.NoError(t, err)
		require.False(t, exists)

		exists, err = tx.Tx().InsertTxCheckIfExists(funding, nil)
		require.NoError(t, err)
		require.True(t, exists)

		isNew, err := tx.Tx().AddCredit(funding, nil, 0, false)
		if err != nil {
			return err
		}
		require.True(t, isNew)

		isNew, err = tx.Tx().AddCredit(funding, nil, 0, false)
		require.NoError(t, err)
		require.False(t, isNew)

		return tx.Tx().PutTxLabel(funding.Hash, "funding")
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		details, err := tx.Tx().TxDetails(&funding.Hash)
		require.NoError(t, err)
		require.Equal(t, int32(-1), details.Block.Height)
		require.Equal(t, "funding", details.Label)
		require.Equal(t, []wtxmgr.CreditRecord{{
			Amount: 50_000,
			Index:  0,
		}}, details.Credits)

		hashes, err := tx.Tx().UnminedTxHashes()
		require.NoError(t, err)
		require.Len(t, hashes, 1)
		require.Equal(t, funding.Hash, *hashes[0])

		transactions, err := tx.Tx().UnminedTxs()
		require.NoError(t, err)
		require.Len(t, transactions, 1)
		require.Equal(t, funding.Hash, transactions[0].TxHash())

		outputs, err := tx.Tx().UnspentOutputs()
		require.NoError(t, err)
		require.Len(t, outputs, 1)
		require.Equal(t, int32(-1), outputs[0].Height)

		balance, err := tx.Tx().Balance(0, synced.Height)
		require.NoError(t, err)
		require.Equal(t, int64(50_000), int64(balance))

		return nil
	}, func() {})
	require.NoError(t, err)

	lockID := wtxmgr.LockID{1, 2, 3}
	output := wire.OutPoint{Hash: funding.Hash, Index: 0}
	var lockExpiry time.Time
	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		var err error
		lockExpiry, err = tx.Tx().LockOutput(lockID, output, time.Hour)
		return err
	}, func() {})
	require.NoError(t, err)
	require.WithinDuration(
		t, time.Now().Add(time.Hour), lockExpiry, time.Second,
	)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		_, err := tx.Tx().LockOutput(
			wtxmgr.LockID{9}, output, time.Hour,
		)

		return err
	}, func() {})
	require.ErrorIs(t, err, wtxmgr.ErrOutputAlreadyLocked)

	err = store.View(ctx, func(tx db.ReadTx) error {
		locked, err := tx.Tx().ListLockedOutputs()
		require.NoError(t, err)
		require.Len(t, locked, 1)
		require.Equal(t, output, locked[0].Outpoint)
		require.True(t, lockExpiry.Equal(locked[0].Expiration))

		unspent, err := tx.Tx().UnspentOutputs()
		require.NoError(t, err)
		require.Empty(t, unspent)

		watch, err := tx.Tx().OutputsToWatch()
		require.NoError(t, err)
		require.Len(t, watch, 1)

		return nil
	}, func() {})
	require.NoError(t, err)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().UnlockOutput(wtxmgr.LockID{9}, output)
	}, func() {})
	require.ErrorIs(t, err, wtxmgr.ErrOutputUnlockNotAllowed)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().UnlockOutput(lockID, output)
	}, func() {})
	require.NoError(t, err)

	spenderTx := wire.NewMsgTx(2)
	spenderTx.AddTxIn(&wire.TxIn{PreviousOutPoint: output})
	spenderTx.AddTxOut(&wire.TxOut{Value: 49_000, PkScript: []byte{0x51}})
	spender, err := wtxmgr.NewTxRecordFromMsgTx(
		spenderTx, time.Unix(3_001, 0),
	)
	require.NoError(t, err)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		err := tx.Tx().InsertTx(spender, nil)
		if err != nil {
			return err
		}

		scripts, err := tx.Tx().PreviousPkScripts(spender, nil)
		require.NoError(t, err)
		require.Equal(t, [][]byte{{0x51}}, scripts)

		return nil
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		outputs, err := tx.Tx().UnspentOutputs()
		require.NoError(t, err)
		require.Empty(t, outputs)

		details, err := tx.Tx().TxDetails(&funding.Hash)
		require.NoError(t, err)
		require.True(t, details.Credits[0].Spent)

		spenderDetails, err := tx.Tx().TxDetails(&spender.Hash)
		require.NoError(t, err)
		require.Equal(t, []wtxmgr.DebitRecord{{
			Amount: 50_000,
			Index:  0,
		}}, spenderDetails.Debits)

		return nil
	}, func() {})
	require.NoError(t, err)

	childTx := wire.NewMsgTx(2)
	childTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash:  spender.Hash,
		Index: 0,
	}})
	childTx.AddTxOut(&wire.TxOut{Value: 48_000, PkScript: []byte{0x51}})
	child, err := wtxmgr.NewTxRecordFromMsgTx(
		childTx, time.Unix(3_002, 0),
	)
	require.NoError(t, err)
	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().InsertTx(child, nil)
	}, func() {})
	require.NoError(t, err)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().RemoveUnminedTx(spender)
	}, func() {})
	require.NoError(t, err)
	err = store.View(ctx, func(tx db.ReadTx) error {
		details, err := tx.Tx().TxDetails(&spender.Hash)
		require.NoError(t, err)
		require.Nil(t, details)

		details, err = tx.Tx().TxDetails(&child.Hash)
		require.NoError(t, err)
		require.Nil(t, details)

		return nil
	}, nil)
	require.NoError(t, err)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().InsertTx(funding, &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				Hash:   synced.Hash,
				Height: synced.Height,
			},
			Time: synced.Timestamp,
		})
	}, func() {})
	require.NoError(t, err)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().PutTxLabel(funding.Hash, "funding updated")
	}, nil)
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		details, err := tx.Tx().UniqueTxDetails(
			&funding.Hash, &wtxmgr.Block{
				Hash:   synced.Hash,
				Height: synced.Height,
			},
		)
		require.NoError(t, err)
		require.Equal(t, synced.Height, details.Block.Height)
		require.Equal(t, "funding updated", details.Label)

		var visited []wtxmgr.TxDetails

		err = tx.Tx().RangeTransactions(
			synced.Height, synced.Height,
			func(details []wtxmgr.TxDetails) (bool, error) {
				visited = append(visited, details...)
				return false, nil
			},
		)
		require.NoError(t, err)
		require.Len(t, visited, 1)
		require.Equal(t, funding.Hash, visited[0].Hash)

		return nil
	}, func() {})
	require.NoError(t, err)

	independentTx := wire.NewMsgTx(2)
	independentTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash:  testHash(61),
		Index: 1,
	}})
	independentTx.AddTxOut(&wire.TxOut{
		Value: 1_000, PkScript: []byte{0x51},
	})
	independent, err := wtxmgr.NewTxRecordFromMsgTx(
		independentTx, time.Unix(3_003, 0),
	)
	require.NoError(t, err)
	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().InsertTx(independent, nil)
	}, nil)
	require.NoError(t, err)

	assertRange := func(begin, end int32, wantHeights []int32) {
		t.Helper()

		var heights []int32
		err := store.View(ctx, func(tx db.ReadTx) error {
			return tx.Tx().RangeTransactions(
				begin, end,
				func(details []wtxmgr.TxDetails) (bool, error) {
					heights = append(heights, details[0].Block.Height)
					return false, nil
				},
			)
		}, func() {
			heights = nil
		})
		require.NoError(t, err)
		require.Equal(t, wantHeights, heights)
	}
	assertRange(0, -1, []int32{synced.Height, -1})
	assertRange(-1, 0, []int32{-1, synced.Height})

	conflictATx := wire.NewMsgTx(2)
	conflictATx.AddTxIn(&wire.TxIn{PreviousOutPoint: output})
	conflictATx.AddTxOut(&wire.TxOut{
		Value: 49_000, PkScript: []byte{0x51},
	})
	conflictA, err := wtxmgr.NewTxRecordFromMsgTx(
		conflictATx, time.Unix(3_004, 0),
	)
	require.NoError(t, err)

	conflictBTx := wire.NewMsgTx(2)
	conflictBTx.AddTxIn(&wire.TxIn{PreviousOutPoint: output})
	conflictBTx.AddTxOut(&wire.TxOut{
		Value: 48_000, PkScript: []byte{0x51},
	})
	conflictB, err := wtxmgr.NewTxRecordFromMsgTx(
		conflictBTx, time.Unix(3_005, 0),
	)
	require.NoError(t, err)

	conflictChildTx := wire.NewMsgTx(2)
	conflictChildTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: conflictB.Hash,
	}})
	conflictChildTx.AddTxOut(&wire.TxOut{
		Value: 47_000, PkScript: []byte{0x51},
	})
	conflictChild, err := wtxmgr.NewTxRecordFromMsgTx(
		conflictChildTx, time.Unix(3_006, 0),
	)
	require.NoError(t, err)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		for _, record := range []*wtxmgr.TxRecord{
			conflictA, conflictB, conflictChild,
		} {
			if err := tx.Tx().InsertTx(record, nil); err != nil {
				return err
			}
		}

		return nil
	}, nil)
	require.NoError(t, err)

	conflictBlock := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   testHash(62),
			Height: synced.Height + 1,
		},
		Time: time.Unix(3_007, 0),
	}
	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().InsertTx(conflictA, &conflictBlock)
	}, nil)
	require.NoError(t, err)
	err = store.View(ctx, func(tx db.ReadTx) error {
		details, err := tx.Tx().TxDetails(&conflictA.Hash)
		require.NoError(t, err)
		require.Equal(t, conflictBlock.Height, details.Block.Height)
		require.Equal(t, []wtxmgr.DebitRecord{{
			Amount: 50_000,
			Index:  0,
		}}, details.Debits)

		details, err = tx.Tx().TxDetails(&conflictB.Hash)
		require.NoError(t, err)
		require.Nil(t, details)
		details, err = tx.Tx().TxDetails(&conflictChild.Hash)
		require.NoError(t, err)
		require.Nil(t, details)

		fundingDetails, err := tx.Tx().TxDetails(&funding.Hash)
		require.NoError(t, err)
		require.True(t, fundingDetails.Credits[0].Spent)
		require.Equal(t, "funding updated", fundingDetails.Label)

		return nil
	}, nil)
	require.NoError(t, err)
}

// testAddressManagerPersistence verifies the complete waddrmgr persistence
// surface against one SQL backend.
//
//nolint:maintidx // One vector covers the complete store surface.
func testAddressManagerPersistence(t *testing.T,
	harness *managerStoreHarness) {

	t.Helper()

	ctx := t.Context()
	start := testBlock(600)
	synced := testBlock(601)
	walletID := harness.createWallet(
		t, "address-manager-persistence", start, synced,
	)
	store := harness.newStore(walletID)

	managerState := waddrmgr.ManagerState{
		Version:                  9,
		CreatedAt:                time.Unix(6_001, 0),
		MasterPubParams:          []byte{1},
		MasterPrivParams:         []byte{2},
		EncryptedCryptoPubKey:    []byte{3},
		EncryptedCryptoPrivKey:   []byte{4},
		EncryptedCryptoScriptKey: []byte{5},
		EncryptedMasterHDPubKey:  []byte{6},
		EncryptedMasterHDPrivKey: []byte{7},
	}
	birthdayBlock := testBlock(602)
	syncState := waddrmgr.SyncState{
		StartBlock:            start,
		SyncedTo:              synced,
		Birthday:              time.Unix(6_002, 0),
		BirthdayBlock:         &birthdayBlock,
		BirthdayBlockVerified: true,
	}
	scope := waddrmgr.KeyScopeBIP0084
	scopeState := waddrmgr.KeyScopeState{
		Scope:                scope,
		AddrSchema:           waddrmgr.ScopeAddrMap[scope],
		EncryptedCoinPubKey:  []byte{8},
		EncryptedCoinPrivKey: []byte{9},
		LastAccount:          4,
	}
	defaultAccount := waddrmgr.AccountState{
		Scope:             scope,
		Account:           1,
		Type:              waddrmgr.AccountDefault,
		Name:              "default",
		EncryptedPubKey:   []byte{10},
		EncryptedPrivKey:  []byte{11},
		NextExternalIndex: 2,
		NextInternalIndex: 3,
	}
	watchSchema := waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0086]
	watchOnlyAccount := waddrmgr.AccountState{
		Scope:                scope,
		Account:              2,
		Type:                 waddrmgr.AccountWatchOnly,
		Name:                 "watch-only",
		EncryptedPubKey:      []byte{12},
		MasterKeyFingerprint: 13,
		NextExternalIndex:    4,
		NextInternalIndex:    5,
		AddrSchema:           &watchSchema,
	}
	branch, index := uint32(0), uint32(7)
	chainAddressID := []byte("chain-address")
	chainAddress := waddrmgr.AddressState{
		Scope:      scope,
		Account:    defaultAccount.Account,
		Type:       waddrmgr.AddressChain,
		AddedAt:    time.Unix(6_003, 0),
		SyncStatus: waddrmgr.AddressSyncFull,
		Branch:     &branch,
		Index:      &index,
	}
	witnessVersion, secret := uint8(0), true
	witnessAddressID := []byte("witness-address")
	witnessAddress := waddrmgr.AddressState{
		Scope:           scope,
		Account:         watchOnlyAccount.Account,
		Type:            waddrmgr.AddressWitnessScript,
		AddedAt:         time.Unix(6_004, 0),
		SyncStatus:      waddrmgr.AddressSyncPartial,
		EncryptedHash:   []byte{14},
		EncryptedScript: []byte{15},
		WitnessVersion:  &witnessVersion,
		IsSecretScript:  &secret,
		Used:            true,
	}
	taprootVersion := uint8(1)
	taprootAddressID := []byte("taproot-address")
	taprootAddress := waddrmgr.AddressState{
		Scope:           scope,
		Account:         watchOnlyAccount.Account,
		Type:            waddrmgr.AddressTaprootScript,
		AddedAt:         time.Unix(6_005, 0),
		SyncStatus:      waddrmgr.AddressSyncNone,
		EncryptedHash:   []byte{16},
		EncryptedScript: []byte{17},
		WitnessVersion:  &taprootVersion,
		IsSecretScript:  &secret,
	}

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		operations := []func() error{
			func() error { return addr.PutManagerState(managerState) },
			func() error { return addr.PutSyncState(syncState) },
			func() error { return addr.PutKeyScope(scopeState) },
			func() error { return addr.PutAccount(defaultAccount) },
			func() error { return addr.PutAccount(watchOnlyAccount) },
			func() error {
				return addr.PutAddress(chainAddressID, chainAddress)
			},
			func() error {
				return addr.PutAddress(witnessAddressID, witnessAddress)
			},
			func() error {
				return addr.PutAddress(taprootAddressID, taprootAddress)
			},
		}
		for _, operation := range operations {
			err := operation()
			if err != nil {
				return err
			}
		}

		return nil
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		addr := tx.Addr()
		gotManager, err := addr.ManagerState()
		require.NoError(t, err)
		require.Equal(t, managerState, gotManager)

		gotSync, err := addr.SyncState()
		require.NoError(t, err)
		require.Equal(t, syncState, gotSync)

		gotScope, err := addr.KeyScope(scope)
		require.NoError(t, err)
		require.Equal(t, scopeState, gotScope)

		scopes, err := addr.KeyScopes()
		require.NoError(t, err)
		require.Equal(t, []waddrmgr.KeyScopeState{scopeState}, scopes)

		gotDefault, err := addr.Account(scope, defaultAccount.Account)
		require.NoError(t, err)
		require.Equal(t, defaultAccount, gotDefault)

		gotWatchOnly, err := addr.AccountByName(
			scope, watchOnlyAccount.Name,
		)
		require.NoError(t, err)
		require.Equal(t, watchOnlyAccount, gotWatchOnly)

		accounts, err := addr.Accounts(scope)
		require.NoError(t, err)
		require.Equal(
			t, []waddrmgr.AccountState{defaultAccount, watchOnlyAccount},
			accounts,
		)

		gotChain, err := addr.Address(scope, chainAddressID)
		require.NoError(t, err)

		chainAddress.Hash = gotChain.Hash
		require.Equal(t, chainAddress, gotChain)

		gotWitness, err := addr.Address(scope, witnessAddressID)
		require.NoError(t, err)

		witnessAddress.Hash = gotWitness.Hash
		require.Equal(t, witnessAddress, gotWitness)

		gotTaproot, err := addr.Address(scope, taprootAddressID)
		require.NoError(t, err)

		taprootAddress.Hash = gotTaproot.Hash
		require.Equal(t, taprootAddress, gotTaproot)

		accountAddresses, err := addr.AccountAddresses(
			scope, defaultAccount.Account,
		)
		require.NoError(t, err)
		require.Equal(
			t, []waddrmgr.AddressState{chainAddress}, accountAddresses,
		)

		activeAddresses, err := addr.ActiveAddresses(scope)
		require.NoError(t, err)
		require.ElementsMatch(
			t, []waddrmgr.AddressState{
				chainAddress, witnessAddress, taprootAddress,
			}, activeAddresses,
		)

		_, err = addr.KeyScope(waddrmgr.KeyScope{Purpose: 999, Coin: 1})
		require.True(t, waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound))
		_, err = addr.Account(scope, 999)
		require.True(t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound))
		_, err = addr.Address(scope, []byte("missing-address"))
		require.True(t, waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound))

		return nil
	}, func() {})
	require.NoError(t, err)

	renamed := "renamed"
	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		err := addr.SetCoinTypeKeys(
			scope, []byte{16}, []byte{17},
		)
		if err != nil {
			return err
		}

		err = addr.SetLastAccount(scope, 8)
		if err != nil {
			return err
		}

		err = addr.RenameAccount(
			scope, defaultAccount.Account, renamed,
		)
		if err != nil {
			return err
		}

		err = addr.SetAccountIndexes(
			scope, defaultAccount.Account, 9, 10,
		)
		if err != nil {
			return err
		}

		err = addr.MarkAddressUsed(scope, chainAddressID)
		if err != nil {
			return err
		}

		err = addr.SetBirthdayBlock(nil)
		if err != nil {
			return err
		}

		return addr.DeletePrivateKeys()
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		addr := tx.Addr()
		gotManager, err := addr.ManagerState()
		require.NoError(t, err)
		require.False(t, gotManager.WatchOnly)
		require.Nil(t, gotManager.MasterPrivParams)
		require.Nil(t, gotManager.EncryptedCryptoPrivKey)
		require.Nil(t, gotManager.EncryptedMasterHDPrivKey)

		gotSync, err := addr.SyncState()
		require.NoError(t, err)
		require.Nil(t, gotSync.BirthdayBlock)
		require.True(t, gotSync.BirthdayBlockVerified)

		gotScope, err := addr.KeyScope(scope)
		require.NoError(t, err)
		require.Equal(t, []byte{16}, gotScope.EncryptedCoinPubKey)
		require.Nil(t, gotScope.EncryptedCoinPrivKey)
		require.Equal(t, uint32(8), gotScope.LastAccount)

		gotAccount, err := addr.AccountByName(scope, renamed)
		require.NoError(t, err)
		require.Nil(t, gotAccount.EncryptedPrivKey)
		require.Equal(t, uint32(9), gotAccount.NextExternalIndex)
		require.Equal(t, uint32(10), gotAccount.NextInternalIndex)

		gotChain, err := addr.Address(scope, chainAddressID)
		require.NoError(t, err)
		require.True(t, gotChain.Used)

		gotWitness, err := addr.Address(scope, witnessAddressID)
		require.NoError(t, err)
		require.Nil(t, gotWitness.EncryptedScript)

		gotTaproot, err := addr.Address(scope, taprootAddressID)
		require.NoError(t, err)
		require.Nil(t, gotTaproot.EncryptedScript)

		return nil
	}, func() {})
	require.NoError(t, err)
}

// testManagerTransaction verifies transaction ownership, reset behavior, and
// address-manager updates.
func testManagerTransaction(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(100)
	synced := testBlock(101)
	walletID := harness.createWallet(t, "manager-transaction", start, synced)
	store := harness.newStore(walletID)

	var resetCount int

	err := store.View(ctx, func(tx db.ReadTx) error {
		hash, err := tx.Addr().BlockHash(start.Height)
		require.NoError(t, err)
		require.Equal(t, start.Hash, *hash)

		return nil
	}, func() {
		resetCount++
	})
	require.NoError(t, err)
	require.Equal(t, 1, resetCount)

	missingHeight := int32(99)
	err = store.View(ctx, func(tx db.ReadTx) error {
		_, err := tx.Addr().BlockHash(missingHeight)
		require.True(t, waddrmgr.IsError(err, waddrmgr.ErrBlockNotFound))

		return nil
	}, func() {})
	require.NoError(t, err)

	replacement := testBlock(101)
	replacement.Hash = testHash(201)
	replacement.Timestamp = time.Unix(2201, 0)
	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().SetSyncedTo(&replacement)
	}, func() {})
	require.NoError(t, err)

	require.Equal(t, replacement.Height, harness.syncedHeight(t, walletID))
	require.Equal(
		t, replacement.Hash,
		harness.blockHash(t, walletID, replacement.Height),
	)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().SetSyncedTo(nil)
	}, func() {})
	require.NoError(t, err)
	require.Equal(t, start.Height, harness.syncedHeight(t, walletID))

	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	var bodyCalled bool

	err = store.Update(canceledCtx, func(db.ReadWriteTx) error {
		bodyCalled = true

		return nil
	}, func() {})
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, bodyCalled)
}

// testRollback verifies the base rollback behavior for mined transactions.
func testRollback(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	walletID := harness.createWallet(
		t, "rollback", testBlock(200), testBlock(201),
	)
	store := harness.newStore(walletID)

	fundingHash := testHash(21)
	fundingID := harness.insertTransaction(
		t, walletID, fundingHash, 200, 0, false,
	)
	fundingCreditID := harness.insertCredit(t, walletID, fundingID)
	harness.setActiveCredit(t, walletID, fundingCreditID)

	spenderHash := testHash(22)
	spenderID := harness.insertTransaction(
		t, walletID, spenderHash, 201, 0, false,
	)
	harness.insertInput(t, spenderID, 0, fundingHash, 0)
	harness.insertCreditSpend(t, walletID, fundingCreditID, spenderID, 0)

	coinbaseHash := testHash(23)
	coinbaseID := harness.insertTransaction(
		t, walletID, coinbaseHash, 200, 1, true,
	)
	coinbaseCreditID := harness.insertCredit(t, walletID, coinbaseID)
	harness.setActiveCredit(t, walletID, coinbaseCreditID)

	childHash := testHash(24)
	childID := harness.insertUnminedTransaction(t, walletID, childHash)
	harness.insertInput(t, childID, 0, coinbaseHash, 0)
	childCreditID := harness.insertCredit(t, walletID, childID)
	harness.setActiveCredit(t, walletID, childCreditID)

	grandchildHash := testHash(25)
	grandchildID := harness.insertUnminedTransaction(
		t, walletID, grandchildHash,
	)
	harness.insertInput(t, grandchildID, 0, childHash, 0)

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().Rollback(200)
	}, func() {})
	require.NoError(t, err)

	require.False(t, harness.transactionMined(t, fundingID))
	require.False(t, harness.transactionMined(t, spenderID))
	require.True(t, harness.transactionExists(t, fundingID))
	require.True(t, harness.transactionExists(t, spenderID))
	require.False(t, harness.transactionExists(t, coinbaseID))
	require.False(t, harness.transactionExists(t, childID))
	require.False(t, harness.transactionExists(t, grandchildID))
	require.Equal(t, int64(0), harness.creditSpendCount(t, walletID))
	require.Equal(t, fundingCreditID, harness.activeCreditID(
		t, walletID, fundingHash, 0,
	))
}

// testRollbackTransaction verifies that address and transaction rewinds commit
// or abort together.
func testRollbackTransaction(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(300)
	synced := testBlock(301)
	walletID := harness.createWallet(t, "rollback-transaction", start, synced)
	store := harness.newStore(walletID)

	txID := harness.insertTransaction(
		t, walletID, testHash(31), 301, 0, false,
	)
	testErr := errors.New("abort manager transaction")

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		err := tx.Addr().SetSyncedTo(&start)
		if err != nil {
			return err
		}

		err = tx.Tx().Rollback(301)
		if err != nil {
			return err
		}

		return testErr
	}, func() {})
	require.ErrorIs(t, err, testErr)
	require.Equal(t, synced.Height, harness.syncedHeight(t, walletID))
	require.True(t, harness.transactionMined(t, txID))
}

// testWalletBlockIsolation verifies that a same-height reorg in one wallet does
// not replace another wallet's active block identity or transaction incidence.
func testWalletBlockIsolation(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	startA := testBlock(699)
	blockA := testBlock(700)
	startB := startA
	startB.Hash = testHash(71)
	blockB := blockA
	blockB.Hash = testHash(72)

	walletA := harness.createWallet(
		t, "block-isolation-a", startA, blockA,
	)
	walletB := harness.createWallet(
		t, "block-isolation-b", startB, blockB,
	)
	storeA := harness.newStore(walletA)
	storeB := harness.newStore(walletB)

	newRecord := func(marker byte) *wtxmgr.TxRecord {
		t.Helper()

		msgTx := wire.NewMsgTx(2)
		msgTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
			Hash:  testHash(marker),
			Index: 1,
		}})
		msgTx.AddTxOut(&wire.TxOut{
			Value:    10_000,
			PkScript: []byte{0x51},
		})
		record, err := wtxmgr.NewTxRecordFromMsgTx(
			msgTx, time.Unix(7_000+int64(marker), 0),
		)
		require.NoError(t, err)

		return record
	}
	recordA := newRecord(73)
	recordB := newRecord(74)
	metaA := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   blockA.Hash,
			Height: blockA.Height,
		},
		Time: blockA.Timestamp,
	}
	metaB := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   blockB.Hash,
			Height: blockB.Height,
		},
		Time: blockB.Timestamp,
	}

	require.NoError(t, storeA.Update(
		t.Context(), func(tx db.ReadWriteTx) error {
			return tx.Tx().InsertTx(recordA, metaA)
		}, nil,
	))
	require.NoError(t, storeB.Update(
		t.Context(), func(tx db.ReadWriteTx) error {
			return tx.Tx().InsertTx(recordB, metaB)
		}, nil,
	))

	require.NoError(t, storeA.Update(
		t.Context(), func(tx db.ReadWriteTx) error {
			if err := tx.Addr().SetSyncedTo(&startA); err != nil {
				return err
			}

			return tx.Tx().Rollback(blockA.Height)
		}, nil,
	))

	require.NoError(t, storeB.View(
		t.Context(), func(tx db.ReadTx) error {
			state, err := tx.Addr().SyncState()
			require.NoError(t, err)
			require.Equal(t, blockB, state.SyncedTo)

			details, err := tx.Tx().UniqueTxDetails(
				&recordB.Hash, &metaB.Block,
			)
			require.NoError(t, err)
			require.NotNil(t, details)
			require.Equal(t, blockB.Hash, details.Block.Hash)

			return nil
		}, nil,
	))
	require.Equal(
		t, blockA.Hash, harness.blockHash(t, walletA, blockA.Height),
	)
	require.Equal(
		t, blockB.Hash, harness.blockHash(t, walletB, blockB.Height),
	)
}

// testDuplicateIncidence verifies rollback behavior when a transaction has
// mined and unmined incidences.
func testDuplicateIncidence(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	walletID := harness.createWallet(
		t, "duplicate-incidence", testBlock(400), testBlock(401),
	)
	store := harness.newStore(walletID)

	hash := testHash(41)
	lowerID := harness.insertTransaction(t, walletID, hash, 400, 0, false)
	lowerCreditID := harness.insertCredit(t, walletID, lowerID)
	higherID := harness.insertTransaction(t, walletID, hash, 401, 0, false)
	higherCreditID := harness.insertCredit(t, walletID, higherID)
	harness.setActiveCredit(t, walletID, lowerCreditID)

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().Rollback(400)
	}, func() {})
	require.NoError(t, err)

	require.False(t, harness.transactionExists(t, lowerID))
	require.True(t, harness.transactionExists(t, higherID))
	require.False(t, harness.transactionMined(t, higherID))
	require.Equal(t, higherCreditID, harness.activeCreditID(
		t, walletID, hash, 0,
	))
}

// testBirthdayVerification verifies that birthday verification is independent
// of the birthday block.
func testBirthdayVerification(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	block := testBlock(500)
	walletID := harness.createWallet(
		t, "birthday-verification", block, block,
	)

	harness.exec(t, `
		UPDATE wallet_sync_states
		SET birthday_block_height = ?, birthday_block_verified = TRUE
		WHERE wallet_id = ?
	`, block.Height, walletID)
	harness.exec(t, `
		UPDATE wallet_sync_states
		SET birthday_block_height = NULL
		WHERE wallet_id = ?
	`, walletID)

	var verified bool

	err := harness.queryRow(t, `
		SELECT birthday_block_verified
		FROM wallet_sync_states
		WHERE wallet_id = ?
	`, walletID).Scan(&verified)
	require.NoError(t, err)
	require.True(t, verified)
}

// createWallet creates the wallet and sync rows required by a conformance case.
func (h *managerStoreHarness) createWallet(t *testing.T, name string,
	start, synced waddrmgr.BlockStamp) int64 {

	t.Helper()

	var walletID int64

	err := h.queryRow(t, `
		INSERT INTO wallets (
			wallet_name, manager_version, manager_created_at,
			is_watch_only, master_pub_params, encrypted_crypto_pub_key
		) VALUES (?, 1, 1, TRUE, ?, ?)
		RETURNING id
	`, name, []byte{1}, []byte{2}).Scan(&walletID)
	require.NoError(t, err)
	h.putBlock(t, walletID, start)
	h.putBlock(t, walletID, synced)

	h.exec(t, `
		INSERT INTO wallet_sync_states (
			wallet_id, start_block_height, synced_block_height,
			birthday_timestamp, birthday_block_verified
		) VALUES (?, ?, ?, 1, FALSE)
	`, walletID, start.Height, synced.Height)

	return walletID
}

// putBlock stores one block fixture for a conformance case.
func (h *managerStoreHarness) putBlock(t *testing.T, walletID int64,
	block waddrmgr.BlockStamp) {

	t.Helper()
	h.exec(t, `
		INSERT INTO blocks (block_height, header_hash, block_timestamp)
		VALUES (?, ?, ?)
		ON CONFLICT (block_height) DO NOTHING
	`, block.Height, block.Hash[:], block.Timestamp.Unix())
	h.exec(t, `
		INSERT INTO wallet_blocks (
			wallet_id, block_height, header_hash, block_timestamp
		) VALUES (?, ?, ?, ?)
		ON CONFLICT (wallet_id, block_height) DO UPDATE SET
			header_hash = excluded.header_hash,
			block_timestamp = excluded.block_timestamp
	`, walletID, block.Height, block.Hash[:], block.Timestamp.Unix())
}

// insertTransaction inserts the transaction row and all of its input
// dependencies.
func (h *managerStoreHarness) insertTransaction(t *testing.T, walletID int64,
	hash chainhash.Hash, height int32, order int64, coinbase bool) int64 {

	t.Helper()

	var transactionID int64

	err := h.queryRow(t, `
		INSERT INTO transactions (
			wallet_id, tx_hash, raw_tx, received_unix, block_height,
			confirmed_order, is_coinbase
		) VALUES (?, ?, ?, 1, ?, ?, ?)
		RETURNING id
	`, walletID, hash[:], []byte{hash[0]}, height, order, coinbase).
		Scan(&transactionID)
	require.NoError(t, err)

	return transactionID
}

// insertUnminedTransaction stores an unmined transaction fixture and returns
// its SQL identifier.
func (h *managerStoreHarness) insertUnminedTransaction(t *testing.T,
	walletID int64, hash chainhash.Hash) int64 {

	t.Helper()

	var transactionID int64

	err := h.queryRow(t, `
		INSERT INTO transactions (
			wallet_id, tx_hash, raw_tx, received_unix, is_coinbase
		) VALUES (?, ?, ?, 1, FALSE)
		RETURNING id
	`, walletID, hash[:], []byte{hash[0]}).Scan(&transactionID)
	require.NoError(t, err)

	return transactionID
}

// insertInput stores one transaction-input fixture.
func (h *managerStoreHarness) insertInput(t *testing.T, transactionID int64,
	inputIndex int64, prevHash chainhash.Hash, prevIndex int64) {

	t.Helper()
	h.exec(t, `
		INSERT INTO transaction_inputs (
			spending_tx_id, input_index, prev_tx_hash, prev_output_index
		) VALUES (?, ?, ?, ?)
	`, transactionID, inputIndex, prevHash[:], prevIndex)
}

// insertCredit stores one wallet-credit fixture and returns its SQL identifier.
func (h *managerStoreHarness) insertCredit(t *testing.T, walletID,
	transactionID int64) int64 {

	t.Helper()

	var creditID int64

	err := h.queryRow(t, `
		INSERT INTO credits (
			wallet_id, transaction_id, output_index, amount, pk_script,
			is_change
		) VALUES (?, ?, ?, 1000, ?, FALSE)
		RETURNING id
	`, walletID, transactionID, 0, []byte{0x51}).Scan(&creditID)
	require.NoError(t, err)

	return creditID
}

// setActiveCredit selects the active transaction incidence for one credit
// fixture.
func (h *managerStoreHarness) setActiveCredit(t *testing.T, walletID,
	creditID int64) {

	t.Helper()
	h.exec(t, `
		INSERT INTO active_credit_incidences (
			wallet_id, tx_hash, output_index, credit_id
		)
		SELECT c.wallet_id, tx.tx_hash, c.output_index, c.id
		FROM credits AS c
		INNER JOIN transactions AS tx
			ON tx.wallet_id = c.wallet_id AND tx.id = c.transaction_id
		WHERE c.wallet_id = ? AND c.id = ?
		ON CONFLICT (wallet_id, tx_hash, output_index) DO UPDATE SET
			credit_id = excluded.credit_id
	`, walletID, creditID)
}

// insertCreditSpend stores one credit-spend fixture.
func (h *managerStoreHarness) insertCreditSpend(t *testing.T, walletID,
	creditID, transactionID, inputIndex int64) {

	t.Helper()
	h.exec(t, `
		INSERT INTO credit_spends (
			wallet_id, credit_id, spending_tx_id, input_index
		) VALUES (?, ?, ?, ?)
	`, walletID, creditID, transactionID, inputIndex)
}

// syncedHeight returns the synced height recorded for a wallet fixture.
func (h *managerStoreHarness) syncedHeight(t *testing.T,
	walletID int64) int32 {

	t.Helper()

	var height int32

	err := h.queryRow(t, `
		SELECT synced_block_height FROM wallet_sync_states
		WHERE wallet_id = ?
	`, walletID).Scan(&height)
	require.NoError(t, err)

	return height
}

// blockHash returns the block hash recorded for a height fixture.
func (h *managerStoreHarness) blockHash(t *testing.T, walletID int64,
	height int32) chainhash.Hash {

	t.Helper()

	var hashBytes []byte

	err := h.queryRow(t, `
		SELECT header_hash FROM wallet_blocks
		WHERE wallet_id = ? AND block_height = ?
	`, walletID, height).Scan(&hashBytes)
	require.NoError(t, err)

	hash, err := chainhash.NewHash(hashBytes)
	require.NoError(t, err)

	return *hash
}

// transactionExists reports whether a transaction fixture still exists.
func (h *managerStoreHarness) transactionExists(t *testing.T,
	transactionID int64) bool {

	t.Helper()

	var count int64

	err := h.queryRow(t, `
		SELECT count(*) FROM transactions WHERE id = ?
	`, transactionID).Scan(&count)
	require.NoError(t, err)

	return count == 1
}

// transactionMined reports whether a transaction fixture has a mined incidence.
func (h *managerStoreHarness) transactionMined(t *testing.T,
	transactionID int64) bool {

	t.Helper()

	var mined bool

	err := h.queryRow(t, `
		SELECT block_height IS NOT NULL FROM transactions WHERE id = ?
	`, transactionID).Scan(&mined)
	require.NoError(t, err)

	return mined
}

// creditSpendCount returns the number of spend rows attached to a transaction
// fixture.
func (h *managerStoreHarness) creditSpendCount(t *testing.T,
	walletID int64) int64 {

	t.Helper()

	var count int64

	err := h.queryRow(t, `
		SELECT count(*) FROM credit_spends WHERE wallet_id = ?
	`, walletID).Scan(&count)
	require.NoError(t, err)

	return count
}

// activeCreditID returns the active incidence selected for a credit fixture.
func (h *managerStoreHarness) activeCreditID(t *testing.T, walletID int64,
	hash chainhash.Hash, outputIndex int64) int64 {

	t.Helper()

	var creditID int64

	err := h.queryRow(t, `
		SELECT credit_id FROM active_credit_incidences
		WHERE wallet_id = ? AND tx_hash = ? AND output_index = ?
	`, walletID, hash[:], outputIndex).Scan(&creditID)
	require.NoError(t, err)

	return creditID
}

// exec executes a dialect-aware test statement after rebinding its
// placeholders.
func (h *managerStoreHarness) exec(t *testing.T, query string,
	args ...any) {

	t.Helper()

	_, err := h.conn.ExecContext(
		context.Background(), h.bind(query), args...,
	)
	require.NoError(t, err)
}

// queryRow queries one dialect-aware test row after rebinding its placeholders.
func (h *managerStoreHarness) queryRow(t *testing.T, query string,
	args ...any) *sql.Row {

	t.Helper()

	return h.conn.QueryRowContext(
		context.Background(), h.bind(query), args...,
	)
}

// bind rewrites question-mark placeholders for the PostgreSQL test backend.
func (h *managerStoreHarness) bind(query string) string {
	if !h.postgres {
		return query
	}

	var builder strings.Builder

	parameter := 1
	for _, char := range query {
		if char != '?' {
			builder.WriteRune(char)

			continue
		}

		builder.WriteString(fmt.Sprintf("$%d", parameter))
		parameter++
	}

	return builder.String()
}

// testBlock constructs a deterministic block fixture for the given height.
func testBlock(height int32) waddrmgr.BlockStamp {
	var hash chainhash.Hash

	hash[0] = 0xff
	binary.BigEndian.PutUint32(hash[1:5], uint32(height))

	return waddrmgr.BlockStamp{
		Height:    height,
		Hash:      hash,
		Timestamp: time.Unix(1000+int64(height), 0),
	}
}

// testHash constructs a deterministic hash fixture from one byte.
func testHash(value byte) chainhash.Hash {
	var hash chainhash.Hash
	for i := range hash {
		hash[i] = value
	}

	return hash
}
