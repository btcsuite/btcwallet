package itest

import (
	"context"
	"crypto/sha256"
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
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

type managerStoreHarness struct {
	conn      *sql.DB
	postgres  bool
	reconnect func(*testing.T) *sql.DB
	kv        *kvBackend
	newStore  func(int64) db.Store

	// newRuntime builds a low-level SQL runtime store for one wallet. It is
	// nil for the KV backend, which uses natural record guards instead of the
	// SQL runtime-state journal.
	newRuntime func(int64) *sqlstore.Store

	// newRuntimeStore builds the semantic db.RuntimeStore for one wallet. It
	// is set for every backend, including KV, so the cross-backend semantic
	// parity vector runs on all three.
	newRuntimeStore func(int64) db.RuntimeStore
}

// testManagerStore runs the shared manager-store conformance cases against one
// backend. The backend-neutral address-manager vector is expressed entirely
// against the db.Store contract and runs identically on the KV, SQLite, and
// PostgreSQL backends. The transaction-incidence cases depend on the SQL
// fixture schema and run only against the SQL backends.
func testManagerStore(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	// Backend-neutral address-manager vector: runs on KV, SQLite, and
	// PostgreSQL.
	t.Run("manager transaction", func(t *testing.T) {
		testManagerTransaction(t, harness)
	})
	t.Run("address manager persistence", func(t *testing.T) {
		testAddressManagerPersistence(t, harness)
	})
	t.Run("address forms", func(t *testing.T) {
		testAddressForms(t, harness)
	})
	t.Run("manager replacement clears private", func(t *testing.T) {
		testManagerReplacementClearsPrivate(t, harness)
	})
	t.Run("account name dedup", func(t *testing.T) {
		testAccountNameDedup(t, harness)
	})
	t.Run("rename account collision", func(t *testing.T) {
		testRenameAccountCollision(t, harness)
	})
	t.Run("address rehome", func(t *testing.T) {
		testAddressRehome(t, harness)
	})
	t.Run("last account sentinel", func(t *testing.T) {
		testLastAccountSentinel(t, harness)
	})
	t.Run("sticky used monotonic", func(t *testing.T) {
		testStickyUsedMonotonic(t, harness)
	})
	t.Run("script private key deletion", func(t *testing.T) {
		testScriptPrivateKeyDeletion(t, harness)
	})
	t.Run("synced-to semantics", func(t *testing.T) {
		testSyncedToSemantics(t, harness)
	})
	t.Run("partial write rollback", func(t *testing.T) {
		testPartialWriteRollback(t, harness)
	})
	t.Run("close reopen", func(t *testing.T) {
		testCloseReopen(t, harness)
	})

	// Cross-backend semantic parity vector: the semantic RuntimeStore
	// operations must produce identical observable results on KV, SQLite, and
	// PostgreSQL.
	t.Run("semantic parity", func(t *testing.T) {
		testSemanticParity(t, harness)
	})
	t.Run("address store", func(t *testing.T) {
		testAddressStore(t, harness)
	})

	// SQL-only transaction-incidence vector: depends on the SQL fixture
	// schema, so it is skipped for the KV backend.
	if harness.kv != nil {
		return
	}

	t.Run("concurrent allocation", func(t *testing.T) {
		testAddressConcurrentAllocation(t, harness)
	})
	t.Run("rollback", func(t *testing.T) {
		testRollback(t, harness)
	})
	t.Run("rollback transaction", func(t *testing.T) {
		testRollbackTransaction(t, harness)
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
	t.Run("runtime store", func(t *testing.T) {
		testRuntimeStore(t, harness)
	})
	t.Run("funding store", func(t *testing.T) {
		testFundingStore(t, harness)
	})
	t.Run("spike store", func(t *testing.T) {
		testSpikeStore(t, harness)
	})
	t.Run("semantic tip", func(t *testing.T) {
		testSemanticTip(t, harness)
	})
}

// testWtxmgrCompatibility verifies the complete wtxmgr surface against one SQL
// backend.
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

		err = tx.Tx().AddCredit(funding, nil, 0, false)
		if err != nil {
			return err
		}

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
	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		_, err := tx.Tx().LockOutput(lockID, output, time.Hour)
		return err
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		locked, err := tx.Tx().ListLockedOutputs()
		require.NoError(t, err)
		require.Len(t, locked, 1)
		require.Equal(t, output, locked[0].Outpoint)

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

		return nil
	}, func() {})
	require.NoError(t, err)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().RemoveUnminedTx(spender)
	}, func() {})
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

	err = store.View(ctx, func(tx db.ReadTx) error {
		details, err := tx.Tx().UniqueTxDetails(
			&funding.Hash, &wtxmgr.Block{
				Hash:   synced.Hash,
				Height: synced.Height,
			},
		)
		require.NoError(t, err)
		require.Equal(t, synced.Height, details.Block.Height)

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
}

// testAddressManagerPersistence verifies the complete waddrmgr persistence
// surface against one SQL backend.
//
//nolint:maintidx // One vector deliberately covers the complete store surface.
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

		// StartBlock.Timestamp is a narrowed field that the KV encoding
		// does not persist, so it is dropped from the expectation to
		// assert the common Store contract across every backend.
		wantSync := syncState
		wantSync.StartBlock.Timestamp = time.Time{}
		gotSync.StartBlock.Timestamp = time.Time{}
		require.Equal(t, wantSync, gotSync)

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

		// The stored identifier is the legacy SHA256 of the address ID.
		// Derive the expectation independently of the returned value so
		// a wrong hashing algorithm remains detectable.
		wantChainHash := sha256.Sum256(chainAddressID)
		chainAddress.Hash = wantChainHash[:]
		require.Equal(t, chainAddress, gotChain)

		gotWitness, err := addr.Address(scope, witnessAddressID)
		require.NoError(t, err)

		wantWitnessHash := sha256.Sum256(witnessAddressID)
		witnessAddress.Hash = wantWitnessHash[:]
		require.Equal(t, witnessAddress, gotWitness)

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
			t, []waddrmgr.AddressState{chainAddress, witnessAddress},
			activeAddresses,
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
		harness.syncedBlockHash(t, walletID),
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

// testSyncedToSemantics verifies the durable synced-to behavior ported from the
// legacy waddrmgr.PutSyncedTo: the predecessor guard, same-height replacement,
// rewind, and recent-block retention.
func testSyncedToSemantics(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()

	t.Run("missing predecessor", func(t *testing.T) {
		start := testBlock(1_000)
		synced := testBlock(1_001)
		walletID := harness.createWallet(
			t, "sync-missing-predecessor", start, synced,
		)
		store := harness.newStore(walletID)

		// Record the birthday block so the predecessor guard is active.
		err := store.Update(ctx, func(tx db.ReadWriteTx) error {
			return tx.Addr().SetBirthdayBlock(&synced)
		}, func() {})
		require.NoError(t, err)

		// Advancing to a tip whose predecessor was never recorded fails
		// with a legacy block-not-found error.
		target := testBlock(2_000)

		var syncErr error

		err = store.Update(ctx, func(tx db.ReadWriteTx) error {
			syncErr = tx.Addr().SetSyncedTo(&target)

			return nil
		}, func() {})
		require.NoError(t, err)
		require.True(
			t, waddrmgr.IsError(syncErr, waddrmgr.ErrBlockNotFound),
		)
		require.Equal(
			t, synced.Height, harness.syncedHeight(t, walletID),
		)
	})

	t.Run("competing same height", func(t *testing.T) {
		start := testBlock(1_100)
		synced := testBlock(1_101)
		walletID := harness.createWallet(
			t, "sync-same-height", start, synced,
		)
		store := harness.newStore(walletID)

		// A different block at the same height does not overwrite the
		// existing one; the synced tip advances to the competing block.
		replacement := testBlock(1_101)
		replacement.Hash = testHash(0x5a)
		replacement.Timestamp = time.Unix(9_100, 0)

		err := store.Update(ctx, func(tx db.ReadWriteTx) error {
			return tx.Addr().SetSyncedTo(&replacement)
		}, func() {})
		require.NoError(t, err)
		require.Equal(
			t, replacement.Height, harness.syncedHeight(t, walletID),
		)
		require.Equal(
			t, replacement.Hash,
			harness.syncedBlockHash(t, walletID),
		)

		// The surrogate-keyed SQL schema keeps both blocks at the height.
		if harness.kv == nil {
			require.Equal(t, 2, harness.blockCountAtHeight(t, 1_101))
		}
	})

	t.Run("rewind", func(t *testing.T) {
		start := testBlock(1_200)
		synced := testBlock(1_201)
		walletID := harness.createWallet(t, "sync-rewind", start, synced)
		store := harness.newStore(walletID)

		// With the birthday block set the predecessor guard is active for
		// both the advance and the rewind, so every referenced predecessor
		// must already exist.
		err := store.Update(ctx, func(tx db.ReadWriteTx) error {
			return tx.Addr().SetBirthdayBlock(&start)
		}, func() {})
		require.NoError(t, err)

		next := testBlock(1_202)
		err = store.Update(ctx, func(tx db.ReadWriteTx) error {
			return tx.Addr().SetSyncedTo(&next)
		}, func() {})
		require.NoError(t, err)
		require.Equal(t, next.Height, harness.syncedHeight(t, walletID))

		// Rewinding to an earlier tip whose predecessor is known succeeds.
		err = store.Update(ctx, func(tx db.ReadWriteTx) error {
			return tx.Addr().SetSyncedTo(&synced)
		}, func() {})
		require.NoError(t, err)
		require.Equal(t, synced.Height, harness.syncedHeight(t, walletID))
	})

	// Recent-block retention exercises the SQL FK-guarded prune against the
	// shared blocks table and its transaction fixtures, so it runs only on
	// the SQL backends.
	if harness.kv != nil {
		return
	}

	t.Run("recent block retention", func(t *testing.T) {
		start := testBlock(2_000_000)
		synced := testBlock(2_000_001)
		walletID := harness.createWallet(
			t, "sync-recent-retention", start, synced,
		)
		store := harness.newStore(walletID)

		// Two blocks below the reorg window: one unreferenced, one still
		// referenced by a mined transaction.
		staleUnref := int32(2_000_010)
		staleRef := int32(2_000_020)

		harness.putBlock(t, testBlock(staleUnref))
		harness.putBlock(t, testBlock(staleRef))
		harness.insertTransaction(
			t, walletID, testHash(0x77), staleRef, 0, false,
		)

		// Advancing past the reorg window prunes the unreferenced stale
		// block.
		tipUnref := testBlock(staleUnref + waddrmgr.MaxReorgDepth)
		err := store.Update(ctx, func(tx db.ReadWriteTx) error {
			return tx.Addr().SetSyncedTo(&tipUnref)
		}, func() {})
		require.NoError(t, err)
		require.False(t, harness.blockExists(t, staleUnref))

		// A stale block still referenced by a transaction is retained.
		tipRef := testBlock(staleRef + waddrmgr.MaxReorgDepth)
		err = store.Update(ctx, func(tx db.ReadWriteTx) error {
			return tx.Addr().SetSyncedTo(&tipRef)
		}, func() {})
		require.NoError(t, err)
		require.True(t, harness.blockExists(t, staleRef))
	})
}

// testStickyUsedMonotonic verifies that re-putting an address never clears its
// used bit, matching the legacy sticky used-address bucket. The SQL upsert must
// be a monotonic no-op instead of tripping the used-monotonicity trigger.
func testStickyUsedMonotonic(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(1_800)
	synced := testBlock(1_801)
	walletID := harness.createWallet(
		t, "sticky-used-monotonic", start, synced,
	)
	store := harness.newStore(walletID)

	scope := waddrmgr.KeyScopeBIP0084
	account := uint32(0)
	harness.seedScope(t, store, scope, account)

	// Each fixture address occupies a distinct derivation path so the
	// derived-address uniqueness guard is respected; the two rows only exist
	// to exercise the sticky-used upsert independently.
	chainAddress := func(index uint32, used bool) waddrmgr.AddressState {
		branch := uint32(0)

		return waddrmgr.AddressState{
			Scope:      scope,
			Account:    account,
			Type:       waddrmgr.AddressChain,
			AddedAt:    time.Unix(1_800, 0),
			SyncStatus: waddrmgr.AddressSyncFull,
			Branch:     &branch,
			Index:      &index,
			Used:       used,
		}
	}

	// A used address that is re-put with Used=false keeps its used bit
	// instead of erroring.
	usedID := []byte("sticky-used")
	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().PutAddress(usedID, chainAddress(0, true))
	}, func() {})
	require.NoError(t, err)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().PutAddress(usedID, chainAddress(0, false))
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		got, err := tx.Addr().Address(scope, usedID)
		require.NoError(t, err)
		require.True(t, got.Used)

		return nil
	}, func() {})
	require.NoError(t, err)

	// An unused address can still transition to used through a re-put, so the
	// monotonic upsert does not freeze the bit at its initial value.
	unusedID := []byte("sticky-unused")
	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().PutAddress(unusedID, chainAddress(1, false))
	}, func() {})
	require.NoError(t, err)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().PutAddress(unusedID, chainAddress(1, true))
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		got, err := tx.Addr().Address(scope, unusedID)
		require.NoError(t, err)
		require.True(t, got.Used)

		return nil
	}, func() {})
	require.NoError(t, err)
}

// testScriptPrivateKeyDeletion verifies that watch-only conversion clears the
// secret script material for both witness-v0 and taproot script addresses while
// retaining public scripts.
func testScriptPrivateKeyDeletion(t *testing.T,
	harness *managerStoreHarness) {

	t.Helper()

	ctx := context.Background()
	start := testBlock(1_900)
	synced := testBlock(1_901)
	walletID := harness.createWallet(
		t, "script-private-key-deletion", start, synced,
	)
	store := harness.newStore(walletID)

	scope := waddrmgr.KeyScopeBIP0086
	account := uint32(0)
	harness.seedScope(t, store, scope, account)

	scriptAddress := func(addrType waddrmgr.StoreAddressType, version uint8,
		isSecret bool) waddrmgr.AddressState {

		v, s := version, isSecret

		return waddrmgr.AddressState{
			Scope:           scope,
			Account:         account,
			Type:            addrType,
			AddedAt:         time.Unix(1_900, 0),
			SyncStatus:      waddrmgr.AddressSyncFull,
			EncryptedHash:   []byte{0xaa},
			EncryptedScript: []byte{0xbb},
			WitnessVersion:  &v,
			IsSecretScript:  &s,
		}
	}

	witnessSecretID := []byte("witness-secret")
	witnessPublicID := []byte("witness-public")
	taprootSecretID := []byte("taproot-secret")
	taprootPublicID := []byte("taproot-public")

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		puts := []struct {
			id    []byte
			state waddrmgr.AddressState
		}{
			{
				witnessSecretID,
				scriptAddress(waddrmgr.AddressWitnessScript, 0, true),
			},
			{
				witnessPublicID,
				scriptAddress(waddrmgr.AddressWitnessScript, 0, false),
			},
			{
				taprootSecretID,
				scriptAddress(waddrmgr.AddressTaprootScript, 1, true),
			},
			{
				taprootPublicID,
				scriptAddress(waddrmgr.AddressTaprootScript, 1, false),
			},
		}
		for _, put := range puts {
			err := addr.PutAddress(put.id, put.state)
			if err != nil {
				return err
			}
		}

		return nil
	}, func() {})
	require.NoError(t, err)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().DeletePrivateKeys()
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		addr := tx.Addr()

		// Secret witness and taproot scripts are cleared.
		gotWitnessSecret, err := addr.Address(scope, witnessSecretID)
		require.NoError(t, err)
		require.Nil(t, gotWitnessSecret.EncryptedScript)

		gotTaprootSecret, err := addr.Address(scope, taprootSecretID)
		require.NoError(t, err)
		require.Nil(t, gotTaprootSecret.EncryptedScript)

		// Public scripts hold no private material and are retained.
		gotWitnessPublic, err := addr.Address(scope, witnessPublicID)
		require.NoError(t, err)
		require.Equal(t, []byte{0xbb}, gotWitnessPublic.EncryptedScript)

		gotTaprootPublic, err := addr.Address(scope, taprootPublicID)
		require.NoError(t, err)
		require.Equal(t, []byte{0xbb}, gotTaprootPublic.EncryptedScript)

		return nil
	}, func() {})
	require.NoError(t, err)
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
		SET birthday_block_id =
			(SELECT id FROM blocks WHERE block_height = ? ORDER BY id LIMIT 1),
			birthday_block_verified = TRUE
		WHERE wallet_id = ?
	`, block.Height, walletID)
	harness.exec(t, `
		UPDATE wallet_sync_states
		SET birthday_block_id = NULL
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

// testAddressForms verifies that all five legacy address forms round-trip
// through the store with the independently derived SHA256 identifier.
func testAddressForms(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(3_000)
	synced := testBlock(3_001)
	walletID := harness.createWallet(t, "address-forms", start, synced)
	store := harness.newStore(walletID)

	scope := waddrmgr.KeyScopeBIP0084
	account := uint32(0)
	harness.seedScope(t, store, scope, account)

	branch, index := uint32(1), uint32(2)
	version, secret := uint8(0), true
	tapVersion, tapPublic := uint8(1), false

	forms := []struct {
		name  string
		id    []byte
		state waddrmgr.AddressState
	}{
		{
			name: "chain",
			id:   []byte("form-chain"),
			state: waddrmgr.AddressState{
				Scope:      scope,
				Account:    account,
				Type:       waddrmgr.AddressChain,
				AddedAt:    time.Unix(3_010, 0),
				SyncStatus: waddrmgr.AddressSyncFull,
				Branch:     &branch,
				Index:      &index,
			},
		},
		{
			name: "imported",
			id:   []byte("form-imported"),
			state: waddrmgr.AddressState{
				Scope:            scope,
				Account:          account,
				Type:             waddrmgr.AddressImported,
				AddedAt:          time.Unix(3_011, 0),
				SyncStatus:       waddrmgr.AddressSyncNone,
				EncryptedPubKey:  []byte{0x01, 0x02},
				EncryptedPrivKey: []byte{0x03, 0x04},
			},
		},
		{
			name: "script",
			id:   []byte("form-script"),
			state: waddrmgr.AddressState{
				Scope:           scope,
				Account:         account,
				Type:            waddrmgr.AddressScript,
				AddedAt:         time.Unix(3_012, 0),
				SyncStatus:      waddrmgr.AddressSyncNone,
				EncryptedHash:   []byte{0x05},
				EncryptedScript: []byte{0x06},
			},
		},
		{
			name: "witness script",
			id:   []byte("form-witness"),
			state: waddrmgr.AddressState{
				Scope:           scope,
				Account:         account,
				Type:            waddrmgr.AddressWitnessScript,
				AddedAt:         time.Unix(3_013, 0),
				SyncStatus:      waddrmgr.AddressSyncFull,
				EncryptedHash:   []byte{0x07},
				EncryptedScript: []byte{0x08},
				WitnessVersion:  &version,
				IsSecretScript:  &secret,
			},
		},
		{
			name: "taproot script",
			id:   []byte("form-taproot"),
			state: waddrmgr.AddressState{
				Scope:           scope,
				Account:         account,
				Type:            waddrmgr.AddressTaprootScript,
				AddedAt:         time.Unix(3_014, 0),
				SyncStatus:      waddrmgr.AddressSyncFull,
				EncryptedHash:   []byte{0x09},
				EncryptedScript: []byte{0x0a},
				WitnessVersion:  &tapVersion,
				IsSecretScript:  &tapPublic,
			},
		},
	}

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		for _, form := range forms {
			err := tx.Addr().PutAddress(form.id, form.state)
			if err != nil {
				return err
			}
		}

		return nil
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		for _, form := range forms {
			got, err := tx.Addr().Address(scope, form.id)
			require.NoError(t, err, form.name)

			// Derive the stored identifier independently so a wrong
			// hashing algorithm remains detectable.
			want := form.state
			wantHash := sha256.Sum256(form.id)
			want.Hash = wantHash[:]
			require.Equal(t, want, got, form.name)
		}

		return nil
	}, func() {})
	require.NoError(t, err)
}

// testManagerReplacementClearsPrivate verifies that replacing the manager state
// with a watch-only state clears the previously stored encrypted private key
// material rather than retaining it, while keeping the public material.
func testManagerReplacementClearsPrivate(t *testing.T,
	harness *managerStoreHarness) {

	t.Helper()

	ctx := context.Background()
	start := testBlock(3_100)
	synced := testBlock(3_101)
	walletID := harness.createWallet(t, "manager-replacement", start, synced)
	store := harness.newStore(walletID)

	full := waddrmgr.ManagerState{
		Version:                  9,
		CreatedAt:                time.Unix(3_100, 0),
		MasterPubParams:          []byte{1},
		MasterPrivParams:         []byte{2},
		EncryptedCryptoPubKey:    []byte{3},
		EncryptedCryptoPrivKey:   []byte{4},
		EncryptedCryptoScriptKey: []byte{5},
		EncryptedMasterHDPubKey:  []byte{6},
		EncryptedMasterHDPrivKey: []byte{7},
	}
	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().PutManagerState(full)
	}, func() {})
	require.NoError(t, err)

	// Replace the state with a watch-only state that omits every private
	// field.
	watchOnly := full
	watchOnly.WatchOnly = true
	watchOnly.MasterPrivParams = nil
	watchOnly.EncryptedCryptoPrivKey = nil
	watchOnly.EncryptedCryptoScriptKey = nil
	watchOnly.EncryptedMasterHDPrivKey = nil

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().PutManagerState(watchOnly)
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		got, err := tx.Addr().ManagerState()
		require.NoError(t, err)

		// The replacement is watch-only and every private field is gone.
		require.Equal(t, watchOnly, got)
		require.True(t, got.WatchOnly)
		require.Nil(t, got.MasterPrivParams)
		require.Nil(t, got.EncryptedCryptoPrivKey)
		require.Nil(t, got.EncryptedCryptoScriptKey)
		require.Nil(t, got.EncryptedMasterHDPrivKey)

		// Public material survives the replacement.
		require.Equal(t, []byte{1}, got.MasterPubParams)
		require.Equal(t, []byte{3}, got.EncryptedCryptoPubKey)
		require.Equal(t, []byte{6}, got.EncryptedMasterHDPubKey)

		return nil
	}, func() {})
	require.NoError(t, err)
}

// testAccountNameDedup verifies that replacing an account under a different
// name removes the stale name index so the previous name no longer resolves.
func testAccountNameDedup(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(3_600)
	synced := testBlock(3_601)
	walletID := harness.createWallet(t, "account-name-dedup", start, synced)
	store := harness.newStore(walletID)

	scope := waddrmgr.KeyScopeBIP0084

	const account = uint32(1)

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		err := addr.PutKeyScope(waddrmgr.KeyScopeState{
			Scope:      scope,
			AddrSchema: waddrmgr.ScopeAddrMap[scope],
		})
		if err != nil {
			return err
		}

		// Store the account, then replace it under a different name.
		err = addr.PutAccount(managerAccount(scope, account, "alpha"))
		if err != nil {
			return err
		}

		return addr.PutAccount(managerAccount(scope, account, "beta"))
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		addr := tx.Addr()

		// The current name resolves to the account.
		got, err := addr.AccountByName(scope, "beta")
		require.NoError(t, err)
		require.Equal(t, account, got.Account)

		// The stale name no longer resolves.
		_, err = addr.AccountByName(scope, "alpha")
		require.True(t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound))

		return nil
	}, func() {})
	require.NoError(t, err)
}

// testRenameAccountCollision verifies that RenameAccount rejects a name owned
// by a different account, but permits renaming to a free name or to the
// account's own current name.
func testRenameAccountCollision(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(3_700)
	synced := testBlock(3_701)
	walletID := harness.createWallet(t, "rename-collision", start, synced)
	store := harness.newStore(walletID)

	scope := waddrmgr.KeyScopeBIP0084

	const (
		accountA = uint32(1)
		accountB = uint32(2)
	)

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		err := addr.PutKeyScope(waddrmgr.KeyScopeState{
			Scope:      scope,
			AddrSchema: waddrmgr.ScopeAddrMap[scope],
		})
		if err != nil {
			return err
		}

		err = addr.PutAccount(managerAccount(scope, accountA, "alpha"))
		if err != nil {
			return err
		}

		return addr.PutAccount(managerAccount(scope, accountB, "beta"))
	}, func() {})
	require.NoError(t, err)

	// Renaming account A onto account B's name is rejected and leaves both
	// name indexes intact.
	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().RenameAccount(scope, accountA, "beta")
	}, func() {})
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrDuplicateAccount))

	err = store.View(ctx, func(tx db.ReadTx) error {
		addr := tx.Addr()

		gotBeta, err := addr.AccountByName(scope, "beta")
		require.NoError(t, err)
		require.Equal(t, accountB, gotBeta.Account)

		gotAlpha, err := addr.AccountByName(scope, "alpha")
		require.NoError(t, err)
		require.Equal(t, accountA, gotAlpha.Account)

		return nil
	}, func() {})
	require.NoError(t, err)

	// Renaming to a free name succeeds and drops the old name. Renaming to the
	// account's own current name is a permitted no-op.
	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().RenameAccount(scope, accountA, "gamma")
	}, func() {})
	require.NoError(t, err)

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().RenameAccount(scope, accountA, "gamma")
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		addr := tx.Addr()

		got, err := addr.AccountByName(scope, "gamma")
		require.NoError(t, err)
		require.Equal(t, accountA, got.Account)

		_, err = addr.AccountByName(scope, "alpha")
		require.True(t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound))

		return nil
	}, func() {})
	require.NoError(t, err)
}

// testAddressRehome verifies that re-homing an address to a different account
// removes the previous account index so the address is not listed under both.
func testAddressRehome(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(3_500)
	synced := testBlock(3_501)
	walletID := harness.createWallet(t, "address-rehome", start, synced)
	store := harness.newStore(walletID)

	scope := waddrmgr.KeyScopeBIP0084
	accountA, accountB := uint32(1), uint32(2)
	addressID := []byte("rehomed-address")
	branch, index := uint32(0), uint32(3)

	addrState := func(account uint32) waddrmgr.AddressState {
		return waddrmgr.AddressState{
			Scope:      scope,
			Account:    account,
			Type:       waddrmgr.AddressChain,
			AddedAt:    time.Unix(3_510, 0),
			SyncStatus: waddrmgr.AddressSyncNone,
			Branch:     &branch,
			Index:      &index,
		}
	}

	// Seed the scope and both accounts, then store the address under A.
	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		err := addr.PutKeyScope(waddrmgr.KeyScopeState{
			Scope:      scope,
			AddrSchema: waddrmgr.ScopeAddrMap[scope],
		})
		if err != nil {
			return err
		}

		err = addr.PutAccount(managerAccount(scope, accountA, "account-a"))
		if err != nil {
			return err
		}

		err = addr.PutAccount(managerAccount(scope, accountB, "account-b"))
		if err != nil {
			return err
		}

		return addr.PutAddress(addressID, addrState(accountA))
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		addrs, err := tx.Addr().AccountAddresses(scope, accountA)
		require.NoError(t, err)
		require.Len(t, addrs, 1)

		return nil
	}, func() {})
	require.NoError(t, err)

	// Re-home the address to account B.
	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().PutAddress(addressID, addrState(accountB))
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		addr := tx.Addr()

		// The stale account no longer lists the address.
		oldAddrs, err := addr.AccountAddresses(scope, accountA)
		require.NoError(t, err)
		require.Empty(t, oldAddrs)

		// The new account owns the address exactly once.
		newAddrs, err := addr.AccountAddresses(scope, accountB)
		require.NoError(t, err)
		require.Len(t, newAddrs, 1)
		require.Equal(t, accountB, newAddrs[0].Account)

		return nil
	}, func() {})
	require.NoError(t, err)
}

// testLastAccountSentinel verifies that the no-account sentinel round-trips
// through the store distinctly from a real account 0, matching the KV backend.
// Running the same assertions against KV, SQLite, and PostgreSQL gives the
// KV-vs-SQL parity check for the nullable last-account column.
func testLastAccountSentinel(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(3_200)
	synced := testBlock(3_201)
	walletID := harness.createWallet(
		t, "last-account-sentinel", start, synced,
	)
	store := harness.newStore(walletID)

	sentinel := waddrmgr.NoAccountAllocated
	sentinelScope := waddrmgr.KeyScopeBIP0084
	zeroScope := waddrmgr.KeyScopeBIP0086

	// A scope that has never allocated an account reports the no-account
	// sentinel; a scope whose last account is zero stays distinct from it.
	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		err := addr.PutKeyScope(waddrmgr.KeyScopeState{
			Scope:       sentinelScope,
			AddrSchema:  waddrmgr.ScopeAddrMap[sentinelScope],
			LastAccount: sentinel,
		})
		if err != nil {
			return err
		}

		return addr.PutKeyScope(waddrmgr.KeyScopeState{
			Scope:       zeroScope,
			AddrSchema:  waddrmgr.ScopeAddrMap[zeroScope],
			LastAccount: 0,
		})
	}, func() {})
	require.NoError(t, err)

	err = store.View(ctx, func(tx db.ReadTx) error {
		addr := tx.Addr()

		gotSentinel, err := addr.KeyScope(sentinelScope)
		require.NoError(t, err)
		require.Equal(t, sentinel, gotSentinel.LastAccount)

		gotZero, err := addr.KeyScope(zeroScope)
		require.NoError(t, err)
		require.Equal(t, uint32(0), gotZero.LastAccount)

		return nil
	}, func() {})
	require.NoError(t, err)

	// The sentinel and account 0 round-trip distinctly through SetLastAccount.
	values := []uint32{0, sentinel, 5, sentinel}
	for _, want := range values {
		err := store.Update(ctx, func(tx db.ReadWriteTx) error {
			return tx.Addr().SetLastAccount(sentinelScope, want)
		}, func() {})
		require.NoError(t, err)

		err = store.View(ctx, func(tx db.ReadTx) error {
			got, err := tx.Addr().KeyScope(sentinelScope)
			require.NoError(t, err)
			require.Equal(t, want, got.LastAccount)

			return nil
		}, func() {})
		require.NoError(t, err)
	}
}

// testPartialWriteRollback verifies that a write which fails partway commits
// none of its mutations.
func testPartialWriteRollback(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(3_300)
	synced := testBlock(3_301)
	walletID := harness.createWallet(t, "partial-write", start, synced)
	store := harness.newStore(walletID)

	scope := waddrmgr.KeyScopeBIP0084
	account := uint32(0)
	addressID := []byte("rolled-back-address")
	branch, index := uint32(0), uint32(0)
	testErr := errors.New("abort partial write")

	// The body writes a scope, account, and address before returning an
	// error, so the whole transaction must roll back.
	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		err := addr.PutKeyScope(waddrmgr.KeyScopeState{
			Scope:      scope,
			AddrSchema: waddrmgr.ScopeAddrMap[scope],
		})
		if err != nil {
			return err
		}

		err = addr.PutAccount(managerAccount(scope, account, "doomed"))
		if err != nil {
			return err
		}

		err = addr.PutAddress(addressID, waddrmgr.AddressState{
			Scope:      scope,
			Account:    account,
			Type:       waddrmgr.AddressChain,
			AddedAt:    time.Unix(3_310, 0),
			SyncStatus: waddrmgr.AddressSyncFull,
			Branch:     &branch,
			Index:      &index,
		})
		if err != nil {
			return err
		}

		return testErr
	}, func() {})
	require.ErrorIs(t, err, testErr)

	// None of the rolled-back rows are visible.
	err = store.View(ctx, func(tx db.ReadTx) error {
		_, err := tx.Addr().KeyScope(scope)
		require.True(t, waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound))

		return nil
	}, func() {})
	require.NoError(t, err)
}

// testCloseReopen verifies that committed address-manager state survives a
// close and reopen of the backend database.
func testCloseReopen(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(3_400)
	synced := testBlock(3_401)
	walletID := harness.createWallet(t, "close-reopen", start, synced)
	store := harness.newStore(walletID)

	scope := waddrmgr.KeyScopeBIP0084
	account := uint32(0)
	addressID := []byte("persisted-address")
	branch, index := uint32(0), uint32(1)
	address := waddrmgr.AddressState{
		Scope:      scope,
		Account:    account,
		Type:       waddrmgr.AddressChain,
		AddedAt:    time.Unix(3_410, 0),
		SyncStatus: waddrmgr.AddressSyncFull,
		Branch:     &branch,
		Index:      &index,
	}

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		err := addr.PutKeyScope(waddrmgr.KeyScopeState{
			Scope:       scope,
			AddrSchema:  waddrmgr.ScopeAddrMap[scope],
			LastAccount: account,
		})
		if err != nil {
			return err
		}

		err = addr.PutAccount(managerAccount(scope, account, "persist"))
		if err != nil {
			return err
		}

		return addr.PutAddress(addressID, address)
	}, func() {})
	require.NoError(t, err)

	// Close and reopen the backend database, then read through a fresh store.
	harness.reopen(t, walletID)
	store = harness.newStore(walletID)

	err = store.View(ctx, func(tx db.ReadTx) error {
		addr := tx.Addr()

		got, err := addr.Address(scope, addressID)
		require.NoError(t, err)

		wantHash := sha256.Sum256(addressID)
		address.Hash = wantHash[:]
		require.Equal(t, address, got)

		gotAccount, err := addr.AccountByName(scope, "persist")
		require.NoError(t, err)
		require.Equal(t, account, gotAccount.Account)

		return nil
	}, func() {})
	require.NoError(t, err)
}

// managerAccount builds a minimal default AccountState for the neutral vector.
func managerAccount(scope waddrmgr.KeyScope, account uint32,
	name string) waddrmgr.AccountState {

	return waddrmgr.AccountState{
		Scope:           scope,
		Account:         account,
		Type:            waddrmgr.AccountDefault,
		Name:            name,
		EncryptedPubKey: []byte("pub-" + name),
	}
}

// reopen closes and reopens the backend database for one wallet so the next
// store created for that wallet reads persisted state from a fresh connection.
func (h *managerStoreHarness) reopen(t *testing.T, walletID int64) {
	t.Helper()

	if h.kv != nil {
		h.kv.reopen(t, walletID)

		return
	}

	require.NoError(t, h.conn.Close())
	h.conn = h.reconnect(t)
}

// createWallet creates the wallet and sync rows required by a conformance case.
func (h *managerStoreHarness) createWallet(t *testing.T, name string,
	start, synced waddrmgr.BlockStamp) int64 {

	t.Helper()

	if h.kv != nil {
		return h.kv.createWallet(t, start, synced)
	}

	h.putBlock(t, start)
	h.putBlock(t, synced)

	var walletID int64

	err := h.queryRow(t, `
		INSERT INTO wallets (
			wallet_name, manager_version, manager_created_at,
			is_watch_only, master_pub_params, encrypted_crypto_pub_key
		) VALUES (?, 1, 1, TRUE, ?, ?)
		RETURNING id
	`, name, []byte{1}, []byte{2}).Scan(&walletID)
	require.NoError(t, err)

	h.exec(t, `
		INSERT INTO wallet_sync_states (
			wallet_id, start_block_id, synced_block_id,
			birthday_timestamp, birthday_block_verified
		) VALUES (
			?,
			(SELECT id FROM blocks WHERE header_hash = ?),
			(SELECT id FROM blocks WHERE header_hash = ?),
			1, FALSE
		)
	`, walletID, start.Hash[:], synced.Hash[:])

	return walletID
}

// putBlock stores one block fixture for a conformance case.
func (h *managerStoreHarness) putBlock(t *testing.T,
	block waddrmgr.BlockStamp) {

	t.Helper()
	h.exec(t, `
		INSERT INTO blocks (block_height, header_hash, block_timestamp)
		VALUES (?, ?, ?)
		ON CONFLICT (header_hash) DO NOTHING
	`, block.Height, block.Hash[:], block.Timestamp.Unix())
}

// seedScope creates a key scope and default account so chain and imported
// addresses can be inserted for a wallet fixture.
func (h *managerStoreHarness) seedScope(t *testing.T, store db.Store,
	scope waddrmgr.KeyScope, account uint32) {

	t.Helper()

	err := store.Update(context.Background(), func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		err := addr.PutKeyScope(waddrmgr.KeyScopeState{
			Scope:      scope,
			AddrSchema: waddrmgr.ScopeAddrMap[scope],
		})
		if err != nil {
			return err
		}

		return addr.PutAccount(waddrmgr.AccountState{
			Scope:           scope,
			Account:         account,
			Type:            waddrmgr.AccountDefault,
			Name:            "seed-account",
			EncryptedPubKey: []byte{1},
		})
	}, func() {})
	require.NoError(t, err)
}

// blockExists reports whether a block fixture still exists at height.
func (h *managerStoreHarness) blockExists(t *testing.T, height int32) bool {
	t.Helper()

	var count int64

	err := h.queryRow(t, `
		SELECT count(*) FROM blocks WHERE block_height = ?
	`, height).Scan(&count)
	require.NoError(t, err)

	return count == 1
}

// insertTransaction inserts the transaction row and all of its input
// dependencies.
func (h *managerStoreHarness) insertTransaction(t *testing.T, walletID int64,
	hash chainhash.Hash, height int32, order int64, coinbase bool) int64 {

	t.Helper()

	var transactionID int64

	err := h.queryRow(t, `
		INSERT INTO transactions (
			wallet_id, tx_hash, raw_tx, received_unix, block_id,
			confirmed_order, is_coinbase
		) VALUES (?, ?, ?, 1,
			(SELECT id FROM blocks WHERE block_height = ? ORDER BY id LIMIT 1),
			?, ?)
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
		INNER JOIN transactions AS tx ON tx.id = c.transaction_id
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

	if h.kv != nil {
		var height int32

		err := h.newStore(walletID).View(
			context.Background(), func(tx db.ReadTx) error {
				state, err := tx.Addr().SyncState()
				if err != nil {
					return err
				}

				height = state.SyncedTo.Height

				return nil
			}, func() {},
		)
		require.NoError(t, err)

		return height
	}

	var height int32

	err := h.queryRow(t, `
		SELECT b.block_height
		FROM wallet_sync_states AS s
		INNER JOIN blocks AS b ON b.id = s.synced_block_id
		WHERE s.wallet_id = ?
	`, walletID).Scan(&height)
	require.NoError(t, err)

	return height
}

// syncedBlockHash returns the header hash of the wallet's current synced block.
// The KV backend reads its recent-block index; the SQL backends read the block
// referenced by the wallet sync state so competing same-height blocks stay
// distinguishable.
func (h *managerStoreHarness) syncedBlockHash(t *testing.T,
	walletID int64) chainhash.Hash {

	t.Helper()

	if h.kv != nil {
		var hash chainhash.Hash

		err := h.newStore(walletID).View(
			context.Background(), func(tx db.ReadTx) error {
				state, err := tx.Addr().SyncState()
				if err != nil {
					return err
				}

				hash = state.SyncedTo.Hash

				return nil
			}, func() {},
		)
		require.NoError(t, err)

		return hash
	}

	var hashBytes []byte

	err := h.queryRow(t, `
		SELECT b.header_hash
		FROM wallet_sync_states AS s
		INNER JOIN blocks AS b ON b.id = s.synced_block_id
		WHERE s.wallet_id = ?
	`, walletID).Scan(&hashBytes)
	require.NoError(t, err)

	hash, err := chainhash.NewHash(hashBytes)
	require.NoError(t, err)

	return *hash
}

// blockCountAtHeight returns the number of block fixtures recorded at a height.
func (h *managerStoreHarness) blockCountAtHeight(t *testing.T,
	height int32) int {

	t.Helper()

	var count int

	err := h.queryRow(t, `
		SELECT count(*) FROM blocks WHERE block_height = ?
	`, height).Scan(&count)
	require.NoError(t, err)

	return count
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
		SELECT block_id IS NOT NULL FROM transactions WHERE id = ?
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
