package kvdb

import (
	"bytes"
	"errors"
	"math"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	errInducedFailure          = errors.New("induced failure")
	errInducedVerificationStep = errors.New("induced verification-step failure")
)

// watchViewDB lets the snapshot regression control when Bolt commits relative
// to opening the read view.
type watchViewDB struct {
	walletdb.DB
	mock.Mock
}

// watchViewDB implements walletdb.DB for the snapshot regression.
var _ walletdb.DB = (*watchViewDB)(nil)

// View invokes the arranged callback to control the real Bolt view.
func (m *watchViewDB) View(
	read func(walletdb.ReadTx) error, reset func()) error {

	args := m.Called(read, reset)

	//nolint:forcetypeassert // The sole View expectation owns this return type.
	view := args.Get(0).(func(func(walletdb.ReadTx) error, func()) error)

	return view(read, reset)
}

// TestLoadWatchSetScopeSnapshot verifies that publishing a new scope while a
// read is open does not make that older read fail.
func TestLoadWatchSetScopeSnapshot(t *testing.T) {
	t.Parallel()

	// Arrange: Open a wallet with no watch data and reserve Bolt pages so
	// the overlapping scope commit can finish without growing its mmap.
	baseStore, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	conn := baseStore.db
	txStore := newTxStore(t, conn)

	const scopeCommitReserve = 512 << 10

	err := walletdb.Update(conn, func(tx walletdb.ReadWriteTx) error {
		pad, err := tx.CreateTopLevelBucket([]byte("watch-view-reserve"))
		if err != nil {
			return err
		}

		return pad.Put([]byte("reserve"), make([]byte, scopeCommitReserve))
	})
	require.NoError(t, err)

	// Commit a new scope after Bolt opens the reader. Its live manager is
	// therefore visible by the time LoadWatchSet starts traversing rows.
	writeScope := func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		schema := waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084]
		_, err := mgr.NewScopedKeyManager(
			ns, waddrmgr.KeyScope{Purpose: 1017}, schema,
		)

		return err
	}
	view := func(read func(walletdb.ReadTx) error, reset func()) error {
		return conn.View(func(snapshot walletdb.ReadTx) error {
			err := walletdb.Update(conn, writeScope)
			if err != nil {
				return err
			}

			return read(snapshot)
		}, reset)
	}
	viewDB := &watchViewDB{DB: conn}
	viewDB.On("View", mock.Anything, mock.Anything).Return(view).Once()
	t.Cleanup(func() {
		viewDB.AssertExpectations(t)
	})

	store := NewStore(viewDB, txStore, mgr)

	// Act: Read the watch set from the view that predates the commit.
	watches, err := store.LoadWatchSet(t.Context(), 0)

	// Assert: The earlier view is valid and observes the empty wallet.
	require.NoError(t, err)
	require.Empty(t, watches.AddressScripts)
	require.Empty(t, watches.OutPoints)
}

// TestResolveOwnedAddressesScopeSnapshot excludes cached imports committed
// after a read view opens, whether their scope already existed or is new.
func TestResolveOwnedAddressesScopeSnapshot(t *testing.T) {
	t.Parallel()

	// Arrange: Reserve pages before opening the view, so publishing a scope
	// inside its callback needs no mmap growth while Bolt retains the reader.
	baseStore, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	conn := baseStore.db
	keys := make([]*btcec.PublicKey, 2)
	scripts := make([][]byte, 0, len(keys))

	// Both imports populate live caches after the old view opens. Separate
	// keys distinguish a missing address row from an entirely missing scope.
	for i := range keys {
		key, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		keys[i] = key.PubKey()
		addr, err := address.NewAddressWitnessPubKeyHash(
			address.Hash160(keys[i].SerializeCompressed()),
			mgr.ChainParams(),
		)
		require.NoError(t, err)

		pkScript, err := txscript.PayToAddrScript(addr)
		require.NoError(t, err)

		scripts = append(scripts, pkScript)
	}

	err := walletdb.Update(conn, func(tx walletdb.ReadWriteTx) error {
		pad, err := tx.CreateTopLevelBucket([]byte("ownership-view-reserve"))
		if err != nil {
			return err
		}

		return pad.Put([]byte("reserve"), make([]byte, 512<<10))
	})
	require.NoError(t, err)

	// The first scope exists in the old snapshot without its imported row;
	// the second scope and its imported row are both absent from that view.
	writeScope := func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		existing, err := mgr.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
		if err != nil {
			return err
		}

		schema := waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084]

		created, err := mgr.NewScopedKeyManager(
			ns, waddrmgr.KeyScope{Purpose: 1017}, schema,
		)
		if err != nil {
			return err
		}

		for i, scoped := range []waddrmgr.AccountStore{existing, created} {
			_, err := scoped.ImportPublicKey(ns, keys[i], nil)
			if err != nil {
				return err
			}
		}

		return nil
	}
	view := func(read func(walletdb.ReadTx) error, reset func()) error {
		return conn.View(func(snapshot walletdb.ReadTx) error {
			err := walletdb.Update(conn, writeScope)
			if err != nil {
				return err
			}

			return read(snapshot)
		}, reset)
	}
	viewDB := &watchViewDB{
		DB: conn,
	}
	viewDB.On("View", mock.Anything, mock.Anything).Return(view).Once()
	t.Cleanup(func() {
		viewDB.AssertExpectations(t)
	})

	store := NewStore(viewDB, nil, mgr)

	// Act: Resolve both cached imports through the view that predates
	// their rows and the new scope's publication.
	owned, err := store.ResolveOwnedAddresses(
		t.Context(), db.ResolveOwnedAddressesQuery{
			ScriptPubKeys: scripts,
		},
	)

	// Assert: Neither cached import is owned in the earlier view. A fresh
	// view sees both, proving that old-view absence is snapshot isolation.
	require.NoError(t, err)
	require.Empty(t, owned)
	current, err := NewStore(conn, nil, mgr).ResolveOwnedAddresses(
		t.Context(), db.ResolveOwnedAddressesQuery{
			ScriptPubKeys: scripts,
		},
	)
	require.NoError(t, err)
	require.Len(t, current, 2)

	for _, script := range scripts {
		require.Contains(t, current, string(script))
	}
}

// newSpendableAddrMgr creates a fresh waddrmgr-backed wallet on top of a new
// temporary walletdb and returns the open *waddrmgr.Manager. The wallet uses
// fixed pub/priv passphrases and a deterministic seed so derived results stay
// reproducible across test runs.
func newSpendableAddrMgr(t *testing.T,
	dbConn walletdb.DB) *waddrmgr.Manager {

	t.Helper()

	const (
		pubPass  = "pub"
		privPass = "priv"
	)

	seed := bytes.Repeat([]byte{0x5A}, hdkeychain.RecommendedSeedLen)

	rootKey, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)

	var mgr *waddrmgr.Manager

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket(waddrmgr.NamespaceKey)
		if err != nil {
			return err
		}

		err = waddrmgr.Create(
			ns, rootKey, []byte(pubPass), []byte(privPass),
			&chaincfg.SimNetParams, &waddrmgr.FastScryptOptions,
			time.Time{},
		)
		if err != nil {
			return err
		}

		mgr, err = waddrmgr.Open(
			ns, []byte(pubPass), &chaincfg.SimNetParams,
		)

		return err
	})
	require.NoError(t, err)

	return mgr
}

// newAddrStore creates a spendable legacy address store for kvdb tests.
func newAddrStore(t *testing.T, dbConn walletdb.DB) *waddrmgr.Manager {
	t.Helper()

	return newSpendableAddrMgr(t, dbConn)
}

// someBlock returns deterministic block metadata for wallet-store tests.
func someBlock(t *testing.T, height uint32) *db.Block {
	t.Helper()

	var hash chainhash.Hash

	hash[0] = byte(height)
	hash[1] = byte(height >> 8)
	hash[2] = byte(height >> 16)
	hash[3] = byte(height >> 24)
	hash[4] = 0x42

	return &db.Block{
		Hash:      hash,
		Height:    height,
		Timestamp: time.Unix(int64(height)*600, 0).UTC(),
	}
}

// failingAddrStore injects SetBirthdayBlock failures after allowing other
// address-manager mutations to use the embedded real manager.
type failingAddrStore struct {
	*waddrmgr.Manager

	failBeforePut bool
}

// SetBirthdayBlock injects a clean or partial birthday-block write failure.
func (f *failingAddrStore) SetBirthdayBlock(ns walletdb.ReadWriteBucket,
	block waddrmgr.BlockStamp, _ bool) error {

	if f.failBeforePut {
		return errInducedFailure
	}

	err := waddrmgr.PutBirthdayBlock(ns, block)
	if err != nil {
		return err
	}

	return errInducedVerificationStep
}

// newWalletStoreTestSetup builds a kvdb.Store hooked up to a freshly
// created spendable waddrmgr wallet for the wallet-store master-key tests.
func newWalletStoreTestSetup(t *testing.T) (*Store, func()) {
	t.Helper()

	dbConn, cleanup := newTestDB(t)
	mgr := newSpendableAddrMgr(t, dbConn)

	cleanupAll := func() {
		mgr.Close()
		cleanup()
	}

	return NewStore(dbConn, nil, mgr), cleanupAll
}

// TestGetEncryptedHDSeed verifies that GetEncryptedHDSeed returns the
// encrypted master HD private key bytes for a spendable wallet (i.e. the
// bucket value is non-empty and differs from the plaintext extended key).
func TestGetEncryptedHDSeed(t *testing.T) {
	t.Parallel()

	store, cleanup := newWalletStoreTestSetup(t)
	t.Cleanup(cleanup)

	encrypted, err := store.GetEncryptedHDSeed(t.Context(), 0)
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)
}

// TestListSyncedBlocksReadsTip verifies that ListSyncedBlocks adapts a
// legacy synced-to block into the db-native block shape.
func TestListSyncedBlocksReadsTip(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	mgr := newSpendableAddrMgr(t, dbConn)
	t.Cleanup(mgr.Close)

	wantHash := chainhash.Hash{1, 2, 3}
	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		return mgr.SetSyncedTo(ns, &waddrmgr.BlockStamp{
			Hash:   wantHash,
			Height: 7,
		})
	})
	require.NoError(t, err)

	store := NewStore(dbConn, nil, mgr)
	blocks, err := store.ListSyncedBlocks(
		t.Context(), db.ListSyncedBlocksQuery{
			StartHeight: 7,
			EndHeight:   7,
		},
	)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, wantHash, blocks[0].Hash)
	require.Equal(t, uint32(7), blocks[0].Height)
}

// TestListSyncedBlocksNormalizesMissingHeight verifies that callers can
// recognize absent legacy history through the shared Store error contract.
func TestListSyncedBlocksNormalizesMissingHeight(t *testing.T) {
	t.Parallel()

	// Arrange: Persist a tip at seven without recording height six, using
	// the real legacy manager so the read produces its native missing error.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	mgr := newSpendableAddrMgr(t, dbConn)
	t.Cleanup(mgr.Close)

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		return mgr.SetSyncedTo(ns, &waddrmgr.BlockStamp{
			Hash:   chainhash.Hash{7},
			Height: 7,
		})
	})
	require.NoError(t, err)

	store := NewStore(dbConn, nil, mgr)

	// Act: Request a range whose first height was never recorded, rather
	// than treating the recorded endpoint as proof of a contiguous history.
	_, err = store.ListSyncedBlocks(t.Context(), db.ListSyncedBlocksQuery{
		StartHeight: 6,
		EndHeight:   7,
	})

	// Assert: Recovery callers see the Store sentinel without depending on
	// the concrete address-manager error type.
	require.ErrorIs(t, err, db.ErrBlockNotFound)
}

// TestListSyncedBlocksRejectsFullUint32Range verifies kvdb rejects a
// full-width height range before the inclusive span wraps or iteration starts.
func TestListSyncedBlocksRejectsFullUint32Range(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	mgr := newSpendableAddrMgr(t, dbConn)
	t.Cleanup(mgr.Close)

	store := NewStore(dbConn, nil, mgr)
	_, err := store.ListSyncedBlocks(
		t.Context(), db.ListSyncedBlocksQuery{
			StartHeight: 0,
			EndHeight:   math.MaxUint32,
		},
	)
	require.ErrorIs(t, err, db.ErrCastingOverflow)
}

// TestGetWalletReadsLegacyMetadata verifies that kvdb.Store adapts legacy
// wallet metadata into the db-native wallet view.
func TestGetWalletReadsLegacyMetadata(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	info, err := store.GetWallet(t.Context(), "default")
	require.NoError(t, err)
	require.Equal(t, uint32(0), info.ID)
	require.Equal(t, "default", info.Name)
	require.Equal(t, addrStore.Birthday().UTC(), info.Birthday)
	require.Nil(t, info.BirthdayBlock)
	require.False(t, info.IsWatchOnly)
}

// TestGetWalletReportsWatchOnly verifies kvdb.Store reports legacy wallet-level
// watch-only state.
func TestGetWalletReportsWatchOnly(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	convertAddrStoreToWatchOnly(t, dbConn, addrStore)
	store := NewStore(dbConn, nil, addrStore)

	info, err := store.GetWallet(t.Context(), "default")
	require.NoError(t, err)
	require.True(t, info.IsWatchOnly)
}

// TestGetWalletKvdbIgnoresName documents that kvdb echoes the requested
// wallet name because it is a single-wallet legacy backend.
func TestGetWalletKvdbIgnoresName(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	info, err := store.GetWallet(t.Context(), "any-name")
	require.NoError(t, err)
	require.Equal(t, "any-name", info.Name)

	info, err = store.GetWallet(t.Context(), "different-name")
	require.NoError(t, err)
	require.Equal(t, "different-name", info.Name)
}

// TestGetWalletMissingAddrStore verifies that GetWallet reports a helpful
// error when the legacy address manager is unavailable.
func TestGetWalletMissingAddrStore(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	store := NewStore(dbConn, nil, nil)

	_, err := store.GetWallet(t.Context(), "default")
	require.ErrorContains(t, err, "missing legacy addr store")
}

// TestUpdateWalletWritesLegacyMetadata verifies that kvdb.Store writes wallet
// metadata through the legacy address manager.
func TestUpdateWalletWritesLegacyMetadata(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	birthday := time.Unix(123, 0).UTC()
	birthdayBlock := &db.Block{
		Hash:      chainhash.Hash{1},
		Height:    0,
		Timestamp: time.Unix(456, 0).UTC(),
	}
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID:      0,
		Birthday:      &birthday,
		BirthdayBlock: birthdayBlock,
		SyncedTo:      birthdayBlock,
	})
	require.NoError(t, err)

	info, err := store.GetWallet(t.Context(), "default")
	require.NoError(t, err)
	require.Equal(t, birthday, info.Birthday)
	require.Equal(t, birthdayBlock, info.BirthdayBlock)
	require.Equal(t, birthdayBlock, info.SyncedTo)
}

// TestUpdateWalletBirthdayBlockAndSyncedToTogether verifies non-zero initial
// birthday block and synced-to writes can land in one kvdb update.
func TestUpdateWalletBirthdayBlockAndSyncedToTogether(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	birthdayBlock := someBlock(t, 100)
	syncedTo := someBlock(t, 101)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		BirthdayBlock: birthdayBlock,
		SyncedTo:      syncedTo,
	})
	require.NoError(t, err)

	info, err := store.GetWallet(t.Context(), "default")
	require.NoError(t, err)
	require.Equal(t, birthdayBlock, info.BirthdayBlock)
	require.Equal(t, syncedTo, info.SyncedTo)
}

// TestUpdateWalletKvdbIgnoresWalletID documents that kvdb applies updates to
// the single legacy wallet regardless of the requested WalletID.
func TestUpdateWalletKvdbIgnoresWalletID(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	birthday := time.Date(2021, 6, 15, 0, 0, 0, 0, time.UTC)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: 99999,
		Birthday: &birthday,
	})
	require.NoError(t, err)

	info, err := store.GetWallet(t.Context(), "default")
	require.NoError(t, err)
	require.Equal(t, birthday, info.Birthday)
}

// TestUpdateWalletRollsBackInMemoryBirthdayOnError verifies validation errors
// do not leave the legacy manager's birthday cache ahead of the transaction.
func TestUpdateWalletRollsBackInMemoryBirthdayOnError(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	initial := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		Birthday: &initial,
	})
	require.NoError(t, err)

	newBirthday := time.Date(2021, 6, 15, 0, 0, 0, 0, time.UTC)
	badBlock := &db.Block{
		Height:    uint32(math.MaxInt32) + 1,
		Hash:      chainhash.Hash{},
		Timestamp: time.Now(),
	}
	err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		Birthday:      &newBirthday,
		BirthdayBlock: badBlock,
	})
	require.Error(t, err)
	require.Equal(t, initial, addrStore.Birthday())
}

// TestUpdateWalletRollsBackAfterPartialMutation verifies in-memory birthday
// and synced-to caches are restored when a later birthday-block write fails.
func TestUpdateWalletRollsBackAfterPartialMutation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		failBeforePut bool
	}{
		{name: "clean failure", failBeforePut: true},
		{name: "partial write", failBeforePut: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			runPartialMutationRollback(t, tc.failBeforePut, 0)
		})
	}
}

// TestUpdateWalletRollsBackAfterPartialMutationNonZeroSync verifies rollback
// clears transient birthday-block state before restoring a non-zero sync tip.
func TestUpdateWalletRollsBackAfterPartialMutationNonZeroSync(t *testing.T) {
	t.Parallel()

	runPartialMutationRollback(t, false, 50)
}

// runPartialMutationRollback drives the injected birthday-block failure flow
// and asserts that in-memory manager caches return to their original values.
func runPartialMutationRollback(t *testing.T, failBeforePut bool,
	initialHeight uint32) {

	t.Helper()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	realMgr := newSpendableAddrMgr(t, dbConn)
	addrStore := &failingAddrStore{
		Manager:       realMgr,
		failBeforePut: failBeforePut,
	}
	store := NewStore(dbConn, nil, addrStore)

	initial := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	initialSync := someBlock(t, initialHeight)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		Birthday: &initial,
		SyncedTo: initialSync,
	})
	require.NoError(t, err)

	newBirthday := time.Date(2021, 6, 15, 0, 0, 0, 0, time.UTC)
	newSync := someBlock(t, initialHeight+100)
	err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		Birthday:      &newBirthday,
		SyncedTo:      newSync,
		BirthdayBlock: newSync,
	})
	require.Error(t, err)

	require.Equal(t, initial, realMgr.Birthday())
	require.Equal(t, initialSync.Hash, realMgr.SyncedTo().Hash)
	require.Equal(t, initialSync.Height, uint32(realMgr.SyncedTo().Height))
}

// TestUpdateWalletMissingAddrStore verifies that UpdateWallet reports a
// helpful error when the legacy address manager is unavailable.
func TestUpdateWalletMissingAddrStore(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	store := NewStore(dbConn, nil, nil)

	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{})
	require.ErrorContains(t, err, "missing legacy addr store")
}

// expectReadReplay arranges a Store whose next View reads two snapshots.
// An optional write between attempts can change the winning result.
func expectReadReplay(t *testing.T, store *Store, between func()) *Store {
	t.Helper()

	view := func(read func(walletdb.ReadTx) error, reset func()) error {
		err := store.db.View(read, reset)
		if err != nil {
			return err
		}

		// The driver releases the first snapshot before retrying.
		if between != nil {
			between()
		}

		return store.db.View(read, reset)
	}
	reader := &watchViewDB{DB: store.db}
	reader.On("View", mock.Anything, mock.Anything).Return(view).Once()
	t.Cleanup(func() { reader.AssertExpectations(t) })

	return NewStore(reader, store.txStore, store.addrStore)
}

// TestStoreReadRetry checks that each legacy read returns only rows and
// metadata from the winning transaction when a driver replays its callback.
func TestStoreReadRetry(t *testing.T) {
	t.Parallel()

	// Arrange one imported credit that the UTXO, history and watch
	// queries can each identify independently after a replay.
	const height = 144

	scope := waddrmgr.KeyScopeBIP0084
	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	creditImportedKeyAtHeight(
		t, store.db, mgr, txStore, scope, 70000, height,
	)

	t.Run("unspent outputs", func(t *testing.T) {
		t.Parallel()

		// Arrange two snapshots containing the same unspent credit.
		reader := expectReadReplay(t, store, nil)

		// Act by listing all available outputs through the replay.
		rows, err := reader.ListUTXOs(t.Context(), db.ListUtxosQuery{})

		// Assert the outpoint contributes exactly one spendable row.
		require.NoError(t, err)
		require.Len(t, rows, 1)
	})

	t.Run("transaction details", func(t *testing.T) {
		t.Parallel()

		// Arrange a history query for the block containing the credit.
		reader := expectReadReplay(t, store, nil)
		query := db.ListTxDetailsQuery{
			StartHeight: height,
			EndHeight:   height,
		}

		// Act by reading its mined transaction in both snapshots.
		rows, err := reader.ListTxDetails(t.Context(), query)

		// Assert the transaction appears once at its queried height.
		require.NoError(t, err)
		require.Len(t, rows, 1)
	})

	t.Run("startup watches", func(t *testing.T) {
		t.Parallel()

		// Arrange one script and one outpoint from the imported credit.
		want, err := store.LoadWatchSet(t.Context(), 0)
		require.NoError(t, err)
		require.Len(t, want.AddressScripts, 1)
		require.Len(t, want.OutPoints, 1)
		reader := expectReadReplay(t, store, nil)

		// Act by loading the interests registered during startup.
		got, err := reader.LoadWatchSet(t.Context(), 0)

		// Assert neither collection retains the first attempt's rows.
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("raw imported addresses", func(t *testing.T) {
		t.Parallel()

		// Arrange one import in each snapshot and a second import that
		// becomes visible when the new scope commits between attempts.
		store, mgr, txs, cleanup := newCreditedFixture(t)
		t.Cleanup(cleanup)
		creditImportedKeyAtHeight(
			t, store.db, mgr, txs, scope, 70000, height,
		)
		derive := kvdbDeriveFnFixture(t, mgr)
		custom := waddrmgr.KeyScope{Purpose: 1017, Coin: 1}
		reader := expectReadReplay(t, store, func() {
			schema := db.ScopeAddrMap[db.KeyScope(scope)]
			zero := uint32(0)
			params := db.CreateDerivedAccountParams{
				Scope:         db.KeyScope(custom),
				Name:          "family zero",
				AddrSchema:    &schema,
				AccountNumber: &zero,
			}
			_, err := store.CreateDerivedAccount(
				t.Context(), params, derive,
			)
			require.NoError(t, err)
			creditImportedKeyAtHeight(
				t, store.db, mgr, txs, custom,
				70001, height+1,
			)
		})
		request, err := page.NewRequest[uint32](3)
		require.NoError(t, err)

		query := db.ListAddressesQuery{Page: request}

		// Act by listing imports across all published scopes.
		result, err := reader.ListAddresses(t.Context(), query)

		// Assert the page matches a fresh listing of both imports,
		// including its cursor and the identity of each address.
		require.NoError(t, err)
		want, err := store.ListAddresses(t.Context(), query)
		require.NoError(t, err)
		require.Len(t, want.Items, 2)
		require.Equal(t, want, result)
	})

	t.Run("accounts", func(t *testing.T) {
		t.Parallel()

		// Arrange a name that moves to a funded account between reads.
		const amount = 70000

		store, mgr, txs, closeDB := newCreditedFixture(t)
		t.Cleanup(closeDB)

		name := "match"
		first := createDerivedAccount(t, store.db, mgr, scope, name)
		winner := createDerivedAccount(
			t, store.db, mgr, scope, "funded",
		)
		creditNextAccountAddress(
			t, store.db, mgr, txs, scope, winner, amount,
		)

		reader := expectReadReplay(t, store, func() {
			rename := db.RenameAccountParams{
				Scope:         db.KeyScope(scope),
				AccountNumber: &first,
				NewName:       "former",
			}
			err := store.RenameAccount(t.Context(), rename)
			require.NoError(t, err)

			rename.AccountNumber = &winner
			rename.NewName = name
			err = store.RenameAccount(t.Context(), rename)
			require.NoError(t, err)
		})

		// Act by querying the named account with balances.
		query := db.ListAccountsQuery{Name: &name}
		rows, err := reader.ListAccounts(t.Context(), query)

		// Assert the winning account has its own number and balance.
		require.NoError(t, err)
		require.Len(t, rows, 1)
		require.Equal(t, &winner, rows[0].AccountNumber)
		require.EqualValues(t, amount, rows[0].ConfirmedBalance)
	})

	t.Run("owned address metadata", func(t *testing.T) {
		t.Parallel()

		// Arrange an account rename between reads of its script.
		store, mgr, _, cleanup := newCreditedFixture(t)
		t.Cleanup(cleanup)
		createDerivedAccount(t, store.db, mgr, scope, "before")
		params := db.NewDerivedAddressParams{
			Scope:       db.KeyScope(scope),
			AccountName: "before",
		}
		addr, err := store.NewDerivedAddress(t.Context(), params)
		require.NoError(t, err)
		reader := expectReadReplay(t, store, func() {
			rename := db.RenameAccountParams{
				Scope:   db.KeyScope(scope),
				OldName: "before",
				NewName: "after",
			}
			err := store.RenameAccount(t.Context(), rename)
			require.NoError(t, err)
		})

		// Act by resolving the same script across the rename.
		query := db.ResolveOwnedAddressesQuery{
			ScriptPubKeys: [][]byte{addr.ScriptPubKey},
		}
		owned, err := reader.ResolveOwnedAddresses(t.Context(), query)

		// Assert the script resolves to the renamed account.
		require.NoError(t, err)

		info := owned[string(addr.ScriptPubKey)]
		require.NotNil(t, info)
		require.Equal(t, "after", info.AccountName)
	})

	t.Run("birthday verification", func(t *testing.T) {
		t.Parallel()

		// Arrange a birthday that loses verification between attempts.
		store, mgr, _, cleanup := newCreditedFixture(t)
		t.Cleanup(cleanup)

		block := mgr.SyncedTo()
		writeBirthdayBlock(t, store.db, mgr, block, true)
		reader := expectReadReplay(t, store, func() {
			writeBirthdayBlock(t, store.db, mgr, block, false)
		})

		// Act by reading the birthday metadata used during startup.
		info, err := reader.GetWallet(t.Context(), "")

		// Assert startup sees the need to verify the birthday on chain.
		require.NoError(t, err)
		require.Nil(t, info.BirthdayBlock)
	})
}

// TestListAddressesOlderScopeSnapshot checks that a newly published scope
// cannot invalidate a raw-address listing against an earlier snapshot.
func TestListAddressesOlderScopeSnapshot(t *testing.T) {
	t.Parallel()

	// Arrange an older database containing one import. Saving its pages
	// lets the live manager publish another scope without blocking Bolt.
	store, mgr, txs, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	creditImportedKeyAtHeight(t, store.db, mgr, txs, scope, 70000, 144)

	request, err := page.NewRequest[uint32](3)
	require.NoError(t, err)

	query := db.ListAddressesQuery{Page: request}
	want, err := store.ListAddresses(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, want.Items, 1)

	file, err := os.CreateTemp(t.TempDir(), "snapshot-*.db")
	require.NoError(t, err)

	copyErr := store.db.Copy(file)
	require.NoError(t, file.Close())
	require.NoError(t, copyErr)

	schema := db.ScopeAddrMap[db.KeyScope(scope)]
	zero := uint32(0)
	params := db.CreateDerivedAccountParams{
		Scope:         db.KeyScope{Purpose: 1017, Coin: 1},
		Name:          "family zero",
		AddrSchema:    &schema,
		AccountNumber: &zero,
	}
	_, err = store.CreateDerivedAccount(
		t.Context(), params, kvdbDeriveFnFixture(t, mgr),
	)
	require.NoError(t, err)

	snapshot, err := walletdb.Open(
		"bdb", file.Name(), true, defaultDBTimeout, false,
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, snapshot.Close()) })

	reader := NewStore(snapshot, txs, mgr)

	// Act through the live manager using only the saved snapshot's rows.
	got, err := reader.ListAddresses(t.Context(), query)

	// Assert the missing scope leaves the original address readable.
	require.NoError(t, err)
	require.Equal(t, want, got)
}
