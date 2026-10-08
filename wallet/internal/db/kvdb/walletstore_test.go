package kvdb

import (
	"bytes"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/stretchr/testify/require"
)

var (
	errInducedFailure          = errors.New("induced failure")
	errInducedVerificationStep = errors.New("induced verification-step failure")
)

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
