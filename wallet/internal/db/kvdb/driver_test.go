package kvdb

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// TestOpenStoreUninitializedDB verifies that opening a pristine database
// reports a missing wallet without closing it: the Manager owns the physical
// handle, so a failed open must leave it usable for the caller to close.
func TestOpenStoreUninitializedDB(t *testing.T) {
	t.Parallel()

	// Arrange a pristine caller-owned database with neither wallet
	// namespace initialized.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	// Act by opening the same pristine database twice. The second call
	// distinguishes a caller-owned handle from one closed by the first
	// failed open.
	_, _, firstErr := OpenStore(Config{
		DB:          dbConn,
		ChainParams: &chaincfg.MainNetParams,
	})
	_, _, secondErr := OpenStore(Config{
		DB:          dbConn,
		ChainParams: &chaincfg.MainNetParams,
	})

	// Assert that both opens report an absent wallet, proving the first
	// failure left the caller-owned database usable.
	require.ErrorIs(t, firstErr, db.ErrWalletNotFound)
	require.ErrorIs(t, secondErr, db.ErrWalletNotFound)
}

// TestOpenStoreIncompleteWallet verifies that a partially initialized wallet
// remains a backend error instead of being classified as an absent wallet.
func TestOpenStoreIncompleteWallet(t *testing.T) {
	t.Parallel()

	// Arrange a database containing only the address-manager namespace. This
	// lone namespace models partial or corrupt wallet state rather than a
	// wallet that was never created.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		_, err := tx.CreateTopLevelBucket(waddrmgr.NamespaceKey)

		return err
	})
	require.NoError(t, err, "failed to construct incomplete wallet state")

	// Act by asking the kvdb adapter to open the incomplete wallet state.
	_, _, err = OpenStore(Config{
		DB:          dbConn,
		ChainParams: &chaincfg.MainNetParams,
	})

	// Assert that the missing transaction-manager namespace remains a
	// backend error and is not collapsed into the absent-wallet sentinel.
	require.ErrorIs(t, err, errMissingTxmgrNamespace)
	require.NotErrorIs(t, err, db.ErrWalletNotFound)
}

// TestCreateWalletThenOpenStore verifies the create/open round trip on one
// caller-owned database, which is the sequence Manager.Create performs.
func TestCreateWalletThenOpenStore(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	cfg := Config{
		DB:          dbConn,
		ChainParams: &chaincfg.MainNetParams,
	}

	// cfg carries the public passphrase for both the create and the later
	// Open, so the round trip uses one credential carrier.
	err := CreateWallet(cfg, CreateWalletRequest{
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	})
	require.NoError(t, err)

	store, addrMgr, err := OpenStore(cfg)
	require.NoError(t, err)
	require.NotNil(t, store)
	require.NotNil(t, addrMgr)
	t.Cleanup(addrMgr.Close)

	// A nil root key creates a watch-only wallet, which is what the address
	// manager must report back.
	require.True(t, addrMgr.WatchOnly())
}
