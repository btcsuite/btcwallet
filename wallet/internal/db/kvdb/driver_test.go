package kvdb

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// TestOpenStoreUninitializedDB verifies that opening a database with no
// waddrmgr namespace fails without closing it: the Manager owns the physical
// handle, so a failed open must leave it usable for the caller to close.
func TestOpenStoreUninitializedDB(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	_, _, err := OpenStore(Config{
		DB:          dbConn,
		ChainParams: &chaincfg.MainNetParams,
	})
	require.ErrorIs(t, err, errMissingAddrmgrNamespace)

	// The handle is still ours: a second attempt reaches the same failure
	// rather than a closed-database error.
	_, _, err = OpenStore(Config{
		DB:          dbConn,
		ChainParams: &chaincfg.MainNetParams,
	})
	require.ErrorIs(t, err, errMissingAddrmgrNamespace)
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
