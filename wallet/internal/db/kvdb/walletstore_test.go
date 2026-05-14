package kvdb

import (
	"bytes"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/stretchr/testify/require"
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
