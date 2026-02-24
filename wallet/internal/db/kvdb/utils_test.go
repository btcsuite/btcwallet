package kvdb

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

const defaultDBTimeout = 10 * time.Second

// newTestDB creates a temporary bdb walletdb for kvdb store tests.
//
// It returns the opened database and a cleanup function that must be called
// after the test completes.
func newTestDB(t *testing.T) (walletdb.DB, func()) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "wallet.db")

	dbConn, err := walletdb.Create(
		"bdb", dbPath, true, defaultDBTimeout, false,
	)
	require.NoError(t, err)

	cleanup := func() {
		_ = dbConn.Close()
	}

	return dbConn, cleanup
}

// newTxStore initializes and opens a wtxmgr store in the test database.
//
// NOTE: The kvdb Store under test expects the walletdb top-level bucket key
// `wtxmgrNamespaceKey` to exist and contain a valid wtxmgr store.
func newTxStore(t *testing.T, dbConn walletdb.DB) *wtxmgr.Store {
	t.Helper()

	var txStore *wtxmgr.Store

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if err != nil {
			return err
		}

		err = wtxmgr.Create(ns)
		if err != nil {
			return err
		}

		txStore, err = wtxmgr.Open(ns, &chaincfg.RegressionNetParams)

		return err
	})
	require.NoError(t, err)

	return txStore
}
