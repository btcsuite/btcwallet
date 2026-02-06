package bwtest

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb" // Register bdb driver.
)

var (
	// ErrUnknownDBBackend is returned when an unknown db backend is requested.
	ErrUnknownDBBackend = errors.New("unknown db backend")
)

const (
	// dbNameKvdb is the identifier used for the kvdb wallet backend.
	dbNameKvdb = "kvdb"

	// kvdbDriver is the walletdb driver name used for kvdb.
	kvdbDriver = "bdb"

	// walletDBFilename is the default wallet database filename.
	walletDBFilename = "wallet.db"
)

// OpenWalletDB opens a wallet database instance rooted at baseDir.
//
// The returned cleanup function should be called to close the database.
func OpenWalletDB(dbType, baseDir string) (walletdb.DB, func() error, error) {
	switch dbType {
	case dbNameKvdb:
		dbPath := filepath.Join(baseDir, walletDBFilename)

		db, err := walletdb.Create(kvdbDriver, dbPath, true,
			defaultTestTimeout, false)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to create bdb instance: %w",
				err)
		}

		cleanup := func() error {
			return db.Close()
		}

		return db, cleanup, nil

	// TODO: Add sqlite and postgres support.
	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrUnknownDBBackend, dbType)
	}
}
