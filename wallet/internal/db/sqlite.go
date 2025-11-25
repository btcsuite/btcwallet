package db

import (
	"database/sql"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// SQLiteWalletDB is the SQLite implementation of the WalletStore interface.
type SQLiteWalletDB struct {
	db      *sql.DB
	queries *sqlcsqlite.Queries
}

// NewSQLiteWalletDB creates a new SQLite-based WalletStore.
func NewSQLiteWalletDB(db *sql.DB) (*SQLiteWalletDB, error) {
	if db == nil {
		return nil, ErrNilDB
	}

	return &SQLiteWalletDB{
		db:      db,
		queries: sqlcsqlite.New(db),
	}, nil
}
