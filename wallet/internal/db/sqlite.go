package db

import (
	"context"
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

// ExecuteTx executes a function within a database transaction. The function
// receives a transactional query executor and should perform all database
// operations using it. The transaction will be automatically committed on
// success or rolled back on error.
func (w *SQLiteWalletDB) ExecuteTx(ctx context.Context,
	fn func(*sqlcsqlite.Queries) error) error {

	return execInTx(ctx, w.db, func(tx *sql.Tx) error {
		qtx := w.queries.WithTx(tx)
		return fn(qtx)
	})
}
