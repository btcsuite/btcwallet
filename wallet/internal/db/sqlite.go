package db

import (
	"context"
	"database/sql"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// SqliteStore is the SQLite implementation of the WalletStore interface.
type SqliteStore struct {
	db      *sql.DB
	queries *sqlcsqlite.Queries
}

// NewSqliteStore creates a new SQLite-based WalletStore.
func NewSqliteStore(db *sql.DB) (*SqliteStore, error) {
	if db == nil {
		return nil, ErrNilDB
	}

	return &SqliteStore{
		db:      db,
		queries: sqlcsqlite.New(db),
	}, nil
}

// ExecuteTx executes a function within a database transaction. The function
// receives a transactional query executor and should perform all database
// operations using it. The transaction will be automatically committed on
// success or rolled back on error.
func (w *SqliteStore) ExecuteTx(ctx context.Context,
	fn func(*sqlcsqlite.Queries) error) error {

	return execInTx(ctx, w.db, func(tx *sql.Tx) error {
		qtx := w.queries.WithTx(tx)
		return fn(qtx)
	})
}
