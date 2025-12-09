package db

import (
	"context"
	"database/sql"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// PostgresWalletDB is the PostgreSQL implementation of the
// WalletStore interface.
type PostgresWalletDB struct {
	db      *sql.DB
	queries *sqlcpg.Queries
}

// NewPostgresWalletDB creates a new PostgreSQL-based WalletStore.
func NewPostgresWalletDB(db *sql.DB) (*PostgresWalletDB, error) {
	if db == nil {
		return nil, ErrNilDB
	}

	return &PostgresWalletDB{
		db:      db,
		queries: sqlcpg.New(db),
	}, nil
}

// ExecuteTx executes a function within a database transaction. The function
// receives a transactional query executor and should perform all database
// operations using it. The transaction will be automatically committed on
// success or rolled back on error.
func (w *PostgresWalletDB) ExecuteTx(ctx context.Context,
	fn func(*sqlcpg.Queries) error) error {

	return execInTx(ctx, w.db, func(tx *sql.Tx) error {
		qtx := w.queries.WithTx(tx)
		return fn(qtx)
	})
}
