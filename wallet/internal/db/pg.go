package db

import (
	"context"
	"database/sql"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// PostgresStore is the PostgreSQL implementation of the
// WalletStore interface.
type PostgresStore struct {
	db      *sql.DB
	queries *sqlcpg.Queries
}

// NewPostgresStore creates a new PostgreSQL-based WalletStore.
func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, ErrNilDB
	}

	return &PostgresStore{
		db:      db,
		queries: sqlcpg.New(db),
	}, nil
}

// ExecuteTx executes a function within a database transaction. The function
// receives a transactional query executor and should perform all database
// operations using it. The transaction will be automatically committed on
// success or rolled back on error.
func (w *PostgresStore) ExecuteTx(ctx context.Context,
	fn func(*sqlcpg.Queries) error) error {

	return execInTx(ctx, w.db, func(tx *sql.Tx) error {
		qtx := w.queries.WithTx(tx)
		return fn(qtx)
	})
}
