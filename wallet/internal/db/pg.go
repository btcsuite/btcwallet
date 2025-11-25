package db

import (
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
