package wallet

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	storesqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
)

// SQLiteLoaderConfig holds the public settings for a Store-backed SQLite
// wallet loader.
type SQLiteLoaderConfig struct {
	// DBPath is the path to the SQLite database file.
	DBPath string

	// WalletName is the durable identity of the wallet within the database.
	WalletName string

	// BusyTimeout is the time SQLite waits for a locked database.
	BusyTimeout time.Duration

	// MaxConnections is the maximum number of open connections.
	MaxConnections int

	// MaxIdleConnections is the maximum number of idle connections.
	MaxIdleConnections int

	// ConnectionLifetime bounds connection reuse in the pool.
	ConnectionLifetime time.Duration

	// Pragmas contains additional SQLite pragma settings.
	Pragmas []string
}

// NewSQLiteLoader opens a Store-backed SQLite wallet loader and applies the
// embedded btcwallet schema. The returned Loader owns the connection pool.
// UnloadWallet closes it after a wallet is loaded; callers must use Close when
// abandoning the loader before a wallet is loaded.
func NewSQLiteLoader(ctx context.Context, chainParams *chaincfg.Params,
	recoveryWindow uint32, cfg SQLiteLoaderConfig,
	opts ...LoaderOption) (*Loader, error) {

	if cfg.WalletName == "" {
		return nil, errors.New("wallet name is required")
	}

	conn, err := storesqlite.Open(ctx, storesqlite.Config{
		DBPath:             cfg.DBPath,
		BusyTimeout:        cfg.BusyTimeout,
		MaxConnections:     cfg.MaxConnections,
		MaxIdleConnections: cfg.MaxIdleConnections,
		ConnectionLifetime: cfg.ConnectionLifetime,
		Pragmas:            cfg.Pragmas,
	})
	if err != nil {
		return nil, err
	}

	if err := storesqlite.ApplyMigrations(conn); err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("apply SQLite wallet schema: %w", err)
	}

	store := dbsqlite.NewNamedStore(conn, cfg.WalletName)
	loader, err := NewLoaderWithStore(
		chainParams, recoveryWindow, store, opts...,
	)
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	loader.storeClose = conn.Close

	return loader, nil
}
