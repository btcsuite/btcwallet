package kvdb

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb" // Register bdb.
	"github.com/btcsuite/btcwallet/wtxmgr"
)

const (
	// defaultStoreTimeout is the walletdb open/create timeout used when a
	// Config leaves Timeout unset.
	defaultStoreTimeout = 60 * time.Second

	// defaultDBDirPerm is the permission applied to the directory created
	// for the walletdb file.
	defaultDBDirPerm = 0o700
)

// errMissingDBPath is returned when a kvdb Config has no DBPath.
var errMissingDBPath = errors.New("missing kvdb DBPath")

// Config holds the filesystem-backed kvdb wallet configuration.
type Config struct {
	// DBPath is the filesystem path to the walletdb database file.
	DBPath string

	// NoFreelistSync controls bbolt freelist synchronization.
	NoFreelistSync bool

	// Timeout is the walletdb open/create timeout. A zero value uses the
	// default timeout.
	Timeout time.Duration
}

// OpenStoreParams holds the inputs needed to load a legacy kvdb wallet store.
type OpenStoreParams struct {
	// PubPassphrase is the public passphrase used by waddrmgr.
	PubPassphrase []byte

	// ChainParams identifies the wallet chain parameters.
	ChainParams *chaincfg.Params
}

// StoreHandle is an opened kvdb wallet store and its legacy manager state.
type StoreHandle struct {
	// DB is the opened walletdb database backing the store.
	DB walletdb.DB

	// Store is the db.Store adapter backed by DB.
	Store *Store

	// AddrStore is the opened legacy address manager.
	AddrStore *waddrmgr.Manager

	// TxStore is the opened legacy transaction manager.
	TxStore *wtxmgr.Store

	closeFn func() error
}

// Store is the kvdb (walletdb) implementation of the db.Store interface.
//
// NOTE: This is a partial implementation that will be expanded as the wallet
// UTXO manager migrates to the new db interfaces.
type Store struct {
	db        walletdb.DB
	txStore   wtxmgr.TxStore
	addrStore waddrmgr.AddrStore

	// writeMu serializes write paths that mutate the live address-manager cache
	// before walletdb commit, keeping commit-failure restores ordered with the
	// next Store write.
	writeMu sync.Mutex
}

// A compile-time assertion to ensure that Store implements the db.Store
// interface.
var _ db.Store = (*Store)(nil)

// NewStore creates a new kvdb-backed wallet store adapter.
func NewStore(dbConn walletdb.DB, txStore wtxmgr.TxStore,
	addrStore waddrmgr.AddrStore) *Store {

	return &Store{
		db:        dbConn,
		txStore:   txStore,
		addrStore: addrStore,
	}
}

// DB returns the walletdb handle backing the store. It is exposed for the
// legacy compatibility paths that still need a raw walletdb transaction (e.g.
// the deprecated passphrase shim), which run identically for kvdb and SQL
// wallets because the legacy address manager is always kvdb-backed.
//
// TODO(yy): Remove once those paths move behind the Store interface.
func (s *Store) DB() walletdb.DB {
	return s.db
}

// CreateStore creates, initializes, and opens a kvdb-backed wallet store.
func CreateStore(cfg Config, createParams CreateLegacyWalletParams) (
	*StoreHandle, error) {

	if cfg.DBPath == "" {
		return nil, errMissingDBPath
	}

	err := os.MkdirAll(filepath.Dir(cfg.DBPath), defaultDBDirPerm)
	if err != nil {
		return nil, fmt.Errorf("create kvdb directory: %w", err)
	}

	dbConn, err := walletdb.Create(
		"bdb", cfg.DBPath, cfg.NoFreelistSync, cfg.timeout(), false,
	)
	if err != nil {
		return nil, fmt.Errorf("create kvdb: %w", err)
	}

	closeFn := func() error {
		return dbConn.Close()
	}

	err = CreateLegacyWallet(dbConn, createParams)
	if err != nil {
		closeErr := closeFn()
		if closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}

		return nil, err
	}

	return LoadStore(dbConn, closeFn, OpenStoreParams{
		PubPassphrase: createParams.PubPassphrase,
		ChainParams:   createParams.ChainParams,
	})
}

// OpenStore opens and loads a kvdb-backed wallet store.
func OpenStore(cfg Config, params OpenStoreParams) (*StoreHandle, error) {
	if cfg.DBPath == "" {
		return nil, errMissingDBPath
	}

	dbConn, err := walletdb.Open(
		"bdb", cfg.DBPath, cfg.NoFreelistSync, cfg.timeout(), false,
	)
	if err != nil {
		return nil, fmt.Errorf("open kvdb: %w", err)
	}

	return LoadStore(dbConn, dbConn.Close, params)
}

// LoadStore loads a kvdb-backed wallet store from an already-open walletdb.
func LoadStore(dbConn walletdb.DB, closeFn func() error,
	params OpenStoreParams) (*StoreHandle, error) {

	addrStore, txStore, err := LoadLegacyWallet(
		dbConn, params.PubPassphrase, params.ChainParams,
	)
	if err != nil {
		if closeFn != nil {
			_ = closeFn()
		}

		return nil, err
	}

	return &StoreHandle{
		DB:        dbConn,
		Store:     NewStore(dbConn, txStore, addrStore),
		AddrStore: addrStore,
		TxStore:   txStore,
		closeFn:   closeFn,
	}, nil
}

// Close closes the walletdb owned by this handle.
func (h *StoreHandle) Close() error {
	if h == nil || h.closeFn == nil {
		return nil
	}

	closeFn := h.closeFn
	h.closeFn = nil

	err := closeFn()
	if err != nil {
		return fmt.Errorf("close kvdb: %w", err)
	}

	return nil
}

// timeout returns the configured timeout or the default timeout.
func (c Config) timeout() time.Duration {
	if c.Timeout == 0 {
		return defaultStoreTimeout
	}

	return c.Timeout
}

// StatsSnapshot returns an empty runtime snapshot for the kvdb backend.
func (s *Store) StatsSnapshot() dbruntime.StatsSnapshot {
	return dbruntime.StatsSnapshot{}
}
