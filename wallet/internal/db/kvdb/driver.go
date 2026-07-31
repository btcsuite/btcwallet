package kvdb

import (
	"sync"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb" // Register bdb.
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// Config is the one configuration source for the kvdb adapter.
//
// The database is supplied already open: the Manager owns the physical handle
// and closes it, so the adapter neither creates the file nor closes it.
type Config struct {
	// DB is the already-open walletdb database.
	DB walletdb.DB

	// ChainParams identifies the wallet chain parameters.
	ChainParams *chaincfg.Params

	// PubPassphrase is the public passphrase protecting waddrmgr's public
	// metadata. It is required to open a wallet in the legacy
	// dual-encryption format.
	//
	// Deprecated: kvdb is a legacy backend and is the only one with a
	// separate public passphrase. This field will be removed with kvdb
	// support.
	PubPassphrase []byte
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

// StatsSnapshot returns an empty runtime snapshot for the kvdb backend.
func (s *Store) StatsSnapshot() dbruntime.StatsSnapshot {
	return dbruntime.StatsSnapshot{}
}
