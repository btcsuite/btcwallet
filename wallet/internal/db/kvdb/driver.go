package kvdb

import (
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// Store is the kvdb (walletdb) implementation of the db.Store interface.
//
// NOTE: This is a partial implementation that will be expanded as the wallet
// UTXO manager migrates to the new db interfaces.
type Store struct {
	db        walletdb.DB
	txStore   wtxmgr.TxStore
	addrStore waddrmgr.AddrStore
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
