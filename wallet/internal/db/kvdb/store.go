// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package kvdb adapts the existing walletdb-backed managers to the wallet's
// backend-neutral transaction boundary.
package kvdb

import (
	"context"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	addrmgrNamespaceKey = []byte("waddrmgr")
	txmgrNamespaceKey   = []byte("wtxmgr")
)

// legacyAddrStore is the existing walletdb-backed address-manager surface used
// by the adapter.
type legacyAddrStore interface {
	BlockHash(ns walletdb.ReadBucket, height int32) (*chainhash.Hash, error)
	SetSyncedTo(ns walletdb.ReadWriteBucket,
		block *waddrmgr.BlockStamp) error
}

// legacyTxStore is the existing walletdb-backed transaction-manager surface
// used by the adapter.
type legacyTxStore interface {
	Rollback(ns walletdb.ReadWriteBucket, height int32) error
}

// Store binds the existing address and transaction managers to walletdb
// transactions. It contains no storage logic of its own.
type Store struct {
	db        walletdb.DB
	addrStore legacyAddrStore
	txStore   legacyTxStore
}

// NewStore creates a walletdb adapter for the existing managers.
func NewStore(db walletdb.DB, addrStore *waddrmgr.Manager,
	txStore *wtxmgr.Store) *Store {

	return newStore(db, addrStore, txStore)
}

func newStore(db walletdb.DB, addrStore legacyAddrStore,
	txStore legacyTxStore) *Store {

	return &Store{
		db:        db,
		addrStore: addrStore,
		txStore:   txStore,
	}
}

// View executes body in one walletdb read transaction.
func (s *Store) View(ctx context.Context, body func(walletstore.ReadTx) error,
	reset func()) error {

	err := ctx.Err()
	if err != nil {
		return err
	}

	return walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		err := ctx.Err()
		if err != nil {
			return err
		}

		reset()

		return body(&readTx{
			addrStore: &addrReadStore{
				ns:    tx.ReadBucket(addrmgrNamespaceKey),
				store: s.addrStore,
			},
		})
	})
}

// Update executes body in one walletdb read/write transaction.
func (s *Store) Update(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	err := ctx.Err()
	if err != nil {
		return err
	}

	return walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		err := ctx.Err()
		if err != nil {
			return err
		}

		reset()

		return body(&readWriteTx{
			addrStore: &addrReadWriteStore{
				ns:    tx.ReadWriteBucket(addrmgrNamespaceKey),
				store: s.addrStore,
			},
			txStore: &txReadWriteStore{
				ns:    tx.ReadWriteBucket(txmgrNamespaceKey),
				store: s.txStore,
			},
		})
	})
}

type readTx struct {
	addrStore walletstore.AddrReadStore
}

// Addr returns the address-manager read view.
//
//nolint:ireturn // The transaction contract returns a domain interface.
func (t *readTx) Addr() walletstore.AddrReadStore {
	return t.addrStore
}

type readWriteTx struct {
	addrStore walletstore.AddrReadWriteStore
	txStore   walletstore.TxReadWriteStore
}

// Addr returns the address-manager read/write view.
//
//nolint:ireturn // The transaction contract returns a domain interface.
func (t *readWriteTx) Addr() walletstore.AddrReadWriteStore {
	return t.addrStore
}

// Tx returns the transaction-manager read/write view.
//
//nolint:ireturn // The transaction contract returns a domain interface.
func (t *readWriteTx) Tx() walletstore.TxReadWriteStore {
	return t.txStore
}

type addrReadStore struct {
	ns    walletdb.ReadBucket
	store legacyAddrStore
}

// BlockHash returns the block hash at a particular block height.
func (s *addrReadStore) BlockHash(height int32) (*chainhash.Hash, error) {
	return s.store.BlockHash(s.ns, height)
}

type addrReadWriteStore struct {
	ns    walletdb.ReadWriteBucket
	store legacyAddrStore
}

// BlockHash returns the block hash at a particular block height.
func (s *addrReadWriteStore) BlockHash(height int32) (*chainhash.Hash, error) {
	return s.store.BlockHash(s.ns, height)
}

// SetSyncedTo marks the address manager as synced through the block.
func (s *addrReadWriteStore) SetSyncedTo(block *waddrmgr.BlockStamp) error {
	return s.store.SetSyncedTo(s.ns, block)
}

type txReadWriteStore struct {
	ns    walletdb.ReadWriteBucket
	store legacyTxStore
}

// Rollback removes all blocks at height onwards.
func (s *txReadWriteStore) Rollback(height int32) error {
	return s.store.Rollback(s.ns, height)
}

var (
	_ walletstore.Store              = (*Store)(nil)
	_ walletstore.ReadTx             = (*readTx)(nil)
	_ walletstore.ReadWriteTx        = (*readWriteTx)(nil)
	_ walletstore.AddrReadStore      = (*addrReadStore)(nil)
	_ walletstore.AddrReadWriteStore = (*addrReadWriteStore)(nil)
	_ walletstore.TxReadWriteStore   = (*txReadWriteStore)(nil)
)
