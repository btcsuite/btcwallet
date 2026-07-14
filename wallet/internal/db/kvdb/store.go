// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package kvdb adapts the existing walletdb-backed managers to the wallet's
// backend-neutral transaction boundary.
package kvdb

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
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
	// BlockHash returns the block hash recorded at the given height.
	BlockHash(ns walletdb.ReadBucket, height int32) (*chainhash.Hash, error)
	// SetSyncedTo updates synced to through the transaction-bound backend.
	SetSyncedTo(ns walletdb.ReadWriteBucket,
		block *waddrmgr.BlockStamp) error
}

// legacyTxStore is the existing walletdb-backed transaction-manager surface
// used by the adapter.
//
//nolint:interfacebloat,inamedparam // This private shim mirrors wtxmgr exactly.
type legacyTxStore interface {
	// AddCredit marks one output of a recorded transaction as wallet-owned.
	AddCredit(walletdb.ReadWriteBucket, *wtxmgr.TxRecord,
		*wtxmgr.BlockMeta, uint32, bool) error
	// Balance returns the spendable balance for the requested confirmation
	// policy and sync height.
	Balance(walletdb.ReadBucket, int32, int32) (btcutil.Amount, error)
	// DeleteExpiredLockedOutputs removes every output lease that has expired.
	DeleteExpiredLockedOutputs(walletdb.ReadWriteBucket) error
	// InsertTx records a mined or unmined transaction incidence.
	InsertTx(walletdb.ReadWriteBucket, *wtxmgr.TxRecord,
		*wtxmgr.BlockMeta) error
	// InsertTxCheckIfExists records a transaction incidence and reports whether
	// it already existed.
	InsertTxCheckIfExists(walletdb.ReadWriteBucket, *wtxmgr.TxRecord,
		*wtxmgr.BlockMeta) (bool, error)
	// ListLockedOutputs returns all output leases that have not expired.
	ListLockedOutputs(walletdb.ReadBucket) ([]*wtxmgr.LockedOutput, error)
	// LockOutput leases an output to an owner for the requested duration.
	LockOutput(walletdb.ReadWriteBucket, wtxmgr.LockID, wire.OutPoint,
		time.Duration) (time.Time, error)
	// OutputsToWatch returns wallet credits that startup recovery should watch.
	OutputsToWatch(walletdb.ReadBucket) ([]wtxmgr.Credit, error)
	// PreviousPkScripts returns the previous output scripts for every input in
	// the transaction.
	PreviousPkScripts(walletdb.ReadBucket, *wtxmgr.TxRecord,
		*wtxmgr.Block) ([][]byte, error)
	// PutTxLabel stores a label for a transaction hash.
	PutTxLabel(walletdb.ReadWriteBucket, chainhash.Hash, string) error
	// RangeTransactions visits transaction details in the ordering and range
	// requested by wtxmgr.
	RangeTransactions(walletdb.ReadBucket, int32, int32,
		func([]wtxmgr.TxDetails) (bool, error)) error
	// RemoveUnminedTx removes an unmined transaction and its descendants.
	RemoveUnminedTx(walletdb.ReadWriteBucket, *wtxmgr.TxRecord) error
	// Rollback rewinds mined transaction incidences at and above the given
	// height.
	Rollback(ns walletdb.ReadWriteBucket, height int32) error
	// TxDetails returns the most recent transaction incidence for a hash.
	TxDetails(walletdb.ReadBucket,
		*chainhash.Hash) (*wtxmgr.TxDetails, error)
	// TxLabel returns the label stored for a transaction hash.
	TxLabel(walletdb.ReadBucket, chainhash.Hash) (string, error)
	// UniqueTxDetails returns the transaction incidence selected by its block
	// identity.
	UniqueTxDetails(walletdb.ReadBucket, *chainhash.Hash,
		*wtxmgr.Block) (*wtxmgr.TxDetails, error)
	// UnlockOutput releases an output lease held by the given owner.
	UnlockOutput(walletdb.ReadWriteBucket, wtxmgr.LockID,
		wire.OutPoint) error
	// UnminedTxHashes returns every transaction hash in the unmined set.
	UnminedTxHashes(walletdb.ReadBucket) ([]*chainhash.Hash, error)
	// UnminedTxs returns unmined transactions in dependency order.
	UnminedTxs(walletdb.ReadBucket) ([]*wire.MsgTx, error)
	// UnspentOutputs returns all credits that are currently spendable.
	UnspentOutputs(walletdb.ReadBucket) ([]wtxmgr.Credit, error)
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

// newStore constructs the KV adapter from the legacy manager interfaces used by
// tests and production.
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
				ManagerReadStore: waddrmgr.BindManagerReadStore(
					tx.ReadBucket(addrmgrNamespaceKey),
				),
				ns:    tx.ReadBucket(addrmgrNamespaceKey),
				store: s.addrStore,
			},
			txStore: &txReadStore{
				ns:    tx.ReadBucket(txmgrNamespaceKey),
				store: s.txStore,
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
				ManagerReadWriteStore: waddrmgr.BindManagerReadWriteStore(
					tx.ReadWriteBucket(addrmgrNamespaceKey),
				),
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
	txStore   walletstore.TxReadStore
}

// Addr returns the address-manager read view.
//
//nolint:ireturn // The transaction contract returns a domain interface.
func (t *readTx) Addr() walletstore.AddrReadStore {
	return t.addrStore
}

// Tx returns the transaction-manager read view.
//
//nolint:ireturn // The transaction contract returns a domain interface.
func (t *readTx) Tx() walletstore.TxReadStore {
	return t.txStore
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
	waddrmgr.ManagerReadStore

	ns    walletdb.ReadBucket
	store legacyAddrStore
}

// BlockHash returns the block hash at a particular block height.
func (s *addrReadStore) BlockHash(height int32) (*chainhash.Hash, error) {
	return s.store.BlockHash(s.ns, height)
}

type addrReadWriteStore struct {
	waddrmgr.ManagerReadWriteStore

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

type txReadStore struct {
	ns    walletdb.ReadBucket
	store legacyTxStore
}

type txReadWriteStore struct {
	ns    walletdb.ReadWriteBucket
	store legacyTxStore
}

// Balance returns the spendable wallet balance.
func (s *txReadStore) Balance(minConf, syncHeight int32) (
	btcutil.Amount, error) {

	return s.store.Balance(s.ns, minConf, syncHeight)
}

// ListLockedOutputs returns all currently leased outputs.
func (s *txReadStore) ListLockedOutputs() ([]*wtxmgr.LockedOutput, error) {
	return s.store.ListLockedOutputs(s.ns)
}

// OutputsToWatch returns the outputs startup recovery should watch.
func (s *txReadStore) OutputsToWatch() ([]wtxmgr.Credit, error) {
	return s.store.OutputsToWatch(s.ns)
}

// PreviousPkScripts returns the scripts for wallet-owned inputs.
func (s *txReadStore) PreviousPkScripts(rec *wtxmgr.TxRecord,
	block *wtxmgr.Block) ([][]byte, error) {

	return s.store.PreviousPkScripts(s.ns, rec, block)
}

// RangeTransactions visits transaction details over a block range.
func (s *txReadStore) RangeTransactions(begin, end int32,
	visit func([]wtxmgr.TxDetails) (bool, error)) error {

	return s.store.RangeTransactions(s.ns, begin, end, visit)
}

// TxDetails returns the most recent transaction incidence for a hash.
func (s *txReadStore) TxDetails(hash *chainhash.Hash) (
	*wtxmgr.TxDetails, error) {

	return s.store.TxDetails(s.ns, hash)
}

// TxLabel returns the label associated with a transaction hash.
func (s *txReadStore) TxLabel(hash chainhash.Hash) (string, error) {
	return s.store.TxLabel(s.ns, hash)
}

// UniqueTxDetails returns the selected transaction incidence.
func (s *txReadStore) UniqueTxDetails(hash *chainhash.Hash,
	block *wtxmgr.Block) (*wtxmgr.TxDetails, error) {

	return s.store.UniqueTxDetails(s.ns, hash, block)
}

// UnminedTxHashes returns all hashes in the unmined set.
func (s *txReadStore) UnminedTxHashes() ([]*chainhash.Hash, error) {
	return s.store.UnminedTxHashes(s.ns)
}

// UnminedTxs returns the dependency-ordered unmined transactions.
func (s *txReadStore) UnminedTxs() ([]*wire.MsgTx, error) {
	return s.store.UnminedTxs(s.ns)
}

// UnspentOutputs returns all currently spendable credits.
func (s *txReadStore) UnspentOutputs() ([]wtxmgr.Credit, error) {
	return s.store.UnspentOutputs(s.ns)
}

// Balance returns the spendable wallet balance.
func (s *txReadWriteStore) Balance(minConf, syncHeight int32) (
	btcutil.Amount, error) {

	return s.store.Balance(s.ns, minConf, syncHeight)
}

// ListLockedOutputs returns all currently leased outputs.
func (s *txReadWriteStore) ListLockedOutputs() ([]*wtxmgr.LockedOutput, error) {
	return s.store.ListLockedOutputs(s.ns)
}

// OutputsToWatch returns the outputs startup recovery should watch.
func (s *txReadWriteStore) OutputsToWatch() ([]wtxmgr.Credit, error) {
	return s.store.OutputsToWatch(s.ns)
}

// PreviousPkScripts returns the scripts for wallet-owned inputs.
func (s *txReadWriteStore) PreviousPkScripts(rec *wtxmgr.TxRecord,
	block *wtxmgr.Block) ([][]byte, error) {

	return s.store.PreviousPkScripts(s.ns, rec, block)
}

// RangeTransactions visits transaction details over a block range.
func (s *txReadWriteStore) RangeTransactions(begin, end int32,
	visit func([]wtxmgr.TxDetails) (bool, error)) error {

	return s.store.RangeTransactions(s.ns, begin, end, visit)
}

// TxDetails returns the most recent transaction incidence for a hash.
func (s *txReadWriteStore) TxDetails(hash *chainhash.Hash) (
	*wtxmgr.TxDetails, error) {

	return s.store.TxDetails(s.ns, hash)
}

// TxLabel returns the label associated with a transaction hash.
func (s *txReadWriteStore) TxLabel(hash chainhash.Hash) (string, error) {
	return s.store.TxLabel(s.ns, hash)
}

// UniqueTxDetails returns the selected transaction incidence.
func (s *txReadWriteStore) UniqueTxDetails(hash *chainhash.Hash,
	block *wtxmgr.Block) (*wtxmgr.TxDetails, error) {

	return s.store.UniqueTxDetails(s.ns, hash, block)
}

// UnminedTxHashes returns all hashes in the unmined set.
func (s *txReadWriteStore) UnminedTxHashes() ([]*chainhash.Hash, error) {
	return s.store.UnminedTxHashes(s.ns)
}

// UnminedTxs returns the dependency-ordered unmined transactions.
func (s *txReadWriteStore) UnminedTxs() ([]*wire.MsgTx, error) {
	return s.store.UnminedTxs(s.ns)
}

// UnspentOutputs returns all currently spendable credits.
func (s *txReadWriteStore) UnspentOutputs() ([]wtxmgr.Credit, error) {
	return s.store.UnspentOutputs(s.ns)
}

// AddCredit marks a recorded output as wallet-owned.
func (s *txReadWriteStore) AddCredit(rec *wtxmgr.TxRecord,
	block *wtxmgr.BlockMeta, index uint32, change bool) error {

	return s.store.AddCredit(s.ns, rec, block, index, change)
}

// DeleteExpiredLockedOutputs removes expired output leases.
func (s *txReadWriteStore) DeleteExpiredLockedOutputs() error {
	return s.store.DeleteExpiredLockedOutputs(s.ns)
}

// InsertTx records a mined or unmined transaction incidence.
func (s *txReadWriteStore) InsertTx(rec *wtxmgr.TxRecord,
	block *wtxmgr.BlockMeta) error {

	return s.store.InsertTx(s.ns, rec, block)
}

// InsertTxCheckIfExists records an incidence and reports duplicates.
func (s *txReadWriteStore) InsertTxCheckIfExists(rec *wtxmgr.TxRecord,
	block *wtxmgr.BlockMeta) (bool, error) {

	return s.store.InsertTxCheckIfExists(s.ns, rec, block)
}

// LockOutput leases an output to an owner.
func (s *txReadWriteStore) LockOutput(id wtxmgr.LockID,
	output wire.OutPoint, duration time.Duration) (time.Time, error) {

	return s.store.LockOutput(s.ns, id, output, duration)
}

// PutTxLabel stores a transaction label.
func (s *txReadWriteStore) PutTxLabel(hash chainhash.Hash,
	label string) error {

	return s.store.PutTxLabel(s.ns, hash, label)
}

// RemoveUnminedTx removes an unmined transaction and its descendants.
func (s *txReadWriteStore) RemoveUnminedTx(rec *wtxmgr.TxRecord) error {
	return s.store.RemoveUnminedTx(s.ns, rec)
}

// Rollback removes all blocks at height onwards.
func (s *txReadWriteStore) Rollback(height int32) error {
	return s.store.Rollback(s.ns, height)
}

// UnlockOutput releases an output lease held by the owner.
func (s *txReadWriteStore) UnlockOutput(id wtxmgr.LockID,
	output wire.OutPoint) error {

	return s.store.UnlockOutput(s.ns, id, output)
}

var (
	_ walletstore.Store              = (*Store)(nil)
	_ walletstore.ReadTx             = (*readTx)(nil)
	_ walletstore.ReadWriteTx        = (*readWriteTx)(nil)
	_ walletstore.AddrReadStore      = (*addrReadStore)(nil)
	_ walletstore.AddrReadWriteStore = (*addrReadWriteStore)(nil)
	_ walletstore.TxReadStore        = (*txReadStore)(nil)
	_ walletstore.TxReadWriteStore   = (*txReadWriteStore)(nil)
)
