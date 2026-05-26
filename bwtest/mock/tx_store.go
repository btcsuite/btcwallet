// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
)

// TxStore is a mock implementation of the wtxmgr.TxStore interface.
type TxStore struct {
	mock.Mock
}

// A compile-time assertion to ensure that TxStore implements the TxStore
// interface.
var _ wtxmgr.TxStore = (*TxStore)(nil)

// Balance implements the wtxmgr.TxStore interface.
func (m *TxStore) Balance(ns walletdb.ReadBucket, minConf int32,
	syncHeight int32) (btcutil.Amount, error) {

	args := m.Called(ns, minConf, syncHeight)
	if args.Get(0) == nil {
		return btcutil.Amount(0), args.Error(1)
	}

	return args.Get(0).(btcutil.Amount), args.Error(1)
}

// DeleteExpiredLockedOutputs implements the wtxmgr.TxStore interface.
func (m *TxStore) DeleteExpiredLockedOutputs(
	ns walletdb.ReadWriteBucket) error {

	args := m.Called(ns)
	return args.Error(0)
}

// InsertTx implements the wtxmgr.TxStore interface.
func (m *TxStore) InsertTx(ns walletdb.ReadWriteBucket,
	rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta) error {

	args := m.Called(ns, rec, block)
	return args.Error(0)
}

// InsertTxCheckIfExists implements the wtxmgr.TxStore interface.
func (m *TxStore) InsertTxCheckIfExists(ns walletdb.ReadWriteBucket,
	rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta) (bool, error) {

	args := m.Called(ns, rec, block)
	return args.Bool(0), args.Error(1)
}

// InsertConfirmedTx implements the wtxmgr.TxStore interface.
func (m *TxStore) InsertConfirmedTx(ns walletdb.ReadWriteBucket,
	rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta,
	credits []wtxmgr.CreditEntry) error {

	args := m.Called(ns, rec, block, credits)
	return args.Error(0)
}

// InsertUnconfirmedTx implements the wtxmgr.TxStore interface.
func (m *TxStore) InsertUnconfirmedTx(ns walletdb.ReadWriteBucket,
	rec *wtxmgr.TxRecord, credits []wtxmgr.CreditEntry) error {

	args := m.Called(ns, rec, credits)
	return args.Error(0)
}

// AddCredit implements the wtxmgr.TxStore interface.
func (m *TxStore) AddCredit(ns walletdb.ReadWriteBucket,
	rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta, index uint32,
	change bool) error {

	args := m.Called(ns, rec, block, index, change)
	return args.Error(0)
}

// ListLockedOutputs implements the wtxmgr.TxStore interface.
func (m *TxStore) ListLockedOutputs(
	ns walletdb.ReadBucket) ([]*wtxmgr.LockedOutput, error) {

	args := m.Called(ns)
	return args.Get(0).([]*wtxmgr.LockedOutput), args.Error(1)
}

// LockOutput implements the wtxmgr.TxStore interface.
func (m *TxStore) LockOutput(ns walletdb.ReadWriteBucket, id wtxmgr.LockID,
	op wire.OutPoint, duration time.Duration) (time.Time, error) {

	args := m.Called(ns, id, op, duration)
	if args.Get(0) == nil {
		return time.Time{}, args.Error(1)
	}

	return args.Get(0).(time.Time), args.Error(1)
}

// OutputsToWatch implements the wtxmgr.TxStore interface.
func (m *TxStore) OutputsToWatch(
	ns walletdb.ReadBucket) ([]wtxmgr.Credit, error) {

	args := m.Called(ns)
	return args.Get(0).([]wtxmgr.Credit), args.Error(1)
}

// PutTxLabel implements the wtxmgr.TxStore interface.
func (m *TxStore) PutTxLabel(ns walletdb.ReadWriteBucket,
	txid chainhash.Hash, label string) error {

	args := m.Called(ns, txid, label)
	return args.Error(0)
}

// RangeTransactions implements the wtxmgr.TxStore interface.
func (m *TxStore) RangeTransactions(ns walletdb.ReadBucket, begin,
	end int32, f func([]wtxmgr.TxDetails) (bool, error)) error {

	args := m.Called(ns, begin, end, f)
	return args.Error(0)
}

// Rollback implements the wtxmgr.TxStore interface.
func (m *TxStore) Rollback(
	ns walletdb.ReadWriteBucket, height int32) error {

	args := m.Called(ns, height)
	return args.Error(0)
}

// TxDetails implements the wtxmgr.TxStore interface.
func (m *TxStore) TxDetails(ns walletdb.ReadBucket,
	txHash *chainhash.Hash) (*wtxmgr.TxDetails, error) {

	args := m.Called(ns, txHash)
	details, _ := args.Get(0).(*wtxmgr.TxDetails)

	return details, args.Error(1)
}

// UniqueTxDetails implements the wtxmgr.TxStore interface.
func (m *TxStore) UniqueTxDetails(ns walletdb.ReadBucket,
	txHash *chainhash.Hash,
	block *wtxmgr.Block) (*wtxmgr.TxDetails, error) {

	args := m.Called(ns, txHash, block)
	details, _ := args.Get(0).(*wtxmgr.TxDetails)

	return details, args.Error(1)
}

// UnlockOutput implements the wtxmgr.TxStore interface.
func (m *TxStore) UnlockOutput(ns walletdb.ReadWriteBucket,
	id wtxmgr.LockID, op wire.OutPoint) error {

	args := m.Called(ns, id, op)
	return args.Error(0)
}

// UnspentOutputs implements the wtxmgr.TxStore interface.
func (m *TxStore) UnspentOutputs(
	ns walletdb.ReadBucket) ([]wtxmgr.Credit, error) {

	args := m.Called(ns)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]wtxmgr.Credit), args.Error(1)
}

// UnspentOutputsIncludingLocked implements the wtxmgr.TxStore interface.
func (m *TxStore) UnspentOutputsIncludingLocked(
	ns walletdb.ReadBucket) ([]wtxmgr.Credit, error) {

	args := m.Called(ns)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]wtxmgr.Credit), args.Error(1)
}

// GetUtxo implements the wtxmgr.TxStore interface.
func (m *TxStore) GetUtxo(ns walletdb.ReadBucket,
	outpoint wire.OutPoint) (*wtxmgr.Credit, error) {

	args := m.Called(ns, outpoint)
	credit, _ := args.Get(0).(*wtxmgr.Credit)

	return credit, args.Error(1)
}

// FetchTxLabel implements the wtxmgr.TxStore interface.
func (m *TxStore) FetchTxLabel(ns walletdb.ReadBucket,
	txid chainhash.Hash) (string, error) {

	args := m.Called(ns, txid)
	return args.String(0), args.Error(1)
}

// UnminedTxs implements the wtxmgr.TxStore interface.
func (m *TxStore) UnminedTxs(
	ns walletdb.ReadBucket) ([]*wire.MsgTx, error) {

	args := m.Called(ns)
	return args.Get(0).([]*wire.MsgTx), args.Error(1)
}

// UnminedTxHashes implements the wtxmgr.TxStore interface.
func (m *TxStore) UnminedTxHashes(
	ns walletdb.ReadBucket) ([]*chainhash.Hash, error) {

	args := m.Called(ns)
	return args.Get(0).([]*chainhash.Hash), args.Error(1)
}

// RemoveUnminedTx implements the wtxmgr.TxStore interface.
func (m *TxStore) RemoveUnminedTx(ns walletdb.ReadWriteBucket,
	rec *wtxmgr.TxRecord) error {

	args := m.Called(ns, rec)
	return args.Error(0)
}
