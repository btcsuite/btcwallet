// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package mock contains shared wallet-internal test doubles.
package mock

import (
	"context"
	"iter"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/stretchr/testify/mock"
)

// Store is a mock implementation of the db.Store interface.
//
// It is used to unit test wallet UTXO manager public methods without
// exercising a real database backend.
type Store struct {
	mock.Mock
}

// A compile-time assertion to ensure that Store implements the db.Store
// interface.
var _ db.Store = (*Store)(nil)

// StatsSnapshot returns an empty runtime snapshot for tests that use the mock
// kvdb store.
func (m *Store) StatsSnapshot() dbruntime.StatsSnapshot {
	return dbruntime.StatsSnapshot{}
}

// CreateWallet implements the db.WalletStore interface.
func (m *Store) CreateWallet(ctx context.Context,
	params db.CreateWalletParams) (*db.WalletInfo, error) {

	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.WalletInfo), args.Error(1)
}

// GetWallet implements the db.WalletStore interface.
func (m *Store) GetWallet(ctx context.Context,
	name string) (*db.WalletInfo, error) {

	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.WalletInfo), args.Error(1)
}

// ListWallets implements the db.WalletStore interface.
func (m *Store) ListWallets(ctx context.Context,
	query db.ListWalletsQuery) (page.Result[db.WalletInfo, uint32], error) {

	args := m.Called(ctx, query)

	result, ok := args.Get(0).(page.Result[db.WalletInfo, uint32])
	if !ok {
		return page.Result[db.WalletInfo, uint32]{}, args.Error(1)
	}

	return result, args.Error(1)
}

// IterWallets implements the db.WalletStore interface.
func (m *Store) IterWallets(ctx context.Context,
	query db.ListWalletsQuery) iter.Seq2[db.WalletInfo, error] {

	args := m.Called(ctx, query)

	seq, ok := args.Get(0).(iter.Seq2[db.WalletInfo, error])
	if ok {
		return seq
	}

	return func(yield func(db.WalletInfo, error) bool) {
		yield(db.WalletInfo{}, args.Error(1))
	}
}

// ListSyncedBlocks implements the db.WalletStore interface.
func (m *Store) ListSyncedBlocks(ctx context.Context,
	query db.ListSyncedBlocksQuery) ([]db.Block, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.Block), args.Error(1)
}

// UpdateWallet implements the db.WalletStore interface.
func (m *Store) UpdateWallet(ctx context.Context,
	params db.UpdateWalletParams) error {

	args := m.Called(ctx, params)

	return args.Error(0)
}

// GetEncryptedHDSeed implements the db.WalletStore interface.
func (m *Store) GetEncryptedHDSeed(ctx context.Context,
	walletID uint32) ([]byte, error) {

	args := m.Called(ctx, walletID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]byte), args.Error(1)
}

// GetWalletSecrets implements the db.WalletStore interface.
func (m *Store) GetWalletSecrets(ctx context.Context,
	walletID uint32) (*db.WalletSecrets, error) {

	args := m.Called(ctx, walletID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.WalletSecrets), args.Error(1)
}

// UpdateWalletSecrets implements the db.WalletStore interface.
func (m *Store) UpdateWalletSecrets(ctx context.Context,
	params db.UpdateWalletSecretsParams) error {

	args := m.Called(ctx, params)

	return args.Error(0)
}

// CreateDerivedAccount implements the db.AccountStore interface.
func (m *Store) CreateDerivedAccount(ctx context.Context,
	params db.CreateDerivedAccountParams,
	deriveFn db.AccountDerivationFunc) (*db.AccountInfo, error) {

	args := m.Called(ctx, params, deriveFn)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AccountInfo), args.Error(1)
}

// CreateImportedAccount implements the db.AccountStore interface.
func (m *Store) CreateImportedAccount(ctx context.Context,
	params db.CreateImportedAccountParams) (*db.AccountInfo, error) {

	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AccountInfo), args.Error(1)
}

// GetAccount implements the db.AccountStore interface.
func (m *Store) GetAccount(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AccountInfo), args.Error(1)
}

// ListAccounts implements the db.AccountStore interface.
func (m *Store) ListAccounts(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.AccountInfo), args.Error(1)
}

// RenameAccount implements the db.AccountStore interface.
func (m *Store) RenameAccount(ctx context.Context,
	params db.RenameAccountParams) error {

	args := m.Called(ctx, params)

	return args.Error(0)
}

// NewDerivedAddress implements the db.AddressStore interface.
func (m *Store) NewDerivedAddress(ctx context.Context,
	params db.NewDerivedAddressParams) (*db.AddressInfo, error) {

	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AddressInfo), args.Error(1)
}

// NewImportedAddress implements the db.AddressStore interface.
func (m *Store) NewImportedAddress(ctx context.Context,
	params db.NewImportedAddressParams) (*db.AddressInfo, error) {

	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AddressInfo), args.Error(1)
}

// GetAddress implements the db.AddressStore interface.
func (m *Store) GetAddress(ctx context.Context,
	query db.GetAddressQuery) (*db.AddressInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AddressInfo), args.Error(1)
}

// ResolveOwnedAddresses implements the db.AddressStore interface.
func (m *Store) ResolveOwnedAddresses(ctx context.Context,
	query db.ResolveOwnedAddressesQuery) (map[string]*db.AddressInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(map[string]*db.AddressInfo), args.Error(1)
}

// ListAddresses implements the db.AddressStore interface.
func (m *Store) ListAddresses(ctx context.Context,
	query db.ListAddressesQuery) (page.Result[db.AddressInfo, uint32], error) {

	args := m.Called(ctx, query)

	result, ok := args.Get(0).(page.Result[db.AddressInfo, uint32])
	if !ok {
		return page.Result[db.AddressInfo, uint32]{}, args.Error(1)
	}

	return result, args.Error(1)
}

// IterAddresses implements the db.AddressStore interface.
func (m *Store) IterAddresses(ctx context.Context,
	query db.ListAddressesQuery) iter.Seq2[db.AddressInfo, error] {

	args := m.Called(ctx, query)

	seq, ok := args.Get(0).(iter.Seq2[db.AddressInfo, error])
	if ok {
		return seq
	}

	return func(yield func(db.AddressInfo, error) bool) {
		yield(db.AddressInfo{}, args.Error(1))
	}
}

// GetAddressSecret implements the db.AddressStore interface.
func (m *Store) GetAddressSecret(ctx context.Context,
	query db.GetAddressSecretQuery) (*db.AddressSecret, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AddressSecret), args.Error(1)
}

// ListAddressTypes implements the db.AddressStore interface.
func (m *Store) ListAddressTypes(ctx context.Context) (
	[]db.AddressTypeInfo, error) {

	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.AddressTypeInfo), args.Error(1)
}

// GetAddressType implements the db.AddressStore interface.
func (m *Store) GetAddressType(ctx context.Context,
	id db.AddressType) (db.AddressTypeInfo, error) {

	args := m.Called(ctx, id)

	result, ok := args.Get(0).(db.AddressTypeInfo)
	if !ok {
		return db.AddressTypeInfo{}, args.Error(1)
	}

	return result, args.Error(1)
}

// GetUtxo implements the db.UTXOStore interface.
func (m *Store) GetUtxo(ctx context.Context,
	query db.GetUtxoQuery) (*db.UtxoInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.UtxoInfo), args.Error(1)
}

// ListUTXOs implements the db.UTXOStore interface.
func (m *Store) ListUTXOs(ctx context.Context,
	query db.ListUtxosQuery) ([]db.UtxoInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.UtxoInfo), args.Error(1)
}

// LeaseOutput implements the db.UTXOStore interface.
func (m *Store) LeaseOutput(ctx context.Context,
	params db.LeaseOutputParams) (*db.LeasedOutput, error) {

	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.LeasedOutput), args.Error(1)
}

// ReleaseOutput implements the db.UTXOStore interface.
func (m *Store) ReleaseOutput(ctx context.Context,
	params db.ReleaseOutputParams) error {

	args := m.Called(ctx, params)
	return args.Error(0)
}

// ListLeasedOutputs implements the db.UTXOStore interface.
func (m *Store) ListLeasedOutputs(ctx context.Context,
	walletID uint32) ([]db.LeasedOutput, error) {

	args := m.Called(ctx, walletID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.LeasedOutput), args.Error(1)
}

// DeleteExpiredLeases implements the db.UTXOStore interface.
func (m *Store) DeleteExpiredLeases(ctx context.Context,
	walletID uint32) error {

	args := m.Called(ctx, walletID)

	return args.Error(0)
}

// ListOutputsToWatch implements the db.UTXOStore interface.
func (m *Store) ListOutputsToWatch(ctx context.Context,
	walletID uint32) ([]db.UtxoInfo, error) {

	args := m.Called(ctx, walletID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.UtxoInfo), args.Error(1)
}

// Balance implements the db.UTXOStore interface.
func (m *Store) Balance(ctx context.Context,
	params db.BalanceParams) (db.BalanceResult, error) {

	args := m.Called(ctx, params)

	result, ok := args.Get(0).(db.BalanceResult)
	if !ok {
		return db.BalanceResult{}, args.Error(1)
	}

	return result, args.Error(1)
}

// CreateTx implements the db.TxStore interface.
func (m *Store) CreateTx(ctx context.Context,
	params db.CreateTxParams) error {

	args := m.Called(ctx, params)
	return args.Error(0)
}

// UpdateTx implements the db.TxStore interface.
func (m *Store) UpdateTx(ctx context.Context,
	params db.UpdateTxParams) error {

	args := m.Called(ctx, params)
	return args.Error(0)
}

// ApplyTxBatch implements the db.TxStore interface.
func (m *Store) ApplyTxBatch(ctx context.Context,
	params db.TxBatchParams) error {

	args := m.Called(ctx, params)

	return args.Error(0)
}

// ApplyScanBatch implements the db.TxStore interface.
func (m *Store) ApplyScanBatch(ctx context.Context,
	params db.ScanBatchParams) error {

	args := m.Called(ctx, params)

	return args.Error(0)
}

// RewindWallet implements the db.TxStore interface.
func (m *Store) RewindWallet(ctx context.Context,
	params db.RewindWalletParams) error {

	args := m.Called(ctx, params)

	return args.Error(0)
}

// GetTx implements the db.TxStore interface.
func (m *Store) GetTx(ctx context.Context,
	query db.GetTxQuery) (*db.TxInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.TxInfo), args.Error(1)
}

// GetTxDetail implements the db.TxStore interface.
func (m *Store) GetTxDetail(ctx context.Context,
	query db.GetTxDetailQuery) (*db.TxDetailInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.TxDetailInfo), args.Error(1)
}

// ListTxns implements the db.TxStore interface.
func (m *Store) ListTxns(ctx context.Context,
	query db.ListTxnsQuery) ([]db.TxInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.TxInfo), args.Error(1)
}

// ListTxDetails implements the db.TxStore interface.
func (m *Store) ListTxDetails(ctx context.Context,
	query db.ListTxDetailsQuery) ([]db.TxDetailInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.TxDetailInfo), args.Error(1)
}

// DeleteTx implements the db.TxStore interface.
func (m *Store) DeleteTx(ctx context.Context,
	params db.DeleteTxParams) error {

	args := m.Called(ctx, params)
	return args.Error(0)
}

// InvalidateUnminedTx implements the db.TxStore interface.
func (m *Store) InvalidateUnminedTx(ctx context.Context,
	params db.InvalidateUnminedTxParams) error {

	args := m.Called(ctx, params)
	return args.Error(0)
}

// RollbackToBlock implements the db.TxStore interface.
func (m *Store) RollbackToBlock(ctx context.Context, height uint32) error {
	args := m.Called(ctx, height)

	return args.Error(0)
}
