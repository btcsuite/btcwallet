// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// This file contains mock implementations of wallet dependencies used in
// tests to isolate wallet logic from underlying storage backends.

package wallet

import (
	"context"
	"iter"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/neutrino"
	"github.com/lightninglabs/neutrino/banman"
	"github.com/lightninglabs/neutrino/headerfs"
	"github.com/stretchr/testify/mock"
)

// mockStore is a mock implementation of the db.Store interface.
//
// It is used to unit test wallet UTXO manager public methods without
// exercising a real database backend.
type mockStore struct {
	mock.Mock
}

// A compile-time assertion to ensure that mockStore implements the db.Store
// interface.
var _ db.Store = (*mockStore)(nil)

// StatsSnapshot returns an empty runtime snapshot for tests that use the mock
// kvdb store.
func (m *mockStore) StatsSnapshot() dbruntime.StatsSnapshot {
	return dbruntime.StatsSnapshot{}
}

// CreateWallet implements the db.WalletStore interface.
func (m *mockStore) CreateWallet(ctx context.Context,
	params db.CreateWalletParams) (*db.WalletInfo, error) {

	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.WalletInfo), args.Error(1)
}

// GetWallet implements the db.WalletStore interface.
func (m *mockStore) GetWallet(ctx context.Context,
	name string) (*db.WalletInfo, error) {

	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.WalletInfo), args.Error(1)
}

// ListWallets implements the db.WalletStore interface.
func (m *mockStore) ListWallets(ctx context.Context,
	query db.ListWalletsQuery) (page.Result[db.WalletInfo, uint32], error) {

	args := m.Called(ctx, query)

	result, ok := args.Get(0).(page.Result[db.WalletInfo, uint32])
	if !ok {
		return page.Result[db.WalletInfo, uint32]{}, args.Error(1)
	}

	return result, args.Error(1)
}

// IterWallets implements the db.WalletStore interface.
func (m *mockStore) IterWallets(ctx context.Context,
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

// UpdateWallet implements the db.WalletStore interface.
func (m *mockStore) UpdateWallet(ctx context.Context,
	params db.UpdateWalletParams) error {

	args := m.Called(ctx, params)

	return args.Error(0)
}

// GetEncryptedHDSeed implements the db.WalletStore interface.
func (m *mockStore) GetEncryptedHDSeed(ctx context.Context,
	walletID uint32) ([]byte, error) {

	args := m.Called(ctx, walletID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]byte), args.Error(1)
}

// UpdateWalletSecrets implements the db.WalletStore interface.
func (m *mockStore) UpdateWalletSecrets(ctx context.Context,
	params db.UpdateWalletSecretsParams) error {

	args := m.Called(ctx, params)

	return args.Error(0)
}

// CreateDerivedAccount implements the db.AccountStore interface.
func (m *mockStore) CreateDerivedAccount(ctx context.Context,
	params db.CreateDerivedAccountParams,
	deriveFn db.AccountDerivationFunc) (*db.AccountInfo, error) {

	args := m.Called(ctx, params, deriveFn)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AccountInfo), args.Error(1)
}

// CreateImportedAccount implements the db.AccountStore interface.
func (m *mockStore) CreateImportedAccount(ctx context.Context,
	params db.CreateImportedAccountParams) (*db.AccountInfo, error) {

	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AccountInfo), args.Error(1)
}

// GetAccount implements the db.AccountStore interface.
func (m *mockStore) GetAccount(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AccountInfo), args.Error(1)
}

// ListAccounts implements the db.AccountStore interface.
func (m *mockStore) ListAccounts(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.AccountInfo), args.Error(1)
}

// RenameAccount implements the db.AccountStore interface.
func (m *mockStore) RenameAccount(ctx context.Context,
	params db.RenameAccountParams) error {

	args := m.Called(ctx, params)

	return args.Error(0)
}

// NewDerivedAddress implements the db.AddressStore interface.
func (m *mockStore) NewDerivedAddress(ctx context.Context,
	params db.NewDerivedAddressParams,
	deriveFn db.AddressDerivationFunc) (*db.AddressInfo, error) {

	args := m.Called(ctx, params, deriveFn)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AddressInfo), args.Error(1)
}

// NewImportedAddress implements the db.AddressStore interface.
func (m *mockStore) NewImportedAddress(ctx context.Context,
	params db.NewImportedAddressParams) (*db.AddressInfo, error) {

	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AddressInfo), args.Error(1)
}

// GetAddress implements the db.AddressStore interface.
func (m *mockStore) GetAddress(ctx context.Context,
	query db.GetAddressQuery) (*db.AddressInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AddressInfo), args.Error(1)
}

// ListAddresses implements the db.AddressStore interface.
func (m *mockStore) ListAddresses(ctx context.Context,
	query db.ListAddressesQuery) (page.Result[db.AddressInfo, uint32], error) {

	args := m.Called(ctx, query)

	result, ok := args.Get(0).(page.Result[db.AddressInfo, uint32])
	if !ok {
		return page.Result[db.AddressInfo, uint32]{}, args.Error(1)
	}

	return result, args.Error(1)
}

// IterAddresses implements the db.AddressStore interface.
func (m *mockStore) IterAddresses(ctx context.Context,
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
func (m *mockStore) GetAddressSecret(ctx context.Context,
	query db.GetAddressSecretQuery) (*db.AddressSecret, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.AddressSecret), args.Error(1)
}

// ListAddressTypes implements the db.AddressStore interface.
func (m *mockStore) ListAddressTypes(ctx context.Context) (
	[]db.AddressTypeInfo, error) {

	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.AddressTypeInfo), args.Error(1)
}

// GetAddressType implements the db.AddressStore interface.
func (m *mockStore) GetAddressType(ctx context.Context,
	id db.AddressType) (db.AddressTypeInfo, error) {

	args := m.Called(ctx, id)

	result, ok := args.Get(0).(db.AddressTypeInfo)
	if !ok {
		return db.AddressTypeInfo{}, args.Error(1)
	}

	return result, args.Error(1)
}

// GetUtxo implements the db.UTXOStore interface.
func (m *mockStore) GetUtxo(ctx context.Context,
	query db.GetUtxoQuery) (*db.UtxoInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.UtxoInfo), args.Error(1)
}

// ListUTXOs implements the db.UTXOStore interface.
func (m *mockStore) ListUTXOs(ctx context.Context,
	query db.ListUtxosQuery) ([]db.UtxoInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.UtxoInfo), args.Error(1)
}

// LeaseOutput implements the db.UTXOStore interface.
func (m *mockStore) LeaseOutput(ctx context.Context,
	params db.LeaseOutputParams) (*db.LeasedOutput, error) {

	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.LeasedOutput), args.Error(1)
}

// ReleaseOutput implements the db.UTXOStore interface.
func (m *mockStore) ReleaseOutput(ctx context.Context,
	params db.ReleaseOutputParams) error {

	args := m.Called(ctx, params)
	return args.Error(0)
}

// ListLeasedOutputs implements the db.UTXOStore interface.
func (m *mockStore) ListLeasedOutputs(ctx context.Context,
	walletID uint32) ([]db.LeasedOutput, error) {

	args := m.Called(ctx, walletID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.LeasedOutput), args.Error(1)
}

// Balance implements the db.UTXOStore interface.
func (m *mockStore) Balance(ctx context.Context,
	params db.BalanceParams) (db.BalanceResult, error) {

	args := m.Called(ctx, params)

	result, ok := args.Get(0).(db.BalanceResult)
	if !ok {
		return db.BalanceResult{}, args.Error(1)
	}

	return result, args.Error(1)
}

// CreateTx implements the db.TxStore interface.
func (m *mockStore) CreateTx(ctx context.Context,
	params db.CreateTxParams) error {

	args := m.Called(ctx, params)
	return args.Error(0)
}

// UpdateTx implements the db.TxStore interface.
func (m *mockStore) UpdateTx(ctx context.Context,
	params db.UpdateTxParams) error {

	args := m.Called(ctx, params)
	return args.Error(0)
}

// GetTx implements the db.TxStore interface.
func (m *mockStore) GetTx(ctx context.Context,
	query db.GetTxQuery) (*db.TxInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.TxInfo), args.Error(1)
}

// GetTxDetail implements the db.TxStore interface.
func (m *mockStore) GetTxDetail(ctx context.Context,
	query db.GetTxDetailQuery) (*db.TxDetailInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*db.TxDetailInfo), args.Error(1)
}

// ListTxns implements the db.TxStore interface.
func (m *mockStore) ListTxns(ctx context.Context,
	query db.ListTxnsQuery) ([]db.TxInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.TxInfo), args.Error(1)
}

// ListTxDetails implements the db.TxStore interface.
func (m *mockStore) ListTxDetails(ctx context.Context,
	query db.ListTxDetailsQuery) ([]db.TxDetailInfo, error) {

	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]db.TxDetailInfo), args.Error(1)
}

// DeleteTx implements the db.TxStore interface.
func (m *mockStore) DeleteTx(ctx context.Context,
	params db.DeleteTxParams) error {

	args := m.Called(ctx, params)
	return args.Error(0)
}

// InvalidateUnminedTx implements the db.TxStore interface.
func (m *mockStore) InvalidateUnminedTx(ctx context.Context,
	params db.InvalidateUnminedTxParams) error {

	args := m.Called(ctx, params)
	return args.Error(0)
}

// RollbackToBlock implements the db.TxStore interface.
func (m *mockStore) RollbackToBlock(ctx context.Context, height uint32) error {
	args := m.Called(ctx, height)

	return args.Error(0)
}

// mockTxStore is a mock implementation of the wtxmgr.TxStore interface.
type mockTxStore struct {
	mock.Mock
}

// A compile-time assertion to ensure that mockTxStore implements the TxStore
// interface.
var _ wtxmgr.TxStore = (*mockTxStore)(nil)

// Balance implements the wtxmgr.TxStore interface.
func (m *mockTxStore) Balance(ns walletdb.ReadBucket, minConf int32,
	syncHeight int32) (btcutil.Amount, error) {

	args := m.Called(ns, minConf, syncHeight)
	if args.Get(0) == nil {
		return btcutil.Amount(0), args.Error(1)
	}

	return args.Get(0).(btcutil.Amount), args.Error(1)
}

// DeleteExpiredLockedOutputs implements the wtxmgr.TxStore interface.
func (m *mockTxStore) DeleteExpiredLockedOutputs(
	ns walletdb.ReadWriteBucket) error {

	args := m.Called(ns)
	return args.Error(0)
}

// InsertTx implements the wtxmgr.TxStore interface.
func (m *mockTxStore) InsertTx(ns walletdb.ReadWriteBucket,
	rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta) error {

	args := m.Called(ns, rec, block)
	return args.Error(0)
}

// InsertTxCheckIfExists implements the wtxmgr.TxStore interface.
func (m *mockTxStore) InsertTxCheckIfExists(ns walletdb.ReadWriteBucket,
	rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta) (bool, error) {

	args := m.Called(ns, rec, block)
	return args.Bool(0), args.Error(1)
}

// InsertConfirmedTx implements the wtxmgr.TxStore interface.
func (m *mockTxStore) InsertConfirmedTx(ns walletdb.ReadWriteBucket,
	rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta,
	credits []wtxmgr.CreditEntry) error {

	args := m.Called(ns, rec, block, credits)
	return args.Error(0)
}

// InsertUnconfirmedTx implements the wtxmgr.TxStore interface.
func (m *mockTxStore) InsertUnconfirmedTx(ns walletdb.ReadWriteBucket,
	rec *wtxmgr.TxRecord, credits []wtxmgr.CreditEntry) error {

	args := m.Called(ns, rec, credits)
	return args.Error(0)
}

// AddCredit implements the wtxmgr.TxStore interface.
func (m *mockTxStore) AddCredit(ns walletdb.ReadWriteBucket,
	rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta, index uint32,
	change bool) error {

	args := m.Called(ns, rec, block, index, change)
	return args.Error(0)
}

// ListLockedOutputs implements the wtxmgr.TxStore interface.
func (m *mockTxStore) ListLockedOutputs(
	ns walletdb.ReadBucket) ([]*wtxmgr.LockedOutput, error) {

	args := m.Called(ns)
	return args.Get(0).([]*wtxmgr.LockedOutput), args.Error(1)
}

// LockOutput implements the wtxmgr.TxStore interface.
func (m *mockTxStore) LockOutput(ns walletdb.ReadWriteBucket, id wtxmgr.LockID,
	op wire.OutPoint, duration time.Duration) (time.Time, error) {

	args := m.Called(ns, id, op, duration)
	if args.Get(0) == nil {
		return time.Time{}, args.Error(1)
	}

	return args.Get(0).(time.Time), args.Error(1)
}

// OutputsToWatch implements the wtxmgr.TxStore interface.
func (m *mockTxStore) OutputsToWatch(
	ns walletdb.ReadBucket) ([]wtxmgr.Credit, error) {

	args := m.Called(ns)
	return args.Get(0).([]wtxmgr.Credit), args.Error(1)
}

// PutTxLabel implements the wtxmgr.TxStore interface.
func (m *mockTxStore) PutTxLabel(ns walletdb.ReadWriteBucket,
	txid chainhash.Hash, label string) error {

	args := m.Called(ns, txid, label)
	return args.Error(0)
}

// RangeTransactions implements the wtxmgr.TxStore interface.
func (m *mockTxStore) RangeTransactions(ns walletdb.ReadBucket, begin,
	end int32, f func([]wtxmgr.TxDetails) (bool, error)) error {

	args := m.Called(ns, begin, end, f)
	return args.Error(0)
}

// Rollback implements the wtxmgr.TxStore interface.
func (m *mockTxStore) Rollback(
	ns walletdb.ReadWriteBucket, height int32) error {

	args := m.Called(ns, height)
	return args.Error(0)
}

// TxDetails implements the wtxmgr.TxStore interface.
func (m *mockTxStore) TxDetails(ns walletdb.ReadBucket,
	txHash *chainhash.Hash) (*wtxmgr.TxDetails, error) {

	args := m.Called(ns, txHash)
	details, _ := args.Get(0).(*wtxmgr.TxDetails)

	return details, args.Error(1)
}

// UniqueTxDetails implements the wtxmgr.TxStore interface.
func (m *mockTxStore) UniqueTxDetails(ns walletdb.ReadBucket,
	txHash *chainhash.Hash,
	block *wtxmgr.Block) (*wtxmgr.TxDetails, error) {

	args := m.Called(ns, txHash, block)
	details, _ := args.Get(0).(*wtxmgr.TxDetails)

	return details, args.Error(1)
}

// UnlockOutput implements the wtxmgr.TxStore interface.
func (m *mockTxStore) UnlockOutput(ns walletdb.ReadWriteBucket,
	id wtxmgr.LockID, op wire.OutPoint) error {

	args := m.Called(ns, id, op)
	return args.Error(0)
}

// UnspentOutputs implements the wtxmgr.TxStore interface.
func (m *mockTxStore) UnspentOutputs(
	ns walletdb.ReadBucket) ([]wtxmgr.Credit, error) {

	args := m.Called(ns)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]wtxmgr.Credit), args.Error(1)
}

// GetUtxo implements the wtxmgr.TxStore interface.
func (m *mockTxStore) GetUtxo(ns walletdb.ReadBucket,
	outpoint wire.OutPoint) (*wtxmgr.Credit, error) {

	args := m.Called(ns, outpoint)
	credit, _ := args.Get(0).(*wtxmgr.Credit)

	return credit, args.Error(1)
}

// FetchTxLabel implements the wtxmgr.TxStore interface.
func (m *mockTxStore) FetchTxLabel(ns walletdb.ReadBucket,
	txid chainhash.Hash) (string, error) {

	args := m.Called(ns, txid)
	return args.String(0), args.Error(1)
}

// UnminedTxs implements the wtxmgr.TxStore interface.
func (m *mockTxStore) UnminedTxs(
	ns walletdb.ReadBucket) ([]*wire.MsgTx, error) {

	args := m.Called(ns)
	return args.Get(0).([]*wire.MsgTx), args.Error(1)
}

// UnminedTxHashes implements the wtxmgr.TxStore interface.
func (m *mockTxStore) UnminedTxHashes(
	ns walletdb.ReadBucket) ([]*chainhash.Hash, error) {

	args := m.Called(ns)
	return args.Get(0).([]*chainhash.Hash), args.Error(1)
}

// RemoveUnminedTx implements the wtxmgr.TxStore interface.
func (m *mockTxStore) RemoveUnminedTx(ns walletdb.ReadWriteBucket,
	rec *wtxmgr.TxRecord) error {

	args := m.Called(ns, rec)
	return args.Error(0)
}

// mockAddrStore is a mock implementation of the waddrmgr.AddrStore interface.
type mockAddrStore struct {
	mock.Mock
}

// Birthday returns the birthday of the address store.
func (m *mockAddrStore) Birthday() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

// SetSyncedTo marks the address manager to be in sync with the
// recently-seen block described by the blockstamp.
func (m *mockAddrStore) SetSyncedTo(ns walletdb.ReadWriteBucket,
	bs *waddrmgr.BlockStamp) error {

	args := m.Called(ns, bs)
	return args.Error(0)
}

// SetBirthdayBlock sets the birthday block, or earliest time a key could
// have been used, for the manager.
func (m *mockAddrStore) SetBirthdayBlock(ns walletdb.ReadWriteBucket,
	block waddrmgr.BlockStamp, verified bool) error {

	args := m.Called(ns, block, verified)
	return args.Error(0)
}

// SyncedTo returns details about the block height and hash that the
// address manager is synced through at the very least.
func (m *mockAddrStore) SyncedTo() waddrmgr.BlockStamp {
	args := m.Called()
	return args.Get(0).(waddrmgr.BlockStamp)
}

// BlockHash returns the block hash at a particular block height.
func (m *mockAddrStore) BlockHash(ns walletdb.ReadBucket,
	height int32) (*chainhash.Hash, error) {

	args := m.Called(ns, height)
	return args.Get(0).(*chainhash.Hash), args.Error(1)
}

// ActiveScopedKeyManagers returns a slice of all the active scoped key
// managers currently known by the root key manager.
func (m *mockAddrStore) ActiveScopedKeyManagers() []waddrmgr.AccountStore {
	args := m.Called()
	return args.Get(0).([]waddrmgr.AccountStore)
}

// FetchScopedKeyManager attempts to fetch an active scoped manager
// according to its registered scope.
func (m *mockAddrStore) FetchScopedKeyManager(
	scope waddrmgr.KeyScope) (waddrmgr.AccountStore, error) {

	args := m.Called(scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(waddrmgr.AccountStore), args.Error(1)
}

// Address returns a managed address given the passed address if it is
// known to the address manager.
func (m *mockAddrStore) Address(ns walletdb.ReadBucket,
	address btcutil.Address) (waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, address)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(waddrmgr.ManagedAddress), args.Error(1)
}

// AddrAccount returns the account to which the given address belongs.
func (m *mockAddrStore) AddrAccount(ns walletdb.ReadBucket,
	address btcutil.Address) (waddrmgr.AccountStore, uint32, error) {

	args := m.Called(ns, address)

	return args.Get(0).(waddrmgr.AccountStore),
		args.Get(1).(uint32), args.Error(2)
}

// AddressDetails determines whether the wallet has access to the private
// keys required to sign for a given address, and returns other address
// details.
func (m *mockAddrStore) AddressDetails(ns walletdb.ReadBucket,
	addr btcutil.Address) (bool, string, waddrmgr.AddressType) {

	args := m.Called(ns, addr)
	return args.Bool(0), args.String(1), args.Get(2).(waddrmgr.AddressType)
}

// ForEachRelevantActiveAddress invokes the given closure on each active
// address relevant to the wallet.
func (m *mockAddrStore) ForEachRelevantActiveAddress(ns walletdb.ReadBucket,
	fn func(addr btcutil.Address) error) error {

	args := m.Called(ns, fn)
	return args.Error(0)
}

// Unlock derives the master private key from the specified passphrase.
func (m *mockAddrStore) Unlock(ns walletdb.ReadBucket,
	passphrase []byte) error {

	args := m.Called(ns, passphrase)
	return args.Error(0)
}

// Lock performs a best try effort to remove and zero all secret keys
// associated with the address manager.
func (m *mockAddrStore) Lock() error {
	args := m.Called()
	return args.Error(0)
}

// IsLocked returns whether or not the address managed is locked.
func (m *mockAddrStore) IsLocked() bool {
	args := m.Called()
	return args.Bool(0)
}

// ChangePassphrase changes either the public or private passphrase to
// the provided value depending on the private flag.
func (m *mockAddrStore) ChangePassphrase(ns walletdb.ReadWriteBucket,
	oldPass, newPass []byte, private bool,
	scryptOptions *waddrmgr.ScryptOptions) error {

	args := m.Called(ns, oldPass, newPass, private, scryptOptions)
	return args.Error(0)
}

// WatchOnly returns true if the root manager is in watch only mode, and
// false otherwise.
func (m *mockAddrStore) WatchOnly() bool {
	args := m.Called()
	return args.Bool(0)
}

// MarkUsed updates the used flag for the provided address.
func (m *mockAddrStore) MarkUsed(ns walletdb.ReadWriteBucket,
	address btcutil.Address) error {

	args := m.Called(ns, address)
	return args.Error(0)
}

// BirthdayBlock returns the birthday block of the address store.
func (m *mockAddrStore) BirthdayBlock(
	ns walletdb.ReadBucket) (waddrmgr.BlockStamp, bool, error) {

	args := m.Called(ns)
	return args.Get(0).(waddrmgr.BlockStamp), args.Bool(1), args.Error(2)
}

// IsWatchOnlyAccount determines if the account with the given key scope
// is set up as watch-only.
func (m *mockAddrStore) IsWatchOnlyAccount(ns walletdb.ReadBucket,
	keyScope waddrmgr.KeyScope, account uint32) (bool, error) {

	args := m.Called(ns, keyScope, account)
	return args.Bool(0), args.Error(1)
}

// NewScopedKeyManager creates a new scoped key manager from the root
// manager.
func (m *mockAddrStore) NewScopedKeyManager(ns walletdb.ReadWriteBucket,
	scope waddrmgr.KeyScope,
	addrSchema waddrmgr.ScopeAddrSchema) (waddrmgr.AccountStore, error) {

	args := m.Called(ns, scope, addrSchema)
	return args.Get(0).(waddrmgr.AccountStore), args.Error(1)
}

// SetBirthday sets the birthday of the address store.
func (m *mockAddrStore) SetBirthday(ns walletdb.ReadWriteBucket,
	birthday time.Time) error {

	args := m.Called(ns, birthday)
	return args.Error(0)
}

// ForEachAccountAddress calls the given function with each address of
// the given account stored in the manager, breaking early on error.
func (m *mockAddrStore) ForEachAccountAddress(ns walletdb.ReadBucket,
	account uint32, fn func(maddr waddrmgr.ManagedAddress) error) error {

	args := m.Called(ns, account, fn)
	return args.Error(0)
}

// LookupAccount returns the corresponding key scope and account number
// for the account with the given name.
func (m *mockAddrStore) LookupAccount(ns walletdb.ReadBucket,
	name string) (waddrmgr.KeyScope, uint32, error) {

	args := m.Called(ns, name)

	return args.Get(0).(waddrmgr.KeyScope),
		args.Get(1).(uint32), args.Error(2)
}

// ForEachActiveAddress calls the given function with each active address
// stored in the manager, breaking early on error.
func (m *mockAddrStore) ForEachActiveAddress(ns walletdb.ReadBucket,
	fn func(addr btcutil.Address) error) error {

	args := m.Called(ns, fn)
	return args.Error(0)
}

// ConvertToWatchingOnly converts the current address manager to a locked
// watching-only address manager.
func (m *mockAddrStore) ConvertToWatchingOnly(
	ns walletdb.ReadWriteBucket) error {

	args := m.Called(ns)
	return args.Error(0)
}

// ChainParams returns the chain parameters for this address manager.
func (m *mockAddrStore) ChainParams() *chaincfg.Params {
	args := m.Called()
	return args.Get(0).(*chaincfg.Params)
}

// Close cleanly shuts down the manager.

func (m *mockAddrStore) EncryptedMasterHDPriv(
	ns walletdb.ReadBucket) ([]byte, error) {

	args := m.Called(ns)
	if raw, ok := args.Get(0).([]byte); ok {
		return raw, args.Error(1)
	}

	return nil, args.Error(1)
}

func (m *mockAddrStore) MasterHDPubKey(
	ns walletdb.ReadBucket) ([]byte, error) {

	args := m.Called(ns)
	if raw, ok := args.Get(0).([]byte); ok {
		return raw, args.Error(1)
	}

	return nil, args.Error(1)
}

func (m *mockAddrStore) Close() {
	m.Called()
}

// Encrypt implements keyvault.Vault.
func (m *mockAddrStore) Encrypt(keyType waddrmgr.CryptoKeyType,
	plaintext []byte) ([]byte, error) {

	args := m.Called(keyType, plaintext)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]byte), args.Error(1)
}

// Decrypt implements keyvault.Vault.
func (m *mockAddrStore) Decrypt(keyType waddrmgr.CryptoKeyType,
	ciphertext []byte) ([]byte, error) {

	args := m.Called(keyType, ciphertext)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]byte), args.Error(1)
}

// mockAccountStore is a mock implementation of the waddrmgr.AccountStore
// interface.
type mockAccountStore struct {
	mock.Mock
}

// A compile-time assertion to ensure that mockAccountStore implements the
// AccountStore interface.
var _ waddrmgr.AccountStore = (*mockAccountStore)(nil)

// Scope implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) Scope() waddrmgr.KeyScope {
	args := m.Called()
	return args.Get(0).(waddrmgr.KeyScope)
}

// AccountProperties implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) AccountProperties(ns walletdb.ReadBucket,
	account uint32) (*waddrmgr.AccountProperties, error) {

	args := m.Called(ns, account)
	return args.Get(0).(*waddrmgr.AccountProperties), args.Error(1)
}

// LastExternalAddress implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) LastExternalAddress(ns walletdb.ReadBucket,
	account uint32) (waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, account)
	return args.Get(0).(waddrmgr.ManagedAddress), args.Error(1)
}

// LastInternalAddress implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) LastInternalAddress(ns walletdb.ReadBucket,
	account uint32) (waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, account)
	return args.Get(0).(waddrmgr.ManagedAddress), args.Error(1)
}

// ForEachAccountAddress implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) ForEachAccountAddress(ns walletdb.ReadBucket,
	account uint32, fn func(maddr waddrmgr.ManagedAddress) error) error {

	args := m.Called(ns, account, fn)
	return args.Error(0)
}

// LookupAccount implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) LookupAccount(ns walletdb.ReadBucket,
	name string) (uint32, error) {

	args := m.Called(ns, name)
	return args.Get(0).(uint32), args.Error(1)
}

// AccountName implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) AccountName(ns walletdb.ReadBucket,
	account uint32) (string, error) {

	args := m.Called(ns, account)
	return args.String(0), args.Error(1)
}

// ExtendExternalAddresses implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) ExtendExternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, count uint32) error {

	args := m.Called(ns, account, count)
	return args.Error(0)
}

// ExtendInternalAddresses implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) ExtendInternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, count uint32) error {

	args := m.Called(ns, account, count)
	return args.Error(0)
}

// MarkUsed implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) MarkUsed(ns walletdb.ReadWriteBucket,
	address btcutil.Address) error {

	args := m.Called(ns, address)
	return args.Error(0)
}

// DeriveFromKeyPath implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) DeriveFromKeyPath(ns walletdb.ReadBucket,
	path waddrmgr.DerivationPath) (waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, path)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(waddrmgr.ManagedAddress), args.Error(1)
}

// CanAddAccountDeprecated implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) CanAddAccountDeprecated() error {
	args := m.Called()
	return args.Error(0)
}

// NewAccount implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) NewAccount(ns walletdb.ReadWriteBucket,
	name string) (uint32, error) {

	args := m.Called(ns, name)
	return args.Get(0).(uint32), args.Error(1)
}

// AllocateDerivedAccountNumber implements waddrmgr.AccountStore.
func (m *mockAccountStore) AllocateDerivedAccountNumber(
	ns walletdb.ReadWriteBucket) (uint32, error) {

	args := m.Called(ns)
	return args.Get(0).(uint32), args.Error(1)
}

// PutDerivedAccountWithKeys implements waddrmgr.AccountStore.
func (m *mockAccountStore) PutDerivedAccountWithKeys(
	ns walletdb.ReadWriteBucket, account uint32, name string,
	plaintextPubKey []byte, encryptedPrivKey []byte) error {

	args := m.Called(
		ns, account, name, plaintextPubKey, encryptedPrivKey,
	)

	return args.Error(0)
}

// AllocateImportedAccountNumber implements waddrmgr.AccountStore.
func (m *mockAccountStore) AllocateImportedAccountNumber(
	ns walletdb.ReadWriteBucket) (uint32, error) {

	args := m.Called(ns)
	return args.Get(0).(uint32), args.Error(1)
}

// PutWatchOnlyAccountWithKeys implements waddrmgr.AccountStore.
func (m *mockAccountStore) PutWatchOnlyAccountWithKeys(
	ns walletdb.ReadWriteBucket, account uint32, name string,
	pubKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32,
	addrSchema *waddrmgr.ScopeAddrSchema) error {

	args := m.Called(
		ns, account, name, pubKey, masterKeyFingerprint, addrSchema,
	)

	return args.Error(0)
}

// LastAccount implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) LastAccount(ns walletdb.ReadBucket) (uint32, error) {
	args := m.Called(ns)
	return args.Get(0).(uint32), args.Error(1)
}

// RenameAccount implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) RenameAccount(ns walletdb.ReadWriteBucket,
	account uint32, name string) error {

	args := m.Called(ns, account, name)
	return args.Error(0)
}

// NextExternalAddresses implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) NextExternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, count uint32) ([]waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, account, count)
	return args.Get(0).([]waddrmgr.ManagedAddress), args.Error(1)
}

// NextInternalAddresses implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) NextInternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, count uint32) ([]waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, account, count)
	return args.Get(0).([]waddrmgr.ManagedAddress), args.Error(1)
}

// NewAddress implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) NewAddress(ns walletdb.ReadWriteBucket,
	account string, internal bool) (btcutil.Address, error) {

	args := m.Called(ns, account, internal)
	return args.Get(0).(btcutil.Address), args.Error(1)
}

// ImportPublicKey implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) ImportPublicKey(ns walletdb.ReadWriteBucket,
	pubKey *btcec.PublicKey,
	bs *waddrmgr.BlockStamp) (waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, pubKey, bs)
	return args.Get(0).(waddrmgr.ManagedAddress), args.Error(1)
}

// ImportTaprootScript implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) ImportTaprootScript(ns walletdb.ReadWriteBucket,
	script *waddrmgr.Tapscript, bs *waddrmgr.BlockStamp, privKeyType byte,
	isInternal bool) (waddrmgr.ManagedTaprootScriptAddress, error) {

	args := m.Called(ns, script, bs, privKeyType, isInternal)
	return args.Get(0).(waddrmgr.ManagedTaprootScriptAddress), args.Error(1)
}

// ForEachAccount implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) ForEachAccount(ns walletdb.ReadBucket,
	fn func(account uint32) error) error {

	args := m.Called(ns, fn)
	return args.Error(0)
}

// IsWatchOnlyAccount implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) IsWatchOnlyAccount(ns walletdb.ReadBucket,
	account uint32) (bool, error) {

	args := m.Called(ns, account)
	return args.Bool(0), args.Error(1)
}

// NewAccountWatchingOnly implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) NewAccountWatchingOnly(ns walletdb.ReadWriteBucket,
	name string, pubKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32,
	addrSchema *waddrmgr.ScopeAddrSchema) (uint32, error) {

	args := m.Called(ns, name, pubKey, masterKeyFingerprint, addrSchema)
	return args.Get(0).(uint32), args.Error(1)
}

// InvalidateAccountCache implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) InvalidateAccountCache(account uint32) {
	m.Called(account)
}

// ImportPrivateKey implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) ImportPrivateKey(ns walletdb.ReadWriteBucket,
	wif *btcutil.WIF,
	bs *waddrmgr.BlockStamp) (waddrmgr.ManagedPubKeyAddress, error) {

	args := m.Called(ns, wif, bs)
	return args.Get(0).(waddrmgr.ManagedPubKeyAddress), args.Error(1)
}

// ActiveAccounts implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) ActiveAccounts() []uint32 {
	args := m.Called()
	return args.Get(0).([]uint32)
}

// ExtendAddresses implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) ExtendAddresses(ns walletdb.ReadWriteBucket,
	account uint32, lastIndex uint32, branch uint32) error {

	args := m.Called(ns, account, lastIndex, branch)
	return args.Error(0)
}

// DeriveAddr implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) DeriveAddr(account, branch, index uint32) (
	btcutil.Address, []byte, error) {

	args := m.Called(account, branch, index)

	var addr btcutil.Address
	if args.Get(0) != nil {
		addr = args.Get(0).(btcutil.Address)
	}

	var script []byte
	if args.Get(1) != nil {
		script = args.Get(1).([]byte)
	}

	return addr, script, args.Error(2)
}

// AddrAccount implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) AddrAccount(ns walletdb.ReadBucket,
	address btcutil.Address) (uint32, error) {

	args := m.Called(ns, address)
	return args.Get(0).(uint32), args.Error(1)
}

// DeriveFromKeyPathCache implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) DeriveFromKeyPathCache(
	kp waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	args := m.Called(kp)
	return args.Get(0).(*btcec.PrivateKey), args.Error(1)
}

// NewRawAccount implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) NewRawAccount(ns walletdb.ReadWriteBucket,
	number uint32) error {

	args := m.Called(ns, number)
	return args.Error(0)
}

// NewRawAccountWatchingOnly implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) NewRawAccountWatchingOnly(
	ns walletdb.ReadWriteBucket,
	number uint32, pubKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32,
	addrSchema *waddrmgr.ScopeAddrSchema) error {

	args := m.Called(ns, number, pubKey, masterKeyFingerprint, addrSchema)
	return args.Error(0)
}

// ImportScript implements the waddrmgr.AccountStore interface.
func (m *mockAccountStore) ImportScript(
	ns walletdb.ReadWriteBucket, script []byte,
	bs *waddrmgr.BlockStamp) (waddrmgr.ManagedScriptAddress, error) {

	args := m.Called(ns, script, bs)
	return args.Get(0).(waddrmgr.ManagedScriptAddress), args.Error(1)
}

func (m *mockAccountStore) ImportWitnessScript(ns walletdb.ReadWriteBucket,
	script []byte, bs *waddrmgr.BlockStamp, witnessVersion byte,
	isSecretScript bool) (waddrmgr.ManagedScriptAddress, error) {

	args := m.Called(ns, script, bs, witnessVersion, isSecretScript)
	if v := args.Get(0); v != nil {
		return v.(waddrmgr.ManagedScriptAddress), args.Error(1)
	}

	return nil, args.Error(1)
}

// mockManagedAddress is a mock implementation of the waddrmgr.ManagedAddress
// interface.
type mockManagedAddress struct {
	mock.Mock
}

// A compile-time assertion to ensure that mockManagedAddress implements the
// ManagedAddress interface.
var _ waddrmgr.ManagedAddress = (*mockManagedAddress)(nil)

// Address implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedAddress) Address() btcutil.Address {
	args := m.Called()
	return args.Get(0).(btcutil.Address)
}

// AddrHash implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedAddress) AddrHash() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// Imported implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedAddress) Imported() bool {
	args := m.Called()
	return args.Bool(0)
}

// Internal implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedAddress) Internal() bool {
	args := m.Called()
	return args.Bool(0)
}

// Compressed implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedAddress) Compressed() bool {
	args := m.Called()
	return args.Bool(0)
}

// Used implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedAddress) Used(ns walletdb.ReadBucket) bool {
	args := m.Called(ns)
	return args.Bool(0)
}

// AddrType implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedAddress) AddrType() waddrmgr.AddressType {
	args := m.Called()
	return args.Get(0).(waddrmgr.AddressType)
}

// InternalAccount implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedAddress) InternalAccount() uint32 {
	args := m.Called()
	return args.Get(0).(uint32)
}

// DerivationInfo implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedAddress) DerivationInfo() (
	waddrmgr.KeyScope, waddrmgr.DerivationPath, bool) {

	args := m.Called()

	return args.Get(0).(waddrmgr.KeyScope),
		args.Get(1).(waddrmgr.DerivationPath), args.Bool(2)
}

// mockCoinSelectionStrategy is a mock implementation of the
// CoinSelectionStrategy interface used for testing purposes.
type mockCoinSelectionStrategy struct {
	mock.Mock
}

// ArrangeCoins implements the CoinSelectionStrategy interface.
func (m *mockCoinSelectionStrategy) ArrangeCoins(coins []Coin,
	feePerKb btcutil.Amount) ([]Coin, error) {

	args := m.Called(coins, feePerKb)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]Coin), args.Error(1)
}

// mockChain is a mock implementation of the chain.Interface.
type mockChain struct {
	mock.Mock
}

// A compile-time assertion to ensure that mockChain implements the
// chain.Interface.
var _ chain.Interface = (*mockChain)(nil)

// Start implements the chain.Interface interface.
func (m *mockChain) Start(_ context.Context) error {
	args := m.Called()
	return args.Error(0)
}

// Stop implements the chain.Interface interface.
func (m *mockChain) Stop() {
	m.Called()
}

// WaitForShutdown implements the chain.Interface interface.
func (m *mockChain) WaitForShutdown() {
	m.Called()
}

// GetBestBlock implements the chain.Interface interface.
func (m *mockChain) GetBestBlock() (*chainhash.Hash, int32, error) {
	args := m.Called()
	hash, _ := args.Get(0).(*chainhash.Hash)

	return hash, args.Get(1).(int32), args.Error(2)
}

// GetBlock implements the chain.Interface interface.
func (m *mockChain) GetBlock(hash *chainhash.Hash) (*wire.MsgBlock, error) {
	args := m.Called(hash)
	block, _ := args.Get(0).(*wire.MsgBlock)

	return block, args.Error(1)
}

// GetBlockHash implements the chain.Interface interface.
func (m *mockChain) GetBlockHash(height int64) (*chainhash.Hash, error) {
	args := m.Called(height)
	hash, _ := args.Get(0).(*chainhash.Hash)

	return hash, args.Error(1)
}

// GetBlockHeader implements the chain.Interface interface.
func (m *mockChain) GetBlockHeader(
	hash *chainhash.Hash) (*wire.BlockHeader, error) {

	args := m.Called(hash)
	header, _ := args.Get(0).(*wire.BlockHeader)

	return header, args.Error(1)
}

func (m *mockChain) GetBlockHashes(start, end int64) ([]chainhash.Hash, error) {
	args := m.Called(start, end)
	return args.Get(0).([]chainhash.Hash), args.Error(1)
}

func (m *mockChain) GetBlockHeaders(
	hashes []chainhash.Hash) ([]*wire.BlockHeader, error) {

	args := m.Called(hashes)
	return args.Get(0).([]*wire.BlockHeader), args.Error(1)
}

func (m *mockChain) GetCFilters(hashes []chainhash.Hash,
	filterType wire.FilterType) ([]*gcs.Filter, error) {

	args := m.Called(hashes, filterType)
	return args.Get(0).([]*gcs.Filter), args.Error(1)
}

func (m *mockChain) GetBlocks(
	hashes []chainhash.Hash) ([]*wire.MsgBlock, error) {

	args := m.Called(hashes)
	return args.Get(0).([]*wire.MsgBlock), args.Error(1)
}

// IsCurrent implements the chain.Interface interface.
func (m *mockChain) IsCurrent() bool {
	args := m.Called()
	return args.Bool(0)
}

// GetCFilter implements the chain.Interface interface.
func (m *mockChain) GetCFilter(hash *chainhash.Hash,
	filterType wire.FilterType) (*gcs.Filter, error) {

	args := m.Called(hash, filterType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*gcs.Filter), args.Error(1)
}

// FilterBlocks implements the chain.Interface interface.
func (m *mockChain) FilterBlocks(req *chain.FilterBlocksRequest) (
	*chain.FilterBlocksResponse, error) {

	args := m.Called(req)
	resp, _ := args.Get(0).(*chain.FilterBlocksResponse)

	return resp, args.Error(1)
}

// BlockStamp implements the chain.Interface interface.
func (m *mockChain) BlockStamp() (*waddrmgr.BlockStamp, error) {
	args := m.Called()
	stamp, _ := args.Get(0).(*waddrmgr.BlockStamp)

	return stamp, args.Error(1)
}

// SendRawTransaction implements the chain.Interface interface.
func (m *mockChain) SendRawTransaction(tx *wire.MsgTx,
	allowHighFees bool) (*chainhash.Hash, error) {

	args := m.Called(tx, allowHighFees)
	hash, _ := args.Get(0).(*chainhash.Hash)

	return hash, args.Error(1)
}

// Rescan implements the chain.Interface interface.
func (m *mockChain) Rescan(hash *chainhash.Hash, addrs []btcutil.Address,
	outpoints map[wire.OutPoint]btcutil.Address) error {

	args := m.Called(hash, addrs, outpoints)
	return args.Error(0)
}

// NotifyReceived implements the chain.Interface interface.
func (m *mockChain) NotifyReceived(addrs []btcutil.Address) error {
	args := m.Called(addrs)
	return args.Error(0)
}

// NotifyBlocks implements the chain.Interface interface.
func (m *mockChain) NotifyBlocks() error {
	args := m.Called()
	return args.Error(0)
}

// Notifications implements the chain.Interface interface.
func (m *mockChain) Notifications() <-chan any {
	args := m.Called()
	ch, _ := args.Get(0).(<-chan any)

	return ch
}

// BackEnd implements the chain.Interface interface.
func (m *mockChain) BackEnd() string {
	args := m.Called()
	return args.String(0)
}

// TestMempoolAccept implements the chain.Interface interface.
func (m *mockChain) TestMempoolAccept(txns []*wire.MsgTx,
	maxFeeRate float64) ([]*btcjson.TestMempoolAcceptResult, error) {

	args := m.Called(txns, maxFeeRate)
	res, _ := args.Get(0).([]*btcjson.TestMempoolAcceptResult)

	return res, args.Error(1)
}

// MapRPCErr implements the chain.Interface interface.
func (m *mockChain) MapRPCErr(err error) error {
	args := m.Called(err)
	return args.Error(0)
}

// mockNeutrinoChain is a mock implementation of the chain.NeutrinoChainService
// interface.
type mockNeutrinoChain struct {
	mockChain
}

// A compile-time assertion to ensure that mockNeutrinoChain implements the
// chain.NeutrinoChainService.
var _ chain.NeutrinoChainService = (*mockNeutrinoChain)(nil)

// Stop implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) Stop() error {
	args := m.Called()
	return args.Error(0)
}

// GetBlock implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) GetBlock(hash chainhash.Hash,
	opts ...neutrino.QueryOption) (*btcutil.Block, error) {

	args := m.Called(hash, opts)
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(*btcutil.Block); ok {
			return val, args.Error(1)
		}
	}

	return nil, args.Error(1)
}

// GetCFilter implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) GetCFilter(hash chainhash.Hash,
	filterType wire.FilterType,
	opts ...neutrino.QueryOption) (*gcs.Filter, error) {

	args := m.Called(hash, filterType, opts)
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(*gcs.Filter); ok {
			return val, args.Error(1)
		}
	}

	return nil, args.Error(1)
}

// GetBlockHeight implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) GetBlockHeight(
	hash *chainhash.Hash) (int32, error) {

	args := m.Called(hash)
	return args.Get(0).(int32), args.Error(1)
}

// BestBlock implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) BestBlock() (*headerfs.BlockStamp, error) {
	args := m.Called()
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(*headerfs.BlockStamp); ok {
			return val, args.Error(1)
		}
	}

	return nil, args.Error(1)
}

// SendTransaction implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) SendTransaction(tx *wire.MsgTx) error {
	args := m.Called(tx)
	return args.Error(0)
}

// GetUtxo implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) GetUtxo(
	opts ...neutrino.RescanOption) (*neutrino.SpendReport, error) {

	args := m.Called(opts)
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(*neutrino.SpendReport); ok {
			return val, args.Error(1)
		}
	}

	return nil, args.Error(1)
}

// BanPeer implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) BanPeer(addr string,
	reason banman.Reason) error {

	args := m.Called(addr, reason)
	return args.Error(0)
}

// IsBanned implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) IsBanned(addr string) bool {
	args := m.Called(addr)
	return args.Bool(0)
}

// AddPeer implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) AddPeer(peer *neutrino.ServerPeer) {
	m.Called(peer)
}

// AddBytesSent implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) AddBytesSent(bytes uint64) {
	m.Called(bytes)
}

// AddBytesReceived implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) AddBytesReceived(bytes uint64) {
	m.Called(bytes)
}

// NetTotals implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) NetTotals() (uint64, uint64) {
	args := m.Called()

	var a, b uint64
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(uint64); ok {
			a = val
		}
	}

	if args.Get(1) != nil {
		if val, ok := args.Get(1).(uint64); ok {
			b = val
		}
	}

	return a, b
}

// UpdatePeerHeights implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) UpdatePeerHeights(hash *chainhash.Hash,
	height int32, peer *neutrino.ServerPeer) {

	m.Called(hash, height, peer)
}

// ChainParams implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) ChainParams() chaincfg.Params {
	args := m.Called()
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(chaincfg.Params); ok {
			return val
		}
	}

	return chaincfg.Params{}
}

// PeerByAddr implements the chain.NeutrinoChainService interface.
func (m *mockNeutrinoChain) PeerByAddr(
	addr string) *neutrino.ServerPeer {

	args := m.Called(addr)
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(*neutrino.ServerPeer); ok {
			return val
		}
	}

	return nil
}

// mockManagedPubKeyAddr is a mock implementation of the
// waddrmgr.ManagedPubKeyAddress interface, used for testing.
type mockManagedPubKeyAddr struct {
	mock.Mock
}

// A compile-time check to ensure that mockManagedPubKeyAddr implements the
// ManagedPubKeyAddress interface.
var _ waddrmgr.ManagedPubKeyAddress = (*mockManagedPubKeyAddr)(nil)

// PubKey implements the waddrmgr.ManagedPubKeyAddress interface.
func (m *mockManagedPubKeyAddr) PubKey() *btcec.PublicKey {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}

	return args.Get(0).(*btcec.PublicKey)
}

// ExportPrivKey implements the waddrmgr.ManagedPubKeyAddress interface.
func (m *mockManagedPubKeyAddr) ExportPrivKey() (*btcutil.WIF, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*btcutil.WIF), args.Error(1)
}

// ExportPubKey implements the waddrmgr.ManagedPubKeyAddress interface.
func (m *mockManagedPubKeyAddr) ExportPubKey() string {
	args := m.Called()
	return args.String(0)
}

// PrivKey implements the waddrmgr.ManagedPubKeyAddress interface.
func (m *mockManagedPubKeyAddr) PrivKey() (*btcec.PrivateKey, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*btcec.PrivateKey), args.Error(1)
}

// Address implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedPubKeyAddr) Address() btcutil.Address {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}

	return args.Get(0).(btcutil.Address)
}

// AddrHash implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedPubKeyAddr) AddrHash() []byte {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}

	return args.Get(0).([]byte)
}

// Imported implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedPubKeyAddr) Imported() bool {
	args := m.Called()
	return args.Bool(0)
}

// Internal implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedPubKeyAddr) Internal() bool {
	args := m.Called()
	return args.Bool(0)
}

// Compressed implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedPubKeyAddr) Compressed() bool {
	args := m.Called()
	return args.Bool(0)
}

// Used implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedPubKeyAddr) Used(ns walletdb.ReadBucket) bool {
	args := m.Called(ns)
	return args.Bool(0)
}

// AddrType implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedPubKeyAddr) AddrType() waddrmgr.AddressType {
	args := m.Called()
	return args.Get(0).(waddrmgr.AddressType)
}

// InternalAccount implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedPubKeyAddr) InternalAccount() uint32 {
	args := m.Called()
	return args.Get(0).(uint32)
}

// DerivationInfo implements the waddrmgr.ManagedAddress interface.
func (m *mockManagedPubKeyAddr) DerivationInfo() (waddrmgr.KeyScope,
	waddrmgr.DerivationPath, bool) {

	args := m.Called()

	return args.Get(0).(waddrmgr.KeyScope),
		args.Get(1).(waddrmgr.DerivationPath), args.Bool(2)
}

// mockSpendDetails is a mock implementation of the SpendDetails interface.
type mockSpendDetails struct {
	mock.Mock
}

// A compile-time assertion to ensure that mockSpendDetails implements the
// SpendDetails interface.
var _ SpendDetails = (*mockSpendDetails)(nil)

// Sign implements the SpendDetails interface.
func (m *mockSpendDetails) Sign(params *RawSigParams,
	privKey *btcec.PrivateKey) (RawSignature, error) {

	args := m.Called(params, privKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(RawSignature), args.Error(1)
}

// isSpendDetails implements the SpendDetails interface.
func (m *mockSpendDetails) isSpendDetails() {}

// mockController is a mock implementation of the Controller interface.
type mockController struct {
	mock.Mock
}

// Compile-time check to ensure mockController implements Controller.
var _ Controller = (*mockController)(nil)

// Unlock implements the Controller interface.
func (m *mockController) Unlock(ctx context.Context, req UnlockRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

// Lock implements the Controller interface.
func (m *mockController) Lock(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// ChangePassphrase implements the Controller interface.
func (m *mockController) ChangePassphrase(ctx context.Context,
	req ChangePassphraseRequest) error {

	args := m.Called(ctx, req)
	return args.Error(0)
}

// Info implements the Controller interface.
func (m *mockController) Info(ctx context.Context) (*Info, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*Info), args.Error(1)
}

// Start implements the Controller interface.
func (m *mockController) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// Stop implements the Controller interface.
func (m *mockController) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// Resync implements the Controller interface.
func (m *mockController) Resync(ctx context.Context, startHeight uint32) error {
	args := m.Called(ctx, startHeight)
	return args.Error(0)
}

// Rescan implements the Controller interface.
func (m *mockController) Rescan(ctx context.Context, startHeight uint32,
	targets []waddrmgr.AccountScope) error {

	args := m.Called(ctx, startHeight, targets)
	return args.Error(0)
}

// mockChainSyncer is a mock implementation of the chainSyncer interface.
type mockChainSyncer struct {
	mock.Mock
}

// A compile-time assertion to ensure that mockChainSyncer implements the
// chainSyncer interface.
var _ chainSyncer = (*mockChainSyncer)(nil)

// run implements the chainSyncer interface.
func (m *mockChainSyncer) run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// requestScan implements the chainSyncer interface.
func (m *mockChainSyncer) requestScan(ctx context.Context, req *scanReq) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

// syncState implements the chainSyncer interface.
func (m *mockChainSyncer) syncState() syncState {
	args := m.Called()
	return args.Get(0).(syncState)
}

// mockTxPublisher is a mock implementation of the TxPublisher interface.
type mockTxPublisher struct {
	mock.Mock
}

// A compile-time check to ensure that mockTxPublisher implements the
// TxPublisher interface.
var _ TxPublisher = (*mockTxPublisher)(nil)

// CheckMempoolAcceptance implements the TxPublisher interface.
func (m *mockTxPublisher) CheckMempoolAcceptance(ctx context.Context,
	tx *wire.MsgTx) error {

	args := m.Called(ctx, tx)
	return args.Error(0)
}

// Broadcast implements the TxPublisher interface.
func (m *mockTxPublisher) Broadcast(ctx context.Context, tx *wire.MsgTx,
	label string) error {

	args := m.Called(ctx, tx, label)
	return args.Error(0)
}

// mockAddress is a mock implementation of the btcutil.Address interface.
// It embeds mock.Mock to allow for flexible stubbing of its methods,
// enabling granular control over address behavior in tests.
type mockAddress struct {
	mock.Mock
}

// EncodeAddress mocks the EncodeAddress method.
// It returns a predefined string based on mock expectations.
func (m *mockAddress) EncodeAddress() string {
	args := m.Called()
	return args.String(0)
}

// ScriptAddress mocks the ScriptAddress method.
// It returns a predefined byte slice based on mock expectations.
func (m *mockAddress) ScriptAddress() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// IsForNet mocks the IsForNet method.
// It returns a predefined boolean based on mock expectations.
func (m *mockAddress) IsForNet(params *chaincfg.Params) bool {
	args := m.Called(params)
	return args.Bool(0)
}

// String mocks the String method.
// It returns a predefined string based on mock expectations.
func (m *mockAddress) String() string {
	args := m.Called()
	return args.String(0)
}

// mockManagedTaprootScriptAddress is a mock implementation of the
// waddrmgr.ManagedTaprootScriptAddress interface.
type mockManagedTaprootScriptAddress struct {
	mockManagedAddress
}

// A compile-time assertion to ensure that mockManagedTaprootScriptAddress
// implements the waddrmgr.ManagedTaprootScriptAddress interface.
var _ waddrmgr.ManagedTaprootScriptAddress = (*mockManagedTaprootScriptAddress)(
	nil,
)

// Script implements the waddrmgr.ManagedScriptAddress interface.
func (m *mockManagedTaprootScriptAddress) Script() ([]byte, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]byte), args.Error(1)
}

// TaprootScript implements the waddrmgr.ManagedTaprootScriptAddress interface.
func (m *mockManagedTaprootScriptAddress) TaprootScript() (
	*waddrmgr.Tapscript, error) {

	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*waddrmgr.Tapscript), args.Error(1)
}
