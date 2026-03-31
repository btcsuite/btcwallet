// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet provides a bitcoin wallet implementation that is centered
// around the concept of a UtxoManager, which is responsible for managing the
// wallet's UTXO set.
//
// TODO(yy): bring wrapcheck back when implementing the `Store` interface.
//
//nolint:wrapcheck
package wallet

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	errUtxoHeightOverflow = errors.New("utxo height overflows int32")
)

// Utxo provides a detailed overview of an unspent transaction output.
type Utxo struct {
	// OutPoint is the transaction output identifier.
	OutPoint wire.OutPoint

	// Amount is the value of the output.
	Amount btcutil.Amount

	// PkScript is the public key script for the output.
	PkScript []byte

	// Confirmations is the number of confirmations the output has.
	Confirmations int32

	// Spendable indicates whether the output is considered spendable.
	Spendable bool

	// Address is the address associated with the output.
	Address btcutil.Address

	// Account is the name of the account that owns the output.
	Account string

	// AddressType is the type of the address.
	AddressType waddrmgr.AddressType

	// Locked indicates whether the output is locked.
	Locked bool
}

// UtxoQuery holds the set of options for a ListUnspent query.
type UtxoQuery struct {
	// Account specifies the account to query UTXOs for. If empty,
	// UTXOs from all accounts are returned.
	Account string

	// MinConfs is the minimum number of confirmations a UTXO must have.
	MinConfs int32

	// MaxConfs is the maximum number of confirmations a UTXO can have.
	MaxConfs int32
}

// UtxoManager provides an interface for querying and managing the wallet's
// UTXO set.
type UtxoManager interface {
	// ListUnspent returns a slice of all unspent transaction outputs that
	// match the query. The returned UTXOs are sorted by amount in
	// ascending order.
	ListUnspent(ctx context.Context, query UtxoQuery) ([]*Utxo, error)

	// GetUtxo returns the output information for a given outpoint.
	GetUtxo(ctx context.Context, prevOut wire.OutPoint) (*Utxo, error)

	// LeaseOutput locks an output for a given duration, preventing it from
	// being used in transactions.
	LeaseOutput(ctx context.Context, id wtxmgr.LockID,
		op wire.OutPoint, duration time.Duration) (time.Time, error)

	// ReleaseOutput unlocks a previously leased output, making it available
	// for use.
	ReleaseOutput(ctx context.Context, id wtxmgr.LockID,
		op wire.OutPoint) error

	// ListLeasedOutputs returns a list of all currently leased outputs.
	ListLeasedOutputs(ctx context.Context) ([]*wtxmgr.LockedOutput, error)
}

// ListUnspent returns the wallet-owned UTXOs that match the provided query.
//
// TODO(yy): Collapse the SQL-backed ListUnspent path into one enriched store
// read by (1) extending ListUTXOs to return account, address type,
// spendable, and locked state, (2) having the SQL backends populate those
// fields from one joined query, and (3) removing the follow-up
// ListLeasedOutputs/GetAddress composition here.
//
// NOTE: This is part of the UtxoManager interface implementation.
func (w *Wallet) ListUnspent(ctx context.Context,
	query UtxoQuery) ([]*Utxo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	log.Debugf("ListUnspent using query: %v", query)

	currentHeight := w.addrStore.SyncedTo().Height
	minConfs := query.MinConfs
	maxConfs := query.MaxConfs

	infos, err := w.store.ListUTXOs(ctx, db.ListUtxosQuery{
		WalletID: w.id,
		MinConfs: &minConfs,
		MaxConfs: &maxConfs,
		Account:  nil,
	})
	if err != nil {
		return nil, fmt.Errorf("list utxos: %w", err)
	}

	leases, err := w.store.ListLeasedOutputs(ctx, w.id)
	if err != nil {
		return nil, fmt.Errorf("list leased outputs: %w", err)
	}

	lockedOutputs := leasedOutputSet(leases)

	utxos := make([]*Utxo, 0, len(infos))
	for i := range infos {
		utxo, include, err := w.buildWalletUtxoFromStore(
			ctx, &infos[i], currentHeight, query.Account,
			lockedOutputs[infos[i].OutPoint],
		)
		if err != nil {
			return nil, err
		}

		if include {
			utxos = append(utxos, utxo)
		}
	}

	// Sort the outputs in ascending order of value. This is a convention
	// to make the list more predictable and potentially useful for coin
	// selection algorithms that prefer smaller UTXOs.
	sort.Slice(utxos, func(i, j int) bool {
		return utxos[i].Amount < utxos[j].Amount
	})

	return utxos, nil
}

// GetUtxo returns one wallet-owned UTXO together with its wallet-facing
// metadata.
//
// TODO(yy): Collapse the SQL-backed GetUtxo path into one enriched store read
// by (1) extending GetUtxo to return account, address type, spendable, and
// locked state, (2) having the SQL backends populate those fields from one
// joined query, and (3) removing the follow-up ListLeasedOutputs/GetAddress
// composition here.
//
// NOTE: This is part of the UtxoManager interface implementation.
func (w *Wallet) GetUtxo(ctx context.Context,
	prevOut wire.OutPoint) (*Utxo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	currentHeight := w.addrStore.SyncedTo().Height

	info, err := w.store.GetUtxo(ctx, db.GetUtxoQuery{
		WalletID: w.id,
		OutPoint: prevOut,
	})
	if err != nil {
		if errors.Is(err, db.ErrUtxoNotFound) {
			return nil, wtxmgr.ErrUtxoNotFound
		}

		return nil, fmt.Errorf("get utxo: %w", err)
	}

	leases, err := w.store.ListLeasedOutputs(ctx, w.id)
	if err != nil {
		return nil, fmt.Errorf("list leased outputs: %w", err)
	}

	lockedOutputs := leasedOutputSet(leases)

	utxo, include, err := w.buildWalletUtxoFromStore(
		ctx, info, currentHeight, "", lockedOutputs[info.OutPoint],
	)
	if err != nil {
		return nil, err
	}

	if !include {
		return nil, wtxmgr.ErrUtxoNotFound
	}

	return utxo, nil
}

// buildWalletUtxoFromStore converts one store-level UTXO row into the wallet's
// public Utxo view.
func (w *Wallet) buildWalletUtxoFromStore(ctx context.Context,
	info *db.UtxoInfo, currentHeight int32,
	accountFilter string, locked bool) (*Utxo, bool, error) {

	addr := extractAddrFromPKScript(info.PkScript, w.cfg.ChainParams)
	if addr == nil {
		return nil, false, nil
	}

	spendable, account, addrType, err := w.lookupStoreAddress(
		ctx, info.PkScript,
	)
	if err != nil {
		return nil, false, err
	}

	if accountFilter != "" && account != accountFilter {
		return nil, false, nil
	}

	confirmations, err := utxoConfirmations(info.Height, currentHeight)
	if err != nil {
		return nil, false, err
	}

	if info.FromCoinBase {
		maturity := w.cfg.ChainParams.CoinbaseMaturity
		if confirmations < int32(maturity) {
			spendable = false
		}
	}

	return &Utxo{
		OutPoint:      info.OutPoint,
		Amount:        info.Amount,
		PkScript:      info.PkScript,
		Confirmations: confirmations,
		Spendable:     spendable,
		Address:       addr,
		Account:       account,
		AddressType:   addrType,
		Locked:        locked,
	}, true, nil
}

// leasedOutputSet builds the active locked-outpoint set from one lease list.
func leasedOutputSet(leases []db.LeasedOutput) map[wire.OutPoint]bool {
	locked := make(map[wire.OutPoint]bool, len(leases))
	for i := range leases {
		locked[leases[i].OutPoint] = true
	}

	return locked
}

// lookupStoreAddress resolves the wallet-facing address metadata for one UTXO
// script.
func (w *Wallet) lookupStoreAddress(ctx context.Context,
	pkScript []byte) (bool, string, waddrmgr.AddressType, error) {

	addrInfo, err := w.store.GetAddress(
		ctx, db.GetAddressQuery{
			WalletID:     w.id,
			ScriptPubKey: pkScript,
		},
	)
	if err != nil {
		return false, "", 0, fmt.Errorf("get address: %w", err)
	}

	walletAddrType, err := walletAddressType(addrInfo.AddrType)
	if err != nil {
		return false, "", 0, err
	}

	return !addrInfo.IsWatchOnly, addrInfo.AccountName, walletAddrType, nil
}

// utxoConfirmations converts one db-native UTXO height into wallet
// confirmation semantics.
func utxoConfirmations(height uint32, currentHeight int32) (int32, error) {
	if height == db.UnminedHeight {
		return 0, nil
	}

	txHeight, ok := safeUint32ToInt32(height)
	if !ok {
		return 0, fmt.Errorf("%w: %d", errUtxoHeightOverflow, height)
	}

	return calcConf(txHeight, currentHeight), nil
}

// LeaseOutput locks an output for a given duration, preventing it from being
// used in transactions.
//
// This method allows a caller to reserve a specific UTXO for a certain period,
// making it unavailable for other operations like coin selection. This is
// useful in scenarios where a transaction is being built and its inputs need to
// be protected from being used by other concurrent operations.
//
// How it works:
// The method delegates the locking operation to the underlying transaction
// store (`wtxmgr`), which maintains a record of all leased outputs. The lease
// is identified by a unique `LockID` and has a specific `duration`.
//
// Logical Steps:
//  1. Initiate a read-write database transaction.
//  2. Call the `wtxmgr.LockOutput` method with the provided `LockID`,
//     outpoint, and `duration`.
//  3. The `wtxmgr` checks if the output is known and not already locked by a
//     different ID.
//  4. If the checks pass, it records the lock with an expiration time.
//  5. The expiration time is returned to the caller.
//
// Database Actions:
//   - This method performs a single read-write database transaction
//     (`walletdb.Update`).
//   - It writes to the `wtxmgr` namespace to record the output lock.
//
// Time Complexity:
//   - The complexity is O(1) as it involves a direct lookup and write in the
//     database.
//
// TODO(yy): The current `wtxmgr.LockOutput` implementation does not check if
// the output is already spent by an unmined transaction. This could lead to a
// scenario where a spent output is leased. The implementation should be
// improved to perform this check.
//
// NOTE: This is part of the UtxoManager interface implementation.
func (w *Wallet) LeaseOutput(ctx context.Context, id wtxmgr.LockID,
	op wire.OutPoint, duration time.Duration) (time.Time, error) {

	err := w.state.validateStarted()
	if err != nil {
		return time.Time{}, err
	}

	lease, err := w.store.LeaseOutput(ctx, db.LeaseOutputParams{
		WalletID: w.id,
		ID:       db.LockID(id),
		OutPoint: op,
		Duration: duration,
	})
	if err != nil {
		switch {
		case errors.Is(err, db.ErrUtxoNotFound):
			return time.Time{}, wtxmgr.ErrUnknownOutput

		case errors.Is(err, db.ErrOutputAlreadyLeased):
			return time.Time{}, wtxmgr.ErrOutputAlreadyLocked
		}

		return time.Time{}, fmt.Errorf("lease output: %w", err)
	}

	return lease.Expiration, nil
}

// ReleaseOutput unlocks a previously leased output, making it available for
// coin selection again.
//
// The lock is released by delegating to the wallet's db.Store implementation.
func (w *Wallet) ReleaseOutput(ctx context.Context, id wtxmgr.LockID,
	op wire.OutPoint) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	params := db.ReleaseOutputParams{
		WalletID: w.id,
		ID:       [32]byte(id),
		OutPoint: op,
	}

	return w.store.ReleaseOutput(ctx, params)
}

// ListLeasedOutputs returns a list of all currently leased outputs.
//
// This method provides a way to inspect which UTXOs are currently locked and
// when their leases expire. This can be useful for debugging and for managing
// long-lived locks.
//
// How it works:
// The method delegates the listing operation to the underlying transaction
// store (`wtxmgr`), which scans its record of all leased outputs.
//
// Logical Steps:
//  1. Initiate a read-only database transaction.
//  2. Call the `wtxmgr.ListLeasedOutputs` method.
//  3. The `wtxmgr` iterates through all the recorded locks and returns them
//     as a slice.
//
// Database Actions:
//   - This method performs a single read-only database transaction
//     (`walletdb.View`).
//   - It reads from the `wtxmgr` namespace to get the list of leased
//     outputs.
//
// Time Complexity:
//   - The complexity is O(L), where L is the number of leased outputs, as it
//     involves a full scan of the leased outputs bucket.
//
// TODO(yy): The current `wtxmgr.ListLeasedOutputs` implementation returns a
// struct from the `wtxmgr` package. This is a leaky abstraction. The method
// should return a struct defined in the `wallet` package to maintain a clean
// separation of concerns.
//
// NOTE: This is part of the UtxoManager interface implementation.
func (w *Wallet) ListLeasedOutputs(
	_ context.Context) ([]*wtxmgr.LockedOutput, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	var leasedOutputs []*wtxmgr.LockedOutput

	err = walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		leasedOutputs, err = w.txStore.ListLockedOutputs(txmgrNs)

		return err
	})

	return leasedOutputs, err
}
