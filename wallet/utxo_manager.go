// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet provides a bitcoin wallet implementation that is centered
// around the concept of a UtxoManager, which is responsible for managing the
// wallet's UTXO set.
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
	"github.com/btcsuite/btcwallet/wallet/internal/addresstype"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	errUtxoHeightOverflow  = errors.New("utxo height overflows int32")
	errUtxoScriptNoAddress = errors.New(
		"utxo pkScript has no extractable address",
	)
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

	infos, err := w.store.ListUTXOs(
		ctx, db.ListUtxosQuery{
			WalletID: w.id,
			MinConfs: &minConfs,
			MaxConfs: &maxConfs,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list utxos: %w", err)
	}

	utxos := make([]*Utxo, 0, len(infos))
	for i := range infos {
		// The store has no scope to disambiguate a bare account name,
		// so the wallet applies the account-name filter here rather
		// than in the ListUTXOs query.
		if query.Account != "" &&
			infos[i].AccountName != query.Account {

			continue
		}

		utxo, err := w.buildWalletUtxoFromStore(
			&infos[i], currentHeight,
		)
		if err != nil {
			return nil, err
		}

		utxos = append(utxos, utxo)
	}

	// Sort the outputs in ascending order of value. This is a convention
	// to make the list more predictable and potentially useful for coin
	// selection algorithms that prefer smaller UTXOs.
	sort.Slice(utxos, func(i, j int) bool {
		return utxos[i].Amount < utxos[j].Amount
	})

	return utxos, nil
}

// buildWalletUtxoFromStore converts one store-level UTXO row into the
// wallet's public Utxo view. The enrichment fields populated by the
// store (AccountName, Origin, AddrType, HasScript, IsLocked) supersede
// the prior per-UTXO follow-up calls to GetAddress / ListLeasedOutputs.
//
// This is a pure mapper: the store only returns wallet-owned, enrichable
// rows, so a row whose script cannot be converted to an address is an
// unexpected store/wallet disagreement and surfaces as an error rather
// than a silent skip. Account filtering is the caller's responsibility
// and is applied before this conversion.
//
// Spendability follows ADR 0012 (wallet-level watch-only invariant):
// a UTXO is spendable when the wallet is not watch-only AND the owning
// account is not imported. Imported-account outputs are unspendable
// even when the wallet holds private-key material for them — matching
// the legacy waddrmgr.AddressDetails policy that this routing path
// replaces.
func (w *Wallet) buildWalletUtxoFromStore(info *db.UtxoInfo,
	currentHeight int32) (*Utxo, error) {

	addr := extractAddrFromPKScript(info.PkScript, w.cfg.ChainParams)
	if addr == nil {
		return nil, fmt.Errorf("%w: outpoint %v", errUtxoScriptNoAddress,
			info.OutPoint)
	}

	walletAddrType, err := addresstype.ToWallet(
		info.AddrType, info.HasScript,
	)
	if err != nil {
		return nil, err
	}

	confirmations, err := utxoConfirmations(info.Height, currentHeight)
	if err != nil {
		return nil, err
	}

	spendable := !w.IsWatchOnly() &&
		info.Origin != db.ImportedAccount

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
		Account:       info.AccountName,
		AddressType:   walletAddrType,
		Locked:        info.IsLocked,
	}, nil
}

// utxoConfirmations converts one db-native UTXO height into wallet confirmation
// semantics.
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

// GetUtxo returns one wallet-owned UTXO together with its wallet-facing
// metadata.
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
		return nil, fmt.Errorf("get utxo: %w", err)
	}

	utxo, err := w.buildWalletUtxoFromStore(info, currentHeight)
	if err != nil {
		return nil, err
	}

	return utxo, nil
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
func (w *Wallet) LeaseOutput(_ context.Context, id wtxmgr.LockID,
	op wire.OutPoint, duration time.Duration) (time.Time, error) {

	err := w.state.validateStarted()
	if err != nil {
		return time.Time{}, err
	}

	var expiration time.Time

	err = walletdb.Update(w.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		expiration, err = w.txStore.LockOutput(
			txmgrNs, id, op, duration,
		)

		return err
	})

	return expiration, err
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
