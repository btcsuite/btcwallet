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

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/addresstype"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// The following are the public, wallet-owned sentinel errors returned by the
// UTXO and lease methods (GetUtxo, LeaseOutput, ReleaseOutput). They are
// intentionally decoupled from the wallet's internal storage layers: callers
// match on these values with errors.Is and must not reach for the internal
// db.Err* sentinels (which live in an internal package) or the legacy
// wtxmgr.Err* sentinels (whose package is slated to become internal). The
// names mirror the historical wtxmgr sentinels so that downstream callers can
// migrate mechanically.
var (
	// ErrUnknownOutput is returned when the requested output is not known
	// to the wallet's UTXO set.
	ErrUnknownOutput = errors.New("unknown output")

	// ErrOutputAlreadyLocked is returned when an output is already leased
	// under a different lock ID and therefore cannot be leased again.
	ErrOutputAlreadyLocked = errors.New("output already locked")

	// ErrOutputUnlockNotAllowed is returned when an output cannot be
	// unlocked, for example because it is held under a different lock ID
	// than the one supplied.
	ErrOutputUnlockNotAllowed = errors.New("output unlock not allowed")
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
	Address address.Address

	// Account is the name of the account that owns the output.
	Account string

	// AddressType is the type of the address.
	AddressType waddrmgr.AddressType

	// Locked indicates whether the output is locked.
	Locked bool
}

// LeasedOutput describes one currently leased wallet output.
type LeasedOutput struct {
	// OutPoint is the leased transaction output identifier.
	OutPoint wire.OutPoint

	// LockID is the lease owner identifier.
	LockID wtxmgr.LockID

	// Expiration is when the current lease expires.
	Expiration time.Time
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
	ListLeasedOutputs(ctx context.Context) ([]*LeasedOutput, error)
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
		accountName := walletUtxoAccountName(&infos[i])

		// The store has no scope to disambiguate a bare account name,
		// so the wallet applies the account-name filter here rather
		// than in the ListUTXOs query.
		if query.Account != "" && accountName != query.Account {
			continue
		}

		utxo, err := w.buildWalletUtxoFromStore(
			&infos[i], accountName, currentHeight,
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

// walletUtxoAccountName returns the wallet-facing account name for a store UTXO
// row.
func walletUtxoAccountName(info *db.UtxoInfo) string {
	if info.AccountName != "" {
		return info.AccountName
	}

	return db.DefaultImportedAccountName
}

// buildWalletUtxoFromStore converts one store-level UTXO row into the
// wallet's public Utxo view. The enrichment fields populated by the
// store (AccountName, AddrType, HasScript, IsLocked) supersede the prior
// per-UTXO follow-up calls to GetAddress / ListLeasedOutputs.
//
// This is a pure mapper: the store only returns wallet-owned, enrichable
// rows, so a row whose script cannot be converted to an address is an
// unexpected store/wallet disagreement and surfaces as an error rather
// than a silent skip. Account filtering is the caller's responsibility
// and is applied before this conversion.
//
// Spendability follows ADR 0012 (wallet-level watch-only invariant) unless
// the store supplies a backend-specific override. SQL stores leave the
// override nil; kvdb uses it for grandfathered mixed-mode rows that can still
// be non-spendable inside an otherwise spendable legacy wallet. Coinbase
// maturity remains a final per-output adjustment.
func (w *Wallet) buildWalletUtxoFromStore(info *db.UtxoInfo,
	accountName string, currentHeight int32) (*Utxo, error) {

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

	spendable := !w.IsWatchOnly()
	if info.Spendable != nil {
		spendable = *info.Spendable
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
		Account:       accountName,
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
		// Translate the internal store sentinel into the public,
		// wallet-owned error so callers do not couple to the internal
		// db package.
		if errors.Is(err, db.ErrUtxoNotFound) {
			return nil, ErrUnknownOutput
		}

		return nil, fmt.Errorf("get utxo: %w", err)
	}

	utxo, err := w.buildWalletUtxoFromStore(
		info, walletUtxoAccountName(info), currentHeight,
	)
	if err != nil {
		return nil, err
	}

	return utxo, nil
}

// LeaseOutput locks an output for a given duration, reserving it so that it is
// not selected for other transactions until the lease expires.
//
// The lock is acquired by delegating to the wallet's db.Store implementation,
// which records the lease under the supplied LockID and returns its expiration
// time. The store's internal sentinels are translated into the public,
// wallet-owned errors: an unknown or already-spent output becomes
// ErrUnknownOutput and an output held under a different lock ID becomes
// ErrOutputAlreadyLocked; any other store error is wrapped for context.
//
// NOTE: This is part of the UtxoManager interface implementation.
func (w *Wallet) LeaseOutput(ctx context.Context, id wtxmgr.LockID,
	op wire.OutPoint, duration time.Duration) (time.Time, error) {

	err := w.state.validateStarted()
	if err != nil {
		return time.Time{}, err
	}

	lease, err := w.store.LeaseOutput(
		ctx, db.LeaseOutputParams{
			WalletID: w.id,
			ID:       db.LockID(id),
			OutPoint: op,
			Duration: duration,
		},
	)
	if err != nil {
		// Translate the internal store sentinels into the public,
		// wallet-owned errors so callers do not couple to the internal
		// db package.
		switch {
		case errors.Is(err, db.ErrUtxoNotFound):
			return time.Time{}, ErrUnknownOutput

		case errors.Is(err, db.ErrOutputAlreadyLeased):
			return time.Time{}, ErrOutputAlreadyLocked
		}

		return time.Time{}, fmt.Errorf("lease output: %w", err)
	}

	return lease.Expiration, nil
}

// ReleaseOutput unlocks a previously leased output, making it available for
// coin selection again.
//
// The lock is released by delegating to the wallet's db.Store implementation;
// the store's internal sentinels are translated into the public, wallet-owned
// ErrUnknownOutput / ErrOutputUnlockNotAllowed errors.
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

	err = w.store.ReleaseOutput(ctx, params)
	if err != nil {
		// Translate the internal store sentinels into the public,
		// wallet-owned errors so callers do not couple to the internal
		// db package.
		switch {
		case errors.Is(err, db.ErrUtxoNotFound):
			return ErrUnknownOutput

		case errors.Is(err, db.ErrOutputUnlockNotAllowed):
			return ErrOutputUnlockNotAllowed
		}

		return fmt.Errorf("release output: %w", err)
	}

	return nil
}

// ListLeasedOutputs returns the wallet-owned outputs that currently have active
// leases.
//
// NOTE: This is part of the UtxoManager interface implementation.
func (w *Wallet) ListLeasedOutputs(
	ctx context.Context) ([]*LeasedOutput, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	leases, err := w.store.ListLeasedOutputs(ctx, w.id)
	if err != nil {
		return nil, fmt.Errorf("list leased outputs: %w", err)
	}

	outputs := make([]*LeasedOutput, len(leases))
	for i := range leases {
		outputs[i] = &LeasedOutput{
			OutPoint:   leases[i].OutPoint,
			LockID:     wtxmgr.LockID(leases[i].LockID),
			Expiration: leases[i].Expiration,
		}
	}

	return outputs, nil
}
