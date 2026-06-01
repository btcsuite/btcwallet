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
	Address address.Address

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

// ListUnspent returns a slice of unspent transaction outputs that match the
// query.
//
// This method provides a comprehensive view of the wallet's UTXO set, allowing
// for filtering by account and confirmation status. The results are enriched
// with detailed information about each UTXO, such as its address, account,
// and spendability.
//
// How it works:
// The method performs a full scan of all UTXOs in the wallet's transaction
// store (`wtxmgr`). For each UTXO, it applies the specified filters (account,
// confirmations). If a UTXO matches, the method then performs an additional
// lookup in the address manager (`waddrmgr`) to enrich the UTXO data with
// details like the owning account name, address type, and spendability. This
// process of fetching a list and then performing a lookup for each item is
// known as the "N+1 query problem" and is a known inefficiency (see TODO).
//
// Logical Steps:
//  1. Initiate a single, read-only database transaction to ensure a
//     consistent view of the data.
//  2. Fetch all unspent transaction outputs from the `wtxmgr` namespace.
//  3. Sort the outputs in ascending order of value. This is a convention to
//     make the list more predictable and potentially useful for coin
//     selection algorithms that prefer larger UTXOs.
//  4. Iterate through each UTXO:
//     a. Calculate its current confirmation status based on the wallet's
//     synced block height.
//     b. Apply the `MinConfs` and `MaxConfs` filters from the query.
//     c. Extract the address from the UTXO's public key script. For
//     multi-address scripts, the first address is used.
//     d. Call `waddrmgr.AddressDetails` to get the spendability status,
//     account name, and address type in a single, efficient lookup.
//     e. Apply the `Account` filter from the query.
//     f. If all filters pass, construct the final `Utxo` struct with all
//     the combined data.
//  5. Append the `Utxo` to the result slice.
//  6. After iterating through all UTXOs, return the final slice.
//
// Database Actions:
//   - This method performs a single read-only database transaction
//     (`walletdb.View`).
//   - It reads from both the `wtxmgr` (for UTXOs) and `waddrmgr` (for
//     address details) namespaces.
//
// Time Complexity:
//   - The complexity is O(U * A_l), where U is the total number of unspent
//     transaction outputs in the wallet and A_l is the average cost of the
//     address and account lookups (`AddressDetails`). This is due to the N+1
//     query problem where each UTXO requires additional lookups.
//
// TODO(yy): The current implementation of ListUnspent fetches all UTXOs
// from the database and then filters them in memory. This is inefficient for
// wallets with a large number of UTXOs. The upcoming SQL schema redesign should
// address the following issues:
//
//  1. **N+1 Query Problem:** The function iterates through all unspent outputs
//     and performs separate database lookups for each one to retrieve its full
//     details. The database schema should be denormalized to include this data
//     directly in the `unspent` value, which would turn the N+1 query into a
//     single, efficient bucket scan.
//
//  2. **Lack of Pagination:** The function loads all results into a single
//     in-memory slice, which can be memory-intensive for wallets with a large
//     UTXO set. A more scalable approach would use an iterator pattern.
//
// NOTE: This is part of the UtxoManager interface implementation.
func (w *Wallet) ListUnspent(_ context.Context,
	query UtxoQuery) ([]*Utxo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	log.Debugf("ListUnspent using query: %v", query)

	syncBlock := w.addrStore.SyncedTo()
	currentHeight := syncBlock.Height

	var utxos []*Utxo

	err = walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// First, fetch all unspent transaction outputs from the UTXO
		// set.
		unspent, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}

		// Iterate through each UTXO to apply filters and enrich it with
		// address-specific details.
		for _, output := range unspent {
			utxo := w.processUnspentOutput(
				addrmgrNs, output, currentHeight, query,
			)
			if utxo != nil {
				utxos = append(utxos, utxo)
			}
		}

		return nil
	})

	// Sort the outputs in ascending order of value. This is a convention
	// to make the list more predictable and potentially useful for coin
	// selection algorithms that prefer smaller UTXOs.
	sort.Slice(utxos, func(i, j int) bool {
		return utxos[i].Amount < utxos[j].Amount
	})

	return utxos, err
}

// processUnspentOutput processes a single unspent output, applying filters and
// enriching it with address details. Returns nil if the output should be
// skipped.
func (w *Wallet) processUnspentOutput(addrmgrNs walletdb.ReadBucket,
	output wtxmgr.Credit, currentHeight int32, query UtxoQuery) *Utxo {

	confs := calcConf(output.Height, currentHeight)

	log.Tracef("Checking utxo[%v]: current height=%v, "+
		"confirm height=%v, conf=%v", output.OutPoint,
		currentHeight, output.Height, confs)

	// Apply the MinConfs and MaxConfs filters from the query.
	if confs < query.MinConfs || confs > query.MaxConfs {
		return nil
	}

	// Extract the address from the UTXO's public key script.
	// For multi-address scripts, the first address is used.
	addr := extractAddrFromPKScript(
		output.PkScript, w.cfg.ChainParams,
	)
	if addr == nil {
		return nil
	}

	// Get all the required address-related details.
	//
	// NOTE: This lookup is the source of the N+1 query problem.
	spendable, account, addrType := w.addrStore.AddressDetails(
		addrmgrNs, addr,
	)

	log.Debugf("Found address: %s from account: %s",
		addr.String(), account)

	// Apply the Account filter from the query.
	if query.Account != "" && account != query.Account {
		return nil
	}

	// A UTXO is also unspendable if it is an immature coinbase output.
	if output.FromCoinBase {
		maturity := w.cfg.ChainParams.CoinbaseMaturity
		if confs < int32(maturity) {
			spendable = false
		}
	}

	// TODO(yy): This should be a column in the new utxo SQL table. Note
	// that currently UnspentOutputs only returns unlocked outputs, so this
	// field will always be false. This will be fixed in the upcoming
	// sqlization PRs.
	locked := output.Locked

	// If all filters pass, construct the final Utxo struct with all the
	// combined data.
	return &Utxo{
		OutPoint:      output.OutPoint,
		Amount:        output.Amount,
		PkScript:      output.PkScript,
		Confirmations: confs,
		Spendable:     spendable,
		Address:       addr,
		Account:       account,
		AddressType:   addrType,
		Locked:        locked,
	}
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
