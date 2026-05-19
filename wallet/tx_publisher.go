// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet provides a bitcoin wallet implementation that is ready for
// use.
//
// TODO(yy): bring wrapcheck back when implementing the `Store` interface.
//
//nolint:wrapcheck
package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/davecgh/go-spew/spew"
)

var (
	// ErrMempoolAccept is a sentinel error used to indicate that the
	// mempool acceptance test returned an unexpected number of results.
	ErrMempoolAccept = errors.New(
		"expected 1 result from TestMempoolAccept",
	)
)

// TxPublisher provides an interface for publishing transactions.
type TxPublisher interface {
	// CheckMempoolAcceptance checks if a transaction would be accepted by
	// the mempool without broadcasting.
	CheckMempoolAcceptance(ctx context.Context, tx *wire.MsgTx) error

	// Broadcast broadcasts a transaction to the network.
	Broadcast(ctx context.Context, tx *wire.MsgTx, label string) error
}

// A compile time check to ensure that Wallet implements the interface.
var _ TxPublisher = (*Wallet)(nil)

// CheckMempoolAcceptance checks if a transaction would be accepted by the
// mempool without broadcasting.
func (w *Wallet) CheckMempoolAcceptance(_ context.Context,
	tx *wire.MsgTx) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	if tx == nil {
		return ErrTxCannotBeNil
	}

	// TODO(yy): thread context through.
	// The TestMempoolAccept rpc expects a slice of transactions.
	txns := []*wire.MsgTx{tx}

	// Use a max feerate of 0 means the default value will be used when
	// testing mempool acceptance. The default max feerate is 0.10 BTC/kvb,
	// or 10,000 sat/vb.
	maxFeeRate := float64(0)

	results, err := w.cfg.Chain.TestMempoolAccept(txns, maxFeeRate)
	if err != nil {
		return err
	}

	// Sanity check that the expected single result is returned.
	if len(results) != 1 {
		return ErrMempoolAccept
	}

	result := results[0]

	// If the transaction is allowed, we can return early.
	if result.Allowed {
		return nil
	}

	// Otherwise, we'll map the reason to a concrete error type and return
	// it.
	//
	//nolint:err113
	err = errors.New(result.RejectReason)

	return w.cfg.Chain.MapRPCErr(err)
}

// Broadcast broadcasts a tx to the network. It is the main implementation of
// the TxPublisher interface.
func (w *Wallet) Broadcast(ctx context.Context, tx *wire.MsgTx,
	label string) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	if tx == nil {
		return ErrTxCannotBeNil
	}

	// We'll start by checking if the tx is acceptable to the mempool.
	err = w.checkMempool(ctx, tx)
	if errors.Is(err, errAlreadyBroadcasted) {
		return nil
	}

	if err != nil {
		return err
	}

	// First, we'll attempt to add the tx to our wallet's DB. This will
	// allow us to track the tx's confirmation status, and also
	// re-broadcast it upon startup. If any of the subsequent steps fail,
	// this tx is invalidated via InvalidateUnminedTx.
	//
	// recorded reports whether a tx row was actually written; it gates the
	// invalidation below so a wallet-unrelated tx (never recorded) is not
	// invalidated, which would clobber the publish error with ErrTxNotFound.
	ourAddrs, recorded, err := w.addTxToWallet(ctx, tx, label)
	if err != nil {
		return err
	}

	// Now, we'll attempt to publish the tx. On successful attempt, we
	// return immediately. On any failures, we invalidate it in the tx store
	// to prevent subsequent attempts with stale transaction data.
	err = w.publishTx(tx, ourAddrs)
	if err == nil {
		return nil
	}

	txid := tx.TxHash()
	log.Errorf("%v: broadcast failed: %v", txid, err)

	// If we never recorded this tx (it is wallet-unrelated), there is
	// nothing to invalidate, so we return the original publish error as-is
	// rather than overwriting it with cleanup context.
	if !recorded {
		return err
	}

	// If the tx was rejected for any other reason, then we'll invalidate it
	// from the tx store, as otherwise, we'll attempt to continually
	// re-broadcast it, and the UTXO state of the wallet won't be accurate.
	removeErr := w.invalidateUnminedTx(ctx, tx)
	if removeErr != nil {
		log.Warnf("Unable to invalidate tx %v after broadcast failed: %v",
			txid, removeErr)

		// Return a wrapped error to give the caller full context.
		return fmt.Errorf("broadcast failed: %w; and failed to "+
			"invalidate in wallet: %v", err, removeErr)
	}

	return err
}

var (
	// errAlreadyBroadcasted is a sentinel error used to indicate that a tx
	// has already been broadcast.
	errAlreadyBroadcasted = errors.New("tx already broadcasted")

	// ErrTxCannotBeNil is returned when a nil transaction is passed to a
	// function.
	ErrTxCannotBeNil = errors.New("tx cannot be nil")

	// ErrTxRetainedInvalid is returned when a tx cannot be recorded for
	// publishing because the store already retains a row for the same hash in
	// a terminal invalid state (failed or replaced). The record-before-publish
	// step refuses to report success in that case so the caller does not
	// publish a tx whose only stored row is invalid and untracked.
	ErrTxRetainedInvalid = errors.New("tx exists in a retained invalid state")
)

// checkMempool is a helper function that checks if a tx is acceptable to the
// mempool before broadcasting.
func (w *Wallet) checkMempool(ctx context.Context,
	tx *wire.MsgTx) error {

	// We'll start by checking if the tx is acceptable to the mempool.
	err := w.CheckMempoolAcceptance(ctx, tx)

	switch {
	// If the tx is already in the mempool or confirmed, we can return
	// early.
	case errors.Is(err, chain.ErrTxAlreadyInMempool),
		errors.Is(err, chain.ErrTxAlreadyKnown),
		errors.Is(err, chain.ErrTxAlreadyConfirmed):

		log.Infof("Tx %v already broadcasted", tx.TxHash())

		// TODO(yy): Update the Store layer with the caller-supplied
		// label when the transaction is already known. With this
		// change, the label passed in will be ignored if the tx is
		// already known.
		return errAlreadyBroadcasted

	// If the backend does not support the mempool acceptance test, we'll
	// just attempt to publish the tx.
	case errors.Is(err, rpcclient.ErrBackendVersion),
		errors.Is(err, chain.ErrUnimplemented):

		log.Warnf("Backend does not support mempool acceptance test, "+
			"broadcasting directly: %v", err)

		return nil

	// If the tx was rejected for any other reason, we'll return the error
	// directly.
	case err != nil:
		return fmt.Errorf("tx rejected by mempool: %w", err)

	// Otherwise, the tx is valid and we can publish it.
	default:
		return nil
	}
}

// creditInfo is a struct that holds all the information needed to atomically
// record a transaction credit.
type creditInfo struct {
	// index is the output index of the credit.
	index uint32

	// addr is the address of the credit.
	addr btcutil.Address
}

// ownedAddrInfo holds information about a wallet-owned address and the
// transaction output indices that pay to it.
type ownedAddrInfo struct {
	// addr is the wallet-owned address.
	addr btcutil.Address

	// outputIndices contains the transaction output indices that contain
	// this address. The indices are not guaranteed to be sorted in any
	// order.
	outputIndices []uint32
}

// addTxToWallet adds a tx to the wallet's database. This function is a critical
// part of the wallet's transaction processing pipeline and is designed for high
// performance and atomicity. It follows a four-stage process:
//
// 1. Extract: First, it performs a CPU-intensive, in-memory pre-processing
// step to parse all transaction outputs and extract all potential addresses.
// This is done outside of any database transaction to avoid holding locks
// during computationally expensive work.
//
// 2. Filter: Second, it uses Store address lookups to filter the large list of
// potential addresses down to the small set that is actually owned by the
// wallet. This minimizes the time spent in the final, more expensive write.
//
// 3. Plan: Third, it prepares a definitive "write plan" in memory. This plan
// is a simple slice of structs that contains all the information needed to
// atomically update the database. This step ensures that transactions with
// multiple outputs to the same address are handled correctly.
//
// 4. Execute: Finally, it executes this plan within a minimal, atomic write
// transaction. This transaction contains no business logic and only performs
// the necessary database writes, ensuring that the exclusive database lock is
// held for the shortest possible time.
//
// It returns the wallet-owned output addresses and a recorded flag reporting
// whether a tx row was actually written to the store. The flag is required
// because a debit-only sweep records a row yet returns zero addresses, so
// callers cannot infer recording from the address slice alone.
func (w *Wallet) addTxToWallet(ctx context.Context, tx *wire.MsgTx,
	label string) ([]btcutil.Address, bool, error) {

	// Stage 1: Extract potential addresses from all transaction outputs.
	// This is a CPU-intensive operation that is performed entirely in
	// memory, without holding any database locks.
	txOutAddrs := w.extractTxAddrs(tx)

	// Stage 2: Filter the extracted addresses to find which ones are owned
	// by the wallet.
	ownedAddrs, err := w.filterOwnedAddresses(ctx, txOutAddrs)
	if err != nil {
		return nil, false, err
	}

	// If the transaction has no outputs relevant to us, it may still be a
	// sweep that spends our own coins. We check the input side before
	// giving up so the tx is still tracked (and can later be invalidated).
	if len(ownedAddrs) == 0 {
		spendsOurs, err := w.spendsWalletOutput(ctx, tx)
		if err != nil {
			return nil, false, err
		}

		// Neither outputs nor inputs are wallet-relevant, so we can
		// safely exit without recording anything. recorded is false so
		// the caller does not invalidate a tx that was never written.
		if !spendsOurs {
			return nil, false, nil
		}

		// The tx spends a wallet output but credits none, so record it
		// with an empty credit set. It is now tracked, so recorded is
		// true even though no addresses are returned.
		err = w.recordTxAndCredits(ctx, tx, label, nil)
		if err != nil {
			return nil, false, err
		}

		return nil, true, nil
	}

	// Stage 3: Prepare a definitive "write plan". This plan is created in
	// memory and contains all the information needed for the final atomic
	// database update.
	//
	// Pre-allocate slices with exact capacity to avoid reallocations.
	// We know the exact number of credits from the total output indices
	// across all owned addresses.
	var totalCredits int
	for _, info := range ownedAddrs {
		totalCredits += len(info.outputIndices)
	}

	creditsToWrite := make([]creditInfo, 0, totalCredits)
	ourAddrs := make([]btcutil.Address, 0, len(ownedAddrs))

	// Iterate directly over owned addresses and their pre-computed output
	// indices. This correctly handles the edge case where a single
	// transaction has multiple outputs paying to the same address.
	for _, info := range ownedAddrs {
		for _, index := range info.outputIndices {
			creditsToWrite = append(creditsToWrite, creditInfo{
				index: index,
				addr:  info.addr,
			})
		}

		ourAddrs = append(ourAddrs, info.addr)
	}

	// Stage 4: Atomically execute the write plan. This is the only stage
	// that takes an exclusive database lock, and it is designed to be as
	// fast as possible, containing no business logic.
	err = w.recordTxAndCredits(ctx, tx, label, creditsToWrite)
	if err != nil {
		return nil, false, err
	}

	return ourAddrs, true, nil
}

// recordTxAndCredits performs a single atomic database transaction to execute a
// pre-computed "write plan" for a transaction.
func (w *Wallet) recordTxAndCredits(ctx context.Context, tx *wire.MsgTx,
	label string, creditsToWrite []creditInfo) error {

	// The Store contract records exactly one credit per output index
	// (CreateTxParams.Credits is keyed by index, so "duplicate credited
	// outputs are impossible by construction"). A bare-multisig output the
	// wallet partly owns can yield more than one owned member address for
	// the same index, so the write plan may carry several creditInfo entries
	// that collapse onto one key. Pick the lexicographically smallest
	// EncodeAddress() as the canonical owner instead of letting whichever
	// entry happens to be visited last win: a map-iteration-order-dependent
	// choice would record a nondeterministic owner across runs. The only
	// effect not captured for the dropped members is marking an imported
	// multisig member's address used, which does not feed gap-limit
	// derivation, so a single canonical owner is sufficient here.
	credits := make(map[uint32]btcutil.Address, len(creditsToWrite))
	for _, credit := range creditsToWrite {
		existing, ok := credits[credit.index]
		if !ok ||
			credit.addr.EncodeAddress() < existing.EncodeAddress() {

			credits[credit.index] = credit.addr
		}
	}

	txHash := tx.TxHash()

	err := w.store.CreateTx(ctx, db.CreateTxParams{
		WalletID: w.id,
		Tx:       tx,
		Received: time.Now(),
		Status:   db.TxStatusPublished,
		Label:    label,
		Credits:  credits,
	})
	if err == nil {
		return nil
	}

	if !errors.Is(err, db.ErrTxAlreadyExists) {
		return err
	}

	// A row already exists for this tx hash; reconcile against its stored
	// status instead of assuming the duplicate is a live, tracked tx.
	return w.handleExistingTx(ctx, txHash, label)
}

// handleExistingTx reconciles a record-before-publish duplicate for txHash
// against the stored row's status. Failed and replaced rows are now RETAINED
// (not deleted) by InvalidateUnminedTx, so a hash collision here no longer
// implies the stored row is still a live, tracked transaction. If a prior
// Broadcast recorded this tx, publishTx failed, and cleanup invalidated the row
// (now TxStatusFailed/TxStatusReplaced, with its wallet-owned spend edges
// already cleared), treating the duplicate as an idempotent success would let
// the caller publish a tx whose only stored row is invalid and untracked,
// leaving the live tx unrebroadcast and its spend edges unclaimed. The
// record-before-publish step is therefore authoritative: only treat the
// duplicate as success when the row is still live for the publish flow.
func (w *Wallet) handleExistingTx(ctx context.Context, txHash chainhash.Hash,
	label string) error {

	existing, err := w.store.GetTx(ctx, db.GetTxQuery{
		WalletID: w.id,
		Txid:     txHash,
	})
	if err != nil {
		return err
	}

	// A retained-invalid row cannot be safely revived through this path: the
	// spend edges InvalidateUnminedTx cleared would need to be re-claimed as a
	// graph-affecting lifecycle change. Return a clear error before publishing
	// against a stale, untracked row.
	if !db.IsUnminedStatus(existing.Status) {
		return fmt.Errorf("%w: tx %v exists with status %v",
			ErrTxRetainedInvalid, txHash, existing.Status)
	}

	// The existing row is still live, so recording is idempotent: its credits
	// and spend edges are already claimed. If another workflow inserted the
	// duplicate as pending, promote it to match the published state this
	// record-before-publish path uses for new rows.
	if len(label) == 0 {
		if existing.Status == db.TxStatusPending {
			state := db.UpdateTxState{Status: db.TxStatusPublished}

			return w.store.UpdateTx(ctx, db.UpdateTxParams{
				WalletID: w.id,
				Txid:     txHash,
				State:    &state,
			})
		}

		return nil
	}

	params := db.UpdateTxParams{
		WalletID: w.id,
		Txid:     txHash,
		Label:    &label,
	}
	if existing.Status == db.TxStatusPending {
		params.State = &db.UpdateTxState{Status: db.TxStatusPublished}
	}

	return w.store.UpdateTx(ctx, params)
}

// extractTxAddrs extracts all potential addresses from a transaction's outputs.
// This is a CPU-intensive function that should be run outside of a database
// transaction.
func (w *Wallet) extractTxAddrs(tx *wire.MsgTx) map[uint32][]btcutil.Address {
	txOutAddrs := make(map[uint32][]btcutil.Address)
	for i, output := range tx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.cfg.ChainParams,
		)
		// Ignore non-standard scripts.
		if err != nil {
			log.Warnf("Cannot extract non-std pkScript=%x",
				output.PkScript)

			continue
		}

		// It's not possible for a transaction to have this many
		// outputs, so we can ignore the gosec error.
		//
		//nolint:gosec
		txOutAddrs[uint32(i)] = addrs
	}

	return txOutAddrs
}

// filterOwnedAddresses takes a map of output indexes to addresses and returns a
// new map containing only the addresses that are owned by the wallet. This
// function is a key part of the wallet's performance strategy. It efficiently
// filters a potentially large set of addresses down to the small subset that
// the wallet needs to act on.
//
// The function is optimized to handle transactions with multiple outputs paying
// to the same address. It internally de-duplicates the addresses to ensure that
// the expensive database lookup is performed only once for each unique address.
func (w *Wallet) filterOwnedAddresses(ctx context.Context,
	txOutAddrs map[uint32][]btcutil.Address) (
	map[string]ownedAddrInfo, error) {

	ownedAddrs := make(map[string]ownedAddrInfo)

	// Pre-deduplicate addresses outside the Store write path.
	uniqueAddrs := make(map[string]ownedAddrInfo)
	for index, addrs := range txOutAddrs {
		for _, addr := range addrs {
			key := addr.EncodeAddress()
			info := uniqueAddrs[key]

			if info.addr == nil {
				info.addr = addr
			}

			info.outputIndices = append(info.outputIndices, index)
			uniqueAddrs[key] = info
		}
	}

	for key, info := range uniqueAddrs {
		// Look the address up by its own script rather than the whole
		// output script. For a single-address output these are
		// identical, but for a bare-multisig output it correctly
		// resolves the wallet-owned member, which the multisig script
		// itself would never match.
		ownScript, err := txscript.PayToAddrScript(info.addr)
		if err != nil {
			return nil, err
		}

		_, err = w.store.GetAddress(ctx, db.GetAddressQuery{
			WalletID:     w.id,
			ScriptPubKey: ownScript,
		})

		// If the address is not found, it simply means it does not
		// belong to the wallet. This is the expected case for most
		// addresses, so we can safely continue to the next one.
		if errors.Is(err, db.ErrAddressNotFound) {
			continue
		}

		if err != nil {
			return nil, err
		}

		ownedAddrs[key] = info
	}

	return ownedAddrs, nil
}

// spendsWalletOutput reports whether the transaction spends at least one output
// owned by the wallet, so a sweep that pays no wallet-owned outputs is still
// recognized as ours.
//
// Wallet relevance cannot rely on current-UTXO membership alone. GetUtxo only
// sees the current unspent set, so a no-change tx that re-spends a wallet
// output already consumed by another unmined wallet tx (a fee-bump / RBF /
// sweep replacement) would miss on GetUtxo and be wrongly classified as
// wallet-unrelated. Such a tx must still be treated as ours so it is recorded
// and the store-level input-conflict path can arbitrate the double-spend before
// it broadcasts unrecorded. We therefore also consult the parent transaction's
// wallet-owned outputs, which persist in the store even after the output is
// spent, instead of treating an absent current UTXO as proof of
// non-ownership.
func (w *Wallet) spendsWalletOutput(ctx context.Context,
	tx *wire.MsgTx) (bool, error) {

	// Cache parent-tx ownership lookups so several inputs spending the same
	// parent only cost one GetTxDetail call.
	ownedParents := make(map[chainhash.Hash]map[uint32]struct{})

	for _, txIn := range tx.TxIn {
		outPoint := txIn.PreviousOutPoint

		_, err := w.store.GetUtxo(ctx, db.GetUtxoQuery{
			WalletID: w.id,
			OutPoint: outPoint,
		})
		if err == nil {
			// The output is a current wallet UTXO, so the tx clearly
			// spends our funds.
			return true, nil
		}

		if !errors.Is(err, db.ErrUtxoNotFound) {
			return false, err
		}

		// The output is not a current UTXO. It may still be a wallet
		// output already spent by another unmined wallet tx, which the
		// parent's recorded owned outputs reveal.
		ownedOutputs, err := w.walletOwnedOutputs(
			ctx, outPoint.Hash, ownedParents,
		)
		if err != nil {
			return false, err
		}

		if _, ok := ownedOutputs[outPoint.Index]; ok {
			return true, nil
		}
	}

	return false, nil
}

// walletOwnedOutputs returns the set of output indexes that the wallet owns in
// the transaction identified by txHash, memoizing the per-parent lookup in
// cache. A parent the wallet does not record contributes an empty set, so its
// outputs are treated as not wallet-owned.
func (w *Wallet) walletOwnedOutputs(ctx context.Context,
	txHash chainhash.Hash,
	cache map[chainhash.Hash]map[uint32]struct{}) (
	map[uint32]struct{}, error) {

	if owned, ok := cache[txHash]; ok {
		return owned, nil
	}

	detail, err := w.store.GetTxDetail(ctx, db.GetTxDetailQuery{
		WalletID: w.id,
		Txid:     txHash,
	})

	// A parent the wallet never recorded cannot have contributed a
	// wallet-owned output, so it spends none of our funds. Memoize a
	// non-nil empty set so a later cache hit returns the same value and the
	// caller can index the result without a nil check.
	if errors.Is(err, db.ErrTxNotFound) {
		empty := make(map[uint32]struct{})
		cache[txHash] = empty

		return empty, nil
	}

	if err != nil {
		return nil, err
	}

	owned := make(map[uint32]struct{}, len(detail.OwnedOutputs))
	for _, output := range detail.OwnedOutputs {
		owned[output.Index] = struct{}{}
	}

	cache[txHash] = owned

	return owned, nil
}

// publishTx is a helper function that handles the process of broadcasting a
// transaction to the network. This includes getting a chain client,
// registering for notifications, and sending the raw transaction.
func (w *Wallet) publishTx(tx *wire.MsgTx, ourAddrs []btcutil.Address) error {
	// We'll also ask to be notified of the tx once it confirms on-chain.
	// This is done outside of the database tx to prevent backend
	// interaction within it.
	err := w.cfg.Chain.NotifyReceived(ourAddrs)
	if err != nil {
		return err
	}

	txid := tx.TxHash()

	// allowHighFees is always false such that the max fee rate allowed is
	// capped at 10,000 sat/vb for bitcoind. Note that this flag is only
	// used in bitcoind chain backend. See,
	// - https://github.com/btcsuite/btcd/blob/442ef28bcf03797e845c8e957e5cd6d4bffb5764/rpcclient/rawtransactions.go#L22
	//
	//nolint:lll
	allowHighFees := false

	_, rpcErr := w.cfg.Chain.SendRawTransaction(tx, allowHighFees)
	if rpcErr == nil {
		return nil
	}

	// If the tx was rejected, we need to determine why and act
	// accordingly.
	//
	// NOTE: This check for ErrTxAlreadyInMempool should only be triggered
	// if the wallet is running without mempool acceptance checks (e.g.,
	// with an older version of the chain backend or with Neutrino).
	// Otherwise, this condition should have been caught earlier by the
	// `checkMempool` function.
	if errors.Is(rpcErr, chain.ErrTxAlreadyInMempool) {
		log.Infof("%v: tx already in mempool", txid)
		return nil
	}

	// If the tx was rejected for any other reason, then we'll return the
	// error and let the caller handle the cleanup.
	return rpcErr
}

// invalidateUnminedTx marks a tx as failed in the unconfirmed store.
func (w *Wallet) invalidateUnminedTx(ctx context.Context,
	tx *wire.MsgTx) error {

	txHash := tx.TxHash()

	dbErr := w.store.InvalidateUnminedTx(ctx, db.InvalidateUnminedTxParams{
		WalletID: w.id,
		Txid:     txHash,
	})
	if dbErr != nil {
		log.Warnf("Unable to invalidate invalid tx %v: %v", txHash,
			dbErr)

		return dbErr
	}

	log.Infof("Invalidated invalid tx: %v", txHash)

	// The serialized tx is for logging only, don't fail on the error.
	var txRaw bytes.Buffer

	_ = tx.Serialize(&txRaw)

	// Optionally log the tx in debug when the size is manageable.
	const maxTxSizeForLog = 1_000_000
	if txRaw.Len() < maxTxSizeForLog {
		log.Debugf("Invalidated invalid tx: %v \n hex=%x",
			newLogClosure(func() string {
				return spew.Sdump(tx)
			}), txRaw.Bytes())
	} else {
		log.Debugf("Invalidated invalid tx %v due to its size "+
			"being too large", txHash)
	}

	return nil
}
