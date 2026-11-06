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

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
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
	//
	// Not every chain backend keeps a mempool to ask. One that does not,
	// such as a light client, returns chain.ErrUnimplemented instead of a
	// verdict, so a caller that must work against any backend treats that
	// as "unknown" rather than as a rejection.
	CheckMempoolAcceptance(ctx context.Context, tx *wire.MsgTx) error

	// Broadcast broadcasts a transaction to the network.
	//
	// When the backend cannot answer the acceptance check, the transaction
	// is published without one, so a nil return means it was sent, not that
	// the network accepted it.
	Broadcast(ctx context.Context, tx *wire.MsgTx, label string) error
}

// A compile time check to ensure that Wallet implements the interface.
var _ TxPublisher = (*Wallet)(nil)

// checkMempoolAcceptanceReq borrows the transaction until the chain check ends.
type checkMempoolAcceptanceReq struct {
	reqCtx

	tx          *wire.MsgTx
	respErrChan chan error
}

// broadcastReq keeps recording, registration and publication in one admission.
type broadcastReq struct {
	reqCtx

	tx          *wire.MsgTx
	label       string
	respErrChan chan error
}

// CheckMempoolAcceptance checks if a transaction would be accepted by the
// mempool without broadcasting.
//
// A chain backend with no mempool cannot answer the question and returns
// chain.ErrUnimplemented rather than a verdict; a backend too old to serve the
// check returns rpcclient.ErrBackendVersion. Neither means the transaction was
// rejected.
//
// NOTE: This is part of the TxPublisher interface.
func (w *Wallet) CheckMempoolAcceptance(ctx context.Context,
	tx *wire.MsgTx) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	if tx == nil {
		return ErrTxCannotBeNil
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := checkMempoolAcceptanceReq{
		reqCtx: reqCtx{ctx: ctx},
		tx:     tx,

		respErrChan: make(chan error, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	return <-r.respErrChan
}

// handleCheckMempoolAcceptance delivers the result of an accepted component
// request.
func (w *Wallet) handleCheckMempoolAcceptance(r checkMempoolAcceptanceReq) {
	// Reuse acceptance checks also performed inside an admitted broadcast.
	r.respErrChan <- w.checkMempoolAcceptance(r.ctx, r.tx)
}

// checkMempoolAcceptance queries the chain inside its accepted request.
func (w *Wallet) checkMempoolAcceptance(_ context.Context,
	tx *wire.MsgTx) error {

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
//
// A backend that cannot answer the mempool acceptance check does not stop the
// publish: the tx is sent without a verdict, so a nil return reports that it
// was handed to the network, not that the network kept it.
// Neutrino refuses conflicting replacements before sending because it cannot
// provide acceptance evidence to displace the original input claims.
//
// Preflight rejection records nothing new. After recording, publication-policy
// failures and unknown outcomes retain history and input claims; recognized
// malformed/mandatory-script rejections clean up. ErrTxRetained also wraps
// readback failures after recording; later validation or explicit deletion can
// still end active tracking.
// DeleteUnconfirmedTx removes a retained unconfirmed branch. A changed witness
// returns ErrTxWitnessMismatch before sending an unconfirmed retry.
// TxStatusPublished tracks publication/rebroadcast, not successful delivery.
//
// Publications and their recording are serialized per Wallet, preserving
// replacement order when callers broadcast concurrently.
func (w *Wallet) Broadcast(ctx context.Context, tx *wire.MsgTx,
	label string) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	if tx == nil {
		return ErrTxCannotBeNil
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := broadcastReq{
		reqCtx:      reqCtx{ctx: ctx},
		tx:          tx,
		label:       label,
		respErrChan: make(chan error, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	return <-r.respErrChan
}

// handleBroadcast records and publishes within the accepted outer request.
// The admitted caller waits for this result before reusing its inputs.
func (w *Wallet) handleBroadcast(r broadcastReq) {
	// Keep each send and its graph update together so a delayed reply cannot
	// reconcile an older acceptance after a later competing publication.
	w.broadcastMu.Lock()
	defer w.broadcastMu.Unlock()

	// We'll start by checking if the tx is acceptable to the mempool.
	err := w.checkMempool(r.ctx, r.tx)
	if errors.Is(err, errAlreadyBroadcasted) {
		r.respErrChan <- nil

		return
	}

	if err != nil {
		r.respErrChan <- err

		return
	}

	// Record before publication so confirmation tracking and rebroadcast
	// can proceed even when sending fails. recorded gates success
	// notifications for wallet-relevant transactions.
	ourAddrs, recorded, err := w.addTxToWallet(r.ctx, r.tx, r.label, false)
	// Preserve the original graph until the backend accepts a competing send.
	// Failed atomic admission still supplies the addresses needed for watches.
	replacement := errors.Is(err, db.ErrTxInputConflict)
	// Neutrino queues nil-result sends for rebroadcast without proving
	// acceptance, so refuse its competing send before handing it that work.
	if err != nil && (!replacement || w.cfg.Chain.BackEnd() == "neutrino") {
		r.respErrChan <- err

		return
	}

	// Cleanup depends on the refusal reason, not which attempt inserted
	// the row. Publication-policy errors must never abandon a tracked spend.
	err = w.publishTx(r.tx, ourAddrs)
	if err == nil {
		if replacement {
			// Caller cancellation cannot undo the node's acceptance.
			// Bound persistence while Stop still joins this handler.
			ctx, cancel := context.WithTimeout(
				context.WithoutCancel(r.ctx), time.Minute,
			)
			defer cancel()

			_, recorded, err = w.addTxToWallet(
				ctx, r.tx, r.label, true,
			)
			if err != nil {
				r.respErrChan <- fmt.Errorf("record accepted "+
					"replacement: %w", err)

				return
			}
		}

		// Only recorded Wallet transactions have a detail to announce.
		// Best-effort notification cannot undo a successful publication.
		if recorded {
			w.notifyTx(r.ctx, r.tx.TxHash())
		}

		r.respErrChan <- nil

		return
	}

	// Keep cleanup and retained-claim reporting coupled to the send outcome.
	r.respErrChan <- w.handlePublicationFailure(
		r.ctx, r.tx, recorded, err,
	)
}

// handlePublicationFailure removes only branches rejected as invalid. It keeps
// retained claims and both causal errors when cleanup cannot release them.
func (w *Wallet) handlePublicationFailure(ctx context.Context, tx *wire.MsgTx,
	recorded bool, publishErr error) error {

	txid := tx.TxHash()
	if recorded && shouldRemoveTx(publishErr) {
		// A recognized malformed/script rejection keeps the existing
		// cleanup behavior; policy and uncertain outcomes never enter it.
		cleanupErr := w.deleteUnminedTx(ctx, tx)
		// Absence means cleanup is complete; other failures retain the
		// claims signal and remain inspectable beside the send error.
		if errors.Is(cleanupErr, db.ErrTxNotFound) {
			cleanupErr = nil
		}

		recorded = cleanupErr != nil
		publishErr = errors.Join(publishErr, cleanupErr)
	}

	// Expose retained claims without hiding the publication/cleanup causes.
	if recorded {
		publishErr = fmt.Errorf("%w: tx %v remains recorded: %w",
			ErrTxRetained, txid, publishErr)
	}

	log.Warnf("%v: broadcast failed: %v", txid, publishErr)

	return publishErr
}

var (
	// errAlreadyBroadcasted is a sentinel error used to indicate that a tx
	// has already been broadcast.
	errAlreadyBroadcasted = errors.New("tx already broadcasted")

	// ErrTxCannotBeNil is returned when a nil transaction is passed to a
	// function.
	ErrTxCannotBeNil = errors.New("tx cannot be nil")

	// ErrTxRetained wraps failures after recording when active history and
	// input claims remain or a failed readback cannot establish their state.
	// Later validation/conflict/deletion can release claims; leases cannot.
	ErrTxRetained = errors.New("transaction retained after publication failure")

	// ErrTxWitnessMismatch rejects unconfirmed retries with the same txid but
	// different witness bytes. Explicitly remove the branch before recording
	// another witness; stored bytes remain unchanged.
	ErrTxWitnessMismatch = errors.New(
		"transaction exists with a different witness",
	)

	// ErrTxRetainedInvalid is returned when a tx cannot be recorded for
	// publishing because the store already retains a row for the same hash in
	// a terminal invalid state (failed or replaced). The record-before-publish
	// step refuses to report success in that case so the caller does not
	// publish a tx whose only stored row is invalid and untracked.
	ErrTxRetainedInvalid = errors.New("tx exists in a retained invalid state")
)

// checkMempool checks acceptance before recording and reports any active
// unconfirmed spend claims left in place when preflight refuses a retry.
func (w *Wallet) checkMempool(ctx context.Context,
	tx *wire.MsgTx) error {

	// We'll start by checking if the tx is acceptable to the mempool.
	err := w.checkMempoolAcceptance(ctx, tx)

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
		err = fmt.Errorf("tx rejected by mempool: %w", err)

		// Preflight writes nothing, but an earlier attempt may still
		// claim the inputs. Report that fact without hiding a read failure.
		existing, lookupErr := w.store.GetTx(ctx, db.GetTxQuery{
			WalletID: w.id,
			Txid:     tx.TxHash(),
		})
		switch {
		case errors.Is(lookupErr, db.ErrTxNotFound):
		case lookupErr != nil:
			err = errors.Join(err, lookupErr)
		case existing.Block == nil && db.IsUnminedStatus(existing.Status):
			err = fmt.Errorf("%w: %w", ErrTxRetained, err)
		}

		return err

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
	addr address.Address
}

// ownedAddrInfo holds information about a wallet-owned address and the
// transaction output indices that pay to it.
type ownedAddrInfo struct {
	// addr is the wallet-owned address.
	addr address.Address

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
// It returns the wallet-owned output addresses and whether wallet-relevant
// recording succeeded, including duplicate reconciliation. A debit-only
// sweep is recorded despite returning zero owned addresses. accepted selects
// batch recording after a successful send; input conflicts retain watch data.
func (w *Wallet) addTxToWallet(ctx context.Context, tx *wire.MsgTx,
	label string, accepted bool) ([]address.Address, bool, error) {

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
	// giving up so the tx is still tracked (and can later be removed).
	if len(ownedAddrs) == 0 {
		spendsOurs, err := w.spendsWalletOutput(ctx, tx)
		if err != nil {
			return nil, false, err
		}

		// Neither outputs nor inputs are wallet-relevant, so we can
		// safely exit without recording anything. recorded is false so
		// the caller does not remove a tx that was never written.
		if !spendsOurs {
			return nil, false, nil
		}

		// The tx spends a wallet output but credits none, so record it
		// with an empty credit set. It is now tracked, so recorded is
		// true even though no addresses are returned.
		err = w.recordTxAndCredits(ctx, tx, label, nil, accepted)
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
	ourAddrs := make([]address.Address, 0, len(ownedAddrs))

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
	err = w.recordTxAndCredits(
		ctx, tx, label, creditsToWrite, accepted,
	)
	if err != nil {
		// The caller uses this watch plan only when the atomic write
		// reports an input conflict; other errors still stop publication.
		return ourAddrs, false, err
	}

	return ourAddrs, true, nil
}

// recordTxAndCredits performs a single atomic database transaction to execute a
// pre-computed "write plan" for a transaction. accepted selects the observation
// batch only after a competing send succeeds.
func (w *Wallet) recordTxAndCredits(ctx context.Context, tx *wire.MsgTx,
	label string, creditsToWrite []creditInfo, accepted bool) error {

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
	credits := make(map[uint32]address.Address, len(creditsToWrite))
	for _, credit := range creditsToWrite {
		existing, ok := credits[credit.index]
		if !ok ||
			credit.addr.EncodeAddress() < existing.EncodeAddress() {

			credits[credit.index] = credit.addr
		}
	}

	params := db.CreateTxParams{
		WalletID: w.id,
		Tx:       tx,
		Received: time.Now(),
		Status:   db.TxStatusPublished,
		Label:    label,
		Credits:  credits,
	}
	// Only a successful send authorizes an accepted observation. Ordinary
	// pre-send recording must keep the existing branch's input claims.
	var err error
	if accepted {
		err = w.store.ApplyTxBatch(ctx, db.TxBatchParams{
			WalletID:     w.id,
			Transactions: []db.CreateTxParams{params},
		})
	} else {
		err = w.store.CreateTx(ctx, params)
	}

	if err != nil && !errors.Is(err, db.ErrTxAlreadyExists) {
		return err
	}

	// SQL can replay successfully while KVDB reports a duplicate. Inspect
	// the retained bytes in either case before sending a different witness.
	err = w.handleExistingTx(ctx, tx, label)
	if err == nil || errors.Is(err, ErrTxRetainedInvalid) {
		return err
	}

	// Recording has committed or found a row. A reconciliation failure
	// cannot establish that its input claims have been released; only known
	// terminal history above can omit the retained-state signal.
	return fmt.Errorf("%w: %w", ErrTxRetained, err)
}

// handleExistingTx checks live status and stored witness bytes before sending.
func (w *Wallet) handleExistingTx(ctx context.Context, tx *wire.MsgTx,
	label string) error {

	txHash := tx.TxHash()

	existing, err := w.store.GetTx(ctx, db.GetTxQuery{
		WalletID: w.id,
		Txid:     txHash,
	})
	if err != nil {
		return err
	}

	// A retained-invalid row cannot be safely revived through this path: the
	// spend edges its invalidating event cleared would need to be re-claimed
	// as a graph-affecting lifecycle change. Return a clear error before
	// publishing against a stale, untracked row.
	if !db.IsUnminedStatus(existing.Status) {
		return fmt.Errorf("%w: tx %v exists with status %v",
			ErrTxRetainedInvalid, txHash, existing.Status)
	}

	// The immutable stored serialization includes the witness. An equal
	// txid alone cannot make a changed unconfirmed witness an exact retry.
	if existing.Block == nil &&
		chainhash.DoubleHashH(existing.SerializedTx) != tx.WitnessHash() {

		return fmt.Errorf("%w: tx %v", ErrTxWitnessMismatch, txHash)
	}

	// The existing row is still live, so recording is idempotent: its credits
	// and spend edges are already claimed. If another workflow inserted the
	// duplicate as pending, promote it to match the published state this
	// record-before-publish path uses for new rows.
	if len(label) == 0 || label == existing.Label {
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
func (w *Wallet) extractTxAddrs(tx *wire.MsgTx) map[uint32][]address.Address {
	txOutAddrs := make(map[uint32][]address.Address)
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
// to the same address. It internally de-duplicates the addresses and resolves
// wallet ownership for the entire set with a single batched Store lookup,
// rather than one lookup per address.
func (w *Wallet) filterOwnedAddresses(ctx context.Context,
	txOutAddrs map[uint32][]address.Address) (
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

	// Resolve each unique address by its own script rather than the whole
	// output script. For a single-address output these are identical, but
	// for a bare-multisig output it correctly resolves the wallet-owned
	// member, which the multisig script itself would never match.
	//
	// The scripts are gathered up front so the wallet-ownership question is
	// answered with a single batched Store lookup instead of one lookup per
	// address.
	scriptToKey := make(map[string]string, len(uniqueAddrs))
	scripts := make([][]byte, 0, len(uniqueAddrs))

	for key, info := range uniqueAddrs {
		ownScript, err := txscript.PayToAddrScript(info.addr)
		if err != nil {
			return nil, err
		}

		scriptKey := string(ownScript)
		if _, ok := scriptToKey[scriptKey]; ok {
			continue
		}

		scriptToKey[scriptKey] = key

		scripts = append(scripts, ownScript)
	}

	// Ask the Store which of the gathered scripts are wallet-owned in one
	// operation. A script present in the result map is owned; an absent one
	// simply does not belong to the wallet, which is the expected case for
	// most addresses.
	owned, err := w.store.ResolveOwnedAddresses(
		ctx, db.ResolveOwnedAddressesQuery{
			WalletID:      w.id,
			ScriptPubKeys: scripts,
		},
	)
	if err != nil {
		return nil, err
	}

	for scriptKey, info := range owned {
		// Keep ownership lookup intact while admitting only receiving credits.
		if !w.addressReceivesCredits(info) {
			continue
		}

		key := scriptToKey[scriptKey]
		ownedAddrs[key] = uniqueAddrs[key]
	}

	return ownedAddrs, nil
}

// addressReceivesCredits applies receiving policy after ownership lookup.
// SQL uses NoChainSync; native wallets also retain their scope/branch scan set.
// Neither restriction changes access to the owned key for signing.
func (w *Wallet) addressReceivesCredits(info *db.AddressInfo) bool {
	if info.NoChainSync {
		return false
	}

	return w.addrStore == nil || waddrmgr.IsReceivingAddress(
		info.HasDerivationPath, waddrmgr.KeyScope(info.KeyScope), info.Branch,
	)
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
	cache map[chainhash.Hash]map[uint32]struct{}) (map[uint32]struct{},
	error) {

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
func (w *Wallet) publishTx(tx *wire.MsgTx, ourAddrs []address.Address) error {
	// We'll also ask to be notified of the tx once it confirms on-chain.
	// This is done outside of the database tx to prevent backend
	// interaction within it.
	err := w.chainSyncer.notifyReceived(w.lifetimeCtx, w.id, ourAddrs)
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
	// NOTE: These already-broadcast checks should only be triggered if the
	// wallet is running without mempool acceptance checks (e.g., with an
	// older version of the chain backend or with Neutrino). Otherwise, this
	// condition should have been caught earlier by the `checkMempool`
	// function, which treats the same set of errors as already broadcast.
	switch {
	case errors.Is(rpcErr, chain.ErrTxAlreadyInMempool),
		errors.Is(rpcErr, chain.ErrTxAlreadyKnown),
		errors.Is(rpcErr, chain.ErrTxAlreadyConfirmed):

		// The tx is already known, confirmed, or in the mempool, so it
		// was accepted by the network. Treat this as a successful
		// publish so the recorded tx keeps being tracked rather than
		// removed by the caller.
		log.Infof("%v: tx already known/confirmed/in mempool", txid)

		return nil

	// If the tx was rejected for any other reason, then we'll return the
	// error and let the caller handle the cleanup.
	default:
		return rpcErr
	}
}

// deleteUnminedTx removes a tx and its recorded descendants from the
// unconfirmed store. A publication error does not prove the tx can never
// confirm, so cleanup leaves no history the chain would later contradict.
func (w *Wallet) deleteUnminedTx(ctx context.Context,
	tx *wire.MsgTx) error {

	txHash := tx.TxHash()

	dbErr := w.store.DeleteUnminedTx(ctx, db.DeleteUnminedTxParams{
		WalletID: w.id,
		Txid:     txHash,
	})
	if dbErr != nil {
		log.Warnf("Unable to remove invalid tx %v: %v", txHash,
			dbErr)

		return dbErr
	}

	log.Infof("Removed invalid tx: %v", txHash)

	// The serialized tx is for logging only, don't fail on the error.
	var txRaw bytes.Buffer

	_ = tx.Serialize(&txRaw)

	// Optionally log the tx in debug when the size is manageable.
	const maxTxSizeForLog = 1_000_000
	if txRaw.Len() < maxTxSizeForLog {
		log.Debugf("Removed invalid tx: %v \n hex=%x",
			newLogClosure(func() string {
				return spew.Sdump(tx)
			}), txRaw.Bytes())
	} else {
		log.Debugf("Removed invalid tx %v due to its size "+
			"being too large", txHash)
	}

	return nil
}

// shouldRemoveTx reports whether a mapped publication error permits removing
// the recorded branch. Policy and unknown outcomes keep the spend tracked.
func shouldRemoveTx(err error) bool {
	// Match only known malformed/mandatory-script identities. Subscription
	// failures and unrecognized send errors provide no deletion verdict.
	switch {
	case errors.Is(err, chain.ErrEmptyOutput),
		errors.Is(err, chain.ErrEmptyInput),
		errors.Is(err, chain.ErrDuplicateInput),
		errors.Is(err, chain.ErrEmptyPrevOut),
		errors.Is(err, chain.ErrBelowOutValue),
		errors.Is(err, chain.ErrNegativeOutput),
		errors.Is(err, chain.ErrLargeOutput),
		errors.Is(err, chain.ErrLargeTotalOutput),
		errors.Is(err, chain.ErrScriptVerifyFlag),
		errors.Is(err, chain.ErrInvalidOpcode),
		errors.Is(err, chain.ErrOversizeTx):

		return true

	default:
		return false
	}
}
