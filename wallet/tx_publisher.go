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
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/davecgh/go-spew/spew"
)

var (
	// errMempoolAccept is a sentinel error used to indicate that the
	// mempool acceptance test returned an unexpected number of results.
	errMempoolAccept = errors.New(
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

	// TODO(yy): thread context through.
	chainClient, err := w.requireChainClient()
	if err != nil {
		return err
	}

	// The TestMempoolAccept rpc expects a slice of transactions.
	txns := []*wire.MsgTx{tx}

	// Use a max feerate of 0 means the default value will be used when
	// testing mempool acceptance. The default max feerate is 0.10 BTC/kvb,
	// or 10,000 sat/vb.
	maxFeeRate := float64(0)

	results, err := chainClient.TestMempoolAccept(txns, maxFeeRate)
	if err != nil {
		return err
	}

	// Sanity check that the expected single result is returned.
	if len(results) != 1 {
		return errMempoolAccept
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

	return chainClient.MapRPCErr(err)
}

// Broadcast broadcasts a tx to the network. It is the main implementation of
// the TxPublisher interface.
func (w *Wallet) Broadcast(ctx context.Context, tx *wire.MsgTx,
	label string) error {

	// We'll start by checking if the tx is acceptable to the mempool.
	err := w.checkMempool(ctx, tx)
	if errors.Is(err, errAlreadyBroadcasted) {
		return nil
	}

	if err != nil {
		return err
	}

	// First, we'll attempt to add the tx to our wallet's DB. This will
	// allow us to track the tx's confirmation status, and also
	// re-broadcast it upon startup. If any of the subsequent steps fail,
	// this tx must be removed.
	ourAddrs, err := w.addTxToWallet(tx, label)
	if err != nil {
		return err
	}

	// Now, we'll attempt to publish the tx.
	err = w.publishTx(tx, ourAddrs)
	if err == nil {
		return nil
	}

	txid := tx.TxHash()
	log.Errorf("%v: broadcast failed: %v", txid, err)

	// If the tx was rejected for any other reason, then we'll remove it
	// from the tx store, as otherwise, we'll attempt to continually
	// re-broadcast it, and the UTXO state of the wallet won't be accurate.
	removeErr := w.removeUnminedTx(tx)
	if removeErr != nil {
		log.Warnf("Unable to remove tx %v after broadcast failed: %v",
			txid, removeErr)

		// Return a wrapped error to give the caller full context.
		return fmt.Errorf("broadcast failed: %w; and failed to "+
			"remove from wallet: %v", err, removeErr)
	}

	return err
}

var (
	// errAlreadyBroadcasted is a sentinel error used to indicate that a tx
	// has already been broadcast.
	errAlreadyBroadcasted = errors.New("tx already broadcasted")
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

		// TODO(yy): Add a new method UpdateTxLabel to allow updating
		// the label of a tx. With this change, the label passed in
		// will be ignored if the tx is already known.
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

	// ma is the managed address of the credit.
	ma waddrmgr.ManagedAddress

	// addr is the address of the credit.
	addr btcutil.Address
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
// 2. Filter: Second, it uses a fast, read-only database transaction to
// filter the large list of potential addresses down to the small set that is
// actually owned by the wallet. This minimizes the time spent in the final,
// more expensive write transaction.
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
func (w *Wallet) addTxToWallet(tx *wire.MsgTx,
	label string) ([]btcutil.Address, error) {

	txRec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	if err != nil {
		return nil, err
	}

	// Stage 1: Extract potential addresses from all transaction outputs.
	// This is a CPU-intensive operation that is performed entirely in
	// memory, without holding any database locks.
	txOutAddrs := w.extractTxAddrs(tx)

	// Stage 2: Filter the extracted addresses to find which ones are owned
	// by the wallet. This is done in a fast, read-only database
	// transaction to minimize contention.
	ownedAddrs, err := w.filterOwnedAddresses(txOutAddrs)
	if err != nil {
		return nil, err
	}

	// If the transaction has no outputs relevant to us, we can exit early.
	if len(ownedAddrs) == 0 {
		return nil, nil
	}

	// Stage 3: Prepare a definitive "write plan". This plan is created in
	// memory and contains all the information needed for the final atomic
	// database update.
	var (
		creditsToWrite []creditInfo
		ourAddrs       []btcutil.Address
	)

	// The nested loop structure here is critical. It iterates through the
	// original transaction outputs and uses the `ownedAddrs` map as a
	// quick lookup table. This correctly handles the edge case where a
	// single transaction has multiple outputs paying to the same address,
	// as it ensures a distinct entry in the `creditsToWrite` slice is
	// created for each individual output. For example, if a transaction
	// has two outputs (index 0 and 1) that both pay to `addr_A`, this
	// loop will create two separate entries in `creditsToWrite`, one for
	// each index, ensuring both UTXOs are correctly credited.
	for index, addrs := range txOutAddrs {
		for _, addr := range addrs {
			ma, ok := ownedAddrs[addr]
			if !ok {
				continue
			}

			creditsToWrite = append(creditsToWrite, creditInfo{
				index: index,
				ma:    ma,
				addr:  addr,
			})
			ourAddrs = append(ourAddrs, addr)
		}
	}

	// Stage 4: Atomically execute the write plan. This is the only stage
	// that takes an exclusive database lock, and it is designed to be as
	// fast as possible, containing no business logic.
	err = w.recordTxAndCredits(txRec, label, creditsToWrite)
	if err != nil {
		return nil, err
	}

	return ourAddrs, nil
}

// recordTxAndCredits performs a single atomic database transaction to execute a
// pre-computed "write plan" for a transaction.
func (w *Wallet) recordTxAndCredits(txRec *wtxmgr.TxRecord, label string,
	creditsToWrite []creditInfo) error {

	return walletdb.Update(w.db, func(dbTx walletdb.ReadWriteTx) error {
		addrmgrNs := dbTx.ReadWriteBucket(waddrmgrNamespaceKey)
		txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)

		// If there is a label we should write, get the namespace key
		// and record it in the tx store.
		if len(label) != 0 {
			txHash := txRec.MsgTx.TxHash()

			err := w.txStore.PutTxLabel(txmgrNs, txHash, label)
			if err != nil {
				return err
			}
		}

		// At the moment all notified txs are assumed to actually be
		// relevant. This assumption will not hold true when SPV
		// support is added, but until then, simply insert the tx
		// because there should either be one or more relevant inputs
		// or outputs.
		exists, err := w.txStore.InsertTxCheckIfExists(
			txmgrNs, txRec, nil,
		)
		if err != nil {
			return err
		}

		// If the tx has already been recorded, we can return early.
		if exists {
			return nil
		}

		// Now, execute the write plan.
		for _, credit := range creditsToWrite {
			err := w.txStore.AddCredit(
				txmgrNs, txRec, nil, credit.index,
				credit.ma.Internal(),
			)
			if err != nil {
				return err
			}

			err = w.addrStore.MarkUsed(addrmgrNs, credit.addr)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

// extractTxAddrs extracts all potential addresses from a transaction's outputs.
// This is a CPU-intensive function that should be run outside of a database
// transaction.
func (w *Wallet) extractTxAddrs(tx *wire.MsgTx) map[uint32][]btcutil.Address {
	txOutAddrs := make(map[uint32][]btcutil.Address)
	for i, output := range tx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams,
		)
		// Ignore non-standard scripts.
		if err != nil {
			log.Warnf("Cannot extract non-std pkScript=%x",
				output.PkScript)

			continue
		}

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
// The function is optimized to handle transactions with multiple outputs
// paying to the same address. It internally de-duplicates the addresses to
// ensure that the expensive database lookup (`w.addrStore.Address`) is
// performed only once for each unique address.
func (w *Wallet) filterOwnedAddresses(
	txOutAddrs map[uint32][]btcutil.Address) (
	map[btcutil.Address]waddrmgr.ManagedAddress, error) {

	ownedAddrs := make(map[btcutil.Address]waddrmgr.ManagedAddress)

	err := walletdb.View(w.db, func(dbTx walletdb.ReadTx) error {
		addrmgrNs := dbTx.ReadBucket(waddrmgrNamespaceKey)

		for _, addrs := range txOutAddrs {
			for _, addr := range addrs {
				// Skip if we've already checked this address.
				if _, ok := ownedAddrs[addr]; ok {
					continue
				}

				ma, err := w.addrStore.Address(addrmgrNs, addr)

				// If the address is not found, it simply means
				// it does not belong to the wallet. This is
				// the expected case for most addresses, so we
				// can safely continue to the next one.
				if waddrmgr.IsError(
					err, waddrmgr.ErrAddressNotFound) {

					continue
				}

				if err != nil {
					return err
				}

				ownedAddrs[addr] = ma
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return ownedAddrs, nil
}

// publishTx is a helper function that handles the process of broadcasting a
// transaction to the network. This includes getting a chain client,
// registering for notifications, and sending the raw transaction.
func (w *Wallet) publishTx(tx *wire.MsgTx, ourAddrs []btcutil.Address) error {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return err
	}

	// We'll also ask to be notified of the tx once it confirms on-chain.
	// This is done outside of the database tx to prevent backend
	// interaction within it.
	err = chainClient.NotifyReceived(ourAddrs)
	if err != nil {
		return err
	}

	txid := tx.TxHash()

	_, rpcErr := chainClient.SendRawTransaction(tx, false)
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

// removeUnminedTx removes a tx from the unconfirmed store.
func (w *Wallet) removeUnminedTx(tx *wire.MsgTx) error {
	txHash := tx.TxHash()

	dbErr := walletdb.Update(w.db, func(dbTx walletdb.ReadWriteTx) error {
		txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)

		txRec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			return err
		}

		return w.txStore.RemoveUnminedTx(txmgrNs, txRec)
	})
	if dbErr != nil {
		log.Warnf("Unable to remove invalid tx %v: %v", txHash, dbErr)
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
