// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// notifyUnminedTransactionFromStore publishes a committed unmined transaction
// and the resulting balances to transaction-notification clients.
func (s *NotificationServer) notifyUnminedTransactionFromStore(
	txHash chainhash.Hash) {

	var notification *TransactionNotifications
	err := s.wallet.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			details, err := tx.Tx().UniqueTxDetails(&txHash, nil)
			if err != nil || details == nil {
				return err
			}

			summaries := []TransactionSummary{
				makeTxSummaryFromStore(tx, s.wallet, details),
			}
			hashes, err := tx.Tx().UnminedTxHashes()
			if err != nil {
				return err
			}

			balances := make(map[uint32]btcutil.Amount)
			relevantAccounts(s.wallet, balances, summaries)
			if err := storeTotalBalances(tx, s.wallet, balances); err != nil {
				return err
			}

			notification = &TransactionNotifications{
				UnminedTransactions:      summaries,
				UnminedTransactionHashes: hashes,
				NewBalances: flattenBalanceMap(
					balances,
				),
			}

			return nil
		}, func() {
			notification = nil
		},
	)
	if err != nil {
		log.Errorf("Cannot create unmined transaction notification: %v", err)
		return
	}
	if notification == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.transactions) == 0 {
		return
	}
	if s.currentTxNtfn != nil {
		log.Errorf("Notifying unmined transaction %s while creating block "+
			"notifications", txHash)
	}

	for _, client := range s.transactions {
		client <- notification
	}
}

// notifyMinedTransactionFromStore adds a committed mined transaction to the
// block notification currently being coalesced.
func (s *NotificationServer) notifyMinedTransactionFromStore(
	txHash chainhash.Hash, block *wtxmgr.BlockMeta) {

	var summary *TransactionSummary
	err := s.wallet.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			details, err := tx.Tx().UniqueTxDetails(
				&txHash, &block.Block,
			)
			if err != nil || details == nil {
				return err
			}

			result := makeTxSummaryFromStore(tx, s.wallet, details)
			summary = &result

			return nil
		}, func() {
			summary = nil
		},
	)
	if err != nil {
		log.Errorf("Cannot create mined transaction notification: %v", err)
		return
	}
	if summary == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.transactions) == 0 {
		return
	}
	if s.currentTxNtfn == nil {
		s.currentTxNtfn = &TransactionNotifications{}
	}

	count := len(s.currentTxNtfn.AttachedBlocks)
	if count == 0 ||
		*s.currentTxNtfn.AttachedBlocks[count-1].Hash != block.Hash {

		hash := block.Hash
		s.currentTxNtfn.AttachedBlocks = append(
			s.currentTxNtfn.AttachedBlocks, Block{
				Hash:      &hash,
				Height:    block.Height,
				Timestamp: block.Time.Unix(),
			},
		)
		count++
	}

	attached := &s.currentTxNtfn.AttachedBlocks[count-1]
	attached.Transactions = append(
		attached.Transactions, *summary,
	)
}

// notifyAttachedBlockFromStore completes and publishes the committed block
// notification currently being coalesced.
//
//nolint:cyclop // The branches preserve notification coalescing semantics.
func (s *NotificationServer) notifyAttachedBlockFromStore(
	block *wtxmgr.BlockMeta) {

	s.mu.Lock()
	defer s.mu.Unlock()

	clients := s.transactions
	if len(clients) == 0 {
		s.currentTxNtfn = nil
		return
	}
	if s.currentTxNtfn == nil {
		s.currentTxNtfn = &TransactionNotifications{}
	}

	count := len(s.currentTxNtfn.AttachedBlocks)
	if count == 0 ||
		*s.currentTxNtfn.AttachedBlocks[count-1].Hash != block.Hash {

		hash := block.Hash
		s.currentTxNtfn.AttachedBlocks = append(
			s.currentTxNtfn.AttachedBlocks, Block{
				Hash:      &hash,
				Height:    block.Height,
				Timestamp: block.Time.Unix(),
			},
		)
	}

	if s.wallet.ChainSynced() &&
		len(s.currentTxNtfn.DetachedBlocks) >=
			len(s.currentTxNtfn.AttachedBlocks) {

		return
	}

	err := s.wallet.store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			hashes, err := tx.Tx().UnminedTxHashes()
			if err != nil {
				return err
			}
			s.currentTxNtfn.UnminedTransactionHashes = hashes

			balances := make(map[uint32]btcutil.Amount)
			for _, attached := range s.currentTxNtfn.AttachedBlocks {
				relevantAccounts(
					s.wallet, balances, attached.Transactions,
				)
			}
			if err := storeTotalBalances(tx, s.wallet, balances); err != nil {
				return err
			}
			s.currentTxNtfn.NewBalances = flattenBalanceMap(balances)

			return nil
		}, nil,
	)
	if err != nil {
		log.Errorf("Cannot complete attached block notification: %v", err)
		return
	}

	for _, client := range clients {
		client <- s.currentTxNtfn
	}
	s.currentTxNtfn = nil
}
