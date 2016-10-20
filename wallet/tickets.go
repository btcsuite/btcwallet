// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"fmt"

	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/chain"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/walletdb"
	"github.com/decred/dcrwallet/wstakemgr"
)

func sliceContainsHash(s []chainhash.Hash, h chainhash.Hash) bool {
	for _, item := range s {
		if h == item {
			return true
		}
	}
	return false
}

// LiveTicketHashes returns the hashes of live tickets that have been purchased
// by the wallet.
func (w *Wallet) LiveTicketHashes(rpcClient *chain.RPCClient, includeImmature bool) ([]chainhash.Hash, error) {
	// This was mostly copied from an older version of the legacy RPC server
	// implementation, hence the overall weirdness, inefficiencies, and the
	// direct dependency on the consensus server RPC client.

	var blk waddrmgr.BlockStamp
	var ticketHashes []chainhash.Hash
	var stakeMgrTickets []chainhash.Hash
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		blk = w.Manager.SyncedTo()

		// UnspentTickets collects all the tickets that pay out to a
		// public key hash for a public key owned by this wallet.
		var err error
		ticketHashes, err = w.TxStore.UnspentTickets(txmgrNs, blk.Height,
			includeImmature)
		if err != nil {
			return err
		}

		// Access the stake manager and see if there are any extra tickets
		// there. Likely they were either pruned because they failed to get
		// into the blockchain or they are P2SH for some script we own.
		stakeMgrTickets, err = w.StakeMgr.DumpSStxHashes()
		return err
	})
	if err != nil {
		return nil, err
	}

	for _, h := range stakeMgrTickets {
		if sliceContainsHash(ticketHashes, h) {
			continue
		}

		// Get the raw transaction information from daemon and add
		// any relevant tickets. The ticket output is always the
		// zeroeth output.
		spent, err := rpcClient.GetTxOut(&h, 0, true)
		if err != nil {
			continue
		}
		// This returns nil if the output is spent.
		if spent == nil {
			continue
		}

		ticketTx, err := rpcClient.GetRawTransactionVerbose(&h)
		if err != nil {
			continue
		}

		txHeight := ticketTx.BlockHeight
		unconfirmed := (txHeight == 0)
		immature := (blk.Height-int32(txHeight) <
			int32(w.ChainParams().TicketMaturity))
		if includeImmature {
			ticketHashes = append(ticketHashes, h)
		} else {
			if !(unconfirmed || immature) {
				ticketHashes = append(ticketHashes, h)
			}
		}
	}

	return ticketHashes, nil
}

// TicketHashesForVotingAddress returns the hashes of all tickets with voting
// rights delegated to votingAddr.  This function does not return the hashes of
// pruned tickets.
func (w *Wallet) TicketHashesForVotingAddress(votingAddr dcrutil.Address) ([]chainhash.Hash, error) {
	var ticketHashes []chainhash.Hash
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		stakemgrNs := tx.ReadBucket(wstakemgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		var err error
		ticketHashes, err = w.StakeMgr.DumpSStxHashesForAddress(
			stakemgrNs, votingAddr)
		if err != nil {
			return err
		}

		// Exclude the hash if the transaction is not saved too.  No
		// promises of hash order are given (and at time of writing,
		// they are copies of iterators of a Go map in wstakemgr) so
		// when one must be removed, replace it with the last and
		// decrease the len.
		for i := 0; i < len(ticketHashes); {
			if w.TxStore.ExistsTx(txmgrNs, &ticketHashes[i]) {
				i++
				continue
			}

			ticketHashes[i] = ticketHashes[len(ticketHashes)-1]
			ticketHashes = ticketHashes[:len(ticketHashes)-1]
		}

		return nil
	})
	return ticketHashes, err
}

// updateStakePoolInvalidTicket properly updates a previously marked Invalid pool ticket,
// it then creates a new entry in the validly tracked pool ticket db.
func (w *Wallet) updateStakePoolInvalidTicket(stakemgrNs walletdb.ReadWriteBucket, addrmgrNs walletdb.ReadBucket,
	addr dcrutil.Address, ticket *chainhash.Hash, ticketHeight int64) error {
	err := w.StakeMgr.RemoveStakePoolUserInvalTickets(stakemgrNs, addr, ticket)
	if err != nil {
		return err
	}
	poolTicket := &wstakemgr.PoolTicket{
		Ticket:       *ticket,
		HeightTicket: uint32(ticketHeight),
		Status:       wstakemgr.TSImmatureOrLive,
	}

	err = w.StakeMgr.UpdateStakePoolUserTickets(stakemgrNs, addrmgrNs, addr, poolTicket)
	if err != nil {
		return err
	}

	return nil
}

// AddTicket adds a ticket transaction to the wallet.
func (w *Wallet) AddTicket(ticket *dcrutil.Tx) error {
	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		stakemgrNs := tx.ReadWriteBucket(wstakemgrNamespaceKey)

		// Insert the ticket to be tracked and voted.
		err := w.StakeMgr.InsertSStx(stakemgrNs, ticket, w.VoteBits)
		if err != nil {
			return err
		}

		if w.stakePoolEnabled {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			// Pluck the ticketaddress to indentify the stakepool user.
			pkVersion := ticket.MsgTx().TxOut[0].Version
			pkScript := ticket.MsgTx().TxOut[0].PkScript
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkVersion,
				pkScript, w.ChainParams())
			if err != nil {
				return err
			}

			ticketHash := ticket.MsgTx().TxSha()

			chainClient, err := w.requireChainClient()
			if err != nil {
				return err
			}
			rawTx, err := chainClient.GetRawTransactionVerbose(&ticketHash)
			if err != nil {
				return err
			}

			// Update the pool ticket stake. This will include removing it from the
			// invalid slice and adding a ImmatureOrLive ticket to the valid ones.
			err = w.updateStakePoolInvalidTicket(stakemgrNs, addrmgrNs, addrs[0], &ticketHash, rawTx.BlockHeight)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// VoteBitsForTicket returns the per-ticket vote bits, if any are saved, falling
// back to the wallet's default vote bits when missing.
func (w *Wallet) VoteBitsForTicket(ticketHash *chainhash.Hash) (stake.VoteBits, error) {
	var voteBits stake.VoteBits
	var ok bool
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		stakemgrNs := tx.ReadBucket(wstakemgrNamespaceKey)
		var err error
		ok, voteBits, err = w.StakeMgr.SStxVoteBits(stakemgrNs, ticketHash)
		return err
	})
	if !ok {
		voteBits = w.VoteBits
	}
	return voteBits, err
}

// SetVoteBitsForTicket sets the per-ticket vote bits.  These vote bits override
// the wallet's default vote bits.
func (w *Wallet) SetVoteBitsForTicket(ticket *chainhash.Hash,
	voteBits stake.VoteBits) error {
	// Sanity check for the extended voteBits length.
	if len(voteBits.ExtendedBits) > stake.MaxSingleBytePushLength-2 {
		return fmt.Errorf("bad extended votebits length (got %v, max %v)",
			len(voteBits.ExtendedBits), stake.MaxSingleBytePushLength-2)
	}

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		stakemgrNs := tx.ReadWriteBucket(wstakemgrNamespaceKey)
		return w.StakeMgr.UpdateSStxVoteBits(stakemgrNs, ticket,
			voteBits)
	})
}

// SetVoteBitsForTickets sets vote bits for many given tickets.  These vote bits
// override the wallet's default vote bits.
func (w *Wallet) SetVoteBitsForTickets(tickets []chainhash.Hash,
	voteBitsSlice []stake.VoteBits) error {
	if len(tickets) != len(voteBitsSlice) {
		return fmt.Errorf("number of tickets (%v) and number of vote bits "+
			"(%v) not equal", len(tickets), len(voteBitsSlice))
	}

	for i := range voteBitsSlice {
		// Sanity check for the extended voteBits length.
		if len(voteBitsSlice[i].ExtendedBits) >
			stake.MaxSingleBytePushLength-2 {
			return fmt.Errorf("bad extended votebits length (got %v, max %v)",
				len(voteBitsSlice[i].ExtendedBits),
				stake.MaxSingleBytePushLength-2)
		}
	}

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		stakemgrNs := tx.ReadWriteBucket(wstakemgrNamespaceKey)
		var err error
		for i := range tickets {
			err = w.StakeMgr.UpdateSStxVoteBits(stakemgrNs, &tickets[i],
				voteBitsSlice[i])
			if err != nil {
				return err
			}
		}

		return nil
	})
}
