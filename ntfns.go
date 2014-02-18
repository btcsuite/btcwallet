/*
 * Copyright (c) 2013, 2014 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// This file implements the notification handlers for btcd-side notifications.

package main

import (
	"encoding/hex"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"github.com/conformal/btcws"
	"sync"
	"time"
)

type notificationHandler func(btcjson.Cmd)

var notificationHandlers = map[string]notificationHandler{
	btcws.BlockConnectedNtfnMethod:    NtfnBlockConnected,
	btcws.BlockDisconnectedNtfnMethod: NtfnBlockDisconnected,
	btcws.ProcessedTxNtfnMethod:       NtfnProcessedTx,
	btcws.TxMinedNtfnMethod:           NtfnTxMined,
	btcws.TxSpentNtfnMethod:           NtfnTxSpent,
}

// NtfnProcessedTx handles the btcws.ProcessedTxNtfn notification.
func NtfnProcessedTx(n btcjson.Cmd) {
	ptn, ok := n.(*btcws.ProcessedTxNtfn)
	if !ok {
		log.Errorf("%v handler: unexpected type", n.Method())
		return
	}

	// Create useful types from the JSON strings.
	receiver, err := btcutil.DecodeAddr(ptn.Receiver)
	if err != nil {
		log.Errorf("%v handler: error parsing receiver: %v", n.Method(), err)
		return
	}
	txID, err := btcwire.NewShaHashFromStr(ptn.TxID)
	if err != nil {
		log.Errorf("%v handler: error parsing txid: %v", n.Method(), err)
		return
	}
	blockHash, err := btcwire.NewShaHashFromStr(ptn.BlockHash)
	if err != nil {
		log.Errorf("%v handler: error parsing block hash: %v", n.Method(), err)
		return
	}
	pkscript, err := hex.DecodeString(ptn.PkScript)
	if err != nil {
		log.Errorf("%v handler: error parsing pkscript: %v", n.Method(), err)
		return
	}

	// Lookup account for address in result.
	aname, err := LookupAccountByAddress(ptn.Receiver)
	if err == ErrNotFound {
		log.Warnf("Received rescan result for unknown address %v", ptn.Receiver)
		return
	}
	a, err := AcctMgr.Account(aname)
	if err == ErrNotFound {
		log.Errorf("Missing account for rescaned address %v", ptn.Receiver)
	}

	// Create RecvTx to add to tx history.
	t := &tx.RecvTx{
		TxID:         *txID,
		TxOutIdx:     ptn.TxOutIndex,
		TimeReceived: time.Now().Unix(),
		BlockHeight:  ptn.BlockHeight,
		BlockHash:    *blockHash,
		BlockIndex:   int32(ptn.BlockIndex),
		BlockTime:    ptn.BlockTime,
		Amount:       ptn.Amount,
		ReceiverHash: receiver.ScriptAddress(),
	}

	// For transactions originating from this wallet, the sent tx history should
	// be recorded before the received history.  If wallet created this tx, wait
	// for the sent history to finish being recorded before continuing.
	req := SendTxHistSyncRequest{
		txid:     *txID,
		response: make(chan SendTxHistSyncResponse),
	}
	SendTxHistSyncChans.access <- req
	resp := <-req.response
	if resp.ok {
		// Wait until send history has been recorded.
		<-resp.c
		SendTxHistSyncChans.remove <- *txID
	}

	// Record the tx history.
	a.TxStore.InsertRecvTx(t)
	AcctMgr.ds.ScheduleTxStoreWrite(a)
	// Notify frontends of tx.  If the tx is unconfirmed, it is always
	// notified and the outpoint is marked as notified.  If the outpoint
	// has already been notified and is now in a block, a txmined notifiction
	// should be sent once to let frontends that all previous send/recvs
	// for this unconfirmed tx are now confirmed.
	recvTxOP := btcwire.NewOutPoint(txID, ptn.TxOutIndex)
	previouslyNotifiedReq := NotifiedRecvTxRequest{
		op:       *recvTxOP,
		response: make(chan NotifiedRecvTxResponse),
	}
	NotifiedRecvTxChans.access <- previouslyNotifiedReq
	if <-previouslyNotifiedReq.response {
		NotifyMinedTx <- t
		NotifiedRecvTxChans.remove <- *recvTxOP
	} else {
		// Notify frontends of new recv tx and mark as notified.
		NotifiedRecvTxChans.add <- *recvTxOP
		NotifyNewTxDetails(allClients, a.Name(), t.TxInfo(a.Name(),
			ptn.BlockHeight, a.Wallet.Net())[0])
	}

	if !ptn.Spent {
		u := &tx.Utxo{
			Amt:       uint64(ptn.Amount),
			Height:    ptn.BlockHeight,
			Subscript: pkscript,
		}
		copy(u.Out.Hash[:], txID[:])
		u.Out.Index = uint32(ptn.TxOutIndex)
		copy(u.AddrHash[:], receiver.ScriptAddress())
		copy(u.BlockHash[:], blockHash[:])
		a.UtxoStore.Insert(u)
		AcctMgr.ds.ScheduleUtxoStoreWrite(a)

		// If this notification came from mempool, notify frontends of
		// the new unconfirmed balance immediately.  Otherwise, wait until
		// the blockconnected notifiation is processed.
		if u.Height == -1 {
			bal := a.CalculateBalance(0) - a.CalculateBalance(1)
			NotifyWalletBalanceUnconfirmed(allClients, a.name, bal)
		}
	}

	// Notify frontends of new account balance.
	confirmed := a.CalculateBalance(1)
	unconfirmed := a.CalculateBalance(0) - confirmed
	NotifyWalletBalance(allClients, a.name, confirmed)
	NotifyWalletBalanceUnconfirmed(allClients, a.name, unconfirmed)
}

// NtfnBlockConnected handles btcd notifications resulting from newly
// connected blocks to the main blockchain.
//
// TODO(jrick): Send block time with notification.  This will be used
// to mark wallet files with a possibly-better earliest block height,
// and will greatly reduce rescan times for wallets created with an
// out of sync btcd.
func NtfnBlockConnected(n btcjson.Cmd) {
	bcn, ok := n.(*btcws.BlockConnectedNtfn)
	if !ok {
		log.Errorf("%v handler: unexpected type", n.Method())
		return
	}
	hash, err := btcwire.NewShaHashFromStr(bcn.Hash)
	if err != nil {
		log.Errorf("%v handler: invalid hash string", n.Method())
		return
	}

	// Update the blockstamp for the newly-connected block.
	bs := &wallet.BlockStamp{
		Height: bcn.Height,
		Hash:   *hash,
	}
	curBlock.Lock()
	curBlock.BlockStamp = *bs
	curBlock.Unlock()

	// btcd notifies btcwallet about transactions first, and then sends
	// the new block notification.  New balance notifications for txs
	// in blocks are therefore sent here after all tx notifications
	// have arrived and finished being processed by the handlers.
	workers := NotifyBalanceRequest{
		block: *hash,
		wg:    make(chan *sync.WaitGroup),
	}
	NotifyBalanceSyncerChans.access <- workers
	if wg := <-workers.wg; wg != nil {
		wg.Wait()
		NotifyBalanceSyncerChans.remove <- *hash
	}
	AcctMgr.BlockNotify(bs)

	// Pass notification to frontends too.
	marshaled, _ := n.MarshalJSON()
	allClients <- marshaled
}

// NtfnBlockDisconnected handles btcd notifications resulting from
// blocks disconnected from the main chain in the event of a chain
// switch and notifies frontends of the new blockchain height.
func NtfnBlockDisconnected(n btcjson.Cmd) {
	bdn, ok := n.(*btcws.BlockDisconnectedNtfn)
	if !ok {
		log.Errorf("%v handler: unexpected type", n.Method())
		return
	}
	hash, err := btcwire.NewShaHashFromStr(bdn.Hash)
	if err != nil {
		log.Errorf("%v handler: invalid hash string", n.Method())
		return
	}

	// Rollback Utxo and Tx data stores.
	AcctMgr.Rollback(bdn.Height, hash)

	// Pass notification to frontends too.
	marshaled, _ := n.MarshalJSON()
	allClients <- marshaled
}

// NtfnTxMined handles btcd notifications resulting from newly
// mined transactions that originated from this wallet.
func NtfnTxMined(n btcjson.Cmd) {
	tmn, ok := n.(*btcws.TxMinedNtfn)
	if !ok {
		log.Errorf("%v handler: unexpected type", n.Method())
		return
	}

	txid, err := btcwire.NewShaHashFromStr(tmn.TxID)
	if err != nil {
		log.Errorf("%v handler: invalid hash string", n.Method())
		return
	}
	blockhash, err := btcwire.NewShaHashFromStr(tmn.BlockHash)
	if err != nil {
		log.Errorf("%v handler: invalid block hash string", n.Method())
		return
	}

	err = AcctMgr.RecordMinedTx(txid, blockhash,
		tmn.BlockHeight, tmn.Index, tmn.BlockTime)
	if err != nil {
		log.Errorf("%v handler: %v", n.Method(), err)
		return
	}

	// Remove mined transaction from pool.
	UnminedTxs.Lock()
	delete(UnminedTxs.m, TXID(*txid))
	UnminedTxs.Unlock()
}

// NtfnTxSpent handles btcd txspent notifications resulting from a block
// transaction being processed that spents a wallet UTXO.
func NtfnTxSpent(n btcjson.Cmd) {
	// TODO(jrick): This might actually be useless and maybe it shouldn't
	// be implemented.
}
