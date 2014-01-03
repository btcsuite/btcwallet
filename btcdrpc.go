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

// This file implements the websocket RPC connection to a btcd instance.

package main

import (
	"code.google.com/p/go.net/websocket"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"github.com/conformal/btcws"
	"sync"
	"time"
)

// ErrBtcdDisconnected describes an error where an operation cannot
// successfully complete due to btcwallet not being connected to
// btcd.
var ErrBtcdDisconnected = btcjson.Error{
	Code:    -1,
	Message: "btcd disconnected",
}

// BtcdRPCConn is a type managing a client connection to a btcd RPC server
// over websockets.
type BtcdRPCConn struct {
	ws         *websocket.Conn
	addRequest chan *AddRPCRequest
	closed     chan struct{}
}

// Ensure that BtcdRPCConn can be used as an RPCConn.
var _ RPCConn = &BtcdRPCConn{}

// NewBtcdRPCConn creates a new RPC connection from a btcd websocket
// connection to btcd.
func NewBtcdRPCConn(ws *websocket.Conn) *BtcdRPCConn {
	conn := &BtcdRPCConn{
		ws:         ws,
		addRequest: make(chan *AddRPCRequest),
		closed:     make(chan struct{}),
	}
	return conn
}

// SendRequest sends an RPC request and returns a channel to read the response's
// result and error.  Part of the RPCConn interface.
func (btcd *BtcdRPCConn) SendRequest(request *RPCRequest) chan *RPCResponse {
	select {
	case <-btcd.closed:
		// The connection has closed, so instead of adding and sending
		// a request, return a channel that just replies with the
		// error for a disconnected btcd.
		responseChan := make(chan *RPCResponse)
		go func() {
			response := &RPCResponse{
				Err: &ErrBtcdDisconnected,
			}
			responseChan <- response
		}()
		return responseChan

	default:
		addRequest := &AddRPCRequest{
			Request:      request,
			ResponseChan: make(chan chan *RPCResponse),
		}
		btcd.addRequest <- addRequest
		return <-addRequest.ResponseChan
	}
}

// Connected returns whether the connection remains established to the RPC
// server.
//
// This function probably should be removed, as any checks for confirming
// the connection are no longer valid after the check and may result in
// races.
func (btcd *BtcdRPCConn) Connected() bool {
	select {
	case <-btcd.closed:
		return false

	default:
		return true
	}
}

// AddRPCRequest is used to add an RPCRequest to the pool of requests
// being manaaged by a btcd RPC connection.
type AddRPCRequest struct {
	Request      *RPCRequest
	ResponseChan chan chan *RPCResponse
}

// send performs the actual send of the marshaled request over the btcd
// websocket connection.
func (btcd *BtcdRPCConn) send(rpcrequest *RPCRequest) error {
	// btcjson.Cmds define their own MarshalJSON which returns an error
	// to satisify the json.Marshaler interface, but will never error.
	mrequest, _ := rpcrequest.request.MarshalJSON()
	return websocket.Message.Send(btcd.ws, mrequest)
}

type receivedResponse struct {
	id    uint64
	raw   []byte
	reply *btcjson.Reply
}

// Start starts the goroutines required to send RPC requests and listen for
// replies.
func (btcd *BtcdRPCConn) Start() {
	done := btcd.closed
	responses := make(chan *receivedResponse)

	// Maintain a map of JSON IDs to RPCRequests currently being waited on.
	go func() {
		m := make(map[uint64]*RPCRequest)
		for {
			select {
			case addrequest := <-btcd.addRequest:
				rpcrequest := addrequest.Request
				m[rpcrequest.request.Id().(uint64)] = rpcrequest

				if err := btcd.send(rpcrequest); err != nil {
					// Connection lost.
					btcd.ws.Close()
					close(done)
				}

				addrequest.ResponseChan <- rpcrequest.response

			case recvResponse := <-responses:
				rpcrequest, ok := m[recvResponse.id]
				if !ok {
					log.Warnf("Received unexpected btcd response")
					continue
				}
				delete(m, recvResponse.id)

				// If no result var was set, create and send
				// send the response unmarshaled by the json
				// package.
				if rpcrequest.result == nil {
					response := &RPCResponse{
						Result: recvResponse.reply.Result,
						Err:    recvResponse.reply.Error,
					}
					rpcrequest.response <- response
					continue
				}

				// A return var was set, so unmarshal again
				// into the var before sending the response.
				r := &btcjson.Reply{
					Result: rpcrequest.result,
				}
				json.Unmarshal(recvResponse.raw, &r)
				response := &RPCResponse{
					Result: r.Result,
					Err:    r.Error,
				}
				rpcrequest.response <- response

			case <-done:
				for _, request := range m {
					response := &RPCResponse{
						Err: &ErrBtcdDisconnected,
					}
					request.response <- response
				}
				return
			}
		}
	}()

	// Listen for replies/notifications from btcd, and decide how to handle them.
	go func() {
		// Idea: instead of reading btcd messages from just one websocket
		// connection, maybe use two so the same connection isn't used
		// for both notifications and responses?  Should make handling
		// must faster as unnecessary unmarshal attempts could be avoided.

		for {
			var m []byte
			if err := websocket.Message.Receive(btcd.ws, &m); err != nil {
				log.Debugf("Cannot recevie btcd message: %v", err)
				close(done)
				return
			}

			// Try notifications (requests with nil ids) first.
			n, err := unmarshalNotification(m)
			if err == nil {
				// Make a copy of the marshaled notification.
				mcopy := make([]byte, len(m))
				copy(mcopy, m)

				// Begin processing the notification.
				go processNotification(n, mcopy)
				continue
			}

			// Must be a response.
			r, err := unmarshalResponse(m)
			if err == nil {
				responses <- r
				continue
			}

			// Not sure what was received but it isn't correct.
			log.Warnf("Received invalid message from btcd")
		}
	}()
}

// unmarshalResponse attempts to unmarshal a marshaled JSON-RPC
// response.
func unmarshalResponse(b []byte) (*receivedResponse, error) {
	var r btcjson.Reply
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}

	// Check for a valid ID.
	if r.Id == nil {
		return nil, errors.New("id is nil")
	}
	fid, ok := (*r.Id).(float64)
	if !ok {
		return nil, errors.New("id is not a number")
	}
	response := &receivedResponse{
		id:    uint64(fid),
		raw:   b,
		reply: &r,
	}
	return response, nil
}

// unmarshalNotification attempts to unmarshal a marshaled JSON-RPC
// notification (Request with a nil or no ID).
func unmarshalNotification(b []byte) (btcjson.Cmd, error) {
	req, err := btcjson.ParseMarshaledCmd(b)
	if err != nil {
		return nil, err
	}

	if req.Id() != nil {
		return nil, errors.New("id is non-nil")
	}

	return req, nil
}

// processNotification checks for a handler for a notification, and sends
func processNotification(n btcjson.Cmd, b []byte) {
	// Message is a btcd notification.  Check the method and dispatch
	// correct handler, or if no handler, pass up to each wallet.
	if ntfnHandler, ok := notificationHandlers[n.Method()]; ok {
		log.Debugf("Running notification handler for method %v",
			n.Method())
		ntfnHandler(n, b)
	} else {
		// No handler; send to all wallets.
		log.Debugf("Sending notification with method %v to all wallets",
			n.Method())
		frontendNotificationMaster <- b
	}
}

type notificationHandler func(btcjson.Cmd, []byte)

var notificationHandlers = map[string]notificationHandler{
	btcws.BlockConnectedNtfnMethod:    NtfnBlockConnected,
	btcws.BlockDisconnectedNtfnMethod: NtfnBlockDisconnected,
	btcws.ProcessedTxNtfnMethod:       NtfnProcessedTx,
	btcws.TxMinedNtfnMethod:           NtfnTxMined,
	btcws.TxSpentNtfnMethod:           NtfnTxSpent,
}

// NtfnProcessedTx handles the btcws.ProcessedTxNtfn notification.
func NtfnProcessedTx(n btcjson.Cmd, marshaled []byte) {
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
	a, err := accountstore.Account(aname)
	if err == ErrAcctNotExist {
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
	a.TxStore.Lock()
	a.TxStore.s.InsertRecvTx(t)
	a.TxStore.dirty = true
	a.TxStore.Unlock()

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
		NotifyNewTxDetails(frontendNotificationMaster, a.Name(), t.TxInfo(a.Name(),
			ptn.BlockHeight, a.Wallet.Net()))
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
		a.UtxoStore.Lock()
		a.UtxoStore.s.Insert(u)
		a.UtxoStore.dirty = true
		a.UtxoStore.Unlock()

		// If this notification came from mempool, notify frontends of
		// the new unconfirmed balance immediately.  Otherwise, wait until
		// the blockconnected notifiation is processed.
		if u.Height == -1 {
			bal := a.CalculateBalance(0) - a.CalculateBalance(1)
			NotifyWalletBalanceUnconfirmed(frontendNotificationMaster,
				a.name, bal)
		}
	}

	// Notify frontends of new account balance.
	confirmed := a.CalculateBalance(1)
	unconfirmed := a.CalculateBalance(0) - confirmed
	NotifyWalletBalance(frontendNotificationMaster, a.name, confirmed)
	NotifyWalletBalanceUnconfirmed(frontendNotificationMaster, a.name, unconfirmed)
}

// NtfnBlockConnected handles btcd notifications resulting from newly
// connected blocks to the main blockchain.
//
// TODO(jrick): Send block time with notification.  This will be used
// to mark wallet files with a possibly-better earliest block height,
// and will greatly reduce rescan times for wallets created with an
// out of sync btcd.
func NtfnBlockConnected(n btcjson.Cmd, marshaled []byte) {
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
	accountstore.BlockNotify(bs)

	// Pass notification to frontends too.
	frontendNotificationMaster <- marshaled
}

// NtfnBlockDisconnected handles btcd notifications resulting from
// blocks disconnected from the main chain in the event of a chain
// switch and notifies frontends of the new blockchain height.
func NtfnBlockDisconnected(n btcjson.Cmd, marshaled []byte) {
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
	go func() {
		accountstore.Rollback(bdn.Height, hash)
	}()

	// Pass notification to frontends too.
	frontendNotificationMaster <- marshaled
}

// NtfnTxMined handles btcd notifications resulting from newly
// mined transactions that originated from this wallet.
func NtfnTxMined(n btcjson.Cmd, marshaled []byte) {
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

	err = accountstore.RecordMinedTx(txid, blockhash,
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
func NtfnTxSpent(n btcjson.Cmd, marshaled []byte) {
	// TODO(jrick): This might actually be useless and maybe it shouldn't
	// be implemented.
}
