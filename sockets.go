/*
 * Copyright (c) 2013 Conformal Systems LLC <info@conformal.com>
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

package main

import (
	"code.google.com/p/go.net/websocket"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcwire"
	"net"
	"net/http"
	"sync"
)

var (
	// ErrConnRefused represents an error where a connection to another
	// process cannot be established.
	ErrConnRefused = errors.New("connection refused")

	// ErrConnLost represents an error where a connection to another
	// process cannot be established.
	ErrConnLost = errors.New("connection lost")

	// Channel to close to notify that connection to btcd has been lost.
	btcdConnected = struct {
		b bool
		c chan bool
	}{
		c: make(chan bool),
	}

	// Channel to send messages btcwallet does not understand and requests
	// from btcwallet to btcd.
	btcdMsgs = make(chan []byte, 100)

	// Adds a frontend listener channel
	addFrontendListener = make(chan (chan []byte))

	// Removes a frontend listener channel
	deleteFrontendListener = make(chan (chan []byte))

	// Messages sent to this channel are sent to each connected frontend.
	frontendNotificationMaster = make(chan []byte, 100)

	// replyHandlers maps between a unique number (passed as part of
	// the JSON Id field) and a function to handle a reply or notification
	// from btcd.  As requests are received, this map is checked for a
	// handler function to route the reply to.  If the function returns
	// true, the handler is removed from the map.
	replyHandlers = struct {
		sync.Mutex
		m map[uint64]func(interface{}, *btcjson.Error) bool
	}{
		m: make(map[uint64]func(interface{}, *btcjson.Error) bool),
	}

	// replyRouter maps unique uint64 ids to reply channels, so btcd
	// replies can be routed to the correct frontend.
	replyRouter = struct {
		sync.Mutex
		m map[uint64]chan []byte
	}{
		m: make(map[uint64]chan []byte),
	}
)

// frontendListenerDuplicator listens for new wallet listener channels
// and duplicates messages sent to frontendNotificationMaster to all
// connected listeners.
func frontendListenerDuplicator() {
	// frontendListeners is a map holding each currently connected frontend
	// listener as the key.  The value is ignored, as this is only used as
	// a set.
	frontendListeners := make(map[chan []byte]bool)

	// Don't want to add or delete a wallet listener while iterating
	// through each to propigate to every attached wallet.  Use a mutex to
	// prevent this.
	var mtx sync.Mutex

	// Check for listener channels to add or remove from set.
	go func() {
		for {
			select {
			case c := <-addFrontendListener:
				mtx.Lock()
				frontendListeners[c] = true
				mtx.Unlock()

			case c := <-deleteFrontendListener:
				mtx.Lock()
				delete(frontendListeners, c)
				mtx.Unlock()
			}
		}
	}()

	// Duplicate all messages sent across frontendNotificationMaster, as
	// well as internal btcwallet notifications, to each listening wallet.
	for {
		var ntfn []byte

		select {
		case conn := <-btcdConnected.c:
			btcdConnected.b = conn
			var idStr interface{} = "btcwallet:btcdconnected"
			r := btcjson.Reply{
				Result: conn,
				Id:     &idStr,
			}
			ntfn, _ = json.Marshal(r)

		case ntfn = <-frontendNotificationMaster:
		}

		mtx.Lock()
		for c := range frontendListeners {
			c <- ntfn
		}
		mtx.Unlock()
	}
}

// frontendReqsNotifications is the handler function for websocket
// connections from a btcwallet instance.  It reads messages from wallet and
// sends back replies, as well as notififying wallets of chain updates.
// There can possibly be many of these running, one for each currently
// connected frontend.
func frontendReqsNotifications(ws *websocket.Conn) {
	// Add frontend notification channel to set so this handler receives
	// updates.
	frontendNotification := make(chan []byte)
	addFrontendListener <- frontendNotification
	defer func() {
		deleteFrontendListener <- frontendNotification
	}()

	// jsonMsgs receives JSON messages from the currently connected frontend.
	jsonMsgs := make(chan []byte)

	// Receive messages from websocket and send across jsonMsgs until
	// connection is lost
	go func() {
		for {
			var m []byte
			if err := websocket.Message.Receive(ws, &m); err != nil {
				close(jsonMsgs)
				return
			}
			jsonMsgs <- m
		}
	}()

	for {
		select {
		case m, ok := <-jsonMsgs:
			if !ok {
				// frontend disconnected.
				return
			}
			// Handle JSON message here.
			go ProcessFrontendMsg(frontendNotification, m)
		case ntfn, _ := <-frontendNotification:
			if err := websocket.Message.Send(ws, ntfn); err != nil {
				// Frontend disconnected.
				return
			}
		}
	}
}

// BtcdHandler listens for replies and notifications from btcd over a
// websocket and sends messages that btcwallet does not understand to
// btcd.  Unlike FrontendHandler, exactly one BtcdHandler goroutine runs.
func BtcdHandler(ws *websocket.Conn) {
	// Notification channel to return from listener goroutine when
	// btcd disconnects.
	disconnected := make(chan int)
	defer func() {
		close(disconnected)
	}()

	// Listen for replies/notifications from btcd, and decide how to handle them.
	replies := make(chan []byte)
	go func() {
		defer close(replies)
		for {
			select {
			case <-disconnected:
				return
			default:
				var m []byte
				if err := websocket.Message.Receive(ws, &m); err != nil {
					return
				}
				replies <- m
			}
		}
	}()

	for {
		select {
		case rply, ok := <-replies:
			if !ok {
				// btcd disconnected
				return
			}
			// Handle message here.
			go ProcessBtcdNotificationReply(rply)
		case r := <-btcdMsgs:
			if err := websocket.Message.Send(ws, r); err != nil {
				// btcd disconnected.
				log.Errorf("Unable to send message to btcd: %v", err)
				return
			}
		}
	}
}

// ProcessBtcdNotificationReply unmarshalls the JSON notification or
// reply received from btcd and decides how to handle it.  Replies are
// routed back to the frontend who sent the message, and wallet
// notifications are processed by btcwallet, and frontend notifications
// are sent to every connected frontend.
func ProcessBtcdNotificationReply(b []byte) {
	// Check if the json id field was set by btcwallet.
	var routeID uint64
	var origID string

	var r btcjson.Reply
	if err := json.Unmarshal(b, &r); err != nil {
		log.Errorf("Unable to unmarshal btcd message: %v", err)
		return
	}
	idStr, ok := (*r.Id).(string)
	if !ok {
		// btcd should only ever be sending JSON messages with a string in
		// the id field.  Log the error and drop the message.
		log.Error("Unable to process btcd notification or reply.")
		return
	}

	n, _ := fmt.Sscanf(idStr, "btcwallet(%d)-%s", &routeID, &origID)
	if n == 1 {
		// Request originated from btcwallet. Run and remove correct
		// handler.
		replyHandlers.Lock()
		f := replyHandlers.m[routeID]
		replyHandlers.Unlock()
		if f != nil {
			go func() {
				if f(r.Result, r.Error) {
					replyHandlers.Lock()
					delete(replyHandlers.m, routeID)
					replyHandlers.Unlock()
				}
			}()
		}
	} else if n == 2 {
		// Attempt to route btcd reply to correct frontend.
		replyRouter.Lock()
		c := replyRouter.m[routeID]
		if c != nil {
			delete(replyRouter.m, routeID)
		} else {
			// Can't route to a frontend, drop reply.
			log.Info("Unable to route btcd reply to frontend. Dropping.")
			return
		}
		replyRouter.Unlock()

		// Convert string back to number if possible.
		var origIDNum float64
		n, _ := fmt.Sscanf(origID, "%f", &origIDNum)
		var id interface{}
		if n == 1 {
			id = origIDNum
		} else {
			id = origID
		}
		r.Id = &id

		b, err := json.Marshal(r)
		if err != nil {
			log.Error("Error marshalling btcd reply. Dropping.")
			return
		}
		c <- b
	} else {
		// btcd notification must either be handled by btcwallet or sent
		// to all frontends if btcwallet can not handle it.
		switch idStr {
		case "btcd:blockconnected":
			NtfnBlockConnected(r.Result)

		case "btcd:blockdisconnected":
			NtfnBlockDisconnected(r.Result)

		default:
			frontendNotificationMaster <- b
		}
	}
}

// NtfnBlockConnected handles btcd notifications resulting from newly
// connected blocks to the main blockchain.  Currently, this only creates
// a new notification for frontends with the new blockchain height.
func NtfnBlockConnected(r interface{}) {
	result, ok := r.(map[string]interface{})
	if !ok {
		log.Error("blockconnected notification: invalid result")
		return
	}
	hashBE, ok := result["hash"].(string)
	if !ok {
		log.Error("blockconnected notification: invalid hash")
		return
	}
	hash, err := btcwire.NewShaHashFromStr(hashBE)
	if err != nil {
		log.Error("btcd:blockconnected handler: invalid hash string")
		return
	}
	heightf, ok := result["height"].(float64)
	if !ok {
		log.Error("blockconnected notification: invalid height")
		return
	}
	height := int64(heightf)
	var minedTxs []string
	if iminedTxs, ok := result["minedtxs"].([]interface{}); ok {
		minedTxs = make([]string, len(iminedTxs))
		for i, iminedTx := range iminedTxs {
			minedTx, ok := iminedTx.(string)
			if !ok {
				log.Error("blockconnected notification: mined tx is not a string")
				continue
			}
			minedTxs[i] = minedTx
		}
	}

	curHeight.Lock()
	curHeight.h = height
	curHeight.Unlock()

	// TODO(jrick): update TxStore and UtxoStore with new hash
	_ = hash
	var id interface{} = "btcwallet:newblockchainheight"
	msgRaw := &btcjson.Reply{
		Result: height,
		Id:     &id,
	}
	msg, err := json.Marshal(msgRaw)
	if err != nil {
		log.Error("btcd:blockconnected handler: unable to marshal reply")
		return
	}
	frontendNotificationMaster <- msg

	// Remove all mined transactions from pool.
	UnminedTxs.Lock()
	for _, txid := range minedTxs {
		delete(UnminedTxs.m, txid)
	}
	UnminedTxs.Unlock()
}

// ResendUnminedTxs resends any transactions in the unmined
// transaction pool to btcd using the 'sendrawtransaction' RPC
// command.
func resendUnminedTxs() {
	for _, hextx := range UnminedTxs.m {
		n := <-NewJSONID
		var id interface{} = fmt.Sprintf("btcwallet(%v)", n)
		m, err := btcjson.CreateMessageWithId("sendrawtransaction", id, hextx)
		if err != nil {
			log.Errorf("cannot create resend request: %v", err)
			continue
		}
		replyHandlers.Lock()
		replyHandlers.m[n] = func(result interface{}, err *btcjson.Error) bool {
			// Do nothing, just remove the handler.
			return true
		}
		replyHandlers.Unlock()
		btcdMsgs <- m
	}
}

// NtfnBlockDisconnected handles btcd notifications resulting from
// blocks disconnected from the main chain in the event of a chain
// switch and notifies frontends of the new blockchain height.
//
// TODO(jrick): Rollback Utxo and Tx data
func NtfnBlockDisconnected(r interface{}) {
	result, ok := r.(map[string]interface{})
	if !ok {
		log.Error("blockdisconnected notification: invalid result")
		return
	}
	hashBE, ok := result["hash"].(string)
	if !ok {
		log.Error("blockdisconnected notification: invalid hash")
		return
	}
	hash, err := btcwire.NewShaHashFromStr(hashBE)
	if err != nil {
		log.Error("btcd:blockdisconnected handler: invalid hash string")
		return
	}
	heightf, ok := result["height"].(float64)
	if !ok {
		log.Error("blockdisconnected notification: invalid height")
	}
	height := int64(heightf)

	// Rollback Utxo and Tx data stores.
	go func() {
		wallets.Rollback(height, hash)
	}()

	var id interface{} = "btcwallet:newblockchainheight"
	msgRaw := &btcjson.Reply{
		Result: height,
		Id:     &id,
	}
	msg, err := json.Marshal(msgRaw)
	if err != nil {
		log.Error("btcd:blockdisconnected handler: unable to marshal reply")
		return
	}
	frontendNotificationMaster <- msg
}

var duplicateOnce sync.Once

// FrontendListenAndServe starts a HTTP server to provide websocket
// connections for any number of btcwallet frontends.
func FrontendListenAndServe() error {
	// We'll need to duplicate replies to frontends to each frontend.
	// Replies are sent to frontendReplyMaster, and duplicated to each valid
	// channel in frontendReplySet.  This runs a goroutine to duplicate
	// requests for each channel in the set.
	//
	// Use a sync.Once to insure no extra duplicators run.
	go duplicateOnce.Do(frontendListenerDuplicator)

	// TODO(jrick): We need some sort of authentication before websocket
	// connections are allowed, and perhaps TLS on the server as well.
	http.Handle("/frontend", websocket.Handler(frontendReqsNotifications))
	return http.ListenAndServe(net.JoinHostPort("", cfg.SvrPort), nil)
}

// BtcdConnect connects to a running btcd instance over a websocket
// for sending and receiving chain-related messages, failing if the
// connection cannot be established or is lost.
func BtcdConnect(reply chan error) {
	// btcd requires basic authorization, so we use a custom config with
	// the Authorization header set.
	server := fmt.Sprintf("ws://%s/wallet", net.JoinHostPort("localhost", cfg.BtcdPort))
	login := cfg.Username + ":" + cfg.Password
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
	config, err := websocket.NewConfig(server, "http://localhost/")
	if err != nil {
		reply <- ErrConnRefused
		return
	}
	config.Header.Add("Authorization", auth)

	// Attempt to connect to running btcd instance. Bail if it fails.
	btcdws, err := websocket.DialConfig(config)
	if err != nil {
		reply <- ErrConnRefused
		return
	}
	reply <- nil

	// Remove all reply handlers (if any exist from an old connection).
	replyHandlers.Lock()
	for k := range replyHandlers.m {
		delete(replyHandlers.m, k)
	}
	replyHandlers.Unlock()

	handlerClosed := make(chan int)
	go func() {
		BtcdHandler(btcdws)
		close(handlerClosed)
	}()

	BtcdHandshake(btcdws)

	<-handlerClosed
	reply <- ErrConnLost
}

// BtcdHandshake first checks that the websocket connection between
// btcwallet and btcd is valid, that is, that there are no mismatching
// settings between the two processes (such as running on different
// Bitcoin networks).  If the sanity checks pass, all wallets are set to
// be tracked against chain notifications from this btcd connection.
func BtcdHandshake(ws *websocket.Conn) {
	n := <-NewJSONID
	msg := btcjson.Message{
		Method: "getcurrentnet",
		Id:     fmt.Sprintf("btcwallet(%v)", n),
	}
	m, _ := json.Marshal(&msg)

	correctNetwork := make(chan bool)

	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}, err *btcjson.Error) bool {
		fnet, ok := result.(float64)
		if !ok {
			log.Error("btcd handshake: result is not a number")
			ws.Close()
			correctNetwork <- false
			return true
		}

		var walletNetwork btcwire.BitcoinNet
		if cfg.MainNet {
			walletNetwork = btcwire.MainNet
		} else {
			walletNetwork = btcwire.TestNet3
		}

		correctNetwork <- btcwire.BitcoinNet(fnet) == walletNetwork

		// No additional replies expected, remove handler.
		return true
	}
	replyHandlers.Unlock()

	btcdMsgs <- m

	if !<-correctNetwork {
		log.Error("btcd and btcwallet running on different Bitcoin networks")
		ws.Close()
		return
	}

	// Begin tracking wallets against this btcd instance.
	wallets.RLock()
	for _, w := range wallets.m {
		w.Track()
	}
	wallets.RUnlock()

	// (Re)send any unmined transactions to btcd in case of a btcd restart.
	resendUnminedTxs()
}
