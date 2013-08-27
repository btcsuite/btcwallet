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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcwire"
	"net/http"
	"sync"
)

var (
	ConnRefused = errors.New("Connection refused")

	// Channel to close to notify that connection to btcd has been lost.
	btcdDisconnected = make(chan int)

	// Channel to send messages btcwallet does not understand to btcd.
	btcdMsgs = make(chan []byte, 100)

	// Adds a frontend listener channel
	addFrontendListener = make(chan (chan []byte))

	// Removes a frontend listener channel
	deleteFrontendListener = make(chan (chan []byte))

	// Messages sent to this channel are sent to each connected frontend.
	frontendNotificationMaster = make(chan []byte, 100)

	replyHandlers = struct {
		sync.Mutex
		m map[uint64]func(interface{}) bool
	}{
		m: make(map[uint64]func(interface{}) bool),
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
	mtx := new(sync.Mutex)

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

	// Duplicate all messages sent across frontendNotificationMaster to each
	// listening wallet.
	for {
		ntfn := <-frontendNotificationMaster
		mtx.Lock()
		for c, _ := range frontendListeners {
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
		case <-btcdDisconnected:
			var idStr interface{} = "btcwallet:btcddisconnected"
			r := btcjson.Reply{
				Id: &idStr,
			}
			m, _ := json.Marshal(r)
			websocket.Message.Send(ws, m)
			return
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
	disconnected := make(chan int)

	defer func() {
		close(disconnected)
		close(btcdDisconnected)
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

	// TODO(jrick): hook this up with addresses in wallet.
	// reqTxsForAddress("addr")

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
	var routeId uint64
	var origId string

	var m map[string]interface{}
	json.Unmarshal(b, &m)
	idStr, ok := m["id"].(string)
	if !ok {
		// btcd should only ever be sending JSON messages with a string in
		// the id field.  Log the error and drop the message.
		log.Error("Unable to process btcd notification or reply.")
		return
	}

	n, _ := fmt.Sscanf(idStr, "btcwallet(%d)-%s", &routeId, &origId)
	if n == 1 {
		// Request originated from btcwallet. Run and remove correct
		// handler.
		replyHandlers.Lock()
		f := replyHandlers.m[routeId]
		replyHandlers.Unlock()
		if f != nil {
			go func() {
				if f(m["result"]) {
					replyHandlers.Lock()
					delete(replyHandlers.m, routeId)
					replyHandlers.Unlock()
				}
			}()
		}
	} else if n == 2 {
		// Attempt to route btcd reply to correct frontend.
		replyRouter.Lock()
		c := replyRouter.m[routeId]
		if c != nil {
			delete(replyRouter.m, routeId)
		} else {
			// Can't route to a frontend, drop reply.
			log.Info("Unable to route btcd reply to frontend. Dropping.")
			return
		}
		replyRouter.Unlock()

		// Convert string back to number if possible.
		var origIdNum float64
		n, _ := fmt.Sscanf(origId, "%f", &origIdNum)
		if n == 1 {
			m["id"] = origIdNum
		} else {
			m["id"] = origId
		}

		b, err := json.Marshal(m)
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
			result := m["result"].(map[string]interface{})
			hashResult := result["hash"].([]interface{})
			hash := new(btcwire.ShaHash)
			for i, _ := range hash[:] {
				hash[i] = byte(hashResult[i].(float64))
			}
			height := int64(result["height"].(float64))

			// TODO(jrick): update TxStore and UtxoStore with new hash
			var id interface{} = "btcwallet:newblockchainheight"
			m := &btcjson.Reply{
				Result: height,
				Id: &id,
			}
			msg, _ := json.Marshal(m)
			frontendNotificationMaster <- msg

		case "btcd:blockdisconnected":
			// TODO(jrick): rollback txs and utxos from removed block.

		default:
			frontendNotificationMaster <- b
		}
	}
}

// ListenAndServe connects to a running btcd instance over a websocket
// for sending and receiving chain-related messages, failing if the
// connection can not be established.  An additional HTTP server is then
// started to provide websocket connections for any number of btcwallet
// frontends.
func ListenAndServe() error {
	// Attempt to connect to running btcd instance. Bail if it fails.
	btcdws, err := websocket.Dial(
		fmt.Sprintf("ws://localhost:%d/wallet", cfg.BtcdPort),
		"",
		"http://localhost/")
	if err != nil {
		return ConnRefused
	}
	go BtcdHandler(btcdws)

	log.Info("Established connection to btcd.")

	// We'll need to duplicate replies to frontends to each frontend.
	// Replies are sent to frontendReplyMaster, and duplicated to each valid
	// channel in frontendReplySet.  This runs a goroutine to duplicate
	// requests for each channel in the set.
	go frontendListenerDuplicator()

	// XXX(jrick): We need some sort of authentication before websocket
	// connections are allowed, and perhaps TLS on the server as well.
	http.Handle("/frontend", websocket.Handler(frontendReqsNotifications))
	if err := http.ListenAndServe(fmt.Sprintf(":%d", cfg.SvrPort), nil); err != nil {
		return err
	}

	return nil
}

func reqTxsForAddress(addr string) {
	for i := 0; i < 10; i++ {
		seq.Lock()
		n := seq.n
		seq.n++
		seq.Unlock()

		id := fmt.Sprintf("btcwallet(%v)", n)
		msg, err := btcjson.CreateMessageWithId("getblockhash", id, i)
		if err != nil {
			fmt.Println(msg)
			panic(err)
		}

		replyHandlers.Lock()
		replyHandlers.m[n] = func(result interface{}) bool {
			fmt.Println(result)
			return true
		}
		replyHandlers.Unlock()

		btcdMsgs <- msg
	}

	seq.Lock()
	n := seq.n
	seq.n++
	seq.Unlock()

	m := &btcjson.Message{
		Jsonrpc: "",
		Id:      fmt.Sprintf("btcwallet(%v)", n),
		Method:  "rescanforutxo",
		Params: []interface{}{
			"17XhEvq9Nahdj7Xe1nv6oRe1tEmaHUuynH",
		},
	}
	msg, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}

	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}) bool {
		fmt.Println("result:", result)
		return result == nil
	}
	replyHandlers.Unlock()

	btcdMsgs <- msg
}
