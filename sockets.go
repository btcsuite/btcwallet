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
	"bytes"
	"code.google.com/p/go.net/websocket"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"github.com/conformal/btcws"
	"github.com/conformal/go-socks"
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

	// Channel for updates and boolean with the most recent update of
	// whether the connection to btcd is active or not.
	btcdConnected = struct {
		b bool
		c chan bool
	}{
		c: make(chan bool),
	}

	// Channel to send messages btcwallet does not understand and requests
	// from btcwallet to btcd.
	btcdMsgs = make(chan []byte)

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

// server holds the items the RPC server may need to access (auth,
// config, shutdown, etc.)
type server struct {
	port      string
	wg        sync.WaitGroup
	listeners []net.Listener
}

// newServer returns a new instance of the server struct.
func newServer() (*server, error) {
	s := server{
		port: cfg.SvrPort,
	}

	// IPv4 listener.
	var listeners []net.Listener
	listenAddr4 := net.JoinHostPort("127.0.0.1", s.port)
	listener4, err := net.Listen("tcp4", listenAddr4)
	if err != nil {
		log.Errorf("RPCS: Couldn't create listener: %v", err)
		return nil, err
	}
	listeners = append(listeners, listener4)

	// IPv6 listener.
	listenAddr6 := net.JoinHostPort("::1", s.port)
	listener6, err := net.Listen("tcp6", listenAddr6)
	if err != nil {
		log.Errorf("RPCS: Couldn't create listener: %v", err)
		return nil, err
	}
	listeners = append(listeners, listener6)

	s.listeners = listeners

	return &s, nil
}

// handleRPCRequest processes a JSON-RPC request from a frontend.
func (s *server) handleRPCRequest(w http.ResponseWriter, r *http.Request) {
	frontend := make(chan []byte)

	body, err := btcjson.GetRaw(r.Body)
	if err != nil {
		log.Errorf("RPCS: Error getting JSON message: %v", err)
	}

	done := make(chan struct{})
	go func() {
		if _, err := w.Write(<-frontend); err != nil {
			log.Warnf("RPCS: could not respond to RPC request: %v",
				err)
		}
		close(done)
	}()

	ProcessRequest(frontend, body, false)
	<-done
}

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

				// TODO(jrick): these notifications belong somewhere better.
				// Probably want to copy AddWalletListener from btcd, and
				// place these notifications in that function.
				NotifyBtcdConnected(frontendNotificationMaster,
					btcdConnected.b)
				if bs, err := GetCurBlock(); err == nil {
					NotifyNewBlockChainHeight(c, bs.Height)
					NotifyBalances(c)
				}

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
			NotifyBtcdConnected(frontendNotificationMaster, conn)
			continue

		case ntfn = <-frontendNotificationMaster:
		}

		mtx.Lock()
		for c := range frontendListeners {
			c <- ntfn
		}
		mtx.Unlock()
	}
}

// NotifyBtcdConnected notifies all frontends of a new btcd connection.
func NotifyBtcdConnected(reply chan []byte, conn bool) {
	btcdConnected.b = conn
	var idStr interface{} = "btcwallet:btcdconnected"
	r := btcjson.Reply{
		Result: conn,
		Id:     &idStr,
	}
	ntfn, _ := json.Marshal(r)
	frontendNotificationMaster <- ntfn
}

// frontendSendRecv is the handler function for websocket connections from
// a btcwallet instance.  It reads requests and sends responses to a
// frontend, as well as notififying wallets of chain updates.  There can
// possibly be many of these running, one for each currently connected
// frontend.
func frontendSendRecv(ws *websocket.Conn) {
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
			// Handle request here.
			go ProcessRequest(frontendNotification, m, true)
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
// BtcdHandler spawns goroutines to perform these tasks, and closes the
// done channel once they are finished.
func BtcdHandler(ws *websocket.Conn, done chan struct{}) {
	// Listen for replies/notifications from btcd, and decide how to handle them.
	replies := make(chan []byte)
	go func() {
		for {
			var m []byte
			if err := websocket.Message.Receive(ws, &m); err != nil {
				log.Debugf("cannot recevie btcd message: %v", err)
				close(replies)
				return
			}
			replies <- m
		}
	}()

	go func() {
		defer close(done)
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
	}()
}

type notificationHandler func(btcws.Notification)

var notificationHandlers = map[string]notificationHandler{
	btcws.BlockConnectedNtfnId:    NtfnBlockConnected,
	btcws.BlockDisconnectedNtfnId: NtfnBlockDisconnected,
	btcws.TxMinedNtfnId:           NtfnTxMined,
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
	if r.Id == nil {
		// btcd should only ever be sending JSON messages with a string in
		// the id field.  Log the error and drop the message.
		log.Error("Unable to process btcd notification or reply.")
		return
	}
	idStr, ok := (*r.Id).(string)
	if !ok {
		// btcd should only ever be sending JSON messages with a string in
		// the id field.  Log the error and drop the message.
		log.Error("Incorrect btcd notification id type.")
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
			replyRouter.Unlock()
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
		// Message is a btcd notification.  Check the id and dispatch
		// correct handler, or if no handler, pass up to each wallet.
		if ntfnHandler, ok := notificationHandlers[idStr]; ok {
			n, err := btcws.ParseMarshaledNtfn(idStr, b)
			if err != nil {
				log.Errorf("Error unmarshaling expected "+
					"notification: %v", err)
				return
			}
			ntfnHandler(n)
			return
		}

		frontendNotificationMaster <- b
	}
}

// NotifyNewBlockChainHeight notifies all frontends of a new
// blockchain height.
func NotifyNewBlockChainHeight(reply chan []byte, height int32) {
	var id interface{} = "btcwallet:newblockchainheight"
	msgRaw := &btcjson.Reply{
		Result: height,
		Id:     &id,
	}
	msg, _ := json.Marshal(msgRaw)
	reply <- msg
}

// NtfnBlockConnected handles btcd notifications resulting from newly
// connected blocks to the main blockchain.
func NtfnBlockConnected(n btcws.Notification) {
	bcn, ok := n.(*btcws.BlockConnectedNtfn)
	if !ok {
		log.Errorf("%v handler: unexpected type", n.Id())
		return
	}
	hash, err := btcwire.NewShaHashFromStr(bcn.Hash)
	if err != nil {
		log.Errorf("%v handler: invalid hash string", n.Id())
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
	// have arrived.
	//
	// TODO(jrick): send frontend tx notifications once that's
	// implemented.
	for _, a := range accounts.m {
		// The UTXO store will be dirty if it was modified
		// from a tx notification.
		if a.UtxoStore.dirty {
			// Notify all frontends of account's new unconfirmed
			// and confirmed balance.
			confirmed := a.CalculateBalance(1)
			unconfirmed := a.CalculateBalance(0) - confirmed
			NotifyWalletBalance(frontendNotificationMaster,
				a.name, confirmed)
			NotifyWalletBalanceUnconfirmed(frontendNotificationMaster,
				a.name, unconfirmed)
		}

		// The account is intentionaly not immediately synced to disk.
		// If btcd is performing an IBD, writing the wallet file for
		// each newly-connected block would result in too many
		// unnecessary disk writes.  The UTXO and transaction stores
		// could be written, but in the case of btcwallet closing
		// before writing the dirty wallet, both would have to be
		// pruned anyways.
		//
		// Instead, the wallet is queued to be written to disk at the
		// next scheduled disk sync.
		a.mtx.Lock()
		a.Wallet.SetSyncedWith(bs)
		a.dirty = true
		a.mtx.Unlock()
		dirtyAccounts.Lock()
		dirtyAccounts.m[a] = true
		dirtyAccounts.Unlock()
	}

	// Notify frontends of new blockchain height.
	NotifyNewBlockChainHeight(frontendNotificationMaster, bcn.Height)
}

// NtfnBlockDisconnected handles btcd notifications resulting from
// blocks disconnected from the main chain in the event of a chain
// switch and notifies frontends of the new blockchain height.
//
// TODO(jrick): Rollback Utxo and Tx data
func NtfnBlockDisconnected(n btcws.Notification) {
	bdn, ok := n.(*btcws.BlockDisconnectedNtfn)
	if !ok {
		log.Errorf("%v handler: unexpected type", n.Id())
		return
	}
	hash, err := btcwire.NewShaHashFromStr(bdn.Hash)
	if err != nil {
		log.Errorf("%v handler: invalid hash string", n.Id())
		return
	}

	// Rollback Utxo and Tx data stores.
	go func() {
		accounts.Rollback(bdn.Height, hash)
	}()

	// Notify frontends of new blockchain height.
	NotifyNewBlockChainHeight(frontendNotificationMaster, bdn.Height)
}

// NtfnTxMined handles btcd notifications resulting from newly
// mined transactions that originated from this wallet.
func NtfnTxMined(n btcws.Notification) {
	tmn, ok := n.(*btcws.TxMinedNtfn)
	if !ok {
		log.Errorf("%v handler: unexpected type", n.Id())
		return
	}

	txid, err := btcwire.NewShaHashFromStr(tmn.TxID)
	if err != nil {
		log.Errorf("%v handler: invalid hash string", n.Id())
		return
	}
	blockhash, err := btcwire.NewShaHashFromStr(tmn.BlockHash)
	if err != nil {
		log.Errorf("%v handler: invalid block hash string", n.Id())
		return
	}

	// Lookup tx in store and add block information.
	accounts.Lock()
out:
	for _, a := range accounts.m {
		a.TxStore.Lock()

		// Search in reverse order, more likely to find it
		// sooner that way.
		for i := len(a.TxStore.s) - 1; i >= 0; i-- {
			sendtx, ok := a.TxStore.s[i].(*tx.SendTx)
			if ok {
				if bytes.Equal(txid.Bytes(), sendtx.TxID[:]) {
					copy(sendtx.BlockHash[:], blockhash.Bytes())
					sendtx.BlockHeight = tmn.BlockHeight
					sendtx.BlockIndex = int32(tmn.Index)
					sendtx.BlockTime = tmn.BlockTime
					a.TxStore.Unlock()
					break out
				}
			}
		}

		a.TxStore.Unlock()
	}
	accounts.Unlock()

	// Remove mined transaction from pool.
	UnminedTxs.Lock()
	delete(UnminedTxs.m, TXID(*txid))
	UnminedTxs.Unlock()
}

var duplicateOnce sync.Once

// Start starts a HTTP server to provide standard RPC and extension
// websocket connections for any number of btcwallet frontends.
func (s *server) Start() {
	// We'll need to duplicate replies to frontends to each frontend.
	// Replies are sent to frontendReplyMaster, and duplicated to each valid
	// channel in frontendReplySet.  This runs a goroutine to duplicate
	// requests for each channel in the set.
	//
	// Use a sync.Once to insure no extra duplicators run.
	go duplicateOnce.Do(frontendListenerDuplicator)

	// TODO(jrick): We need some sort of authentication before websocket
	// connections are allowed, and perhaps TLS on the server as well.
	serveMux := http.NewServeMux()
	httpServer := &http.Server{Handler: serveMux}
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.handleRPCRequest(w, r)
	})
	serveMux.Handle("/frontend", websocket.Handler(frontendSendRecv))
	for _, listener := range s.listeners {
		s.wg.Add(1)
		go func(listener net.Listener) {
			log.Infof("RPCS: RPC server listening on %s", listener.Addr())
			httpServer.Serve(listener)
			log.Tracef("RPCS: RPC listener done for %s", listener.Addr())
			s.wg.Done()
		}(listener)
	}
}

// BtcdConnect connects to a running btcd instance over a websocket
// for sending and receiving chain-related messages, failing if the
// connection cannot be established or is lost.
func BtcdConnect(certificates []byte, reply chan error) {
	url := fmt.Sprintf("wss://%s/wallet", cfg.Connect)
	config, err := websocket.NewConfig(url, "https://localhost/")
	if err != nil {
		reply <- ErrConnRefused
		return
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certificates)
	config.TlsConfig = &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}

	// btcd requires basic authorization, so we use a custom config with
	// the Authorization header set.
	login := cfg.Username + ":" + cfg.Password
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
	config.Header.Add("Authorization", auth)

	// Attempt to connect to running btcd instance. Bail if it fails.
	var btcdws *websocket.Conn
	var cerr error
	if cfg.Proxy != "" {
		proxy := &socks.Proxy{
			Addr:     cfg.Proxy,
			Username: cfg.ProxyUser,
			Password: cfg.ProxyPass,
		}
		conn, err := proxy.Dial("tcp", cfg.Connect)
		if err != nil {
			log.Warnf("Error connecting to proxy: %v", err)
			reply <- ErrConnRefused
			return
		}

		tlsConn := tls.Client(conn, config.TlsConfig)
		btcdws, cerr = websocket.NewClient(config, tlsConn)
	} else {
		btcdws, cerr = websocket.DialConfig(config)
	}
	if cerr != nil {
		log.Errorf("%s", cerr)
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

	done := make(chan struct{})
	BtcdHandler(btcdws, done)

	if err := BtcdHandshake(btcdws); err != nil {
		log.Errorf("%v", err)
		reply <- ErrConnRefused
		return
	}

	// done is closed when BtcdHandler's goroutines are finished.
	<-done
	reply <- ErrConnLost
}

// resendUnminedTxs resends any transactions in the unmined
// transaction pool to btcd using the 'sendrawtransaction' RPC
// command.
func resendUnminedTxs() {
	for _, createdTx := range UnminedTxs.m {
		n := <-NewJSONID
		var id interface{} = fmt.Sprintf("btcwallet(%v)", n)
		m, err := btcjson.CreateMessageWithId("sendrawtransaction", id, string(createdTx.rawTx))
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

// BtcdHandshake first checks that the websocket connection between
// btcwallet and btcd is valid, that is, that there are no mismatching
// settings between the two processes (such as running on different
// Bitcoin networks).  If the sanity checks pass, all wallets are set to
// be tracked against chain notifications from this btcd connection.
func BtcdHandshake(ws *websocket.Conn) error {
	n := <-NewJSONID
	cmd := btcws.NewGetCurrentNetCmd(fmt.Sprintf("btcwallet(%v)", n))
	mcmd, err := cmd.MarshalJSON()
	if err != nil {
		return fmt.Errorf("cannot complete btcd handshake: %v", err)
	}

	correctNetwork := make(chan bool)

	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}, err *btcjson.Error) bool {
		fnet, ok := result.(float64)
		if !ok {
			log.Error("btcd handshake: result is not a number")
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

	btcdMsgs <- mcmd

	if !<-correctNetwork {
		return errors.New("btcd and btcwallet running on different Bitcoin networks")
	}

	// TODO(jrick): Check that there was not any reorgs done
	// since last connection.  If so, rollback and rescan to
	// catch up.

	for _, a := range accounts.m {
		a.RescanActiveAddresses()
	}

	// Begin tracking wallets against this btcd instance.
	for _, a := range accounts.m {
		a.Track()
	}

	// (Re)send any unmined transactions to btcd in case of a btcd restart.
	resendUnminedTxs()

	// Get current blockchain height and best block hash.
	if bs, err := GetCurBlock(); err == nil {
		NotifyNewBlockChainHeight(frontendNotificationMaster, bs.Height)
		NotifyBalances(frontendNotificationMaster)
	}

	return nil
}
