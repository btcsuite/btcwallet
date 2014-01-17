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

package main

import (
	"code.google.com/p/go.net/websocket"
	"crypto/sha256"
	_ "crypto/sha512" // for cert generation
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcws"
	"github.com/conformal/go-socks"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

var (
	// ErrConnRefused represents an error where a connection to another
	// process cannot be established.
	ErrConnRefused = errors.New("connection refused")

	// ErrConnLost represents an error where a connection to another
	// process cannot be established.
	ErrConnLost = errors.New("connection lost")

	// Adds a frontend listener channel
	addFrontendListener = make(chan (chan []byte))

	// Removes a frontend listener channel
	deleteFrontendListener = make(chan (chan []byte))

	// Messages sent to this channel are sent to each connected frontend.
	frontendNotificationMaster = make(chan []byte, 100)
)

// server holds the items the RPC server may need to access (auth,
// config, shutdown, etc.)
type server struct {
	wg        sync.WaitGroup
	listeners []net.Listener
	authsha   [sha256.Size]byte
}

// parseListeners splits the list of listen addresses passed in addrs into
// IPv4 and IPv6 slices and returns them.  This allows easy creation of the
// listeners on the correct interface "tcp4" and "tcp6".  It also properly
// detects addresses which apply to "all interfaces" and adds the address to
// both slices.
func parseListeners(addrs []string) ([]string, []string, error) {
	ipv4ListenAddrs := make([]string, 0, len(addrs)*2)
	ipv6ListenAddrs := make([]string, 0, len(addrs)*2)
	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// Shouldn't happen due to already being normalized.
			return nil, nil, err
		}

		// Empty host or host of * on plan9 is both IPv4 and IPv6.
		if host == "" || (host == "*" && runtime.GOOS == "plan9") {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
			continue
		}

		// Parse the IP.
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, nil, fmt.Errorf("'%s' is not a valid IP "+
				"address", host)
		}

		// To4 returns nil when the IP is not an IPv4 address, so use
		// this determine the address type.
		if ip.To4() == nil {
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
		} else {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
		}
	}
	return ipv4ListenAddrs, ipv6ListenAddrs, nil
}

// newServer returns a new instance of the server struct.
func newServer(listenAddrs []string) (*server, error) {
	login := cfg.Username + ":" + cfg.Password
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
	s := server{
		authsha: sha256.Sum256([]byte(auth)),
	}

	// Check for existence of cert file and key file
	if !fileExists(cfg.RPCKey) && !fileExists(cfg.RPCCert) {
		// if both files do not exist, we generate them.
		err := genCertPair(cfg.RPCCert, cfg.RPCKey)
		if err != nil {
			return nil, err
		}
	}
	keypair, err := tls.LoadX509KeyPair(cfg.RPCCert, cfg.RPCKey)
	if err != nil {
		return nil, err
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{keypair},
	}

	ipv4ListenAddrs, ipv6ListenAddrs, err := parseListeners(listenAddrs)
	listeners := make([]net.Listener, 0,
		len(ipv6ListenAddrs)+len(ipv4ListenAddrs))
	for _, addr := range ipv4ListenAddrs {
		listener, err := tls.Listen("tcp4", addr, &tlsConfig)
		if err != nil {
			log.Warnf("RPCS: Can't listen on %s: %v", addr,
				err)
			continue
		}
		listeners = append(listeners, listener)
	}

	for _, addr := range ipv6ListenAddrs {
		listener, err := tls.Listen("tcp6", addr, &tlsConfig)
		if err != nil {
			log.Warnf("RPCS: Can't listen on %s: %v", addr,
				err)
			continue
		}
		listeners = append(listeners, listener)
	}
	if len(listeners) == 0 {
		return nil, errors.New("RPCS: No valid listen address")
	}

	s.listeners = listeners

	return &s, nil
}

// genCertPair generates a key/cert pair to the paths provided.
func genCertPair(certFile, keyFile string) error {
	log.Infof("Generating TLS certificates...")

	// Create directories for cert and key files if they do not yet exist.
	certDir, _ := filepath.Split(certFile)
	keyDir, _ := filepath.Split(keyFile)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return err
	}

	// Generate cert pair.
	org := "btcwallet autogenerated cert"
	validUntil := time.Now().Add(10 * 365 * 24 * time.Hour)
	cert, key, err := btcutil.NewTLSCertPair(org, validUntil, nil)
	if err != nil {
		return err
	}

	// Write cert and key files.
	if err = ioutil.WriteFile(certFile, cert, 0666); err != nil {
		return err
	}
	if err = ioutil.WriteFile(keyFile, key, 0600); err != nil {
		os.Remove(certFile)
		return err
	}

	log.Infof("Done generating TLS certificates")
	return nil
}

// handleRPCRequest processes a JSON-RPC request from a frontend.
func (s *server) handleRPCRequest(w http.ResponseWriter, r *http.Request) {
	body, err := btcjson.GetRaw(r.Body)
	if err != nil {
		log.Errorf("RPCS: Error getting JSON message: %v", err)
	}

	response := ProcessFrontendRequest(body, false)
	mresponse, err := json.Marshal(response)
	if err != nil {
		id := response.Id
		response = &btcjson.Reply{
			Id:    id,
			Error: &btcjson.ErrInternal,
		}
		mresponse, _ = json.Marshal(response)
	}

	if _, err := w.Write(mresponse); err != nil {
		log.Warnf("RPCS: could not respond to RPC request: %v", err)
	}
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

				NotifyBtcdConnection(c)
				bs, err := GetCurBlock()
				if err == nil {
					NotifyNewBlockChainHeight(c, bs)
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
		ntfn := <-frontendNotificationMaster

		mtx.Lock()
		for c := range frontendListeners {
			c <- ntfn
		}
		mtx.Unlock()
	}
}

// NotifyBtcdConnection notifies a frontend of the current connection
// status of btcwallet to btcd.
func NotifyBtcdConnection(reply chan []byte) {
	if btcd, ok := CurrentRPCConn().(*BtcdRPCConn); ok {
		ntfn := btcws.NewBtcdConnectedNtfn(btcd.Connected())
		mntfn, _ := ntfn.MarshalJSON()
		reply <- mntfn
	}

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
			go func() {
				reply := ProcessFrontendRequest(m, true)
				mreply, _ := json.Marshal(reply)
				frontendNotification <- mreply
			}()

		case ntfn, _ := <-frontendNotification:
			if err := websocket.Message.Send(ws, ntfn); err != nil {
				// Frontend disconnected.
				return
			}
		}
	}
}

// NotifyNewBlockChainHeight notifies all frontends of a new
// blockchain height.  This sends the same notification as
// btcd, so this can probably be removed.
func NotifyNewBlockChainHeight(reply chan []byte, bs wallet.BlockStamp) {
	ntfn := btcws.NewBlockConnectedNtfn(bs.Hash.String(), bs.Height)
	mntfn, _ := ntfn.MarshalJSON()
	reply <- mntfn
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

	log.Trace("Starting RPC server")

	serveMux := http.NewServeMux()
	httpServer := &http.Server{Handler: serveMux}
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := s.checkAuth(r); err != nil {
			http.Error(w, "401 Unauthorized.", http.StatusUnauthorized)
			return
		}
		s.handleRPCRequest(w, r)
	})
	serveMux.HandleFunc("/frontend", func(w http.ResponseWriter, r *http.Request) {
		if err := s.checkAuth(r); err != nil {
			http.Error(w, "401 Unauthorized.", http.StatusUnauthorized)
			return
		}
		websocket.Handler(frontendSendRecv).ServeHTTP(w, r)
	})
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

// checkAuth checks the HTTP Basic authentication supplied by a frontend
// in the HTTP request r.  If the frontend's supplied authentication does
// not match the username and password expected, a non-nil error is
// returned.
//
// This check is time-constant.
func (s *server) checkAuth(r *http.Request) error {
	authhdr := r.Header["Authorization"]
	if len(authhdr) <= 0 {
		log.Infof("Frontend did not supply authentication.")
		return errors.New("auth failure")
	}

	authsha := sha256.Sum256([]byte(authhdr[0]))
	cmp := subtle.ConstantTimeCompare(authsha[:], s.authsha[:])
	if cmp != 1 {
		log.Infof("Frontend did not supply correct authentication.")
		return errors.New("auth failure")
	}
	return nil
}

// BtcdWS opens a websocket connection to a btcd instance.
func BtcdWS(certificates []byte) (*websocket.Conn, error) {
	url := fmt.Sprintf("wss://%s/wallet", cfg.Connect)
	config, err := websocket.NewConfig(url, "https://localhost/")
	if err != nil {
		return nil, err
	}

	// btcd uses a self-signed TLS certifiate which is used as the CA.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certificates)
	config.TlsConfig = &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}

	// btcd requires basic authorization, so set the Authorization header.
	login := cfg.Username + ":" + cfg.Password
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
	config.Header.Add("Authorization", auth)

	// Dial connection.
	var ws *websocket.Conn
	var cerr error
	if cfg.Proxy != "" {
		proxy := &socks.Proxy{
			Addr:     cfg.Proxy,
			Username: cfg.ProxyUser,
			Password: cfg.ProxyPass,
		}
		conn, err := proxy.Dial("tcp", cfg.Connect)
		if err != nil {
			return nil, err
		}

		tlsConn := tls.Client(conn, config.TlsConfig)
		ws, cerr = websocket.NewClient(config, tlsConn)
	} else {
		ws, cerr = websocket.DialConfig(config)
	}
	if cerr != nil {
		return nil, cerr
	}
	return ws, nil
}

// BtcdConnect connects to a running btcd instance over a websocket
// for sending and receiving chain-related messages, failing if the
// connection cannot be established or is lost.
func BtcdConnect(certificates []byte) (*BtcdRPCConn, error) {
	// Open websocket connection.
	ws, err := BtcdWS(certificates)
	if err != nil {
		log.Errorf("Cannot open websocket connection to btcd: %v", err)
		return nil, err
	}

	// Create and start RPC connection using the btcd websocket.
	rpc := NewBtcdRPCConn(ws)
	rpc.Start()
	return rpc, nil
}

// resendUnminedTxs resends any transactions in the unmined transaction
// pool to btcd using the 'sendrawtransaction' RPC command.
func resendUnminedTxs() {
	for _, createdTx := range UnminedTxs.m {
		hextx := hex.EncodeToString(createdTx.rawTx)
		if txid, err := SendRawTransaction(CurrentRPCConn(), hextx); err != nil {
			// TODO(jrick): Check error for if this tx is a double spend,
			// remove it if so.
		} else {
			log.Debugf("Resent unmined transaction %v", txid)
		}
	}
}

// Handshake first checks that the websocket connection between btcwallet and
// btcd is valid, that is, that there are no mismatching settings between
// the two processes (such as running on different Bitcoin networks).  If the
// sanity checks pass, all wallets are set to be tracked against chain
// notifications from this btcd connection.
//
// TODO(jrick): Track and Rescan commands should be replaced with a
// single TrackSince function (or similar) which requests address
// notifications and performs the rescan since some block height.
func Handshake(rpc RPCConn) error {
	net, jsonErr := GetCurrentNet(rpc)
	if jsonErr != nil {
		return jsonErr
	}
	if net != cfg.Net() {
		return errors.New("btcd and btcwallet running on different Bitcoin networks")
	}

	// Request notifications for connected and disconnected blocks.
	NotifyBlocks(rpc)

	// Get current best block.  If this is before than the oldest
	// saved block hash, assume that this btcd instance is not yet
	// synced up to a previous btcd that was last used with this
	// wallet.
	bs, err := GetCurBlock()
	if err != nil {
		return fmt.Errorf("cannot get best block: %v", err)
	}
	NotifyNewBlockChainHeight(frontendNotificationMaster, bs)
	NotifyBalances(frontendNotificationMaster)

	// Get default account.  Only the default account is used to
	// track recently-seen blocks.
	a, err := accountstore.Account("")
	if err != nil {
		// No account yet is not a handshake error, but means our
		// handshake is done.
		return nil
	}

	// TODO(jrick): if height is less than the earliest-saved block
	// height, should probably wait for btcd to catch up.

	// Check that there was not any reorgs done since last connection.
	// If so, rollback and rescan to catch up.
	it := a.Wallet.NewIterateRecentBlocks()
	for cont := it != nil; cont; cont = it.Prev() {
		bs := it.BlockStamp()
		log.Debugf("Checking for previous saved block with height %v hash %v",
			bs.Height, bs.Hash)

		_, err := GetBlock(rpc, bs.Hash.String())
		if err != nil {
			continue
		}

		log.Debug("Found matching block.")

		// If we had to go back to any previous blocks (it.Next
		// returns true), then rollback the next and all child blocks.
		// This rollback is done here instead of in the blockMissing
		// check above for each removed block because Rollback will
		// try to write new tx and utxo files on each rollback.
		if it.Next() {
			bs := it.BlockStamp()
			accountstore.Rollback(bs.Height, &bs.Hash)
		}

		// Set default account to be marked in sync with the current
		// blockstamp.  This invalidates the iterator.
		a.Wallet.SetSyncedWith(bs)

		// Begin tracking wallets against this btcd instance.
		accountstore.Track()
		accountstore.RescanActiveAddresses()

		// (Re)send any unmined transactions to btcd in case of a btcd restart.
		resendUnminedTxs()

		// Get current blockchain height and best block hash.
		return nil
	}

	log.Warnf("None of the previous saved blocks in btcd chain.  Must perform full rescan.")

	// Iterator was invalid (wallet has never been synced) or there was a
	// huge chain fork + reorg (more than 20 blocks).  Since we don't know
	// what block (if any) this wallet is synced to, roll back everything
	// and start a new rescan since the earliest block wallet must know
	// about.
	a.fullRescan = true
	accountstore.Track()
	accountstore.RescanActiveAddresses()
	resendUnminedTxs()
	return nil
}
