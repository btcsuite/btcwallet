/*
 * Copyright (c) 2013-2015 The btcsuite developers
 * Copyright (c) 2015-2016 The Decred developers
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
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/websocket"

	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrrpcclient"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/chain"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/wallet"
	"github.com/decred/dcrwallet/wstakemgr"
	"github.com/decred/dcrwallet/wtxmgr"
)

// Error types to simplify the reporting of specific categories of
// errors, and their *dcrjson.RPCError creation.
type (
	// DeserializationError describes a failed deserializaion due to bad
	// user input.  It cooresponds to dcrjson.ErrRPCDeserialization.
	DeserializationError struct {
		error
	}

	// InvalidParameterError describes an invalid parameter passed by
	// the user.  It cooresponds to dcrjson.ErrRPCInvalidParameter.
	InvalidParameterError struct {
		error
	}

	// ParseError describes a failed parse due to bad user input.  It
	// cooresponds to dcrjson.ErrRPCParse.
	ParseError struct {
		error
	}
)

// Errors variables that are defined once here to avoid duplication below.
var (
	ErrNeedPositiveAmount = InvalidParameterError{
		errors.New("amount must be positive"),
	}

	ErrNeedPositiveSpendLimit = InvalidParameterError{
		errors.New("spend limit must be positive"),
	}

	ErrNeedPositiveMinconf = InvalidParameterError{
		errors.New("minconf must be positive"),
	}

	ErrAddressNotInWallet = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCWallet,
		Message: "address not found in wallet",
	}

	ErrAccountNameNotFound = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCWalletInvalidAccountName,
		Message: "account name not found",
	}

	ErrUnloadedWallet = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCWallet,
		Message: "Request requires a wallet but wallet has not loaded yet",
	}

	ErrWalletUnlockNeeded = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCWalletUnlockNeeded,
		Message: "Enter the wallet passphrase with walletpassphrase first",
	}

	ErrNotImportedAccount = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCWallet,
		Message: "imported addresses must belong to the imported account",
	}

	ErrNoTransactionInfo = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCNoTxInfo,
		Message: "No information for transaction",
	}

	ErrReservedAccountName = dcrjson.RPCError{
		Code:    dcrjson.ErrRPCInvalidParameter,
		Message: "Account name is reserved by RPC server",
	}
)

// TODO(jrick): There are several error paths which 'replace' various errors
// with a more appropiate error from the dcrjson package.  Create a map of
// these replacements so they can be handled once after an RPC handler has
// returned and before the error is marshaled.

// confirmed checks whether a transaction at height txHeight has met minconf
// confirmations for a blockchain at height curHeight.
func confirmed(minconf, txHeight, curHeight int32) bool {
	return confirms(txHeight, curHeight) >= minconf
}

// confirms returns the number of confirmations for a transaction in a block at
// height txHeight (or -1 for an unconfirmed tx) given the chain height
// curHeight.
func confirms(txHeight, curHeight int32) int32 {
	switch {
	case txHeight == -1, txHeight > curHeight:
		return 0
	default:
		return curHeight - txHeight + 1
	}
}

type websocketClient struct {
	conn          *websocket.Conn
	authenticated bool
	remoteAddr    string
	allRequests   chan []byte
	responses     chan []byte
	quit          chan struct{} // closed on disconnect
	wg            sync.WaitGroup
}

func newWebsocketClient(c *websocket.Conn, authenticated bool,
	remoteAddr string) *websocketClient {
	return &websocketClient{
		conn:          c,
		authenticated: authenticated,
		remoteAddr:    remoteAddr,
		allRequests:   make(chan []byte),
		responses:     make(chan []byte),
		quit:          make(chan struct{}),
	}
}

func (c *websocketClient) send(b []byte) error {
	select {
	case c.responses <- b:
		return nil
	case <-c.quit:
		return errors.New("websocket client disconnected")
	}
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
	org := "dcrwallet autogenerated cert"
	validUntil := time.Now().Add(time.Hour * 24 * 365 * 10)
	cert, key, err := dcrutil.NewTLSCertPair(org, validUntil, nil)
	if err != nil {
		return err
	}

	// Write cert and key files.
	if err = ioutil.WriteFile(certFile, cert, 0666); err != nil {
		return err
	}
	if err = ioutil.WriteFile(keyFile, key, 0600); err != nil {
		if rmErr := os.Remove(certFile); rmErr != nil {
			log.Warnf("Cannot remove written certificates: %v", rmErr)
		}
		return err
	}

	log.Info("Done generating TLS certificates")
	return nil
}

// rpcServer holds the items the RPC server may need to access (auth,
// config, shutdown, etc.)
type rpcServer struct {
	wallet        *wallet.Wallet
	chainSvr      *chain.Client
	createOK      bool
	handlerLookup func(string) (requestHandler, bool)
	handlerMu     sync.Mutex

	listeners []net.Listener
	authsha   [sha256.Size]byte
	upgrader  websocket.Upgrader

	maxPostClients      int64 // Max concurrent HTTP POST clients.
	maxWebsocketClients int64 // Max concurrent websocket clients.

	// Channels to register or unregister a websocket client for
	// websocket notifications.
	registerWSC   chan *websocketClient
	unregisterWSC chan *websocketClient

	// Channels read from other components from which notifications are
	// created.
	connectedBlocks    <-chan wtxmgr.BlockMeta
	disconnectedBlocks <-chan wtxmgr.BlockMeta
	ticketsPurchased   <-chan wstakemgr.StakeNotification
	votesCreated       <-chan wstakemgr.StakeNotification
	revocationsCreated <-chan wstakemgr.StakeNotification
	relevantTxs        <-chan chain.RelevantTx
	managerLocked      <-chan bool
	confirmedBalance   <-chan dcrutil.Amount
	unconfirmedBalance <-chan dcrutil.Amount

	//chainServerConnected  <-chan bool
	registerWalletNtfns chan struct{}

	// enqueueNotification and dequeueNotification handle both sides of an
	// infinitly growing queue for websocket client notifications.
	enqueueNotification chan wsClientNotification
	dequeueNotification chan wsClientNotification

	// notificationHandlerQuit is closed when the notification handler
	// goroutine shuts down.  After this is closed, no more notifications
	// will be sent to any websocket client response channel.
	notificationHandlerQuit chan struct{}

	wg      sync.WaitGroup
	quit    chan struct{}
	quitMtx sync.Mutex
}

// newRPCServer creates a new server for serving RPC client connections, both
// HTTP POST and websocket.
func newRPCServer(listenAddrs []string, maxPost,
	maxWebsockets int64) (*rpcServer, error) {
	login := cfg.Username + ":" + cfg.Password
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
	s := rpcServer{
		handlerLookup:       unloadedWalletHandlerFunc,
		authsha:             sha256.Sum256([]byte(auth)),
		maxPostClients:      maxPost,
		maxWebsocketClients: maxWebsockets,
		upgrader: websocket.Upgrader{
			// Allow all origins.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		registerWSC:             make(chan *websocketClient),
		unregisterWSC:           make(chan *websocketClient),
		registerWalletNtfns:     make(chan struct{}),
		enqueueNotification:     make(chan wsClientNotification),
		dequeueNotification:     make(chan wsClientNotification),
		notificationHandlerQuit: make(chan struct{}),
		quit: make(chan struct{}),
	}

	// Setup TLS if not disabled.
	listenFunc := net.Listen
	if !cfg.DisableServerTLS {
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
			MinVersion:   tls.VersionTLS12,
		}

		// Change the standard net.Listen function to the tls one.
		listenFunc = func(net string, laddr string) (net.Listener, error) {
			return tls.Listen(net, laddr, &tlsConfig)
		}
	} else {
		log.Info("Server TLS is disabled")
	}

	ipv4ListenAddrs, ipv6ListenAddrs, err := parseListeners(listenAddrs)
	if err != nil {
		return nil, err
	}
	listeners := make([]net.Listener, 0,
		len(ipv6ListenAddrs)+len(ipv4ListenAddrs))
	for _, addr := range ipv4ListenAddrs {
		listener, err := listenFunc("tcp4", addr)
		if err != nil {
			log.Warnf("RPCS: Can't listen on %s: %v", addr,
				err)
			continue
		}
		listeners = append(listeners, listener)
	}

	for _, addr := range ipv6ListenAddrs {
		listener, err := listenFunc("tcp6", addr)
		if err != nil {
			log.Warnf("RPCS: Can't listen on %s: %v", addr,
				err)
			continue
		}
		listeners = append(listeners, listener)
	}
	if len(listeners) == 0 {
		return nil, errors.New("no valid listen address")
	}

	s.listeners = listeners

	return &s, nil
}

// jsonAuthFail sends a message back to the client if the http auth is rejected.
func jsonAuthFail(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", `Basic realm="dcrwallet RPC"`)
	http.Error(w, "401 Unauthorized.", http.StatusUnauthorized)
}

// Start starts a HTTP server to provide standard RPC and extension
// websocket connections for any number of dcrwallet clients.
func (s *rpcServer) Start() {
	s.wg.Add(3)
	go s.notificationListener()
	go s.notificationQueue()
	go s.notificationHandler()

	log.Trace("Starting RPC server")

	serveMux := http.NewServeMux()
	const rpcAuthTimeoutSeconds = 10

	httpServer := &http.Server{
		Handler: serveMux,

		// Timeout connections which don't complete the initial
		// handshake within the allowed timeframe.
		ReadTimeout: time.Second * rpcAuthTimeoutSeconds,
	}

	serveMux.Handle("/", throttledFn(s.maxPostClients,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Connection", "close")
			w.Header().Set("Content-Type", "application/json")
			r.Close = true

			if err := s.checkAuthHeader(r); err != nil {
				log.Warnf("Unauthorized client connection attempt")
				jsonAuthFail(w)
				return
			}
			s.wg.Add(1)
			s.PostClientRPC(w, r)
			s.wg.Done()
		}))

	serveMux.Handle("/ws", throttledFn(s.maxWebsocketClients,
		func(w http.ResponseWriter, r *http.Request) {
			authenticated := false
			switch s.checkAuthHeader(r) {
			case nil:
				authenticated = true
			case ErrNoAuth:
				// nothing
			default:
				// If auth was supplied but incorrect, rather than simply
				// being missing, immediately terminate the connection.
				log.Warnf("Disconnecting improperly authorized " +
					"websocket client")
				jsonAuthFail(w)
				return
			}

			conn, err := s.upgrader.Upgrade(w, r, nil)
			if err != nil {
				log.Warnf("Cannot websocket upgrade client %s: %v",
					r.RemoteAddr, err)
				return
			}
			wsc := newWebsocketClient(conn, authenticated, r.RemoteAddr)
			s.WebsocketClientRPC(wsc)
		}))

	for _, listener := range s.listeners {
		s.wg.Add(1)
		go func(listener net.Listener) {
			log.Infof("RPCS: RPC server listening on %s", listener.Addr())
			_ = httpServer.Serve(listener)
			log.Tracef("RPCS: RPC listener done for %s", listener.Addr())
			s.wg.Done()
		}(listener)
	}
}

// Stop gracefully shuts down the rpc server by stopping and disconnecting all
// clients, disconnecting the chain server connection, and closing the wallet's
// account files.
func (s *rpcServer) Stop() {
	s.quitMtx.Lock()
	defer s.quitMtx.Unlock()

	select {
	case <-s.quit:
		return
	default:
	}

	log.Warn("Server shutting down")
	s.wallet.CloseDatabases()

	// Stop the connected wallet and chain server, if any.
	s.handlerMu.Lock()
	if s.wallet != nil {
		s.wallet.Stop()
	}
	if s.chainSvr != nil {
		s.chainSvr.Stop()
	}
	s.handlerMu.Unlock()

	// Stop all the listeners.
	for _, listener := range s.listeners {
		err := listener.Close()
		if err != nil {
			log.Errorf("Cannot close listener %s: %v",
				listener.Addr(), err)
		}
	}

	// Signal the remaining goroutines to stop.
	close(s.quit)
}

func (s *rpcServer) WaitForShutdown() {
	// First wait for the wallet and chain server to stop, if they
	// were ever set.
	s.handlerMu.Lock()
	if s.wallet != nil {
		s.wallet.WaitForShutdown()
	}
	if s.chainSvr != nil {
		s.chainSvr.WaitForShutdown()
	}
	s.handlerMu.Unlock()

	s.wg.Wait()
}

// SetWallet sets the wallet dependency component needed to run a fully
// functional Decred wallet RPC server.  If wallet is nil, this informs the
// server that the createencryptedwallet RPC method is valid and must be called
// by a client before any other wallet methods are allowed.
func (s *rpcServer) SetWallet(wallet *wallet.Wallet) {
	defer s.handlerMu.Unlock()
	s.handlerMu.Lock()

	if wallet == nil {
		s.handlerLookup = missingWalletHandlerFunc
		s.createOK = true
		return
	}

	s.wallet = wallet
	s.registerWalletNtfns <- struct{}{}

	if s.chainSvr != nil {
		// With both the wallet and chain server set, all handlers are
		// ok to run.
		s.handlerLookup = lookupAnyHandler
	}
}

// SetChainServer sets the chain server client component needed to run a fully
// functional decred wallet RPC server.  This should be set even before the
// client is connected, as any request handlers should return the error for
// a never connected client, rather than panicking (or never being looked up)
// if the client was never conneceted and added.
func (s *rpcServer) SetChainServer(chainSvr *chain.Client) {
	defer s.handlerMu.Unlock()
	s.handlerMu.Lock()

	s.chainSvr = chainSvr

	if s.wallet != nil {
		// With both the chain server and wallet set, all handlers are
		// ok to run.
		s.handlerLookup = lookupAnyHandler
	}
}

// HandlerClosure creates a closure function for handling requests of the given
// method.  This may be a request that is handled directly by dcrwallet, or
// a chain server request that is handled by passing the request down to dcrd.
//
// NOTE: These handlers do not handle special cases, such as the authenticate
// method.  Each of these must be checked beforehand (the method is already
// known) and handled accordingly.
func (s *rpcServer) HandlerClosure(method string) requestHandlerClosure {
	defer s.handlerMu.Unlock()
	s.handlerMu.Lock()

	// With the lock held, make copies of these pointers for the closure.
	wallet := s.wallet
	chainSvr := s.chainSvr

	if handler, ok := s.handlerLookup(method); ok {
		return func(req *dcrjson.Request) (interface{}, *dcrjson.RPCError) {
			cmd, err := dcrjson.UnmarshalCmd(req)
			if err != nil {
				return nil, dcrjson.ErrRPCInvalidRequest
			}
			res, err := handler(wallet, chainSvr, cmd)
			if err != nil {
				return nil, jsonError(err)
			}
			return res, nil
		}
	}

	return func(req *dcrjson.Request) (interface{}, *dcrjson.RPCError) {
		if chainSvr == nil {
			return nil, &dcrjson.RPCError{
				Code:    -1,
				Message: "Chain server is disconnected",
			}
		}
		res, err := chainSvr.RawRequest(req.Method, req.Params)
		if err != nil {
			return nil, jsonError(err)
		}
		return &res, nil
	}
}

// ErrNoAuth represents an error where authentication could not succeed
// due to a missing Authorization HTTP header.
var ErrNoAuth = errors.New("no auth")

// checkAuthHeader checks the HTTP Basic authentication supplied by a client
// in the HTTP request r.  It errors with ErrNoAuth if the request does not
// contain the Authorization header, or another non-nil error if the
// authentication was provided but incorrect.
//
// This check is time-constant.
func (s *rpcServer) checkAuthHeader(r *http.Request) error {
	authhdr := r.Header["Authorization"]
	if len(authhdr) == 0 {
		return ErrNoAuth
	}

	authsha := sha256.Sum256([]byte(authhdr[0]))
	cmp := subtle.ConstantTimeCompare(authsha[:], s.authsha[:])
	if cmp != 1 {
		return errors.New("bad auth")
	}
	return nil
}

// throttledFn wraps an http.HandlerFunc with throttling of concurrent active
// clients by responding with an HTTP 429 when the threshold is crossed.
func throttledFn(threshold int64, f http.HandlerFunc) http.Handler {
	return throttled(threshold, f)
}

// throttled wraps an http.Handler with throttling of concurrent active
// clients by responding with an HTTP 429 when the threshold is crossed.
func throttled(threshold int64, h http.Handler) http.Handler {
	var active int64

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt64(&active, 1)
		defer atomic.AddInt64(&active, -1)

		if current-1 >= threshold {
			log.Warnf("Reached threshold of %d concurrent active clients",
				threshold)
			http.Error(w, "429 Too Many Requests", 429)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// sanitizeRequest returns a sanitized string for the request which may be
// safely logged.  It is intended to strip private keys, passphrases, and any
// other secrets from request parameters before they may be saved to a log file.
func sanitizeRequest(r *dcrjson.Request) string {
	// These are considered unsafe to log, so sanitize parameters.
	switch r.Method {
	case "encryptwallet", "importprivkey", "importwallet",
		"signrawtransaction", "walletpassphrase",
		"walletpassphrasechange":

		return fmt.Sprintf(
			`{"id":%v,"method":"%s","params":SANITIZED %d parameters}`,
			r.ID, r.Method, len(r.Params))
	}

	return fmt.Sprintf(`{"id":%v,"method":"%s","params":%v}`, r.ID,
		r.Method, r.Params)
}

// idPointer returns a pointer to the passed ID, or nil if the interface is nil.
// Interface pointers are usually a red flag of doing something incorrectly,
// but this is only implemented here to work around an oddity with dcrjson,
// which uses empty interface pointers for response IDs.
func idPointer(id interface{}) (p *interface{}) {
	if id != nil {
		p = &id
	}
	return
}

// invalidAuth checks whether a websocket request is a valid (parsable)
// authenticate request and checks the supplied username and passphrase
// against the server auth.
func (s *rpcServer) invalidAuth(req *dcrjson.Request) bool {
	cmd, err := dcrjson.UnmarshalCmd(req)
	if err != nil {
		return false
	}
	authCmd, ok := cmd.(*dcrjson.AuthenticateCmd)
	if !ok {
		return false
	}
	// Check credentials.
	login := authCmd.Username + ":" + authCmd.Passphrase
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
	authSha := sha256.Sum256([]byte(auth))
	return subtle.ConstantTimeCompare(authSha[:], s.authsha[:]) != 1
}

func (s *rpcServer) WebsocketClientRead(wsc *websocketClient) {
	for {
		_, request, err := wsc.conn.ReadMessage()
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				log.Warnf("Websocket receive failed from client %s: %v",
					wsc.remoteAddr, err)
			}
			close(wsc.allRequests)
			break
		}
		wsc.allRequests <- request
	}
}

func (s *rpcServer) WebsocketClientRespond(wsc *websocketClient) {
	// A for-select with a read of the quit channel is used instead of a
	// for-range to provide clean shutdown.  This is necessary due to
	// WebsocketClientRead (which sends to the allRequests chan) not closing
	// allRequests during shutdown if the remote websocket client is still
	// connected.
out:
	for {
		select {
		case reqBytes, ok := <-wsc.allRequests:
			if !ok {
				// client disconnected
				break out
			}

			var req dcrjson.Request
			err := json.Unmarshal(reqBytes, &req)
			if err != nil {
				if !wsc.authenticated {
					// Disconnect immediately.
					break out
				}
				resp := makeResponse(req.ID, nil,
					dcrjson.ErrRPCInvalidRequest)
				mresp, err := json.Marshal(resp)
				// We expect the marshal to succeed.  If it
				// doesn't, it indicates some non-marshalable
				// type in the response.
				if err != nil {
					panic(err)
				}
				err = wsc.send(mresp)
				if err != nil {
					break out
				}
				continue
			}

			if req.Method == "authenticate" {
				if wsc.authenticated || s.invalidAuth(&req) {
					// Disconnect immediately.
					break out
				}
				wsc.authenticated = true
				resp := makeResponse(req.ID, nil, nil)
				// Expected to never fail.
				mresp, err := json.Marshal(resp)
				if err != nil {
					panic(err)
				}
				err = wsc.send(mresp)
				if err != nil {
					break out
				}
				continue
			}

			if !wsc.authenticated {
				// Disconnect immediately.
				break out
			}

			switch req.Method {
			case "stop":
				s.Stop()
				resp := makeResponse(req.ID,
					"dcrwallet stopping.", nil)
				mresp, err := json.Marshal(resp)
				// Expected to never fail.
				if err != nil {
					panic(err)
				}
				err = wsc.send(mresp)
				if err != nil {
					break out
				}

			default:
				req := req // Copy for the closure
				f := s.HandlerClosure(req.Method)
				wsc.wg.Add(1)
				go func() {
					resp, jsonErr := f(&req)
					mresp, err := dcrjson.MarshalResponse(req.ID, resp, jsonErr)
					if err != nil {
						log.Errorf("Unable to marshal response: %v", err)
					} else {
						_ = wsc.send(mresp)
					}
					wsc.wg.Done()
				}()
			}

		case <-s.quit:
			break out
		}
	}

	// Remove websocket client from notification group, or if the server is
	// shutting down, wait until the notification handler has finished
	// running.  This is needed to ensure that no more notifications will be
	// sent to the client's responses chan before it's closed below.
	select {
	case s.unregisterWSC <- wsc:
	case <-s.quit:
		<-s.notificationHandlerQuit
	}

	// allow client to disconnect after all handler goroutines are done
	wsc.wg.Wait()
	close(wsc.responses)
	s.wg.Done()
}

func (s *rpcServer) WebsocketClientSend(wsc *websocketClient) {
	const deadline time.Duration = 2 * time.Second
out:
	for {
		select {
		case response, ok := <-wsc.responses:
			if !ok {
				// client disconnected
				break out
			}
			err := wsc.conn.SetWriteDeadline(time.Now().Add(deadline))
			if err != nil {
				log.Warnf("Cannot set write deadline on "+
					"client %s: %v", wsc.remoteAddr, err)
			}
			err = wsc.conn.WriteMessage(websocket.TextMessage,
				response)
			if err != nil {
				log.Warnf("Failed websocket send to client "+
					"%s: %v", wsc.remoteAddr, err)
				break out
			}

		case <-s.quit:
			break out
		}
	}
	close(wsc.quit)
	log.Infof("Disconnected websocket client %s", wsc.remoteAddr)
	s.wg.Done()
}

// WebsocketClientRPC starts the goroutines to serve JSON-RPC requests and
// notifications over a websocket connection for a single client.
func (s *rpcServer) WebsocketClientRPC(wsc *websocketClient) {
	log.Infof("New websocket client %s", wsc.remoteAddr)

	// Clear the read deadline set before the websocket hijacked
	// the connection.
	if err := wsc.conn.SetReadDeadline(time.Time{}); err != nil {
		log.Warnf("Cannot remove read deadline: %v", err)
	}

	// Add client context so notifications duplicated to each
	// client are received by this client.
	select {
	case s.registerWSC <- wsc:
	case <-s.quit:
		return
	}

	// WebsocketClientRead is intentionally not run with the waitgroup
	// so it is ignored during shutdown.  This is to prevent a hang during
	// shutdown where the goroutine is blocked on a read of the
	// websocket connection if the client is still connected.
	go s.WebsocketClientRead(wsc)

	s.wg.Add(2)
	go s.WebsocketClientRespond(wsc)
	go s.WebsocketClientSend(wsc)

	<-wsc.quit
}

// maxRequestSize specifies the maximum number of bytes in the request body
// that may be read from a client.  This is currently limited to 4MB.
const maxRequestSize = 1024 * 1024 * 4

// PostClientRPC processes and replies to a JSON-RPC client request.
func (s *rpcServer) PostClientRPC(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, maxRequestSize)
	rpcRequest, err := ioutil.ReadAll(body)
	if err != nil {
		// TODO: what if the underlying reader errored?
		http.Error(w, "413 Request Too Large.",
			http.StatusRequestEntityTooLarge)
		return
	}

	// First check whether wallet has a handler for this request's method.
	// If unfound, the request is sent to the chain server for further
	// processing.  While checking the methods, disallow authenticate
	// requests, as they are invalid for HTTP POST clients.
	var req dcrjson.Request
	err = json.Unmarshal(rpcRequest, &req)
	if err != nil {
		resp, err := dcrjson.MarshalResponse(req.ID, nil,
			dcrjson.ErrRPCInvalidRequest)
		if err != nil {
			log.Errorf("Unable to marshal response: %v", err)
			http.Error(w, "500 Internal Server Error",
				http.StatusInternalServerError)
			return
		}
		_, err = w.Write(resp)
		if err != nil {
			log.Warnf("Cannot write invalid request request to "+
				"client: %v", err)
		}
		return
	}

	// Create the response and error from the request.  Two special cases
	// are handled for the authenticate and stop request methods.
	var res interface{}
	var jsonErr *dcrjson.RPCError
	switch req.Method {
	case "authenticate":
		// Drop it.
		return
	case "stop":
		s.Stop()
		res = "dcrwallet stopping"
	default:
		res, jsonErr = s.HandlerClosure(req.Method)(&req)
	}

	// Marshal and send.
	mresp, err := dcrjson.MarshalResponse(req.ID, res, jsonErr)
	if err != nil {
		log.Errorf("Unable to marshal response: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	_, err = w.Write(mresp)
	if err != nil {
		log.Warnf("Unable to respond to client: %v", err)
	}
}

// Notification messages for websocket clients.
type (
	wsClientNotification interface {
		// This returns a slice only because some of these types result
		// in multpile client notifications.
		notificationCmds(w *wallet.Wallet) []interface{}
	}

	blockConnected    wtxmgr.BlockMeta
	blockDisconnected wtxmgr.BlockMeta

	// Stake notifications.
	ticketPurchased   wstakemgr.StakeNotification
	voteCreated       wstakemgr.StakeNotification
	revocationCreated wstakemgr.StakeNotification

	relevantTx chain.RelevantTx

	managerLocked bool

	confirmedBalance   dcrutil.Amount
	unconfirmedBalance dcrutil.Amount

	daemonConnected bool
)

func (b ticketPurchased) notificationCmds(w *wallet.Wallet) []interface{} {
	n := dcrjson.NewTicketPurchasedNtfn(b.TxHash.String(), b.Amount)
	return []interface{}{n}
}

func (b voteCreated) notificationCmds(w *wallet.Wallet) []interface{} {
	n := dcrjson.NewVoteCreatedNtfn(
		b.TxHash.String(),
		b.BlockHash.String(),
		int32(b.Height),
		b.SStxIn.String(),
		b.VoteBits)
	return []interface{}{n}
}

func (b revocationCreated) notificationCmds(w *wallet.Wallet) []interface{} {
	n := dcrjson.NewRevocationCreatedNtfn(
		b.TxHash.String(),
		b.SStxIn.String())
	return []interface{}{n}
}

func (b blockConnected) notificationCmds(w *wallet.Wallet) []interface{} {
	n := dcrjson.NewBlockConnectedNtfn(b.Hash.String(), b.Height, b.Time.Unix(),
		b.VoteBits)
	return []interface{}{n}
}

func (b blockDisconnected) notificationCmds(w *wallet.Wallet) []interface{} {
	n := dcrjson.NewBlockDisconnectedNtfn(b.Hash.String(), b.Height, b.Time.Unix(),
		b.VoteBits)
	return []interface{}{n}
}

func (t relevantTx) notificationCmds(w *wallet.Wallet) []interface{} {
	syncBlock := w.Manager.SyncedTo()

	var block *wtxmgr.Block
	if t.Block != nil {
		block = &t.Block.Block
	}
	details, err := w.TxStore.UniqueTxDetails(&t.TxRecord.Hash, block)
	if err != nil {
		log.Errorf("Cannot fetch transaction details for "+
			"client notification: %v", err)
		return nil
	}
	if details == nil {
		log.Errorf("No details found for client transaction notification")
		return nil
	}

	ltr := wallet.ListTransactions(details, w.Manager, syncBlock.Height,
		activeNet.Params)
	ntfns := make([]interface{}, len(ltr))
	for i := range ntfns {
		ntfns[i] = dcrjson.NewNewTxNtfn(ltr[i].Account, ltr[i])
	}
	return ntfns
}

func (l managerLocked) notificationCmds(w *wallet.Wallet) []interface{} {
	n := dcrjson.NewWalletLockStateNtfn(bool(l))
	return []interface{}{n}
}

func (b confirmedBalance) notificationCmds(w *wallet.Wallet) []interface{} {
	n := dcrjson.NewAccountBalanceNtfn("",
		dcrutil.Amount(b).ToCoin(), true)
	return []interface{}{n}
}

func (b unconfirmedBalance) notificationCmds(w *wallet.Wallet) []interface{} {
	n := dcrjson.NewAccountBalanceNtfn("",
		dcrutil.Amount(b).ToCoin(), false)
	return []interface{}{n}
}

func (b daemonConnected) notificationCmds(w *wallet.Wallet) []interface{} {
	n := dcrjson.NewBtcdConnectedNtfn(bool(b))
	return []interface{}{n}
}

func (s *rpcServer) notificationListener() {
out:
	for {
		select {
		case n := <-s.connectedBlocks:
			s.enqueueNotification <- blockConnected(n)
		case n := <-s.disconnectedBlocks:
			s.enqueueNotification <- blockDisconnected(n)
		case n := <-s.ticketsPurchased:
			s.enqueueNotification <- ticketPurchased(n)
		case n := <-s.votesCreated:
			s.enqueueNotification <- voteCreated(n)
		case n := <-s.revocationsCreated:
			s.enqueueNotification <- revocationCreated(n)
		case n := <-s.relevantTxs:
			s.enqueueNotification <- relevantTx(n)
		case n := <-s.managerLocked:
			s.enqueueNotification <- managerLocked(n)
		case n := <-s.confirmedBalance:
			s.enqueueNotification <- confirmedBalance(n)
		case n := <-s.unconfirmedBalance:
			s.enqueueNotification <- unconfirmedBalance(n)

		// Registration of all notifications is done by the handler so
		// it doesn't require another rpcServer mutex.
		case <-s.registerWalletNtfns:
			connectedBlocks, err := s.wallet.ListenConnectedBlocks()
			if err != nil {
				log.Errorf("Could not register for new "+
					"connected block notifications: %v",
					err)
				continue
			}
			disconnectedBlocks, err := s.wallet.ListenDisconnectedBlocks()
			if err != nil {
				log.Errorf("Could not register for new "+
					"disconnected block notifications: %v",
					err)
				continue
			}
			ticketsPurchased, err := s.wallet.ListenTicketsPurchased()
			if err != nil {
				log.Errorf("Could not register for newly created "+
					"tickets notifications: %v",
					err)
				continue
			}
			votesCreated, err := s.wallet.ListenVotesCreated()
			if err != nil {
				log.Errorf("Could not register for newly created "+
					"votes notifications: %v",
					err)
				continue
			}
			revocationsCreated, err := s.wallet.ListenRevocationsCreated()
			if err != nil {
				log.Errorf("Could not register for newly created "+
					"revocations notifications: %v",
					err)
				continue
			}
			relevantTxs, err := s.wallet.ListenRelevantTxs()
			if err != nil {
				log.Errorf("Could not register for new relevant "+
					"transaction notifications: %v", err)
				continue
			}
			managerLocked, err := s.wallet.ListenLockStatus()
			if err != nil {
				log.Errorf("Could not register for manager "+
					"lock state changes: %v", err)
				continue
			}
			confirmedBalance, err := s.wallet.ListenConfirmedBalance()
			if err != nil {
				log.Errorf("Could not register for confirmed "+
					"balance changes: %v", err)
				continue
			}
			unconfirmedBalance, err := s.wallet.ListenUnconfirmedBalance()
			if err != nil {
				log.Errorf("Could not register for unconfirmed "+
					"balance changes: %v", err)
				continue
			}
			s.connectedBlocks = connectedBlocks
			s.disconnectedBlocks = disconnectedBlocks
			s.ticketsPurchased = ticketsPurchased
			s.votesCreated = votesCreated
			s.revocationsCreated = revocationsCreated
			s.relevantTxs = relevantTxs
			s.managerLocked = managerLocked
			s.confirmedBalance = confirmedBalance
			s.unconfirmedBalance = unconfirmedBalance

		case <-s.quit:
			break out
		}
	}
	close(s.enqueueNotification)
	go s.drainNotifications()
	s.wg.Done()
}

func (s *rpcServer) drainNotifications() {
	for {
		select {
		case <-s.connectedBlocks:
		case <-s.disconnectedBlocks:
		case <-s.ticketsPurchased:
		case <-s.votesCreated:
		case <-s.revocationsCreated:
		case <-s.relevantTxs:
		case <-s.managerLocked:
		case <-s.confirmedBalance:
		case <-s.unconfirmedBalance:
		case <-s.registerWalletNtfns:
		}
	}
}

// notificationQueue manages an infinitly-growing queue of notifications that
// wallet websocket clients may be interested in.  It quits when the
// enqueueNotification channel is closed, dropping any still pending
// notifications.
func (s *rpcServer) notificationQueue() {
	var q []wsClientNotification
	var dequeue chan<- wsClientNotification
	skipQueue := s.dequeueNotification
	var next wsClientNotification
out:
	for {
		select {
		case n, ok := <-s.enqueueNotification:
			if !ok {
				// Sender closed input channel.
				break out
			}

			// Either send to out immediately if skipQueue is
			// non-nil (queue is empty) and reader is ready,
			// or append to the queue and send later.
			select {
			case skipQueue <- n:
			default:
				q = append(q, n)
				dequeue = s.dequeueNotification
				skipQueue = nil
				next = q[0]
			}

		case dequeue <- next:
			q[0] = nil // avoid leak
			q = q[1:]
			if len(q) == 0 {
				dequeue = nil
				skipQueue = s.dequeueNotification
			} else {
				next = q[0]
			}
		}
	}
	close(s.dequeueNotification)
	s.wg.Done()
}

func (s *rpcServer) notificationHandler() {
	clients := make(map[chan struct{}]*websocketClient)
out:
	for {
		select {
		case c := <-s.registerWSC:
			clients[c.quit] = c

		case c := <-s.unregisterWSC:
			delete(clients, c.quit)

		case nmsg, ok := <-s.dequeueNotification:
			// No more notifications.
			if !ok {
				break out
			}

			// Ignore if there are no clients to receive the
			// notification.
			if len(clients) == 0 {
				continue
			}

			ns := nmsg.notificationCmds(s.wallet)
			for _, n := range ns {
				mn, err := dcrjson.MarshalCmd(nil, n)
				// All notifications are expected to be
				// marshalable.
				if err != nil {
					panic(err)
				}
				for _, c := range clients {
					if err := c.send(mn); err != nil {
						delete(clients, c.quit)
					}
				}
			}

		case <-s.quit:
			break out
		}
	}
	close(s.notificationHandlerQuit)
	s.wg.Done()
}

// requestHandler is a handler function to handle an unmarshaled and parsed
// request into a marshalable response.  If the error is a *dcrjson.RPCError
// or any of the above special error classes, the server will respond with
// the JSON-RPC appropiate error code.  All other errors use the wallet
// catch-all error code, dcrjson.ErrRPCWallet.
type requestHandler func(*wallet.Wallet, *chain.Client,
	interface{}) (interface{}, error)

var rpcHandlers = map[string]struct {
	handler requestHandler

	// Function variables cannot be compared against anything but nil, so
	// use a boolean to record whether help generation is necessary.  This
	// is used by the tests to ensure that help can be generated for every
	// implemented method.
	//
	// A single map and this bool is here is used rather than several maps
	// for the unimplemented handlers so every method has exactly one
	// handler function.
	noHelp bool
}{
	// Reference implementation wallet methods (implemented)
	"addmultisigaddress":     {handler: AddMultiSigAddress},
	"createmultisig":         {handler: CreateMultiSig},
	"dumpprivkey":            {handler: DumpPrivKey},
	"getaccount":             {handler: GetAccount},
	"getaccountaddress":      {handler: GetAccountAddress},
	"getaddressesbyaccount":  {handler: GetAddressesByAccount},
	"getbalance":             {handler: GetBalance},
	"getbestblockhash":       {handler: GetBestBlockHash},
	"getblockcount":          {handler: GetBlockCount},
	"getinfo":                {handler: GetInfo},
	"getmultisigoutinfo":     {handler: GetMultisigOutInfo},
	"getnewaddress":          {handler: GetNewAddress},
	"getrawchangeaddress":    {handler: GetRawChangeAddress},
	"getreceivedbyaccount":   {handler: GetReceivedByAccount},
	"getreceivedbyaddress":   {handler: GetReceivedByAddress},
	"getmasterpubkey":        {handler: GetMasterPubkey},
	"getseed":                {handler: GetSeed},
	"getticketmaxprice":      {handler: GetTicketMaxPrice},
	"gettickets":             {handler: GetTickets},
	"gettransaction":         {handler: GetTransaction},
	"help":                   {handler: Help},
	"importprivkey":          {handler: ImportPrivKey},
	"importscript":           {handler: ImportScript},
	"keypoolrefill":          {handler: KeypoolRefill},
	"listaccounts":           {handler: ListAccounts},
	"listlockunspent":        {handler: ListLockUnspent},
	"listreceivedbyaccount":  {handler: ListReceivedByAccount},
	"listreceivedbyaddress":  {handler: ListReceivedByAddress},
	"listsinceblock":         {handler: ListSinceBlock},
	"listtransactions":       {handler: ListTransactions},
	"listunspent":            {handler: ListUnspent},
	"lockunspent":            {handler: LockUnspent},
	"purchaseticket":         {handler: PurchaseTicket},
	"sendfrom":               {handler: SendFrom},
	"sendmany":               {handler: SendMany},
	"sendtoaddress":          {handler: SendToAddress},
	"sendtomultisig":         {handler: SendToMultiSig},
	"sendtosstx":             {handler: SendToSStx},
	"sendtossgen":            {handler: SendToSSGen},
	"sendtossrtx":            {handler: SendToSSRtx},
	"setgenerate":            {handler: SetGenerate},
	"setticketmaxprice":      {handler: SetTicketMaxPrice},
	"settxfee":               {handler: SetTxFee},
	"signmessage":            {handler: SignMessage},
	"signrawtransaction":     {handler: SignRawTransaction},
	"signrawtransactions":    {handler: SignRawTransactions},
	"redeemmultisigout":      {handler: RedeemMultiSigOut},
	"redeemmultisigouts":     {handler: RedeemMultiSigOuts},
	"ticketsforaddress":      {handler: TicketsForAddress},
	"validateaddress":        {handler: ValidateAddress},
	"verifymessage":          {handler: VerifyMessage},
	"walletlock":             {handler: WalletLock},
	"walletpassphrase":       {handler: WalletPassphrase},
	"walletpassphrasechange": {handler: WalletPassphraseChange},

	// Reference implementation methods (still unimplemented)
	"backupwallet":         {handler: Unimplemented, noHelp: true},
	"dumpwallet":           {handler: Unimplemented, noHelp: true},
	"getwalletinfo":        {handler: Unimplemented, noHelp: true},
	"importwallet":         {handler: Unimplemented, noHelp: true},
	"listaddressgroupings": {handler: Unimplemented, noHelp: true},

	// Reference methods which can't be implemented by dcrwallet due to
	// design decision differences
	"encryptwallet": {handler: Unsupported, noHelp: true},
	"move":          {handler: Unsupported, noHelp: true},
	"setaccount":    {handler: Unsupported, noHelp: true},

	// Extensions to the reference client JSON-RPC API
	"createnewaccount": {handler: CreateNewAccount},
	"getbestblock":     {handler: GetBestBlock},

	// This was an extension but the reference implementation added it as
	// well, but with a different API (no account parameter).  It's listed
	// here because it hasn't been update to use the reference
	// implemenation's API.
	"getunconfirmedbalance":   {handler: GetUnconfirmedBalance},
	"listaddresstransactions": {handler: ListAddressTransactions},
	"listalltransactions":     {handler: ListAllTransactions},
	"renameaccount":           {handler: RenameAccount},
	"walletislocked":          {handler: WalletIsLocked},
}

// Unimplemented handles an unimplemented RPC request with the
// appropiate error.
func Unimplemented(*wallet.Wallet, *chain.Client,
	interface{}) (interface{}, error) {
	return nil, &dcrjson.RPCError{
		Code:    dcrjson.ErrRPCUnimplemented,
		Message: "Method unimplemented",
	}
}

// Unsupported handles a standard bitcoind RPC request which is
// unsupported by dcrwallet due to design differences.
func Unsupported(*wallet.Wallet, *chain.Client,
	interface{}) (interface{}, error) {
	return nil, &dcrjson.RPCError{
		Code:    -1,
		Message: "Request unsupported by dcrwallet",
	}
}

// UnloadedWallet is the handler func that is run when a wallet has not been
// loaded yet when trying to execute a wallet RPC.
func UnloadedWallet(*wallet.Wallet, *chain.Client,
	interface{}) (interface{}, error) {
	return nil, &ErrUnloadedWallet
}

// NoEncryptedWallet is the handler func that is run when no wallet has been
// created by the user yet.
// loaded yet when trying to execute a wallet RPC.
func NoEncryptedWallet(*wallet.Wallet, *chain.Client,
	interface{}) (interface{}, error) {
	return nil, &dcrjson.RPCError{
		Code: dcrjson.ErrRPCWallet,
		Message: "Request requires a wallet but no wallet has been " +
			"created -- use createencryptedwallet to recover",
	}
}

// TODO(jrick): may be a good idea to add handlers for passthrough to the chain
// server.  If a handler can not be looked up in one of the above maps, use this
// passthrough handler instead.  This isn't done at the moment since all
// requests are executed serialized, and blocking all requests, and even just
// requests from the same client, on the result of a dcrd RPC can result is too
// much waiting for the round trip.

// lookupAnyHandler looks up a request handler func for the passed method from
// the http post and (if the request is from a websocket connection) websocket
// handler maps.  If a suitable handler could not be found, ok is false.
func lookupAnyHandler(method string) (f requestHandler, ok bool) {
	handlerData, ok := rpcHandlers[method]
	f = handlerData.handler
	return
}

// unloadedWalletHandlerFunc looks up whether a request requires a wallet, and
// if so, returns a specialized handler func to return errors for an unloaded
// wallet component necessary to complete the request.  If ok is false, the
// function is invalid and should be passed through instead.
func unloadedWalletHandlerFunc(method string) (f requestHandler, ok bool) {
	_, ok = rpcHandlers[method]
	if ok {
		f = UnloadedWallet
	}
	return
}

// missingWalletHandlerFunc looks up whether a request requires a wallet, and
// if so, returns a specialized handler func to return errors for no wallets
// being created yet with the createencryptedwallet RPC.  If ok is false, the
// function is invalid and should be passed through instead.
func missingWalletHandlerFunc(method string) (f requestHandler, ok bool) {
	_, ok = rpcHandlers[method]
	if ok {
		f = NoEncryptedWallet
	}
	return
}

// requestHandlerClosure is a closure over a requestHandler or passthrough
// request with the RPC server's wallet and chain server variables as part
// of the closure context.
type requestHandlerClosure func(*dcrjson.Request) (interface{}, *dcrjson.RPCError)

// makeResponse makes the JSON-RPC response struct for the result and error
// returned by a requestHandler.  The returned response is not ready for
// marshaling and sending off to a client, but must be
func makeResponse(id, result interface{}, err error) dcrjson.Response {
	idPtr := idPointer(id)
	if err != nil {
		return dcrjson.Response{
			ID:    idPtr,
			Error: jsonError(err),
		}
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return dcrjson.Response{
			ID: idPtr,
			Error: &dcrjson.RPCError{
				Code:    dcrjson.ErrRPCInternal.Code,
				Message: "Unexpected error marshalling result",
			},
		}
	}
	return dcrjson.Response{
		ID:     idPtr,
		Result: json.RawMessage(resultBytes),
	}
}

// jsonError creates a JSON-RPC error from the Go error.
func jsonError(err error) *dcrjson.RPCError {
	if err == nil {
		return nil
	}

	code := dcrjson.ErrRPCWallet
	switch e := err.(type) {
	case dcrjson.RPCError:
		return &e
	case *dcrjson.RPCError:
		return e
	case DeserializationError:
		code = dcrjson.ErrRPCDeserialization
	case InvalidParameterError:
		code = dcrjson.ErrRPCInvalidParameter
	case ParseError:
		code = dcrjson.ErrRPCParse.Code
	case waddrmgr.ManagerError:
		switch e.ErrorCode {
		case waddrmgr.ErrWrongPassphrase:
			code = dcrjson.ErrRPCWalletPassphraseIncorrect
		}
	}
	return &dcrjson.RPCError{
		Code:    code,
		Message: err.Error(),
	}
}

// makeMultiSigScript is a helper function to combine common logic for
// AddMultiSig and CreateMultiSig.
// all error codes are rpc parse error here to match bitcoind which just throws
// a runtime exception. *sigh*.
func makeMultiSigScript(w *wallet.Wallet, keys []string,
	nRequired int) ([]byte, error) {
	keysesPrecious := make([]*dcrutil.AddressSecpPubKey, len(keys))

	// The address list will made up either of addreseses (pubkey hash), for
	// which we need to look up the keys in wallet, straight pubkeys, or a
	// mixture of the two.
	for i, a := range keys {
		// try to parse as pubkey address
		a, err := decodeAddress(a, activeNet.Params)
		if err != nil {
			return nil, err
		}

		switch addr := a.(type) {
		case *dcrutil.AddressSecpPubKey:
			keysesPrecious[i] = addr
		case *dcrutil.AddressPubKeyHash:
			ainfo, err := w.Manager.Address(addr)
			if err != nil {
				return nil, err
			}

			apkinfo := ainfo.(waddrmgr.ManagedPubKeyAddress)

			// This will be an addresspubkey
			a, err := decodeAddress(apkinfo.ExportPubKey(),
				activeNet.Params)
			if err != nil {
				return nil, err
			}

			apk := a.(*dcrutil.AddressSecpPubKey)
			keysesPrecious[i] = apk
		default:
			return nil, err
		}
	}

	return txscript.MultiSigScript(keysesPrecious, nRequired)
}

// AddMultiSigAddress handles an addmultisigaddress request by adding a
// multisig address to the given wallet.
func AddMultiSigAddress(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.AddMultisigAddressCmd)

	// If an account is specified, ensure that is the imported account.
	if cmd.Account != nil && *cmd.Account != waddrmgr.ImportedAddrAccountName {
		return nil, &ErrNotImportedAccount
	}

	txscript, err := makeMultiSigScript(w, cmd.Keys, cmd.NRequired)
	if err != nil {
		return nil, ParseError{err}
	}

	// Insert into the tx store.
	err = w.TxStore.InsertTxScript(txscript)
	if err != nil {
		return nil, err
	}

	// TODO(oga) blockstamp current block?
	bs := &waddrmgr.BlockStamp{
		Hash:   *activeNet.Params.GenesisHash,
		Height: 0,
	}

	addr, err := w.Manager.ImportScript(txscript, bs)
	if err != nil {
		return nil, err
	}

	err = chainSvr.NotifyReceived([]dcrutil.Address{addr.Address()})
	if err != nil {
		return nil, err
	}

	return addr.Address().EncodeAddress(), nil
}

// CreateMultiSig handles an createmultisig request by returning a
// multisig address for the given inputs.
func CreateMultiSig(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.CreateMultisigCmd)

	txscript, err := makeMultiSigScript(w, cmd.Keys, cmd.NRequired)
	if err != nil {
		return nil, ParseError{err}
	}

	address, err := dcrutil.NewAddressScriptHash(txscript, activeNet.Params)
	if err != nil {
		// above is a valid script, shouldn't happen.
		return nil, err
	}

	return dcrjson.CreateMultiSigResult{
		Address:      address.EncodeAddress(),
		RedeemScript: hex.EncodeToString(txscript),
	}, nil
}

// DumpPrivKey handles a dumpprivkey request with the private key
// for a single address, or an appropiate error if the wallet
// is locked.
func DumpPrivKey(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.DumpPrivKeyCmd)

	addr, err := decodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, err
	}

	key, err := w.DumpWIFPrivateKey(addr)
	if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		// Address was found, but the private key isn't
		// accessible.
		return nil, &ErrWalletUnlockNeeded
	}
	return key, err
}

// DumpWallet handles a dumpwallet request by returning  all private
// keys in a wallet, or an appropiate error if the wallet is locked.
// TODO: finish this to match bitcoind by writing the dump to a file.
func DumpWallet(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	keys, err := w.DumpPrivKeys()
	if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		return nil, &ErrWalletUnlockNeeded
	}

	return keys, err
}

// GetAddressesByAccount handles a getaddressesbyaccount request by returning
// all addresses for an account, or an error if the requested account does
// not exist.
func GetAddressesByAccount(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetAddressesByAccountCmd)

	account, err := w.Manager.LookupAccount(cmd.Account)
	if err != nil {
		return nil, err
	}

	var addrStrs []string
	err = w.Manager.ForEachAccountAddress(account,
		func(maddr waddrmgr.ManagedAddress) error {
			addrStrs = append(addrStrs, maddr.Address().EncodeAddress())
			return nil
		})
	return addrStrs, err
}

// GetBalance handles a getbalance request by returning the balance for an
// account (wallet), or an error if the requested account does not
// exist.
func GetBalance(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetBalanceCmd)

	var balance dcrutil.Amount
	var err error
	accountName := "default"
	if cmd.Account != nil {
		accountName = *cmd.Account
	}
	balType := wtxmgr.BFBalanceSpendable
	if cmd.BalanceType != nil {
		switch *cmd.BalanceType {
		case "spendable":
			balType = wtxmgr.BFBalanceSpendable
		case "locked":
			balType = wtxmgr.BFBalanceLockedStake
		case "all":
			balType = wtxmgr.BFBalanceAll
		case "fullscan":
			balType = wtxmgr.BFBalanceFullScan
		default:
			return nil, fmt.Errorf("unknown balance type '%v', please use "+
				"spendable, locked, all, or fullscan", *cmd.BalanceType)
		}
	}
	if accountName == "default" {
		balance, err = w.CalculateBalance(int32(*cmd.MinConf),
			balType)
	} else {
		var account uint32
		account, err = w.Manager.LookupAccount(accountName)
		if err != nil {
			return nil, err
		}
		balance, err = w.CalculateAccountBalance(account, int32(*cmd.MinConf))
	}
	if err != nil {
		return nil, err
	}
	return balance.ToCoin(), nil
}

// GetBestBlock handles a getbestblock request by returning a JSON object
// with the height and hash of the most recently processed block.
func GetBestBlock(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	blk := w.Manager.SyncedTo()
	result := &dcrjson.GetBestBlockResult{
		Hash:   blk.Hash.String(),
		Height: blk.Height,
	}
	return result, nil
}

// GetBestBlockHash handles a getbestblockhash request by returning the hash
// of the most recently processed block.
func GetBestBlockHash(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	blk := w.Manager.SyncedTo()
	return blk.Hash.String(), nil
}

// GetBlockCount handles a getblockcount request by returning the chain height
// of the most recently processed block.
func GetBlockCount(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	blk := w.Manager.SyncedTo()
	return blk.Height, nil
}

// GetInfo handles a getinfo request by returning the a structure containing
// information about the current state of dcrcwallet.
// exist.
func GetInfo(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	// Call down to dcrd for all of the information in this command known
	// by them.
	info, err := chainSvr.GetInfo()
	if err != nil {
		return nil, err
	}

	bal, err := w.CalculateBalance(1, wtxmgr.BFBalanceSpendable)
	if err != nil {
		return nil, err
	}

	// TODO(davec): This should probably have a database version as opposed
	// to using the manager version.
	info.WalletVersion = int32(waddrmgr.LatestMgrVersion)
	info.Balance = bal.ToCoin()
	info.KeypoolOldest = time.Now().Unix()
	info.KeypoolSize = int32(cfg.KeypoolSize)
	info.PaytxFee = w.FeeIncrement.ToCoin()
	// We don't set the following since they don't make much sense in the
	// wallet architecture:
	//  - unlocked_until
	//  - errors

	return info, nil
}

func decodeAddress(s string, params *chaincfg.Params) (dcrutil.Address, error) {
	// Secp256k1 pubkey as a string, handle differently.
	if len(s) == 66 || len(s) == 130 {
		pubKeyBytes, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		pubKeyAddr, err := dcrutil.NewAddressSecpPubKey(pubKeyBytes,
			params)
		if err != nil {
			return nil, err
		}

		return pubKeyAddr, nil
	}

	addr, err := dcrutil.DecodeAddress(s, params)
	if err != nil {
		msg := fmt.Sprintf("Invalid address %q: decode failed with %#q", s, err)
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	if !addr.IsForNet(activeNet.Params) {
		msg := fmt.Sprintf("Invalid address %q: not intended for use on %s",
			addr, params.Name)
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	return addr, nil
}

// GetAccount handles a getaccount request by returning the account name
// associated with a single address.
func GetAccount(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetAccountCmd)

	addr, err := decodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, err
	}

	// Fetch the associated account
	account, err := w.Manager.AddrAccount(addr)
	if err != nil {
		return nil, &ErrAddressNotInWallet
	}

	acctName, err := w.Manager.AccountName(account)
	if err != nil {
		return nil, &ErrAccountNameNotFound
	}
	return acctName, nil
}

// GetAccountAddress handles a getaccountaddress by returning the most
// recently-created chained address that has not yet been used (does not yet
// appear in the blockchain, or any tx that has arrived in the dcrd mempool).
// If the most recently-requested address has been used, a new address (the
// next chained address in the keypool) is used.  This can fail if the keypool
// runs out (and will return dcrjson.ErrRPCWalletKeypoolRanOut if that happens).
func GetAccountAddress(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetAccountAddressCmd)

	account, err := w.Manager.LookupAccount(cmd.Account)
	if err != nil {
		return nil, err
	}
	addr, err := w.CurrentAddress(account)
	if err != nil {
		return nil, err
	}

	return addr.EncodeAddress(), err
}

// GetUnconfirmedBalance handles a getunconfirmedbalance extension request
// by returning the current unconfirmed balance of an account.
func GetUnconfirmedBalance(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetUnconfirmedBalanceCmd)

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.Manager.LookupAccount(acctName)
	if err != nil {
		return nil, err
	}
	unconfirmed, err := w.CalculateAccountBalance(account, 0)
	if err != nil {
		return nil, err
	}
	confirmed, err := w.CalculateAccountBalance(account, 1)
	if err != nil {
		return nil, err
	}

	return (unconfirmed - confirmed).ToUnit(dcrutil.AmountCoin), nil
}

// ImportPrivKey handles an importprivkey request by parsing
// a WIF-encoded private key and adding it to an account.
func ImportPrivKey(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.ImportPrivKeyCmd)

	// Ensure that private keys are only imported to the correct account.
	//
	// Yes, Label is the account name.
	if cmd.Label != nil && *cmd.Label != waddrmgr.ImportedAddrAccountName {
		return nil, &ErrNotImportedAccount
	}

	wif, err := dcrutil.DecodeWIF(cmd.PrivKey)
	if err != nil {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInvalidAddressOrKey,
			Message: "WIF decode failed: " + err.Error(),
		}
	}
	if !wif.IsForNet(activeNet.Params) {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInvalidAddressOrKey,
			Message: "Key is not intended for " + activeNet.Params.Name,
		}
	}

	// Import the private key, handling any errors.
	_, err = w.ImportPrivateKey(wif, nil, *cmd.Rescan)
	switch {
	case waddrmgr.IsError(err, waddrmgr.ErrDuplicateAddress):
		// Do not return duplicate key errors to the client.
		return nil, nil
	case waddrmgr.IsError(err, waddrmgr.ErrLocked):
		return nil, &ErrWalletUnlockNeeded
	}

	return nil, err
}

// ImportScript imports a redeem script for a P2SH output.
func ImportScript(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.ImportScriptCmd)
	rs, err := hex.DecodeString(cmd.Hex)
	if err != nil {
		return nil, err
	}

	if len(rs) == 0 {
		return nil, fmt.Errorf("passed empty script")
	}

	err = w.TxStore.InsertTxScript(rs)
	if err != nil {
		return nil, err
	}

	// Get current block's height and hash.
	bs, err := chainSvr.BlockStamp()
	if err != nil {
		return nil, err
	}
	mscriptaddr, err := w.Manager.ImportScript(rs, bs)
	if err != nil {
		switch {
		// Don't care if it's already there.
		case waddrmgr.IsError(err, waddrmgr.ErrDuplicateAddress):
			return nil, err
		case waddrmgr.IsError(err, waddrmgr.ErrLocked):
			log.Debugf("failed to attempt script importation " +
				"of incoming tx because addrmgr was locked")
			return nil, err
		default:
			return nil, err
		}
	} else {
		// This is the first time seeing this script address
		// belongs to us, so do a rescan and see if there are
		// any other outputs to this address.
		job := &wallet.RescanJob{
			Addrs:     []dcrutil.Address{mscriptaddr.Address()},
			OutPoints: nil,
			BlockStamp: waddrmgr.BlockStamp{
				0,
				*activeNet.Params.GenesisHash,
			},
		}

		// Submit rescan job and log when the import has completed.
		// Do not block on finishing the rescan.  The rescan success
		// or failure is logged elsewhere, and the channel is not
		// required to be read, so discard the return value.
		_ = w.SubmitRescan(job)

		log.Infof("Redeem script hash %x (address %v) successfully added.",
			mscriptaddr.Address().ScriptAddress(),
			mscriptaddr.Address().EncodeAddress())
	}

	return nil, nil
}

// KeypoolRefill handles the keypoolrefill command. Since we handle the keypool
// automatically this does nothing since refilling is never manually required.
func KeypoolRefill(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	return nil, nil
}

// CreateNewAccount handles a createnewaccount request by creating and
// returning a new account. If the last account has no transaction history
// as per BIP 0044 a new account cannot be created so an error will be returned.
func CreateNewAccount(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.CreateNewAccountCmd)

	// The wildcard * is reserved by the rpc server with the special meaning
	// of "all accounts", so disallow naming accounts to this string.
	if cmd.Account == "*" {
		return nil, &ErrReservedAccountName
	}

	// Check that we are within the maximum allowed non-empty accounts limit.
	account, err := w.Manager.LastAccount()
	if err != nil {
		return nil, err
	}
	if account > maxEmptyAccounts {
		used, err := w.AccountUsed(account)
		if err != nil {
			return nil, err
		}
		if !used {
			return nil, errors.New("cannot create account: " +
				"previous account has no transaction history")
		}
	}

	_, err = w.Manager.NewAccount(cmd.Account)
	if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		return nil, &dcrjson.RPCError{
			Code: dcrjson.ErrRPCWalletUnlockNeeded,
			Message: "Creating an account requires the wallet to be unlocked. " +
				"Enter the wallet passphrase with walletpassphrase to unlock",
		}
	}
	return nil, err
}

// RenameAccount handles a renameaccount request by renaming an account.
// If the account does not exist an appropiate error will be returned.
func RenameAccount(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.RenameAccountCmd)

	// The wildcard * is reserved by the rpc server with the special meaning
	// of "all accounts", so disallow naming accounts to this string.
	if cmd.NewAccount == "*" {
		return nil, &ErrReservedAccountName
	}

	// Check that given account exists
	account, err := w.Manager.LookupAccount(cmd.OldAccount)
	if err != nil {
		return nil, err
	}
	return nil, w.Manager.RenameAccount(account, cmd.NewAccount)
}

// GetMultisigOutInfo displays information about a given multisignature
// output.
func GetMultisigOutInfo(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetMultisigOutInfoCmd)

	hash, err := chainhash.NewHashFromStr(cmd.Hash)
	if err != nil {
		return nil, err
	}

	// Multisig outs are always in TxTreeRegular.
	op := &wire.OutPoint{*hash, cmd.Index, dcrutil.TxTreeRegular}
	mso, err := w.TxStore.GetMultisigOutput(op)
	if err != nil {
		return nil, err
	}

	scriptAddr, err := dcrutil.NewAddressScriptHashFromHash(mso.ScriptHash[:],
		activeNet.Params)
	if err != nil {
		return nil, err
	}

	redeemScript, err := w.TxStore.GetTxScript(mso.ScriptHash[:])
	if err != nil {
		return nil, err
	}
	// Couldn't find it, look in the manager too.
	if redeemScript == nil {
		address, err := w.Manager.Address(scriptAddr)
		if err != nil {
			return nil, err
		}
		sa, ok := address.(waddrmgr.ManagedScriptAddress)
		if !ok {
			return nil, errors.New("address is not a script" +
				" address")
		}

		redeemScript, err = sa.Script()
		if err != nil {
			return nil, err
		}
	}

	// Get the list of pubkeys required to sign.
	var pubkeys []string
	_, pubkeyAddrs, _, err := txscript.ExtractPkScriptAddrs(
		txscript.DefaultScriptVersion, redeemScript, activeNet.Params)
	if err != nil {
		return nil, err
	}
	for _, pka := range pubkeyAddrs {
		pubkeys = append(pubkeys, hex.EncodeToString(pka.ScriptAddress()))
	}

	return dcrjson.GetMultisigOutInfoResult{
		Address:      scriptAddr.EncodeAddress(),
		RedeemScript: hex.EncodeToString(redeemScript),
		M:            mso.M,
		N:            mso.N,
		Pubkeys:      pubkeys,
		TxHash:       mso.TxHash.String(),
		BlockHeight:  mso.BlockHeight,
		BlockHash:    mso.BlockHash.String(),
		Spent:        mso.Spent,
		SpentBy:      mso.SpentBy.String(),
		SpentByIndex: mso.SpentByIndex,
		Amount:       mso.Amount.ToCoin(),
	}, nil
}

// GetNewAddress handles a getnewaddress request by returning a new
// address for an account.  If the account does not exist an appropiate
// error is returned.
// TODO: Follow BIP 0044 and warn if number of unused addresses exceeds
// the gap limit.
func GetNewAddress(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetNewAddressCmd)

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.Manager.LookupAccount(acctName)
	if err != nil {
		return nil, err
	}

	var addr dcrutil.Address
	if acctName == "default" {
		addr, err = w.GetNewAddressExternal()
		if err != nil {
			return nil, err
		}
	} else {
		addr, err = w.NewAddress(account)
		if err != nil {
			return nil, err
		}
	}

	if *cmd.Verbose {
		toReturn := make(map[string]string)
		toReturn["address"] = addr.EncodeAddress()

		ainfo, err := w.Manager.Address(addr)
		if err != nil {
			return nil, err
		}

		apkinfo := ainfo.(waddrmgr.ManagedPubKeyAddress)

		// This will be an addresspubkey.
		a, err := decodeAddress(apkinfo.ExportPubKey(),
			activeNet.Params)
		if err != nil {
			return nil, err
		}
		apk := a.(*dcrutil.AddressSecpPubKey)
		toReturn["pubkey"] = apk.String()

		// Return the new payment address string along with the pubkey.
		return toReturn, nil
	}

	return addr.EncodeAddress(), nil
}

// GetRawChangeAddress handles a getrawchangeaddress request by creating
// and returning a new change address for an account.
//
// Note: bitcoind allows specifying the account as an optional parameter,
// but ignores the parameter.
func GetRawChangeAddress(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetRawChangeAddressCmd)

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.Manager.LookupAccount(acctName)
	if err != nil {
		return nil, err
	}
	addr, err := w.NewChangeAddress(account)
	if err != nil {
		return nil, err
	}

	// Return the new payment address string.
	return addr.EncodeAddress(), nil
}

// GetReceivedByAccount handles a getreceivedbyaccount request by returning
// the total amount received by addresses of an account.
func GetReceivedByAccount(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetReceivedByAccountCmd)

	account, err := w.Manager.LookupAccount(cmd.Account)
	if err != nil {
		return nil, err
	}

	bal, _, err := w.TotalReceivedForAccount(account, int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}

	return bal.ToUnit(dcrutil.AmountCoin), nil
}

// GetReceivedByAddress handles a getreceivedbyaddress request by returning
// the total amount received by a single address.
func GetReceivedByAddress(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetReceivedByAddressCmd)

	addr, err := decodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, err
	}
	total, err := w.TotalReceivedForAddr(addr, int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}

	return total.ToUnit(dcrutil.AmountCoin), nil
}

// GetMasterPubkey handles a getmasterpubkey request by returning the wallet
// master pubkey encoded as a string.
func GetMasterPubkey(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	pkString, err := w.Manager.GetMasterPubkey()
	if err != nil {
		return nil, err
	}

	return &dcrjson.GetMasterPubkeyResult{pkString}, nil
}

// GetSeed handles a getseed request by returning the wallet seed encoded as
// a string.
func GetSeed(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	seedStr, err := w.Manager.GetSeed()
	if err != nil {
		return nil, err
	}

	return &dcrjson.GetSeedResult{seedStr}, nil
}

// GetTicketMaxPrice gets the maximum price the user is willing to pay for a
// ticket.
func GetTicketMaxPrice(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {

	return w.GetTicketMaxPrice().ToCoin(), nil
}

// hashInSlice returns whether a hash exists in a slice or not.
func hashInSlice(h chainhash.Hash, list []chainhash.Hash) bool {
	for _, hash := range list {
		if h == hash {
			return true
		}
	}

	return false
}

// GetTickets handles a gettickets request by returning the hashes of the tickets
// currently owned by wallet, encoded as strings.
func GetTickets(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetTicketsCmd)
	blk := w.Manager.SyncedTo()

	// UnspentTickets collects all the tickets that pay out to a
	// public key hash for a public key owned by this wallet.
	tickets, err := w.TxStore.UnspentTickets(blk.Height, cmd.IncludeImmature)
	if err != nil {
		return nil, err
	}

	// Access the stake manager and see if there are any extra tickets
	// there. Likely they were either pruned because they failed to get
	// into the blockchain or they are P2SH for some script we own.
	var extraTickets []chainhash.Hash
	stakeMgrTickets, err := w.StakeMgr.DumpSStxHashes()
	if err != nil {
		return nil, err
	}
	for _, h := range stakeMgrTickets {
		if !hashInSlice(h, tickets) {
			extraTickets = append(extraTickets, h)
		}
	}
	for _, h := range extraTickets {
		// Get the raw transaction information from daemon and add
		// any relevant tickets. The ticket output is always the
		// zeroeth output.
		spent, err := chainSvr.GetTxOut(&h, 0, true)
		if err != nil {
			continue
		}
		// This returns nil if the output is spent.
		if spent == nil {
			continue
		}

		ticketTx, err := chainSvr.GetRawTransactionVerbose(&h)
		if err != nil {
			continue
		}

		txHeight := ticketTx.BlockHeight
		unconfirmed := (txHeight == 0)
		immature := (blk.Height-int32(txHeight) <
			int32(w.ChainParams().TicketMaturity))
		if cmd.IncludeImmature {
			tickets = append(tickets, h)
		} else {
			if !(unconfirmed || immature) {
				tickets = append(tickets, h)
			}
		}
	}

	// Compose a slice of strings to return.
	ticketsStr := make([]string, len(tickets), len(tickets))
	for i, ticket := range tickets {
		ticketsStr[i] = ticket.String()
	}

	return &dcrjson.GetTicketsResult{ticketsStr}, nil
}

// GetTransaction handles a gettransaction request by returning details about
// a single transaction saved by wallet.
func GetTransaction(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.GetTransactionCmd)

	txSha, err := chainhash.NewHashFromStr(cmd.Txid)
	if err != nil {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCDecodeHexString,
			Message: "Transaction hash string decode failed: " + err.Error(),
		}
	}

	details, err := w.TxStore.TxDetails(txSha)
	if err != nil {
		return nil, err
	}
	if details == nil {
		return nil, &ErrNoTransactionInfo
	}

	syncBlock := w.Manager.SyncedTo()

	// TODO: The serialized transaction is already in the DB, so
	// reserializing can be avoided here.
	var txBuf bytes.Buffer
	txBuf.Grow(details.MsgTx.SerializeSize())
	err = details.MsgTx.Serialize(&txBuf)
	if err != nil {
		return nil, err
	}

	// TODO: Add a "generated" field to this result type.  "generated":true
	// is only added if the transaction is a coinbase.
	ret := dcrjson.GetTransactionResult{
		TxID:            cmd.Txid,
		Hex:             hex.EncodeToString(txBuf.Bytes()),
		Time:            details.Received.Unix(),
		TimeReceived:    details.Received.Unix(),
		WalletConflicts: []string{}, // Not saved
		//Generated:     blockchain.IsCoinBaseTx(&details.MsgTx),
	}

	if details.Block.Height != -1 {
		ret.BlockHash = details.Block.Hash.String()
		ret.BlockTime = details.Block.Time.Unix()
		ret.Confirmations = int64(confirms(details.Block.Height,
			syncBlock.Height))
	}

	var (
		debitTotal  dcrutil.Amount
		creditTotal dcrutil.Amount // Excludes change
		outputTotal dcrutil.Amount
		fee         dcrutil.Amount
		feeF64      float64
	)
	for _, deb := range details.Debits {
		debitTotal += deb.Amount
	}
	for _, cred := range details.Credits {
		if !cred.Change {
			creditTotal += cred.Amount
		}
	}
	for _, output := range details.MsgTx.TxOut {
		outputTotal += dcrutil.Amount(output.Value)
	}
	// Fee can only be determined if every input is a debit.
	if len(details.Debits) == len(details.MsgTx.TxIn) {
		fee = debitTotal - outputTotal
		feeF64 = fee.ToCoin()
	}

	if len(details.Debits) == 0 {
		// Credits must be set later, but since we know the full length
		// of the details slice, allocate it with the correct cap.
		ret.Details = make([]dcrjson.GetTransactionDetailsResult, 0,
			len(details.Credits))
	} else {
		ret.Details = make([]dcrjson.GetTransactionDetailsResult, 1,
			len(details.Credits)+1)

		ret.Details[0] = dcrjson.GetTransactionDetailsResult{
			// Fields left zeroed:
			//   InvolvesWatchOnly
			//   Account
			//   Address
			//   Vout
			//
			// TODO(jrick): Address and Vout should always be set,
			// but we're doing the wrong thing here by not matching
			// core.  Instead, gettransaction should only be adding
			// details for transaction outputs, just like
			// listtransactions (but using the short result format).
			Category: "send",
			Amount:   (-debitTotal).ToCoin(), // negative since it is a send
			Fee:      &feeF64,
		}
		ret.Fee = feeF64
	}

	credCat := wallet.RecvCategory(details, syncBlock.Height,
		w.ChainParams()).String()
	for _, cred := range details.Credits {
		// Change is ignored.
		if cred.Change {
			continue
		}

		var address string
		var accountName string
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			details.MsgTx.TxOut[cred.Index].Version,
			details.MsgTx.TxOut[cred.Index].PkScript,
			activeNet.Params)
		if err == nil && len(addrs) == 1 {
			addr := addrs[0]
			address = addr.EncodeAddress()
			account, err := w.Manager.AddrAccount(addr)
			if err == nil {
				accountName, err = w.Manager.AccountName(account)
				if err != nil {
					accountName = ""
				}
			}

		}

		ret.Details = append(ret.Details, dcrjson.GetTransactionDetailsResult{
			// Fields left zeroed:
			//   InvolvesWatchOnly
			//   Fee
			Account:  accountName,
			Address:  address,
			Category: credCat,
			Amount:   cred.Amount.ToCoin(),
			Vout:     cred.Index,
		})
	}

	ret.Amount = creditTotal.ToCoin()
	return ret, nil
}

// These generators create the following global variables in this package:
//
//   var localeHelpDescs map[string]func() map[string]string
//   var requestUsages string
//
// localeHelpDescs maps from locale strings (e.g. "en_US") to a function that
// builds a map of help texts for each RPC server method.  This prevents help
// text maps for every locale map from being rooted and created during init.
// Instead, the appropiate function is looked up when help text is first needed
// using the current locale and saved to the global below for futher reuse.
//
// requestUsages contains single line usages for every supported request,
// separated by newlines.  It is set during init.  These usages are used for all
// locales.
//
//go:generate go run internal/rpchelp/genrpcserverhelp.go -tags generate
//go:generate gofmt -w rpcserverhelp.go

var helpDescs map[string]string
var helpDescsMu sync.Mutex // Help may execute concurrently, so synchronize access.

// Help handles the help request by returning one line usage of all available
// methods, or full help for a specific method.
func Help(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.HelpCmd)

	// dcrd returns different help messages depending on the kind of
	// connection the client is using.  Only methods availble to HTTP POST
	// clients are available to be used by wallet clients, even though
	// wallet itself is a websocket client to dcrd.  Therefore, create a
	// POST client as needed.
	//
	// Returns nil if chainSvr is currently nil or there is an error
	// creating the client.
	//
	// This is hacky and is probably better handled by exposing help usage
	// texts in a non-internal dcrd package.
	postClient := func() *dcrrpcclient.Client {
		if chainSvr == nil {
			return nil
		}
		var certs []byte
		if !cfg.DisableClientTLS {
			var err error
			certs, err = ioutil.ReadFile(cfg.CAFile)
			if err != nil {
				return nil
			}
		}
		conf := dcrrpcclient.ConnConfig{
			Host:         cfg.RPCConnect,
			User:         cfg.DcrdUsername,
			Pass:         cfg.DcrdPassword,
			DisableTLS:   cfg.DisableClientTLS,
			Certificates: certs,
			HTTPPostMode: true,
		}
		client, err := dcrrpcclient.New(&conf, nil)
		if err != nil {
			return nil
		}
		return client
	}

	if cmd.Command == nil || *cmd.Command == "" {
		// Prepend chain server usage if it is available.
		usages := requestUsages
		client := postClient()
		if client != nil {
			rawChainUsage, err := client.RawRequest("help", nil)
			var chainUsage string
			if err == nil {
				_ = json.Unmarshal([]byte(rawChainUsage), &chainUsage)
			}
			if chainUsage != "" {
				usages = "Chain server usage:\n\n" + chainUsage + "\n\n" +
					"Wallet server usage (overrides chain requests):\n\n" +
					requestUsages
			}
		}
		return usages, nil
	}

	defer helpDescsMu.Unlock()
	helpDescsMu.Lock()

	if helpDescs == nil {
		// TODO: Allow other locales to be set via config or detemine
		// this from environment variables.  For now, hardcode US
		// English.
		helpDescs = localeHelpDescs["en_US"]()
	}

	helpText, ok := helpDescs[*cmd.Command]
	if ok {
		return helpText, nil
	}

	// Return the chain server's detailed help if possible.
	var chainHelp string
	client := postClient()
	if client != nil {
		param := make([]byte, len(*cmd.Command)+2)
		param[0] = '"'
		copy(param[1:], *cmd.Command)
		param[len(param)-1] = '"'
		rawChainHelp, err := client.RawRequest("help", []json.RawMessage{param})
		if err == nil {
			_ = json.Unmarshal([]byte(rawChainHelp), &chainHelp)
		}
	}
	if chainHelp != "" {
		return chainHelp, nil
	}
	return nil, &dcrjson.RPCError{
		Code:    dcrjson.ErrRPCInvalidParameter,
		Message: fmt.Sprintf("No help for method '%s'", *cmd.Command),
	}
}

// ListAccounts handles a listaccounts request by returning a map of account
// names to their balances.
func ListAccounts(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListAccountsCmd)

	accountBalances := map[string]float64{}
	var accounts []uint32
	err := w.Manager.ForEachAccount(func(account uint32) error {
		accounts = append(accounts, account)
		return nil
	})
	if err != nil {
		return nil, err
	}
	minConf := int32(*cmd.MinConf)
	for _, account := range accounts {
		acctName, err := w.Manager.AccountName(account)
		if err != nil {
			return nil, &ErrAccountNameNotFound
		}
		bal, err := w.CalculateAccountBalance(account, minConf)
		if err != nil {
			return nil, err
		}
		accountBalances[acctName] = bal.ToCoin()
	}
	// Return the map.  This will be marshaled into a JSON object.
	return accountBalances, nil
}

// ListLockUnspent handles a listlockunspent request by returning an slice of
// all locked outpoints.
func ListLockUnspent(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	return w.LockedOutpoints(), nil
}

// ListReceivedByAccount handles a listreceivedbyaccount request by returning
// a slice of objects, each one containing:
//  "account": the receiving account;
//  "amount": total amount received by the account;
//  "confirmations": number of confirmations of the most recent transaction.
// It takes two parameters:
//  "minconf": minimum number of confirmations to consider a transaction -
//             default: one;
//  "includeempty": whether or not to include addresses that have no transactions -
//                  default: false.
func ListReceivedByAccount(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListReceivedByAccountCmd)

	var accounts []uint32
	err := w.Manager.ForEachAccount(func(account uint32) error {
		accounts = append(accounts, account)
		return nil
	})
	if err != nil {
		return nil, err
	}

	ret := make([]dcrjson.ListReceivedByAccountResult, 0, len(accounts))
	minConf := int32(*cmd.MinConf)
	for _, account := range accounts {
		acctName, err := w.Manager.AccountName(account)
		if err != nil {
			return nil, &ErrAccountNameNotFound
		}
		bal, confirmations, err := w.TotalReceivedForAccount(account,
			minConf)
		if err != nil {
			return nil, err
		}
		ret = append(ret, dcrjson.ListReceivedByAccountResult{
			Account:       acctName,
			Amount:        bal.ToCoin(),
			Confirmations: uint64(confirmations),
		})
	}
	return ret, nil
}

// ListReceivedByAddress handles a listreceivedbyaddress request by returning
// a slice of objects, each one containing:
//  "account": the account of the receiving address;
//  "address": the receiving address;
//  "amount": total amount received by the address;
//  "confirmations": number of confirmations of the most recent transaction.
// It takes two parameters:
//  "minconf": minimum number of confirmations to consider a transaction -
//             default: one;
//  "includeempty": whether or not to include addresses that have no transactions -
//                  default: false.
func ListReceivedByAddress(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListReceivedByAddressCmd)

	// Intermediate data for each address.
	type AddrData struct {
		// Total amount received.
		amount dcrutil.Amount
		// Number of confirmations of the last transaction.
		confirmations int32
		// Hashes of transactions which include an output paying to the address
		tx []string
		// Account which the address belongs to
		account string
	}

	syncBlock := w.Manager.SyncedTo()

	// Intermediate data for all addresses.
	allAddrData := make(map[string]AddrData)
	// Create an AddrData entry for each active address in the account.
	// Otherwise we'll just get addresses from transactions later.
	sortedAddrs, err := w.SortedActivePaymentAddresses()
	if err != nil {
		return nil, err
	}
	for _, address := range sortedAddrs {
		// There might be duplicates, just overwrite them.
		allAddrData[address] = AddrData{}
	}

	minConf := *cmd.MinConf
	var endHeight int32
	if minConf == 0 {
		endHeight = -1
	} else {
		endHeight = syncBlock.Height - int32(minConf) + 1
	}
	err = w.TxStore.RangeTransactions(0, endHeight,
		func(details []wtxmgr.TxDetails) (bool, error) {
			if len(details) == 0 {
				return false, fmt.Errorf("no transaction details could be found")
			}

			confirmations := confirms(details[0].Block.Height, syncBlock.Height)
			for _, tx := range details {
				for _, cred := range tx.Credits {
					pkVersion := tx.MsgTx.TxOut[cred.Index].Version
					pkScript := tx.MsgTx.TxOut[cred.Index].PkScript
					_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkVersion,
						pkScript, activeNet.Params)
					if err != nil {
						// Non standard script, skip.
						continue
					}
					for _, addr := range addrs {
						addrStr := addr.EncodeAddress()
						addrData, ok := allAddrData[addrStr]
						if ok {
							addrData.amount += cred.Amount
							// Always overwrite confirmations with newer ones.
							addrData.confirmations = confirmations
						} else {
							addrData = AddrData{
								amount:        cred.Amount,
								confirmations: confirmations,
							}
						}
						addrData.tx = append(addrData.tx, tx.Hash.String())
						allAddrData[addrStr] = addrData
					}
				}
			}
			return false, nil
		})
	if err != nil {
		return nil, err
	}

	// Massage address data into output format.
	numAddresses := len(allAddrData)
	ret := make([]dcrjson.ListReceivedByAddressResult, numAddresses, numAddresses)
	idx := 0
	for address, addrData := range allAddrData {
		ret[idx] = dcrjson.ListReceivedByAddressResult{
			Address:       address,
			Amount:        addrData.amount.ToUnit(dcrutil.AmountCoin),
			Confirmations: uint64(addrData.confirmations),
			TxIDs:         addrData.tx,
		}
		idx++
	}
	return ret, nil
}

// ListSinceBlock handles a listsinceblock request by returning an array of maps
// with details of sent and received wallet transactions since the given block.
func ListSinceBlock(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListSinceBlockCmd)

	syncBlock := w.Manager.SyncedTo()
	targetConf := int64(*cmd.TargetConfirmations)

	// For the result we need the block hash for the last block counted
	// in the blockchain due to confirmations. We send this off now so that
	// it can arrive asynchronously while we figure out the rest.
	gbh := chainSvr.GetBlockHashAsync(int64(syncBlock.Height) + 1 - targetConf)

	var start int32
	if cmd.BlockHash != nil {
		hash, err := chainhash.NewHashFromStr(*cmd.BlockHash)
		if err != nil {
			return nil, DeserializationError{err}
		}
		block, err := chainSvr.GetBlockVerbose(hash, false)
		if err != nil {
			return nil, err
		}
		start = int32(block.Height) + 1
	}

	txInfoList, err := w.ListSinceBlock(start, -1, syncBlock.Height)
	if err != nil {
		return nil, err
	}

	// Done with work, get the response.
	blockHash, err := gbh.Receive()
	if err != nil {
		return nil, err
	}

	res := dcrjson.ListSinceBlockResult{
		Transactions: txInfoList,
		LastBlock:    blockHash.String(),
	}
	return res, nil
}

// ListTransactions handles a listtransactions request by returning an
// array of maps with details of sent and recevied wallet transactions.
func ListTransactions(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListTransactionsCmd)

	// TODO: ListTransactions does not currently understand the difference
	// between transactions pertaining to one account from another.  This
	// will be resolved when wtxmgr is combined with the waddrmgr namespace.

	if cmd.Account != nil && *cmd.Account != "*" {
		// For now, don't bother trying to continue if the user
		// specified an account, since this can't be (easily or
		// efficiently) calculated.
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCWallet,
			Message: "Transactions are not yet grouped by account",
		}
	}

	return w.ListTransactions(*cmd.From, *cmd.Count)
}

// ListAddressTransactions handles a listaddresstransactions request by
// returning an array of maps with details of spent and received wallet
// transactions.  The form of the reply is identical to listtransactions,
// but the array elements are limited to transaction details which are
// about the addresess included in the request.
func ListAddressTransactions(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListAddressTransactionsCmd)

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, &dcrjson.RPCError{
			Code: dcrjson.ErrRPCInvalidParameter,
			Message: "Listing transactions for addresses may only " +
				"be done for all accounts",
		}
	}

	// Decode addresses.
	hash160Map := make(map[string]struct{})
	for _, addrStr := range cmd.Addresses {
		addr, err := decodeAddress(addrStr, activeNet.Params)
		if err != nil {
			return nil, err
		}
		hash160Map[string(addr.ScriptAddress())] = struct{}{}
	}

	return w.ListAddressTransactions(hash160Map)
}

// ListAllTransactions handles a listalltransactions request by returning
// a map with details of sent and recevied wallet transactions.  This is
// similar to ListTransactions, except it takes only a single optional
// argument for the account name and replies with all transactions.
func ListAllTransactions(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListAllTransactionsCmd)

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInvalidParameter,
			Message: "Listing all transactions may only be done for all accounts",
		}
	}

	return w.ListAllTransactions()
}

// ListUnspent handles the listunspent command.
func ListUnspent(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.ListUnspentCmd)

	var addresses map[string]struct{}
	if cmd.Addresses != nil {
		addresses = make(map[string]struct{})
		// confirm that all of them are good:
		for _, as := range *cmd.Addresses {
			a, err := decodeAddress(as, activeNet.Params)
			if err != nil {
				return nil, err
			}
			addresses[a.EncodeAddress()] = struct{}{}
		}
	}

	return w.ListUnspent(int32(*cmd.MinConf), int32(*cmd.MaxConf), addresses)
}

// ListUnspentMultisig handles the listunspentmultisig command.
func ListUnspentMultisig(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	return nil, nil
}

// LockUnspent handles the lockunspent command.
func LockUnspent(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.LockUnspentCmd)

	switch {
	case cmd.Unlock && len(cmd.Transactions) == 0:
		w.ResetLockedOutpoints()
	default:
		for _, input := range cmd.Transactions {
			txSha, err := chainhash.NewHashFromStr(input.Txid)
			if err != nil {
				return nil, ParseError{err}
			}
			op := wire.OutPoint{Hash: *txSha, Index: input.Vout}
			if cmd.Unlock {
				w.UnlockOutpoint(op)
			} else {
				w.LockOutpoint(op)
			}
		}
	}
	return true, nil
}

// PurchaseTicket indicates to the wallet that a ticket should be purchased
// using all currently available funds. If the ticket could not be purchased
// because there are not enough eligible funds, an error will be returned.
// cj: Doesn't actually use chainSvr.
func PurchaseTicket(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {

	// Enforce valid and positive spend limit.
	cmd := icmd.(*dcrjson.PurchaseTicketCmd)
	spendLimit, err := dcrutil.NewAmount(cmd.SpendLimit)
	if err != nil {
		return nil, err
	}
	if spendLimit < 0 {
		return nil, ErrNeedPositiveSpendLimit
	}

	// Override the minimum number of required confirmations if specified
	// and enforce it is positive.
	minConf := int32(1)
	if cmd.MinConf != nil {
		minConf = int32(*cmd.MinConf)
		if minConf < 0 {
			return nil, ErrNeedPositiveMinconf
		}
	}

	// Set ticket address if specified.
	var ticketAddr dcrutil.Address
	if cmd.TicketAddress != nil {
		addr, err := decodeAddress(*cmd.TicketAddress, activeNet.Params)
		if err != nil {
			return nil, err
		}
		ticketAddr = addr
	}

	hash, err := w.CreatePurchaseTicket(0, spendLimit, minConf, ticketAddr)
	if err != nil {
		if err == wallet.ErrSStxInputOverflow {
			hash = ""
		}
	}

	return hash, err
}

// RedeemMultiSigOut receives a transaction hash/idx and fetches the first output
// index or indices with known script hashes from the transaction. It then
// construct a transaction with a single P2PKH paying to a specified address.
// It signs any inputs that it can, then provides the raw transaction to
// the user to export to others to sign.
func RedeemMultiSigOut(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.RedeemMultiSigOutCmd)

	// Convert the address to a useable format. If
	// we have no address, create a new address in
	// this wallet to send the output to.
	var addr dcrutil.Address
	var err error
	if cmd.Address != nil {
		addr, err = decodeAddress(*cmd.Address, activeNet.Params)
	} else {
		account := uint32(waddrmgr.DefaultAccountNum)
		addr, err = w.NewAddress(account)
		if err != nil {
			return nil, err
		}
	}

	// Lookup the multisignature output and get the amount
	// along with the script for that transaction. Then,
	// begin crafting a MsgTx.
	hash, err := chainhash.NewHashFromStr(cmd.Hash)
	if err != nil {
		return nil, err
	}
	op := wire.OutPoint{
		*hash,
		cmd.Index,
		cmd.Tree,
	}
	msCredit, err := w.TxStore.GetMultisigCredit(&op)
	if err != nil {
		return nil, err
	}
	sc := txscript.GetScriptClass(txscript.DefaultScriptVersion,
		msCredit.MSScript)
	if sc != txscript.MultiSigTy {
		return nil, fmt.Errorf("invalid P2SH script: not multisig")
	}
	var msgTx wire.MsgTx
	msgTx.AddTxIn(wire.NewTxIn(&op, nil))

	// Calculate the fees required, and make sure we have enough.
	// Then produce the txout.
	size := wallet.EstimateTxSize(1, 1)
	var feeIncrement dcrutil.Amount
	switch {
	case activeNet.Params == &chaincfg.MainNetParams:
		feeIncrement = wallet.FeeIncrementMainnet
	case activeNet.Params == &chaincfg.TestNetParams:
		feeIncrement = wallet.FeeIncrementTestnet
	default:
		feeIncrement = wallet.FeeIncrementTestnet
	}
	feeEst := wallet.FeeForSize(feeIncrement, size)
	if feeEst >= msCredit.Amount {
		return nil, fmt.Errorf("multisig out amt is too small "+
			"(have %v, %v fee suggested)", msCredit.Amount, feeEst)
	}
	toReceive := msCredit.Amount - feeEst
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, fmt.Errorf("cannot create txout script: %s", err)
	}
	msgTx.AddTxOut(wire.NewTxOut(int64(toReceive), pkScript))

	// Start creating the SignRawTransactionCmd.
	outpointScript, err := txscript.PayToScriptHashScript(msCredit.ScriptHash[:])
	if err != nil {
		return nil, err
	}
	outpointScriptStr := hex.EncodeToString(outpointScript)

	rti := dcrjson.RawTxInput{
		cmd.Hash,
		cmd.Index,
		cmd.Tree,
		outpointScriptStr,
		"",
	}
	rtis := []dcrjson.RawTxInput{rti}

	var buf bytes.Buffer
	buf.Grow(msgTx.SerializeSize())
	if err = msgTx.Serialize(&buf); err != nil {
		return nil, err
	}
	txDataStr := hex.EncodeToString(buf.Bytes())
	sigHashAll := "ALL"

	srtc := &dcrjson.SignRawTransactionCmd{
		txDataStr,
		&rtis,
		&[]string{},
		&sigHashAll,
	}

	// Sign it and give the results to the user.
	signedTxResult, err := SignRawTransaction(w, chainSvr, srtc)
	if signedTxResult == nil || err != nil {
		return nil, err
	}
	srtTyped := signedTxResult.(dcrjson.SignRawTransactionResult)
	return dcrjson.RedeemMultiSigOutResult{srtTyped.Hex,
		srtTyped.Complete,
		srtTyped.Errors}, nil
}

// RedeemMultisigOuts receives a script hash (in the form of a
// script hash address), looks up all the unspent outpoints associated
// with that address, then generates a list of partially signed
// transactions spending to either an address specified or internal
// addresses in this wallet.
func RedeemMultiSigOuts(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.RedeemMultiSigOutsCmd)

	// Get all the multisignature outpoints that are unspent for this
	// address.
	addr, err := decodeAddress(cmd.FromScrAddress, activeNet.Params)
	if err != nil {
		return nil, err
	}
	msos, err := w.TxStore.UnspentMultisigCreditsForAddress(addr)
	if err != nil {
		return nil, err
	}
	max := uint32(0xffffffff)
	if cmd.Number != nil {
		max = uint32(*cmd.Number)
	}

	itr := uint32(0)
	rmsoResults := make([]dcrjson.RedeemMultiSigOutResult, len(msos), len(msos))
	for i, mso := range msos {
		if itr > max {
			break
		}

		rmsoRequest := &dcrjson.RedeemMultiSigOutCmd{
			Hash:    mso.OutPoint.Hash.String(),
			Index:   mso.OutPoint.Index,
			Tree:    mso.OutPoint.Tree,
			Address: cmd.ToAddress,
		}
		redeemResult, err := RedeemMultiSigOut(w, chainSvr, rmsoRequest)
		if err != nil {
			return nil, err
		}
		redeemResultTyped := redeemResult.(dcrjson.RedeemMultiSigOutResult)
		rmsoResults[i] = redeemResultTyped

		itr++
	}

	return dcrjson.RedeemMultiSigOutsResult{rmsoResults}, nil
}

func TicketsForAddress(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.TicketsForAddressCmd)

	addr, err := dcrutil.DecodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	tickets, err := w.StakeMgr.DumpSStxHashesForAddress(addr)
	if err != nil {
		return nil, err
	}

	ticketsStr := make([]string, len(tickets), len(tickets))
	for i, h := range tickets {
		ticketsStr[i] = h.String()
	}

	return dcrjson.TicketsForAddressResult{ticketsStr}, nil
}

// sendPairs creates and sends payment transactions.
// It returns the transaction hash in string format upon success
// All errors are returned in dcrjson.RPCError format
func sendPairs(w *wallet.Wallet, chainSvr *chain.Client,
	amounts map[string]dcrutil.Amount, account uint32, minconf int32) (string,
	error) {
	createdTx, err := w.SendPairs(amounts, account, minconf)
	if err != nil {
		if err == wallet.ErrNonPositiveAmount {
			return "", ErrNeedPositiveAmount
		}
		if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			return "", &ErrWalletUnlockNeeded
		}
		switch err.(type) {
		case dcrjson.RPCError:
			return "", err
		}

		return "", &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInternal.Code,
			Message: err.Error(),
		}
	}

	txShaStr := createdTx.MsgTx.TxSha().String()
	log.Infof("Successfully sent transaction %v", txShaStr)
	return txShaStr, nil
}

func isNilOrEmpty(s *string) bool {
	return s == nil || *s == ""
}

// SendFrom handles a sendfrom RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to another payment
// address.  Leftover inputs not sent to the payment address or a fee for
// the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func SendFrom(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendFromCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) || !isNilOrEmpty(cmd.CommentTo) {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCUnimplemented,
			Message: "Transaction comments are not yet supported",
		}
	}

	account, err := w.Manager.LookupAccount(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that signed integer parameters are positive.
	if cmd.Amount < 0 {
		return nil, ErrNeedPositiveAmount
	}
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, ErrNeedPositiveMinconf
	}
	// Create map of address and amount pairs.
	amt, err := dcrutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}
	pairs := map[string]dcrutil.Amount{
		cmd.ToAddress: amt,
	}

	return sendPairs(w, chainSvr, pairs, account, minConf)
}

// SendMany handles a sendmany RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to any number of
// payment addresses.  Leftover inputs not sent to the payment address
// or a fee for the miner are sent back to a new address in the wallet.
// Upon success, the TxID for the created transaction is returned.
func SendMany(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendManyCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCUnimplemented,
			Message: "Transaction comments are not yet supported",
		}
	}

	account, err := w.Manager.LookupAccount(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that minconf is positive.
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, ErrNeedPositiveMinconf
	}

	// Recreate address/amount pairs, using dcrutil.Amount.
	pairs := make(map[string]dcrutil.Amount, len(cmd.Amounts))
	for k, v := range cmd.Amounts {
		amt, err := dcrutil.NewAmount(v)
		if err != nil {
			return nil, err
		}
		pairs[k] = amt
	}

	return sendPairs(w, chainSvr, pairs, account, minConf)
}

// SendToAddress handles a sendtoaddress RPC request by creating a new
// transaction spending unspent transaction outputs for a wallet to another
// payment address.  Leftover inputs not sent to the payment address or a fee
// for the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func SendToAddress(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendToAddressCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) || !isNilOrEmpty(cmd.CommentTo) {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCUnimplemented,
			Message: "Transaction comments are not yet supported",
		}
	}

	amt, err := dcrutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}

	// Check that signed integer parameters are positive.
	if amt < 0 {
		return nil, ErrNeedPositiveAmount
	}

	// Mock up map of address and amount pairs.
	pairs := map[string]dcrutil.Amount{
		cmd.Address: amt,
	}

	// sendtoaddress always spends from the default account, this matches bitcoind
	return sendPairs(w, chainSvr, pairs, waddrmgr.DefaultAccountNum, 1)
}

// SendToMultiSig handles a sendtomultisig RPC request by creating a new
// transaction spending amount many funds to an output containing a multi-
// signature script hash. The function will fail if there isn't at least one
// public key in the public key list that corresponds to one that is owned
// locally.
// Upon successfully sending the transaction to the daemon, the script hash
// is stored in the transaction manager and the corresponding address
// specified to be watched by the daemon.
// The function returns a tx hash, P2SH address, and a multisig script if
// successful.
// TODO Use with non-default accounts as well
func SendToMultiSig(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendToMultiSigCmd)
	account := uint32(waddrmgr.DefaultAccountNum)
	amount, err := dcrutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}
	nrequired := int8(*cmd.NRequired)
	minconf := int32(*cmd.MinConf)
	pubkeys := make([]*dcrutil.AddressSecpPubKey, len(cmd.Pubkeys))

	// The address list will made up either of addreseses (pubkey hash), for
	// which we need to look up the keys in wallet, straight pubkeys, or a
	// mixture of the two.
	for i, a := range cmd.Pubkeys {
		// Try to parse as pubkey address.
		a, err := decodeAddress(a, activeNet.Params)
		if err != nil {
			return nil, err
		}

		switch addr := a.(type) {
		case *dcrutil.AddressSecpPubKey:
			pubkeys[i] = addr
		case *dcrutil.AddressPubKeyHash:
			ainfo, err := w.Manager.Address(addr)
			if err != nil {
				return nil, err
			}

			apkinfo := ainfo.(waddrmgr.ManagedPubKeyAddress)

			// This will be an addresspubkey.
			a, err := decodeAddress(apkinfo.ExportPubKey(),
				activeNet.Params)
			if err != nil {
				return nil, err
			}

			apk := a.(*dcrutil.AddressSecpPubKey)
			pubkeys[i] = apk
		default:
			return nil, err
		}
	}

	ctx, addr, script, err :=
		w.CreateMultisigTx(account, amount, pubkeys, nrequired, minconf)
	if err != nil {
		return nil, fmt.Errorf("CreateMultisigTx error: %v", err.Error())
	}

	result := &dcrjson.SendToMultiSigResult{
		ctx.MsgTx.TxSha().String(),
		addr.EncodeAddress(),
		hex.EncodeToString(script),
	}

	err = chainSvr.NotifyReceived([]dcrutil.Address{addr})
	if err != nil {
		return nil, err
	}

	log.Infof("Successfully sent funds to multisignature output in "+
		"transaction %v", ctx.MsgTx.TxSha().String())

	return result, nil
}

// SendToSStx handles a sendtosstx RPC request by creating a new transaction
// payment addresses.  Leftover inputs not sent to the payment address
// or a fee for the miner are sent back to a new address in the wallet.
// Upon success, the TxID for the created transaction is returned.
// DECRED TODO: Clean these up
func SendToSStx(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendToSStxCmd)
	minconf := int32(*cmd.MinConf)

	account, err := w.Manager.LookupAccount(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that minconf is positive.
	if minconf < 0 {
		return nil, ErrNeedPositiveMinconf
	}

	// Recreate address/amount pairs, using dcrutil.Amount.
	pair := make(map[string]dcrutil.Amount, len(cmd.Amounts))
	for k, v := range cmd.Amounts {
		pair[k] = dcrutil.Amount(v)
	}
	// Get current block's height and hash.
	bs, err := chainSvr.BlockStamp()
	if err != nil {
		return nil, err
	}

	usedEligible := []wtxmgr.Credit{}
	eligible, err := w.FindEligibleOutputs(account, minconf, bs)
	if err != nil {
		return nil, err
	}
	// check to properly find utxos from eligible to help signMsgTx later on
	for _, input := range cmd.Inputs {
		for _, allEligible := range eligible {

			if allEligible.Hash.String() == input.Txid &&
				allEligible.Index == input.Vout &&
				allEligible.Tree == input.Tree {
				usedEligible = append(usedEligible, allEligible)
				break
			}
		}
	}
	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := w.CreateSStxTx(pair, usedEligible, cmd.Inputs,
		cmd.COuts, minconf)
	if err != nil {
		switch err {
		case wallet.ErrNonPositiveAmount:
			return nil, ErrNeedPositiveAmount
		default:
			return nil, err
		}
	}
	// TODO Why is this here? Can we remove it? cj
	/*
		var ok bool
		createdTx.msgtx, ok, err = chainSvr.SignRawTransaction(createdTx.msgtx)
		if err != nil {
			log.Errorf("Error signing tx: %v", err)
			return nil, err
		}
		if !ok {
			log.Errorf("Not all inputs have been signed for sstx")
			return nil, err
		}
	*/

	txSha, err := chainSvr.SendRawTransaction(createdTx.MsgTx, false)
	if err != nil {
		return nil, err
	}
	log.Infof("Successfully sent SStx purchase transaction %v", txSha)
	return txSha.String(), nil
}

// SendToSSGen handles a sendtossgen RPC request by creating a new transaction
// spending a stake ticket and generating stake rewards.
// Upon success, the TxID for the created transaction is returned.
// DECRED TODO: Clean these up
func SendToSSGen(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendToSSGenCmd)

	_, err := w.Manager.LookupAccount(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Get the tx hash for the ticket.
	ticketHash, err := chainhash.NewHashFromStr(cmd.TicketHash)
	if err != nil {
		return nil, err
	}

	// Get the block header hash that the SSGen tx votes on.
	blockHash, err := chainhash.NewHashFromStr(cmd.BlockHash)
	if err != nil {
		return nil, err
	}

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := w.CreateSSGenTx(*ticketHash, *blockHash,
		cmd.Height, cmd.VoteBits)
	if err != nil {
		switch err {
		case wallet.ErrNonPositiveAmount:
			return nil, ErrNeedPositiveAmount
		default:
			return nil, err
		}
	}

	txSha := createdTx.MsgTx.TxSha()

	log.Infof("Successfully sent transaction %v", txSha)
	return txSha.String(), nil
}

// SendToSSRtx handles a sendtossrtx RPC request by creating a new transaction
// spending a stake ticket and generating stake rewards.
// Upon success, the TxID for the created transaction is returned.
// DECRED TODO: Clean these up
func SendToSSRtx(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SendToSSRtxCmd)

	_, err := w.Manager.LookupAccount(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Get the tx hash for the ticket.
	ticketHash, err := chainhash.NewHashFromStr(cmd.TicketHash)
	if err != nil {
		return nil, err
	}

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := w.CreateSSRtx(*ticketHash)
	if err != nil {
		switch err {
		case wallet.ErrNonPositiveAmount:
			return nil, ErrNeedPositiveAmount
		default:
			return nil, err
		}
	}

	txSha, err := chainSvr.SendRawTransaction(createdTx.MsgTx, false)
	if err != nil {
		return nil, err
	}
	log.Infof("Successfully sent transaction %v", txSha)
	return txSha.String(), nil
}

// SetGenerate enables or disables stake mining the wallet (ticket
// autopurchase, vote generation, and revocation generation). The
// number of processors may be declared but is ignored (as this is
// non-PoW work).
func SetGenerate(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SetGenerateCmd)
	err := w.SetGenerate(cmd.Generate)

	return nil, err
}

// SetTicketMaxPrice sets the maximum price the user is willing to pay for a
// ticket.
func SetTicketMaxPrice(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SetTicketMaxPriceCmd)

	amt, err := dcrutil.NewAmount(cmd.Max)
	if err != nil {
		return nil, err
	}

	w.SetTicketMaxPrice(amt)
	return nil, nil
}

// SetTxFee sets the transaction fee per kilobyte added to transactions.
func SetTxFee(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SetTxFeeCmd)

	// Check that amount is not negative.
	if cmd.Amount < 0 {
		return nil, ErrNeedPositiveAmount
	}

	incr, err := dcrutil.NewAmount(cmd.Amount)
	if err != nil {
		return nil, err
	}
	w.FeeIncrement = incr

	// A boolean true result is returned upon success.
	return true, nil
}

// SignMessage signs the given message with the private key for the given
// address
func SignMessage(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SignMessageCmd)

	addr, err := decodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, err
	}

	ainfo, err := w.Manager.Address(addr)
	if err != nil {
		return nil, err
	}
	pka, ok := ainfo.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		msg := fmt.Sprintf("Address '%s' does not have an associated "+
			"private key", addr)
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	privKey, err := pka.PrivKey()
	if err != nil {
		return nil, err
	}

	fullmsg := "Decred Signed Message:\n" + cmd.Message
	r, s, err := chainec.Secp256k1.Sign(privKey, chainhash.HashFuncB([]byte(fullmsg)))
	if err != nil {
		return nil, err
	}
	sig := chainec.Secp256k1.NewSignature(r, s)

	return base64.StdEncoding.EncodeToString(sig.Serialize()), nil
}

// pendingTx is used for async fetching of transaction dependancies in
// SignRawTransaction.
type pendingTx struct {
	resp   dcrrpcclient.FutureGetRawTransactionResult
	inputs []uint32 // list of inputs that care about this tx.
}

// SignRawTransaction handles the signrawtransaction command.
func SignRawTransaction(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SignRawTransactionCmd)

	serializedTx, err := decodeHexStr(cmd.RawTx)
	if err != nil {
		return nil, err
	}
	msgTx := wire.NewMsgTx()
	err = msgTx.Deserialize(bytes.NewBuffer(serializedTx))
	if err != nil {
		e := errors.New("TX decode failed")
		return nil, DeserializationError{e}
	}

	for _, input := range msgTx.TxIn {
		if txscript.IsMultisigSigScript(input.SignatureScript) {
			rs, err :=
				txscript.MultisigRedeemScriptFromScriptSig(
					input.SignatureScript)
			if err != nil {
				return nil, err
			}

			class, addrs, _, err := txscript.ExtractPkScriptAddrs(
				txscript.DefaultScriptVersion, rs, activeNet.Params)
			if err != nil {
				// Non-standard outputs are skipped.
				continue
			}
			if class != txscript.MultiSigTy {
				// This should never happen, but be paranoid.
				continue
			}

			isRelevant := false
			for _, addr := range addrs {
				_, err := w.Manager.Address(addr)
				if err == nil {
					isRelevant = true
					err = w.Manager.MarkUsed(addr)
					if err != nil {
						return nil, err
					}
					log.Debugf("Marked address %v used", addr)
				} else {
					// Missing addresses are skipped.  Other errors should
					// be propagated.
					if !waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
						return nil, err
					}
				}
			}
			// Add the script to the script databases.
			if isRelevant {
				err = w.TxStore.InsertTxScript(rs)
				if err != nil {
					return nil, err
				}

				// Get current block's height and hash.
				bs, err := chainSvr.BlockStamp()
				if err != nil {
					return nil, err
				}
				mscriptaddr, err := w.Manager.ImportScript(rs, bs)
				if err != nil {
					switch {
					// Don't care if it's already there.
					case waddrmgr.IsError(err, waddrmgr.ErrDuplicateAddress):
						break
					case waddrmgr.IsError(err, waddrmgr.ErrLocked):
						log.Debugf("failed to attempt script importation " +
							"of incoming tx because addrmgr was locked")
						break
					default:
						return nil, err
					}
				} else {
					// This is the first time seeing this script address
					// belongs to us, so do a rescan and see if there are
					// any other outputs to this address.
					job := &wallet.RescanJob{
						Addrs:     []dcrutil.Address{mscriptaddr.Address()},
						OutPoints: nil,
						BlockStamp: waddrmgr.BlockStamp{
							0,
							*activeNet.Params.GenesisHash,
						},
					}

					// Submit rescan job and log when the import has completed.
					// Do not block on finishing the rescan.  The rescan success
					// or failure is logged elsewhere, and the channel is not
					// required to be read, so discard the return value.
					_ = w.SubmitRescan(job)
				}
			}
		}
	}

	// First we add the stuff we have been given.
	// TODO(oga) really we probably should look these up with dcrd anyway
	// to make sure that they match the blockchain if present.
	inputs := make(map[wire.OutPoint][]byte)
	scripts := make(map[string][]byte)
	var cmdInputs []dcrjson.RawTxInput
	if cmd.Inputs != nil {
		cmdInputs = *cmd.Inputs
	}
	for _, rti := range cmdInputs {
		inputSha, err := chainhash.NewHashFromStr(rti.Txid)
		if err != nil {
			return nil, DeserializationError{err}
		}

		txscript, err := decodeHexStr(rti.ScriptPubKey)
		if err != nil {
			return nil, err
		}

		// redeemScript is only actually used iff the user provided
		// private keys. In which case, it is used to get the scripts
		// for signing. If the user did not provide keys then we always
		// get scripts from the wallet.
		// Empty strings are ok for this one and hex.DecodeString will
		// DTRT.
		// Note that redeemScript is NOT only the redeemscript
		// required to be appended to the end of a P2SH output
		// spend, but the entire signature script for spending
		// *any* outpoint with dummy values inserted into it
		// that can later be replacing by txscript's sign.
		if cmd.PrivKeys != nil && len(*cmd.PrivKeys) != 0 {
			redeemScript, err := decodeHexStr(rti.RedeemScript)
			if err != nil {
				return nil, err
			}

			addr, err := dcrutil.NewAddressScriptHash(redeemScript,
				activeNet.Params)
			if err != nil {
				return nil, DeserializationError{err}
			}
			scripts[addr.String()] = redeemScript
		}
		inputs[wire.OutPoint{
			Hash:  *inputSha,
			Tree:  rti.Tree,
			Index: rti.Vout,
		}] = txscript
	}

	// Now we go and look for any inputs that we were not provided by
	// querying dcrd with getrawtransaction. We queue up a bunch of async
	// requests and will wait for replies after we have checked the rest of
	// the arguments.
	requested := make(map[chainhash.Hash]*pendingTx)
	for i, txIn := range msgTx.TxIn {
		// We don't need the first input of a stakebase tx, as it's garbage
		// anyway.
		if i == 0 && *cmd.Flags == "ssgen" {
			continue
		}

		// Did we get this txin from the arguments?
		if _, ok := inputs[txIn.PreviousOutPoint]; ok {
			continue
		}

		// Are we already fetching this tx? If so mark us as interested
		// in this outpoint. (N.B. that any *sane* tx will only
		// reference each outpoint once, since anything else is a double
		// spend. We don't check this ourselves to save having to scan
		// the array, it will fail later if so).
		if ptx, ok := requested[txIn.PreviousOutPoint.Hash]; ok {
			ptx.inputs = append(ptx.inputs,
				txIn.PreviousOutPoint.Index)
			continue
		}

		// Never heard of this one before, request it.
		prevHash := &txIn.PreviousOutPoint.Hash
		requested[txIn.PreviousOutPoint.Hash] = &pendingTx{
			resp:   chainSvr.GetRawTransactionAsync(prevHash),
			inputs: []uint32{txIn.PreviousOutPoint.Index},
		}
	}

	// Parse list of private keys, if present. If there are any keys here
	// they are the keys that we may use for signing. If empty we will
	// use any keys known to us already.
	var keys map[string]*dcrutil.WIF
	if cmd.PrivKeys != nil {
		keys = make(map[string]*dcrutil.WIF)

		for _, key := range *cmd.PrivKeys {
			wif, err := dcrutil.DecodeWIF(key)
			if err != nil {
				return nil, DeserializationError{err}
			}

			if !wif.IsForNet(activeNet.Params) {
				s := "key network doesn't match wallet's"
				return nil, DeserializationError{errors.New(s)}
			}

			var addr dcrutil.Address
			switch wif.DSA() {
			case chainec.ECTypeSecp256k1:
				addr, err = dcrutil.NewAddressSecpPubKey(wif.SerializePubKey(),
					activeNet.Params)
				if err != nil {
					return nil, DeserializationError{err}
				}
			case chainec.ECTypeEdwards:
				addr, err = dcrutil.NewAddressEdwardsPubKey(
					wif.SerializePubKey(),
					activeNet.Params)
				if err != nil {
					return nil, DeserializationError{err}
				}
			case chainec.ECTypeSecSchnorr:
				addr, err = dcrutil.NewAddressSecSchnorrPubKey(
					wif.SerializePubKey(),
					activeNet.Params)
				if err != nil {
					return nil, DeserializationError{err}
				}
			}
			keys[addr.EncodeAddress()] = wif
		}
	}

	var hashType txscript.SigHashType
	switch *cmd.Flags {
	case "ALL":
		hashType = txscript.SigHashAll
	case "NONE":
		hashType = txscript.SigHashNone
	case "SINGLE":
		hashType = txscript.SigHashSingle
	case "ALL|ANYONECANPAY":
		hashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	case "NONE|ANYONECANPAY":
		hashType = txscript.SigHashNone | txscript.SigHashAnyOneCanPay
	case "SINGLE|ANYONECANPAY":
		hashType = txscript.SigHashSingle | txscript.SigHashAnyOneCanPay
	case "ssgen": // Special case of SigHashAll
		hashType = txscript.SigHashAll
	case "ssrtx": // Special case of SigHashAll
		hashType = txscript.SigHashAll
	default:
		e := errors.New("Invalid sighash parameter")
		return nil, InvalidParameterError{e}
	}

	// We have checked the rest of the args. now we can collect the async
	// txs. TODO(oga) If we don't mind the possibility of wasting work we
	// could move waiting to the following loop and be slightly more
	// asynchronous.
	for txid, ptx := range requested {
		tx, err := ptx.resp.Receive()
		if err != nil {
			return nil, err
		}

		for _, input := range ptx.inputs {
			tree := dcrutil.TxTreeRegular
			txType := stake.DetermineTxType(tx)
			if txType != stake.TxTypeRegular {
				tree = dcrutil.TxTreeStake
			}

			if input >= uint32(len(tx.MsgTx().TxOut)) {
				e := fmt.Errorf("input %s:%d is not in tx",
					txid.String(), input)
				return nil, InvalidParameterError{e}
			}

			inputs[wire.OutPoint{
				Hash:  txid,
				Index: input,
				Tree:  tree,
			}] = tx.MsgTx().TxOut[input].PkScript
		}
	}

	// All args collected. Now we can sign all the inputs that we can.
	// `complete' denotes that we successfully signed all outputs and that
	// all scripts will run to completion. This is returned as part of the
	// reply.

	var signErrors []dcrjson.SignRawTransactionError
	for i, txIn := range msgTx.TxIn {
		// For an SSGen tx, skip the first input as it is a stake base
		// and doesn't need to be signed.
		if i == 0 && *cmd.Flags == "ssgen" {
			// Put some garbage in the signature script.
			txIn.SignatureScript = []byte{0xDE, 0xAD, 0xBE, 0xEF}
			continue
		}

		input, ok := inputs[txIn.PreviousOutPoint]
		if !ok {
			// failure to find previous is actually an error since
			// we failed above if we don't have all the inputs.
			return nil, fmt.Errorf("%s:%d,%v not found",
				txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index,
				txIn.PreviousOutPoint.Tree)
		}

		// Set up our callbacks that we pass to txscript so it can
		// look up the appropriate keys and scripts by address.
		getKey := txscript.KeyClosure(func(addr dcrutil.Address) (
			chainec.PrivateKey, bool, error) {
			if len(keys) != 0 {
				wif, ok := keys[addr.EncodeAddress()]
				if !ok {
					return nil, false,
						fmt.Errorf("no key for address (needed: %v, have %v)",
							addr.EncodeAddress(), keys)
				}
				return wif.PrivKey, true, nil
			}
			address, err := w.Manager.Address(addr)
			if err != nil {
				return nil, false, err
			}

			pka, ok := address.(waddrmgr.ManagedPubKeyAddress)
			if !ok {
				return nil, false, fmt.Errorf("address %v is not "+
					"a pubkey address", address.Address().EncodeAddress())
			}

			key, err := pka.PrivKey()
			if err != nil {
				return nil, false, err
			}

			return key, pka.Compressed(), nil
		})

		getScript := txscript.ScriptClosure(func(
			addr dcrutil.Address) ([]byte, error) {
			// If keys were provided then we can only use the
			// scripts provided with our inputs, too.
			if len(keys) != 0 {
				txscript, ok := scripts[addr.EncodeAddress()]
				if !ok {
					return nil, errors.New("no script for " +
						"address")
				}
				return txscript, nil
			}

			// First check tx manager script store.
			scrTxStore, err :=
				w.TxStore.GetTxScript(addr.ScriptAddress())
			if err != nil {
				return nil, err
			}
			if scrTxStore != nil {
				return scrTxStore, nil
			}

			// Then check the address manager.
			address, err := w.Manager.Address(addr)
			if err != nil {
				return nil, err
			}
			sa, ok := address.(waddrmgr.ManagedScriptAddress)
			if !ok {
				return nil, errors.New("address is not a script" +
					" address")
			}

			return sa.Script()
		})

		// SigHashSingle inputs can only be signed if there's a
		// corresponding output. However this could be already signed,
		// so we always verify the output.
		if (hashType&txscript.SigHashSingle) !=
			txscript.SigHashSingle || i < len(msgTx.TxOut) {
			// Check for alternative checksig scripts and
			// set the signature suite accordingly.
			ecType := chainec.ECTypeSecp256k1
			class := txscript.GetScriptClass(txscript.DefaultScriptVersion, input)
			if class == txscript.PubkeyAltTy ||
				class == txscript.PubkeyHashAltTy {
				var err error
				ecType, err = txscript.ExtractPkScriptAltSigType(input)
				if err != nil {
					return nil, errors.New("unknown checksigalt signature " +
						"suite specified")
				}
			}

			script, err := txscript.SignTxOutput(activeNet.Params,
				msgTx, i, input, hashType, getKey,
				getScript, txIn.SignatureScript,
				ecType)
			// Failure to sign isn't an error, it just means that
			// the tx isn't complete.
			if err != nil {
				signErrors = append(signErrors,
					dcrjson.SignRawTransactionError{
						TxID:      txIn.PreviousOutPoint.Hash.String(),
						Vout:      txIn.PreviousOutPoint.Index,
						ScriptSig: hex.EncodeToString(txIn.SignatureScript),
						Sequence:  txIn.Sequence,
						Error:     err.Error(),
					})
				continue
			}
			txIn.SignatureScript = script
		}

		// Either it was already signed or we just signed it.
		// Find out if it is completely satisfied or still needs more. Be sure
		// to skip the verify minimal data push check for outputs
		flags := txscript.StandardVerifyFlags
		vm, err := txscript.NewEngine(input, msgTx, i, flags,
			txscript.DefaultScriptVersion)
		if err == nil {
			err = vm.Execute()
		}
		if err != nil {
			multisigNotEnoughSigs := false
			class, addr, _, _ := txscript.ExtractPkScriptAddrs(
				txscript.DefaultScriptVersion,
				inputs[txIn.PreviousOutPoint],
				activeNet.Params)

			if err == txscript.ErrStackUnderflow &&
				class == txscript.ScriptHashTy {
				redeemScript, _ := getScript(addr[0])
				redeemClass := txscript.GetScriptClass(
					txscript.DefaultScriptVersion, redeemScript)
				if redeemClass == txscript.MultiSigTy {
					multisigNotEnoughSigs = true
				}
			}
			// Only report an error for the script engine in the event
			// that it's not a multisignature underflow, indicating that
			// we didn't have enough signatures in front of the
			// redeemScript rather than an actual error.
			if !multisigNotEnoughSigs {
				signErrors = append(signErrors,
					dcrjson.SignRawTransactionError{
						TxID:      txIn.PreviousOutPoint.Hash.String(),
						Vout:      txIn.PreviousOutPoint.Index,
						ScriptSig: hex.EncodeToString(txIn.SignatureScript),
						Sequence:  txIn.Sequence,
						Error:     err.Error(),
					})
			}
		}
	}

	var buf bytes.Buffer
	buf.Grow(msgTx.SerializeSize())

	// All returned errors (not OOM, which panics) encounted during
	// bytes.Buffer writes are unexpected.
	if err = msgTx.Serialize(&buf); err != nil {
		panic(err)
	}

	return dcrjson.SignRawTransactionResult{
		Hex:      hex.EncodeToString(buf.Bytes()),
		Complete: len(signErrors) == 0,
		Errors:   signErrors,
	}, nil
}

// SignRawTransactions handles the signrawtransactions command.
func SignRawTransactions(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.SignRawTransactionsCmd)

	// Sign each transaction sequentially and record the results.
	// Error out if we meet some unexpected failure.
	results := make([]dcrjson.SignRawTransactionResult,
		len(cmd.RawTxs), len(cmd.RawTxs))
	for i, etx := range cmd.RawTxs {
		flagAll := "ALL"
		srtc := &dcrjson.SignRawTransactionCmd{
			RawTx: etx,
			Flags: &flagAll,
		}
		result, err := SignRawTransaction(w, chainSvr, srtc)
		if err != nil {
			return nil, err
		}

		tResult := result.(dcrjson.SignRawTransactionResult)
		results[i] = tResult
	}

	// If the user wants completed transactions to be automatically send,
	// do that now. Otherwise, construct the slice and return it.
	toReturn := make([]dcrjson.SignedTransaction,
		len(cmd.RawTxs), len(cmd.RawTxs))

	if *cmd.Send {
		for i, result := range results {
			if result.Complete {
				// Slow/mem hungry because of the deserializing.
				serializedTx, err := decodeHexStr(result.Hex)
				if err != nil {
					return nil, err
				}
				msgTx := wire.NewMsgTx()
				err = msgTx.Deserialize(bytes.NewBuffer(serializedTx))
				if err != nil {
					e := errors.New("TX decode failed")
					return nil, DeserializationError{e}
				}
				sent := false
				hashStr := ""
				hash, err := chainSvr.SendRawTransaction(msgTx, false)
				// If sendrawtransaction errors out (blockchain rule
				// issue, etc), continue onto the next transaction.
				if err == nil {
					sent = true
					hashStr = hash.String()
				}

				st := dcrjson.SignedTransaction{
					result,
					sent,
					&hashStr,
				}
				toReturn[i] = st
			} else {
				st := dcrjson.SignedTransaction{
					result,
					false,
					nil,
				}
				toReturn[i] = st
			}
		}
	} else { // Just return the results.
		for i, result := range results {
			st := dcrjson.SignedTransaction{
				result,
				false,
				nil,
			}
			toReturn[i] = st
		}
	}

	return &dcrjson.SignRawTransactionsResult{toReturn}, nil
}

// ValidateAddress handles the validateaddress command.
func ValidateAddress(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.ValidateAddressCmd)

	result := dcrjson.ValidateAddressWalletResult{}
	addr, err := decodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		// Use result zero value (IsValid=false).
		return result, nil
	}

	// We could put whether or not the address is a script here,
	// by checking the type of "addr", however, the reference
	// implementation only puts that information if the script is
	// "ismine", and we follow that behaviour.
	result.Address = addr.EncodeAddress()
	result.IsValid = true

	ainfo, err := w.Manager.Address(addr)
	if err != nil {
		if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
			// No additional information available about the address.
			return result, nil
		}
		return nil, err
	}

	// The address lookup was successful which means there is further
	// information about it available and it is "mine".
	result.IsMine = true
	acctName, err := w.Manager.AccountName(ainfo.Account())
	if err != nil {
		return nil, &ErrAccountNameNotFound
	}
	result.Account = acctName

	switch ma := ainfo.(type) {
	case waddrmgr.ManagedPubKeyAddress:
		result.IsCompressed = ma.Compressed()
		result.PubKey = ma.ExportPubKey()
		pubKeyBytes, err := hex.DecodeString(result.PubKey)
		if err != nil {
			return nil, err
		}
		pubKeyAddr, err := dcrutil.NewAddressSecpPubKey(pubKeyBytes,
			w.ChainParams())
		if err != nil {
			return nil, err
		}
		result.PubKeyAddr = pubKeyAddr.String()

	case waddrmgr.ManagedScriptAddress:
		result.IsScript = true

		// The script is only available if the manager is unlocked, so
		// just break out now if there is an error.
		script, err := ma.Script()
		if err != nil {
			break
		}
		result.Hex = hex.EncodeToString(script)

		// This typically shouldn't fail unless an invalid script was
		// imported.  However, if it fails for any reason, there is no
		// further information available, so just set the script type
		// a non-standard and break out now.
		class, addrs, reqSigs, err := txscript.ExtractPkScriptAddrs(
			txscript.DefaultScriptVersion, script, activeNet.Params)
		if err != nil {
			result.Script = txscript.NonStandardTy.String()
			break
		}

		addrStrings := make([]string, len(addrs))
		for i, a := range addrs {
			addrStrings[i] = a.EncodeAddress()
		}
		result.Addresses = addrStrings

		// Multi-signature scripts also provide the number of required
		// signatures.
		result.Script = class.String()
		if class == txscript.MultiSigTy {
			result.SigsRequired = int32(reqSigs)
		}
	}

	return result, nil
}

// VerifyMessage handles the verifymessage command by verifying the provided
// compact signature for the given address and message.
func VerifyMessage(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.VerifyMessageCmd)

	addr, err := decodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, err
	}

	// decode base64 signature
	sig, err := base64.StdEncoding.DecodeString(cmd.Signature)
	if err != nil {
		return nil, err
	}

	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	pk, wasCompressed, err := chainec.Secp256k1.RecoverCompact(sig,
		chainhash.HashFuncB([]byte("Decred Signed Message:\n"+
			cmd.Message)))
	if err != nil {
		return nil, err
	}

	// Decred: This should actually be a universalized constructor.
	pkDcr := chainec.Secp256k1.NewPublicKey(pk.GetX(), pk.GetY())

	var serializedPubKey []byte
	if wasCompressed {
		serializedPubKey = pkDcr.SerializeCompressed()
	} else {
		serializedPubKey = pkDcr.SerializeUncompressed()
	}
	// Verify that the signed-by address matches the given address
	switch checkAddr := addr.(type) {
	case *dcrutil.AddressPubKeyHash: // ok
		return bytes.Equal(dcrutil.Hash160(serializedPubKey),
			checkAddr.Hash160()[:]), nil
	case *dcrutil.AddressSecpPubKey: // ok
		return string(serializedPubKey) == checkAddr.String(), nil
	default:
		return nil, errors.New("address type not supported")
	}
}

// WalletIsLocked handles the walletislocked extension request by
// returning the current lock state (false for unlocked, true for locked)
// of an account.
func WalletIsLocked(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	return w.Locked(), nil
}

// WalletLock handles a walletlock request by locking the all account
// wallets, returning an error if any wallet is not encrypted (for example,
// a watching-only wallet).
func WalletLock(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	w.Lock()
	return nil, nil
}

// WalletPassphrase responds to the walletpassphrase request by unlocking
// the wallet.  The decryption key is saved in the wallet until timeout
// seconds expires, after which the wallet is locked.
func WalletPassphrase(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.WalletPassphraseCmd)

	timeout := time.Second * time.Duration(cmd.Timeout)
	err := w.Unlock([]byte(cmd.Passphrase), timeout)

	if err == nil {
		if timeout > 0 {
			log.Infof("The wallet has been unlocked. This is set to expire  "+
				"in %v.", timeout)
		} else {
			log.Infof("The wallet has been unlocked without a time limit.")
		}
	}

	return nil, err
}

// WalletPassphraseChange responds to the walletpassphrasechange request
// by unlocking all accounts with the provided old passphrase, and
// re-encrypting each private key with an AES key derived from the new
// passphrase.
//
// If the old passphrase is correct and the passphrase is changed, all
// wallets will be immediately locked.
func WalletPassphraseChange(w *wallet.Wallet, chainSvr *chain.Client,
	icmd interface{}) (interface{}, error) {
	cmd := icmd.(*dcrjson.WalletPassphraseChangeCmd)

	err := w.ChangePassphrase([]byte(cmd.OldPassphrase),
		[]byte(cmd.NewPassphrase))
	if waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase) {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCWalletPassphraseIncorrect,
			Message: "Incorrect passphrase",
		}
	}
	return nil, err
}

// decodeHexStr decodes the hex encoding of a string, possibly prepending a
// leading '0' character if there is an odd number of bytes in the hex string.
// This is to prevent an error for an invalid hex string when using an odd
// number of bytes when calling hex.Decode.
func decodeHexStr(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, &dcrjson.RPCError{
			Code:    dcrjson.ErrRPCDecodeHexString,
			Message: "Hex string decode failed: " + err.Error(),
		}
	}
	return decoded, nil
}
