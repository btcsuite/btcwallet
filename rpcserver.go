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

	"github.com/conformal/btcec"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcrpcclient"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/chain"
	"github.com/conformal/btcwallet/txstore"
	"github.com/conformal/btcwallet/waddrmgr"
	"github.com/conformal/btcwire"
	"github.com/conformal/btcws"
	"github.com/conformal/websocket"
)

// Error types to simplify the reporting of specific categories of
// errors, and their btcjson.Error creation.
type (
	// DeserializationError describes a failed deserializaion due to bad
	// user input.  It cooresponds to btcjson.ErrDeserialization.
	DeserializationError struct {
		error
	}

	// InvalidParameterError describes an invalid parameter passed by
	// the user.  It cooresponds to btcjson.ErrInvalidParameter.
	InvalidParameterError struct {
		error
	}

	// ParseError describes a failed parse due to bad user input.  It
	// cooresponds to btcjson.ErrParse.
	ParseError struct {
		error
	}

	// InvalidAddressOrKeyError describes a parse, network mismatch, or
	// missing address error when decoding or validating an address or
	// key.  It cooresponds to btcjson.ErrInvalidAddressOrKey.
	InvalidAddressOrKeyError struct {
		error
	}
)

// Errors variables that are defined once here to avoid duplication below.
var (
	ErrNeedPositiveAmount = InvalidParameterError{
		errors.New("amount must be positive"),
	}

	ErrNeedPositiveMinconf = InvalidParameterError{
		errors.New("minconf must be positive"),
	}

	ErrAddressNotInWallet = InvalidAddressOrKeyError{
		errors.New("address not found in wallet"),
	}

	ErrNoAccountSupport = btcjson.Error{
		Code:    btcjson.ErrWalletInvalidAccountName.Code,
		Message: "btcwallet does not support non-default accounts",
	}

	ErrUnloadedWallet = btcjson.Error{
		Code:    btcjson.ErrWallet.Code,
		Message: "Request requires a wallet but wallet has not loaded yet",
	}

	ErrNeedsChainSvr = btcjson.Error{
		Code:    btcjson.ErrWallet.Code,
		Message: "Request requires chain connected chain server",
	}
)

// TODO(jrick): There are several error paths which 'replace' various errors
// with a more appropiate error from the btcjson package.  Create a map of
// these replacements so they can be handled once after an RPC handler has
// returned and before the error is marshaled.

// checkAccountName verifies that the passed account name is for the default
// account or '*' to represent all accounts.  This is necessary to return
// errors to RPC clients for invalid account names, as account support is
// currently missing from btcwallet.
func checkAccountName(account string) error {
	if account != "" && account != "*" {
		return ErrNoAccountSupport
	}
	return nil
}

// checkDefaultAccount verifies that the passed account name is the default
// account.  This is necessary to return errors to RPC clients for invalid
// account names, as account support is currently missing from btcwallet.
func checkDefaultAccount(account string) error {
	if account != "" {
		return ErrNoAccountSupport
	}
	return nil
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

func newWebsocketClient(c *websocket.Conn, authenticated bool, remoteAddr string) *websocketClient {
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

// isManagerLockedError returns whether or not the passed error is due to the
// address manager being locked.
func isManagerLockedError(err error) bool {
	merr, ok := err.(waddrmgr.ManagerError)
	return ok && merr.ErrorCode == waddrmgr.ErrLocked
}

// isManagerWrongPassphraseError returns whether or not the passed error is due
// to the address manager being provided with an invalid passprhase.
func isManagerWrongPassphraseError(err error) bool {
	merr, ok := err.(waddrmgr.ManagerError)
	return ok && merr.ErrorCode == waddrmgr.ErrWrongPassphrase
}

// isManagerDuplicateError returns whether or not the passed error is due to a
// duplicate item being provided to the address manager.
func isManagerDuplicateError(err error) bool {
	merr, ok := err.(waddrmgr.ManagerError)
	if !ok {
		return false
	}

	return merr.ErrorCode == waddrmgr.ErrDuplicate
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
	org := "btcwallet autogenerated cert"
	validUntil := time.Now().Add(time.Hour * 24 * 365 * 10)
	cert, key, err := btcutil.NewTLSCertPair(org, validUntil, nil)
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
	wallet        *Wallet
	chainSvr      *chain.Client
	createOK      bool
	handlerLookup func(string) (requestHandler, bool)
	handlerLock   sync.Locker

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
	connectedBlocks       <-chan waddrmgr.BlockStamp
	disconnectedBlocks    <-chan waddrmgr.BlockStamp
	newCredits            <-chan txstore.Credit
	newDebits             <-chan txstore.Debits
	minedCredits          <-chan txstore.Credit
	minedDebits           <-chan txstore.Debits
	managerLocked         <-chan bool
	confirmedBalance      <-chan btcutil.Amount
	unconfirmedBalance    <-chan btcutil.Amount
	chainServerConnected  <-chan bool
	registerWalletNtfns   chan struct{}
	registerChainSvrNtfns chan struct{}

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
func newRPCServer(listenAddrs []string, maxPost, maxWebsockets int64) (*rpcServer, error) {
	login := cfg.Username + ":" + cfg.Password
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
	s := rpcServer{
		handlerLookup:       unloadedWalletHandlerFunc,
		handlerLock:         new(sync.Mutex),
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
		registerChainSvrNtfns:   make(chan struct{}),
		enqueueNotification:     make(chan wsClientNotification),
		dequeueNotification:     make(chan wsClientNotification),
		notificationHandlerQuit: make(chan struct{}),
		quit: make(chan struct{}),
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
		return nil, errors.New("no valid listen address")
	}

	s.listeners = listeners

	return &s, nil
}

// Start starts a HTTP server to provide standard RPC and extension
// websocket connections for any number of btcwallet clients.
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
				http.Error(w, "401 Unauthorized.", http.StatusUnauthorized)
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
				http.Error(w, "401 Unauthorized.", http.StatusUnauthorized)
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

	// Stop the connected wallet and chain server, if any.
	s.handlerLock.Lock()
	if s.wallet != nil {
		s.wallet.Stop()
	}
	if s.chainSvr != nil {
		s.chainSvr.Stop()
	}
	s.handlerLock.Unlock()

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
	s.handlerLock.Lock()
	if s.wallet != nil {
		s.wallet.WaitForShutdown()
	}
	if s.chainSvr != nil {
		s.chainSvr.WaitForShutdown()
	}
	s.handlerLock.Unlock()

	s.wg.Wait()
}

type noopLocker struct{}

func (noopLocker) Lock()   {}
func (noopLocker) Unlock() {}

// SetWallet sets the wallet dependency component needed to run a fully
// functional bitcoin wallet RPC server.  If wallet is nil, this informs the
// server that the createencryptedwallet RPC method is valid and must be called
// by a client before any other wallet methods are allowed.
func (s *rpcServer) SetWallet(wallet *Wallet) {
	s.handlerLock.Lock()
	defer s.handlerLock.Unlock()

	if wallet == nil {
		s.handlerLookup = missingWalletHandlerFunc
		s.createOK = true
		return
	}

	s.wallet = wallet
	s.registerWalletNtfns <- struct{}{}

	if s.chainSvr != nil {
		// If the chain server rpc client is also set, there's no reason
		// to keep the mutex around.  Make the locker simply execute
		// noops instead.
		s.handlerLock = noopLocker{}

		// With both the wallet and chain server set, all handlers are
		// ok to run.
		s.handlerLookup = lookupAnyHandler

		// Make sure already connected websocket clients get a notification
		// if the chain RPC client connection is set and connected.
		s.chainSvr.NotifyConnected()
	}
}

// SetChainServer sets the chain server client component needed to run a fully
// functional bitcoin wallet RPC server.  This should be set even before the
// client is connected, as any request handlers should return the error for
// a never connected client, rather than panicking (or never being looked up)
// if the client was never conneceted and added.
func (s *rpcServer) SetChainServer(chainSvr *chain.Client) {
	s.handlerLock.Lock()
	defer s.handlerLock.Unlock()

	s.chainSvr = chainSvr
	s.registerChainSvrNtfns <- struct{}{}

	if s.wallet != nil {
		// If the wallet had already been set, there's no reason to keep
		// the mutex around.  Make the locker simply execute noops
		// instead.
		s.handlerLock = noopLocker{}

		// With both the chain server and wallet set, all handlers are
		// ok to run.
		s.handlerLookup = lookupAnyHandler
	}
}

// HandlerClosure creates a closure function for handling requests of the given
// method.  This may be a request that is handled directly by btcwallet, or
// a chain server request that is handled by passing the request down to btcd.
//
// NOTE: These handlers do not handle special cases, such as the authenticate
// method.  Each of these must be checked beforehand (the method is already
// known) and handled accordingly.
func (s *rpcServer) HandlerClosure(method string) requestHandlerClosure {
	s.handlerLock.Lock()
	defer s.handlerLock.Unlock()

	// With the lock held, make copies of these pointers for the closure.
	wallet := s.wallet
	chainSvr := s.chainSvr

	if handler, ok := s.handlerLookup(method); ok {
		return func(request []byte, raw *rawRequest) btcjson.Reply {
			cmd, err := btcjson.ParseMarshaledCmd(request)
			if err != nil {
				return makeResponse(raw.ID, nil,
					btcjson.ErrInvalidRequest)
			}

			result, err := handler(wallet, chainSvr, cmd)
			return makeResponse(raw.ID, result, err)
		}
	}

	return func(request []byte, raw *rawRequest) btcjson.Reply {
		if chainSvr == nil {
			err := btcjson.Error{
				Code:    -1,
				Message: "Chain server is disconnected",
			}
			return makeResponse(raw.ID, nil, err)
		}

		res, err := chainSvr.RawRequest(raw.Method, raw.Params)

		// The raw result will only marshal correctly if called with the
		// MarshalJSON method, and that method requires a pointer receiver.
		return makeResponse(raw.ID, &res, err)
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
			log.Warnf("Reached threshold of %d concurrent active clients", threshold)
			http.Error(w, "429 Too Many Requests", 429)
			return
		}

		h.ServeHTTP(w, r)
	})
}

type rawRequest struct {
	// "jsonrpc" value isn't checked so we exclude it.
	ID     interface{}       `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

// String returns a sanitized string for the request which may be safely
// logged.  It is intended to strip private keys, passphrases, and any other
// secrets from request parameters before they may be saved to a log file.
//
// This intentionally implements the fmt.Stringer interface to prevent
// accidental leaking of secrets.
func (r *rawRequest) String() string {
	// These are considered unsafe to log, so sanitize parameters.
	switch r.Method {
	case "encryptwallet", "importprivkey", "importwallet",
		"signrawtransaction", "walletpassphrase",
		"walletpassphrasechange":

		return fmt.Sprintf(`{"id":%v,"method":"%s","params":SANITIZED %d parameters}`,
			r.ID, r.Method, len(r.Params))
	}

	return fmt.Sprintf(`{"id":%v,"method":"%s","params":%v}`, r.ID,
		r.Method, r.Params)
}

// idPointer returns a pointer to the passed ID, or nil if the interface is nil.
// Interface pointers are usually a red flag of doing something incorrectly,
// but this is only implemented here to work around an oddity with btcjson,
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
func (s *rpcServer) invalidAuth(request []byte) bool {
	cmd, err := btcjson.ParseMarshaledCmd(request)
	if err != nil {
		return false
	}
	authCmd, ok := cmd.(*btcws.AuthenticateCmd)
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
		case request, ok := <-wsc.allRequests:
			if !ok {
				// client disconnected
				break out
			}

			var raw rawRequest
			if err := json.Unmarshal(request, &raw); err != nil {
				if !wsc.authenticated {
					// Disconnect immediately.
					break out
				}
				resp := makeResponse(raw.ID, nil,
					btcjson.ErrInvalidRequest)
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

			if raw.Method == "authenticate" {
				if wsc.authenticated || s.invalidAuth(request) {
					// Disconnect immediately.
					break out
				}
				wsc.authenticated = true
				resp := makeResponse(raw.ID, nil, nil)
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

			switch raw.Method {
			case "stop":
				s.Stop()
				resp := makeResponse(raw.ID,
					"btcwallet stopping.", nil)
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
				f := s.HandlerClosure(raw.Method)
				wsc.wg.Add(1)
				go func(request []byte, raw *rawRequest) {
					resp := f(request, raw)
					mresp, err := json.Marshal(resp)
					if err != nil {
						// Completely unexpected error, but have seen
						// it happen regardless.  Log the sanitized
						// request and begin clean shutdown, panicing
						// if shutdown takes too long.
						log.Criticalf("Unexpected error marshaling "+
							"response for request '%s': %v",
							raw, err)
						wsc.wg.Done()

						s.Stop()
						go func() {
							time.Sleep(30 * time.Second)
							panic("shutdown took too long")
						}()

						return
					}
					_ = wsc.send(mresp)

					wsc.wg.Done()
				}(request, &raw)
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

	// TODO(jrick): this is crappy. kill it.
	s.handlerLock.Lock()
	if s.chainSvr != nil {
		s.chainSvr.NotifyConnected()
	}
	s.handlerLock.Unlock()

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
	var raw rawRequest
	err = json.Unmarshal(rpcRequest, &raw)
	if err != nil {
		resp := makeResponse(raw.ID, nil, btcjson.ErrInvalidRequest)
		mresp, err := json.Marshal(resp)
		// We expect the marshal to succeed.  If it doesn't, it
		// indicates some non-marshalable type in the response.
		if err != nil {
			panic(err)
		}
		_, err = w.Write(mresp)
		if err != nil {
			log.Warnf("Cannot write invalid request request to "+
				"client: %v", err)
		}
		return
	}

	// Create the response and error from the request.  Three special cases
	// are handled for the authenticate and stop request methods.
	var resp btcjson.Reply
	switch raw.Method {
	case "authenticate":
		// Drop it.
		return
	case "stop":
		s.Stop()
		resp = makeResponse(raw.ID, "btcwallet stopping.", nil)
	default:
		resp = s.HandlerClosure(raw.Method)(rpcRequest, &raw)
	}

	// Marshal and send.
	mresp, err := json.Marshal(resp)
	// All responses originating from us must be marshalable.
	if err != nil {
		panic(err)
	}
	// Send marshaled response to client.
	if _, err := w.Write(mresp); err != nil {
		log.Warnf("Unable to respond to client: %v", err)
	}
}

// Notification messages for websocket clients.
type (
	wsClientNotification interface {
		// This returns a slice only because some of these types result
		// in multpile client notifications.
		notificationCmds(w *Wallet) []btcjson.Cmd
	}

	blockConnected    waddrmgr.BlockStamp
	blockDisconnected waddrmgr.BlockStamp

	txCredit txstore.Credit
	txDebit  txstore.Debits

	managerLocked bool

	confirmedBalance   btcutil.Amount
	unconfirmedBalance btcutil.Amount

	btcdConnected bool
)

func (b blockConnected) notificationCmds(w *Wallet) []btcjson.Cmd {
	n := btcws.NewBlockConnectedNtfn(b.Hash.String(), b.Height)
	return []btcjson.Cmd{n}
}

func (b blockDisconnected) notificationCmds(w *Wallet) []btcjson.Cmd {
	n := btcws.NewBlockDisconnectedNtfn(b.Hash.String(), b.Height)
	return []btcjson.Cmd{n}
}

func (c txCredit) notificationCmds(w *Wallet) []btcjson.Cmd {
	bs, err := w.chainSvr.BlockStamp()
	if err != nil {
		log.Warnf("Dropping tx credit notification due to unknown "+
			"chain height: %v", err)
		return nil
	}
	ltr, err := txstore.Credit(c).ToJSON("", bs.Height, activeNet.Params)
	if err != nil {
		log.Errorf("Cannot create notification for transaction "+
			"credit: %v", err)
		return nil
	}
	n := btcws.NewTxNtfn("", &ltr)
	return []btcjson.Cmd{n}
}

func (d txDebit) notificationCmds(w *Wallet) []btcjson.Cmd {
	bs, err := w.chainSvr.BlockStamp()
	if err != nil {
		log.Warnf("Dropping tx debit notification due to unknown "+
			"chain height: %v", err)
		return nil
	}
	ltrs, err := txstore.Debits(d).ToJSON("", bs.Height, activeNet.Params)
	if err != nil {
		log.Errorf("Cannot create notification for transaction "+
			"debits: %v", err)
		return nil
	}
	ns := make([]btcjson.Cmd, len(ltrs))
	for i := range ns {
		ns[i] = btcws.NewTxNtfn("", &ltrs[i])
	}
	return ns
}

func (l managerLocked) notificationCmds(w *Wallet) []btcjson.Cmd {
	n := btcws.NewWalletLockStateNtfn("", bool(l))
	return []btcjson.Cmd{n}
}

func (b confirmedBalance) notificationCmds(w *Wallet) []btcjson.Cmd {
	n := btcws.NewAccountBalanceNtfn("",
		btcutil.Amount(b).ToUnit(btcutil.AmountBTC), true)
	return []btcjson.Cmd{n}
}

func (b unconfirmedBalance) notificationCmds(w *Wallet) []btcjson.Cmd {
	n := btcws.NewAccountBalanceNtfn("",
		btcutil.Amount(b).ToUnit(btcutil.AmountBTC), false)
	return []btcjson.Cmd{n}
}

func (b btcdConnected) notificationCmds(w *Wallet) []btcjson.Cmd {
	n := btcws.NewBtcdConnectedNtfn(bool(b))
	return []btcjson.Cmd{n}
}

func (s *rpcServer) notificationListener() {
out:
	for {
		select {
		case n := <-s.connectedBlocks:
			s.enqueueNotification <- blockConnected(n)
		case n := <-s.disconnectedBlocks:
			s.enqueueNotification <- blockDisconnected(n)
		case n := <-s.newCredits:
			s.enqueueNotification <- txCredit(n)
		case n := <-s.newDebits:
			s.enqueueNotification <- txDebit(n)
		case n := <-s.minedCredits:
			s.enqueueNotification <- txCredit(n)
		case n := <-s.minedDebits:
			s.enqueueNotification <- txDebit(n)
		case n := <-s.managerLocked:
			s.enqueueNotification <- managerLocked(n)
		case n := <-s.confirmedBalance:
			s.enqueueNotification <- confirmedBalance(n)
		case n := <-s.unconfirmedBalance:
			s.enqueueNotification <- unconfirmedBalance(n)
		case n := <-s.chainServerConnected:
			s.enqueueNotification <- btcdConnected(n)

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
			newCredits, err := s.wallet.TxStore.ListenNewCredits()
			if err != nil {
				log.Errorf("Could not register for new "+
					"credit notifications: %v", err)
				continue
			}
			newDebits, err := s.wallet.TxStore.ListenNewDebits()
			if err != nil {
				log.Errorf("Could not register for new "+
					"debit notifications: %v", err)
				continue
			}
			minedCredits, err := s.wallet.TxStore.ListenMinedCredits()
			if err != nil {
				log.Errorf("Could not register for mined "+
					"credit notifications: %v", err)
				continue
			}
			minedDebits, err := s.wallet.TxStore.ListenMinedDebits()
			if err != nil {
				log.Errorf("Could not register for mined "+
					"debit notifications: %v", err)
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
			s.newCredits = newCredits
			s.newDebits = newDebits
			s.minedCredits = minedCredits
			s.minedDebits = minedDebits
			s.managerLocked = managerLocked
			s.confirmedBalance = confirmedBalance
			s.unconfirmedBalance = unconfirmedBalance

		case <-s.registerChainSvrNtfns:
			chainServerConnected, err := s.chainSvr.ListenConnected()
			if err != nil {
				log.Errorf("Could not register for chain server "+
					"connection changes: %v", err)
				continue
			}
			s.chainServerConnected = chainServerConnected

			// Make sure already connected websocket clients get a
			// notification for the current client connection state.
			//
			// TODO(jrick): I am appalled by doing this but trying
			// not to change how notifications work for the moment.
			// A revamped notification API without this horror will
			// be implemented soon.
			go s.chainSvr.NotifyConnected()

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
		case <-s.newCredits:
		case <-s.newDebits:
		case <-s.minedCredits:
		case <-s.minedDebits:
		case <-s.confirmedBalance:
		case <-s.unconfirmedBalance:
		case <-s.chainServerConnected:
		case <-s.registerWalletNtfns:
		case <-s.registerChainSvrNtfns:
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
				mn, err := n.MarshalJSON()
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
// request into a marshalable response.  If the error is a btcjson.Error
// or any of the above special error classes, the server will respond with
// the JSON-RPC appropiate error code.  All other errors use the wallet
// catch-all error code, btcjson.ErrWallet.Code.
type requestHandler func(*Wallet, *chain.Client, btcjson.Cmd) (interface{}, error)

var rpcHandlers = map[string]requestHandler{
	// Reference implementation wallet methods (implemented)
	"addmultisigaddress":     AddMultiSigAddress,
	"createmultisig":         CreateMultiSig,
	"dumpprivkey":            DumpPrivKey,
	"getaccount":             GetAccount,
	"getaccountaddress":      GetAccountAddress,
	"getaddressesbyaccount":  GetAddressesByAccount,
	"getbalance":             GetBalance,
	"getinfo":                GetInfo,
	"getnewaddress":          GetNewAddress,
	"getrawchangeaddress":    GetRawChangeAddress,
	"getreceivedbyaccount":   GetReceivedByAccount,
	"getreceivedbyaddress":   GetReceivedByAddress,
	"gettransaction":         GetTransaction,
	"importprivkey":          ImportPrivKey,
	"keypoolrefill":          KeypoolRefill,
	"listaccounts":           ListAccounts,
	"listlockunspent":        ListLockUnspent,
	"listreceivedbyaccount":  ListReceivedByAccount,
	"listreceivedbyaddress":  ListReceivedByAddress,
	"listsinceblock":         ListSinceBlock,
	"listtransactions":       ListTransactions,
	"listunspent":            ListUnspent,
	"lockunspent":            LockUnspent,
	"sendfrom":               SendFrom,
	"sendmany":               SendMany,
	"sendtoaddress":          SendToAddress,
	"settxfee":               SetTxFee,
	"signmessage":            SignMessage,
	"signrawtransaction":     SignRawTransaction,
	"validateaddress":        ValidateAddress,
	"verifymessage":          VerifyMessage,
	"walletlock":             WalletLock,
	"walletpassphrase":       WalletPassphrase,
	"walletpassphrasechange": WalletPassphraseChange,

	// Reference implementation methods (still unimplemented)
	"backupwallet":         Unimplemented,
	"dumpwallet":           Unimplemented,
	"getwalletinfo":        Unimplemented,
	"importwallet":         Unimplemented,
	"listaddressgroupings": Unimplemented,

	// Reference methods which can't be implemented by btcwallet due to
	// design decision differences
	"encryptwallet": Unsupported,
	"move":          Unsupported,
	"setaccount":    Unsupported,

	// Extensions to the reference client JSON-RPC API
	"exportwatchingwallet": ExportWatchingWallet,
	// This was an extension but the reference implementation added it as
	// well, but with a different API (no account parameter).  It's listed
	// here because it hasn't been update to use the reference
	// implemenation's API.
	"getunconfirmedbalance":   GetUnconfirmedBalance,
	"listaddresstransactions": ListAddressTransactions,
	"listalltransactions":     ListAllTransactions,
	"walletislocked":          WalletIsLocked,
}

// Unimplemented handles an unimplemented RPC request with the
// appropiate error.
func Unimplemented(*Wallet, *chain.Client, btcjson.Cmd) (interface{}, error) {
	return nil, btcjson.ErrUnimplemented
}

// Unsupported handles a standard bitcoind RPC request which is
// unsupported by btcwallet due to design differences.
func Unsupported(*Wallet, *chain.Client, btcjson.Cmd) (interface{}, error) {
	return nil, btcjson.Error{
		Code:    -1,
		Message: "Request unsupported by btcwallet",
	}
}

// UnloadedWallet is the handler func that is run when a wallet has not been
// loaded yet when trying to execute a wallet RPC.
func UnloadedWallet(*Wallet, *chain.Client, btcjson.Cmd) (interface{}, error) {
	return nil, ErrUnloadedWallet
}

// NoEncryptedWallet is the handler func that is run when no wallet has been
// created by the user yet.
// loaded yet when trying to execute a wallet RPC.
func NoEncryptedWallet(*Wallet, *chain.Client, btcjson.Cmd) (interface{}, error) {
	return nil, btcjson.Error{
		Code: btcjson.ErrWallet.Code,
		Message: "Request requires a wallet but no wallet has been " +
			"created -- use createencryptedwallet to recover",
	}
}

// TODO(jrick): may be a good idea to add handlers for passthrough to the chain
// server.  If a handler can not be looked up in one of the above maps, use this
// passthrough handler instead.  This isn't done at the moment since all
// requests are executed serialized, and blocking all requests, and even just
// requests from the same client, on the result of a btcd RPC can result is too
// much waiting for the round trip.

// lookupAnyHandler looks up a request handler func for the passed method from
// the http post and (if the request is from a websocket connection) websocket
// handler maps.  If a suitable handler could not be found, ok is false.
func lookupAnyHandler(method string) (f requestHandler, ok bool) {
	f, ok = rpcHandlers[method]
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
type requestHandlerClosure func([]byte, *rawRequest) btcjson.Reply

// makeResponse makes the JSON-RPC response struct for the result and error
// returned by a requestHandler.  The returned response is not ready for
// marshaling and sending off to a client, but must be
func makeResponse(id, result interface{}, err error) btcjson.Reply {
	idPtr := idPointer(id)
	if err != nil {
		return btcjson.Reply{
			Id:    idPtr,
			Error: jsonError(err),
		}
	}
	return btcjson.Reply{
		Id:     idPtr,
		Result: result,
	}
}

// jsonError creates a JSON-RPC error from the Go error.
func jsonError(err error) *btcjson.Error {
	if err == nil {
		return nil
	}

	jsonErr := btcjson.Error{
		Message: err.Error(),
	}
	switch e := err.(type) {
	case btcjson.Error:
		return &e
	case *btcjson.Error:
		return e
	case DeserializationError:
		jsonErr.Code = btcjson.ErrDeserialization.Code
	case InvalidParameterError:
		jsonErr.Code = btcjson.ErrInvalidParameter.Code
	case ParseError:
		jsonErr.Code = btcjson.ErrParse.Code
	case InvalidAddressOrKeyError:
		jsonErr.Code = btcjson.ErrInvalidAddressOrKey.Code
	default: // All other errors get the wallet error code.
		jsonErr.Code = btcjson.ErrWallet.Code
	}
	return &jsonErr
}

// makeMultiSigScript is a helper function to combine common logic for
// AddMultiSig and CreateMultiSig.
// all error codes are rpc parse error here to match bitcoind which just throws
// a runtime exception. *sigh*.
func makeMultiSigScript(w *Wallet, keys []string, nRequired int) ([]byte, error) {
	keysesPrecious := make([]*btcutil.AddressPubKey, len(keys))

	// The address list will made up either of addreseses (pubkey hash), for
	// which we need to look up the keys in wallet, straight pubkeys, or a
	// mixture of the two.
	for i, a := range keys {
		// try to parse as pubkey address
		a, err := btcutil.DecodeAddress(a, activeNet.Params)
		if err != nil {
			return nil, err
		}

		switch addr := a.(type) {
		case *btcutil.AddressPubKey:
			keysesPrecious[i] = addr
		case *btcutil.AddressPubKeyHash:
			ainfo, err := w.Manager.Address(addr)
			if err != nil {
				return nil, err
			}

			apkinfo := ainfo.(waddrmgr.ManagedPubKeyAddress)

			// This will be an addresspubkey
			a, err := btcutil.DecodeAddress(apkinfo.ExportPubKey(),
				activeNet.Params)
			if err != nil {
				return nil, err
			}

			apk := a.(*btcutil.AddressPubKey)
			keysesPrecious[i] = apk
		default:
			return nil, err
		}
	}

	return btcscript.MultiSigScript(keysesPrecious, nRequired)
}

// AddMultiSigAddress handles an addmultisigaddress request by adding a
// multisig address to the given wallet.
func AddMultiSigAddress(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.AddMultisigAddressCmd)

	err := checkDefaultAccount(cmd.Account)
	if err != nil {
		return nil, err
	}

	script, err := makeMultiSigScript(w, cmd.Keys, cmd.NRequired)
	if err != nil {
		return nil, ParseError{err}
	}

	// TODO(oga) blockstamp current block?
	bs := &waddrmgr.BlockStamp{
		Hash:   *activeNet.Params.GenesisHash,
		Height: 0,
	}

	addr, err := w.Manager.ImportScript(script, bs)
	if err != nil {
		return nil, err
	}

	return addr.Address().EncodeAddress(), nil
}

// CreateMultiSig handles an createmultisig request by returning a
// multisig address for the given inputs.
func CreateMultiSig(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.CreateMultisigCmd)

	script, err := makeMultiSigScript(w, cmd.Keys, cmd.NRequired)
	if err != nil {
		return nil, ParseError{err}
	}

	address, err := btcutil.NewAddressScriptHash(script, activeNet.Params)
	if err != nil {
		// above is a valid script, shouldn't happen.
		return nil, err
	}

	return btcjson.CreateMultiSigResult{
		Address:      address.EncodeAddress(),
		RedeemScript: hex.EncodeToString(script),
	}, nil
}

// DumpPrivKey handles a dumpprivkey request with the private key
// for a single address, or an appropiate error if the wallet
// is locked.
func DumpPrivKey(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.DumpPrivKeyCmd)

	addr, err := btcutil.DecodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, btcjson.ErrInvalidAddressOrKey
	}

	key, err := w.DumpWIFPrivateKey(addr)
	if isManagerLockedError(err) {
		// Address was found, but the private key isn't
		// accessible.
		return nil, btcjson.ErrWalletUnlockNeeded
	}
	return key, err
}

// DumpWallet handles a dumpwallet request by returning  all private
// keys in a wallet, or an appropiate error if the wallet is locked.
// TODO: finish this to match bitcoind by writing the dump to a file.
func DumpWallet(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	keys, err := w.DumpPrivKeys()
	if isManagerLockedError(err) {
		return nil, btcjson.ErrWalletUnlockNeeded
	}

	return keys, err
}

// ExportWatchingWallet handles an exportwatchingwallet request by exporting
// the current account wallet as a watching wallet (with no private keys), and
// returning  base64-encoding of serialized account files.
//
// TODO: remove Download from the command, this always assumes download now.
func ExportWatchingWallet(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcws.ExportWatchingWalletCmd)

	err := checkAccountName(cmd.Account)
	if err != nil {
		return nil, err
	}

	return w.ExportWatchingWallet()
}

// GetAddressesByAccount handles a getaddressesbyaccount request by returning
// all addresses for an account, or an error if the requested account does
// not exist.
func GetAddressesByAccount(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.GetAddressesByAccountCmd)

	err := checkAccountName(cmd.Account)
	if err != nil {
		return nil, err
	}

	return w.SortedActivePaymentAddresses()
}

// GetBalance handles a getbalance request by returning the balance for an
// account (wallet), or an error if the requested account does not
// exist.
func GetBalance(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.GetBalanceCmd)

	err := checkAccountName(cmd.Account)
	if err != nil {
		return nil, err
	}

	balance, err := w.CalculateBalance(cmd.MinConf)
	if err != nil {
		return nil, err
	}

	return balance.ToUnit(btcutil.AmountBTC), nil
}

// GetInfo handles a getinfo request by returning the a structure containing
// information about the current state of btcwallet.
// exist.
func GetInfo(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	// Call down to btcd for all of the information in this command known
	// by them.
	info, err := chainSvr.GetInfo()
	if err != nil {
		return nil, err
	}

	bal, err := w.CalculateBalance(1)
	if err != nil {
		return nil, err
	}

	// TODO(davec): This should probably have a database version as opposed
	// to using the manager version.
	info.WalletVersion = int32(waddrmgr.LatestMgrVersion)
	info.Balance = bal.ToUnit(btcutil.AmountBTC)
	// Keypool times are not tracked. set to current time.
	info.KeypoolOldest = time.Now().Unix()
	info.KeypoolSize = int32(cfg.KeypoolSize)
	info.PaytxFee = w.FeeIncrement.ToUnit(btcutil.AmountBTC)
	// We don't set the following since they don't make much sense in the
	// wallet architecture:
	//  - unlocked_until
	//  - errors

	return info, nil
}

// GetAccount handles a getaccount request by returning the account name
// associated with a single address.
func GetAccount(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.GetAccountCmd)

	// Is address valid?
	addr, err := btcutil.DecodeAddress(cmd.Address, activeNet.Params)
	if err != nil || !addr.IsForNet(activeNet.Params) {
		return nil, btcjson.ErrInvalidAddressOrKey
	}

	// If it is in the wallet, we consider it part of the default account.
	_, err = w.Manager.Address(addr)
	if err != nil {
		return nil, btcjson.ErrInvalidAddressOrKey
	}

	return "", nil
}

// GetAccountAddress handles a getaccountaddress by returning the most
// recently-created chained address that has not yet been used (does not yet
// appear in the blockchain, or any tx that has arrived in the btcd mempool).
// If the most recently-requested address has been used, a new address (the
// next chained address in the keypool) is used.  This can fail if the keypool
// runs out (and will return btcjson.ErrWalletKeypoolRanOut if that happens).
func GetAccountAddress(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.GetAccountAddressCmd)

	err := checkDefaultAccount(cmd.Account)
	if err != nil {
		return nil, err
	}

	addr, err := w.CurrentAddress()
	if err != nil {
		return nil, err
	}

	return addr.EncodeAddress(), err
}

// GetUnconfirmedBalance handles a getunconfirmedbalance extension request
// by returning the current unconfirmed balance of an account.
func GetUnconfirmedBalance(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcws.GetUnconfirmedBalanceCmd)

	err := checkAccountName(cmd.Account)
	if err != nil {
		return nil, err
	}

	unconfirmed, err := w.CalculateBalance(0)
	if err != nil {
		return nil, err
	}
	confirmed, err := w.CalculateBalance(1)
	if err != nil {
		return nil, err
	}

	return (unconfirmed - confirmed).ToUnit(btcutil.AmountBTC), nil
}

// ImportPrivKey handles an importprivkey request by parsing
// a WIF-encoded private key and adding it to an account.
func ImportPrivKey(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.ImportPrivKeyCmd)

	// Yes, Label is the account name...
	err := checkDefaultAccount(cmd.Label)
	if err != nil {
		return nil, err
	}

	wif, err := btcutil.DecodeWIF(cmd.PrivKey)
	if err != nil || !wif.IsForNet(activeNet.Params) {
		return nil, btcjson.ErrInvalidAddressOrKey
	}

	// Import the private key, handling any errors.
	_, err = w.ImportPrivateKey(wif, nil, cmd.Rescan)
	switch {
	case isManagerDuplicateError(err):
		// Do not return duplicate key errors to the client.
		return nil, nil
	case isManagerLockedError(err):
		return nil, btcjson.ErrWalletUnlockNeeded
	}

	return nil, err
}

// KeypoolRefill handles the keypoolrefill command. Since we handle the keypool
// automatically this does nothing since refilling is never manually required.
func KeypoolRefill(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	return nil, nil
}

// GetNewAddress handlesa getnewaddress request by returning a new
// address for an account.  If the account does not exist or the keypool
// ran out with a locked wallet, an appropiate error is returned.
func GetNewAddress(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.GetNewAddressCmd)

	err := checkDefaultAccount(cmd.Account)
	if err != nil {
		return nil, err
	}

	addr, err := w.NewAddress()
	if err != nil {
		return nil, err
	}

	// Return the new payment address string.
	return addr.EncodeAddress(), nil
}

// GetRawChangeAddress handles a getrawchangeaddress request by creating
// and returning a new change address for an account.
//
// Note: bitcoind allows specifying the account as an optional parameter,
// but ignores the parameter.
func GetRawChangeAddress(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	addr, err := w.NewChangeAddress()
	if err != nil {
		return nil, err
	}

	// Return the new payment address string.
	return addr.EncodeAddress(), nil
}

// GetReceivedByAccount handles a getreceivedbyaccount request by returning
// the total amount received by addresses of an account.
func GetReceivedByAccount(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.GetReceivedByAccountCmd)

	err := checkAccountName(cmd.Account)
	if err != nil {
		return nil, err
	}

	bal, err := w.TotalReceived(cmd.MinConf)
	if err != nil {
		return nil, err
	}

	return bal.ToUnit(btcutil.AmountBTC), nil
}

// GetReceivedByAddress handles a getreceivedbyaddress request by returning
// the total amount received by a single address.
func GetReceivedByAddress(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.GetReceivedByAddressCmd)

	addr, err := btcutil.DecodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, InvalidAddressOrKeyError{err}
	}
	total, err := w.TotalReceivedForAddr(addr, cmd.MinConf)
	if err != nil {
		return nil, err
	}

	return total.ToUnit(btcutil.AmountBTC), nil
}

// GetTransaction handles a gettransaction request by returning details about
// a single transaction saved by wallet.
func GetTransaction(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.GetTransactionCmd)

	txSha, err := btcwire.NewShaHashFromStr(cmd.Txid)
	if err != nil {
		return nil, btcjson.ErrDecodeHexString
	}

	record, ok := w.TxRecord(txSha)
	if !ok {
		return nil, btcjson.ErrNoTxInfo
	}

	bs, err := w.SyncedChainTip()
	if err != nil {
		return nil, err
	}

	var txBuf bytes.Buffer
	txBuf.Grow(record.Tx().MsgTx().SerializeSize())
	err = record.Tx().MsgTx().Serialize(&txBuf)
	if err != nil {
		return nil, err
	}

	// TODO(jrick) set "generate" to true if this is the coinbase (if
	// record.Tx().Index() == 0).
	ret := btcjson.GetTransactionResult{
		TxID:            txSha.String(),
		Hex:             hex.EncodeToString(txBuf.Bytes()),
		Time:            record.Received().Unix(),
		TimeReceived:    record.Received().Unix(),
		WalletConflicts: []string{},
	}

	if record.BlockHeight != -1 {
		txBlock, err := record.Block()
		if err != nil {
			return nil, err
		}
		ret.BlockIndex = int64(record.Tx().Index())
		ret.BlockHash = txBlock.Hash.String()
		ret.BlockTime = txBlock.Time.Unix()
		ret.Confirmations = int64(record.Confirmations(bs.Height))
	}

	credits := record.Credits()
	debits, err := record.Debits()
	var targetAddr *string
	var creditAmount btcutil.Amount
	if err != nil {
		// Credits must be set later, but since we know the full length
		// of the details slice, allocate it with the correct cap.
		ret.Details = make([]btcjson.GetTransactionDetailsResult, 0, len(credits))
	} else {
		ret.Details = make([]btcjson.GetTransactionDetailsResult, 1, len(credits)+1)

		details := btcjson.GetTransactionDetailsResult{
			Account:  "",
			Category: "send",
			// negative since it is a send
			Amount: (-debits.OutputAmount(true)).ToUnit(btcutil.AmountBTC),
			Fee:    debits.Fee().ToUnit(btcutil.AmountBTC),
		}
		targetAddr = &details.Address
		ret.Details[0] = details
		ret.Fee = details.Fee

		creditAmount = -debits.InputAmount()
	}

	for _, cred := range record.Credits() {
		// Change is ignored.
		if cred.Change() {
			continue
		}

		creditAmount += cred.Amount()

		var addr string
		// Errors don't matter here, as we only consider the
		// case where len(addrs) == 1.
		_, addrs, _, _ := cred.Addresses(activeNet.Params)
		if len(addrs) == 1 {
			addr = addrs[0].EncodeAddress()
			// The first non-change output address is considered the
			// target for sent transactions.
			if targetAddr != nil && *targetAddr == "" {
				*targetAddr = addr
			}
		}

		ret.Details = append(ret.Details, btcjson.GetTransactionDetailsResult{
			Account:  "",
			Category: cred.Category(bs.Height).String(),
			Amount:   cred.Amount().ToUnit(btcutil.AmountBTC),
			Address:  addr,
		})
	}

	ret.Amount = creditAmount.ToUnit(btcutil.AmountBTC)
	return ret, nil
}

// ListAccounts handles a listaccounts request by returning a map of account
// names to their balances.
func ListAccounts(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.ListAccountsCmd)

	bal, err := w.CalculateBalance(cmd.MinConf)
	if err != nil {
		return nil, err
	}

	// Return the map.  This will be marshaled into a JSON object.
	return map[string]float64{"": bal.ToUnit(btcutil.AmountBTC)}, nil
}

// ListLockUnspent handles a listlockunspent request by returning an slice of
// all locked outpoints.
func ListLockUnspent(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
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
// Since btcwallet doesn't implement account support yet, only the default account ""
// will be returned
func ListReceivedByAccount(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.ListReceivedByAccountCmd)

	bs, err := w.SyncedChainTip()
	if err != nil {
		return nil, err
	}

	// Total amount received.
	var amount btcutil.Amount

	// Number of confirmations of the last transaction.
	var confirmations int32

	for _, record := range w.TxStore.Records() {
		for _, credit := range record.Credits() {
			if !credit.Confirmed(cmd.MinConf, bs.Height) {
				// Not enough confirmations, skip the current block.
				continue
			}
			amount += credit.Amount()
			confirmations = credit.Confirmations(bs.Height)
		}
	}

	ret := []btcjson.ListReceivedByAccountResult{
		{
			Account:       "",
			Amount:        amount.ToUnit(btcutil.AmountBTC),
			Confirmations: uint64(confirmations),
		},
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
func ListReceivedByAddress(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.ListReceivedByAddressCmd)

	// Intermediate data for each address.
	type AddrData struct {
		// Total amount received.
		amount btcutil.Amount
		// Number of confirmations of the last transaction.
		confirmations int32
		// Hashes of transactions which include an output paying to the address
		tx []string
	}

	bs, err := w.SyncedChainTip()
	if err != nil {
		return nil, err
	}

	// Intermediate data for all addresses.
	allAddrData := make(map[string]AddrData)
	if cmd.IncludeEmpty {
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
	}
	for _, record := range w.TxStore.Records() {
		for _, credit := range record.Credits() {
			confirmations := credit.Confirmations(bs.Height)
			if !credit.Confirmed(cmd.MinConf, bs.Height) {
				// Not enough confirmations, skip the current block.
				continue
			}
			_, addresses, _, err := credit.Addresses(activeNet.Params)
			if err != nil {
				// Unusable address, skip it.
				continue
			}
			for _, address := range addresses {
				addrStr := address.EncodeAddress()
				addrData, ok := allAddrData[addrStr]
				if ok {
					addrData.amount += credit.Amount()
					// Always overwrite confirmations with newer ones.
					addrData.confirmations = confirmations
				} else {
					addrData = AddrData{
						amount:        credit.Amount(),
						confirmations: confirmations,
					}
				}
				addrData.tx = append(addrData.tx, credit.Tx().Sha().String())
				allAddrData[addrStr] = addrData
			}
		}
	}

	// Massage address data into output format.
	numAddresses := len(allAddrData)
	ret := make([]btcjson.ListReceivedByAddressResult, numAddresses, numAddresses)
	idx := 0
	for address, addrData := range allAddrData {
		ret[idx] = btcjson.ListReceivedByAddressResult{
			Account:       "",
			Address:       address,
			Amount:        addrData.amount.ToUnit(btcutil.AmountBTC),
			Confirmations: uint64(addrData.confirmations),
			TxIDs:         addrData.tx,
		}
		idx++
	}
	return ret, nil
}

// ListSinceBlock handles a listsinceblock request by returning an array of maps
// with details of sent and received wallet transactions since the given block.
func ListSinceBlock(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.ListSinceBlockCmd)

	height := int32(-1)
	if cmd.BlockHash != "" {
		hash, err := btcwire.NewShaHashFromStr(cmd.BlockHash)
		if err != nil {
			return nil, DeserializationError{err}
		}
		block, err := chainSvr.GetBlock(hash)
		if err != nil {
			return nil, err
		}
		height = int32(block.Height())
	}

	bs, err := w.SyncedChainTip()
	if err != nil {
		return nil, err
	}

	// For the result we need the block hash for the last block counted
	// in the blockchain due to confirmations. We send this off now so that
	// it can arrive asynchronously while we figure out the rest.
	gbh := chainSvr.GetBlockHashAsync(int64(bs.Height) + 1 - int64(cmd.TargetConfirmations))
	if err != nil {
		return nil, err
	}

	txInfoList, err := w.ListSinceBlock(height, bs.Height,
		cmd.TargetConfirmations)
	if err != nil {
		return nil, err
	}

	// Done with work, get the response.
	blockHash, err := gbh.Receive()
	if err != nil {
		return nil, err
	}

	res := btcjson.ListSinceBlockResult{
		Transactions: txInfoList,
		LastBlock:    blockHash.String(),
	}
	return res, nil
}

// ListTransactions handles a listtransactions request by returning an
// array of maps with details of sent and recevied wallet transactions.
func ListTransactions(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.ListTransactionsCmd)

	err := checkAccountName(cmd.Account)
	if err != nil {
		return nil, err
	}

	return w.ListTransactions(cmd.From, cmd.Count)
}

// ListAddressTransactions handles a listaddresstransactions request by
// returning an array of maps with details of spent and received wallet
// transactions.  The form of the reply is identical to listtransactions,
// but the array elements are limited to transaction details which are
// about the addresess included in the request.
func ListAddressTransactions(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcws.ListAddressTransactionsCmd)

	err := checkAccountName(cmd.Account)
	if err != nil {
		return nil, err
	}

	// Decode addresses.
	pkHashMap := make(map[string]struct{})
	for _, addrStr := range cmd.Addresses {
		addr, err := btcutil.DecodeAddress(addrStr, activeNet.Params)
		if err != nil {
			return nil, btcjson.ErrInvalidAddressOrKey
		}
		apkh, ok := addr.(*btcutil.AddressPubKeyHash)
		if !ok || !apkh.IsForNet(activeNet.Params) {
			return nil, btcjson.ErrInvalidAddressOrKey
		}
		pkHashMap[string(addr.ScriptAddress())] = struct{}{}
	}

	return w.ListAddressTransactions(pkHashMap)
}

// ListAllTransactions handles a listalltransactions request by returning
// a map with details of sent and recevied wallet transactions.  This is
// similar to ListTransactions, except it takes only a single optional
// argument for the account name and replies with all transactions.
func ListAllTransactions(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcws.ListAllTransactionsCmd)

	err := checkAccountName(cmd.Account)
	if err != nil {
		return nil, err
	}

	return w.ListAllTransactions()
}

// ListUnspent handles the listunspent command.
func ListUnspent(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.ListUnspentCmd)

	addresses := make(map[string]bool)
	if len(cmd.Addresses) != 0 {
		// confirm that all of them are good:
		for _, as := range cmd.Addresses {
			a, err := btcutil.DecodeAddress(as, activeNet.Params)
			if err != nil {
				return nil, btcjson.ErrInvalidAddressOrKey
			}

			if _, ok := addresses[a.EncodeAddress()]; ok {
				// duplicate
				return nil, btcjson.ErrInvalidParameter
			}
			addresses[a.EncodeAddress()] = true
		}
	}

	return w.ListUnspent(cmd.MinConf, cmd.MaxConf, addresses)
}

// LockUnspent handles the lockunspent command.
func LockUnspent(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.LockUnspentCmd)

	switch {
	case cmd.Unlock && len(cmd.Transactions) == 0:
		w.ResetLockedOutpoints()
	default:
		for _, input := range cmd.Transactions {
			txSha, err := btcwire.NewShaHashFromStr(input.Txid)
			if err != nil {
				return nil, ParseError{err}
			}
			op := btcwire.OutPoint{Hash: *txSha, Index: input.Vout}
			if cmd.Unlock {
				w.UnlockOutpoint(op)
			} else {
				w.LockOutpoint(op)
			}
		}
	}
	return true, nil
}

// sendPairs is a helper routine to reduce duplicated code when creating and
// sending payment transactions.
func sendPairs(w *Wallet, chainSvr *chain.Client, cmd btcjson.Cmd,
	amounts map[string]btcutil.Amount, minconf int) (interface{}, error) {

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := w.CreateSimpleTx(amounts, minconf)
	if err != nil {
		switch {
		case err == ErrNonPositiveAmount:
			return nil, ErrNeedPositiveAmount
		case isManagerLockedError(err):
			return nil, btcjson.ErrWalletUnlockNeeded
		}

		return nil, err
	}

	// Add to transaction store.
	txr, err := w.TxStore.InsertTx(createdTx.tx, nil)
	if err != nil {
		log.Errorf("Error adding sent tx history: %v", err)
		return nil, btcjson.ErrInternal
	}
	_, err = txr.AddDebits()
	if err != nil {
		log.Errorf("Error adding sent tx history: %v", err)
		return nil, btcjson.ErrInternal
	}
	if createdTx.changeIndex >= 0 {
		_, err = txr.AddCredit(uint32(createdTx.changeIndex), true)
		if err != nil {
			log.Errorf("Error adding change address for sent "+
				"tx: %v", err)
			return nil, btcjson.ErrInternal
		}
	}
	w.TxStore.MarkDirty()

	txSha, err := chainSvr.SendRawTransaction(createdTx.tx.MsgTx(), false)
	if err != nil {
		return nil, err
	}
	log.Infof("Successfully sent transaction %v", txSha)
	return txSha.String(), nil
}

// SendFrom handles a sendfrom RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to another payment
// address.  Leftover inputs not sent to the payment address or a fee for
// the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func SendFrom(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.SendFromCmd)

	err := checkAccountName(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that signed integer parameters are positive.
	if cmd.Amount < 0 {
		return nil, ErrNeedPositiveAmount
	}
	if cmd.MinConf < 0 {
		return nil, ErrNeedPositiveMinconf
	}
	// Create map of address and amount pairs.
	pairs := map[string]btcutil.Amount{
		cmd.ToAddress: btcutil.Amount(cmd.Amount),
	}

	return sendPairs(w, chainSvr, cmd, pairs, cmd.MinConf)
}

// SendMany handles a sendmany RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to any number of
// payment addresses.  Leftover inputs not sent to the payment address
// or a fee for the miner are sent back to a new address in the wallet.
// Upon success, the TxID for the created transaction is returned.
func SendMany(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.SendManyCmd)

	err := checkAccountName(cmd.FromAccount)
	if err != nil {
		return nil, err
	}

	// Check that minconf is positive.
	if cmd.MinConf < 0 {
		return nil, ErrNeedPositiveMinconf
	}

	// Recreate address/amount pairs, using btcutil.Amount.
	pairs := make(map[string]btcutil.Amount, len(cmd.Amounts))
	for k, v := range cmd.Amounts {
		pairs[k] = btcutil.Amount(v)
	}

	return sendPairs(w, chainSvr, cmd, pairs, cmd.MinConf)
}

// SendToAddress handles a sendtoaddress RPC request by creating a new
// transaction spending unspent transaction outputs for a wallet to another
// payment address.  Leftover inputs not sent to the payment address or a fee
// for the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func SendToAddress(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.SendToAddressCmd)

	// Check that signed integer parameters are positive.
	if cmd.Amount < 0 {
		return nil, ErrNeedPositiveAmount
	}

	// Mock up map of address and amount pairs.
	pairs := map[string]btcutil.Amount{
		cmd.Address: btcutil.Amount(cmd.Amount),
	}

	return sendPairs(w, chainSvr, cmd, pairs, 1)
}

// SetTxFee sets the transaction fee per kilobyte added to transactions.
func SetTxFee(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.SetTxFeeCmd)

	// Check that amount is not negative.
	if cmd.Amount < 0 {
		return nil, ErrNeedPositiveAmount
	}

	w.FeeIncrement = btcutil.Amount(cmd.Amount)

	// A boolean true result is returned upon success.
	return true, nil
}

// SignMessage signs the given message with the private key for the given
// address
func SignMessage(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.SignMessageCmd)

	addr, err := btcutil.DecodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, ParseError{err}
	}

	ainfo, err := w.Manager.Address(addr)
	if err != nil {
		return nil, btcjson.ErrInvalidAddressOrKey
	}

	pka := ainfo.(waddrmgr.ManagedPubKeyAddress)
	privKey, err := pka.PrivKey()
	if err != nil {
		return nil, err
	}

	fullmsg := "Bitcoin Signed Message:\n" + cmd.Message
	sigbytes, err := btcec.SignCompact(btcec.S256(), privKey,
		btcwire.DoubleSha256([]byte(fullmsg)), ainfo.Compressed())
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.EncodeToString(sigbytes), nil
}

// pendingTx is used for async fetching of transaction dependancies in
// SignRawTransaction.
type pendingTx struct {
	resp   btcrpcclient.FutureGetRawTransactionResult
	inputs []uint32 // list of inputs that care about this tx.
}

// SignRawTransaction handles the signrawtransaction command.
func SignRawTransaction(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.SignRawTransactionCmd)

	serializedTx, err := decodeHexStr(cmd.RawTx)
	if err != nil {
		return nil, btcjson.ErrDecodeHexString
	}
	msgTx := btcwire.NewMsgTx()
	err = msgTx.Deserialize(bytes.NewBuffer(serializedTx))
	if err != nil {
		e := errors.New("TX decode failed")
		return nil, DeserializationError{e}
	}

	// First we add the stuff we have been given.
	// TODO(oga) really we probably should look these up with btcd anyway
	// to make sure that they match the blockchain if present.
	inputs := make(map[btcwire.OutPoint][]byte)
	scripts := make(map[string][]byte)
	for _, rti := range cmd.Inputs {
		inputSha, err := btcwire.NewShaHashFromStr(rti.Txid)
		if err != nil {
			return nil, DeserializationError{err}
		}

		script, err := decodeHexStr(rti.ScriptPubKey)
		if err != nil {
			return nil, DeserializationError{err}
		}

		// redeemScript is only actually used iff the user provided
		// private keys. In which case, it is used to get the scripts
		// for signing. If the user did not provide keys then we always
		// get scripts from the wallet.
		// Empty strings are ok for this one and hex.DecodeString will
		// DTRT.
		if len(cmd.PrivKeys) != 0 {
			redeemScript, err := decodeHexStr(rti.RedeemScript)
			if err != nil {
				return nil, DeserializationError{err}
			}

			addr, err := btcutil.NewAddressScriptHash(redeemScript,
				activeNet.Params)
			if err != nil {
				return nil, DeserializationError{err}
			}
			scripts[addr.String()] = redeemScript
		}
		inputs[btcwire.OutPoint{
			Hash:  *inputSha,
			Index: rti.Vout,
		}] = script
	}

	// Now we go and look for any inputs that we were not provided by
	// querying btcd with getrawtransaction. We queue up a bunch of async
	// requests and will wait for replies after we have checked the rest of
	// the arguments.
	requested := make(map[btcwire.ShaHash]*pendingTx)
	for _, txIn := range msgTx.TxIn {
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
	var keys map[string]*btcutil.WIF
	if len(cmd.PrivKeys) != 0 {
		keys = make(map[string]*btcutil.WIF)

		for _, key := range cmd.PrivKeys {
			wif, err := btcutil.DecodeWIF(key)
			if err != nil {
				return nil, DeserializationError{err}
			}

			if !wif.IsForNet(activeNet.Params) {
				s := "key network doesn't match wallet's"
				return nil, DeserializationError{errors.New(s)}
			}

			addr, err := btcutil.NewAddressPubKey(wif.SerializePubKey(),
				activeNet.Params)
			if err != nil {
				return nil, DeserializationError{err}
			}
			keys[addr.EncodeAddress()] = wif
		}
	}

	hashType := btcscript.SigHashAll
	if cmd.Flags != "" {
		switch cmd.Flags {
		case "ALL":
			hashType = btcscript.SigHashAll
		case "NONE":
			hashType = btcscript.SigHashNone
		case "SINGLE":
			hashType = btcscript.SigHashSingle
		case "ALL|ANYONECANPAY":
			hashType = btcscript.SigHashAll |
				btcscript.SigHashAnyOneCanPay
		case "NONE|ANYONECANPAY":
			hashType = btcscript.SigHashNone |
				btcscript.SigHashAnyOneCanPay
		case "SINGLE|ANYONECANPAY":
			hashType = btcscript.SigHashSingle |
				btcscript.SigHashAnyOneCanPay
		default:
			e := errors.New("Invalid sighash parameter")
			return nil, InvalidParameterError{e}
		}
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
			if input >= uint32(len(tx.MsgTx().TxOut)) {
				e := fmt.Errorf("input %s:%d is not in tx",
					txid.String(), input)
				return nil, InvalidParameterError{e}
			}

			inputs[btcwire.OutPoint{
				Hash:  txid,
				Index: input,
			}] = tx.MsgTx().TxOut[input].PkScript
		}
	}

	// All args collected. Now we can sign all the inputs that we can.
	// `complete' denotes that we successfully signed all outputs and that
	// all scripts will run to completion. This is returned as part of the
	// reply.
	complete := true
	for i, txIn := range msgTx.TxIn {
		input, ok := inputs[txIn.PreviousOutPoint]
		if !ok {
			// failure to find previous is actually an error since
			// we failed above if we don't have all the inputs.
			return nil, fmt.Errorf("%s:%d not found",
				txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
		}

		// Set up our callbacks that we pass to btcscript so it can
		// look up the appropriate keys and scripts by address.
		getKey := btcscript.KeyClosure(func(addr btcutil.Address) (
			*btcec.PrivateKey, bool, error) {
			if len(keys) != 0 {
				wif, ok := keys[addr.EncodeAddress()]
				if !ok {
					return nil, false,
						errors.New("no key for address")
				}
				return wif.PrivKey, wif.CompressPubKey, nil
			}
			address, err := w.Manager.Address(addr)
			if err != nil {
				return nil, false, err
			}

			pka, ok := address.(waddrmgr.ManagedPubKeyAddress)
			if !ok {
				return nil, false, errors.New("address is not " +
					"a pubkey address")
			}

			key, err := pka.PrivKey()
			if err != nil {
				return nil, false, err
			}

			return key, pka.Compressed(), nil
		})

		getScript := btcscript.ScriptClosure(func(
			addr btcutil.Address) ([]byte, error) {
			// If keys were provided then we can only use the
			// scripts provided with our inputs, too.
			if len(keys) != 0 {
				script, ok := scripts[addr.EncodeAddress()]
				if !ok {
					return nil, errors.New("no script for " +
						"address")
				}
				return script, nil
			}
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
		if (hashType&btcscript.SigHashSingle) !=
			btcscript.SigHashSingle || i < len(msgTx.TxOut) {

			script, err := btcscript.SignTxOutput(activeNet.Params,
				msgTx, i, input, hashType, getKey,
				getScript, txIn.SignatureScript)
			// Failure to sign isn't an error, it just means that
			// the tx isn't complete.
			if err != nil {
				complete = false
				continue
			}
			txIn.SignatureScript = script
		}

		// Either it was already signed or we just signed it.
		// Find out if it is completely satisfied or still needs more.
		flags := btcscript.ScriptBip16 | btcscript.ScriptCanonicalSignatures |
			btcscript.ScriptStrictMultiSig
		engine, err := btcscript.NewScript(txIn.SignatureScript, input,
			i, msgTx, flags)
		if err != nil || engine.Execute() != nil {
			complete = false
		}
	}

	var buf bytes.Buffer
	buf.Grow(msgTx.SerializeSize())

	// All returned errors (not OOM, which panics) encounted during
	// bytes.Buffer writes are unexpected.
	if err = msgTx.Serialize(&buf); err != nil {
		panic(err)
	}

	return btcjson.SignRawTransactionResult{
		Hex:      hex.EncodeToString(buf.Bytes()),
		Complete: complete,
	}, nil
}

// ValidateAddress handles the validateaddress command.
func ValidateAddress(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.ValidateAddressCmd)

	result := btcjson.ValidateAddressResult{}
	addr, err := btcutil.DecodeAddress(cmd.Address, activeNet.Params)
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
	if managerErr, ok := err.(waddrmgr.ManagerError); ok {
		if managerErr.ErrorCode == waddrmgr.ErrAddressNotFound {
			// No additional information available about the address.
			return result, nil
		}
	}
	if err != nil {
		return nil, err
	}

	result.Account = ""
	result.IsWatchOnly = w.Manager.IsWatchingOnly()

	switch ma := ainfo.(type) {
	case waddrmgr.ManagedPubKeyAddress:
		result.IsCompressed = ma.Compressed()
		result.PubKey = ma.ExportPubKey()

		// The address is "mine" if the associated private key is managed
		// by the wallet and it's outputs are spendable
		_, err := ma.PrivKey()
		if err == nil {
			result.IsMine = true
		}
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
		class, addrs, reqSigs, err := btcscript.ExtractPkScriptAddrs(
			script, activeNet.Params)
		if err != nil {
			result.Script = btcscript.NonStandardTy.String()
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
		if class == btcscript.MultiSigTy {
			result.SigsRequired = int32(reqSigs)
		}
	}

	return result, nil
}

// VerifyMessage handles the verifymessage command by verifying the provided
// compact signature for the given address and message.
func VerifyMessage(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.VerifyMessageCmd)

	addr, err := btcutil.DecodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, ParseError{err}
	}

	// decode base64 signature
	sig, err := base64.StdEncoding.DecodeString(cmd.Signature)
	if err != nil {
		return nil, err
	}

	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	pk, wasCompressed, err := btcec.RecoverCompact(btcec.S256(), sig,
		btcwire.DoubleSha256([]byte("Bitcoin Signed Message:\n"+
			cmd.Message)))
	if err != nil {
		return nil, err
	}

	var serializedPubKey []byte
	if wasCompressed {
		serializedPubKey = pk.SerializeCompressed()
	} else {
		serializedPubKey = pk.SerializeUncompressed()
	}
	// Verify that the signed-by address matches the given address
	switch checkAddr := addr.(type) {
	case *btcutil.AddressPubKeyHash: // ok
		return bytes.Equal(btcutil.Hash160(serializedPubKey), checkAddr.Hash160()[:]), nil
	case *btcutil.AddressPubKey: // ok
		return string(serializedPubKey) == checkAddr.String(), nil
	default:
		return nil, errors.New("address type not supported")
	}
}

// WalletIsLocked handles the walletislocked extension request by
// returning the current lock state (false for unlocked, true for locked)
// of an account.
func WalletIsLocked(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	return w.Locked(), nil
}

// WalletLock handles a walletlock request by locking the all account
// wallets, returning an error if any wallet is not encrypted (for example,
// a watching-only wallet).
func WalletLock(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	w.Lock()
	return nil, nil
}

// WalletPassphrase responds to the walletpassphrase request by unlocking
// the wallet.  The decryption key is saved in the wallet until timeout
// seconds expires, after which the wallet is locked.
func WalletPassphrase(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.WalletPassphraseCmd)

	timeout := time.Second * time.Duration(cmd.Timeout)
	err := w.Unlock([]byte(cmd.Passphrase), timeout)
	return nil, err
}

// WalletPassphraseChange responds to the walletpassphrasechange request
// by unlocking all accounts with the provided old passphrase, and
// re-encrypting each private key with an AES key derived from the new
// passphrase.
//
// If the old passphrase is correct and the passphrase is changed, all
// wallets will be immediately locked.
func WalletPassphraseChange(w *Wallet, chainSvr *chain.Client, icmd btcjson.Cmd) (interface{}, error) {
	cmd := icmd.(*btcjson.WalletPassphraseChangeCmd)

	err := w.ChangePassphrase([]byte(cmd.OldPassphrase),
		[]byte(cmd.NewPassphrase))
	if isManagerWrongPassphraseError(err) {
		return nil, btcjson.ErrWalletPassphraseIncorrect
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
	return hex.DecodeString(hexStr)
}
