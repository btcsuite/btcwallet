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
	"crypto/ecdsa"
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
	"time"

	"github.com/conformal/btcec"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcrpcclient"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/txstore"
	"github.com/conformal/btcwallet/wallet"
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
)

type websocketClient struct {
	conn             *websocket.Conn
	authenticated    bool
	remoteAddr       string
	allRequests      chan []byte
	unauthedRequests chan unauthedRequest
	responses        chan []byte
	quit             chan struct{} // closed on disconnect
}

func newWebsocketClient(c *websocket.Conn, authenticated bool, remoteAddr string) *websocketClient {
	return &websocketClient{
		conn:             c,
		authenticated:    authenticated,
		remoteAddr:       remoteAddr,
		allRequests:      make(chan []byte),
		unauthedRequests: make(chan unauthedRequest, maxConcurrentClientRequests),
		responses:        make(chan []byte),
		quit:             make(chan struct{}),
	}
}

var errDisconnected = errors.New("websocket client disconnected")

func (c *websocketClient) send(b []byte) error {
	select {
	case c.responses <- b:
		return nil
	case <-c.quit:
		return errDisconnected
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
	wg        sync.WaitGroup
	listeners []net.Listener
	authsha   [sha256.Size]byte
	wsClients map[*websocketClient]struct{}

	upgrader websocket.Upgrader

	requests chan handlerJob

	addWSClient    chan *websocketClient
	removeWSClient chan *websocketClient
	broadcasts     chan []byte

	quit chan struct{}
}

// newRPCServer creates a new server for serving RPC client connections, both
// HTTP POST and websocket.
func newRPCServer(listenAddrs []string) (*rpcServer, error) {
	login := cfg.Username + ":" + cfg.Password
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
	s := rpcServer{
		authsha:   sha256.Sum256([]byte(auth)),
		wsClients: map[*websocketClient]struct{}{},
		upgrader: websocket.Upgrader{
			// Allow all origins.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		requests:       make(chan handlerJob),
		addWSClient:    make(chan *websocketClient),
		removeWSClient: make(chan *websocketClient),
		broadcasts:     make(chan []byte),
		quit:           make(chan struct{}),
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
	// A duplicator for notifications intended for all clients runs
	// in another goroutines.  Any such notifications are sent to
	// the allClients channel and then sent to each connected client.
	s.wg.Add(2)
	go s.NotificationHandler()
	go s.RequestHandler()

	log.Trace("Starting RPC server")

	serveMux := http.NewServeMux()
	const rpcAuthTimeoutSeconds = 10
	httpServer := &http.Server{
		Handler: serveMux,

		// Timeout connections which don't complete the initial
		// handshake within the allowed timeframe.
		ReadTimeout: time.Second * rpcAuthTimeoutSeconds,
	}
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "application/json")
		r.Close = true

		// TODO: Limit number of active connections.

		if err := s.checkAuthHeader(r); err != nil {
			log.Warnf("Unauthorized client connection attempt")
			http.Error(w, "401 Unauthorized.", http.StatusUnauthorized)
			return
		}
		s.PostClientRPC(w, r)
	})
	serveMux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
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
	})
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
	// If the server is changed to run more than one rpc handler at a time,
	// to prevent a double channel close, this should be replaced with an
	// atomic test-and-set.
	select {
	case <-s.quit:
		log.Warnf("Server already shutting down")
		return
	default:
	}

	log.Warn("Server shutting down")

	// Stop all the listeners.  There will not be any listeners if
	// listening is disabled.
	for _, listener := range s.listeners {
		err := listener.Close()
		if err != nil {
			log.Errorf("Cannot close listener %s: %v",
				listener.Addr(), err)
		}
	}

	// Disconnect the connected chain server, if any.
	client, err := accessClient()
	if err == nil {
		client.Stop()
	}

	// Stop the account manager and finish all pending account file writes.
	AcctMgr.Stop()

	// Signal the remaining goroutines to stop.
	close(s.quit)
}

func (s *rpcServer) WaitForShutdown() {
	AcctMgr.WaitForShutdown()
	s.wg.Wait()
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
	s.wg.Done()
}

type rawRequest struct {
	// "jsonrpc" value isn't checked so we exclude it.
	ID     interface{}       `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

// idPointer returns a pointer to the passed ID, or nil if the interface is nil.
// Interface pointers are usually a red flag of doing something incorrectly,
// but this is only implemented here to work around an oddity with btcjson,
// which uses empty interface pointers for request and response IDs.
func idPointer(id interface{}) (p *interface{}) {
	if id != nil {
		p = &id
	}
	return
}

func marshalError(id *interface{}) []byte {
	response := btcjson.Reply{
		Id:    id,
		Error: &btcjson.ErrInvalidRequest,
	}
	mresponse, err := json.Marshal(response)
	// We expect the marshal to succeed.  If it doesn't, it indicates some
	// non-marshalable type in the response.
	if err != nil {
		panic(err)
	}
	return mresponse
}

// websocketPassthrough pass a websocket client's raw request to the connected
// chain server.
func (s *rpcServer) websocketPassthrough(wsc *websocketClient, request rawRequest) {
	resp := passthrough(request)
	_ = wsc.send(resp)
}

// postPassthrough pass a websocket client's raw request to the connected
// chain server.
func (s *rpcServer) postPassthrough(w http.ResponseWriter, request rawRequest) {
	resp := passthrough(request)
	if _, err := w.Write(resp); err != nil {
		log.Warnf("Unable to respond to client with passthrough "+
			"response: %v", err)
	}
}

// passthrough is a helper function for websocketPassthrough and postPassthrough
// to request and receive the chain server's marshaled response to an
// unhandled-by-wallet request.  The marshaled response includes the original
// request's ID.
func passthrough(request rawRequest) []byte {
	var res json.RawMessage
	client, err := accessClient()
	if err == nil {
		res, err = client.RawRequest(request.Method, request.Params)
	}
	var jsonErr *btcjson.Error
	if err != nil {
		switch e := err.(type) {
		case *btcjson.Error:
			jsonErr = e
		case btcjson.Error:
			jsonErr = &e
		default:
			jsonErr = &btcjson.Error{
				Code:    btcjson.ErrWallet.Code,
				Message: err.Error(),
			}
		}
	}

	// The raw result will only marshal correctly if called with the
	// MarshalJSON method, and that method requires a pointer receiver.
	var pres *json.RawMessage
	if res != nil {
		pres = &res
	}

	resp := btcjson.Reply{
		Id:     idPointer(request.ID),
		Result: pres,
		Error:  jsonErr,
	}
	mresp, err := json.Marshal(resp)
	// The chain server response was successfully unmarshaled or we created
	// our own error, so a marshal can never error.
	if err != nil {
		panic(err)
	}
	return mresp
}

type unauthedRequest struct {
	marshaledRequest []byte
	handler          requestHandler
}

func (s *rpcServer) WebsocketClientGateway(wsc *websocketClient) {
out:
	for request := range wsc.allRequests {
		// Get the method of the request and check whether it should be
		// handled by wallet or passed down to btcd.  If the latter,
		// handle in a new goroutine (to not block or be blocked by
		// the handling of actual wallet requests).
		//
		// This is done by unmarshaling the JSON bytes into a rawRequest
		// to avoid the mangling of unmarshaling and re-marshaling of
		// large JSON numbers, as well as the overhead of unneeded
		// unmarshals and marshals.
		var raw rawRequest
		if err := json.Unmarshal(request, &raw); err != nil {
			if !wsc.authenticated {
				// Disconnect immediately.
				break out
			}
			err = wsc.send(marshalError(idPointer(raw.ID)))
			if err != nil {
				break out
			}
			continue
		}

		f, ok := handlerFunc(raw.Method, true)
		if ok || raw.Method == "authenticate" {
			// unauthedRequests is buffered to the max number of
			// concurrent websocket client requests so as to not
			// block the passthrough of later btcd requests.
			wsc.unauthedRequests <- unauthedRequest{request, f}
		} else {
			// websocketPassthrough is run as a goroutine to
			// send an unhandled request to the chain server without
			// blocking the handling of later wallet requests.
			go s.websocketPassthrough(wsc, raw)
		}
	}
	close(wsc.unauthedRequests)
	s.wg.Done()
}

// invalidAuth checks whether a websocket request is allowed for the current
// authentication state.  If an unauthenticated client submitted an
// authenticate request, the authentication is verified and the client's
// authentication state is modified.
func (s *rpcServer) invalidAuth(wsc *websocketClient, request btcjson.Cmd) (invalid, checked bool) {
	if authCmd, ok := request.(*btcws.AuthenticateCmd); ok {
		// Duplication authentication is not allowed.
		if wsc.authenticated {
			return true, false
		}

		// Check credentials.
		login := authCmd.Username + ":" + authCmd.Passphrase
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
		authSha := sha256.Sum256([]byte(auth))
		cmp := subtle.ConstantTimeCompare(authSha[:], s.authsha[:])
		wsc.authenticated = cmp == 1
		return cmp != 1, true
	}
	// Unauthorized clients must first issue an authenticate request.  If
	// not already authenticated, the auth is invalid.
	return !wsc.authenticated, false
}

func (s *rpcServer) WebsocketClientRespond(wsc *websocketClient) {
out:
	for r := range wsc.unauthedRequests {
		cmd, parseErr := btcjson.ParseMarshaledCmd(r.marshaledRequest)
		var id interface{}
		if cmd != nil {
			id = cmd.Id()
		}

		// Verify that the websocket is authenticated and not send an
		// unnecessary authentication request, or perform the check
		// if unauthenticated and this is an authentication request.
		// Disconnect the client immediately if the authentication is
		// invalid or disallowed.
		switch invalid, checked := s.invalidAuth(wsc, cmd); {
		case invalid:
			log.Warnf("Disconnecting improperly authenticated "+
				"websocket client %s", wsc.remoteAddr)
			break out
		case checked:
			// Marshal and send a successful auth response.  The
			// marshal is expected to never fail.
			response := btcjson.Reply{Id: idPointer(id)}
			mresponse, err := json.Marshal(response)
			if err != nil {
				panic(err)
			}
			if err := wsc.send(mresponse); err != nil {
				break out
			}
			continue
		}

		// The parse error is checked after the authentication check
		// so we don't respond back for invalid requests sent by
		// unauthenticated clients.
		if parseErr != nil {
			if wsc.send(marshalError(idPointer(id))) != nil {
				break out
			}
			continue
		}

		// Send request and the handler func (already looked up) to the
		// server's global request handler.  This serializes the
		// execution of all handlers from all connections (both
		// websocket and HTTP POST), and runs the handler with exclusive
		// access of the account manager.
		responseChan := make(chan handlerResponse)
		s.requests <- handlerJob{
			request:  cmd,
			handler:  r.handler,
			response: responseChan,
		}
		response := <-responseChan
		resp := btcjson.Reply{
			Id:     idPointer(id),
			Result: response.result,
			Error:  response.jsonErr,
		}
		mresp, err := json.Marshal(resp)
		// All responses originating from us must be marshalable.
		if err != nil {
			panic(err)
		}
		// Send marshaled response to client.
		if err := wsc.send(mresp); err != nil {
			break out
		}
	}
	close(wsc.responses)
	s.wg.Done()
}

func (s *rpcServer) WebsocketClientSend(wsc *websocketClient) {
	const deadline time.Duration = 2 * time.Second
	for response := range wsc.responses {
		err := wsc.conn.SetWriteDeadline(time.Now().Add(deadline))
		if err != nil {
			log.Warnf("Cannot set write deadline on client %s: %v",
				wsc.remoteAddr, err)
		}
		err = wsc.conn.WriteMessage(websocket.TextMessage, response)
		if err != nil {
			log.Warnf("Failed websocket send to client %s: %v",
				wsc.remoteAddr, err)
			break
		}
	}
	close(wsc.quit)
	log.Infof("Disconnected websocket client %s", wsc.remoteAddr)
	s.removeWSClient <- wsc
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
	s.addWSClient <- wsc

	s.wg.Add(4)
	go s.WebsocketClientRead(wsc)
	go s.WebsocketClientGateway(wsc)
	go s.WebsocketClientRespond(wsc)
	go s.WebsocketClientSend(wsc)

	// Send initial unsolicited notifications.
	// TODO: these should be requested by the client first.
	s.NotifyConnectionStatus(wsc)
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
	if err != nil || raw.Method == "authenticate" {
		_, err := w.Write(marshalError(idPointer(raw.ID)))
		if err != nil {
			log.Warnf("Cannot write invalid request request to "+
				"client: %v", err)
		}
		return
	}
	f, ok := handlerFunc(raw.Method, false)
	if !ok {
		s.postPassthrough(w, raw)
		return
	}

	// Parse the full request since it must be handled by wallet.
	cmd, err := btcjson.ParseMarshaledCmd(rpcRequest)
	var id interface{}
	if cmd != nil {
		id = cmd.Id()
	}
	if err != nil {
		fmt.Printf("%s\n", rpcRequest)
		_, err := w.Write(marshalError(idPointer(cmd.Id())))
		if err != nil {
			log.Warnf("Client sent invalid request but unable "+
				"to respond with error: %v", err)
		}
		return
	}

	// Send request and the handler func (already looked up) to the
	// server's global request handler.  This serializes the
	// execution of all handlers from all connections (both
	// websocket and HTTP POST), and runs the handler with exclusive
	// access of the account manager.
	responseChan := make(chan handlerResponse)
	s.requests <- handlerJob{
		request:  cmd,
		handler:  f,
		response: responseChan,
	}
	response := <-responseChan
	resp := btcjson.Reply{
		Id:     idPointer(id),
		Result: response.result,
		Error:  response.jsonErr,
	}
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

// NotifyConnectionStatus notifies all connected websocket clients of the
// current connection status of btcwallet to btcd.
func (s *rpcServer) NotifyConnectionStatus(wsc *websocketClient) {
	connected := false
	client, err := accessClient()
	if err == nil {
		connected = !client.Disconnected()
	}
	ntfn := btcws.NewBtcdConnectedNtfn(connected)
	mntfn, err := ntfn.MarshalJSON()
	// btcws notifications must always marshal without error.
	if err != nil {
		panic(err)
	}
	if wsc == nil {
		s.broadcasts <- mntfn
	} else {
		// Don't care whether the client disconnected at this
		// point, so discard error.
		_ = wsc.send(mntfn)
	}
}

func (s *rpcServer) NotificationHandler() {
out:
	for {
		select {
		case c := <-s.addWSClient:
			s.wsClients[c] = struct{}{}
		case c := <-s.removeWSClient:
			delete(s.wsClients, c)
		case b := <-s.broadcasts:
			for wsc := range s.wsClients {
				if err := wsc.send(b); err != nil {
					delete(s.wsClients, wsc)
				}
			}
		case <-s.quit:
			break out
		}
	}
	s.wg.Done()
}

// requestHandler is a handler function to handle an unmarshaled and parsed
// request into a marshalable response.  If the error is a btcjson.Error
// or any of the above special error classes, the server will respond with
// the JSON-RPC appropiate error code.  All other errors use the wallet
// catch-all error code, btcjson.ErrWallet.Code.
type requestHandler func(btcjson.Cmd) (interface{}, error)

var rpcHandlers = map[string]requestHandler{
	// Standard bitcoind methods (implemented)
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
	"gettransaction":         GetTransaction,
	"importprivkey":          ImportPrivKey,
	"keypoolrefill":          KeypoolRefill,
	"listaccounts":           ListAccounts,
	"listlockunspent":        ListLockUnspent,
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
	"stop":                   Stop,
	"validateaddress":        ValidateAddress,
	"verifymessage":          VerifyMessage,
	"walletlock":             WalletLock,
	"walletpassphrase":       WalletPassphrase,
	"walletpassphrasechange": WalletPassphraseChange,

	// Standard bitcoind methods (currently unimplemented)
	"backupwallet":          Unimplemented,
	"dumpwallet":            Unimplemented,
	"getreceivedbyaddress":  Unimplemented,
	"getwalletinfo":         Unimplemented,
	"importwallet":          Unimplemented,
	"listaddressgroupings":  Unimplemented,
	"listreceivedbyaccount": Unimplemented,
	"move":                  Unimplemented,
	"setaccount":            Unimplemented,

	// Standard bitcoind methods which won't be implemented by btcwallet.
	"encryptwallet": Unsupported,

	// Extensions not exclusive to websocket connections.
	"createencryptedwallet": CreateEncryptedWallet,
}

// Extensions exclusive to websocket connections.
var wsHandlers = map[string]requestHandler{
	"exportwatchingwallet":    ExportWatchingWallet,
	"getaddressbalance":       GetAddressBalance,
	"getunconfirmedbalance":   GetUnconfirmedBalance,
	"listaddresstransactions": ListAddressTransactions,
	"listalltransactions":     ListAllTransactions,
	"recoveraddresses":        RecoverAddresses,
	"walletislocked":          WalletIsLocked,
}

// handlerFunc looks up a request handler func for the passed method from
// the http post and (if the request is from a websocket connection) websocket
// handler maps.  If a suitable handler could not be found, ok is false.
func handlerFunc(method string, ws bool) (f requestHandler, ok bool) {
	f, ok = rpcHandlers[method]
	if !ok && ws {
		f, ok = wsHandlers[method]
	}
	return f, ok
}

type handlerResponse struct {
	result  interface{}
	jsonErr *btcjson.Error
}

type handlerJob struct {
	request  btcjson.Cmd
	handler  requestHandler
	response chan<- handlerResponse
}

// RequestHandler reads and processes client requests from the request channel.
// Each request is run with exclusive access to the account manager.
func (s *rpcServer) RequestHandler() {
out:
	for {
		select {
		case r := <-s.requests:
			AcctMgr.Grab()
			result, err := r.handler(r.request)
			AcctMgr.Release()

			var jsonErr *btcjson.Error
			if err != nil {
				jsonErr = &btcjson.Error{Message: err.Error()}
				switch e := err.(type) {
				case btcjson.Error:
					*jsonErr = e
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
			}
			r.response <- handlerResponse{result, jsonErr}

		case <-s.quit:
			break out
		}
	}
	s.wg.Done()
}

// Unimplemented handles an unimplemented RPC request with the
// appropiate error.
func Unimplemented(btcjson.Cmd) (interface{}, error) {
	return nil, btcjson.ErrUnimplemented
}

// Unsupported handles a standard bitcoind RPC request which is
// unsupported by btcwallet due to design differences.
func Unsupported(btcjson.Cmd) (interface{}, error) {
	return nil, btcjson.Error{
		Code:    -1,
		Message: "Request unsupported by btcwallet",
	}
}

// makeMultiSigScript is a helper function to combine common logic for
// AddMultiSig and CreateMultiSig.
// all error codes are rpc parse error here to match bitcoind which just throws
// a runtime exception. *sigh*.
func makeMultiSigScript(keys []string, nRequired int) ([]byte, error) {
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
			ainfo, err := AcctMgr.Address(addr)
			if err != nil {
				return nil, err
			}

			apkinfo := ainfo.(wallet.PubKeyAddress)

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
func AddMultiSigAddress(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcjson.AddMultisigAddressCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	acct, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	script, err := makeMultiSigScript(cmd.Keys, cmd.NRequired)
	if err != nil {
		return nil, ParseError{err}
	}

	// TODO(oga) blockstamp current block?
	address, err := acct.ImportScript(script, &wallet.BlockStamp{})
	if err != nil {
		return nil, err
	}

	return address.EncodeAddress(), nil
}

// CreateMultiSig handles an createmultisig request by returning a
// multisig address for the given inputs.
func CreateMultiSig(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcjson.CreateMultisigCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	script, err := makeMultiSigScript(cmd.Keys, cmd.NRequired)
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
func DumpPrivKey(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.DumpPrivKeyCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	addr, err := btcutil.DecodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, btcjson.ErrInvalidAddressOrKey
	}

	key, err := AcctMgr.DumpWIFPrivateKey(addr)
	if err == wallet.ErrWalletLocked {
		// Address was found, but the private key isn't
		// accessible.
		return nil, btcjson.ErrWalletUnlockNeeded
	}
	return key, err
}

// DumpWallet handles a dumpwallet request by returning  all private
// keys in a wallet, or an appropiate error if the wallet is locked.
// TODO: finish this to match bitcoind by writing the dump to a file.
func DumpWallet(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	_, ok := icmd.(*btcjson.DumpWalletCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	keys, err := AcctMgr.DumpKeys()
	if err == wallet.ErrWalletLocked {
		// Address was found, but the private key isn't
		// accessible.
		return nil, btcjson.ErrWalletUnlockNeeded
	}
	return keys, err
}

// ExportWatchingWallet handles an exportwatchingwallet request by exporting
// the current account wallet as a watching wallet (with no private keys), and
// either writing the exported wallet to disk, or base64-encoding serialized
// account files and sending them back in the response.
func ExportWatchingWallet(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.ExportWatchingWalletCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	wa, err := a.ExportWatchingWallet()
	if err != nil {
		return nil, err
	}

	if cmd.Download {
		return wa.exportBase64()
	}

	// Create export directory, write files there.
	err = wa.ExportToDirectory("watchingwallet")
	return nil, err
}

// GetAddressesByAccount handles a getaddressesbyaccount request by returning
// all addresses for an account, or an error if the requested account does
// not exist.
func GetAddressesByAccount(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetAddressesByAccountCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}
	return a.SortedActivePaymentAddresses(), nil
}

// GetBalance handles a getbalance request by returning the balance for an
// account (wallet), or an error if the requested account does not
// exist.
func GetBalance(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetBalanceCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	balance, err := AcctMgr.CalculateBalance(cmd.Account, cmd.MinConf)
	if err == ErrNotFound {
		return nil, btcjson.ErrWalletInvalidAccountName
	}
	return balance, err
}

// GetInfo handles a getinfo request by returning the a structure containing
// information about the current state of btcwallet.
// exist.
func GetInfo(icmd btcjson.Cmd) (interface{}, error) {
	// Call down to btcd for all of the information in this command known
	// by them.
	client, err := accessClient()
	if err != nil {
		return nil, err
	}
	info, err := client.GetInfo()
	if err != nil {
		return nil, err
	}

	balance := float64(0.0)
	accounts := AcctMgr.ListAccounts(1)
	for _, v := range accounts {
		balance += v
	}
	info.WalletVersion = int(wallet.VersCurrent.Uint32())
	info.Balance = balance
	// Keypool times are not tracked. set to current time.
	info.KeypoolOldest = time.Now().Unix()
	info.KeypoolSize = int(cfg.KeypoolSize)
	TxFeeIncrement.Lock()
	info.PaytxFee = float64(TxFeeIncrement.i) / float64(btcutil.SatoshiPerBitcoin)
	TxFeeIncrement.Unlock()
	// We don't set the following since they don't make much sense in the
	// wallet architecture:
	//  - unlocked_until
	//  - errors

	return info, nil
}

// GetAccount handles a getaccount request by returning the account name
// associated with a single address.
func GetAccount(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetAccountCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	// Is address valid?
	addr, err := btcutil.DecodeAddress(cmd.Address, activeNet.Params)
	if err != nil || !addr.IsForNet(activeNet.Params) {
		return nil, btcjson.ErrInvalidAddressOrKey
	}

	// Look up account which holds this address.
	acct, err := AcctMgr.AccountByAddress(addr)
	if err != nil {
		if err == ErrNotFound {
			return nil, ErrAddressNotInWallet
		}
		return nil, err
	}
	return acct.Name(), nil
}

// GetAccountAddress handles a getaccountaddress by returning the most
// recently-created chained address that has not yet been used (does not yet
// appear in the blockchain, or any tx that has arrived in the btcd mempool).
// If the most recently-requested address has been used, a new address (the
// next chained address in the keypool) is used.  This can fail if the keypool
// runs out (and will return btcjson.ErrWalletKeypoolRanOut if that happens).
func GetAccountAddress(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetAccountAddressCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	// Lookup account for this request.
	a, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	addr, err := a.CurrentAddress()
	if err != nil {
		if err == wallet.ErrWalletLocked {
			return nil, btcjson.ErrWalletKeypoolRanOut
		}
		return nil, err
	}
	return addr.EncodeAddress(), err
}

// GetAddressBalance handles a getaddressbalance extension request by
// returning the current balance (sum of unspent transaction output amounts)
// for a single address.
func GetAddressBalance(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.GetAddressBalanceCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	// Is address valid?
	addr, err := btcutil.DecodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, btcjson.ErrInvalidAddressOrKey
	}

	// Get the account which holds the address in the request.
	a, err := AcctMgr.AccountByAddress(addr)
	if err != nil {
		return nil, ErrAddressNotInWallet
	}

	return a.CalculateAddressBalance(addr, int(cmd.Minconf)), nil
}

// GetUnconfirmedBalance handles a getunconfirmedbalance extension request
// by returning the current unconfirmed balance of an account.
func GetUnconfirmedBalance(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.GetUnconfirmedBalanceCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	// Get the account included in the request.
	a, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	return a.CalculateBalance(0) - a.CalculateBalance(1), nil
}

// ImportPrivKey handles an importprivkey request by parsing
// a WIF-encoded private key and adding it to an account.
func ImportPrivKey(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.ImportPrivKeyCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	// Get the acount included in the request. Yes, Label is the
	// account name...
	a, err := AcctMgr.Account(cmd.Label)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	wif, err := btcutil.DecodeWIF(cmd.PrivKey)
	if err != nil || !wif.IsForNet(activeNet.Params) {
		return nil, btcjson.ErrInvalidAddressOrKey
	}

	// Import the private key, handling any errors.
	bs := wallet.BlockStamp{}
	if _, err := a.ImportPrivateKey(wif, &bs, cmd.Rescan); err != nil {
		switch err {
		case wallet.ErrDuplicate:
			// Do not return duplicate key errors to the client.
			return nil, nil
		case wallet.ErrWalletLocked:
			return nil, btcjson.ErrWalletUnlockNeeded
		default:
			return nil, err
		}
	}

	// If the import was successful, reply with nil.
	return nil, nil
}

// KeypoolRefill handles the keypoolrefill command. Since we handle the keypool
// automatically this does nothing since refilling is never manually required.
func KeypoolRefill(icmd btcjson.Cmd) (interface{}, error) {
	return nil, nil
}

// NotifyNewBlockChainHeight notifies all websocket clients of a new
// blockchain height.  This sends the same notification as
// btcd, so this can probably be removed.
func (s *rpcServer) NotifyNewBlockChainHeight(bs *wallet.BlockStamp) {
	ntfn := btcws.NewBlockConnectedNtfn(bs.Hash.String(), bs.Height)
	mntfn, err := ntfn.MarshalJSON()
	// btcws notifications must always marshal without error.
	if err != nil {
		panic(err)
	}
	s.broadcasts <- mntfn
}

// NotifyBalances notifies an attached websocket clients of the current
// confirmed and unconfirmed account balances.
//
// TODO(jrick): Switch this to return a single JSON object
// (map[string]interface{}) of all accounts and their balances, instead of
// separate notifications for each account.
func (s *rpcServer) NotifyBalances() {
	for _, a := range AcctMgr.AllAccounts() {
		balance := a.CalculateBalance(1)
		unconfirmed := a.CalculateBalance(0) - balance
		s.NotifyWalletBalance(a.name, balance)
		s.NotifyWalletBalanceUnconfirmed(a.name, unconfirmed)
	}
}

// GetNewAddress handlesa getnewaddress request by returning a new
// address for an account.  If the account does not exist or the keypool
// ran out with a locked wallet, an appropiate error is returned.
func GetNewAddress(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetNewAddressCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	addr, err := a.NewAddress()
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
func GetRawChangeAddress(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcjson.GetRawChangeAddressCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	addr, err := a.NewChangeAddress()
	if err != nil {
		return nil, err
	}

	// Return the new payment address string.
	return addr.EncodeAddress(), nil
}

// GetReceivedByAccount handles a getreceivedbyaccount request by returning
// the total amount received by addresses of an account.
func GetReceivedByAccount(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcjson.GetReceivedByAccountCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	return a.TotalReceived(cmd.MinConf)
}

// GetTransaction handles a gettransaction request by returning details about
// a single transaction saved by wallet.
func GetTransaction(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.GetTransactionCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	txSha, err := btcwire.NewShaHashFromStr(cmd.Txid)
	if err != nil {
		return nil, btcjson.ErrDecodeHexString
	}

	accumulatedTxen := AcctMgr.GetTransaction(txSha)
	if len(accumulatedTxen) == 0 {
		return nil, btcjson.ErrNoTxInfo
	}

	bs, err := GetCurBlock()
	if err != nil {
		return nil, err
	}

	received := btcutil.Amount(0)
	var debits *txstore.Debits
	var debitAccount string
	var targetAddr string

	ret := btcjson.GetTransactionResult{
		Details:         []btcjson.GetTransactionDetailsResult{},
		WalletConflicts: []string{},
	}
	details := []btcjson.GetTransactionDetailsResult{}
	for _, e := range accumulatedTxen {
		for _, cred := range e.Tx.Credits() {
			// Change is ignored.
			if cred.Change() {
				continue
			}

			received += cred.Amount()

			var addr string
			// Errors don't matter here, as we only consider the
			// case where len(addrs) == 1.
			_, addrs, _, _ := cred.Addresses(activeNet.Params)
			if len(addrs) == 1 {
				addr = addrs[0].EncodeAddress()
				// The first non-change output address is considered the
				// target for sent transactions.
				if targetAddr == "" {
					targetAddr = addr
				}
			}

			details = append(details, btcjson.GetTransactionDetailsResult{
				Account:  e.Account,
				Category: cred.Category(bs.Height).String(),
				Amount:   cred.Amount().ToUnit(btcutil.AmountBTC),
				Address:  addr,
			})
		}

		if d, err := e.Tx.Debits(); err == nil {
			// There should only be a single debits record for any
			// of the account's transaction records.
			debits = &d
			debitAccount = e.Account
		}
	}

	totalAmount := received
	if debits != nil {
		totalAmount -= debits.InputAmount()
		info := btcjson.GetTransactionDetailsResult{
			Account:  debitAccount,
			Address:  targetAddr,
			Category: "send",
			// negative since it is a send
			Amount: (-debits.OutputAmount(true)).ToUnit(btcutil.AmountBTC),
			Fee:    debits.Fee().ToUnit(btcutil.AmountBTC),
		}
		ret.Fee += info.Fee
		// Add sent information to front.
		ret.Details = append(ret.Details, info)

	}
	ret.Details = append(ret.Details, details...)

	ret.Amount = totalAmount.ToUnit(btcutil.AmountBTC)

	// Generic information should be the same, so just use the first one.
	first := accumulatedTxen[0]
	ret.TxID = first.Tx.Tx().Sha().String()

	buf := bytes.NewBuffer(nil)
	buf.Grow(first.Tx.Tx().MsgTx().SerializeSize())
	err = first.Tx.Tx().MsgTx().Serialize(buf)
	if err != nil {
		return nil, err
	}
	ret.Hex = hex.EncodeToString(buf.Bytes())

	// TODO(oga) technically we have different time and
	// timereceived depending on if a transaction was send or
	// receive. We ideally should provide the correct numbers for
	// both. Right now they will always be the same
	ret.Time = first.Tx.Received().Unix()
	ret.TimeReceived = first.Tx.Received().Unix()
	if txr := first.Tx; txr.BlockHeight != -1 {
		txBlock, err := txr.Block()
		if err != nil {
			return nil, err
		}

		ret.BlockIndex = int64(first.Tx.Tx().Index())
		ret.BlockHash = txBlock.Hash.String()
		ret.BlockTime = txBlock.Time.Unix()
		ret.Confirmations = int64(txr.Confirmations(bs.Height))
	}
	// TODO(oga) if the tx is a coinbase we should set "generated" to true.
	// Since we do not mine this currently is never the case.
	return ret, nil
}

// ListAccounts handles a listaccounts request by returning a map of account
// names to their balances.
func ListAccounts(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.ListAccountsCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	// Return the map.  This will be marshaled into a JSON object.
	return AcctMgr.ListAccounts(cmd.MinConf), nil
}

// ListLockUnspent handles a listlockunspent request by returning an array of
// all locked outpoints.
func ListLockUnspent(icmd btcjson.Cmd) (interface{}, error) {
	// Due to our poor account support, this assumes only the default
	// account is available.  When the keystore and account heirarchies are
	// reversed, the locked outpoints mapping will cover all accounts.
	a, err := AcctMgr.Account("")
	if err != nil {
		return nil, err
	}

	return a.LockedOutpoints(), nil
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
func ListReceivedByAddress(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcjson.ListReceivedByAddressCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	// Intermediate data for each address.
	type AddrData struct {
		// Associated account.
		account *Account
		// Total amount received.
		amount btcutil.Amount
		// Number of confirmations of the last transaction.
		confirmations int32
	}

	// Intermediate data for all addresses.
	allAddrData := make(map[string]AddrData)

	bs, err := GetCurBlock()
	if err != nil {
		return nil, err
	}

	for _, account := range AcctMgr.AllAccounts() {
		if cmd.IncludeEmpty {
			// Create an AddrData entry for each active address in the account.
			// Otherwise we'll just get addresses from transactions later.
			for _, address := range account.SortedActivePaymentAddresses() {
				// There might be duplicates, just overwrite them.
				allAddrData[address] = AddrData{account: account}
			}
		}
		for _, record := range account.TxStore.Records() {
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
						// Address already present, check account consistency.
						if addrData.account != account {
							return nil, fmt.Errorf(
								"Address %v in both account %v and account %v",
								addrStr, addrData.account.name, account.name)
						}
						addrData.amount += credit.Amount()
						// Always overwrite confirmations with newer ones.
						addrData.confirmations = confirmations
					} else {
						addrData = AddrData{
							account:       account,
							amount:        credit.Amount(),
							confirmations: confirmations,
						}
					}
					allAddrData[addrStr] = addrData
				}
			}
		}
	}

	// Massage address data into output format.
	numAddresses := len(allAddrData)
	ret := make([]btcjson.ListReceivedByAddressResult, numAddresses, numAddresses)
	idx := 0
	for address, addrData := range allAddrData {
		ret[idx] = btcjson.ListReceivedByAddressResult{
			Account:       addrData.account.name,
			Address:       address,
			Amount:        addrData.amount.ToUnit(btcutil.AmountBTC),
			Confirmations: uint64(addrData.confirmations),
		}
		idx++
	}
	return ret, nil
}

// ListSinceBlock handles a listsinceblock request by returning an array of maps
// with details of sent and received wallet transactions since the given block.
func ListSinceBlock(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcjson.ListSinceBlockCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	client, err := accessClient()
	if err != nil {
		return nil, err
	}

	height := int32(-1)
	if cmd.BlockHash != "" {
		hash, err := btcwire.NewShaHashFromStr(cmd.BlockHash)
		if err != nil {
			return nil, DeserializationError{err}
		}
		block, err := client.GetBlock(hash)
		if err != nil {
			return nil, err
		}
		height = int32(block.Height())
	}

	bs, err := GetCurBlock()
	if err != nil {
		return nil, err
	}

	// For the result we need the block hash for the last block counted
	// in the blockchain due to confirmations. We send this off now so that
	// it can arrive asynchronously while we figure out the rest.
	gbh := client.GetBlockHashAsync(int64(bs.Height) + 1 - int64(cmd.TargetConfirmations))
	if err != nil {
		return nil, err
	}

	txInfoList, err := AcctMgr.ListSinceBlock(height, bs.Height,
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
func ListTransactions(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.ListTransactionsCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	return a.ListTransactions(cmd.From, cmd.Count)
}

// ListAddressTransactions handles a listaddresstransactions request by
// returning an array of maps with details of spent and received wallet
// transactions.  The form of the reply is identical to listtransactions,
// but the array elements are limited to transaction details which are
// about the addresess included in the request.
func ListAddressTransactions(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.ListAddressTransactionsCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
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

	return a.ListAddressTransactions(pkHashMap)
}

// ListAllTransactions handles a listalltransactions request by returning
// a map with details of sent and recevied wallet transactions.  This is
// similar to ListTransactions, except it takes only a single optional
// argument for the account name and replies with all transactions.
func ListAllTransactions(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.ListAllTransactionsCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	return a.ListAllTransactions()
}

// ListUnspent handles the listunspent command.
func ListUnspent(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcjson.ListUnspentCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

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

	return AcctMgr.ListUnspent(cmd.MinConf, cmd.MaxConf, addresses)
}

// LockUnspent handles the lockunspent command.
func LockUnspent(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcjson.LockUnspentCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	// Due to our poor account support, this assumes only the default
	// account is available.  When the keystore and account heirarchies are
	// reversed, the locked outpoints mapping will cover all accounts.
	a, err := AcctMgr.Account("")
	if err != nil {
		return nil, err
	}

	switch {
	case cmd.Unlock && len(cmd.Transactions) == 0:
		a.ResetLockedOutpoints()
	default:
		for _, input := range cmd.Transactions {
			txSha, err := btcwire.NewShaHashFromStr(input.Txid)
			if err != nil {
				return nil, ParseError{err}
			}
			op := btcwire.OutPoint{Hash: *txSha, Index: input.Vout}
			if cmd.Unlock {
				a.UnlockOutpoint(op)
			} else {
				a.LockOutpoint(op)
			}
		}
	}
	return true, nil
}

// sendPairs is a helper routine to reduce duplicated code when creating and
// sending payment transactions.
func sendPairs(icmd btcjson.Cmd, account string, amounts map[string]btcutil.Amount,
	minconf int) (interface{}, error) {

	client, err := accessClient()
	if err != nil {
		return nil, err
	}

	// Check that the account specified in the request exists.
	a, err := AcctMgr.Account(account)
	if err != nil {
		return nil, btcjson.ErrWalletInvalidAccountName
	}

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := a.txToPairs(amounts, minconf)
	if err != nil {
		switch err {
		case ErrNonPositiveAmount:
			return nil, ErrNeedPositiveAmount
		case wallet.ErrWalletLocked:
			return nil, btcjson.ErrWalletUnlockNeeded
		default:
			return nil, err
		}
	}

	// If a change address was added, sync wallet to disk and request
	// transaction notifications to the change address.
	if createdTx.changeAddr != nil {
		AcctMgr.ds.ScheduleWalletWrite(a)
		if err := AcctMgr.ds.FlushAccount(a); err != nil {
			return nil, fmt.Errorf("Cannot write account: %v", err)
		}
		err := client.NotifyReceived([]btcutil.Address{createdTx.changeAddr})
		if err != nil {
			return nil, err
		}
	}

	txSha, err := client.SendRawTransaction(createdTx.tx.MsgTx(), false)
	if err != nil {
		return nil, err
	}
	if err := handleSendRawTxReply(icmd, txSha, a, createdTx); err != nil {
		return nil, err
	}
	return txSha.String(), nil
}

// SendFrom handles a sendfrom RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to another payment
// address.  Leftover inputs not sent to the payment address or a fee for
// the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func SendFrom(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.SendFromCmd)
	if !ok {
		return nil, btcjson.ErrInternal
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

	return sendPairs(cmd, cmd.FromAccount, pairs, cmd.MinConf)
}

// SendMany handles a sendmany RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to any number of
// payment addresses.  Leftover inputs not sent to the payment address
// or a fee for the miner are sent back to a new address in the wallet.
// Upon success, the TxID for the created transaction is returned.
func SendMany(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.SendManyCmd)
	if !ok {
		return nil, btcjson.ErrInternal
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

	return sendPairs(cmd, cmd.FromAccount, pairs, cmd.MinConf)
}

// SendToAddress handles a sendtoaddress RPC request by creating a new
// transaction spending unspent transaction outputs for a wallet to another
// payment address.  Leftover inputs not sent to the payment address or a fee
// for the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.
func SendToAddress(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.SendToAddressCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	// Check that signed integer parameters are positive.
	if cmd.Amount < 0 {
		return nil, ErrNeedPositiveAmount
	}

	// Mock up map of address and amount pairs.
	pairs := map[string]btcutil.Amount{
		cmd.Address: btcutil.Amount(cmd.Amount),
	}

	return sendPairs(cmd, "", pairs, 1)
}

func handleSendRawTxReply(icmd btcjson.Cmd, txSha *btcwire.ShaHash, a *Account, txInfo *CreatedTx) error {
	// Add to transaction store.
	txr, err := a.TxStore.InsertTx(txInfo.tx, nil)
	if err != nil {
		log.Errorf("Error adding sent tx history: %v", err)
		return btcjson.ErrInternal
	}
	debits, err := txr.AddDebits(txInfo.inputs)
	if err != nil {
		log.Errorf("Error adding sent tx history: %v", err)
		return btcjson.ErrInternal
	}
	AcctMgr.ds.ScheduleTxStoreWrite(a)

	// Notify websocket clients of the transaction.
	bs, err := GetCurBlock()
	if err == nil {
		ltr, err := debits.ToJSON(a.Name(), bs.Height, a.Net())
		if err != nil {
			log.Errorf("Error adding sent tx history: %v", err)
			return btcjson.ErrInternal
		}
		for _, details := range ltr {
			server.NotifyNewTxDetails(a.Name(), details)
		}
	}

	// Disk sync tx and utxo stores.
	if err := AcctMgr.ds.FlushAccount(a); err != nil {
		log.Errorf("Cannot write account: %v", err)
		return err
	}

	// Notify websocket clients of account's new unconfirmed and
	// confirmed balance.
	confirmed := a.CalculateBalance(1)
	unconfirmed := a.CalculateBalance(0) - confirmed
	server.NotifyWalletBalance(a.name, confirmed)
	server.NotifyWalletBalanceUnconfirmed(a.name, unconfirmed)

	// The comments to be saved differ based on the underlying type
	// of the cmd, so switch on the type to check whether it is a
	// SendFromCmd or SendManyCmd.
	//
	// TODO(jrick): If message succeeded in being sent, save the
	// transaction details with comments.
	switch cmd := icmd.(type) {
	case *btcjson.SendFromCmd:
		_ = cmd.Comment
		_ = cmd.CommentTo

	case *btcjson.SendManyCmd:
		_ = cmd.Comment
	case *btcjson.SendToAddressCmd:
		_ = cmd.Comment
		_ = cmd.CommentTo
	}

	log.Infof("Successfully sent transaction %v", txSha)
	return nil
}

// SetTxFee sets the transaction fee per kilobyte added to transactions.
func SetTxFee(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.SetTxFeeCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	// Check that amount is not negative.
	if cmd.Amount < 0 {
		return nil, ErrNeedPositiveAmount
	}

	// Set global tx fee.
	TxFeeIncrement.Lock()
	TxFeeIncrement.i = btcutil.Amount(cmd.Amount)
	TxFeeIncrement.Unlock()

	// A boolean true result is returned upon success.
	return true, nil
}

// SignMessage signs the given message with the private key for the given
// address
func SignMessage(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.SignMessageCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	addr, err := btcutil.DecodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, ParseError{err}
	}

	ainfo, err := AcctMgr.Address(addr)
	if err != nil {
		return nil, btcjson.ErrInvalidAddressOrKey
	}

	pka := ainfo.(wallet.PubKeyAddress)
	privkey, err := pka.PrivKey()
	if err != nil {
		return nil, err
	}

	fullmsg := "Bitcoin Signed Message:\n" + cmd.Message
	sigbytes, err := btcec.SignCompact(btcec.S256(), privkey,
		btcwire.DoubleSha256([]byte(fullmsg)), ainfo.Compressed())
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.EncodeToString(sigbytes), nil
}

// CreateEncryptedWallet creates a new account with an encrypted
// wallet.  If an account with the same name as the requested account
// name already exists, an invalid account name error is returned to
// the client.
//
// Wallets will be created on TestNet3, or MainNet if btcwallet is run with
// the --mainnet option.
func CreateEncryptedWallet(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.CreateEncryptedWalletCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	err := AcctMgr.CreateEncryptedWallet([]byte(cmd.Passphrase))
	if err != nil {
		if err == ErrWalletExists {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	// A nil reply is sent upon successful wallet creation.
	return nil, nil
}

// RecoverAddresses recovers the next n addresses from an account's wallet.
func RecoverAddresses(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcws.RecoverAddressesCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	err = a.RecoverAddresses(cmd.N)
	return nil, err
}

// pendingTx is used for async fetching of transaction dependancies in
// SignRawTransaction.
type pendingTx struct {
	resp   btcrpcclient.FutureGetRawTransactionResult
	inputs []uint32 // list of inputs that care about this tx.
}

// SignRawTransaction handles the signrawtransaction command.
func SignRawTransaction(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcjson.SignRawTransactionCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	serializedTx, err := hex.DecodeString(cmd.RawTx)
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

		script, err := hex.DecodeString(rti.ScriptPubKey)
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
			redeemScript, err := hex.DecodeString(rti.RedeemScript)
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

	var client *rpcClient

	// Now we go and look for any inputs that we were not provided by
	// querying btcd with getrawtransaction. We queue up a bunch of async
	// requests and will wait for replies after we have checked the rest of
	// the arguments.
	requested := make(map[btcwire.ShaHash]*pendingTx)
	for _, txIn := range msgTx.TxIn {
		// Did we get this txin from the arguments?
		if _, ok := inputs[txIn.PreviousOutpoint]; ok {
			continue
		}

		// Are we already fetching this tx? If so mark us as interested
		// in this outpoint. (N.B. that any *sane* tx will only
		// reference each outpoint once, since anything else is a double
		// spend. We don't check this ourselves to save having to scan
		// the array, it will fail later if so).
		if ptx, ok := requested[txIn.PreviousOutpoint.Hash]; ok {
			ptx.inputs = append(ptx.inputs,
				txIn.PreviousOutpoint.Index)
			continue
		}

		// Never heard of this one before, request it.
		if client == nil {
			client, err = accessClient()
			if err != nil {
				return nil, err
			}
		}
		prevHash := &txIn.PreviousOutpoint.Hash
		requested[txIn.PreviousOutpoint.Hash] = &pendingTx{
			resp:   client.GetRawTransactionAsync(prevHash),
			inputs: []uint32{txIn.PreviousOutpoint.Index},
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
		input, ok := inputs[txIn.PreviousOutpoint]
		if !ok {
			// failure to find previous is actually an error since
			// we failed above if we don't have all the inputs.
			return nil, fmt.Errorf("%s:%d not found",
				txIn.PreviousOutpoint.Hash,
				txIn.PreviousOutpoint.Index)
		}

		// Set up our callbacks that we pass to btcscript so it can
		// look up the appropriate keys and scripts by address.
		getKey := btcscript.KeyClosure(func(addr btcutil.Address) (
			*ecdsa.PrivateKey, bool, error) {
			if len(keys) != 0 {
				wif, ok := keys[addr.EncodeAddress()]
				if !ok {
					return nil, false,
						errors.New("no key for address")
				}
				return wif.PrivKey.ToECDSA(), wif.CompressPubKey, nil
			}
			address, err := AcctMgr.Address(addr)
			if err != nil {
				return nil, false, err
			}

			pka, ok := address.(wallet.PubKeyAddress)
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
			address, err := AcctMgr.Address(addr)
			if err != nil {
				return nil, err
			}
			sa, ok := address.(wallet.ScriptAddress)
			if !ok {
				return nil, errors.New("address is not a script" +
					" address")
			}

			// TODO(oga) we could possible speed things up further
			// by returning the addresses, class and nrequired here
			// thus avoiding recomputing them.
			return sa.Script(), nil
		})

		// SigHashSingle inputs can only be signed if there's a
		// corresponding output. However this could be already signed,
		// so we always verify the output.
		if (hashType&btcscript.SigHashSingle) !=
			btcscript.SigHashSingle || i < len(msgTx.TxOut) {

			script, err := btcscript.SignTxOutput(activeNet.Params,
				msgTx, i, input, byte(hashType), getKey,
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
		engine, err := btcscript.NewScript(txIn.SignatureScript, input,
			i, msgTx, btcscript.ScriptBip16|
				btcscript.ScriptCanonicalSignatures)
		if err != nil || engine.Execute() != nil {
			complete = false
		}
	}

	buf := bytes.NewBuffer(nil)
	buf.Grow(msgTx.SerializeSize())

	// All returned errors (not OOM, which panics) encounted during
	// bytes.Buffer writes are unexpected.
	if err = msgTx.Serialize(buf); err != nil {
		panic(err)
	}

	return btcjson.SignRawTransactionResult{
		Hex:      hex.EncodeToString(buf.Bytes()),
		Complete: complete,
	}, nil
}

// Stop handles the stop command by shutting down the process after the request
// is handled.
func Stop(icmd btcjson.Cmd) (interface{}, error) {
	server.Stop()
	return "btcwallet stopping.", nil
}

// ValidateAddress handles the validateaddress command.
func ValidateAddress(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcjson.ValidateAddressCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	result := btcjson.ValidateAddressResult{}
	addr, err := btcutil.DecodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		// Use zero value (false) for IsValid.
		return result, nil
	}

	// We could put whether or not the address is a script here,
	// by checking the type of "addr", however, the reference
	// implementation only puts that information if the script is
	// "ismine", and we follow that behaviour.
	result.Address = addr.EncodeAddress()
	result.IsValid = true

	// We can't use AcctMgr.Address() here since we also need the account
	// name.
	if account, err := AcctMgr.AccountByAddress(addr); err == nil {
		// The address must be handled by this account, so we expect
		// this call to succeed without error.
		ainfo, err := account.Address(addr)
		if err != nil {
			panic(err)
		}

		result.IsMine = true
		result.Account = account.name

		if pka, ok := ainfo.(wallet.PubKeyAddress); ok {
			result.IsCompressed = pka.Compressed()
			result.PubKey = pka.ExportPubKey()

		} else if sa, ok := ainfo.(wallet.ScriptAddress); ok {
			result.IsScript = true
			addresses := sa.Addresses()
			addrStrings := make([]string, len(addresses))
			for i, a := range addresses {
				addrStrings[i] = a.EncodeAddress()
			}
			result.Addresses = addrStrings
			result.Hex = hex.EncodeToString(sa.Script())

			class := sa.ScriptClass()
			// script type
			result.Script = class.String()
			if class == btcscript.MultiSigTy {
				result.SigsRequired = sa.RequiredSigs()
			}
		}
	}

	return result, nil
}

// VerifyMessage handles the verifymessage command by verifying the provided
// compact signature for the given address and message.
func VerifyMessage(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcjson.VerifyMessageCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	addr, err := btcutil.DecodeAddress(cmd.Address, activeNet.Params)
	if err != nil {
		return nil, ParseError{err}
	}

	// First check we know about the address and get the keys.
	ainfo, err := AcctMgr.Address(addr)
	if err != nil {
		return nil, btcjson.ErrInvalidAddressOrKey
	}

	pka := ainfo.(wallet.PubKeyAddress)
	privkey, err := pka.PrivKey()
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
	pk, wasCompressed, err := btcec.RecoverCompact(btcec.S256(), sig,
		btcwire.DoubleSha256([]byte("Bitcoin Signed Message:\n"+
			cmd.Message)))
	if err != nil {
		return nil, err
	}

	// Return boolean if keys match.
	return (pk.X.Cmp(privkey.X) == 0 && pk.Y.Cmp(privkey.Y) == 0 &&
		ainfo.Compressed() == wasCompressed), nil
}

// WalletIsLocked handles the walletislocked extension request by
// returning the current lock state (false for unlocked, true for locked)
// of an account.  An error is returned if the requested account does not
// exist.
func WalletIsLocked(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcws.WalletIsLockedCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	a, err := AcctMgr.Account(cmd.Account)
	if err != nil {
		if err == ErrNotFound {
			return nil, btcjson.ErrWalletInvalidAccountName
		}
		return nil, err
	}

	return a.Wallet.IsLocked(), nil
}

// WalletLock handles a walletlock request by locking the all account
// wallets, returning an error if any wallet is not encrypted (for example,
// a watching-only wallet).
func WalletLock(icmd btcjson.Cmd) (interface{}, error) {
	err := AcctMgr.LockWallets()
	return nil, err
}

// WalletPassphrase responds to the walletpassphrase request by unlocking
// the wallet.  The decryption key is saved in the wallet until timeout
// seconds expires, after which the wallet is locked.
func WalletPassphrase(icmd btcjson.Cmd) (interface{}, error) {
	// Type assert icmd to access parameters.
	cmd, ok := icmd.(*btcjson.WalletPassphraseCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	if err := AcctMgr.UnlockWallets(cmd.Passphrase); err != nil {
		return nil, err
	}

	go func(timeout int64) {
		time.Sleep(time.Second * time.Duration(timeout))
		AcctMgr.Grab()
		defer AcctMgr.Release()
		err := AcctMgr.LockWallets()
		if err != nil {
			log.Warnf("Cannot lock account wallets: %v", err)
		}
	}(cmd.Timeout)

	return nil, nil
}

// WalletPassphraseChange responds to the walletpassphrasechange request
// by unlocking all accounts with the provided old passphrase, and
// re-encrypting each private key with an AES key derived from the new
// passphrase.
//
// If the old passphrase is correct and the passphrase is changed, all
// wallets will be immediately locked.
func WalletPassphraseChange(icmd btcjson.Cmd) (interface{}, error) {
	cmd, ok := icmd.(*btcjson.WalletPassphraseChangeCmd)
	if !ok {
		return nil, btcjson.ErrInternal
	}

	err := AcctMgr.ChangePassphrase([]byte(cmd.OldPassphrase),
		[]byte(cmd.NewPassphrase))
	if err == wallet.ErrWrongPassphrase {
		return nil, btcjson.ErrWalletPassphraseIncorrect
	}
	return nil, err
}

// AccountNtfn is a struct for marshalling any generic notification
// about a account for a websocket client.
//
// TODO(jrick): move to btcjson so it can be shared with clients?
type AccountNtfn struct {
	Account      string      `json:"account"`
	Notification interface{} `json:"notification"`
}

// NotifyWalletLockStateChange sends a notification to all websocket clients
// that the wallet has just been locked or unlocked.
func (s *rpcServer) NotifyWalletLockStateChange(account string, locked bool) {
	ntfn := btcws.NewWalletLockStateNtfn(account, locked)
	mntfn, err := ntfn.MarshalJSON()
	// If the marshal failed, it indicates that the btcws notification
	// struct contains a field with a type that is not marshalable.
	if err != nil {
		panic(err)
	}
	s.broadcasts <- mntfn
}

// NotifyWalletBalance sends a confirmed account balance notification
// to all websocket clients.
func (s *rpcServer) NotifyWalletBalance(account string, balance float64) {
	ntfn := btcws.NewAccountBalanceNtfn(account, balance, true)
	mntfn, err := ntfn.MarshalJSON()
	// If the marshal failed, it indicates that the btcws notification
	// struct contains a field with a type that is not marshalable.
	if err != nil {
		panic(err)
	}
	s.broadcasts <- mntfn
}

// NotifyWalletBalanceUnconfirmed sends a confirmed account balance
// notification to all websocket clients.
func (s *rpcServer) NotifyWalletBalanceUnconfirmed(account string, balance float64) {
	ntfn := btcws.NewAccountBalanceNtfn(account, balance, false)
	mntfn, err := ntfn.MarshalJSON()
	// If the marshal failed, it indicates that the btcws notification
	// struct contains a field with a type that is not marshalable.
	if err != nil {
		panic(err)
	}
	s.broadcasts <- mntfn
}

// NotifyNewTxDetails sends details of a new transaction to all websocket
// clients.
func (s *rpcServer) NotifyNewTxDetails(account string, details btcjson.ListTransactionsResult) {
	ntfn := btcws.NewTxNtfn(account, &details)
	mntfn, err := ntfn.MarshalJSON()
	// If the marshal failed, it indicates that the btcws notification
	// struct contains a field with a type that is not marshalable.
	if err != nil {
		panic(err)
	}
	s.broadcasts <- mntfn
}
