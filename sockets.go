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
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcws"
	"github.com/conformal/go-socks"
	"io"
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
	// ErrBadAuth represents an error where a request is denied due to
	// a missing, incorrect, or duplicate authentication request.
	ErrBadAuth = errors.New("bad auth")

	// ErrNoAuth represents an error where authentication could not succeed
	// due to a missing Authorization HTTP header.
	ErrNoAuth = errors.New("no auth")

	// ErrConnRefused represents an error where a connection to another
	// process cannot be established.
	ErrConnRefused = errors.New("connection refused")

	// ErrConnLost represents an error where a connection to another
	// process cannot be established.
	ErrConnLost = errors.New("connection lost")

	// Adds a frontend listener channel
	addClient = make(chan clientContext)

	// Messages sent to this channel are sent to each connected frontend.
	allClients = make(chan []byte, 100)
)

// server holds the items the RPC server may need to access (auth,
// config, shutdown, etc.)
type server struct {
	wg        sync.WaitGroup
	listeners []net.Listener
	authsha   [sha256.Size]byte
}

type clientContext struct {
	send chan []byte
	quit chan struct{} // closed on disconnect
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
		return nil, errors.New("no valid listen address")
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
		if rmErr := os.Remove(certFile); rmErr != nil {
			log.Warnf("Cannot remove written certificates: %v", rmErr)
		}
		return err
	}

	log.Info("Done generating TLS certificates")
	return nil
}

// ParseRequest parses a command or notification out of a JSON-RPC request,
// returning any errors as a JSON-RPC error.
func ParseRequest(msg []byte) (btcjson.Cmd, *btcjson.Error) {
	cmd, err := btcjson.ParseMarshaledCmd(msg)
	if err != nil || cmd.Id() == nil {
		return cmd, &btcjson.ErrInvalidRequest
	}
	return cmd, nil
}

// ReplyToFrontend responds to a marshaled JSON-RPC request with a
// marshaled JSON-RPC response for both standard and extension
// (websocket) clients.  The returned error is ErrBadAuth if a
// missing, incorrect, or duplicate authentication request is
// received.
func (s *server) ReplyToFrontend(msg []byte, ws, authenticated bool) ([]byte, error) {
	cmd, jsonErr := ParseRequest(msg)
	var id interface{}
	if cmd != nil {
		id = cmd.Id()
	}

	// If client is not already authenticated, the parsed request must
	// be for authentication.
	authCmd, ok := cmd.(*btcws.AuthenticateCmd)
	if authenticated {
		if ok {
			// Duplicate auth request.
			return nil, ErrBadAuth
		}
	} else {
		if !ok {
			// The first unauthenticated request must be an auth request.
			return nil, ErrBadAuth
		}

		// Check credentials.
		login := authCmd.Username + ":" + authCmd.Passphrase
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
		authSha := sha256.Sum256([]byte(auth))
		cmp := subtle.ConstantTimeCompare(authSha[:], s.authsha[:])
		if cmp != 1 {
			return nil, ErrBadAuth
		}
		return nil, nil
	}

	if jsonErr != nil {
		response := btcjson.Reply{
			Id:    &id,
			Error: jsonErr,
		}
		mresponse, err := json.Marshal(response)
		// We expect the marshal to succeed.  If it doesn't, it
		// indicates that either jsonErr (which is created by us) or
		// the id itself (which was successfully unmashaled) are of
		// some non-marshalable type.
		if err != nil {
			panic(err)
		}
		return mresponse, nil
	}

	cReq := NewClientRequest(cmd, ws)
	rawResp := cReq.Handle()

	response := struct {
		Jsonrpc string           `json:"jsonrpc"`
		Id      interface{}      `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}{
		Jsonrpc: "1.0",
		Id:      id,
		Result:  rawResp.Result,
		Error:   rawResp.Error,
	}
	mresponse, err := json.Marshal(response)
	if err != nil {
		log.Errorf("Cannot marshal response: %v", err)
		response := btcjson.Reply{
			Id:    &id,
			Error: &btcjson.ErrInternal,
		}
		mresponse, err = json.Marshal(&response)
		// We expect this marshal to succeed.  If it doesn't, btcjson
		// returned an id with an non-marshalable type or ErrInternal
		// is just plain wrong.
		if err != nil {
			panic(err)
		}
	}

	return mresponse, nil
}

// ServeRPCRequest processes and replies to a JSON-RPC client request.
func (s *server) ServeRPCRequest(w http.ResponseWriter, r *http.Request) {
	body, err := btcjson.GetRaw(r.Body)
	if err != nil {
		log.Errorf("RPCS: Error getting JSON message: %v", err)
	}

	resp, err := s.ReplyToFrontend(body, false, true)
	if err == ErrBadAuth {
		http.Error(w, "401 Unauthorized.", http.StatusUnauthorized)
		return
	}
	if _, err := w.Write(resp); err != nil {
		log.Warnf("RPCS: could not respond to RPC request: %v", err)
	}
}

// clientResponseDuplicator listens for new wallet listener channels
// and duplicates messages sent to allClients to all connected clients.
func clientResponseDuplicator() {
	clients := make(map[clientContext]struct{})

	for {
		select {
		case cc := <-addClient:
			clients[cc] = struct{}{}

		case n := <-allClients:
			for cc := range clients {
				select {
				case <-cc.quit:
					delete(clients, cc)
				case cc.send <- n:
				}
			}
		}
	}
}

// NotifyBtcdConnection notifies a frontend of the current connection
// status of btcwallet to btcd.
func NotifyBtcdConnection(reply chan []byte) {
	if btcd, ok := CurrentServerConn().(*BtcdRPCConn); ok {
		ntfn := btcws.NewBtcdConnectedNtfn(btcd.Connected())
		mntfn, err := ntfn.MarshalJSON()
		// btcws notifications must always marshal without error.
		if err != nil {
			panic(err)
		}
		reply <- mntfn
	}
}

// stringQueue manages a queue of strings, reading from in and sending
// the oldest unsent to out.  This handler closes out and returns after
// in is closed and any queued items are sent.  Any reads on quit result
// in immediate shutdown of the handler.
func stringQueue(in <-chan string, out chan<- string, quit <-chan struct{}) {
	var q []string
	var dequeue chan<- string
	skipQueue := out
	var next string
out:
	for {
		select {
		case n, ok := <-in:
			if !ok {
				// Sender closed input channel.  Nil channel
				// and continue so the remaining queued
				// items may be sent.  If the queue is empty,
				// break out of the loop.
				in = nil
				if dequeue == nil {
					break out
				}
				continue
			}

			// Either send to out immediately if skipQueue is
			// non-nil (queue is empty) and reader is ready,
			// or append to the queue and send later.
			select {
			case skipQueue <- n:
			default:
				q = append(q, n)
				dequeue = out
				skipQueue = nil
				next = q[0]
			}

		case dequeue <- next:
			copy(q, q[1:])
			q[len(q)-1] = "" // avoid leak
			q = q[:len(q)-1]
			if len(q) == 0 {
				// If the input chan was closed and nil'd,
				// break out of the loop.
				if in == nil {
					break out
				}
				dequeue = nil
				skipQueue = out
			} else {
				next = q[0]
			}

		case <-quit:
			break out
		}
	}
	close(out)
}

// WSSendRecv is the handler for websocket client connections.  It loops
// forever (until disconnected), reading JSON-RPC requests and sending
// sending responses and notifications.
func (s *server) WSSendRecv(ws *websocket.Conn, remoteAddr string, authenticated bool) {
	// Clear the read deadline set before the websocket hijacked
	// the connection.
	if err := ws.SetReadDeadline(time.Time{}); err != nil {
		log.Warnf("Cannot remove read deadline: %v", err)
	}

	// Add client context so notifications duplicated to each
	// client are received by this client.
	recvQuit := make(chan struct{})
	sendQuit := make(chan struct{})
	cc := clientContext{
		send: make(chan []byte, 1), // buffer size is number of initial notifications
		quit: make(chan struct{}),
	}
	go func() {
		select {
		case <-recvQuit:
		case <-sendQuit:
		}
		log.Infof("Disconnected websocket client %s", remoteAddr)
		close(cc.quit)
	}()
	log.Infof("New websocket client %s", remoteAddr)

	NotifyBtcdConnection(cc.send) // TODO(jrick): clients should explicitly request this.
	addClient <- cc

	// received passes all received messages from the currently connected
	// frontend to the for-select loop.  It is closed when reading a
	// message from the websocket connection fails (presumably due to
	// a disconnected client).
	recvQueueIn := make(chan string)

	// Receive messages from websocket and send across jsonMsgs until
	// connection is lost
	go func() {
		for {
			var m string
			if err := websocket.Message.Receive(ws, &m); err != nil {
				select {
				case <-sendQuit:
					// Do not log error.

				default:
					if err != io.EOF {
						log.Warnf("Websocket receive failed from client %s: %v",
							remoteAddr, err)
					}
				}
				close(recvQueueIn)
				close(recvQuit)
				return
			}
			recvQueueIn <- m
		}
	}()

	// Manage queue of received messages for LIFO processing.
	recvQueueOut := make(chan string)
	go stringQueue(recvQueueIn, recvQueueOut, cc.quit)

	badAuth := make(chan struct{})
	sendResp := make(chan []byte)
	go func() {
	out:
		for m := range recvQueueOut {
			resp, err := s.ReplyToFrontend([]byte(m), true, authenticated)
			if err == ErrBadAuth {
				select {
				case badAuth <- struct{}{}:
				case <-cc.quit:
				}
				break out
			}

			// Authentication passed.
			authenticated = true

			select {
			case sendResp <- resp:
			case <-cc.quit:
				break out
			}
		}
		close(sendResp)
	}()

	const deadline time.Duration = 2 * time.Second

out:
	for {
		var m []byte
		var ok bool

		select {
		case <-badAuth:
			// Bad auth. Disconnect.
			log.Warnf("Disconnecting unauthorized websocket client %s", remoteAddr)
			break out

		case m = <-cc.send: // sends from external writers.  never closes.
		case m, ok = <-sendResp:
			if !ok {
				// Nothing left to send.  Return so the handler exits.
				break out
			}
		case <-cc.quit:
			break out
		}

		err := ws.SetWriteDeadline(time.Now().Add(deadline))
		if err != nil {
			log.Errorf("Cannot set write deadline on client %s: %v", remoteAddr, err)
			break out
		}
		err = websocket.Message.Send(ws, string(m))
		if err != nil {
			log.Warnf("Websocket send failed to client %s: %v", remoteAddr, err)
			break out
		}
	}
	close(sendQuit)
	log.Tracef("Leaving function WSSendRecv")
}

// NotifyNewBlockChainHeight notifies all frontends of a new
// blockchain height.  This sends the same notification as
// btcd, so this can probably be removed.
func NotifyNewBlockChainHeight(reply chan []byte, bs wallet.BlockStamp) {
	ntfn := btcws.NewBlockConnectedNtfn(bs.Hash.String(), bs.Height)
	mntfn, err := ntfn.MarshalJSON()
	// btcws notifications must always marshal without error.
	if err != nil {
		panic(err)
	}
	reply <- mntfn
}

var duplicateOnce sync.Once

// Start starts a HTTP server to provide standard RPC and extension
// websocket connections for any number of btcwallet frontends.
func (s *server) Start() {
	// A duplicator for notifications intended for all clients runs
	// in another goroutines.  Any such notifications are sent to
	// the allClients channel and then sent to each connected client.
	//
	// Use a sync.Once to insure no extra duplicators run.
	go duplicateOnce.Do(clientResponseDuplicator)

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
		if err := s.checkAuth(r); err != nil {
			log.Warnf("Unauthorized client connection attempt")
			http.Error(w, "401 Unauthorized.", http.StatusUnauthorized)
			return
		}
		s.ServeRPCRequest(w, r)
	})
	serveMux.HandleFunc("/frontend", func(w http.ResponseWriter, r *http.Request) {
		authenticated := false
		if err := s.checkAuth(r); err != nil {
			// If auth was supplied but incorrect, rather than simply being
			// missing, immediately terminate the connection.
			if err != ErrNoAuth {
				log.Warnf("Disconnecting improperly authorized websocket client")
				http.Error(w, "401 Unauthorized.", http.StatusUnauthorized)
				return
			}
		} else {
			authenticated = true
		}

		// A new Server instance is created rather than just creating the
		// handler closure since the default server will disconnect the
		// client if the origin is unset.
		wsServer := websocket.Server{
			Handler: websocket.Handler(func(ws *websocket.Conn) {
				s.WSSendRecv(ws, r.RemoteAddr, authenticated)
			}),
		}
		wsServer.ServeHTTP(w, r)
	})
	for _, listener := range s.listeners {
		s.wg.Add(1)
		go func(listener net.Listener) {
			log.Infof("RPCS: RPC server listening on %s", listener.Addr())
			if err := httpServer.Serve(listener); err != nil {
				log.Errorf("Listener for %s exited with error: %v",
					listener.Addr(), err)
			}
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
	if len(authhdr) == 0 {
		return ErrNoAuth
	}

	authsha := sha256.Sum256([]byte(authhdr[0]))
	cmp := subtle.ConstantTimeCompare(authsha[:], s.authsha[:])
	if cmp != 1 {
		return ErrBadAuth
	}
	return nil
}

// BtcdWS opens a websocket connection to a btcd instance.
func BtcdWS(certificates []byte) (*websocket.Conn, error) {
	url := fmt.Sprintf("wss://%s/ws", cfg.RPCConnect)
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
	login := cfg.BtcdUsername + ":" + cfg.BtcdPassword
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
		conn, err := proxy.Dial("tcp", cfg.RPCConnect)
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

// Handshake first checks that the websocket connection between btcwallet and
// btcd is valid, that is, that there are no mismatching settings between
// the two processes (such as running on different Bitcoin networks).  If the
// sanity checks pass, all wallets are set to be tracked against chain
// notifications from this btcd connection.
//
// TODO(jrick): Track and Rescan commands should be replaced with a
// single TrackSince function (or similar) which requests address
// notifications and performs the rescan since some block height.
func Handshake(rpc ServerConn) error {
	net, jsonErr := GetCurrentNet(rpc)
	if jsonErr != nil {
		return jsonErr
	}
	if net != activeNet.Net {
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
	NotifyNewBlockChainHeight(allClients, bs)
	NotifyBalances(allClients)

	// Get default account.  Only the default account is used to
	// track recently-seen blocks.
	a, err := AcctMgr.Account("")
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

		_, jsonErr := GetBlock(rpc, bs.Hash.String())
		if jsonErr != nil {
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
			err := AcctMgr.Rollback(bs.Height, &bs.Hash)
			if err != nil {
				return err
			}
		}

		// Set default account to be marked in sync with the current
		// blockstamp.  This invalidates the iterator.
		a.Wallet.SetSyncedWith(bs)

		// Begin tracking wallets against this btcd instance.
		AcctMgr.Track()
		if err := AcctMgr.RescanActiveAddresses(); err != nil {
			return err
		}
		// TODO: Only begin tracking new unspent outputs as a result
		// of the rescan.  This is also pretty racy, as a new block
		// could arrive between rescan and by the time the new outpoint
		// is added to btcd's websocket's unspent output set.
		AcctMgr.Track()

		// (Re)send any unmined transactions to btcd in case of a btcd restart.
		AcctMgr.ResendUnminedTxs()

		// Get current blockchain height and best block hash.
		return nil
	}

	// Iterator was invalid (wallet has never been synced) or there was a
	// huge chain fork + reorg (more than 20 blocks).
	AcctMgr.Track()
	if err := AcctMgr.RescanActiveAddresses(); err != nil {
		return err
	}
	// TODO: only begin tracking new unspent outputs as a result of the
	// rescan.  This is also racy (see comment for second Track above).
	AcctMgr.Track()
	AcctMgr.ResendUnminedTxs()
	return nil
}
