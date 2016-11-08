// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chain

import (
	"errors"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrrpcclient"
)

var requiredChainServerAPI = semver{major: 2, minor: 0, patch: 0}

// RPCClient represents a persistent client connection to a decred RPC server
// for information regarding the current best block chain.
type RPCClient struct {
	*dcrrpcclient.Client
	connConfig        *dcrrpcclient.ConnConfig // Work around unexported field
	chainParams       *chaincfg.Params
	reconnectAttempts int

	enqueueNotification       chan interface{}
	dequeueNotification       chan interface{}
	enqueueVotingNotification chan interface{}
	dequeueVotingNotification chan interface{}

	quit    chan struct{}
	wg      sync.WaitGroup
	started bool
	quitMtx sync.Mutex
}

// NewRPCClient creates a client connection to the server described by the
// connect string.  If disableTLS is false, the remote RPC certificate must be
// provided in the certs slice.  The connection is not established immediately,
// but must be done using the Start method.  If the remote server does not
// operate on the same bitcoin network as described by the passed chain
// parameters, the connection will be disconnected.
func NewRPCClient(chainParams *chaincfg.Params, connect, user, pass string, certs []byte,
	disableTLS bool, reconnectAttempts int) (*RPCClient, error) {

	if reconnectAttempts < 0 {
		return nil, errors.New("reconnectAttempts must be positive")
	}

	client := &RPCClient{
		connConfig: &dcrrpcclient.ConnConfig{
			Host:                 connect,
			Endpoint:             "ws",
			User:                 user,
			Pass:                 pass,
			Certificates:         certs,
			DisableAutoReconnect: true,
			DisableConnectOnNew:  true,
			DisableTLS:           disableTLS,
		},
		chainParams:               chainParams,
		reconnectAttempts:         reconnectAttempts,
		enqueueNotification:       make(chan interface{}),
		dequeueNotification:       make(chan interface{}),
		enqueueVotingNotification: make(chan interface{}),
		dequeueVotingNotification: make(chan interface{}),
		quit: make(chan struct{}),
	}
	ntfnCallbacks := &dcrrpcclient.NotificationHandlers{
		OnClientConnected:       client.onClientConnect,
		OnBlockConnected:        client.onBlockConnected,
		OnBlockDisconnected:     client.onBlockDisconnected,
		OnRelevantTxAccepted:    client.onRelevantTxAccepted,
		OnReorganization:        client.onReorganization,
		OnWinningTickets:        client.onWinningTickets,
		OnSpentAndMissedTickets: client.onSpentAndMissedTickets,
		OnStakeDifficulty:       client.onStakeDifficulty,
	}
	rpcClient, err := dcrrpcclient.New(client.connConfig, ntfnCallbacks)
	if err != nil {
		return nil, err
	}
	client.Client = rpcClient
	return client, nil
}

// Start attempts to establish a client connection with the remote server.
// If successful, handler goroutines are started to process notifications
// sent by the server.  After a limited number of connection attempts, this
// function gives up, and therefore will not block forever waiting for the
// connection to be established to a server that may not exist.
func (c *RPCClient) Start() error {
	err := c.Connect(c.reconnectAttempts)
	if err != nil {
		return err
	}

	// Verify that the server is running on the expected network.
	net, err := c.GetCurrentNet()
	if err != nil {
		c.Disconnect()
		return err
	}
	if net != c.chainParams.Net {
		c.Disconnect()
		return errors.New("mismatched networks")
	}

	// Ensure the RPC server has a compatible API version.
	var serverAPI semver
	versionResult, err := c.Version()
	if err == nil {
		serverAPI = semver{
			major: versionResult.Major,
			minor: versionResult.Minor,
			patch: versionResult.Patch,
		}
	}
	if !semverCompatible(requiredChainServerAPI, serverAPI) {
		return errors.New("consensus JSON-RPC server does not have a " +
			"compatible API version")
	}

	c.quitMtx.Lock()
	c.started = true
	c.quitMtx.Unlock()

	c.wg.Add(2)
	go c.handler()
	go c.handlerVoting()
	return nil
}

// Stop disconnects the client and signals the shutdown of all goroutines
// started by Start.
func (c *RPCClient) Stop() {
	c.quitMtx.Lock()
	select {
	case <-c.quit:
	default:
		close(c.quit)
		c.Client.Shutdown()

		if !c.started {
			close(c.dequeueNotification)
			close(c.dequeueVotingNotification)
		}
	}
	c.quitMtx.Unlock()
}

// WaitForShutdown blocks until both the client has finished disconnecting
// and all handlers have exited.
func (c *RPCClient) WaitForShutdown() {
	c.Client.WaitForShutdown()
	c.wg.Wait()
}

// Notification types.  These are defined here and processed from from reading
// a notificationChan to avoid handling these notifications directly in
// dcrrpcclient callbacks, which isn't very Go-like and doesn't allow
// blocking client calls.
type (
	// ClientConnected is a notification for when a client connection is
	// opened or reestablished to the chain server.
	ClientConnected struct{}

	// BlockConnected is a notification for a newly-attached block to the
	// best chain.
	BlockConnected struct {
		BlockHeader  []byte
		Transactions [][]byte
	}

	// BlockDisconnected is a notifcation that the block described by the
	// BlockStamp was reorganized out of the best chain.
	BlockDisconnected struct {
		BlockHeader []byte
	}

	// RelevantTxAccepted is a notification that a transaction accepted by
	// mempool passed the client's transaction filter.
	RelevantTxAccepted struct {
		Transaction []byte
	}

	// Reorganization is a notification that a reorg has happen with the new
	// old and new tip included.
	Reorganization struct {
		OldHash   *chainhash.Hash
		OldHeight int64
		NewHash   *chainhash.Hash
		NewHeight int64
	}

	// WinningTickets is a notification with the winning tickets (and the
	// block they are in.
	WinningTickets struct {
		BlockHash   *chainhash.Hash
		BlockHeight int64
		Tickets     []*chainhash.Hash
	}

	// MissedTickets is a notifcation for tickets that have been missed.
	MissedTickets struct {
		BlockHash   *chainhash.Hash
		BlockHeight int64
		Tickets     []*chainhash.Hash
	}

	// StakeDifficulty is a notification for the current stake difficulty.
	StakeDifficulty struct {
		BlockHash   *chainhash.Hash
		BlockHeight int64
		StakeDiff   int64
	}
)

// Notifications returns a channel of parsed notifications sent by the remote
// decred RPC server.  This channel must be continually read or the process
// may abort for running out memory, as unread notifications are queued for
// later reads.
func (c *RPCClient) Notifications() <-chan interface{} {
	return c.dequeueNotification
}

// NotificationsVoting returns a channel of parsed voting notifications sent
// by the remote RPC server.  This channel must be continually read or the
// process may abort for running out memory, as unread notifications are
// queued for later reads.
func (c *RPCClient) NotificationsVoting() <-chan interface{} {
	return c.dequeueVotingNotification
}

func (c *RPCClient) onClientConnect() {
	select {
	case c.enqueueNotification <- ClientConnected{}:
	case <-c.quit:
	}
}

func (c *RPCClient) onBlockConnected(header []byte, transactions [][]byte) {
	select {
	case c.enqueueNotification <- BlockConnected{
		BlockHeader:  header,
		Transactions: transactions,
	}:
	case <-c.quit:
	}
}

func (c *RPCClient) onBlockDisconnected(header []byte) {
	select {
	case c.enqueueNotification <- BlockDisconnected{
		BlockHeader: header,
	}:
	case <-c.quit:
	}
}

func (c *RPCClient) onRelevantTxAccepted(transaction []byte) {
	select {
	case c.enqueueNotification <- RelevantTxAccepted{
		Transaction: transaction,
	}:
	case <-c.quit:
	}
}

// onReorganization handles reorganization notifications and passes them
// downstream to the notifications queue.
func (c *RPCClient) onReorganization(oldHash *chainhash.Hash, oldHeight int32,
	newHash *chainhash.Hash, newHeight int32) {
	select {
	case c.enqueueNotification <- Reorganization{
		oldHash,
		int64(oldHeight),
		newHash,
		int64(newHeight),
	}:
	case <-c.quit:
	}
}

// onWinningTickets handles winning tickets notifications data and passes it
// downstream to the notifications queue.
func (c *RPCClient) onWinningTickets(hash *chainhash.Hash, height int64,
	tickets []*chainhash.Hash) {
	select {
	case c.enqueueVotingNotification <- WinningTickets{
		hash,
		height,
		tickets,
	}:
	case <-c.quit:
	}
}

// onSpentAndMissedTickets handles missed tickets notifications data and passes
// it downstream to the notifications queue.
func (c *RPCClient) onSpentAndMissedTickets(hash *chainhash.Hash,
	height int64,
	stakeDiff int64,
	tickets map[chainhash.Hash]bool) {

	var missedTickets []*chainhash.Hash

	// Copy the missing ticket hashes to a slice.
	for ticket, isSpent := range tickets {
		newTicket := ticket
		if !isSpent { // if missed
			missedTickets = append(missedTickets, &newTicket)
		}
	}

	select {
	case c.enqueueVotingNotification <- MissedTickets{
		hash,
		height,
		missedTickets,
	}:
	case <-c.quit:
	}
}

// onStakeDifficulty handles stake difficulty notifications data and passes it
// downstream to the notification queue.
func (c *RPCClient) onStakeDifficulty(hash *chainhash.Hash,
	height int64,
	stakeDiff int64) {

	select {
	case c.enqueueNotification <- StakeDifficulty{
		hash,
		height,
		stakeDiff,
	}:
	case <-c.quit:
	}
}

// handler maintains a queue of notifications and the current state (best
// block) of the chain.
func (c *RPCClient) handler() {
	// TODO: Rather than leaving this as an unbounded queue for all types of
	// notifications, try dropping ones where a later enqueued notification
	// can fully invalidate one waiting to be processed.  For example,
	// blockconnected notifications for greater block heights can remove the
	// need to process earlier blockconnected notifications still waiting
	// here.

	var notifications []interface{}
	enqueue := c.enqueueNotification
	var dequeue chan interface{}
	var next interface{}
	pingChan := time.After(time.Minute)
out:
	for {
		select {
		case n, ok := <-enqueue:
			if !ok {
				// If no notifications are queued for handling,
				// the queue is finished.
				if len(notifications) == 0 {
					break out
				}
				// nil channel so no more reads can occur.
				enqueue = nil
				continue
			}
			if len(notifications) == 0 {
				next = n
				dequeue = c.dequeueNotification
			}
			notifications = append(notifications, n)
			pingChan = time.After(time.Minute)

		case dequeue <- next:
			notifications[0] = nil
			notifications = notifications[1:]
			if len(notifications) != 0 {
				next = notifications[0]
			} else {
				// If no more notifications can be enqueued, the
				// queue is finished.
				if enqueue == nil {
					break out
				}
				dequeue = nil
			}

		case <-pingChan:
			// No notifications were received in the last 60s.
			// Ensure the connection is still active by making a new
			// request to the server.
			// TODO: A minute timeout is used to prevent the handler
			// loop from blocking here forever, but this is much larger
			// than it needs to be due to dcrd processing websocket
			// requests synchronously (see
			// https://github.com/btcsuite/btcd/issues/504).  Decrease
			// this to something saner like 3s when the above issue is
			// fixed.
			type sessionResult struct {
				err error
			}
			sessionResponse := make(chan sessionResult, 1)
			go func() {
				_, err := c.Session()
				sessionResponse <- sessionResult{err}
			}()

			select {
			case resp := <-sessionResponse:
				if resp.err != nil {
					log.Errorf("Failed to receive session "+
						"result: %v", resp.err)
					c.Stop()
					break out
				}
				pingChan = time.After(time.Minute)

			case <-time.After(time.Minute):
				log.Errorf("Timeout waiting for session RPC")
				c.Stop()
				break out
			}

		case <-c.quit:
			break out
		}
	}

	c.Stop()
	close(c.dequeueNotification)
	c.wg.Done()
}

// handler maintains a queue of notifications and the current state (best
// block) of the chain.
func (c *RPCClient) handlerVoting() {
	var notifications []interface{}
	enqueue := c.enqueueVotingNotification
	var dequeue chan interface{}
	var next interface{}
out:
	for {
		select {
		case n, ok := <-enqueue:
			if !ok {
				// If no notifications are queued for handling,
				// the queue is finished.
				if len(notifications) == 0 {
					break out
				}
				// nil channel so no more reads can occur.
				enqueue = nil
				continue
			}
			if len(notifications) == 0 {
				next = n
				dequeue = c.dequeueVotingNotification
			}
			notifications = append(notifications, n)

		case dequeue <- next:
			notifications[0] = nil
			notifications = notifications[1:]
			if len(notifications) != 0 {
				next = notifications[0]
			} else {
				// If no more notifications can be enqueued, the
				// queue is finished.
				if enqueue == nil {
					break out
				}
				dequeue = nil
			}

		case <-c.quit:
			break out
		}
	}
	close(c.dequeueVotingNotification)
	c.wg.Done()
}

// POSTClient creates the equivalent HTTP POST dcrrpcclient.Client.
func (c *RPCClient) POSTClient() (*dcrrpcclient.Client, error) {
	configCopy := *c.connConfig
	configCopy.HTTPPostMode = true
	return dcrrpcclient.New(&configCopy, nil)
}
