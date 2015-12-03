/*
 * Copyright (c) 2013-2015 The btcsuite developers
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

package chain

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcrpcclient"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// Client allows multiple bitcoin backends to be used. It is primarily designed with the btcrpcclient in mind.
// See https://godoc.org/github.com/btcsuite/btcrpcclient
type Client interface {
	// Start attempts to establish a client connection with the remote server.
	Start() error
	// Stop disconnects the client.
	Stop()
	// WaitForShutdown waits for the client to shutdown.
	WaitForShutdown()

	// BlockStamp returns the latest block notified by the client, or an error
	// if the client has been shut down.
	BlockStamp() (*waddrmgr.BlockStamp, error)

	// Rescan rescans the block chain starting from the provided starting block
	// to the end of the longest chain for transactions that pay to the passed
	// addresses and transactions which spend the passed outpoints.
	Rescan(startBlock *wire.ShaHash, addresses []btcutil.Address, outpoints []*wire.OutPoint) error

	// NotifyBlocks registers the client to receive notifications when blocks are
	// connected and disconnected from the main chain. The notifications are
	// delivered to the notification handlers associated with the client. Calling
	// this function has no effect if there are no notification handlers and will
	// result in an error if the client is configured to run in HTTP POST mode.
	NotifyBlocks() error

	// Notifications returns a channel of parsed notifications sent by the remote
	// bitcoin RPC server.
	Notifications() <-chan interface{}

	// GetBlock returns a raw block from the server given its hash.
	GetBlock(blockHash *wire.ShaHash) (*btcutil.Block, error)

	// SendRawTransaction submits the encoded transaction to the server which
	// will then relay it to the network.
	SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (*wire.ShaHash, error)

	// NotifyReceived registers the client to receive notifications every time a
	// new transaction which pays to one of the passed addresses is accepted to
	// memory pool or in a block connected to the block chain.
	NotifyReceived(addresses []btcutil.Address) error

	// RawRequest allows the caller to send a raw or custom request to the server.
	RawRequest(method string, params []json.RawMessage) (json.RawMessage, error)

	// GetInfo returns miscellaneous info regarding the RPC server. The returned
	// info object may be void of wallet information if the remote server does
	// not include wallet functionality.
	GetInfo() (*btcjson.InfoWalletResult, error)

	// GetBlockHashAsync returns an instance of a type that can be used to get
	// the result of the RPC at some future time by invoking the Receive function
	// on the returned instance.
	GetBlockHashAsync(blockHeight int64) btcrpcclient.FutureGetBlockHashResult

	// GetBlockVerbose returns a data structure from the server with information
	// about a block given its hash.
	GetBlockVerbose(blockHash *wire.ShaHash, verboseTx bool) (*btcjson.GetBlockVerboseResult, error)

	// GetRawTransactionAsync returns an instance of a type that can be used to get the result of the RPC at some future time by invoking the Receive function on the returned instance.
	GetRawTransactionAsync(txHash *wire.ShaHash) btcrpcclient.FutureGetRawTransactionResult
}

// BTCRPCClient represents a persistent client connection to a bitcoin RPC server
// for information regarding the current best block chain.
type BTCRPCClient struct {
	*btcrpcclient.Client
	chainParams *chaincfg.Params

	enqueueNotification chan interface{}
	dequeueNotification chan interface{}
	currentBlock        chan *waddrmgr.BlockStamp

	quit    chan struct{}
	wg      sync.WaitGroup
	started bool
	quitMtx sync.Mutex
}

// NewClient creates a client connection to the server described by the connect
// string.  If disableTLS is false, the remote RPC certificate must be provided
// in the certs slice.  The connection is not established immediately, but must
// be done using the Start method.  If the remote server does not operate on
// the same bitcoin network as described by the passed chain parameters, the
// connection will be disconnected.
func NewClient(chainParams *chaincfg.Params, connect, user, pass string, certs []byte, disableTLS bool) (*BTCRPCClient, error) {
	client := BTCRPCClient{
		chainParams:         chainParams,
		enqueueNotification: make(chan interface{}),
		dequeueNotification: make(chan interface{}),
		currentBlock:        make(chan *waddrmgr.BlockStamp),
		quit:                make(chan struct{}),
	}
	ntfnCallbacks := btcrpcclient.NotificationHandlers{
		OnClientConnected:   client.onClientConnect,
		OnBlockConnected:    client.onBlockConnected,
		OnBlockDisconnected: client.onBlockDisconnected,
		OnRecvTx:            client.onRecvTx,
		OnRedeemingTx:       client.onRedeemingTx,
		OnRescanFinished:    client.onRescanFinished,
		OnRescanProgress:    client.onRescanProgress,
	}
	conf := btcrpcclient.ConnConfig{
		Host:                 connect,
		Endpoint:             "ws",
		User:                 user,
		Pass:                 pass,
		Certificates:         certs,
		DisableAutoReconnect: true,
		DisableConnectOnNew:  true,
		DisableTLS:           disableTLS,
	}
	c, err := btcrpcclient.New(&conf, &ntfnCallbacks)
	if err != nil {
		return nil, err
	}
	client.Client = c
	return &client, nil
}

// Start attempts to establish a client connection with the remote server.
// If successful, handler goroutines are started to process notifications
// sent by the server.  After a limited number of connection attempts, this
// function gives up, and therefore will not block forever waiting for the
// connection to be established to a server that may not exist.
func (c *BTCRPCClient) Start() error {
	err := c.Connect(5) // attempt connection 5 tries at most
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

	c.quitMtx.Lock()
	c.started = true
	c.quitMtx.Unlock()

	c.wg.Add(1)
	go c.handler()
	return nil
}

// Stop disconnects the client and signals the shutdown of all goroutines
// started by Start.
func (c *BTCRPCClient) Stop() {
	c.quitMtx.Lock()
	select {
	case <-c.quit:
	default:
		close(c.quit)
		c.Client.Shutdown()

		if !c.started {
			close(c.dequeueNotification)
		}
	}
	c.quitMtx.Unlock()
}

// WaitForShutdown blocks until both the client has finished disconnecting
// and all handlers have exited.
func (c *BTCRPCClient) WaitForShutdown() {
	c.Client.WaitForShutdown()
	c.wg.Wait()
}

// Notification types.  These are defined here and processed from from reading
// a notificationChan to avoid handling these notifications directly in
// btcrpcclient callbacks, which isn't very Go-like and doesn't allow
// blocking client calls.
type (
	// ClientConnected is a notification for when a client connection is
	// opened or reestablished to the chain server.
	ClientConnected struct{}

	// BlockConnected is a notification for a newly-attached block to the
	// best chain.
	BlockConnected wtxmgr.BlockMeta

	// BlockDisconnected is a notifcation that the block described by the
	// BlockStamp was reorganized out of the best chain.
	BlockDisconnected wtxmgr.BlockMeta

	// RelevantTx is a notification for a transaction which spends wallet
	// inputs or pays to a watched address.
	RelevantTx struct {
		TxRecord *wtxmgr.TxRecord
		Block    *wtxmgr.BlockMeta // nil if unmined
	}

	// RescanProgress is a notification describing the current status
	// of an in-progress rescan.
	RescanProgress struct {
		Hash   *wire.ShaHash
		Height int32
		Time   time.Time
	}

	// RescanFinished is a notification that a previous rescan request
	// has finished.
	RescanFinished struct {
		Hash   *wire.ShaHash
		Height int32
		Time   time.Time
	}
)

// Notifications returns a channel of parsed notifications sent by the remote
// bitcoin RPC server.  This channel must be continually read or the process
// may abort for running out memory, as unread notifications are queued for
// later reads.
func (c *BTCRPCClient) Notifications() <-chan interface{} {
	return c.dequeueNotification
}

// BlockStamp returns the latest block notified by the client, or an error
// if the client has been shut down.
func (c *BTCRPCClient) BlockStamp() (*waddrmgr.BlockStamp, error) {
	select {
	case bs := <-c.currentBlock:
		return bs, nil
	case <-c.quit:
		return nil, errors.New("disconnected")
	}
}

// parseBlock parses a btcws definition of the block a tx is mined it to the
// Block structure of the wtxmgr package, and the block index.  This is done
// here since btcrpcclient doesn't parse this nicely for us.
func parseBlock(block *btcjson.BlockDetails) (*wtxmgr.BlockMeta, error) {
	if block == nil {
		return nil, nil
	}
	blksha, err := wire.NewShaHashFromStr(block.Hash)
	if err != nil {
		return nil, err
	}
	blk := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Height: block.Height,
			Hash:   *blksha,
		},
		Time: time.Unix(block.Time, 0),
	}
	return blk, nil
}

func (c *BTCRPCClient) onClientConnect() {
	select {
	case c.enqueueNotification <- ClientConnected{}:
	case <-c.quit:
	}
}

func (c *BTCRPCClient) onBlockConnected(hash *wire.ShaHash, height int32, time time.Time) {
	select {
	case c.enqueueNotification <- BlockConnected{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: time,
	}:
	case <-c.quit:
	}
}

func (c *BTCRPCClient) onBlockDisconnected(hash *wire.ShaHash, height int32, time time.Time) {
	select {
	case c.enqueueNotification <- BlockDisconnected{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: time,
	}:
	case <-c.quit:
	}
}

func (c *BTCRPCClient) onRecvTx(tx *btcutil.Tx, block *btcjson.BlockDetails) {
	blk, err := parseBlock(block)
	if err != nil {
		// Log and drop improper notification.
		log.Errorf("recvtx notification bad block: %v", err)
		return
	}

	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx.MsgTx(), time.Now())
	if err != nil {
		log.Errorf("Cannot create transaction record for relevant "+
			"tx: %v", err)
		return
	}
	select {
	case c.enqueueNotification <- RelevantTx{rec, blk}:
	case <-c.quit:
	}
}

func (c *BTCRPCClient) onRedeemingTx(tx *btcutil.Tx, block *btcjson.BlockDetails) {
	// Handled exactly like recvtx notifications.
	c.onRecvTx(tx, block)
}

func (c *BTCRPCClient) onRescanProgress(hash *wire.ShaHash, height int32, blkTime time.Time) {
	select {
	case c.enqueueNotification <- &RescanProgress{hash, height, blkTime}:
	case <-c.quit:
	}
}

func (c *BTCRPCClient) onRescanFinished(hash *wire.ShaHash, height int32, blkTime time.Time) {
	select {
	case c.enqueueNotification <- &RescanFinished{hash, height, blkTime}:
	case <-c.quit:
	}

}

// handler maintains a queue of notifications and the current state (best
// block) of the chain.
func (c *BTCRPCClient) handler() {
	hash, height, err := c.GetBestBlock()
	if err != nil {
		log.Errorf("Failed to receive best block from chain server: %v", err)
		c.Stop()
		c.wg.Done()
		return
	}

	bs := &waddrmgr.BlockStamp{Hash: *hash, Height: height}

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
			if n, ok := next.(BlockConnected); ok {
				bs = &waddrmgr.BlockStamp{
					n.Height,
					n.Hash,
				}
			}

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
			// then it needs to be due to btcd processing websocket
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

		case c.currentBlock <- bs:

		case <-c.quit:
			break out
		}
	}

	c.Stop()
	close(c.dequeueNotification)
	c.wg.Done()
}
