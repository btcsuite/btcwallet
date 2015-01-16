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

package chain

import (
	"errors"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcjson/v2/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcrpcclient"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/legacy/txstore"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// Client represents a persistent client connection to a bitcoin RPC server
// for information regarding the current best block chain.
type Client struct {
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
func NewClient(chainParams *chaincfg.Params, connect, user, pass string, certs []byte, disableTLS bool) (*Client, error) {
	client := Client{
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
		Host:                connect,
		Endpoint:            "ws",
		User:                user,
		Pass:                pass,
		Certificates:        certs,
		DisableConnectOnNew: true,
		DisableTLS:          disableTLS,
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
func (c *Client) Start() error {
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
func (c *Client) Stop() {
	c.quitMtx.Lock()
	defer c.quitMtx.Unlock()

	select {
	case <-c.quit:
	default:
		close(c.quit)
		c.Client.Shutdown()

		if !c.started {
			close(c.dequeueNotification)
		}
	}
}

// WaitForShutdown blocks until both the client has finished disconnecting
// and all handlers have exited.
func (c *Client) WaitForShutdown() {
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
	BlockConnected waddrmgr.BlockStamp

	// BlockDisconnected is a notifcation that the block described by the
	// BlockStamp was reorganized out of the best chain.
	BlockDisconnected waddrmgr.BlockStamp

	// RecvTx is a notification for a transaction which pays to a wallet
	// address.
	RecvTx struct {
		Tx    *btcutil.Tx    // Index is guaranteed to be set.
		Block *txstore.Block // nil if unmined
	}

	// RedeemingTx is a notification for a transaction which spends an
	// output controlled by the wallet.
	RedeemingTx struct {
		Tx    *btcutil.Tx    // Index is guaranteed to be set.
		Block *txstore.Block // nil if unmined
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
func (c *Client) Notifications() <-chan interface{} {
	return c.dequeueNotification
}

// BlockStamp returns the latest block notified by the client, or an error
// if the client has been shut down.
func (c *Client) BlockStamp() (*waddrmgr.BlockStamp, error) {
	select {
	case bs := <-c.currentBlock:
		return bs, nil
	case <-c.quit:
		return nil, errors.New("disconnected")
	}
}

// parseBlock parses a btcjson definition of the block a tx is mined it to the
// Block structure of the txstore package, and the block index.  This is done
// here since btcrpcclient doesn't parse this nicely for us.
func parseBlock(block *btcjson.BlockDetails) (blk *txstore.Block, idx int, err error) {
	if block == nil {
		return nil, btcutil.TxIndexUnknown, nil
	}
	blksha, err := wire.NewShaHashFromStr(block.Hash)
	if err != nil {
		return nil, btcutil.TxIndexUnknown, err
	}
	blk = &txstore.Block{
		Height: block.Height,
		Hash:   *blksha,
		Time:   time.Unix(block.Time, 0),
	}
	return blk, block.Index, nil
}

func (c *Client) onClientConnect() {
	log.Info("Established websocket RPC connection to btcd")
	c.enqueueNotification <- ClientConnected{}
}

func (c *Client) onBlockConnected(hash *wire.ShaHash, height int32) {
	c.enqueueNotification <- BlockConnected{Hash: *hash, Height: height}
}

func (c *Client) onBlockDisconnected(hash *wire.ShaHash, height int32) {
	c.enqueueNotification <- BlockDisconnected{Hash: *hash, Height: height}
}

func (c *Client) onRecvTx(tx *btcutil.Tx, block *btcjson.BlockDetails) {
	var blk *txstore.Block
	index := btcutil.TxIndexUnknown
	if block != nil {
		var err error
		blk, index, err = parseBlock(block)
		if err != nil {
			// Log and drop improper notification.
			log.Errorf("recvtx notification bad block: %v", err)
			return
		}
	}
	tx.SetIndex(index)
	c.enqueueNotification <- RecvTx{tx, blk}
}

func (c *Client) onRedeemingTx(tx *btcutil.Tx, block *btcjson.BlockDetails) {
	var blk *txstore.Block
	index := btcutil.TxIndexUnknown
	if block != nil {
		var err error
		blk, index, err = parseBlock(block)
		if err != nil {
			// Log and drop improper notification.
			log.Errorf("redeemingtx notification bad block: %v", err)
			return
		}
	}
	tx.SetIndex(index)
	c.enqueueNotification <- RedeemingTx{tx, blk}
}

func (c *Client) onRescanProgress(hash *wire.ShaHash, height int32, blkTime time.Time) {
	c.enqueueNotification <- &RescanProgress{hash, height, blkTime}
}

func (c *Client) onRescanFinished(hash *wire.ShaHash, height int32, blkTime time.Time) {
	c.enqueueNotification <- &RescanFinished{hash, height, blkTime}
}

// handler maintains a queue of notifications and the current state (best
// block) of the chain.
func (c *Client) handler() {
	hash, height, err := c.GetBestBlock()
	if err != nil {
		close(c.quit)
		c.wg.Done()
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

		case dequeue <- next:
			if n, ok := next.(BlockConnected); ok {
				bs = (*waddrmgr.BlockStamp)(&n)
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

		case c.currentBlock <- bs:

		case <-c.quit:
			break out
		}
	}
	close(c.dequeueNotification)
	c.wg.Done()
}
