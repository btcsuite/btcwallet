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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/conformal/btcrpcclient"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/txstore"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"github.com/conformal/btcws"
)

// InvalidNotificationError describes an error due to an invalid chain server
// notification and should be warned by wallet, but does not indicate an
// problem with the current wallet state.
type InvalidNotificationError struct {
	error
}

var (
	// MismatchingNetworks represents an error where a client connection
	// to btcd cannot succeed due to btcwallet and btcd operating on
	// different bitcoin networks.
	ErrMismatchedNets = errors.New("mismatched networks")
)

const (
	// maxConcurrentClientRequests is the maximum number of
	// unhandled/running requests that the server will run for a websocket
	// client at a time.  Beyond this limit, additional request reads will
	// block until a running request handler finishes.  This limit exists to
	// prevent a single connection from causing a denial of service attack
	// with an unnecessarily large number of requests.
	maxConcurrentClientRequests = 20

	// maxUnhandledNotifications is the maximum number of still marshaled
	// and unhandled notifications.  If this limit is reached, the
	// btcrpcclient client notification handlers will begin blocking until
	// an unhandled notification is processed.
	maxUnhandledNotifications = 50
)

type blockSummary struct {
	hash   *btcwire.ShaHash
	height int32
}

type acceptedTx struct {
	tx    *btcutil.Tx
	block *btcws.BlockDetails // nil if unmined
}

// Notification types.  These are defined here and processed from from reading
// a notificationChan to avoid handling these notifications directly in
// btcrpcclient callbacks, which isn't very go-like and doesn't allow
// blocking client calls.
type (
	// Container type for any notification.
	notification interface {
		handleNotification() error
	}

	blockConnected    blockSummary
	blockDisconnected blockSummary
	recvTx            acceptedTx
	redeemingTx       acceptedTx
	rescanFinished    struct {
		error
	}
	rescanProgress int32
)

type notificationChan chan notification

func (c notificationChan) onBlockConnected(hash *btcwire.ShaHash, height int32) {
	c <- (blockConnected)(blockSummary{hash, height})
}

func (c notificationChan) onBlockDisconnected(hash *btcwire.ShaHash, height int32) {
	c <- (blockDisconnected)(blockSummary{hash, height})
}

func (c notificationChan) onRecvTx(tx *btcutil.Tx, block *btcws.BlockDetails) {
	c <- recvTx{tx, block}
}

func (c notificationChan) onRedeemingTx(tx *btcutil.Tx, block *btcws.BlockDetails) {
	c <- redeemingTx{tx, block}
}

func (c notificationChan) onRescanFinished(height int32) {
	c <- rescanFinished{error: nil}
}

func (c notificationChan) onRescanProgress(height int32) {
	c <- rescanProgress(height)
}

func (n blockConnected) handleNotification() error {
	// Update the blockstamp for the newly-connected block.
	bs := &wallet.BlockStamp{
		Height: n.height,
		Hash:   *n.hash,
	}
	curBlock.Lock()
	curBlock.BlockStamp = *bs
	curBlock.Unlock()

	AcctMgr.Grab()
	AcctMgr.BlockNotify(bs)
	AcctMgr.Release()

	// Pass notification to wallet clients too.
	if server != nil {
		// TODO: marshaling should be perfomred by the server, and
		// sent only to client that have requested the notification.
		marshaled, err := n.MarshalJSON()
		// The parsed notification is expected to be marshalable.
		if err != nil {
			panic(err)
		}
		server.broadcasts <- marshaled
	}

	return nil
}

// MarshalJSON creates the JSON encoding of the chain notification to pass
// to any connected wallet clients.  This should never error.
func (n blockConnected) MarshalJSON() ([]byte, error) {
	nn := btcws.NewBlockConnectedNtfn(n.hash.String(), n.height)
	return nn.MarshalJSON()
}

func (n blockDisconnected) handleNotification() error {
	AcctMgr.Grab()
	defer AcctMgr.Release()

	// Rollback Utxo and Tx data stores.
	if err := AcctMgr.Rollback(n.height, n.hash); err != nil {
		return err
	}

	// Pass notification to wallet clients too.
	if server != nil {
		// TODO: marshaling should be perfomred by the server, and
		// sent only to client that have requested the notification.
		marshaled, err := n.MarshalJSON()
		// A btcws.BlockDisconnectedNtfn is expected to marshal without error.
		// If it does, it indicates that one of its struct fields is of a
		// non-marshalable type.
		if err != nil {
			panic(err)
		}
		server.broadcasts <- marshaled
	}

	return nil
}

// MarshalJSON creates the JSON encoding of the chain notification to pass
// to any connected wallet clients.  This should never error.
func (n blockDisconnected) MarshalJSON() ([]byte, error) {
	nn := btcws.NewBlockDisconnectedNtfn(n.hash.String(), n.height)
	return nn.MarshalJSON()
}

func parseBlock(block *btcws.BlockDetails) (*txstore.Block, int, error) {
	if block == nil {
		return nil, btcutil.TxIndexUnknown, nil
	}
	blksha, err := btcwire.NewShaHashFromStr(block.Hash)
	if err != nil {
		return nil, btcutil.TxIndexUnknown, err
	}
	b := &txstore.Block{
		Height: block.Height,
		Hash:   *blksha,
		Time:   time.Unix(block.Time, 0),
	}
	return b, block.Index, nil
}

func (n recvTx) handleNotification() error {
	block, txIdx, err := parseBlock(n.block)
	if err != nil {
		return InvalidNotificationError{err}
	}
	n.tx.SetIndex(txIdx)

	bs, err := GetCurBlock()
	if err != nil {
		return fmt.Errorf("cannot get current block: %v", err)
	}

	AcctMgr.Grab()
	defer AcctMgr.Release()

	// For every output, find all accounts handling that output address (if any)
	// and record the received txout.
	for outIdx, txout := range n.tx.MsgTx().TxOut {
		var accounts []*Account
		// Errors don't matter here.  If addrs is nil, the range below
		// does nothing.
		_, addrs, _, _ := btcscript.ExtractPkScriptAddrs(txout.PkScript,
			activeNet.Params)
		for _, addr := range addrs {
			a, err := AcctMgr.AccountByAddress(addr)
			if err != nil {
				continue
			}
			accounts = append(accounts, a)
		}

		for _, a := range accounts {
			txr, err := a.TxStore.InsertTx(n.tx, block)
			if err != nil {
				return err
			}
			cred, err := txr.AddCredit(uint32(outIdx), false)
			if err != nil {
				return err
			}
			AcctMgr.ds.ScheduleTxStoreWrite(a)

			// Notify wallet clients of tx.  If the tx is unconfirmed, it is always
			// notified and the outpoint is marked as notified.  If the outpoint
			// has already been notified and is now in a block, a txmined notifiction
			// should be sent once to let wallet clients that all previous send/recvs
			// for this unconfirmed tx are now confirmed.
			op := *cred.OutPoint()
			previouslyNotifiedReq := NotifiedRecvTxRequest{
				op:       op,
				response: make(chan NotifiedRecvTxResponse),
			}
			NotifiedRecvTxChans.access <- previouslyNotifiedReq
			if <-previouslyNotifiedReq.response {
				NotifiedRecvTxChans.remove <- op
			} else {
				// Notify clients of new recv tx and mark as notified.
				NotifiedRecvTxChans.add <- op

				ltr, err := cred.ToJSON(a.Name(), bs.Height, a.Wallet.Net())
				if err != nil {
					return err
				}
				server.NotifyNewTxDetails(a.Name(), ltr)
			}

			// Notify clients of new account balance.
			confirmed := a.CalculateBalance(1)
			unconfirmed := a.CalculateBalance(0) - confirmed
			server.NotifyWalletBalance(a.name, confirmed)
			server.NotifyWalletBalanceUnconfirmed(a.name, unconfirmed)
		}
	}

	return nil
}

func (n redeemingTx) handleNotification() error {
	block, txIdx, err := parseBlock(n.block)
	if err != nil {
		return InvalidNotificationError{err}
	}
	n.tx.SetIndex(txIdx)

	AcctMgr.Grab()
	err = AcctMgr.RecordSpendingTx(n.tx, block)
	AcctMgr.Release()
	return err
}

func (n rescanFinished) handleNotification() error {
	AcctMgr.rm.MarkFinished(n)
	return nil
}

func (n rescanProgress) handleNotification() error {
	AcctMgr.rm.MarkProgress(n)
	return nil
}

type rpcClient struct {
	*btcrpcclient.Client // client to btcd
	chainNotifications   notificationChan
	wg                   sync.WaitGroup
}

func newRPCClient(certs []byte) (*rpcClient, error) {
	ntfns := make(notificationChan, maxUnhandledNotifications)
	client := rpcClient{
		chainNotifications: ntfns,
	}
	initializedClient := make(chan struct{})
	ntfnCallbacks := btcrpcclient.NotificationHandlers{
		OnClientConnected: func() {
			log.Info("Established connection to btcd")
			<-initializedClient

			// nil client to broadcast to all connected clients
			server.NotifyConnectionStatus(nil)

			err := client.Handshake()
			if err != nil {
				log.Errorf("Cannot complete handshake: %v", err)
				client.Stop()
			}
		},
		OnBlockConnected:    ntfns.onBlockConnected,
		OnBlockDisconnected: ntfns.onBlockDisconnected,
		OnRecvTx:            ntfns.onRecvTx,
		OnRedeemingTx:       ntfns.onRedeemingTx,
		OnRescanFinished:    ntfns.onRescanFinished,
		OnRescanProgress:    ntfns.onRescanProgress,
	}
	conf := btcrpcclient.ConnConfig{
		Host:         cfg.RPCConnect,
		Endpoint:     "ws",
		User:         cfg.BtcdUsername,
		Pass:         cfg.BtcdPassword,
		Certificates: certs,
	}
	c, err := btcrpcclient.New(&conf, &ntfnCallbacks)
	if err != nil {
		return nil, err
	}
	client.Client = c
	close(initializedClient)
	return &client, nil
}

func (c *rpcClient) Start() {
	c.wg.Add(1)
	go c.handleNotifications()
}

func (c *rpcClient) Stop() {
	if !c.Client.Disconnected() {
		log.Warn("Disconnecting chain server client connection")
		c.Client.Shutdown()
	}
	close(c.chainNotifications)
}

func (c *rpcClient) WaitForShutdown() {
	c.Client.WaitForShutdown()
	c.wg.Wait()
}

func (c *rpcClient) handleNotifications() {
	for n := range c.chainNotifications {
		err := n.handleNotification()
		if err != nil {
			switch e := err.(type) {
			case InvalidNotificationError:
				log.Warnf("Ignoring invalid notification: %v", e)
			default:
				log.Errorf("Cannot handle notification: %v", e)
			}
		}
	}
	c.wg.Done()
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
func (c *rpcClient) Handshake() error {
	net, err := c.GetCurrentNet()
	if err != nil {
		return err
	}
	if net != activeNet.Net {
		return ErrMismatchedNets
	}

	// Request notifications for connected and disconnected blocks.
	if err := c.NotifyBlocks(); err != nil {
		return err
	}

	// Get current best block.  If this is before than the oldest
	// saved block hash, assume that this btcd instance is not yet
	// synced up to a previous btcd that was last used with this
	// wallet.
	bs, err := GetCurBlock()
	if err != nil {
		return fmt.Errorf("cannot get best block: %v", err)
	}
	if server != nil {
		server.NotifyNewBlockChainHeight(&bs)
		server.NotifyBalances(nil)
	}

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

		if _, err := c.GetBlock(&bs.Hash); err != nil {
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
		if err := AcctMgr.RescanActiveAddresses(nil); err != nil {
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
	if err := AcctMgr.RescanActiveAddresses(&bs); err != nil {
		return err
	}
	// TODO: only begin tracking new unspent outputs as a result of the
	// rescan.  This is also racy (see comment for second Track above).
	AcctMgr.Track()
	AcctMgr.ResendUnminedTxs()
	return nil
}
