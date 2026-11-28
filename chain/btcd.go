// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/btcutil/v2/gcs/builder"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// blockStampSnapshot pairs the last-dequeued legacy BlockStamp with the
// unactivated intake BlockStamp so BlockStamp() selects the active view
// atomically even when the handler goroutine is already parked in select.
type blockStampSnapshot struct {
	dequeued     *waddrmgr.BlockStamp
	intake       *waddrmgr.BlockStamp
	legacyActive *atomic.Bool
}

// current returns the dequeued legacy stamp once legacy notifications are
// active, or the intake stamp while the legacy queue remains unactivated.
func (b blockStampSnapshot) current() *waddrmgr.BlockStamp {
	if b.legacyActive.Load() {
		return b.dequeued
	}

	return b.intake
}

// RPCClient represents a persistent client connection to a bitcoin RPC server
// for information regarding the current best block chain.
type RPCClient struct {
	*rpcclient.Client
	connConfig        *rpcclient.ConnConfig // Work around unexported field
	chainParams       *chaincfg.Params
	reconnectAttempts int

	enqueueNotification chan interface{}
	dequeueNotification chan interface{}
	eventStream         *chainEventStream
	currentBlock        chan blockStampSnapshot

	// legacyNotificationsActive enables unbounded legacy buffering once
	// Notifications() or Rescan() is called.
	legacyNotificationsActive atomic.Bool

	quit    chan struct{}
	wg      sync.WaitGroup
	started bool
	quitMtx sync.Mutex

	batchClient *rpcclient.Client
}

// A compile-time check to ensure that RPCClient satisfies the chain.Interface
// interface.
var _ Interface = (*RPCClient)(nil)

// notificationHandlers builds the default btcd websocket callbacks shared by
// NewRPCClient and NewRPCClientWithConfig. The deprecated btcd handlers remain
// required for legacy chain.Interface notifications and active
// EventSubscription block-disconnect delivery.
//
//nolint:staticcheck // Keep deprecated btcd callbacks for chain notifications.
func (c *RPCClient) notificationHandlers() *rpcclient.NotificationHandlers {
	return &rpcclient.NotificationHandlers{
		OnClientConnected:        c.onClientConnect,
		OnBlockConnected:         c.onBlockConnected,
		OnBlockDisconnected:      c.onBlockDisconnected,
		OnFilteredBlockConnected: c.onFilteredBlockConnected,
		OnRelevantTxAccepted:     c.onRelevantTxAccepted,
		OnRecvTx:                 c.onRecvTx,
		OnRedeemingTx:            c.onRedeemingTx,
		OnRescanFinished:         c.onRescanFinished,
		OnRescanProgress:         c.onRescanProgress,
	}
}

// NewRPCClient creates a client connection to the server described by the
// connect string.  If disableTLS is false, the remote RPC certificate must be
// provided in the certs slice.  The connection is not established immediately,
// but must be done using the Start method.  If the remote server does not
// operate on the same bitcoin network as described by the passed chain
// parameters, the connection will be disconnected.
//
// TODO(yy): deprecate it in favor of NewRPCClientWithConfig.
func NewRPCClient(chainParams *chaincfg.Params, connect, user, pass string, certs []byte,
	disableTLS bool, reconnectAttempts int) (*RPCClient, error) {

	if reconnectAttempts < 0 {
		return nil, errors.New("reconnectAttempts must be positive")
	}

	client := &RPCClient{
		connConfig: &rpcclient.ConnConfig{
			Host:                 connect,
			Endpoint:             "ws",
			User:                 user,
			Pass:                 pass,
			Certificates:         certs,
			DisableAutoReconnect: false,
			DisableConnectOnNew:  true,
			DisableTLS:           disableTLS,
		},
		chainParams:         chainParams,
		reconnectAttempts:   reconnectAttempts,
		enqueueNotification: make(chan interface{}),
		dequeueNotification: make(chan interface{}),
		currentBlock:        make(chan blockStampSnapshot),
		quit:                make(chan struct{}),
	}
	client.eventStream = newChainEventStream(chainParams, client)

	rpcClient, err := rpcclient.New(
		client.connConfig, client.notificationHandlers(),
	)
	if err != nil {
		return nil, err
	}

	batchConfig := *client.connConfig

	// The batch client is exclusively used for batch RPC calls, which
	// require HTTP POST mode. Therefore, we explicitly set HTTPPostMode to
	// true and clear the Endpoint field to ensure the batch client is
	// correctly configured, regardless of the main client's WebSocket (ws)
	// or HTTP POST configuration.
	batchConfig.HTTPPostMode = true
	batchConfig.Endpoint = ""

	batchClient, err := rpcclient.NewBatch(&batchConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create batch client: %w", err)
	}

	client.batchClient = batchClient
	client.Client = rpcClient

	return client, nil
}

// RPCClientConfig defines the config options used when initializing the RPC
// Client.
type RPCClientConfig struct {
	// Conn describes the connection configuration parameters for the
	// client.
	Conn *rpcclient.ConnConfig

	// Params defines a Bitcoin network by its parameters.
	Chain *chaincfg.Params

	// NotificationHandlers defines callback function pointers to invoke
	// with notifications. If not set, the default handlers defined in this
	// client will be used.
	NotificationHandlers *rpcclient.NotificationHandlers

	// ReconnectAttempts defines the number to reties (each after an
	// increasing backoff) if the connection can not be established.
	ReconnectAttempts int
}

// validate checks the required config options are set.
func (r *RPCClientConfig) validate() error {
	if r == nil {
		return errors.New("missing rpc config")
	}

	// Make sure retry attempts is positive.
	if r.ReconnectAttempts < 0 {
		return errors.New("reconnectAttempts must be positive")
	}

	// Make sure the chain params are configed.
	if r.Chain == nil {
		return errors.New("missing chain params config")
	}

	// Make sure connection config is supplied.
	if r.Conn == nil {
		return errors.New("missing conn config")
	}

	// If disableTLS is false, the remote RPC certificate must be provided
	// in the certs slice.
	if !r.Conn.DisableTLS && r.Conn.Certificates == nil {
		return errors.New("must provide certs when TLS is enabled")
	}

	return nil
}

// NewRPCClientWithConfig creates a client connection to the server based on
// the config options supplised.
//
// The connection is not established immediately, but must be done using the
// Start method.  If the remote server does not operate on the same bitcoin
// network as described by the passed chain parameters, the connection will be
// disconnected.
func NewRPCClientWithConfig(cfg *RPCClientConfig) (*RPCClient, error) {
	// Make sure the config is valid.
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Mimic the old behavior defined in `NewRPCClient`. We will remove
	// these hard-codings once this package is more properly refactored.
	cfg.Conn.DisableAutoReconnect = false
	cfg.Conn.DisableConnectOnNew = true

	client := &RPCClient{
		connConfig:          cfg.Conn,
		chainParams:         cfg.Chain,
		reconnectAttempts:   cfg.ReconnectAttempts,
		enqueueNotification: make(chan interface{}),
		dequeueNotification: make(chan interface{}),
		currentBlock:        make(chan blockStampSnapshot),
		quit:                make(chan struct{}),
	}
	client.eventStream = newChainEventStream(cfg.Chain, client)

	// Use the configed notification callbacks, if not set, default to the
	// callbacks defined in this package.
	ntfnCallbacks := cfg.NotificationHandlers
	if ntfnCallbacks == nil {
		ntfnCallbacks = client.notificationHandlers()
	}

	// Create the RPC client using the above config.
	rpcClient, err := rpcclient.New(client.connConfig, ntfnCallbacks)
	if err != nil {
		return nil, err
	}

	batchConfig := *cfg.Conn

	// The batch client is exclusively used for batch RPC calls, which
	// require HTTP POST mode. Therefore, we explicitly set HTTPPostMode to
	// true and clear the Endpoint field to ensure the batch client is
	// correctly configured, regardless of the main client's WebSocket (ws)
	// or HTTP POST configuration.
	batchConfig.HTTPPostMode = true
	batchConfig.Endpoint = ""

	batchClient, err := rpcclient.NewBatch(&batchConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create batch client: %w", err)
	}

	client.batchClient = batchClient
	client.Client = rpcClient

	return client, nil
}

// BackEnd returns the name of the driver.
func (c *RPCClient) BackEnd() string {
	return "btcd"
}

// SubmitPackage is unimplemented for the btcd backend. btcd defines the
// submitpackage JSON-RPC command type but its RPC server registers no handler
// for it, so a RawRequest would fail with a method-not-found error. Returning
// ErrUnimplemented avoids advertising support that does not exist; a btcd
// server-side submitpackage handler must land before this can do anything.
//
// NOTE: This is part of the chain.Interface interface.
func (c *RPCClient) SubmitPackage(_ []*wire.MsgTx,
	_ *float64) (*btcjson.SubmitPackageResult, error) {

	return nil, ErrUnimplemented
}

// Start attempts to establish a client connection with the remote server.
// If successful, handler goroutines are started to process notifications
// sent by the server.  After a limited number of connection attempts, this
// function gives up, and therefore will not block forever waiting for the
// connection to be established to a server that may not exist.
func (c *RPCClient) Start(ctx context.Context) error {
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

	// Query the initial best block before spawning handler(bs) so
	// notifications enabled immediately after Start() cannot deadlock
	// rpcclient's websocket reader against an in-flight GetBestBlock RPC.
	// Bind ctx cancellation to Stop so canceling Start unblocks the RPC.
	stopCancel := context.AfterFunc(ctx, c.Stop)

	hash, height, err := c.GetBestBlock()
	if !stopCancel() {
		c.Stop()

		return ctx.Err()
	}

	if err != nil {
		c.Stop()

		return fmt.Errorf("failed to receive best block from chain "+
			"server: %w", err)
	}

	bs := &waddrmgr.BlockStamp{Hash: *hash, Height: height}

	c.quitMtx.Lock()
	c.started = true
	c.wg.Add(1)

	go c.handler(bs)

	c.quitMtx.Unlock()

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
		c.Client.WaitForShutdown()
		c.batchClient.Shutdown()
		c.batchClient.WaitForShutdown()

		if !c.started {
			c.eventStream.close()
			close(c.dequeueNotification)
		}
	}
	c.quitMtx.Unlock()
}

// IsCurrent returns whether the chain backend considers its view of the network
// as "current".
func (c *RPCClient) IsCurrent() bool {
	bestHash, _, err := c.GetBestBlock()
	if err != nil {
		return false
	}
	bestHeader, err := c.GetBlockHeader(bestHash)
	if err != nil {
		return false
	}
	return bestHeader.Timestamp.After(time.Now().Add(-isCurrentDelta))
}

// Rescan wraps the normal Rescan command with an additional parameter that
// allows us to map an outpoint to the address in the chain that it pays to.
// This is useful when using BIP 158 filters as they include the prev pkScript
// rather than the full outpoint. Calling Rescan activates unbounded legacy
// Notifications() buffering; drain Notifications() per its contract.
func (c *RPCClient) Rescan(startHash *chainhash.Hash, addrs []address.Address,
	outPoints map[wire.OutPoint]address.Address) error {

	// Enable unbounded legacy buffering before async rescan callbacks fire.
	c.legacyNotificationsActive.Store(true)

	flatOutpoints := make([]*wire.OutPoint, 0, len(outPoints))
	for ops := range outPoints {
		ops := ops

		flatOutpoints = append(flatOutpoints, &ops)
	}

	return c.Client.Rescan(startHash, addrs, flatOutpoints) // nolint:staticcheck
}

// NotifyReceived registers addresses with both btcd's legacy notification
// filter and LoadTxFilter so legacy Notifications() receives matching txns and
// btcd's shared filter includes them; EventSubscription delivery still
// requires enrolling watches via EventSubscription.WatchAddrs.
func (c *RPCClient) NotifyReceived(addrs []address.Address) error {
	// Keep legacy NotifyReceived for OnRecvTx consumers alongside
	// LoadTxFilter.
	//nolint:staticcheck
	err := c.Client.NotifyReceived(addrs)
	if err != nil {
		return err
	}

	if len(addrs) == 0 {
		return nil
	}

	return c.LoadTxFilter(false, addrs, nil)
}

// NotifySpent registers outpoints with both btcd's legacy notification filter
// and LoadTxFilter without stealth-enabling NotifyBlocks.
func (c *RPCClient) NotifySpent(points []*wire.OutPoint) error {
	flat := make([]wire.OutPoint, len(points))
	for i, op := range points {
		if op == nil {
			return fmt.Errorf("%w: nil outpoint at index %d",
				ErrInvalidParam, i)
		}

		flat[i] = *op
	}

	// Keep legacy NotifySpent for OnRedeemingTx consumers alongside
	// LoadTxFilter.
	//nolint:staticcheck
	err := c.Client.NotifySpent(points)
	if err != nil {
		return err
	}

	if len(flat) == 0 {
		return nil
	}

	return c.LoadTxFilter(false, nil, flat)
}

// WatchAddrsFromTip registers addresses with btcd's transaction notification
// filters without issuing a rescan. The context is checked before registration
// so a canceled delivery attempt cannot introduce new watches.
func (c *RPCClient) WatchAddrsFromTip(ctx context.Context,
	addrs []address.Address) error {

	err := ctx.Err()
	if err != nil {
		return err
	}

	return c.NotifyReceived(addrs)
}

// GetCFilter returns a compact filter for the given block hash and filter
// type. It wraps the underlying rpcclient method and converts the result to a
// *gcs.Filter.
func (c *RPCClient) GetCFilter(hash *chainhash.Hash,
	filterType wire.FilterType) (*gcs.Filter, error) {

	rawFilter, err := c.Client.GetCFilter(hash, filterType)
	if err != nil {
		return nil, fmt.Errorf("failed to get filter: %w", err)
	}

	filter, err := gcs.FromNBytes(
		builder.DefaultP, builder.DefaultM, rawFilter.Data,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter from bytes: %w",
			err)
	}

	return filter, nil
}

// WaitForShutdown blocks until both the client has finished disconnecting
// and all handlers have exited.
func (c *RPCClient) WaitForShutdown() {
	c.Client.WaitForShutdown()
	c.wg.Wait()
}

// Notifications returns a channel of parsed notifications sent by the remote
// bitcoin RPC server and activates unbounded legacy buffering; see
// Interface.Notifications for the pre-activation retention and drain contract.
func (c *RPCClient) Notifications() <-chan interface{} {
	// Enable unbounded legacy queuing now that a caller requested it.
	c.legacyNotificationsActive.Store(true)

	return c.dequeueNotification
}

// SubscribeChainEvents enrolls a reader on the started RPCClient.
func (c *RPCClient) SubscribeChainEvents(
	ctx context.Context) EventSubscription {

	return c.eventStream.subscribe(ctx)
}

// BlockStamp returns the latest block notified by the client, or an error
// if the client has been shut down.
func (c *RPCClient) BlockStamp() (*waddrmgr.BlockStamp, error) {
	select {
	case snap := <-c.currentBlock:
		return snap.current(), nil
	case <-c.quit:
		return nil, errors.New("disconnected")
	}
}

// FilterBlocks scans the blocks contained in the FilterBlocksRequest for any
// addresses of interest. For each requested block, the corresponding compact
// filter will first be checked for matches, skipping those that do not report
// anything. If the filter returns a positive match, the full block will be
// fetched and filtered. This method returns a FilterBlocksResponse for the first
// block containing a matching address. If no matches are found in the range of
// blocks requested, the returned response will be nil.
func (c *RPCClient) FilterBlocks(
	req *FilterBlocksRequest) (*FilterBlocksResponse, error) {

	blockFilterer := NewBlockFilterer(c.chainParams, req)

	// Construct the watchlist using the addresses and outpoints contained
	// in the filter blocks request.
	watchList, err := buildFilterBlocksWatchList(req)
	if err != nil {
		return nil, err
	}

	// Iterate over the requested blocks, fetching the compact filter for
	// each one, and matching it against the watchlist generated above. If
	// the filter returns a positive match, the full block is then requested
	// and scanned for addresses using the block filterer.
	for i, blk := range req.Blocks {
		rawFilter, err := c.Client.GetCFilter(
			&blk.Hash, wire.GCSFilterRegular,
		)
		if err != nil {
			return nil, err
		}

		// Ensure the filter is large enough to be deserialized.
		if len(rawFilter.Data) < 4 {
			continue
		}

		filter, err := gcs.FromNBytes(
			builder.DefaultP, builder.DefaultM, rawFilter.Data,
		)
		if err != nil {
			return nil, err
		}

		// Skip any empty filters.
		if filter.N() == 0 {
			continue
		}

		key := builder.DeriveKey(&blk.Hash)
		matched, err := filter.MatchAny(key, watchList)
		if err != nil {
			return nil, err
		} else if !matched {
			continue
		}

		log.Infof("Fetching block height=%d hash=%v",
			blk.Height, blk.Hash)

		rawBlock, err := c.GetBlock(&blk.Hash)
		if err != nil {
			return nil, err
		}

		if !blockFilterer.FilterBlock(rawBlock) {
			continue
		}

		// If any external or internal addresses were detected in this
		// block, we return them to the caller so that the rescan
		// windows can widened with subsequent addresses. The
		// `BatchIndex` is returned so that the caller can compute the
		// *next* block from which to begin again.
		resp := &FilterBlocksResponse{
			BatchIndex:         uint32(i),
			BlockMeta:          blk,
			FoundExternalAddrs: blockFilterer.FoundExternal,
			FoundInternalAddrs: blockFilterer.FoundInternal,
			FoundOutPoints:     blockFilterer.FoundOutPoints,
			RelevantTxns:       blockFilterer.RelevantTxns,
		}

		return resp, nil
	}

	// No addresses were found for this range.
	return nil, nil
}

// parseBlock parses a btcws definition of the block a tx is mined it to the
// Block structure of the wtxmgr package, and the block index.  This is done
// here since rpcclient doesn't parse this nicely for us.
func parseBlock(block *btcjson.BlockDetails) (*wtxmgr.BlockMeta, error) {
	if block == nil {
		return nil, nil
	}
	blkHash, err := chainhash.NewHashFromStr(block.Hash)
	if err != nil {
		return nil, err
	}
	blk := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Height: block.Height,
			Hash:   *blkHash,
		},
		Time: time.Unix(block.Time, 0),
	}
	return blk, nil
}

func (c *RPCClient) onClientConnect() {
	select {
	case c.enqueueNotification <- ClientConnected{}:
	case <-c.quit:
	}
}

func (c *RPCClient) onBlockConnected(hash *chainhash.Hash, height int32, time time.Time) {
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

func (c *RPCClient) onBlockDisconnected(hash *chainhash.Hash, height int32, time time.Time) {
	ntfn := BlockDisconnected{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: time,
	}
	if c.eventStream.hasSubscribers() {
		c.eventStream.publish(ntfn)
	}

	select {
	case c.enqueueNotification <- ntfn:
	case <-c.quit:
	}
}

// onFilteredBlockConnected publishes btcd's atomic filtered block notification
// directly to EventSubscription in websocket wire order.
func (c *RPCClient) onFilteredBlockConnected(height int32,
	header *wire.BlockHeader, txs []*btcutil.Tx) {

	if !c.eventStream.hasSubscribers() {
		return
	}

	recs := make([]*wtxmgr.TxRecord, 0, len(txs))
	for _, tx := range txs {
		rec, err := wtxmgr.NewTxRecordFromMsgTx(
			tx.MsgTx(), header.Timestamp,
		)
		if err != nil {
			log.Errorf("Cannot create filtered block tx: %v", err)
			continue
		}

		recs = append(recs, rec)
	}

	blk := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: header.BlockHash(), Height: height},
		Time:  header.Timestamp,
	}

	c.eventStream.publish(FilteredBlockConnected{
		Block: blk, RelevantTxs: recs,
	})
}

// onRelevantTxAccepted decodes rawTx via wire.MsgTx so witness txns keep their
// canonical txid, and publishes an unconfirmed RelevantTx to EventSubscription.
func (c *RPCClient) onRelevantTxAccepted(rawTx []byte) {
	if !c.eventStream.hasSubscribers() {
		return
	}

	var msgTx wire.MsgTx

	err := msgTx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		log.Errorf("Cannot deserialize relevant tx: %v", err)

		return
	}

	rec, err := wtxmgr.NewTxRecordFromMsgTx(&msgTx, time.Now())
	if err != nil {
		log.Errorf("Cannot create relevant tx record: %v", err)

		return
	}

	c.eventStream.publish(RelevantTx{rec, nil})
}

func (c *RPCClient) onRecvTx(tx *btcutil.Tx, block *btcjson.BlockDetails) {
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

func (c *RPCClient) onRedeemingTx(tx *btcutil.Tx, block *btcjson.BlockDetails) {
	// Handled exactly like recvtx notifications.
	c.onRecvTx(tx, block)
}

func (c *RPCClient) onRescanProgress(hash *chainhash.Hash, height int32, blkTime time.Time) {
	select {
	case c.enqueueNotification <- &RescanProgress{*hash, height, blkTime}:
	case <-c.quit:
	}
}

func (c *RPCClient) onRescanFinished(hash *chainhash.Hash, height int32, blkTime time.Time) {
	select {
	case c.enqueueNotification <- &RescanFinished{hash, height, blkTime}:
	case <-c.quit:
	}

}

// blockStampFromConnected returns a BlockStamp when n is BlockConnected, or
// fallback otherwise.
func blockStampFromConnected(n any,
	fallback *waddrmgr.BlockStamp) *waddrmgr.BlockStamp {

	if blk, ok := n.(BlockConnected); ok {
		return &waddrmgr.BlockStamp{
			Height: blk.Height,
			Hash:   blk.Hash,
		}
	}

	return fallback
}

// enqueueLegacyNotification updates intakeBS while unactivated and appends n
// to notifications unless the pre-activation cap (reserving one slot for the
// initial async ClientConnected marker) drops it.
func (c *RPCClient) enqueueLegacyNotification(notifications []any, n any,
	hasClientConnected *bool, intakeBS **waddrmgr.BlockStamp) []any {

	_, isConnected := n.(ClientConnected)
	if !c.legacyNotificationsActive.Load() {
		*intakeBS = blockStampFromConnected(n, *intakeBS)

		limit := legacyPreActivationCap
		if !*hasClientConnected && !isConnected {
			limit--
		}

		if len(notifications) >= limit {
			return notifications
		}
	}

	*hasClientConnected = *hasClientConnected || isConnected

	return append(notifications, n)
}

// dequeueLegacyNotification removes the delivered head from notifications and
// returns the remaining slice, next head, updated dequeue channel, and whether
// the handler loop can exit because enqueue is already closed.
func dequeueLegacyNotification(notifications []any, dequeue chan any,
	enqueueClosed bool) ([]any, any, chan any, bool) {

	notifications[0] = nil

	notifications = notifications[1:]
	if len(notifications) != 0 {
		return notifications, notifications[0], dequeue, false
	}

	return notifications, nil, nil, enqueueClosed
}

// handler delivers native notifications, maintains the last notified block,
// and buffers legacy notifications up to legacyPreActivationCap (reserving one
// slot for the initial ClientConnected marker) until Notifications() or
// Rescan() activates unbounded FIFO buffering that must be drained continually.
func (c *RPCClient) handler(bs *waddrmgr.BlockStamp) {
	defer c.wg.Done()

	stream := c.eventStream
	defer stream.close()

	intakeBS := bs

	// TODO: Rather than leaving this as an unbounded queue for all types of
	// notifications, try dropping ones where a later enqueued notification
	// can fully invalidate one waiting to be processed.  For example,
	// blockconnected notifications for greater block heights can remove the
	// need to process earlier blockconnected notifications still waiting
	// here.

	var notifications []any

	enqueue := c.enqueueNotification

	var dequeue chan any

	var next any

	hasClientConnected := false
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

			// While no legacy consumer is active, advance intakeBS
			// and bound unread legacy entries. Once activated,
			// BlockStamp serves bs, which advances only on dequeue
			// to preserve the legacy-delivery fence.
			notifications = c.enqueueLegacyNotification(
				notifications, n, &hasClientConnected,
				&intakeBS,
			)
			if len(notifications) == 1 {
				next = notifications[0]
				dequeue = c.dequeueNotification
			}

		case dequeue <- next:
			bs = blockStampFromConnected(next, bs)

			var done bool

			notifications, next, dequeue, done =
				dequeueLegacyNotification(
					notifications, dequeue, enqueue == nil,
				)
			if done {
				break out
			}

		case c.currentBlock <- blockStampSnapshot{
			dequeued:     bs,
			intake:       intakeBS,
			legacyActive: &c.legacyNotificationsActive,
		}:

		case <-c.quit:
			break out
		}
	}

	c.Stop()
	close(c.dequeueNotification)
}

// POSTClient creates the equivalent HTTP POST rpcclient.Client.
func (c *RPCClient) POSTClient() (*rpcclient.Client, error) {
	configCopy := *c.connConfig
	configCopy.HTTPPostMode = true
	return rpcclient.New(&configCopy, nil)
}

// LookupInputMempoolSpend returns the transaction hash and true if the given
// input is found being spent in mempool, otherwise it returns nil and false.
func (c *RPCClient) LookupInputMempoolSpend(op wire.OutPoint) (
	chainhash.Hash, bool) {

	return getTxSpendingPrevOut(op, c.Client)
}

// MapRPCErr takes an error returned from calling RPC methods from various
// chain backends and maps it to an defined error here. It uses the
// `BtcdErrMap`, whose keys are btcd error strings and values are errors made
// from bitcoind error strings.
// Input diagnostics take precedence over their nested policy causes.
func (c *RPCClient) MapRPCErr(rpcErr error) error {
	// Share current-reason precedence with peer rejects before applying
	// this backend's version-dependent legacy fallback.
	err := mapBtcdErr(rpcErr)
	if err != nil {
		return err
	}

	// If no matching error is found, we try to match it to an older
	// version of `btcd`.
	//
	// Get the backend's version.
	backend, bErr := c.BackendVersion()
	if bErr != nil {
		// If there's an error getting the backend version, we return
		// the original error and the backend error.
		return fmt.Errorf("%w: %v, failed to get backend version %v",
			ErrUndefined, rpcErr, bErr)
	}

	// If this version doesn't support `testmempoolaccept`, it must be
	// below v0.24.2. In this case, we will match the errors defined in
	// pre-v0.24.2.
	//
	// NOTE: `testmempoolaccept` is implemented in v0.24.1, but this
	// version was never tagged, which means it must be v0.24.2 when it's
	// supported.
	if !backend.SupportTestMempoolAccept() {
		// If the backend is older than v0.24.2, we will try to match
		// the error to the older version of `btcd`.
		for btcdErr, matchedErr := range BtcdErrMapPre2402 {
			// Match it against btcd's error.
			if matchErrStr(rpcErr, btcdErr) {
				return matchedErr
			}
		}
	}

	// If not matched, return the original error wrapped.
	return fmt.Errorf("%w: %v", ErrUndefined, rpcErr)
}

// SendRawTransaction sends a raw transaction via btcd.
func (c *RPCClient) SendRawTransaction(tx *wire.MsgTx,
	allowHighFees bool) (*chainhash.Hash, error) {

	txid, err := c.Client.SendRawTransaction(tx, allowHighFees)
	if err != nil {
		return nil, c.MapRPCErr(err)
	}

	return txid, nil
}

// GetBlockHashes returns a slice of block hashes for the given height range.
func (c *RPCClient) GetBlockHashes(startHeight,
	endHeight int64) ([]chainhash.Hash, error) {

	if startHeight > endHeight {
		return nil, fmt.Errorf("%w: start height %d, end height %d",
			ErrInvalidParam, startHeight, endHeight)
	}

	count := endHeight - startHeight + 1
	hashes := make([]chainhash.Hash, 0, count)
	futures := make([]rpcclient.FutureGetBlockHashResult, 0, count)

	for h := startHeight; h <= endHeight; h++ {
		futures = append(futures, c.batchClient.GetBlockHashAsync(h))
	}

	err := c.batchClient.Send()
	if err != nil {
		return nil, fmt.Errorf("batch send: %w", err)
	}

	for _, f := range futures {
		hash, err := f.Receive()
		if err != nil {
			return nil, fmt.Errorf("receive block hash: %w", err)
		}

		hashes = append(hashes, *hash)
	}

	return hashes, nil
}

// GetCFilters returns a slice of filters for the given block hashes.
func (c *RPCClient) GetCFilters(hashes []chainhash.Hash,
	filterType wire.FilterType) ([]*gcs.Filter, error) {

	filters := make([]*gcs.Filter, 0, len(hashes))
	futures := make([]rpcclient.FutureGetCFilterResult, 0, len(hashes))

	for _, hash := range hashes {
		futures = append(
			futures,
			c.batchClient.GetCFilterAsync(&hash, filterType),
		)
	}

	err := c.batchClient.Send()
	if err != nil {
		return nil, fmt.Errorf("batch send: %w", err)
	}

	for _, f := range futures {
		msgFilter, err := f.Receive()
		if err != nil {
			return nil, fmt.Errorf("receive cfilter: %w", err)
		}

		filter, err := gcs.FromNBytes(
			builder.DefaultP, builder.DefaultM, msgFilter.Data,
		)
		if err != nil {
			return nil, fmt.Errorf("parse cfilter: %w", err)
		}

		filters = append(filters, filter)
	}

	return filters, nil
}

// GetBlocks returns a slice of full blocks for the given block hashes.
func (c *RPCClient) GetBlocks(hashes []chainhash.Hash) (
	[]*wire.MsgBlock, error) {

	blocks := make([]*wire.MsgBlock, 0, len(hashes))
	futures := make([]rpcclient.FutureGetBlockResult, 0, len(hashes))

	for _, hash := range hashes {
		futures = append(futures, c.batchClient.GetBlockAsync(&hash))
	}

	err := c.batchClient.Send()
	if err != nil {
		return nil, fmt.Errorf("batch send: %w", err)
	}

	for _, f := range futures {
		block, err := f.Receive()
		if err != nil {
			return nil, fmt.Errorf("receive block: %w", err)
		}

		blocks = append(blocks, block)
	}

	return blocks, nil
}

// GetBlockHeaders returns a slice of block headers for the given block hashes.
func (c *RPCClient) GetBlockHeaders(hashes []chainhash.Hash) (
	[]*wire.BlockHeader, error) {

	headers := make([]*wire.BlockHeader, 0, len(hashes))
	futures := make([]rpcclient.FutureGetBlockHeaderResult, 0, len(hashes))

	for _, hash := range hashes {
		futures = append(
			futures, c.batchClient.GetBlockHeaderAsync(&hash),
		)
	}

	err := c.batchClient.Send()
	if err != nil {
		return nil, fmt.Errorf("batch send: %w", err)
	}

	for _, f := range futures {
		header, err := f.Receive()
		if err != nil {
			return nil, fmt.Errorf("receive header: %w", err)
		}

		headers = append(headers, header)
	}

	return headers, nil
}
