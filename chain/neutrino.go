package chain

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/btcutil/gcs/builder"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain/internal/rescan"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/neutrino"
	"github.com/lightninglabs/neutrino/banman"
	"github.com/lightninglabs/neutrino/headerfs"
)

// NeutrinoChainService is an interface that encapsulates all the public
// methods of a *neutrino.ChainService
type NeutrinoChainService interface {
	Start() error
	GetBlock(chainhash.Hash, ...neutrino.QueryOption) (*btcutil.Block, error)
	GetBlockHeight(*chainhash.Hash) (int32, error)
	BestBlock() (*headerfs.BlockStamp, error)
	GetBlockHash(int64) (*chainhash.Hash, error)
	GetBlockHeader(*chainhash.Hash) (*wire.BlockHeader, error)
	IsCurrent() bool
	SendTransaction(*wire.MsgTx) error
	GetCFilter(chainhash.Hash, wire.FilterType,
		...neutrino.QueryOption) (*gcs.Filter, error)
	GetUtxo(...neutrino.RescanOption) (*neutrino.SpendReport, error)
	BanPeer(string, banman.Reason) error
	IsBanned(addr string) bool
	AddPeer(*neutrino.ServerPeer)
	AddBytesSent(uint64)
	AddBytesReceived(uint64)
	NetTotals() (uint64, uint64)
	UpdatePeerHeights(*chainhash.Hash, int32, *neutrino.ServerPeer)
	ChainParams() chaincfg.Params
	Stop() error
	PeerByAddr(string) *neutrino.ServerPeer
}

var _ NeutrinoChainService = (*neutrino.ChainService)(nil)

// NeutrinoClient is an implementation of the btcwalet chain.Interface interface.
type NeutrinoClient struct {
	CS NeutrinoChainService

	chainParams *chaincfg.Params

	// We currently support one rescan/notifiction goroutine per client
	rescanCh      chan rescan.Interface
	rescanQuitCh  chan chan struct{}
	rescanErr     chan error
	newRescanFunc rescan.NewFunc

	enqueueNotification     chan interface{}
	dequeueNotification     chan interface{}
	startTime               time.Time
	lastProgressSent        bool
	lastFilteredBlockHeader *wire.BlockHeader
	currentBlock            chan *waddrmgr.BlockStamp

	quit     chan struct{}
	wg       sync.WaitGroup
	started  bool
	finished bool
	isRescan bool

	clientMtx sync.Mutex
}

// NewNeutrinoClient creates a new NeutrinoClient struct with a backing
// ChainService.
func NewNeutrinoClient(chainParams *chaincfg.Params,
	chainService *neutrino.ChainService) *NeutrinoClient {

	return &NeutrinoClient{
		CS:           chainService,
		chainParams:  chainParams,
		rescanCh:     make(chan rescan.Interface, 1),
		rescanQuitCh: make(chan chan struct{}, 1),
		rescanErr:    make(chan error),
	}
}

// BackEnd returns the name of the driver.
func (s *NeutrinoClient) BackEnd() string {
	return "neutrino"
}

// Start replicates the RPC client's Start method.
func (s *NeutrinoClient) Start() error {
	if err := s.CS.Start(); err != nil {
		return fmt.Errorf("error starting chain service: %v", err)
	}

	s.clientMtx.Lock()
	defer s.clientMtx.Unlock()
	if !s.started {
		// Reset the client state.
		s.enqueueNotification = make(chan interface{})
		s.dequeueNotification = make(chan interface{})
		s.currentBlock = make(chan *waddrmgr.BlockStamp)
		s.quit = make(chan struct{})
		s.started = true

		// Launch the notification handler.
		s.wg.Add(1)
		go s.notificationHandler()

		// Place a ClientConnected notification onto the queue.
		select {
		case s.enqueueNotification <- ClientConnected{}:
		case <-s.quit:
		}
	}
	return nil
}

// Stop replicates the RPC client's Stop method.
func (s *NeutrinoClient) Stop() {
	s.clientMtx.Lock()
	defer s.clientMtx.Unlock()
	if !s.started {
		return
	}
	close(s.quit)
	s.started = false
}

// WaitForShutdown replicates the RPC client's WaitForShutdown method.
func (s *NeutrinoClient) WaitForShutdown() {
	s.wg.Wait()
}

// GetBlock replicates the RPC client's GetBlock command.
func (s *NeutrinoClient) GetBlock(hash *chainhash.Hash) (*wire.MsgBlock, error) {
	// TODO(roasbeef): add a block cache?
	//  * which evication strategy? depends on use case
	//  Should the block cache be INSIDE neutrino instead of in btcwallet?
	block, err := s.CS.GetBlock(*hash)
	if err != nil {
		return nil, err
	}
	return block.MsgBlock(), nil
}

// GetBlockHeight gets the height of a block by its hash. It serves as a
// replacement for the use of GetBlockVerboseTxAsync for the wallet package
// since we can't actually return a FutureGetBlockVerboseResult because the
// underlying type is private to rpcclient.
func (s *NeutrinoClient) GetBlockHeight(hash *chainhash.Hash) (int32, error) {
	return s.CS.GetBlockHeight(hash)
}

// GetBestBlock replicates the RPC client's GetBestBlock command.
func (s *NeutrinoClient) GetBestBlock() (*chainhash.Hash, int32, error) {
	chainTip, err := s.CS.BestBlock()
	if err != nil {
		return nil, 0, err
	}

	return &chainTip.Hash, chainTip.Height, nil
}

// BlockStamp returns the latest block notified by the client, or an error
// if the client has been shut down.
func (s *NeutrinoClient) BlockStamp() (*waddrmgr.BlockStamp, error) {
	select {
	case bs := <-s.currentBlock:
		return bs, nil
	case <-s.quit:
		return nil, errors.New("disconnected")
	}
}

// GetBlockHash returns the block hash for the given height, or an error if the
// client has been shut down or the hash at the block height doesn't exist or
// is unknown.
func (s *NeutrinoClient) GetBlockHash(height int64) (*chainhash.Hash, error) {
	return s.CS.GetBlockHash(height)
}

// GetBlockHeader returns the block header for the given block hash, or an error
// if the client has been shut down or the hash doesn't exist or is unknown.
func (s *NeutrinoClient) GetBlockHeader(
	blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	return s.CS.GetBlockHeader(blockHash)
}

// IsCurrent returns whether the chain backend considers its view of the network
// as "current".
func (s *NeutrinoClient) IsCurrent() bool {
	return s.CS.IsCurrent()
}

// SendRawTransaction replicates the RPC client's SendRawTransaction command.
func (s *NeutrinoClient) SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (
	*chainhash.Hash, error) {
	err := s.CS.SendTransaction(tx)
	if err != nil {
		return nil, err
	}
	hash := tx.TxHash()
	return &hash, nil
}

// FilterBlocks scans the blocks contained in the FilterBlocksRequest for any
// addresses of interest. For each requested block, the corresponding compact
// filter will first be checked for matches, skipping those that do not report
// anything. If the filter returns a positive match, the full block will be
// fetched and filtered. This method returns a FilterBlocksResponse for the first
// block containing a matching address. If no matches are found in the range of
// blocks requested, the returned response will be nil.
func (s *NeutrinoClient) FilterBlocks(
	req *FilterBlocksRequest) (*FilterBlocksResponse, error) {

	blockFilterer := NewBlockFilterer(s.chainParams, req)

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
		// TODO(wilmer): Investigate why polling it still necessary
		// here. While testing, I ran into a few instances where the
		// filter was not retrieved, leading to a panic. This should not
		// happen in most cases thanks to the query logic revamp within
		// Neutrino, but it seems there's still an uncovered edge case.
		filter, err := s.pollCFilter(&blk.Hash)
		if err != nil {
			return nil, err
		}

		// Skip any empty filters.
		if filter == nil || filter.N() == 0 {
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

		// TODO(conner): can optimize bandwidth by only fetching
		// stripped blocks
		rawBlock, err := s.GetBlock(&blk.Hash)
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

// buildFilterBlocksWatchList constructs a watchlist used for matching against a
// cfilter from a FilterBlocksRequest. The watchlist will be populated with all
// external addresses, internal addresses, and outpoints contained in the
// request.
func buildFilterBlocksWatchList(req *FilterBlocksRequest) ([][]byte, error) {
	// Construct a watch list containing the script addresses of all
	// internal and external addresses that were requested, in addition to
	// the set of outpoints currently being watched.
	watchListSize := len(req.ExternalAddrs) +
		len(req.InternalAddrs) +
		len(req.WatchedOutPoints)

	watchList := make([][]byte, 0, watchListSize)

	for _, addr := range req.ExternalAddrs {
		p2shAddr, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}

		watchList = append(watchList, p2shAddr)
	}

	for _, addr := range req.InternalAddrs {
		p2shAddr, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}

		watchList = append(watchList, p2shAddr)
	}

	for _, addr := range req.WatchedOutPoints {
		addr, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}

		watchList = append(watchList, addr)
	}

	return watchList, nil
}

// pollCFilter attempts to fetch a CFilter from the neutrino client. This is
// used to get around the fact that the filter headers may lag behind the
// highest known block header.
func (s *NeutrinoClient) pollCFilter(hash *chainhash.Hash) (*gcs.Filter, error) {
	var (
		filter *gcs.Filter
		err    error
		count  int
	)

	const maxFilterRetries = 50
	for count < maxFilterRetries {
		if count > 0 {
			time.Sleep(100 * time.Millisecond)
		}

		filter, err = s.CS.GetCFilter(
			*hash, wire.GCSFilterRegular, neutrino.OptimisticBatch(),
		)
		if err != nil {
			count++
			continue
		}

		return filter, nil
	}

	return nil, err
}

// Rescan replicates the RPC client's Rescan command.
func (s *NeutrinoClient) Rescan(startHash *chainhash.Hash, addrs []btcutil.Address,
	outPoints map[wire.OutPoint]btcutil.Address) error {

	s.clientMtx.Lock()
	defer s.clientMtx.Unlock()

	if !s.started {
		return fmt.Errorf("can't do a rescan when the chain client " +
			"is not started")
	}

	bestBlock, err := s.CS.BestBlock()
	if err != nil {
		return fmt.Errorf("can't get chain service's best block: %s", err)
	}

	header, err := s.CS.GetBlockHeader(&bestBlock.Hash)
	if err != nil {
		return fmt.Errorf("can't get block header for hash %v: %s",
			bestBlock.Hash, err)
	}

	inputsToWatch, err := toInputsToWatch(outPoints)
	if err != nil {
		return err
	}

	select {
	case rescan := <-s.rescanCh:
		// Rescan process exists so get its corresponding quit channel.
		rescanQuit := <-s.rescanQuitCh

		// Kill the existing rescan before creating a new rescan
		// process.
		close(rescanQuit)
		rescan.WaitForShutdown()
	default:
		// No rescan process exists, nothing to shutdown.
	}

	s.finished = header.BlockHash() == *startHash
	s.lastProgressSent = false
	s.lastFilteredBlockHeader = nil
	s.isRescan = true

	// If the wallet is already fully caught up, or the rescan has started
	// with state that indicates a "fresh" wallet, we'll send a
	// notification indicating the rescan has "finished".
	if s.finished {
		select {
		case s.enqueueNotification <- &RescanFinished{
			Hash:   startHash,
			Height: bestBlock.Height,
			Time:   header.Timestamp,
		}:
		case <-s.quit:
			return nil
		}
	}

	// Initialize a new rescan process.
	s.createRescan(
		neutrino.StartBlock(&headerfs.BlockStamp{Hash: *startHash}),
		neutrino.WatchAddrs(addrs...),
		neutrino.WatchInputs(inputsToWatch...),
	)

	return nil
}

// NotifyBlocks replicates the RPC client's NotifyBlocks command.
func (s *NeutrinoClient) NotifyBlocks() error {
	select {
	case rescan := <-s.rescanCh:
		// Rescan is running, put it back and do nothing because
		// we are already notifying on blocks.
		s.rescanCh <- rescan
		return nil
	default:
	}

	// Otherwise, start a rescan without watching any addresses.
	var addrs []btcutil.Address
	return s.NotifyReceived(addrs)
}

// NotifyReceived replicates the RPC client's NotifyReceived command.
//
// NotifyReceived checks if a rescan process is running, if one exists already
// it updates the rescan process to include the additional addressess.
// Otherwise, it initializes a new rescan with the given addresses.
//
// TODO(mstreet3) error if the client is not started?
func (s *NeutrinoClient) NotifyReceived(addrs []btcutil.Address) error {
	s.clientMtx.Lock()
	defer s.clientMtx.Unlock()

	select {
	case rescan := <-s.rescanCh:
		// The rescan is running so update the watch list and put it back.
		err := rescan.Update(neutrino.AddAddrs(addrs...))
		s.rescanCh <- rescan
		return err
	default:
		// No scanning so update the client state then initialize a new
		// rescan.
	}

	// Don't need RescanFinished or RescanProgress notifications.
	s.finished = true
	s.lastProgressSent = true
	s.lastFilteredBlockHeader = nil

	// Rescan with just the specified addresses.
	s.createRescan(neutrino.WatchAddrs(addrs...))
	return nil
}

// Notifications replicates the RPC client's Notifications method.
func (s *NeutrinoClient) Notifications() <-chan interface{} {
	return s.dequeueNotification
}

// SetStartTime is a non-interface method to set the birthday of the wallet
// using this object. Since only a single rescan at a time is currently
// supported, only one birthday needs to be set. This does not fully restart a
// running rescan, so should not be used to update a rescan while it is running.
// TODO: When factoring out to multiple rescans per Neutrino client, add a
// birthday per client.
func (s *NeutrinoClient) SetStartTime(startTime time.Time) {
	s.clientMtx.Lock()
	defer s.clientMtx.Unlock()

	s.startTime = startTime
}

// onFilteredBlockConnected sends appropriate notifications to the notification
// channel.
func (s *NeutrinoClient) onFilteredBlockConnected(rescanQuit <-chan struct{},
	height int32, header *wire.BlockHeader, relevantTxs []*btcutil.Tx) {
	ntfn := FilteredBlockConnected{
		Block: &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				Hash:   header.BlockHash(),
				Height: height,
			},
			Time: header.Timestamp,
		},
	}
	for _, tx := range relevantTxs {
		rec, err := wtxmgr.NewTxRecordFromMsgTx(tx.MsgTx(),
			header.Timestamp)
		if err != nil {
			log.Errorf("Cannot create transaction record for "+
				"relevant tx: %s", err)
			// TODO(aakselrod): Return?
			continue
		}
		ntfn.RelevantTxs = append(ntfn.RelevantTxs, rec)
	}

	select {
	case s.enqueueNotification <- ntfn:
	case <-s.quit:
		return
	case <-rescanQuit:
		return
	}

	s.clientMtx.Lock()
	s.lastFilteredBlockHeader = header
	s.clientMtx.Unlock()

	// Handle RescanFinished notification if required.
	s.dispatchRescanFinished(rescanQuit)
}

// onBlockDisconnected sends appropriate notifications to the notification
// channel.
func (s *NeutrinoClient) onBlockDisconnected(rescanQuit <-chan struct{},
	hash *chainhash.Hash, height int32, t time.Time) {
	select {
	case s.enqueueNotification <- BlockDisconnected{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: t,
	}:
	case <-s.quit:
	case <-rescanQuit:
	}
}

func (s *NeutrinoClient) onBlockConnected(rescanQuit <-chan struct{},
	hash *chainhash.Hash, height int32, time time.Time) {
	// TODO: Move this closure out and parameterize it? Is it useful
	// outside here?
	sendRescanProgress := func() {
		select {
		case s.enqueueNotification <- &RescanProgress{
			Hash:   hash,
			Height: height,
			Time:   time,
		}:
		case <-s.quit:
		case <-rescanQuit:
		}
	}
	// Only send BlockConnected notification if we're processing blocks
	// before the birthday. Otherwise, we can just update using
	// RescanProgress notifications.
	if time.Before(s.startTime) {
		// Send a RescanProgress notification every 10K blocks.
		if height%10000 == 0 {
			s.clientMtx.Lock()
			shouldSend := s.isRescan && !s.finished
			s.clientMtx.Unlock()
			if shouldSend {
				sendRescanProgress()
			}
		}
	} else {
		// Send a RescanProgress notification if we're just going over
		// the boundary between pre-birthday and post-birthday blocks,
		// and note that we've sent it.
		s.clientMtx.Lock()
		if !s.lastProgressSent {
			shouldSend := s.isRescan && !s.finished
			if shouldSend {
				s.clientMtx.Unlock()
				sendRescanProgress()
				s.clientMtx.Lock()
				s.lastProgressSent = true
			}
		}
		s.clientMtx.Unlock()
		select {
		case s.enqueueNotification <- BlockConnected{
			Block: wtxmgr.Block{
				Hash:   *hash,
				Height: height,
			},
			Time: time,
		}:
		case <-s.quit:
		case <-rescanQuit:
		}
	}

	// Check if we're able to dispatch our final RescanFinished notification
	// after processing this block.
	s.dispatchRescanFinished(rescanQuit)
}

// dispatchRescanFinished determines whether we're able to dispatch our final
// RescanFinished notification in order to mark the wallet as synced with the
// chain. If the notification has already been dispatched, then it won't be done
// again.
func (s *NeutrinoClient) dispatchRescanFinished(rescanQuit <-chan struct{}) {
	bs, err := s.CS.BestBlock()
	if err != nil {
		log.Errorf("Can't get chain service's best block: %s", err)
		return
	}

	s.clientMtx.Lock()
	// Only send the RescanFinished notification once.
	if s.lastFilteredBlockHeader == nil || s.finished {
		s.clientMtx.Unlock()
		return
	}

	// Only send the RescanFinished notification once the underlying chain
	// service sees itself as current.
	if bs.Hash != s.lastFilteredBlockHeader.BlockHash() {
		s.clientMtx.Unlock()
		return
	}

	s.finished = s.CS.IsCurrent() && s.lastProgressSent
	if !s.finished {
		s.clientMtx.Unlock()
		return
	}

	header := s.lastFilteredBlockHeader
	s.clientMtx.Unlock()

	select {
	case s.enqueueNotification <- &RescanFinished{
		Hash:   &bs.Hash,
		Height: bs.Height,
		Time:   header.Timestamp,
	}:
	case <-s.quit:
		return
	case <-rescanQuit:
		return
	}
}

// notificationHandler queues and dequeues notifications. There are currently
// no bounds on the queue, so the dequeue channel should be read continually to
// avoid running out of memory.
func (s *NeutrinoClient) notificationHandler() {
	hash, height, err := s.GetBestBlock()
	if err != nil {
		log.Errorf("Failed to get best block from chain service: %s",
			err)
		s.Stop()
		s.wg.Done()
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
	enqueue := s.enqueueNotification
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
				dequeue = s.dequeueNotification
			}
			notifications = append(notifications, n)

		case dequeue <- next:
			if n, ok := next.(BlockConnected); ok {
				bs = &waddrmgr.BlockStamp{
					Height: n.Height,
					Hash:   n.Hash,
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

		case err := <-s.rescanErr:
			if err != nil {
				log.Errorf("Neutrino rescan ended with error: %s", err)
			}

		case s.currentBlock <- bs:

		case <-s.quit:
			break out
		}
	}

	s.Stop()
	close(s.dequeueNotification)
	s.wg.Done()
}

// createRescan is a convenience method to consistently recreate a rescanner.
func (s *NeutrinoClient) createRescan(opts ...neutrino.RescanOption) {
	var (
		// Create a quit channel for the new rescanner.
		stop = make(chan struct{})

		// Inject the rescanner constructor.
		newRescan = s.getNewRescanFunc()

		// Wrap the quit channel inside closures to use as handlers.
		obc = func(hash *chainhash.Hash, height int32, time time.Time) {
			s.onBlockConnected(stop, hash, height, time)
		}

		ofbc = func(height int32, header *wire.BlockHeader, txs []*btcutil.Tx) {
			s.onFilteredBlockConnected(stop, height, header, txs)
		}

		obd = func(hash *chainhash.Hash, height int32, time time.Time) {
			s.onBlockDisconnected(stop, hash, height, time)
		}

		// Build the default options for the rescanner.
		defaultOpts = []neutrino.RescanOption{
			neutrino.NotificationHandlers(rpcclient.NotificationHandlers{
				OnBlockConnected:         obc,
				OnFilteredBlockConnected: ofbc,
				OnBlockDisconnected:      obd,
			}),
			neutrino.StartTime(s.startTime),
			neutrino.QuitChan(stop),
		}
		fullOpts = append(opts, defaultOpts...)
	)

	// Construct the rescan.
	rescan := newRescan(fullOpts...)

	// Broadcast the new objects via sends on their respective channels.
	s.rescanCh <- rescan
	s.rescanQuitCh <- stop

	// Only start the rescanner after it is sucessfully broadcast.
	errCh := rescan.Start()

	// Start a goroutine to consume any errors and broadcast them on
	// s.rescanErr.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.consumeRescanErr(stop, errCh)
	}()
}

// consumeRescanErr forwards errors from the rescan goroutine to the client.
// Stops sending errors when either the client signals to quit, the rescanner
// associated with the error channel is shutdown or the channel of errors is
// closed.
func (s *NeutrinoClient) consumeRescanErr(
	rescanQuit <-chan struct{},
	errCh <-chan error,
) {
	for {
		select {
		case <-s.quit:
			return
		case <-rescanQuit:
			return
		case err, open := <-errCh:
			if !open {
				return
			}
			select {
			case s.rescanErr <- err:
			case <-s.quit:
				return
			case <-rescanQuit:
				return
			}
		}
	}
}

// getNewRescanFunc injects the Rescanner constructor when called and defaults
// to using neutrino.NewRescan when unspecified.
func (s *NeutrinoClient) getNewRescanFunc() rescan.NewFunc {
	if s.newRescanFunc == nil {
		s.newRescanFunc = func(ropts ...neutrino.RescanOption) rescan.Interface {
			cs := &neutrino.RescanChainSource{
				ChainService: s.CS.(*neutrino.ChainService),
			}
			return neutrino.NewRescan(cs, ropts...)
		}
	}
	return s.newRescanFunc
}

// toInputsToWatch transforms an address map into an array of inputs with script.
func toInputsToWatch(
	ops map[wire.OutPoint]btcutil.Address,
) ([]neutrino.InputWithScript, error) {
	inputsToWatch := make([]neutrino.InputWithScript, 0, len(ops))
	for op, addr := range ops {
		addrScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}

		inputsToWatch = append(inputsToWatch, neutrino.InputWithScript{
			OutPoint: op,
			PkScript: addrScript,
		})
	}
	return inputsToWatch, nil
}
