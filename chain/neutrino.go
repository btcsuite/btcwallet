package chain

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcrpcclient"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/neutrino"
)

// SPVChain is an implementation of the btcwalet chain.Interface interface.
type SPVChain struct {
	CS *neutrino.ChainService

	// We currently support one rescan/notifiction goroutine per client
	rescan neutrino.Rescan

	enqueueNotification chan interface{}
	dequeueNotification chan interface{}
	currentBlock        chan *waddrmgr.BlockStamp

	quit       chan struct{}
	rescanQuit chan struct{}
	rescanErr  <-chan error
	wg         sync.WaitGroup
	started    bool
	scanning   bool
	finished   bool

	clientMtx sync.Mutex
}

// NewSPVChain creates a new SPVChain struct with a backing ChainService
func NewSPVChain(chainService *neutrino.ChainService) *SPVChain {
	return &SPVChain{CS: chainService}
}

// Start replicates the RPC client's Start method.
func (s *SPVChain) Start() error {
	s.CS.Start()
	s.clientMtx.Lock()
	defer s.clientMtx.Unlock()
	if !s.started {
		s.enqueueNotification = make(chan interface{})
		s.dequeueNotification = make(chan interface{})
		s.currentBlock = make(chan *waddrmgr.BlockStamp)
		s.quit = make(chan struct{})
		s.started = true
		s.wg.Add(1)
		go func() {
			select {
			case s.enqueueNotification <- ClientConnected{}:
			case <-s.quit:
				return
			}
		}()
		go s.notificationHandler()
	}
	return nil
}

// Stop replicates the RPC client's Stop method.
func (s *SPVChain) Stop() {
	s.clientMtx.Lock()
	defer s.clientMtx.Unlock()
	if !s.started {
		return
	}
	close(s.quit)
	s.started = false
}

// WaitForShutdown replicates the RPC client's WaitForShutdown method.
func (s *SPVChain) WaitForShutdown() {
	s.wg.Wait()
}

// GetBlock replicates the RPC client's GetBlock command.
func (s *SPVChain) GetBlock(hash *chainhash.Hash) (*wire.MsgBlock, error) {
	// TODO(roasbeef): add a block cache?
	//  * which evication strategy? depends on use case
	//  Should the block cache be INSIDE neutrino instead of in btcwallet?
	block, err := s.CS.GetBlockFromNetwork(*hash)
	if err != nil {
		return nil, err
	}
	return block.MsgBlock(), nil
}

// GetBlockHeight gets the height of a block by its hash. It serves as a
// replacement for the use of GetBlockVerboseTxAsync for the wallet package
// since we can't actually return a FutureGetBlockVerboseResult because the
// underlying type is private to btcrpcclient.
func (s *SPVChain) GetBlockHeight(hash *chainhash.Hash) (int32, error) {
	_, height, err := s.CS.GetBlockByHash(*hash)
	if err != nil {
		return 0, err
	}
	return int32(height), nil
}

// GetBestBlock replicates the RPC client's GetBestBlock command.
func (s *SPVChain) GetBestBlock() (*chainhash.Hash, int32, error) {
	header, height, err := s.CS.LatestBlock()
	if err != nil {
		return nil, 0, err
	}
	hash := header.BlockHash()
	return &hash, int32(height), nil
}

// BlockStamp returns the latest block notified by the client, or an error
// if the client has been shut down.
func (s *SPVChain) BlockStamp() (*waddrmgr.BlockStamp, error) {
	select {
	case bs := <-s.currentBlock:
		return bs, nil
	case <-s.quit:
		return nil, errors.New("disconnected")
	}
}

// SendRawTransaction replicates the RPC client's SendRawTransaction command.
func (s *SPVChain) SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (
	*chainhash.Hash, error) {
	err := s.CS.SendTransaction(tx)
	if err != nil {
		return nil, err
	}
	hash := tx.TxHash()
	return &hash, nil
}

// Rescan replicates the RPC client's Rescan command.
func (s *SPVChain) Rescan(startHash *chainhash.Hash, addrs []btcutil.Address,
	outPoints []*wire.OutPoint) error {
	s.clientMtx.Lock()
	if !s.started {
		s.clientMtx.Unlock()
		return fmt.Errorf("can't do a rescan when the chain client " +
			"is not started")
	}
	if s.scanning {
		// Restart the rescan by killing the existing rescan.
		close(s.rescanQuit)
	}
	s.rescanQuit = make(chan struct{})
	s.scanning = true
	s.finished = false
	s.clientMtx.Unlock()
	watchOutPoints := make([]wire.OutPoint, 0, len(outPoints))
	for _, op := range outPoints {
		watchOutPoints = append(watchOutPoints, *op)
	}
	s.rescan = s.CS.NewRescan(
		neutrino.NotificationHandlers(btcrpcclient.NotificationHandlers{
			OnFilteredBlockConnected: s.onFilteredBlockConnected,
			OnBlockDisconnected:      s.onBlockDisconnected,
		}),
		neutrino.StartBlock(&waddrmgr.BlockStamp{Hash: *startHash}),
		neutrino.QuitChan(s.rescanQuit),
		neutrino.WatchAddrs(addrs...),
		neutrino.WatchOutPoints(watchOutPoints...),
	)
	s.rescanErr = s.rescan.Start()
	return nil
}

// NotifyBlocks replicates the RPC client's NotifyBlocks command.
func (s *SPVChain) NotifyBlocks() error {
	s.clientMtx.Lock()
	// If we're scanning, we're already notifying on blocks. Otherwise,
	// start a rescan without watching any addresses.
	if !s.scanning {
		s.clientMtx.Unlock()
		return s.NotifyReceived([]btcutil.Address{})
	}
	s.clientMtx.Unlock()
	return nil
}

// NotifyReceived replicates the RPC client's NotifyReceived command.
func (s *SPVChain) NotifyReceived(addrs []btcutil.Address) error {
	// If we have a rescan running, we just need to add the appropriate
	// addresses to the watch list.
	s.clientMtx.Lock()
	if s.scanning {
		s.clientMtx.Unlock()
		return s.rescan.Update(neutrino.AddAddrs(addrs...))
	}
	s.rescanQuit = make(chan struct{})
	s.scanning = true
	// Don't need RescanFinished notifications.
	s.finished = true
	s.clientMtx.Unlock()
	// Rescan with just the specified addresses.
	s.rescan = s.CS.NewRescan(
		neutrino.NotificationHandlers(btcrpcclient.NotificationHandlers{
			OnFilteredBlockConnected: s.onFilteredBlockConnected,
			OnBlockDisconnected:      s.onBlockDisconnected,
		}),
		neutrino.QuitChan(s.rescanQuit),
		neutrino.WatchAddrs(addrs...),
	)
	s.rescanErr = s.rescan.Start()
	return nil
}

// Notifications replicates the RPC client's Notifications method.
func (s *SPVChain) Notifications() <-chan interface{} {
	return s.dequeueNotification
}

// onFilteredBlockConnected sends appropriate notifications to the notification
// channel.
func (s *SPVChain) onFilteredBlockConnected(height int32,
	header *wire.BlockHeader, relevantTxs []*btcutil.Tx) {
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
	case <-s.rescanQuit:
		return
	}
	bs, err := s.CS.SyncedTo()
	if err != nil {
		log.Errorf("Can't get chain service's best block: %s", err)
		return
	}
	if bs.Hash == header.BlockHash() {
		// Only send the RescanFinished notification once.
		s.clientMtx.Lock()
		if s.finished {
			s.clientMtx.Unlock()
			return
		}
		s.finished = true
		s.clientMtx.Unlock()
		select {
		case s.enqueueNotification <- &RescanFinished{
			Hash:   &bs.Hash,
			Height: bs.Height,
			Time:   header.Timestamp,
		}:
		case <-s.quit:
			return
		case <-s.rescanQuit:
			return

		}
	}
}

// onBlockDisconnected sends appropriate notifications to the notification
// channel.
func (s *SPVChain) onBlockDisconnected(hash *chainhash.Hash, height int32,
	t time.Time) {
	select {
	case s.enqueueNotification <- BlockDisconnected{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: t,
	}:
	case <-s.quit:
	case <-s.rescanQuit:
	}
}

// notificationHandler queues and dequeues notifications. There are currently
// no bounds on the queue, so the dequeue channel should be read continually to
// avoid running out of memory.
func (s *SPVChain) notificationHandler() {
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
