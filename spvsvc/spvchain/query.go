// NOTE: THIS API IS UNSTABLE RIGHT NOW.

package spvchain

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/gcs"
	"github.com/btcsuite/btcutil/gcs/builder"
)

var (
	// QueryTimeout specifies how long to wait for a peer to answer a query.
	QueryTimeout = time.Second * 3

	// QueryNumRetries specifies how many times to retry sending a query to
	// each peer before we've concluded we aren't going to get a valid
	// response. This allows to make up for missed messages in some
	// instances.
	QueryNumRetries = 2
)

// Query options can be modified per-query, unlike global options.
// TODO: Make more query options that override global options.
type queryOptions struct {
	// timeout lets the query know how long to wait for a peer to
	// answer the query before moving onto the next peer.
	timeout time.Duration

	// numRetries tells the query how many times to retry asking each peer
	// the query.
	numRetries uint8

	// doneChan lets the query signal the caller when it's done, in case
	// it's run in a goroutine.
	doneChan chan<- struct{}
}

// QueryOption is a functional option argument to any of the network query
// methods, such as GetBlockFromNetwork and GetCFilter (when that resorts to a
// network query). These are always processed in order, with later options
// overriding earlier ones.
type QueryOption func(*queryOptions)

// defaultQueryOptions returns a queryOptions set to package-level defaults.
func defaultQueryOptions() *queryOptions {
	return &queryOptions{
		timeout:    QueryTimeout,
		numRetries: uint8(QueryNumRetries),
	}
}

// Timeout is a query option that lets the query know how long to wait for
// each peer we ask the query to answer it before moving on.
func Timeout(timeout time.Duration) QueryOption {
	return func(qo *queryOptions) {
		qo.timeout = timeout
	}
}

// NumRetries is a query option that lets the query know the maximum number of
// times each peer should be queried. The default is one.
func NumRetries(numRetries uint8) QueryOption {
	return func(qo *queryOptions) {
		qo.numRetries = numRetries
	}
}

// DoneChan allows the caller to pass a channel that will get closed when the
// query is finished.
func DoneChan(doneChan chan<- struct{}) QueryOption {
	return func(qo *queryOptions) {
		qo.doneChan = doneChan
	}
}

type spMsg struct {
	sp  *serverPeer
	msg wire.Message
}

type spMsgSubscription struct {
	msgChan  chan<- spMsg
	quitChan <-chan struct{}
	wg       *sync.WaitGroup
}

// queryPeers is a helper function that sends a query to one or more peers and
// waits for an answer. The timeout for queries is set by the QueryTimeout
// package-level variable.
func (s *ChainService) queryPeers(
	// queryMsg is the message to send to each peer selected by selectPeer.
	queryMsg wire.Message,
	// checkResponse is caled for every message within the timeout period.
	// The quit channel lets the query know to terminate because the
	// required response has been found. This is done by closing the
	// channel.
	checkResponse func(sp *serverPeer, resp wire.Message,
		quit chan<- struct{}),
	// options takes functional options for executing the query.
	options ...QueryOption,
) {
	qo := defaultQueryOptions()
	for _, option := range options {
		option(qo)
	}

	// This is done in a single-threaded query because the peerState is held
	// in a single thread. This is the only part of the query framework that
	// requires access to peerState, so it's done once per query.
	peers := s.Peers()
	syncPeer := s.blockManager.SyncPeer()

	// This will be shared state between the per-peer goroutines.
	quit := make(chan struct{})
	allQuit := make(chan struct{})
	startQuery := make(chan struct{})
	var wg sync.WaitGroup
	var syncPeerTries uint32
	// Increase this number to be able to handle more queries at once as
	// each channel gets results for all queries, otherwise messages can
	// get mixed and there's a vicious cycle of retries causing a bigger
	// message flood, more of which get missed.
	msgChan := make(chan spMsg)
	var subwg sync.WaitGroup
	subscription := spMsgSubscription{
		msgChan:  msgChan,
		quitChan: allQuit,
		wg:       &subwg,
	}

	// Start a goroutine for each peer that potentially queries that peer.
	for _, sp := range peers {
		wg.Add(1)
		go func(sp *serverPeer) {
			numRetries := qo.numRetries
			defer wg.Done()
			defer sp.unsubscribeRecvMsgs(subscription)
			// Should we do this when the goroutine gets a message
			// via startQuery rather than at the launch of the
			// goroutine?
			if !sp.Connected() {
				return
			}
			timeout := make(<-chan time.Time)
		queryLoop:
			for {
				select {
				case <-timeout:
					// After timeout, we try to notify
					// another of our peer goroutines to
					// do a query until we get a signal to
					// quit.
					select {
					case startQuery <- struct{}{}:
					case <-quit:
						return
					case <-allQuit:
						return
					}
					// At this point, we've sent startQuery.
					// We return if we've run through this
					// section of code numRetries times.
					if numRetries--; numRetries == 0 {
						return
					}
				case <-quit:
					// After we're told to quit, we return.
					return
				case <-allQuit:
					// After we're told to quit, we return.
					return
				case <-startQuery:
					// We're the lucky peer whose turn it is
					// to try to answer the current query.
					// TODO: Add support for querying *all*
					// peers simultaneously to avoid timeout
					// delays.
					// If the sync peer hasn't tried yet and
					// we aren't the sync peer, don't do
					// anything but forward the message down
					// the startQuery channel until the
					// sync peer gets a shot.
					if sp == syncPeer {
						atomic.StoreUint32(
							&syncPeerTries, 1)
					}
					if atomic.LoadUint32(&syncPeerTries) ==
						0 {
						select {
						case startQuery <- struct{}{}:
						case <-quit:
							return
						case <-allQuit:
							return
						}
						continue queryLoop
					}
					sp.subscribeRecvMsg(subscription)
					// Don't want the peer hanging on send
					// to the channel if we quit before
					// reading the channel.
					sentChan := make(chan struct{}, 1)
					sp.QueueMessage(queryMsg, sentChan)
					select {
					case <-sentChan:
					case <-quit:
						return
					case <-allQuit:
						return
					}
					timeout = time.After(qo.timeout)
				default:
				}
			}
		}(sp)
	}
	startQuery <- struct{}{}

	// This goroutine will wait until all of the peer-query goroutines have
	// terminated, and then initiate a query shutdown.
	go func() {
		wg.Wait()
		// If we timed out on each goroutine and didn't quit or time out
		// on the main goroutine, make sure our main goroutine knows to
		// quit.
		select {
		case <-allQuit:
		default:
			close(allQuit)
		}
		// Close the done channel, if any
		if qo.doneChan != nil {
			close(qo.doneChan)
		}
		// Wait until all goroutines started by subscriptions have
		// exited after we closed allQuit before letting the message
		// channel get garbage collected.
		subwg.Wait()
	}()

	// Loop for any messages sent to us via our subscription channel and
	// check them for whether they satisfy the query. Break the loop if it's
	// time to quit.
	timeout := time.After(time.Duration(len(peers)+1) *
		qo.timeout * time.Duration(qo.numRetries))
checkResponses:
	for {
		select {
		case <-timeout:
			// When we time out, close the allQuit channel
			// if it hasn't already been closed.
			select {
			case <-allQuit:
			default:
				close(allQuit)
			}
			break checkResponses
		case <-quit:
			break checkResponses
		case <-allQuit:
			break checkResponses
		case sm := <-msgChan:
			// TODO: This will get stuck if checkResponse
			// gets stuck. This is a caveat for callers that
			// should be fixed before exposing this function
			// for public use.
			checkResponse(sm.sp, sm.msg, quit)
		}
	}
}

// GetCFilter gets a cfilter from the database. Failing that, it requests the
// cfilter from the network and writes it to the database.
func (s *ChainService) GetCFilter(blockHash chainhash.Hash,
	extended bool, options ...QueryOption) *gcs.Filter {
	getFilter := s.GetBasicFilter
	getHeader := s.GetBasicHeader
	putFilter := s.putBasicFilter
	if extended {
		getFilter = s.GetExtFilter
		getHeader = s.GetExtHeader
		putFilter = s.putExtFilter
	}
	filter, err := getFilter(blockHash)
	if err == nil && filter != nil {
		return filter
	}
	block, _, err := s.GetBlockByHash(blockHash)
	if err != nil || block.BlockHash() != blockHash {
		return nil
	}
	curHeader, err := getHeader(blockHash)
	if err != nil {
		return nil
	}
	prevHeader, err := getHeader(block.PrevBlock)
	if err != nil {
		return nil
	}
	s.queryPeers(
		// Send a wire.GetCFilterMsg
		wire.NewMsgGetCFilter(&blockHash, extended),
		// Check responses and if we get one that matches,
		// end the query early.
		func(sp *serverPeer, resp wire.Message,
			quit chan<- struct{}) {
			switch response := resp.(type) {
			// We're only interested in "cfilter" messages.
			case *wire.MsgCFilter:
				if len(response.Data) < 4 {
					// Filter data is too short.
					// Ignore this message.
					return
				}
				if blockHash != response.BlockHash {
					// The response doesn't match our
					// request. Ignore this message.
					return
				}
				gotFilter, err :=
					gcs.FromNBytes(builder.DefaultP,
						response.Data)
				if err != nil {
					// Malformed filter data. We
					// can ignore this message.
					return
				}
				if builder.MakeHeaderForFilter(gotFilter,
					*prevHeader) !=
					*curHeader {
					// Filter data doesn't match
					// the headers we know about.
					// Ignore this response.
					return
				}
				// At this point, the filter matches
				// what we know about it and we declare
				// it sane. We can kill the query and
				// pass the response back to the caller.
				close(quit)
				filter = gotFilter
			default:
			}
		},
		options...,
	)
	// If we've found a filter, write it to the database for next time.
	if filter != nil {
		putFilter(blockHash, filter)
		log.Tracef("Wrote filter for block %s, extended: %t",
			blockHash, extended)
	}
	return filter
}

// GetBlockFromNetwork gets a block by requesting it from the network, one peer
// at a time, until one answers.
func (s *ChainService) GetBlockFromNetwork(
	blockHash chainhash.Hash, options ...QueryOption) *btcutil.Block {
	blockHeader, height, err := s.GetBlockByHash(blockHash)
	if err != nil || blockHeader.BlockHash() != blockHash {
		return nil
	}
	getData := wire.NewMsgGetData()
	getData.AddInvVect(wire.NewInvVect(wire.InvTypeBlock,
		&blockHash))
	// The block is only updated from the checkResponse function argument,
	// which is always called single-threadedly. We don't check the block
	// until after the query is finished, so we can just write to it
	// naively.
	var foundBlock *btcutil.Block
	s.queryPeers(
		// Send a wire.GetCFilterMsg
		getData,
		// Check responses and if we get one that matches,
		// end the query early.
		func(sp *serverPeer, resp wire.Message,
			quit chan<- struct{}) {
			switch response := resp.(type) {
			// We're only interested in "block" messages.
			case *wire.MsgBlock:
				// If this isn't our block, ignore it.
				if response.BlockHash() !=
					blockHash {
					return
				}
				block := btcutil.NewBlock(response)
				// Only set height if btcutil hasn't
				// automagically put one in.
				if block.Height() ==
					btcutil.BlockHeightUnknown {
					block.SetHeight(
						int32(height))
				}
				// If this claims our block but doesn't
				// pass the sanity check, the peer is
				// trying to bamboozle us. Disconnect
				// it.
				if err := blockchain.CheckBlockSanity(
					block,
					// We don't need to check PoW
					// because by the time we get
					// here, it's been checked
					// during header synchronization
					s.chainParams.PowLimit,
					s.timeSource,
				); err != nil {
					log.Warnf("Invalid block for %s "+
						"received from %s -- "+
						"disconnecting peer", blockHash,
						sp.Addr())
					sp.Disconnect()
					return
				}
				// At this point, the block matches what we know
				// about it and we declare it sane. We can kill
				// the query and pass the response back to the
				// caller.
				close(quit)
				foundBlock = block
			default:
			}
		},
		options...,
	)
	return foundBlock
}
