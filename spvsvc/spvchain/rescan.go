// NOTE: THIS API IS UNSTABLE RIGHT NOW.

package spvchain

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcrpcclient"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/gcs"
	"github.com/btcsuite/btcutil/gcs/builder"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// Relevant package-level variables live here
var ()

// Functional parameters for Rescan
type rescanOptions struct {
	queryOptions   []QueryOption
	ntfn           btcrpcclient.NotificationHandlers
	startBlock     *waddrmgr.BlockStamp
	endBlock       *waddrmgr.BlockStamp
	watchAddrs     []btcutil.Address
	watchOutPoints []wire.OutPoint
	watchTXIDs     []chainhash.Hash
	quit           <-chan struct{}
}

// RescanOption is a functional option argument to any of the rescan and
// notification subscription methods. These are always processed in order, with
// later options overriding earlier ones.
type RescanOption func(ro *rescanOptions)

func defaultRescanOptions() *rescanOptions {
	return &rescanOptions{}
}

// QueryOptions pass onto the underlying queries.
func QueryOptions(options ...QueryOption) RescanOption {
	return func(ro *rescanOptions) {
		ro.queryOptions = options
	}
}

// NotificationHandlers specifies notification handlers for the rescan. These
// will always run in the same goroutine as the caller.
func NotificationHandlers(ntfn btcrpcclient.NotificationHandlers) RescanOption {
	return func(ro *rescanOptions) {
		ro.ntfn = ntfn
	}
}

// StartBlock specifies the start block. The hash is checked first; if there's
// no such hash (zero hash avoids lookup), the height is checked next. If
// the height is 0 or the start block isn't specified, starts from the genesis
// block. This block is assumed to already be known, and no notifications will
// be sent for this block.
func StartBlock(startBlock *waddrmgr.BlockStamp) RescanOption {
	return func(ro *rescanOptions) {
		ro.startBlock = startBlock
	}
}

// EndBlock specifies the end block. The hash is checked first; if there's no
// such hash (zero hash avoids lookup), the height is checked next. If the
// height is 0 or in the future or the end block isn't specified, the quit
// channel MUST be specified as Rescan will sync to the tip of the blockchain
// and continue to stay in sync and pass notifications. This is enforced at
// runtime.
func EndBlock(endBlock *waddrmgr.BlockStamp) RescanOption {
	return func(ro *rescanOptions) {
		ro.endBlock = endBlock
	}
}

// WatchAddrs specifies the addresses to watch/filter for. Each call to this
// function adds to the list of addresses being watched rather than replacing
// the list. Each time a transaction spends to the specified address, the
// outpoint is added to the WatchOutPoints list.
func WatchAddrs(watchAddrs ...btcutil.Address) RescanOption {
	return func(ro *rescanOptions) {
		ro.watchAddrs = append(ro.watchAddrs, watchAddrs...)
	}
}

// WatchOutPoints specifies the outpoints to watch for on-chain spends. Each
// call to this function adds to the list of outpoints being watched rather
// than replacing the list.
func WatchOutPoints(watchOutPoints ...wire.OutPoint) RescanOption {
	return func(ro *rescanOptions) {
		ro.watchOutPoints = append(ro.watchOutPoints, watchOutPoints...)
	}
}

// WatchTXIDs specifies the outpoints to watch for on-chain spends. Each
// call to this function adds to the list of outpoints being watched rather
// than replacing the list.
func WatchTXIDs(watchTXIDs ...chainhash.Hash) RescanOption {
	return func(ro *rescanOptions) {
		ro.watchTXIDs = append(ro.watchTXIDs, watchTXIDs...)
	}
}

// QuitChan specifies the quit channel. This can be used by the caller to let
// an indefinite rescan (one with no EndBlock set) know it should gracefully
// shut down. If this isn't specified, an end block MUST be specified as Rescan
// must know when to stop. This is enforced at runtime.
func QuitChan(quit <-chan struct{}) RescanOption {
	return func(ro *rescanOptions) {
		ro.quit = quit
	}
}

// Rescan is a single-threaded function that uses headers from the database and
// functional options as arguments.
func (s *ChainService) Rescan(options ...RescanOption) error {
	ro := defaultRescanOptions()
	ro.endBlock = &waddrmgr.BlockStamp{
		Hash:   *s.chainParams.GenesisHash,
		Height: 0,
	}
	for _, option := range options {
		option(ro)
	}

	var watchList [][]byte
	// If we have something to watch, create a watch list.
	for _, addr := range ro.watchAddrs {
		watchList = append(watchList, addr.ScriptAddress())
	}
	for _, op := range ro.watchOutPoints {
		watchList = append(watchList,
			builder.OutPointToFilterEntry(op))
	}
	for _, txid := range ro.watchTXIDs {
		watchList = append(watchList, txid[:])
	}
	if len(watchList) == 0 {
		return fmt.Errorf("Rescan must specify addresses and/or " +
			"outpoints and/or TXIDs to watch")
	}

	// Check that we have either an end block or a quit channel.
	if ro.endBlock != nil {
		if (ro.endBlock.Hash != chainhash.Hash{}) {
			_, height, err := s.GetBlockByHash(ro.endBlock.Hash)
			if err != nil {
				ro.endBlock.Hash = chainhash.Hash{}
			} else {
				ro.endBlock.Height = int32(height)
			}
		}
		if (ro.endBlock.Hash == chainhash.Hash{}) {
			if ro.endBlock.Height != 0 {
				header, err := s.GetBlockByHeight(
					uint32(ro.endBlock.Height))
				if err == nil {
					ro.endBlock.Hash = header.BlockHash()
				} else {
					ro.endBlock = &waddrmgr.BlockStamp{}
				}
			}
		}
	} else {
		ro.endBlock = &waddrmgr.BlockStamp{}
	}
	if ro.quit == nil && ro.endBlock.Height == 0 {
		return fmt.Errorf("Rescan request must specify a quit channel" +
			" or valid end block")
	}

	// Track our position in the chain.
	var curHeader wire.BlockHeader
	curStamp := *ro.startBlock

	// Find our starting block.
	if (curStamp.Hash != chainhash.Hash{}) {
		header, height, err := s.GetBlockByHash(curStamp.Hash)
		if err == nil {
			curHeader = header
			curStamp.Height = int32(height)
		} else {
			curStamp.Hash = chainhash.Hash{}
		}
	}
	if (curStamp.Hash == chainhash.Hash{}) {
		if curStamp.Height == 0 {
			curStamp.Hash = *s.chainParams.GenesisHash
		} else {
			header, err := s.GetBlockByHeight(
				uint32(curStamp.Height))
			if err == nil {
				curHeader = header
				curStamp.Hash = curHeader.BlockHash()
			} else {
				curHeader =
					s.chainParams.GenesisBlock.Header
				curStamp.Hash =
					*s.chainParams.GenesisHash
				curStamp.Height = 0
			}
		}
	}
	log.Tracef("Starting rescan from known block %d (%s)", curStamp.Height,
		curStamp.Hash)

	// Listen for notifications.
	blockConnected := make(chan wire.BlockHeader)
	blockDisconnected := make(chan wire.BlockHeader)
	subscription := blockSubscription{
		onConnectBasic: blockConnected,
		onDisconnect:   blockDisconnected,
		quit:           ro.quit,
	}

	// Loop through blocks, one at a time. This relies on the underlying
	// ChainService API to send blockConnected and blockDisconnected
	// notifications in the correct order.
	current := false
rescanLoop:
	for {
		// If we're current, we wait for notifications.
		if current {
			// Wait for a signal that we have a newly connected
			// header and cfheader, or a newly disconnected header;
			// alternatively, forward ourselves to the next block
			// if possible.
			select {
			case <-ro.quit:
				s.unsubscribeBlockMsgs(subscription)
				return nil
			case header := <-blockConnected:
				// Only deal with the next block from what we
				// know about. Otherwise, it's in the future.
				if header.PrevBlock != curStamp.Hash {
					continue rescanLoop
				}
				curHeader = header
				curStamp.Hash = header.BlockHash()
				curStamp.Height++
			case header := <-blockDisconnected:
				// Only deal with it if it's the current block
				// we know about. Otherwise, it's in the future.
				if header.BlockHash() == curStamp.Hash {
					// Run through notifications. This is
					// all single-threaded. We include
					// deprecated calls as they're still
					// used, for now.
					if ro.ntfn.
						OnFilteredBlockDisconnected !=
						nil {
						ro.ntfn.OnFilteredBlockDisconnected(
							curStamp.Height,
							&curHeader)
					}
					if ro.ntfn.OnBlockDisconnected != nil {
						ro.ntfn.OnBlockDisconnected(
							&curStamp.Hash,
							curStamp.Height,
							curHeader.Timestamp)
					}
					header, _, err := s.GetBlockByHash(
						header.PrevBlock)
					if err != nil {
						return err
					}
					curHeader = header
					curStamp.Hash = header.BlockHash()
					curStamp.Height--
				}
				continue rescanLoop
			}
		} else {
			// Since we're not current, we try to manually advance
			// the block. If we fail, we mark outselves as current
			// and follow notifications.
			header, err := s.GetBlockByHeight(uint32(
				curStamp.Height + 1))
			if err != nil {
				log.Tracef("Rescan became current at %d (%s), "+
					"subscribing to block notifications",
					curStamp.Height, curStamp.Hash)
				current = true
				// Subscribe to block notifications.
				s.subscribeBlockMsg(subscription)
				continue rescanLoop
			}
			curHeader = header
			curStamp.Height++
			curStamp.Hash = header.BlockHash()
		}

		// At this point, we've found the block header that's next in
		// our rescan. First, if we're sending out BlockConnected
		// notifications, do that.
		if ro.ntfn.OnBlockConnected != nil {
			ro.ntfn.OnBlockConnected(&curStamp.Hash,
				curStamp.Height, curHeader.Timestamp)
		}
		// Now we need to see if it matches the rescan's filters, so we
		// get the basic filter from the DB or network.
		var block *btcutil.Block
		var relevantTxs []*btcutil.Tx
		var bFilter, eFilter *gcs.Filter
		var err error
		key := builder.DeriveKey(&curStamp.Hash)
		matched := false
		bFilter = s.GetCFilter(curStamp.Hash, false)
		if bFilter != nil && bFilter.N() != 0 {
			// We see if any relevant transactions match.
			matched, err = bFilter.MatchAny(key, watchList)
			if err != nil {
				return err
			}
		}
		if len(ro.watchTXIDs) > 0 {
			eFilter = s.GetCFilter(curStamp.Hash, true)
		}
		if eFilter != nil && eFilter.N() != 0 {
			// We see if any relevant transactions match.
			matched, err = eFilter.MatchAny(key, watchList)
			if err != nil {
				return err
			}
		}
		// If we have no transactions, we just send an
		// OnFilteredBlockConnected notification with  no relevant
		// transactions.
		if matched {
			// We've matched. Now we actually get the block
			// and cycle through the transactions to see
			// which ones are relevant.
			block = s.GetBlockFromNetwork(
				curStamp.Hash, ro.queryOptions...)
			if block == nil {
				return fmt.Errorf("Couldn't get block "+
					"%d (%s)", curStamp.Height,
					curStamp.Hash)
			}
			relevantTxs, err = notifyBlock(block,
				&ro.watchOutPoints, ro.watchAddrs,
				ro.watchTXIDs, &watchList, ro.ntfn)
			if err != nil {
				return err
			}
		}
		if ro.ntfn.OnFilteredBlockConnected != nil {
			ro.ntfn.OnFilteredBlockConnected(curStamp.Height,
				&curHeader, relevantTxs)
		}
		if curStamp.Hash == ro.endBlock.Hash || curStamp.Height ==
			ro.endBlock.Height {
			return nil
		}
	}
}

// notifyBlock notifies listeners based on the block filter. It writes back to
// the outPoints argument the updated list of outpoints to monitor based on
// matched addresses.
func notifyBlock(block *btcutil.Block, outPoints *[]wire.OutPoint,
	addrs []btcutil.Address, txids []chainhash.Hash, watchList *[][]byte,
	ntfn btcrpcclient.NotificationHandlers) ([]*btcutil.Tx, error) {
	var relevantTxs []*btcutil.Tx
	blockHeader := block.MsgBlock().Header
	details := btcjson.BlockDetails{
		Height: block.Height(),
		Hash:   block.Hash().String(),
		Time:   blockHeader.Timestamp.Unix(),
	}
	for txIdx, tx := range block.Transactions() {
		relevant := false
		txDetails := details
		txDetails.Index = txIdx
		for _, hash := range txids {
			if hash == *(tx.Hash()) {
				relevant = true
				break
			}
		}
		for _, in := range tx.MsgTx().TxIn {
			if relevant {
				break
			}
			for _, op := range *outPoints {
				if in.PreviousOutPoint == op {
					relevant = true
					if ntfn.OnRedeemingTx != nil {
						ntfn.OnRedeemingTx(tx,
							&txDetails)
					}
					break
				}
			}
		}
		for outIdx, out := range tx.MsgTx().TxOut {
			pushedData, err :=
				txscript.PushedData(
					out.PkScript)
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if relevant {
					break
				}
				for _, data := range pushedData {
					if bytes.Equal(data,
						addr.ScriptAddress()) {
						relevant = true
						hash := tx.Hash()
						outPoint := wire.OutPoint{
							Hash:  *hash,
							Index: uint32(outIdx),
						}
						*outPoints = append(*outPoints,
							outPoint)
						*watchList = append(*watchList,
							builder.OutPointToFilterEntry(
								outPoint))
						if ntfn.OnRecvTx != nil {
							ntfn.OnRecvTx(tx,
								&txDetails)
						}
					}
				}
			}
		}
		if relevant {
			relevantTxs = append(relevantTxs, tx)
		}
	}
	return relevantTxs, nil
}
