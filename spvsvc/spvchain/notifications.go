// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spvchain

import (
	"errors"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/gcs"
	"github.com/btcsuite/btcutil/gcs/builder"
)

type getConnCountMsg struct {
	reply chan int32
}

type getPeersMsg struct {
	reply chan []*serverPeer
}

type getOutboundGroup struct {
	key   string
	reply chan int
}

type getAddedNodesMsg struct {
	reply chan []*serverPeer
}

type disconnectNodeMsg struct {
	cmp   func(*serverPeer) bool
	reply chan error
}

type connectNodeMsg struct {
	addr      string
	permanent bool
	reply     chan error
}

type removeNodeMsg struct {
	cmp   func(*serverPeer) bool
	reply chan error
}

type forAllPeersMsg struct {
	closure func(*serverPeer)
}

type getCFilterMsg struct {
	cfRequest
	prevHeader *chainhash.Hash
	curHeader  *chainhash.Hash
	reply      chan *gcs.Filter
}

type getBlockMsg struct {
	blockHeader *wire.BlockHeader
	height      uint32
	reply       chan *btcutil.Block
}

// TODO: General - abstract out more of blockmanager into queries. It'll make
// this way more maintainable and usable.

// handleQuery is the central handler for all queries and commands from other
// goroutines related to peer state.
func (s *ChainService) handleQuery(state *peerState, querymsg interface{}) {
	switch msg := querymsg.(type) {
	case getConnCountMsg:
		nconnected := int32(0)
		state.forAllPeers(func(sp *serverPeer) {
			if sp.Connected() {
				nconnected++
			}
		})
		msg.reply <- nconnected

	case getPeersMsg:
		peers := make([]*serverPeer, 0, state.Count())
		state.forAllPeers(func(sp *serverPeer) {
			if !sp.Connected() {
				return
			}
			peers = append(peers, sp)
		})
		msg.reply <- peers

	case connectNodeMsg:
		// TODO: duplicate oneshots?
		// Limit max number of total peers.
		if state.Count() >= MaxPeers {
			msg.reply <- errors.New("max peers reached")
			return
		}
		for _, peer := range state.persistentPeers {
			if peer.Addr() == msg.addr {
				if msg.permanent {
					msg.reply <- errors.New("peer already connected")
				} else {
					msg.reply <- errors.New("peer exists as a permanent peer")
				}
				return
			}
		}

		netAddr, err := addrStringToNetAddr(msg.addr)
		if err != nil {
			msg.reply <- err
			return
		}

		// TODO: if too many, nuke a non-perm peer.
		go s.connManager.Connect(&connmgr.ConnReq{
			Addr:      netAddr,
			Permanent: msg.permanent,
		})
		msg.reply <- nil
	case removeNodeMsg:
		found := disconnectPeer(state.persistentPeers, msg.cmp, func(sp *serverPeer) {
			// Keep group counts ok since we remove from
			// the list now.
			state.outboundGroups[addrmgr.GroupKey(sp.NA())]--
		})

		if found {
			msg.reply <- nil
		} else {
			msg.reply <- errors.New("peer not found")
		}
	case getOutboundGroup:
		count, ok := state.outboundGroups[msg.key]
		if ok {
			msg.reply <- count
		} else {
			msg.reply <- 0
		}
	// Request a list of the persistent (added) peers.
	case getAddedNodesMsg:
		// Respond with a slice of the relavent peers.
		peers := make([]*serverPeer, 0, len(state.persistentPeers))
		for _, sp := range state.persistentPeers {
			peers = append(peers, sp)
		}
		msg.reply <- peers
	case disconnectNodeMsg:
		// Check outbound peers.
		found := disconnectPeer(state.outboundPeers, msg.cmp, func(sp *serverPeer) {
			// Keep group counts ok since we remove from
			// the list now.
			state.outboundGroups[addrmgr.GroupKey(sp.NA())]--
		})
		if found {
			// If there are multiple outbound connections to the same
			// ip:port, continue disconnecting them all until no such
			// peers are found.
			for found {
				found = disconnectPeer(state.outboundPeers, msg.cmp, func(sp *serverPeer) {
					state.outboundGroups[addrmgr.GroupKey(sp.NA())]--
				})
			}
			msg.reply <- nil
			return
		}

		msg.reply <- errors.New("peer not found")
	case forAllPeersMsg:
		// Run the closure on all peers in the passed state.
		state.forAllPeers(msg.closure)
		// Even though this is a query, there's no reply channel as the
		// forAllPeers method doesn't return anything. An error might be
		// useful in the future.
	case getCFilterMsg:
		found := false
		state.queryPeers(
			// Should we query this peer?
			func(sp *serverPeer) bool {
				// Don't send requests to disconnected peers.
				return sp.Connected()
			},
			// Send a wire.GetCFilterMsg
			wire.NewMsgGetCFilter(&msg.blockHash, msg.extended),
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
					filter, err :=
						gcs.FromNBytes(builder.DefaultP,
							response.Data)
					if err != nil {
						// Malformed filter data. We
						// can ignore this message.
						return
					}
					if MakeHeaderForFilter(filter,
						*msg.prevHeader) !=
						*msg.curHeader {
						// Filter data doesn't match
						// the headers we know about.
						// Ignore this response.
						return
					}
					// At this point, the filter matches
					// what we know about it and we declare
					// it sane. We can kill the query and
					// pass the response back to the caller.
					found = true
					close(quit)
					msg.reply <- filter
				default:
				}
			},
		)
		// We timed out without finding a correct answer to our query.
		if !found {
			msg.reply <- nil
		}
	case getBlockMsg:
		found := false
		getData := wire.NewMsgGetData()
		blockHash := msg.blockHeader.BlockHash()
		getData.AddInvVect(wire.NewInvVect(wire.InvTypeBlock,
			&blockHash))
		state.queryPeers(
			// Should we query this peer?
			func(sp *serverPeer) bool {
				// Don't send requests to disconnected peers.
				return sp.Connected()
			},
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
							int32(msg.height))
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
						log.Warnf("Invalid block for "+
							"%s received from %s "+
							"-- disconnecting peer",
							blockHash, sp.Addr())
						sp.Disconnect()
						return
					}
					found = true
					close(quit)
					msg.reply <- block
				default:
				}
			},
		)
		// We timed out without finding a correct answer to our query.
		if !found {
			msg.reply <- nil
		}
	}
}
