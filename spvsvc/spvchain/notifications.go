// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spvchain

import (
	"errors"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/connmgr"
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
		// TODO: Remove this when it's unnecessary due to wider use of
		// queryPeers.
		// Run the closure on all peers in the passed state.
		state.forAllPeers(msg.closure)
		// Even though this is a query, there's no reply channel as the
		// forAllPeers method doesn't return anything. An error might be
		// useful in the future.
	}
}

// ConnectedCount returns the number of currently connected peers.
func (s *ChainService) ConnectedCount() int32 {
	replyChan := make(chan int32)

	s.query <- getConnCountMsg{reply: replyChan}

	return <-replyChan
}

// OutboundGroupCount returns the number of peers connected to the given
// outbound group key.
func (s *ChainService) OutboundGroupCount(key string) int {
	replyChan := make(chan int)
	s.query <- getOutboundGroup{key: key, reply: replyChan}
	return <-replyChan
}

// AddedNodeInfo returns an array of btcjson.GetAddedNodeInfoResult structures
// describing the persistent (added) nodes.
func (s *ChainService) AddedNodeInfo() []*serverPeer {
	replyChan := make(chan []*serverPeer)
	s.query <- getAddedNodesMsg{reply: replyChan}
	return <-replyChan
}

// Peers returns an array of all connected peers.
func (s *ChainService) Peers() []*serverPeer {
	replyChan := make(chan []*serverPeer)

	s.query <- getPeersMsg{reply: replyChan}

	return <-replyChan
}

// DisconnectNodeByAddr disconnects a peer by target address. Both outbound and
// inbound nodes will be searched for the target node. An error message will
// be returned if the peer was not found.
func (s *ChainService) DisconnectNodeByAddr(addr string) error {
	replyChan := make(chan error)

	s.query <- disconnectNodeMsg{
		cmp:   func(sp *serverPeer) bool { return sp.Addr() == addr },
		reply: replyChan,
	}

	return <-replyChan
}

// DisconnectNodeByID disconnects a peer by target node id. Both outbound and
// inbound nodes will be searched for the target node. An error message will be
// returned if the peer was not found.
func (s *ChainService) DisconnectNodeByID(id int32) error {
	replyChan := make(chan error)

	s.query <- disconnectNodeMsg{
		cmp:   func(sp *serverPeer) bool { return sp.ID() == id },
		reply: replyChan,
	}

	return <-replyChan
}

// RemoveNodeByAddr removes a peer from the list of persistent peers if
// present. An error will be returned if the peer was not found.
func (s *ChainService) RemoveNodeByAddr(addr string) error {
	replyChan := make(chan error)

	s.query <- removeNodeMsg{
		cmp:   func(sp *serverPeer) bool { return sp.Addr() == addr },
		reply: replyChan,
	}

	return <-replyChan
}

// RemoveNodeByID removes a peer by node ID from the list of persistent peers
// if present. An error will be returned if the peer was not found.
func (s *ChainService) RemoveNodeByID(id int32) error {
	replyChan := make(chan error)

	s.query <- removeNodeMsg{
		cmp:   func(sp *serverPeer) bool { return sp.ID() == id },
		reply: replyChan,
	}

	return <-replyChan
}

// ConnectNode adds `addr' as a new outbound peer. If permanent is true then the
// peer will be persistent and reconnect if the connection is lost.
// It is an error to call this with an already existing peer.
func (s *ChainService) ConnectNode(addr string, permanent bool) error {
	replyChan := make(chan error)

	s.query <- connectNodeMsg{addr: addr, permanent: permanent, reply: replyChan}

	return <-replyChan
}

// ForAllPeers runs a closure over all peers (outbound and persistent) to which
// the ChainService is connected. Nothing is returned because the peerState's
// ForAllPeers method doesn't return anything as the closure passed to it
// doesn't return anything.
func (s *ChainService) ForAllPeers(closure func(sp *serverPeer)) {
	s.query <- forAllPeersMsg{
		closure: closure,
	}
}
