// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"fmt"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

// txGraph is a directed acyclic graph containing transaction nodes with their
// dependency nodes.
type txGraph map[chainhash.Hash][]chainhash.Hash

// inDegree is a map of the interior degrees of graph nodes.
type inDegree map[chainhash.Hash]int

// txRecExistsInSlice returns true is a transaction exists in a slice (by hash),
// otherwise false.
func txRecExistsInSlice(s []*TxRecord, e *TxRecord) bool {
	if s == nil {
		return false
	}

	hashE := e.Hash
	for _, a := range s {
		hashS := a.Hash
		if hashS.IsEqual(&hashE) {
			return true
		}
	}
	return false
}

// txRecHashExistsInSlice returns true is a transaction hash exists in a slice of
// msgTx (by hash), otherwise false.
func txRecHashExistsInSlice(s []*TxRecord, e chainhash.Hash) bool {
	if s == nil {
		return false
	}

	for _, a := range s {
		hashS := a.Hash
		if hashS.IsEqual(&e) {
			return true
		}
	}
	return false
}

// txRecFromSliceByHash searches for a tx in a slice by hash, and then returns
// that tx.
func txRecFromSliceByHash(s []*TxRecord, h chainhash.Hash) *TxRecord {
	for _, tx := range s {
		hS := tx.Hash
		if hS.IsEqual(&h) {
			return tx
		}
	}

	return nil
}

// parseTxsAsGraph parses the list of transactions and returns a graph
// representation and a list of the in-degrees of each node.  The returned graph
// represents compile order rather than dependency order.  That is, for each map
// map key n, the map elements are libraries that depend on n being compiled
// first.
func parseTxRecsAsGraph(txs []*TxRecord) (g txGraph, in inDegree, err error) {
	// Scan and interpret input, build graph.
	g = txGraph{}
	in = inDegree{}
	for _, tx := range txs {
		txHash := tx.Hash
		g[txHash] = g[txHash]
		for _, dep := range tx.MsgTx.TxIn {
			// Skip transactions that are not in the local list.
			if !txRecHashExistsInSlice(txs, dep.PreviousOutPoint.Hash) {
				continue
			}

			in[dep.PreviousOutPoint.Hash] = in[dep.PreviousOutPoint.Hash]
			if dep.PreviousOutPoint.Hash.IsEqual(&txHash) {
				return nil, nil, fmt.Errorf("internal dependency detected")
			}
			successors := g[dep.PreviousOutPoint.Hash]
			for i := 0; ; i++ {
				if i == len(successors) {
					g[dep.PreviousOutPoint.Hash] = append(successors, txHash)
					in[txHash]++
					break
				}
				if dep.PreviousOutPoint.Hash == successors[i] {
					break // ignore duplicate dependencies
				}
			}
		}
	}
	return g, in, nil
}

// General purpose topological sort, not specific to the application of
// library dependencies.  Adapted from Wikipedia pseudo code, one main
// difference here is that this function does not consume the input graph.
// WP refers to incoming edges, but does not really need them fully represented.
// A count of incoming edges, or the in-degree of each node is enough.  Also,
// WP stops at cycle detection and doesn't output information about the cycle.
// A little extra code at the end of this function recovers the cyclic nodes.
// Implementation courtesy of http://rosettacode.org/wiki/Topological_sort#Go
func topSortKahn(g txGraph, in inDegree) (order, cyclic []chainhash.Hash,
	err error) {
	var L, S []chainhash.Hash
	// rem for "remaining edges," this function makes a local copy of the
	// in-degrees and consumes that instead of consuming an input.
	rem := inDegree{}
	for n, d := range in {
		if d == 0 {
			// accumulate "set of all nodes with no incoming edges"
			S = append(S, n)
		} else {
			// initialize rem from in-degree
			rem[n] = d
		}
	}
	for len(S) > 0 {
		last := len(S) - 1 // "remove a node n from S"
		n := S[last]
		S = S[:last]
		L = append(L, n) // "add n to tail of L"
		for _, m := range g[n] {
			// WP pseudo code reads "for each node m..." but it means for each
			// node m *remaining in the graph.*  We consume rem rather than
			// the graph, so "remaining in the graph" for us means rem[m] > 0.
			if rem[m] > 0 {
				rem[m]--         // "remove edge from the graph"
				if rem[m] == 0 { // if "m has no other incoming edges"
					S = append(S, m) // "insert m into S"
				}
			}
		}
	}
	// "If graph has edges," for us means a value in rem is > 0.
	for c, in := range rem {
		if in > 0 {
			// recover cyclic nodes
			for _, nb := range g[c] {
				if rem[nb] > 0 {
					cyclic = append(cyclic, c)
					break
				}
			}
		}
	}
	if len(cyclic) > 0 {
		return nil, cyclic, fmt.Errorf("cyclic dependencies detected")
	}
	return L, nil, nil
}
