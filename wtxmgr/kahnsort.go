// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import "github.com/jadeblaquiere/ctcd/chaincfg/chainhash"

type graphNode struct {
	value    *TxRecord
	outEdges []*chainhash.Hash
	inDegree int
}

type hashGraph map[chainhash.Hash]graphNode

func makeGraph(set map[chainhash.Hash]*TxRecord) hashGraph {
	graph := make(hashGraph)

	for _, rec := range set {
		// Add a node for every transaction record.  The output edges
		// and input degree are set by iterating over each record's
		// inputs below.
		if _, ok := graph[rec.Hash]; !ok {
			graph[rec.Hash] = graphNode{value: rec}
		}

	inputLoop:
		for _, input := range rec.MsgTx.TxIn {
			// Transaction inputs that reference transactions not
			// included in the set do not create any (local) graph
			// edges.
			if _, ok := set[input.PreviousOutPoint.Hash]; !ok {
				continue
			}

			inputNode := graph[input.PreviousOutPoint.Hash]

			// Skip duplicate edges.
			for _, outEdge := range inputNode.outEdges {
				if *outEdge == input.PreviousOutPoint.Hash {
					continue inputLoop
				}
			}

			// Mark a directed edge from the previous transaction
			// hash to this transaction record and increase the
			// input degree for this record's node.
			inputRec := inputNode.value
			if inputRec == nil {
				inputRec = set[input.PreviousOutPoint.Hash]
			}
			graph[input.PreviousOutPoint.Hash] = graphNode{
				value:    inputRec,
				outEdges: append(inputNode.outEdges, &rec.Hash),
				inDegree: inputNode.inDegree,
			}
			node := graph[rec.Hash]
			graph[rec.Hash] = graphNode{
				value:    rec,
				outEdges: node.outEdges,
				inDegree: node.inDegree + 1,
			}
		}
	}

	return graph
}

// graphRoots returns the roots of the graph.  That is, it returns the node's
// values for all nodes which contain an input degree of 0.
func graphRoots(graph hashGraph) []*TxRecord {
	roots := make([]*TxRecord, 0, len(graph))
	for _, node := range graph {
		if node.inDegree == 0 {
			roots = append(roots, node.value)
		}
	}
	return roots
}

// dependencySort topologically sorts a set of transaction records by their
// dependency order.  It is implemented using Kahn's algorithm.
func dependencySort(txs map[chainhash.Hash]*TxRecord) []*TxRecord {
	graph := makeGraph(txs)
	s := graphRoots(graph)

	// If there are no edges (no transactions from the map reference each
	// other), then Kahn's algorithm is unnecessary.
	if len(s) == len(txs) {
		return s
	}

	sorted := make([]*TxRecord, 0, len(txs))
	for len(s) != 0 {
		rec := s[0]
		s = s[1:]
		sorted = append(sorted, rec)

		n := graph[rec.Hash]
		for _, mHash := range n.outEdges {
			m := graph[*mHash]
			if m.inDegree != 0 {
				m.inDegree--
				graph[*mHash] = m
				if m.inDegree == 0 {
					s = append(s, m.value)
				}
			}
		}
	}
	return sorted
}
