package chain

import (
	"fmt"
	"io"
	"math"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// conn mocks a network connection by implementing the net.Conn interface. It is
// used to test peer connection without actually opening a network connection.
type conn struct {
	io.Reader
	io.Writer
	io.Closer
	localAddr  string
	remoteAddr string
}

func (c conn) LocalAddr() net.Addr {
	return &addr{"tcp", c.localAddr}
}
func (c conn) RemoteAddr() net.Addr {
	return &addr{"tcp", c.remoteAddr}
}
func (c conn) SetDeadline(t time.Time) error      { return nil }
func (c conn) SetReadDeadline(t time.Time) error  { return nil }
func (c conn) SetWriteDeadline(t time.Time) error { return nil }

// addr mocks a network address.
type addr struct {
	net, address string
}

func (m addr) Network() string { return m.net }
func (m addr) String() string  { return m.address }

// pipe turns two mock connections into a full-duplex connection similar to
// net.Pipe to allow pipe's with (fake) addresses.
func pipe(c1, c2 *conn) (*conn, *conn) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	c1.Writer = w1
	c1.Closer = w1
	c2.Reader = r1
	c1.Reader = r2
	c2.Writer = w2
	c2.Closer = w2

	return c1, c2
}

// calcMerkleRoot creates a merkle tree from the slice of transactions and
// returns the root of the tree.
//
// This function was copied from:
//     https://github.com/btcsuite/btcd/blob/36a96f6a0025b6aeaebe4106821c2d46ee4be8d4/blockchain/fullblocktests/generate.go#L303
func calcMerkleRoot(txns []*wire.MsgTx) chainhash.Hash {
	if len(txns) == 0 {
		return chainhash.Hash{}
	}

	utilTxns := make([]*btcutil.Tx, 0, len(txns))
	for _, tx := range txns {
		utilTxns = append(utilTxns, btcutil.NewTx(tx))
	}
	merkles := blockchain.BuildMerkleTreeStore(utilTxns, false)
	return *merkles[len(merkles)-1]
}

// solveBlock attempts to find a nonce which makes the passed block header hash
// to a value less than the target difficulty.  When a successful solution is
// found true is returned and the nonce field of the passed header is updated
// with the solution.  False is returned if no solution exists.
//
// This function was copied from:
//     https://github.com/btcsuite/btcd/blob/36a96f6a0025b6aeaebe4106821c2d46ee4be8d4/blockchain/fullblocktests/generate.go#L324
func solveBlock(header *wire.BlockHeader) bool {
	// sbResult is used by the solver goroutines to send results.
	type sbResult struct {
		found bool
		nonce uint32
	}

	// Make sure all spawned goroutines finish executing before returning.
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
	}()

	// solver accepts a block header and a nonce range to test. It is
	// intended to be run as a goroutine.
	targetDifficulty := blockchain.CompactToBig(header.Bits)
	quit := make(chan bool)
	results := make(chan sbResult)
	solver := func(hdr wire.BlockHeader, startNonce, stopNonce uint32) {
		defer wg.Done()

		// We need to modify the nonce field of the header, so make sure
		// we work with a copy of the original header.
		for i := startNonce; i >= startNonce && i <= stopNonce; i++ {
			select {
			case <-quit:
				return
			default:
				hdr.Nonce = i
				hash := hdr.BlockHash()
				if blockchain.HashToBig(&hash).Cmp(
					targetDifficulty) <= 0 {

					select {
					case results <- sbResult{true, i}:
					case <-quit:
					}

					return
				}
			}
		}

		select {
		case results <- sbResult{false, 0}:
		case <-quit:
		}
	}

	startNonce := uint32(1)
	stopNonce := uint32(math.MaxUint32)
	numCores := uint32(runtime.NumCPU())
	noncesPerCore := (stopNonce - startNonce) / numCores
	wg.Add(int(numCores))
	for i := uint32(0); i < numCores; i++ {
		rangeStart := startNonce + (noncesPerCore * i)
		rangeStop := startNonce + (noncesPerCore * (i + 1)) - 1
		if i == numCores-1 {
			rangeStop = stopNonce
		}
		go solver(*header, rangeStart, rangeStop)
	}
	for i := uint32(0); i < numCores; i++ {
		result := <-results
		if result.found {
			close(quit)
			header.Nonce = result.nonce
			return true
		}
	}

	return false
}

// genBlockChain generates a test chain with the given number of blocks.
func genBlockChain(numBlocks uint32) ([]*chainhash.Hash, map[chainhash.Hash]*wire.MsgBlock) {
	prevHash := chainParams.GenesisHash
	prevHeader := &chainParams.GenesisBlock.Header

	hashes := make([]*chainhash.Hash, numBlocks)
	blocks := make(map[chainhash.Hash]*wire.MsgBlock, numBlocks)

	// Each block contains three transactions, including the coinbase
	// transaction. Each non-coinbase transaction spends outputs from
	// the previous block. We also need to produce blocks that succeed
	// validation through blockchain.CheckBlockSanity.
	script := []byte{0x01, 0x01}
	createTx := func(prevOut wire.OutPoint) *wire.MsgTx {
		return &wire.MsgTx{
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: prevOut,
				SignatureScript:  script,
			}},
			TxOut: []*wire.TxOut{{PkScript: script}},
		}
	}
	for i := uint32(0); i < numBlocks; i++ {
		txs := []*wire.MsgTx{
			createTx(wire.OutPoint{Index: wire.MaxPrevOutIndex}),
			createTx(wire.OutPoint{Hash: *prevHash, Index: 0}),
			createTx(wire.OutPoint{Hash: *prevHash, Index: 1}),
		}
		header := &wire.BlockHeader{
			Version:    1,
			PrevBlock:  *prevHash,
			MerkleRoot: calcMerkleRoot(txs),
			Timestamp:  prevHeader.Timestamp.Add(10 * time.Minute),
			Bits:       chainParams.PowLimitBits,
			Nonce:      0,
		}
		if !solveBlock(header) {
			panic(fmt.Sprintf("could not solve block at idx %v", i))
		}
		block := &wire.MsgBlock{
			Header:       *header,
			Transactions: txs,
		}

		blockHash := block.BlockHash()
		hashes[i] = &blockHash
		blocks[blockHash] = block

		prevHash = &blockHash
		prevHeader = header
	}

	return hashes, blocks
}

// producesInvalidBlock produces a copy of the block that duplicates the last
// transaction. When the block has an odd number of transactions, this results
// in the invalid block maintaining the same hash as the valid block.
func produceInvalidBlock(block *wire.MsgBlock) *wire.MsgBlock {
	numTxs := len(block.Transactions)
	lastTx := block.Transactions[numTxs-1]
	blockCopy := &wire.MsgBlock{
		Header:       block.Header,
		Transactions: make([]*wire.MsgTx, numTxs),
	}
	copy(blockCopy.Transactions, block.Transactions)
	blockCopy.AddTransaction(lastTx)
	return blockCopy
}
