package chain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// ErrRescanReorg is returned when a block that was already rescanned is
// removed from the main chain by a reorganization.
var ErrRescanReorg = errors.New("rescanned block reorganized out of the " +
	"main chain")

// rescanClient is the subset of the btcd RPC client used by the client-side
// rescan.
type rescanClient interface {
	GetBestBlock() (*chainhash.Hash, int32, error)
	GetBlockHash(blockHeight int64) (*chainhash.Hash, error)
	GetBlockHeaderVerbose(
		blockHash *chainhash.Hash) (*btcjson.GetBlockHeaderVerboseResult,
		error)
	GetHeaders(blockLocators []chainhash.Hash,
		hashStop *chainhash.Hash) ([]wire.BlockHeader, error)
	LoadTxFilter(reload bool, addresses []address.Address,
		outPoints []wire.OutPoint) error
	RescanBlocks(
		blockHashes []chainhash.Hash) ([]btcjson.RescannedBlock, error)
	NotifyReceived(addresses []address.Address) error
	NotifySpent(outpoints []*wire.OutPoint) error
}

// A compile-time check to ensure that rpcclient.Client satisfies the
// rescanClient interface.
var _ rescanClient = (*rpcclient.Client)(nil)

// rescanFilter tracks the watched addresses and the unspent watched outpoints
// of a rescan, so that outputs found by the rescan can be watched for spends.
type rescanFilter struct {
	params  *chaincfg.Params
	addrs   map[string]struct{}
	unspent map[wire.OutPoint]struct{}
}

// newRescanFilter creates a rescanFilter for the passed addresses and
// outpoints.
func newRescanFilter(params *chaincfg.Params, addrs []address.Address,
	outPoints map[wire.OutPoint]address.Address) *rescanFilter {

	filter := &rescanFilter{
		params:  params,
		addrs:   make(map[string]struct{}, len(addrs)),
		unspent: make(map[wire.OutPoint]struct{}, len(outPoints)),
	}

	for _, addr := range addrs {
		filter.addrs[addr.EncodeAddress()] = struct{}{}
	}

	for op := range outPoints {
		filter.unspent[op] = struct{}{}
	}

	return filter
}

// update removes the outpoints spent by the transaction from the unspent set
// and adds its outputs that pay to a watched address.
func (f *rescanFilter) update(tx *wire.MsgTx) {
	for _, in := range tx.TxIn {
		delete(f.unspent, in.PreviousOutPoint)
	}

	hash := tx.TxHash()
	for i, out := range tx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			out.PkScript, f.params,
		)
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if _, ok := f.addrs[addr.EncodeAddress()]; ok {
				op := wire.OutPoint{Hash: hash, Index: uint32(i)}
				f.unspent[op] = struct{}{}

				break
			}
		}
	}
}

// outPoints returns the unspent watched outpoints.
func (f *rescanFilter) outPoints() []wire.OutPoint {
	ops := make([]wire.OutPoint, 0, len(f.unspent))
	for op := range f.unspent {
		ops = append(ops, op)
	}

	return ops
}

// outPointRefs returns references to the unspent watched outpoints.
func (f *rescanFilter) outPointRefs() []*wire.OutPoint {
	ops := f.outPoints()

	refs := make([]*wire.OutPoint, len(ops))
	for i := range ops {
		refs[i] = &ops[i]
	}

	return refs
}

// rescan performs the rescan of the deprecated btcd rescan command on the
// client, using loadtxfilter, getheaders and rescanblocks. As with the rescan
// command, the start block is included, matching transactions are notified as
// relevant transactions, and once the scan reaches the best block the
// addresses and unspent outpoints are registered with notifyreceived and
// notifyspent for subsequent notifications.
func (c *RPCClient) rescan(conn rescanClient, startHash *chainhash.Hash,
	addrs []address.Address,
	outPoints map[wire.OutPoint]address.Address) error {

	last, err := rescanStart(conn, startHash)
	if err != nil {
		return err
	}

	// Without addresses or outpoints nothing is scanned, and the best
	// block is reported as the end of the rescan.
	if len(addrs) == 0 && len(outPoints) == 0 {
		return c.rescanNothing(conn)
	}

	filter := newRescanFilter(c.chainParams, addrs, outPoints)

	err = c.rescanLoad(conn, filter, addrs, last)
	if err != nil {
		return err
	}

	for {
		select {
		case <-c.quit:
			return rpcclient.ErrClientShutdown
		default:
		}

		var done bool

		last, done, err = c.rescanStep(conn, filter, addrs, last)
		if err != nil {
			return err
		}

		if done {
			c.onRescanFinished(&last.Hash, last.Height, last.Timestamp)

			return nil
		}
	}
}

// rescanStep rescans the blocks that follow the last rescanned block and
// returns the new last rescanned block. If there are no such blocks, the
// watches are registered and true is returned if the last block is still the
// best block.
func (c *RPCClient) rescanStep(conn rescanClient, filter *rescanFilter,
	addrs []address.Address,
	last waddrmgr.BlockStamp) (waddrmgr.BlockStamp, bool, error) {

	blocks, err := rescanNext(conn, last)
	if err != nil {
		return last, false, err
	}

	if len(blocks) == 0 {
		done, err := c.rescanTop(conn, filter, addrs, last)

		return last, done, err
	}

	err = c.rescanBlocks(conn, filter, blocks)
	if err != nil {
		return last, false, err
	}

	last = blocks[len(blocks)-1]
	c.onRescanProgress(&last.Hash, last.Height, last.Timestamp)

	return last, false, nil
}

// rescanStart returns the start block of a rescan, which must be in the main
// chain.
func rescanStart(conn rescanClient,
	startHash *chainhash.Hash) (waddrmgr.BlockStamp, error) {

	start, err := conn.GetBlockHeaderVerbose(startHash)
	if err != nil {
		return waddrmgr.BlockStamp{}, err
	}

	mainHash, err := conn.GetBlockHash(int64(start.Height))
	if err != nil {
		return waddrmgr.BlockStamp{}, err
	}

	if *mainHash != *startHash {
		return waddrmgr.BlockStamp{}, fmt.Errorf("rescan start block "+
			"%v is not in the main chain", startHash)
	}

	return waddrmgr.BlockStamp{
		Hash:      *startHash,
		Height:    start.Height,
		Timestamp: time.Unix(start.Time, 0),
	}, nil
}

// rescanLoad loads the transaction filter of a rescan and rescans the start
// block.
func (c *RPCClient) rescanLoad(conn rescanClient, filter *rescanFilter,
	addrs []address.Address, start waddrmgr.BlockStamp) error {

	err := conn.LoadTxFilter(true, addrs, filter.outPoints())
	if err != nil {
		return err
	}

	return c.rescanBlocks(conn, filter, []waddrmgr.BlockStamp{start})
}

// rescanNothing finishes a rescan without addresses or outpoints at the best
// block.
func (c *RPCClient) rescanNothing(conn rescanClient) error {
	hash, height, err := conn.GetBestBlock()
	if err != nil {
		return err
	}

	header, err := conn.GetBlockHeaderVerbose(hash)
	if err != nil {
		return err
	}

	c.onRescanFinished(hash, height, time.Unix(header.Time, 0))

	return nil
}

// rescanNext returns the blocks that follow the last rescanned block, which
// must link to it. No blocks are returned if the last block is the best block.
func rescanNext(conn rescanClient,
	last waddrmgr.BlockStamp) ([]waddrmgr.BlockStamp, error) {

	headers, err := conn.GetHeaders([]chainhash.Hash{last.Hash}, nil)
	if err != nil {
		return nil, err
	}

	blocks := make([]waddrmgr.BlockStamp, len(headers))

	previous := last.Hash
	for i := range headers {
		if headers[i].PrevBlock != previous {
			return nil, fmt.Errorf("%w: %v", ErrRescanReorg, previous)
		}

		previous = headers[i].BlockHash()
		blocks[i] = waddrmgr.BlockStamp{
			Hash:      previous,
			Height:    last.Height + int32(i) + 1,
			Timestamp: headers[i].Timestamp,
		}
	}

	return blocks, nil
}

// rescanTop registers the addresses and unspent outpoints for subsequent
// notifications once the rescan has reached the last block, and returns true
// if that block is still the best block. Otherwise blocks were connected in the
// meantime, which the rescan continues with.
func (c *RPCClient) rescanTop(conn rescanClient, filter *rescanFilter,
	addrs []address.Address, last waddrmgr.BlockStamp) (bool, error) {

	if len(addrs) != 0 {
		err := conn.NotifyReceived(addrs)
		if err != nil {
			return false, err
		}
	}

	if len(filter.unspent) != 0 {
		err := conn.NotifySpent(filter.outPointRefs())
		if err != nil {
			return false, err
		}
	}

	best, _, err := conn.GetBestBlock()
	if err != nil {
		return false, err
	}

	if *best == last.Hash {
		return true, nil
	}

	hash, err := conn.GetBlockHash(int64(last.Height))
	if err != nil {
		return false, err
	}

	if *hash != last.Hash {
		return false, fmt.Errorf("%w: %v", ErrRescanReorg, last.Hash)
	}

	return false, nil
}

// rescanBlocks matches the blocks against the loaded transaction filter and
// notifies the matching transactions as relevant transactions.
func (c *RPCClient) rescanBlocks(conn rescanClient, filter *rescanFilter,
	blocks []waddrmgr.BlockStamp) error {

	hashes := make([]chainhash.Hash, len(blocks))

	index := make(map[chainhash.Hash]*waddrmgr.BlockStamp, len(blocks))
	for i := range blocks {
		hashes[i] = blocks[i].Hash
		index[blocks[i].Hash] = &blocks[i]
	}

	rescanned, err := conn.RescanBlocks(hashes)
	if err != nil {
		return err
	}

	for _, rescannedBlock := range rescanned {
		hash, err := chainhash.NewHashFromStr(rescannedBlock.Hash)
		if err != nil {
			return err
		}

		block, ok := index[*hash]
		if !ok {
			return fmt.Errorf("rescanblocks returned unrequested "+
				"block %v", hash)
		}

		details := &btcjson.BlockDetails{
			Height: block.Height,
			Hash:   block.Hash.String(),
			Time:   block.Timestamp.Unix(),
		}

		for _, txHex := range rescannedBlock.Transactions {
			serialized, err := hex.DecodeString(txHex)
			if err != nil {
				return err
			}

			tx := &wire.MsgTx{}

			err = tx.Deserialize(bytes.NewReader(serialized))
			if err != nil {
				return err
			}

			filter.update(tx)
			c.onRecvTx(btcutil.NewTx(tx), details)
		}
	}

	return nil
}
