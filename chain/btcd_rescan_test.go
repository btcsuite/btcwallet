package chain

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// rescanTestClient returns an RPCClient with a buffered notification queue.
func rescanTestClient() *RPCClient {
	return &RPCClient{
		chainParams:         &chaincfg.RegressionNetParams,
		enqueueNotification: make(chan interface{}, 16),
		quit:                make(chan struct{}),
	}
}

// drainNotifications returns the queued notifications.
func drainNotifications(c *RPCClient) []interface{} {
	var out []interface{}
	for {
		select {
		case n := <-c.enqueueNotification:
			out = append(out, n)
		default:
			return out
		}
	}
}

// txHex serializes the transaction as hex.
func txHex(t *testing.T, tx *wire.MsgTx) string {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))

	return hex.EncodeToString(buf.Bytes())
}

// sameOutPoints returns a matcher for a set of outpoint references.
func sameOutPoints(want ...wire.OutPoint) interface{} {
	return mock.MatchedBy(func(got []*wire.OutPoint) bool {
		if len(got) != len(want) {
			return false
		}

		set := make(map[wire.OutPoint]struct{}, len(want))
		for _, op := range want {
			set[op] = struct{}{}
		}

		for _, op := range got {
			if _, ok := set[*op]; !ok {
				return false
			}
		}

		return true
	})
}

// TestRPCClientRescan checks that the client-side rescan includes the start
// block, notifies matching transactions in block order followed by progress
// and finished notifications, and watches the addresses and the unspent
// outpoints, including outputs found by the rescan, once at the best block.
func TestRPCClientRescan(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	addr, err := address.NewAddressWitnessPubKeyHash(
		bytes.Repeat([]byte{1}, 20), params,
	)
	require.NoError(t, err)
	other, err := address.NewAddressWitnessPubKeyHash(
		bytes.Repeat([]byte{2}, 20), params,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	otherScript, err := txscript.PayToAddrScript(other)
	require.NoError(t, err)

	// The watched outpoint is not spent by the rescanned blocks.
	watched := wire.OutPoint{Hash: chainhash.Hash{9}, Index: 3}

	// tx1 pays twice to the address, tx2 spends the first output.
	tx1 := wire.NewMsgTx(2)
	tx1.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{7}}, nil,
		nil))
	tx1.AddTxOut(wire.NewTxOut(1000, pkScript))
	tx1.AddTxOut(wire.NewTxOut(2000, pkScript))
	spent := wire.OutPoint{Hash: tx1.TxHash(), Index: 0}
	unspent := wire.OutPoint{Hash: tx1.TxHash(), Index: 1}

	tx2 := wire.NewMsgTx(2)
	tx2.AddTxIn(wire.NewTxIn(&spent, nil, nil))
	tx2.AddTxOut(wire.NewTxOut(900, otherScript))

	startHash := chainhash.Hash{1}
	header1 := wire.BlockHeader{
		PrevBlock: startHash,
		Timestamp: time.Unix(1_000_100, 0),
	}
	hash1 := header1.BlockHash()
	header2 := wire.BlockHeader{
		PrevBlock: hash1,
		Timestamp: time.Unix(1_000_200, 0),
	}
	hash2 := header2.BlockHash()

	addrs := []address.Address{addr}
	conn := &mockRescanClient{}
	conn.On("GetBlockHeaderVerbose", startHash).Return(
		&btcjson.GetBlockHeaderVerboseResult{Height: 100,
			Time: 1_000_000}, nil,
	)
	conn.On("GetBlockHash", int64(100)).Return(&startHash, nil)
	conn.On("LoadTxFilter", true, addrs, []wire.OutPoint{watched}).
		Return(nil)
	conn.On("RescanBlocks", []chainhash.Hash{startHash}).Return(
		[]btcjson.RescannedBlock{}, nil,
	)
	conn.On("GetHeaders", []chainhash.Hash{startHash},
		(*chainhash.Hash)(nil)).Return(
		[]wire.BlockHeader{header1, header2}, nil,
	)
	conn.On("RescanBlocks", []chainhash.Hash{hash1, hash2}).Return(
		[]btcjson.RescannedBlock{
			{Hash: hash1.String(), Transactions: []string{
				txHex(t, tx1)}},
			{Hash: hash2.String(), Transactions: []string{
				txHex(t, tx2)}},
		}, nil,
	)
	conn.On("GetHeaders", []chainhash.Hash{hash2},
		(*chainhash.Hash)(nil)).Return([]wire.BlockHeader{}, nil)
	conn.On("NotifyReceived", addrs).Return(nil)
	conn.On("NotifySpent", sameOutPoints(watched, unspent)).Return(nil)
	conn.On("GetBestBlock").Return(&hash2, int32(102), nil)

	c := rescanTestClient()
	err = c.rescan(conn, &startHash, addrs,
		map[wire.OutPoint]address.Address{watched: addr})
	require.NoError(t, err)
	conn.AssertExpectations(t)

	ntfns := drainNotifications(c)
	require.Len(t, ntfns, 4)

	relevant1, ok := ntfns[0].(RelevantTx)
	require.True(t, ok)
	require.Equal(t, tx1.TxHash(), relevant1.TxRecord.Hash)
	require.Equal(t, wtxmgr.Block{Hash: hash1, Height: 101},
		relevant1.Block.Block)
	require.Equal(t, header1.Timestamp, relevant1.Block.Time)

	relevant2, ok := ntfns[1].(RelevantTx)
	require.True(t, ok)
	require.Equal(t, tx2.TxHash(), relevant2.TxRecord.Hash)
	require.Equal(t, wtxmgr.Block{Hash: hash2, Height: 102},
		relevant2.Block.Block)

	require.Equal(t, &RescanProgress{Hash: hash2, Height: 102,
		Time: header2.Timestamp}, ntfns[2])
	require.Equal(t, &RescanFinished{Hash: &hash2, Height: 102,
		Time: header2.Timestamp}, ntfns[3])
}

// TestRPCClientRescanNewBlocks checks that blocks connected while the watches
// are registered at the best block are rescanned before the rescan finishes.
func TestRPCClientRescanNewBlocks(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	addr, err := address.NewAddressWitnessPubKeyHash(
		bytes.Repeat([]byte{1}, 20), params,
	)
	require.NoError(t, err)

	startHash := chainhash.Hash{1}
	header1 := wire.BlockHeader{
		PrevBlock: startHash,
		Timestamp: time.Unix(1_000_100, 0),
	}
	hash1 := header1.BlockHash()

	addrs := []address.Address{addr}
	conn := &mockRescanClient{}
	conn.On("GetBlockHeaderVerbose", startHash).Return(
		&btcjson.GetBlockHeaderVerboseResult{Height: 100,
			Time: 1_000_000}, nil,
	)
	conn.On("GetBlockHash", int64(100)).Return(&startHash, nil)
	conn.On("LoadTxFilter", true, addrs, []wire.OutPoint{}).Return(nil)
	conn.On("RescanBlocks", mock.Anything).Return(
		[]btcjson.RescannedBlock{}, nil,
	)
	conn.On("NotifyReceived", addrs).Return(nil)

	// At the start block a block has been connected meanwhile.
	conn.On("GetHeaders", []chainhash.Hash{startHash},
		(*chainhash.Hash)(nil)).Return([]wire.BlockHeader{}, nil).Once()
	conn.On("GetBestBlock").Return(&hash1, int32(101), nil).Once()
	conn.On("GetHeaders", []chainhash.Hash{startHash},
		(*chainhash.Hash)(nil)).Return(
		[]wire.BlockHeader{header1}, nil,
	).Once()
	conn.On("GetHeaders", []chainhash.Hash{hash1},
		(*chainhash.Hash)(nil)).Return([]wire.BlockHeader{}, nil)
	conn.On("GetBestBlock").Return(&hash1, int32(101), nil).Once()

	c := rescanTestClient()
	err = c.rescan(conn, &startHash, addrs, nil)
	require.NoError(t, err)
	conn.AssertExpectations(t)
	conn.AssertNumberOfCalls(t, "NotifyReceived", 2)
	conn.AssertNotCalled(t, "NotifySpent", mock.Anything)

	ntfns := drainNotifications(c)
	require.Len(t, ntfns, 2)
	require.Equal(t, &RescanFinished{Hash: &hash1, Height: 101,
		Time: header1.Timestamp}, ntfns[1])
}

// TestRPCClientRescanReorg checks that the rescan fails when a rescanned block
// is no longer in the main chain.
func TestRPCClientRescanReorg(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams
	addr, err := address.NewAddressWitnessPubKeyHash(
		bytes.Repeat([]byte{1}, 20), params,
	)
	require.NoError(t, err)

	startHash := chainhash.Hash{1}
	stale := wire.BlockHeader{
		PrevBlock: chainhash.Hash{2},
		Timestamp: time.Unix(1_000_100, 0),
	}

	addrs := []address.Address{addr}
	conn := &mockRescanClient{}
	conn.On("GetBlockHeaderVerbose", startHash).Return(
		&btcjson.GetBlockHeaderVerboseResult{Height: 100}, nil,
	)
	conn.On("GetBlockHash", int64(100)).Return(&startHash, nil)
	conn.On("LoadTxFilter", true, addrs, []wire.OutPoint{}).Return(nil)
	conn.On("RescanBlocks", []chainhash.Hash{startHash}).Return(
		[]btcjson.RescannedBlock{}, nil,
	)
	conn.On("GetHeaders", []chainhash.Hash{startHash},
		(*chainhash.Hash)(nil)).Return([]wire.BlockHeader{stale}, nil)

	c := rescanTestClient()
	err = c.rescan(conn, &startHash, addrs, nil)
	require.ErrorIs(t, err, ErrRescanReorg)
	require.Empty(t, drainNotifications(c))
}

// TestRPCClientRescanNothing checks that a rescan without addresses or
// outpoints scans nothing and finishes at the best block.
func TestRPCClientRescanNothing(t *testing.T) {
	t.Parallel()

	startHash := chainhash.Hash{1}
	bestHash := chainhash.Hash{3}

	conn := &mockRescanClient{}
	conn.On("GetBlockHeaderVerbose", startHash).Return(
		&btcjson.GetBlockHeaderVerboseResult{Height: 100}, nil,
	)
	conn.On("GetBlockHash", int64(100)).Return(&startHash, nil)
	conn.On("GetBestBlock").Return(&bestHash, int32(200), nil)
	conn.On("GetBlockHeaderVerbose", bestHash).Return(
		&btcjson.GetBlockHeaderVerboseResult{Height: 200,
			Time: 2_000_000}, nil,
	)

	c := rescanTestClient()
	err := c.rescan(conn, &startHash, nil, nil)
	require.NoError(t, err)
	conn.AssertExpectations(t)
	conn.AssertNotCalled(t, "LoadTxFilter", mock.Anything, mock.Anything,
		mock.Anything)

	require.Equal(t, []interface{}{&RescanFinished{Hash: &bestHash,
		Height: 200, Time: time.Unix(2_000_000, 0)}},
		drainNotifications(c))
}

// TestRPCClientRescanStartNotMain checks that the rescan fails for a start
// block that is not in the main chain.
func TestRPCClientRescanStartNotMain(t *testing.T) {
	t.Parallel()

	startHash := chainhash.Hash{1}
	mainHash := chainhash.Hash{2}

	conn := &mockRescanClient{}
	conn.On("GetBlockHeaderVerbose", startHash).Return(
		&btcjson.GetBlockHeaderVerboseResult{Height: 100}, nil,
	)
	conn.On("GetBlockHash", int64(100)).Return(&mainHash, nil)

	c := rescanTestClient()
	err := c.rescan(conn, &startHash, nil, nil)
	require.ErrorContains(t, err, "not in the main chain")
	require.Empty(t, drainNotifications(c))
}
