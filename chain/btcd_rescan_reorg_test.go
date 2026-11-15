package chain

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// hookConn calls before ahead of each call to the wrapped rescan connection,
// with the method name and the number of calls of that method so far.
type hookConn struct {
	conn   rescanClient
	calls  map[string]int
	before func(method string, call int)
}

func (h *hookConn) hook(method string) {
	h.calls[method]++
	if h.before != nil {
		h.before(method, h.calls[method])
	}
}

func (h *hookConn) GetBestBlock() (*chainhash.Hash, int32, error) {
	h.hook("GetBestBlock")
	return h.conn.GetBestBlock()
}

func (h *hookConn) GetBlockHash(height int64) (*chainhash.Hash, error) {
	h.hook("GetBlockHash")
	return h.conn.GetBlockHash(height)
}

func (h *hookConn) GetBlockHeaderVerbose(
	hash *chainhash.Hash) (*btcjson.GetBlockHeaderVerboseResult, error) {

	h.hook("GetBlockHeaderVerbose")
	return h.conn.GetBlockHeaderVerbose(hash)
}

func (h *hookConn) GetHeaders(locators []chainhash.Hash,
	stop *chainhash.Hash) ([]wire.BlockHeader, error) {

	h.hook("GetHeaders")
	return h.conn.GetHeaders(locators, stop)
}

func (h *hookConn) LoadTxFilter(reload bool, addrs []address.Address,
	outPoints []wire.OutPoint) error {

	h.hook("LoadTxFilter")
	return h.conn.LoadTxFilter(reload, addrs, outPoints)
}

func (h *hookConn) RescanBlocks(
	hashes []chainhash.Hash) ([]btcjson.RescannedBlock, error) {

	h.hook("RescanBlocks")
	return h.conn.RescanBlocks(hashes)
}

func (h *hookConn) NotifyReceived(addrs []address.Address) error {
	h.hook("NotifyReceived")
	return h.conn.NotifyReceived(addrs)
}

func (h *hookConn) NotifySpent(outpoints []*wire.OutPoint) error {
	h.hook("NotifySpent")
	return h.conn.NotifySpent(outpoints)
}

// reorgEnv is a rescan server and the miner that produces its chain. For the
// btcd backend the miner is the rescan server. Otherwise the miner is a peer of
// the rescan server, which follows its chain over p2p.
type reorgEnv struct {
	miner *rpctest.Harness
	conn  *rpcclient.Client
	name  string
}

// sync waits until the rescan server has the best block of the miner.
func (e *reorgEnv) sync(t *testing.T) {
	t.Helper()

	want, _, err := e.miner.Client.GetBestBlock()
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		got, _, err := e.conn.GetBestBlock()
		return err == nil && *got == *want
	}, 5*time.Minute, 100*time.Millisecond)
}

// newReorgEnv starts a btcd miner and connects the rescan connection, to the
// miner or, if RESCAN_REORG_SERVER is set (host:port,p2phost:port,user,pass),
// to a btcd-compatible server. The miner then also listens for p2p connections
// on p2phost:port, which the server must be configured to connect to.
func newReorgEnv(t *testing.T) *reorgEnv {
	t.Helper()

	var parts []string

	args := []string{"--txindex"}
	if server := os.Getenv("RESCAN_REORG_SERVER"); server != "" {
		parts = strings.Split(server, ",")
		require.Len(t, parts, 4)

		args = append(args, "--listen="+parts[1])
	}

	params := &chaincfg.RegressionNetParams
	miner, err := rpctest.New(
		params, nil, args, os.Getenv("RESCAN_REORG_BTCD"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, miner.TearDown()) })
	require.NoError(t, miner.SetUp(true, 25))

	cfg := miner.RPCConfig()
	env := &reorgEnv{miner: miner, name: "btcd"}

	if parts != nil {
		cfg = rpcclient.ConnConfig{
			Host:       parts[0],
			Endpoint:   "ws",
			User:       parts[2],
			Pass:       parts[3],
			DisableTLS: true,
		}
		env.name = parts[0]
	}

	// A server may accept connections only once its chain is current.
	require.Eventually(t, func() bool {
		env.conn, err = rpcclient.New(&cfg, nil)
		return err == nil
	}, 5*time.Minute, time.Second)
	t.Cleanup(env.conn.Shutdown)

	env.sync(t)

	return env
}

// reorgLayout is the chain built by a scenario above its start block. Three
// payments to the watched address are mined at start+1, start+1800 (in the
// first getheaders batch) and start+2500 (in the second batch), and the best
// block is at start+2600.
type reorgLayout struct {
	addr     address.Address
	start    int32
	startHsh chainhash.Hash
	tip      int32
	txs      map[chainhash.Hash]string
}

func (e *reorgEnv) mine(t *testing.T, n uint32) {
	t.Helper()

	_, err := e.miner.Client.Generate(n)
	require.NoError(t, err)
}

func (e *reorgEnv) pay(t *testing.T, pkScript []byte) chainhash.Hash {
	t.Helper()

	txid, err := e.miner.SendOutputs(
		[]*wire.TxOut{wire.NewTxOut(10_000, pkScript)},
		btcutil.Amount(10_000),
	)
	require.NoError(t, err)
	e.mine(t, 1)

	return *txid
}

func (e *reorgEnv) layout(t *testing.T) *reorgLayout {
	t.Helper()

	var key [20]byte

	_, err := rand.Read(key[:])
	require.NoError(t, err)

	addr, err := address.NewAddressWitnessPubKeyHash(
		key[:], &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	hash, start, err := e.miner.Client.GetBestBlock()
	require.NoError(t, err)

	l := &reorgLayout{
		addr:     addr,
		start:    start,
		startHsh: *hash,
		txs:      make(map[chainhash.Hash]string),
	}

	l.txs[e.pay(t, pkScript)] = "A"
	e.mine(t, 1798)
	l.txs[e.pay(t, pkScript)] = "B"
	e.mine(t, 699)
	l.txs[e.pay(t, pkScript)] = "C"
	e.mine(t, 100)

	_, l.tip, err = e.miner.Client.GetBestBlock()
	require.NoError(t, err)
	require.Equal(t, start+2600, l.tip)

	e.sync(t)

	return l
}

// reorg replaces the main chain from the passed height with a fork that has
// more work than the replaced chain, so that p2p peers follow it. The payments
// of the layout in the replaced blocks return to the mempool and are mined in
// the fork.
func (e *reorgEnv) reorg(t *testing.T, l *reorgLayout, height int32) {
	t.Helper()

	hash, err := e.miner.Client.GetBlockHash(int64(height))
	require.NoError(t, err)

	_, tip, err := e.miner.Client.GetBestBlock()
	require.NoError(t, err)

	var moved []chainhash.Hash
	for txid := range l.txs {
		tx, err := e.miner.Client.GetRawTransactionVerbose(&txid)
		require.NoError(t, err)

		block, err := chainhash.NewHashFromStr(tx.BlockHash)
		require.NoError(t, err)

		header, err := e.miner.Client.GetBlockHeaderVerbose(block)
		require.NoError(t, err)

		if header.Height >= height {
			moved = append(moved, txid)
		}
	}

	require.NoError(t, e.miner.Client.InvalidateBlock(hash))

	// Disconnected transactions return to the mempool asynchronously.
	require.Eventually(t, func() bool {
		pool, err := e.miner.Client.GetRawMempool()
		if err != nil {
			return false
		}

		pooled := make(map[chainhash.Hash]struct{}, len(pool))
		for _, txid := range pool {
			pooled[*txid] = struct{}{}
		}

		for _, txid := range moved {
			if _, ok := pooled[txid]; !ok {
				return false
			}
		}

		return true
	}, time.Minute, 10*time.Millisecond)

	e.mine(t, uint32(tip-height+2))
	e.sync(t)
}

// reorgResult is the outcome of a rescan.
type reorgResult struct {
	err      error
	txs      []RelevantTx
	finished *RescanFinished
}

func (r *reorgResult) String() string {
	var b strings.Builder
	for _, tx := range r.txs {
		fmt.Fprintf(&b, " %v@%d", tx.TxRecord.Hash.String()[:8],
			tx.Block.Height)
	}

	if r.finished != nil {
		fmt.Fprintf(&b, " finished@%d", r.finished.Height)
	}

	return fmt.Sprintf("err=%v txs:%s", r.err, b.String())
}

// onMain returns whether the block is in the main chain of the server.
func (e *reorgEnv) onMain(t *testing.T, block chainhash.Hash,
	height int32) bool {

	t.Helper()

	hash, err := e.conn.GetBlockHash(int64(height))
	require.NoError(t, err)

	return *hash == block
}

// reorgCheck checks the result of a rescan.
type reorgCheck func(t *testing.T, e *reorgEnv, l *reorgLayout,
	r *reorgResult)

// reorgCase changes the chain before a call of the rescan, identified by the
// method name and the number of calls of that method.
type reorgCase struct {
	name   string
	method string
	call   int
	action func(t *testing.T, e *reorgEnv, l *reorgLayout)
	check  reorgCheck
}

// checkMainTxs checks that the rescan finished at the best block and notified
// each payment of the layout that is mined in the main chain once, in its
// block. A payment of a replaced block may not be mined in the fork, if it
// spends an output of a replaced block.
func checkMainTxs(t *testing.T, e *reorgEnv, l *reorgLayout, r *reorgResult) {
	t.Helper()

	require.NoError(t, r.err)
	require.NotNil(t, r.finished)

	best, height, err := e.conn.GetBestBlock()
	require.NoError(t, err)
	require.Equal(t, *best, *r.finished.Hash)
	require.Equal(t, height, r.finished.Height)

	want := make(map[string]chainhash.Hash)
	for txid, name := range l.txs {
		tx, err := e.miner.Client.GetRawTransactionVerbose(&txid)
		if err != nil || tx.BlockHash == "" {
			continue
		}

		block, err := chainhash.NewHashFromStr(tx.BlockHash)
		require.NoError(t, err)

		want[name] = *block
	}

	got := make(map[string]chainhash.Hash)
	for _, tx := range r.txs {
		name := l.txs[tx.TxRecord.Hash]
		require.NotContains(t, got, name, "payment %v notified twice",
			name)

		got[name] = tx.Block.Hash
	}

	require.Contains(t, want, "A")
	require.Equal(t, want, got)
	checkInBlocks(t, e, r)
}

// checkInBlocks checks that each notified transaction is in the block it was
// notified in, which may have been replaced since.
func checkInBlocks(t *testing.T, e *reorgEnv, r *reorgResult) {
	t.Helper()

	for _, tx := range r.txs {
		block, err := e.miner.Client.GetBlock(&tx.Block.Hash)
		require.NoError(t, err)

		var found bool
		for _, blockTx := range block.Transactions {
			if blockTx.TxHash() == tx.TxRecord.Hash {
				found = true

				break
			}
		}

		require.True(t, found, "tx %v notified in block %v at height "+
			"%d that does not contain it", tx.TxRecord.Hash,
			tx.Block.Hash, tx.Block.Height)
	}
}

// checkFailed checks that the rescan failed, and that the transactions it
// notified before are in their blocks. The rescan detects a reorganization of
// rescanned blocks (ErrRescanReorg), and the server may refuse to rescan
// blocks that are no longer in the main chain.
func checkFailed(t *testing.T, e *reorgEnv, _ *reorgLayout, r *reorgResult) {
	t.Helper()

	require.Error(t, r.err)
	require.Nil(t, r.finished)
	checkInBlocks(t, e, r)
}

// reorgAt returns an action that reorganizes the chain from the height at the
// passed offset from the start block.
func reorgAt(offset int32) func(*testing.T, *reorgEnv, *reorgLayout) {
	return func(t *testing.T, e *reorgEnv, l *reorgLayout) {
		t.Helper()
		e.reorg(t, l, l.start+offset)
	}
}

var reorgCases = []reorgCase{{
	name:  "no reorg",
	check: checkMainTxs,
}, {
	name:   "start block reorged before first scan",
	method: "LoadTxFilter",
	call:   1,
	action: reorgAt(0),
	check:  checkFailed,
}, {
	name:   "scanned blocks reorged",
	method: "GetHeaders",
	call:   2,
	action: reorgAt(1000),
	check:  checkFailed,
}, {
	name:   "fetched batch reorged before scan",
	method: "RescanBlocks",
	call:   2,
	action: reorgAt(1500),
	check:  checkFailed,
}, {
	name:   "reorg ahead of scanned blocks",
	method: "GetHeaders",
	call:   2,
	action: reorgAt(2200),
	check:  checkMainTxs,
}, {
	name:   "blocks connected at top",
	method: "GetBestBlock",
	call:   1,
	action: func(t *testing.T, e *reorgEnv, _ *reorgLayout) {
		t.Helper()
		e.mine(t, 3)
		e.sync(t)
	},
	check: checkMainTxs,
}, {
	name:   "last block reorged at top",
	method: "GetBestBlock",
	call:   1,
	action: reorgAt(2600),
	check:  checkFailed,
}}

// run builds a layout above the best block, rescans it with the change of the
// case and checks the result.
func (e *reorgEnv) run(t *testing.T, tc reorgCase) {
	t.Helper()

	l := e.layout(t)

	conn := &hookConn{conn: e.conn, calls: make(map[string]int)}
	conn.before = func(method string, call int) {
		if method == tc.method && call == tc.call {
			tc.action(t, e, l)
		}
	}

	c := &RPCClient{
		chainParams:         &chaincfg.RegressionNetParams,
		enqueueNotification: make(chan interface{}, 4096),
		quit:                make(chan struct{}),
	}

	r := &reorgResult{}
	r.err = c.rescan(conn, &l.startHsh, []address.Address{l.addr}, nil)

	for _, n := range drainNotifications(c) {
		switch n := n.(type) {
		case RelevantTx:
			r.txs = append(r.txs, n)
		case *RescanFinished:
			r.finished = n
		}
	}

	var stale []string
	for _, tx := range r.txs {
		if !e.onMain(t, tx.Block.Hash, tx.Block.Height) {
			stale = append(stale, l.txs[tx.TxRecord.Hash])
		}
	}

	t.Logf("%s start=%d tip=%d calls=%v %v stale=%v", e.name, l.start,
		l.tip, conn.calls, r, stale)

	tc.check(t, e, l, r)
}

// TestRPCClientRescanReorgServer runs the client-side rescan against a real
// server and changes the chain before a chosen call of the rescan.
//
//nolint:paralleltest // The cases extend the chain of one miner.
func TestRPCClientRescanReorgServer(t *testing.T) {
	if testing.Short() {
		t.Skip("mines several thousand blocks per case")
	}

	env := newReorgEnv(t)

	for _, tc := range reorgCases {
		t.Run(tc.name, func(t *testing.T) {
			env.run(t, tc)
		})
	}
}
