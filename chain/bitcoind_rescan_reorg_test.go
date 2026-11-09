package chain

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

type rescanCase struct {
	name                                        string
	oldDepth, newDepth, forkHeight, startHeight int
	failFinal                                   bool
}

// rescanRPC switches chains while returning the old tip's block. Live block
// notifications are queued before the rescan publishes that stale response.
type rescanRPC struct {
	mu                  sync.Mutex
	t                   *testing.T
	client              *BitcoindClient
	old, replacement    []*wire.MsgBlock
	blocks              map[string]*wire.MsgBlock
	heights             map[string]int32
	switched, failFinal bool
}

func rescanBlock(previous chainhash.Hash, nonce uint32) *wire.MsgBlock {
	return &wire.MsgBlock{Header: wire.BlockHeader{
		Version: 1, PrevBlock: previous, Nonce: nonce,
		Timestamp: time.Unix(1_700_000_000+int64(nonce), 0),
	}}
}

func (s *rescanRPC) serveHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var req struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	result, rpcErr := s.result(req.Method, req.Params)

	err := json.NewEncoder(w).Encode(map[string]any{
		"id": req.ID, "result": result, "error": rpcErr,
	})
	if err != nil {
		s.t.Errorf("encode RPC response: %v", err)
	}
}

func (s *rescanRPC) result(method string,
	params []json.RawMessage) (any, *btcjson.RPCError) {

	switch method {
	case "getnetworkinfo":
		return map[string]any{"version": 290000,
			"subversion": "/Satoshi:29.0.0/"}, nil
	case "getblockchaininfo":
		if s.switched && s.failFinal {
			return nil, &btcjson.RPCError{Code: btcjson.ErrRPCInternal.Code,
				Message: "best block unavailable"}
		}

		branch := s.old
		if s.switched {
			branch = s.replacement
		}

		return map[string]any{"chain": "test", "blocks": len(branch) - 1,
			"bestblockhash": branch[len(branch)-1].BlockHash().String()}, nil
	case "getblockhash":
		return s.blockHash(params)
	case "getblockheader", "getblock":
		var hash string

		_ = json.Unmarshal(params[0], &hash)

		return s.blockResult(method, hash)
	default:
		return nil, &btcjson.RPCError{Code: btcjson.ErrRPCMethodNotFound.Code,
			Message: method}
	}
}

func (s *rescanRPC) blockHash(params []json.RawMessage) (
	any, *btcjson.RPCError) {

	var height int

	_ = json.Unmarshal(params[0], &height)

	branch := s.old
	if s.switched {
		branch = s.replacement
	}

	if height < 0 || height >= len(branch) {
		return nil, &btcjson.RPCError{Code: btcjson.ErrRPCInvalidParameter,
			Message: "height out of range"}
	}

	return branch[height].BlockHash().String(), nil
}

func (s *rescanRPC) blockResult(method, hash string) (any, *btcjson.RPCError) {
	b, ok := s.blocks[hash]
	if !ok {
		return nil, &btcjson.RPCError{Code: btcjson.ErrRPCInvalidAddressOrKey,
			Message: "unknown block"}
	}

	if method == "getblockheader" {
		return btcjson.GetBlockHeaderVerboseResult{
			Hash: hash, Height: s.heights[hash],
			PreviousHash: b.Header.PrevBlock.String(),
			Time:         b.Header.Timestamp.Unix(),
		}, nil
	}

	if !s.switched && hash == s.old[len(s.old)-1].BlockHash().String() {
		s.replaceTip()
	}

	var raw bytes.Buffer

	err := b.Serialize(&raw)
	if err != nil {
		s.t.Errorf("serialize block: %v", err)
	}

	return hex.EncodeToString(raw.Bytes()), nil
}

func (s *rescanRPC) replaceTip() {
	s.switched = true
	for i := len(s.old) - 1; i > 0; i-- {
		if i < len(s.replacement) &&
			s.old[i].BlockHash() == s.replacement[i].BlockHash() {

			break
		}

		h := s.old[i].BlockHash()
		s.client.onBlockDisconnected(&h, int32(i), s.old[i].Header.Timestamp)
	}

	for i := 1; i < len(s.replacement); i++ {
		if i < len(s.old) &&
			s.old[i].BlockHash() == s.replacement[i].BlockHash() {

			continue
		}

		h := s.replacement[i].BlockHash()
		s.client.onFilteredBlockConnected(
			int32(i), &s.replacement[i].Header, nil,
		)
		s.client.onBlockConnected(
			&h, int32(i), s.replacement[i].Header.Timestamp,
		)
	}
}

// newRescanTestClient runs the real HTTP RPC client and notification queue.
func newRescanTestClient(t *testing.T, s *rescanRPC,
	watched chainhash.Hash) *BitcoindClient {

	t.Helper()

	for _, branch := range [][]*wire.MsgBlock{s.old, s.replacement} {
		for i, b := range branch {
			h := b.BlockHash().String()
			s.blocks[h], s.heights[h] = b, int32(i)
		}
	}

	server := httptest.NewServer(http.HandlerFunc(s.serveHTTP))
	t.Cleanup(server.Close)
	rpc, err := rpcclient.New(&rpcclient.ConnConfig{
		Host: strings.TrimPrefix(server.URL, "http://"),
		User: "test", Pass: "test", HTTPPostMode: true, DisableTLS: true,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { rpc.Shutdown(); rpc.WaitForShutdown() })

	conn := &BitcoindConn{
		client: rpc, cfg: BitcoindConfig{ChainParams: &chaincfg.TestNet3Params},
	}
	client := conn.NewBitcoindClient()
	client.notifyBlocks = 1
	client.watchedTxs[watched] = struct{}{}
	client.notificationQueue.Start()
	t.Cleanup(client.notificationQueue.Stop)
	s.mu.Lock()
	s.client = client
	s.mu.Unlock()

	return client
}

func rescanBranches(t *testing.T, tc rescanCase) (*rescanRPC, chainhash.Hash) {
	t.Helper()

	old := []*wire.MsgBlock{rescanBlock(chainhash.Hash{}, 0)}
	for i := 1; i <= tc.oldDepth; i++ {
		old = append(old, rescanBlock(old[i-1].BlockHash(), uint32(i)))
	}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{9}}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))

	last := old[tc.oldDepth]
	require.NoError(t, last.AddTransaction(tx))
	last.Header.MerkleRoot = tx.TxHash()

	replacement := append([]*wire.MsgBlock(nil), old[:tc.forkHeight+1]...)
	for i := tc.forkHeight + 1; i <= tc.newDepth; i++ {
		replacement = append(replacement, rescanBlock(
			replacement[i-1].BlockHash(), uint32(100+i)))
	}

	return &rescanRPC{t: t, old: old, replacement: replacement,
		blocks:    make(map[string]*wire.MsgBlock),
		heights:   make(map[string]int32),
		failFinal: tc.failFinal}, tx.TxHash()
}

// rescanMessages drains exactly the published notifications using a FIFO
// marker, including when a failed lookup must not publish completion.
func rescanMessages(t *testing.T, c *BitcoindClient) []any {
	t.Helper()

	type end struct{}
	c.notificationQueue.ChanIn() <- end{}

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()

	var messages []any
	for {
		select {
		case n := <-c.notificationQueue.ChanOut():
			if _, ok := n.(end); ok {
				return messages
			}

			messages = append(messages, n)
		case <-deadline.C:
			t.Fatal("rescan notification stream did not drain")
		}
	}
}

func assertRescanMessages(t *testing.T, tc rescanCase, s *rescanRPC,
	target chainhash.Hash, messages []any) {

	t.Helper()

	oldHash := s.old[len(s.old)-1].BlockHash()
	tip := s.replacement[len(s.replacement)-1]
	confirmedOld, seenOld := false, false

	var lastBlock *wtxmgr.BlockMeta

	finished := 0
	for _, msg := range messages {
		switch n := msg.(type) {
		case RelevantTx:
			if n.TxRecord.Hash == target {
				require.NotNil(t, n.Block)
				confirmedOld = n.Block.Hash == oldHash
				seenOld = true
			}
		case BlockDisconnected:
			require.Greater(t, n.Height, int32(tc.forkHeight),
				"canonical prefix must stay connected")

			if n.Hash == oldHash {
				confirmedOld = false
			}
		case FilteredBlockConnected:
			require.Equal(t, s.heights[n.Block.Hash.String()], n.Block.Height)
			lastBlock = n.Block
		case *RescanFinished:
			finished++

			require.Equal(t, tc.forkHeight == tc.oldDepth, confirmedOld,
				"late orphan transaction must not remain confirmed")
			require.NotNil(t, lastBlock)
			require.Equal(t, lastBlock.Hash, *n.Hash,
				"completion must identify the last block actually scanned")
			require.Equal(t, tip.BlockHash(), *n.Hash)
			require.EqualValues(t, tc.newDepth, n.Height)
			require.Equal(t, tip.Header.Timestamp, n.Time)
		}
	}

	require.True(t, seenOld, "must exercise late transaction publication")

	if tc.failFinal {
		require.Zero(t, finished)
	} else {
		require.Equal(t, 1, finished)
	}
}

// TestBitcoindRescanTipReorg proves completion cannot name a replacement tip
// while a transaction published from the orphan remains confirmed.
func TestBitcoindRescanTipReorg(t *testing.T) {
	t.Parallel()

	for _, tc := range []rescanCase{
		{name: "unchanged", oldDepth: 2, newDepth: 2, forkHeight: 2},
		{name: "tip extends", oldDepth: 2, newDepth: 3, forkHeight: 2},
		{name: "same height", oldDepth: 2, newDepth: 2, forkHeight: 1},
		{name: "longer replacement", oldDepth: 2, newDepth: 3, forkHeight: 1},
		{name: "shorter replacement", oldDepth: 3, newDepth: 1},
		{name: "fork before scan start", oldDepth: 3, newDepth: 3,
			startHeight: 2},
		{name: "final lookup unavailable", oldDepth: 2, newDepth: 2,
			forkHeight: 1,
			failFinal:  true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, target := rescanBranches(t, tc)
			c := newRescanTestClient(t, s, target)

			err := c.rescan(s.old[tc.startHeight].BlockHash())
			if tc.failFinal {
				require.ErrorContains(t, err, "best block unavailable")
			} else {
				require.NoError(t, err)
			}

			assertRescanMessages(t, tc, s, target, rescanMessages(t, c))
		})
	}
}
