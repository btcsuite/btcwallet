package chain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/stretchr/testify/require"
)

const (
	// rescanTestBlocks is the number of blocks each test rescans.
	rescanTestBlocks = 6

	// rescanTestTimeout bounds the wait for a rescan notification. It
	// allows for the backoff before one retry.
	rescanTestTimeout = 15 * time.Second
)

// failingGetBlockProxy forwards JSON-RPC requests to a bitcoind node and fails
// selected getblock calls with the error Core returns for an unreadable block.
type failingGetBlockProxy struct {
	// shouldFail decides from the 1-based getblock call number whether
	// that call fails.
	shouldFail func(call int64) bool

	// calls counts the getblock calls seen.
	calls atomic.Int64

	// failed counts the getblock calls failed.
	failed atomic.Int64

	backend *httputil.ReverseProxy
}

// ServeHTTP fails the selected getblock calls and forwards everything else.
func (p *failingGetBlockProxy) ServeHTTP(w http.ResponseWriter,
	r *http.Request) {

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Batches are arrays and do not decode here. They are forwarded.
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if json.Unmarshal(body, &req) == nil && req.Method == "getblock" &&
		p.shouldFail(p.calls.Add(1)) {

		p.failed.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"result":null,"error":{"code":-1,"message":`+
			`"Block not found on disk"},"id":%s}`, req.ID)

		return
	}

	p.backend.ServeHTTP(w, r)
}

// setupRescanClient mines rescanTestBlocks blocks and returns the hash to
// rescan from, the expected tip height, and a started client that reaches its
// bitcoind node through a proxy with the given failure rule.
func setupRescanClient(t *testing.T, shouldFail func(call int64) bool) (
	*BitcoindClient, *failingGetBlockProxy, chainhash.Hash, int32) {

	t.Helper()

	miner, _ := setupMiners(t)
	direct := setupBitcoind(t, miner.P2PAddress(), true)

	_, startHeight, err := miner.Client.GetBestBlock()
	require.NoError(t, err)

	_, err = miner.Client.Generate(rescanTestBlocks)
	require.NoError(t, err)

	tip := startHeight + rescanTestBlocks
	waitForBackendHeight(t, direct, tip)

	startHash, err := direct.GetBlockHash(int64(startHeight))
	require.NoError(t, err)

	client, proxy := newProxiedClient(t, direct, shouldFail)

	return client, proxy, *startHash, tip
}

// waitForBackendHeight waits until the bitcoind node reaches the height.
func waitForBackendHeight(t *testing.T, client *BitcoindClient, tip int32) {
	t.Helper()

	require.Eventually(t, func() bool {
		_, height, err := client.GetBestBlock()
		return err == nil && height == tip
	}, rescanTestTimeout, 50*time.Millisecond)
}

// newProxiedClient returns a started client that reaches the same bitcoind
// node as direct through a proxy with the given failure rule.
func newProxiedClient(t *testing.T, direct *BitcoindClient,
	shouldFail func(call int64) bool) (*BitcoindClient,
	*failingGetBlockProxy) {

	t.Helper()

	target, err := url.Parse("http://" + direct.chainConn.cfg.Host)
	require.NoError(t, err)

	proxy := &failingGetBlockProxy{
		shouldFail: shouldFail,
		backend:    httputil.NewSingleHostReverseProxy(target),
	}
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)

	cfg := direct.chainConn.cfg
	cfg.Host = strings.TrimPrefix(server.URL, "http://")

	conn, err := NewBitcoindConn(&cfg)
	require.NoError(t, err)
	require.NoError(t, conn.Start())
	t.Cleanup(conn.Stop)

	client := conn.NewBitcoindClient()
	require.NoError(t, client.Start(t.Context()))
	t.Cleanup(client.Stop)

	return client, proxy
}

// TestBitcoindRescanRetriesFailedBlock asserts that a rescan survives a failed
// getblock, finishes at the tip, and delivers every block exactly once.
func TestBitcoindRescanRetriesFailedBlock(t *testing.T) {
	// Arrange: fail the third block of the rescan, once.
	failThird := func(call int64) bool {
		return call == 3
	}
	client, proxy, start, tip := setupRescanClient(t, failThird)

	require.NoError(t, client.NotifyBlocks())

	// Act.
	require.NoError(t, client.Rescan(&start, nil, nil))

	// Assert.
	seen := make(map[int32]int)
	timeout := time.After(rescanTestTimeout)
	for finished := false; !finished; {
		select {
		case ntfn := <-client.Notifications():
			switch n := ntfn.(type) {
			case FilteredBlockConnected:
				seen[n.Block.Height]++

			case *RescanFinished:
				require.Equal(t, tip, n.Height)
				finished = true
			}

		case <-timeout:
			t.Fatalf("no RescanFinished after a failed getblock; "+
				"blocks delivered: %d", len(seen))
		}
	}

	require.EqualValues(t, 1, proxy.failed.Load())
	require.Len(t, seen, rescanTestBlocks)
	for height, count := range seen {
		require.Equalf(t, 1, count, "block %d delivered %d times",
			height, count)
	}
}

// TestBitcoindRescanRetryAcrossReorg asserts that when a reorg replaces blocks
// a failed rescan delivered, the retry disconnects them and delivers the new
// chain.
func TestBitcoindRescanRetryAcrossReorg(t *testing.T) {
	// Arrange: two forks from a common block. The backend is on the short
	// one, and the rescan delivers two of its blocks and then fails.
	miner1, miner2 := setupMiners(t)
	direct := setupBitcoind(t, miner1.P2PAddress(), true)

	start, height, err := miner1.Client.GetBestBlock()
	require.NoError(t, err)
	waitForBackendHeight(t, direct, height)

	err = miner1.Client.AddNode(miner2.P2PAddress(), rpcclient.ANRemove)
	require.NoError(t, err)

	longFork, err := miner2.Client.Generate(rescanTestBlocks + 2)
	require.NoError(t, err)

	shortFork, err := miner1.Client.Generate(rescanTestBlocks - 1)
	require.NoError(t, err)
	waitForBackendHeight(t, direct, height+rescanTestBlocks-1)

	var released atomic.Bool
	client, proxy := newProxiedClient(t, direct, func(call int64) bool {
		return call >= 3 && !released.Load()
	})
	require.NoError(t, client.NotifyBlocks())
	require.NoError(t, client.Rescan(start, nil, nil))
	require.Eventually(t, func() bool {
		return proxy.failed.Load() > 0
	}, rescanTestTimeout, 10*time.Millisecond)

	// Act: the backend reorgs to the long fork while the rescan waits.
	require.NoError(t, rpctest.ConnectNode(miner1, miner2))
	require.NoError(t, rpctest.JoinNodes(
		[]*rpctest.Harness{miner1, miner2}, rpctest.Blocks,
	))
	waitForBackendHeight(t, direct, height+int32(len(longFork)))
	released.Store(true)

	// Assert: the delivered blocks of the short fork are disconnected, and
	// every height ends on the long fork.
	view := make(map[int32]chainhash.Hash)
	disconnected := make(map[chainhash.Hash]struct{})
	onLongFork := func() bool {
		for i, hash := range longFork {
			if view[height+int32(i)+1] != *hash {
				return false
			}
		}

		_, first := disconnected[*shortFork[0]]
		_, second := disconnected[*shortFork[1]]

		return first && second
	}

	timeout := time.After(rescanTestTimeout)
	for finished := false; !finished || !onLongFork(); {
		select {
		case ntfn := <-client.Notifications():
			switch n := ntfn.(type) {
			case BlockConnected:
				view[n.Height] = n.Hash

			case BlockDisconnected:
				disconnected[n.Hash] = struct{}{}
				if view[n.Height] == n.Hash {
					delete(view, n.Height)
				}

			case *RescanFinished:
				require.Equal(t, *longFork[len(longFork)-1],
					*n.Hash)
				finished = true
			}

		case <-timeout:
			t.Fatalf("rescan did not settle on the long fork: "+
				"finished=%v, heights=%d, disconnected=%d",
				finished, len(view), len(disconnected))
		}
	}
}

// TestBitcoindRescanRetryStopsOnShutdown asserts that a rescan that keeps
// failing does not hold up the client's shutdown.
func TestBitcoindRescanRetryStopsOnShutdown(t *testing.T) {
	// Arrange: every getblock fails.
	client, proxy, start, _ := setupRescanClient(t, func(int64) bool {
		return true
	})
	require.NoError(t, client.Rescan(&start, nil, nil))
	require.Eventually(t, func() bool {
		return proxy.failed.Load() > 0
	}, rescanTestTimeout, 10*time.Millisecond)

	// Act.
	done := make(chan struct{})
	go func() {
		client.Stop()
		client.WaitForShutdown()
		close(done)
	}()

	// Assert: shutdown does not wait out the retry loop.
	select {
	case <-done:
	case <-time.After(rescanRetryMinBackoff * 10):
		t.Fatal("client did not shut down while a rescan was retrying")
	}
}
