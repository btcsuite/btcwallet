package bwtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/stretchr/testify/require"
)

// TestWaitForMinerTipRejectsPartialMatch verifies that neither the right hash
// at the wrong height nor a competing hash at the right height completes the
// external miner readiness boundary.
func TestWaitForMinerTipRejectsPartialMatch(t *testing.T) {
	t.Parallel()

	// Arrange: the RPC source advances through two partial matches before
	// publishing the complete expected tip. No Wallet state is involved.
	wantHash := chainhash.Hash{1}

	const wantHeight = 3

	var calls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {

		var request struct {
			ID json.RawMessage `json:"id"`
		}

		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		hash, height := wantHash, wantHeight
		switch calls.Add(1) {
		case 1:
			height--

		case 2:
			hash = chainhash.Hash{2}
		}

		response := struct {
			Result map[string]any  `json:"result"`
			Error  any             `json:"error"`
			ID     json.RawMessage `json:"id"`
		}{
			Result: map[string]any{"hash": hash.String(), "height": height},
			ID:     request.ID,
		}

		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			t.Errorf("write miner response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	client, err := rpcclient.New(&rpcclient.ConnConfig{
		Host:         strings.TrimPrefix(server.URL, "http://"),
		User:         "test",
		Pass:         "test",
		HTTPPostMode: true,
		DisableTLS:   true,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(client.Shutdown)

	h := &HarnessTest{
		T: t,
		miner: &minerHarness{
			T:       t,
			Harness: &rpctest.Harness{Client: client},
		},
	}

	// Act: wait through both partial matches to the complete tip.
	h.WaitForMinerTip(wantHash, wantHeight)

	// Assert: accepting either partial match would return before call three.
	require.Equal(t, int32(3), calls.Load())
}
