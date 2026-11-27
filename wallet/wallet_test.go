package wallet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

var (
	TstSerializedTx, _ = hex.DecodeString("010000000114d9ff358894c486b4ae11c2a8cf7851b1df64c53d2e511278eff17c22fb7373000000008c493046022100995447baec31ee9f6d4ec0e05cb2a44f6b817a99d5f6de167d1c75354a946410022100c9ffc23b64d770b0e01e7ff4d25fbc2f1ca8091053078a247905c39fce3760b601410458b8e267add3c1e374cf40f1de02b59213a82e1d84c2b94096e22e2f09387009c96debe1d0bcb2356ffdcf65d2a83d4b34e72c62eccd8490dbf2110167783b2bffffffff0280969800000000001976a914479ed307831d0ac19ebc5f63de7d5f1a430ddb9d88ac38bfaa00000000001976a914dadf9e3484f28b385ddeaa6c575c0c0d18e9788a88ac00000000")
	TstTx, _           = btcutil.NewTxFromBytes(TstSerializedTx)
	TstTxHash          = TstTx.Hash()

	TstMinedTxBlockHeight        = int32(279143)
	TstMinedSignedTxBlockDetails = &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   *TstTxHash,
			Height: TstMinedTxBlockHeight,
		},
		Time: time.Now(),
	}
)

// TestLocateBirthdayBlock ensures we can properly map a block in the chain to a
// timestamp.
func TestLocateBirthdayBlock(t *testing.T) {
	t.Parallel()

	// We'll use test chains of 30 blocks with a duration between two
	// consecutive blocks being slightly greater than the largest margin
	// allowed by locateBirthdayBlock. Doing so lets us test the method more
	// effectively as there is only one block within the chain that can map
	// to a timestamp (this does not apply to the first and last blocks,
	// which can map to many timestamps beyond either end of chain).
	const (
		numBlocks     = 30
		blockInterval = birthdayBlockDelta + 1
	)

	genesisTimestamp := chainParams.GenesisBlock.Header.Timestamp

	testCases := []struct {
		name           string
		birthday       time.Time
		birthdayHeight int32
	}{
		{
			name:           "left-right-left-left",
			birthday:       genesisTimestamp.Add(8 * blockInterval),
			birthdayHeight: 8,
		},
		{
			name:           "right-right-right-left",
			birthday:       genesisTimestamp.Add(27 * blockInterval),
			birthdayHeight: 27,
		},
		{
			name:           "before start height",
			birthday:       genesisTimestamp.Add(-blockInterval),
			birthdayHeight: 0,
		},
		{
			name:           "start height",
			birthday:       genesisTimestamp,
			birthdayHeight: 0,
		},
		{
			name:           "end height",
			birthday:       genesisTimestamp.Add(numBlocks * blockInterval),
			birthdayHeight: numBlocks - 1,
		},
		{
			name:           "after end height",
			birthday:       genesisTimestamp.Add(2 * numBlocks * blockInterval),
			birthdayHeight: numBlocks - 1,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		success := t.Run(testCase.name, func(t *testing.T) {
			chainConn := createMockChainConn(
				chainParams.GenesisBlock, numBlocks, blockInterval,
			)
			birthdayBlock, err := locateBirthdayBlock(
				chainConn, testCase.birthday,
			)
			if err != nil {
				t.Fatalf("unable to locate birthday block: %v",
					err)
			}
			if birthdayBlock.Height != testCase.birthdayHeight {
				t.Fatalf("expected birthday block with height "+
					"%d, got %d", testCase.birthdayHeight,
					birthdayBlock.Height)
			}
		})
		if !success {
			break
		}
	}
}

// TestLabelTransaction tests labelling of transactions with invalid labels,
// and failure to label a transaction when it already has a label.
func TestLabelTransaction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// Whether the transaction should be known to the wallet.
		txKnown bool

		// Whether the test should write an existing label to disk.
		existingLabel bool

		// The overwrite parameter to call label transaction with.
		overwrite bool

		// The error we expect to be returned.
		expectedErr error
	}{
		{
			name:          "existing label, not overwrite",
			txKnown:       true,
			existingLabel: true,
			overwrite:     false,
			expectedErr:   ErrTxLabelExists,
		},
		{
			name:          "existing label, overwritten",
			txKnown:       true,
			existingLabel: true,
			overwrite:     true,
			expectedErr:   nil,
		},
		{
			name:          "no prexisting label, ok",
			txKnown:       true,
			existingLabel: false,
			overwrite:     false,
			expectedErr:   nil,
		},
		{
			name:          "transaction unknown",
			txKnown:       false,
			existingLabel: false,
			overwrite:     false,
			expectedErr:   ErrUnknownTransaction,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			w, cleanup := testWallet(t)
			defer cleanup()

			// If the transaction should be known to the store, we
			// write txdetail to disk.
			if test.txKnown {
				rec, err := wtxmgr.NewTxRecord(
					TstSerializedTx, time.Now(),
				)
				if err != nil {
					t.Fatal(err)
				}

				err = walletdb.Update(w.db,
					func(tx walletdb.ReadWriteTx) error {

						ns := tx.ReadWriteBucket(
							wtxmgrNamespaceKey,
						)

						return w.TxStore.InsertTx(
							ns, rec, nil,
						)
					})
				if err != nil {
					t.Fatalf("could not insert tx: %v", err)
				}
			}

			// If we want to setup an existing label for the purpose
			// of the test, write one to disk.
			if test.existingLabel {
				err := w.LabelTransaction(
					*TstTxHash, "existing label", false,
				)
				if err != nil {
					t.Fatalf("could not write label: %v",
						err)
				}
			}

			newLabel := "new label"
			err := w.LabelTransaction(
				*TstTxHash, newLabel, test.overwrite,
			)
			if err != test.expectedErr {
				t.Fatalf("expected: %v, got: %v",
					test.expectedErr, err)
			}
		})
	}
}

// TestGetTransaction tests if we can fetch a mined, an existing
// and a non-existing transaction from the wallet like we expect.
func TestGetTransaction(t *testing.T) {
	t.Parallel()
	rec, err := wtxmgr.NewTxRecord(TstSerializedTx, time.Now())
	require.NoError(t, err)

	tests := []struct {
		name string

		// Transaction id.
		txid chainhash.Hash

		// Expected height.
		expectedHeight int32

		// Store function.
		f func(*wtxmgr.Store, walletdb.ReadWriteBucket) (*wtxmgr.Store, error)

		// The error we expect to be returned.
		expectedErr error
	}{
		{
			name:           "existing unmined transaction",
			txid:           *TstTxHash,
			expectedHeight: -1,
			// We write txdetail for the tx to disk.
			f: func(s *wtxmgr.Store, ns walletdb.ReadWriteBucket) (
				*wtxmgr.Store, error) {

				err = s.InsertTx(ns, rec, nil)
				return s, err
			},
			expectedErr: nil,
		},
		{
			name: "existing mined transaction",
			txid: *TstTxHash,
			// We write txdetail for the tx to disk.
			f: func(s *wtxmgr.Store, ns walletdb.ReadWriteBucket) (
				*wtxmgr.Store, error) {

				err = s.InsertTx(ns, rec, TstMinedSignedTxBlockDetails)
				return s, err
			},
			expectedHeight: TstMinedTxBlockHeight,
			expectedErr:    nil,
		},
		{
			name: "non-existing transaction",
			txid: *TstTxHash,
			// Write no txdetail to disk.
			f: func(s *wtxmgr.Store, ns walletdb.ReadWriteBucket) (
				*wtxmgr.Store, error) {

				return s, nil
			},
			expectedErr: ErrNoTx,
		},
	}
	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			w, cleanup := testWallet(t)
			defer cleanup()

			err := walletdb.Update(w.db, func(rw walletdb.ReadWriteTx) error {
				ns := rw.ReadWriteBucket(wtxmgrNamespaceKey)
				_, err := test.f(w.TxStore, ns)
				return err
			})
			require.NoError(t, err)
			tx, err := w.GetTransaction(test.txid)
			require.ErrorIs(t, err, test.expectedErr)

			// Discontinue if no transaction were found.
			if err != nil {
				return
			}

			// Check if we get the expected hash.
			require.Equal(t, &test.txid, tx.Summary.Hash)

			// Check the block height.
			require.Equal(t, test.expectedHeight, tx.Height)
		})
	}
}

// TestGetTransactionConfirmations tests that GetTransaction correctly
// calculates confirmations for both confirmed and unconfirmed transactions.
// This is a regression test for a bug where confirmations were set to the
// block height instead of being calculated as currentHeight - blockHeight + 1.
//
// The bug had several negative impacts:
//   - Unconfirmed transactions showed -1 confirmations instead of 0, breaking
//     zero-conf (accepting transactions before block inclusion)
//   - Confirmed transactions showed block height instead of actual confirmation
//     count
//   - LND and other consumers would make incorrect decisions based on wrong
//     counts
func TestGetTransactionConfirmations(t *testing.T) {
	t.Parallel()

	rec, err := wtxmgr.NewTxRecord(TstSerializedTx, time.Now())
	require.NoError(t, err)

	tests := []struct {
		name string

		// Block height where transaction is mined (-1 for unmined).
		txBlockHeight int32

		// Current wallet sync height.
		currentHeight int32

		// Expected confirmations.
		expectedConfirmations int32

		// Expected height in result.
		expectedHeight int32

		// Whether to check for non-zero timestamp.
		expectTimestamp bool
	}{
		{
			name:                  "unconfirmed tx",
			txBlockHeight:         -1,
			currentHeight:         100,
			expectedConfirmations: 0,
			expectedHeight:        -1,
			expectTimestamp:       false,
		},
		{
			name:                  "tx with 1 confirmation",
			txBlockHeight:         100,
			currentHeight:         100,
			expectedConfirmations: 1,
			expectedHeight:        100,
			expectTimestamp:       true,
		},
		{
			name:                  "tx with 3 confirmations",
			txBlockHeight:         8,
			currentHeight:         10,
			expectedConfirmations: 3,
			expectedHeight:        8,
			expectTimestamp:       true,
		},
		{
			name:                  "old tx with many confirmations",
			txBlockHeight:         1,
			currentHeight:         1000,
			expectedConfirmations: 1000,
			expectedHeight:        1,
			expectTimestamp:       true,
		},
		{
			name:                  "tx in future block",
			txBlockHeight:         105,
			currentHeight:         100,
			expectedConfirmations: 0,
			expectedHeight:        105,
			expectTimestamp:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w, cleanup := testWallet(t)
			t.Cleanup(cleanup)

			// Set the wallet's synced height.
			err := walletdb.Update(
				w.db, func(tx walletdb.ReadWriteTx) error {
					addrmgrNs := tx.ReadWriteBucket(
						waddrmgrNamespaceKey,
					)
					bs := &waddrmgr.BlockStamp{
						Height: tt.currentHeight,
						Hash:   chainhash.Hash{},
					}

					return w.Manager.SetSyncedTo(
						addrmgrNs, bs,
					)
				},
			)
			require.NoError(t, err)

			// Insert transaction into wallet.
			err = walletdb.Update(
				w.db, func(tx walletdb.ReadWriteTx) error {
					ns := tx.ReadWriteBucket(
						wtxmgrNamespaceKey,
					)

					// Create block metadata if transaction
					// is mined.
					var blockMeta *wtxmgr.BlockMeta
					if tt.txBlockHeight != -1 {
						hash := chainhash.Hash{}
						height := tt.txBlockHeight
						block := wtxmgr.Block{
							Hash:   hash,
							Height: height,
						}
						blockMeta = &wtxmgr.BlockMeta{
							Block: block,
							Time:  time.Now(),
						}
					}

					return w.TxStore.InsertTx(
						ns, rec, blockMeta,
					)
				},
			)
			require.NoError(t, err)

			result, err := w.GetTransaction(*TstTxHash)
			require.NoError(t, err)

			require.Equal(
				t, tt.expectedConfirmations,
				result.Confirmations,
			)

			require.Equal(t, tt.expectedHeight, result.Height)

			if tt.expectTimestamp {
				require.NotZero(t, result.Timestamp)
			} else {
				require.Zero(t, result.Timestamp)
			}

			// Additional checks for unconfirmed transactions.
			if tt.txBlockHeight == -1 {
				require.Nil(t, result.BlockHash)
				require.Equal(t, int32(0), result.Confirmations)
			} else {
				require.NotNil(t, result.BlockHash)
				// Only expect positive confirmations when tx is
				// not in a future block.
				if tt.txBlockHeight <= tt.currentHeight {
					require.Positive(
						t, result.Confirmations,
					)
				} else {
					// Confirmed txns in future blocks for
					// example due to reorg should be
					// treated as unconfirmed and have 0
					// confirmations.
					require.Equal(
						t, int32(0),
						result.Confirmations,
					)
				}
			}
		})
	}
}

// TestDuplicateAddressDerivation tests that duplicate addresses are not
// derived when multiple goroutines are concurrently requesting new addresses.
func TestDuplicateAddressDerivation(t *testing.T) {
	w, cleanup := testWallet(t)
	defer cleanup()

	var (
		m           sync.Mutex
		globalAddrs = make(map[string]address.Address)
	)

	for o := 0; o < 10; o++ {
		var eg errgroup.Group

		for n := 0; n < 10; n++ {
			eg.Go(func() error {
				addrs := make([]address.Address, 10)
				for i := 0; i < 10; i++ {
					addr, err := w.NewAddress(
						0, waddrmgr.KeyScopeBIP0084,
					)
					if err != nil {
						return err
					}

					addrs[i] = addr
				}

				m.Lock()
				defer m.Unlock()

				for idx := range addrs {
					addrStr := addrs[idx].String()
					if a, ok := globalAddrs[addrStr]; ok {
						return fmt.Errorf("duplicate "+
							"address! already "+
							"have %v, want to "+
							"add %v", a, addrs[idx])
					}

					globalAddrs[addrStr] = addrs[idx]
				}

				return nil
			})
		}

		require.NoError(t, eg.Wait())
	}
}

func TestEndRecovery(t *testing.T) {
	// This is an unconventional unit test, but I'm trying to keep things as
	// succint as possible so that this test is readable without having to mock
	// up literally everything.
	// The unmonitored goroutine we're looking at is pretty deep:
	// SynchronizeRPC -> handleChainNotifications -> syncWithChain -> recovery
	// The "deadlock" we're addressing isn't actually a deadlock, but the wallet
	// will hang on Stop() -> WaitForShutdown() until (*Wallet).recovery gets
	// every single block, which could be hours depending on hardware and
	// network factors. The WaitGroup is incremented in SynchronizeRPC, and
	// WaitForShutdown will not return until handleChainNotifications returns,
	// which is blocked by a running (*Wallet).recovery loop.
	// It is noted that the conditions for long recovery are difficult to hit
	// when using btcwallet with a fresh seed, because it requires an early
	// birthday to be set or established.

	w, cleanup := testWallet(t)

	blockHashCalled := make(chan struct{})

	chainClient := &mockChainClient{
		// Force the loop to iterate about forever.
		getBestBlockHeight: math.MaxInt32,
		// Get control of when the loop iterates.
		getBlockHashFunc: func() (*chainhash.Hash, error) {
			blockHashCalled <- struct{}{}
			return &chainhash.Hash{}, nil
		},
		// Avoid a panic.
		getBlockHeader: &wire.BlockHeader{},
	}

	recoveryDone := make(chan struct{})
	go func() {
		defer close(recoveryDone)
		w.recovery(chainClient, &waddrmgr.BlockStamp{})
	}()

	getBlockHashCalls := func(expCalls int) {
		var i int
		for {
			select {
			case <-blockHashCalled:
				i++
			case <-time.After(time.Second):
				t.Fatal("expected BlockHash to be called")
			}
			if i == expCalls {
				break
			}
		}
	}

	// Recovery is running.
	getBlockHashCalls(3)

	// Closing the quit channel, e.g. Stop() without endRecovery, alone will not
	// end the recovery loop.
	w.quitMu.Lock()
	close(w.quit)
	w.quitMu.Unlock()
	// Continues scanning.
	getBlockHashCalls(3)

	// We're done with this one
	atomic.StoreUint32(&w.recovering.Load().(*recoverySyncer).quit, 1)
	select {
	case <-blockHashCalled:
	case <-recoveryDone:
	}
	cleanup()

	// Try again.
	w, cleanup = testWallet(t)
	defer cleanup()

	// We'll catch the error to make sure we're hitting our desired path. The
	// WaitGroup isn't required for the test, but does show how it completes
	// shutdown at a higher level.
	var err error
	w.wg.Add(1)
	recoveryDone = make(chan struct{})
	go func() {
		defer w.wg.Done()
		defer close(recoveryDone)
		err = w.recovery(chainClient, &waddrmgr.BlockStamp{})
	}()

	waitedForShutdown := make(chan struct{})
	go func() {
		w.WaitForShutdown()
		close(waitedForShutdown)
	}()

	// Recovery is running.
	getBlockHashCalls(3)

	// endRecovery is required to exit the unmonitored goroutine.
	end := w.endRecovery()
	select {
	case <-blockHashCalled:
	case <-recoveryDone:
	}
	<-end

	// testWallet starts a couple of other unrelated goroutines that need to be
	// killed, so we still need to close the quit channel.
	w.quitMu.Lock()
	close(w.quit)
	w.quitMu.Unlock()

	select {
	case <-waitedForShutdown:
	case <-time.After(time.Second):
		t.Fatal("WaitForShutdown never returned")
	}

	if !strings.EqualFold(err.Error(), "recovery: forced shutdown") {
		t.Fatal("wrong error")
	}
}

// TestGetTransactionsBitcoindEndBlockHash verifies that GetTransactions assigns
// the resolved BitcoindClient endBlock height to end rather than start.
func TestGetTransactionsBitcoindEndBlockHash(t *testing.T) {
	t.Parallel()

	block100Hash := chainhash.Hash{0x01}
	block200Hash := chainhash.Hash{0x02}
	block300Hash := chainhash.Hash{0x03}

	blockHeights := map[string]int32{
		block100Hash.String(): 100,
		block200Hash.String(): 200,
		block300Hash.String(): 300,
	}

	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ID     any             `json:"id"`
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			var result any
			switch req.Method {
			case "getblockhash":
				result = chaincfg.TestNet3Params.GenesisHash.String()
			case "getblockchaininfo":
				result = map[string]any{"pruned": false}
			case "getinfo", "getnetworkinfo":
				result = map[string]any{"version": 240000}
			case "getblockheader":
				var params []any
				_ = json.Unmarshal(req.Params, &params)
				hashStr, _ := params[0].(string)
				height, ok := blockHeights[hashStr]
				if !ok {
					http.Error(
						w, "unknown block",
						http.StatusNotFound,
					)
					return
				}
				result = map[string]any{"height": height}
			default:
				http.Error(
					w, "unsupported method: "+req.Method,
					http.StatusNotFound,
				)
				return
			}

			resp := map[string]any{
				"jsonrpc": "1.0",
				"id":      req.ID,
				"result":  result,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		},
	))
	defer srv.Close()

	bitcoindConn, err := chain.NewBitcoindConn(&chain.BitcoindConfig{
		ChainParams:   &chaincfg.TestNet3Params,
		Host:          strings.TrimPrefix(srv.URL, "http://"),
		User:          "user",
		Pass:          "pass",
		PollingConfig: &chain.PollingConfig{},
	})
	require.NoError(t, err)

	w, cleanup := testWallet(t)
	defer func() {
		w.Stop()
		w.WaitForShutdown()
		_ = w.Database().Close()
		cleanup()
	}()
	w.chainClient = bitcoindConn.NewBitcoindClient()

	blocks := []struct {
		hash   chainhash.Hash
		height int32
	}{
		{hash: block100Hash, height: 100},
		{hash: block200Hash, height: 200},
		{hash: block300Hash, height: 300},
	}

	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		for i, blk := range blocks {
			msgTx := TstTx.MsgTx().Copy()
			msgTx.LockTime = uint32(i + 1)
			rec, err := wtxmgr.NewTxRecordFromMsgTx(
				msgTx, time.Now(),
			)
			if err != nil {
				return err
			}
			meta := &wtxmgr.BlockMeta{
				Block: wtxmgr.Block{
					Hash:   blk.hash,
					Height: blk.height,
				},
				Time: time.Now(),
			}
			if err := w.TxStore.InsertTx(ns, rec, meta); err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err)

	testCases := []struct {
		name       string
		startBlock *BlockIdentifier
		endBlock   *BlockIdentifier
	}{
		{
			name:       "height start and hash end",
			startBlock: NewBlockIdentifierFromHeight(100),
			endBlock:   NewBlockIdentifierFromHash(&block200Hash),
		},
		{
			name:       "hash start and hash end",
			startBlock: NewBlockIdentifierFromHash(&block100Hash),
			endBlock:   NewBlockIdentifierFromHash(&block200Hash),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			res, err := w.GetTransactions(
				tc.startBlock, tc.endBlock, "", nil,
			)
			require.NoError(t, err)
			require.Len(t, res.MinedTransactions, 2)
			require.Equal(
				t, int32(100), res.MinedTransactions[0].Height,
			)
			require.Equal(
				t, int32(200), res.MinedTransactions[1].Height,
			)
		})
	}
}
