// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

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
			w := testWallet(t)

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

						return w.txStore.InsertTx(
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
		f func(wtxmgr.TxStore,
			walletdb.ReadWriteBucket) (wtxmgr.TxStore, error)

		// The error we expect to be returned.
		expectedErr error
	}{
		{
			name:           "existing unmined transaction",
			txid:           *TstTxHash,
			expectedHeight: -1,
			// We write txdetail for the tx to disk.
			f: func(s wtxmgr.TxStore, ns walletdb.ReadWriteBucket) (
				wtxmgr.TxStore, error) {

				err = s.InsertTx(ns, rec, nil)
				return s, err
			},
			expectedErr: nil,
		},
		{
			name: "existing mined transaction",
			txid: *TstTxHash,
			// We write txdetail for the tx to disk.
			f: func(s wtxmgr.TxStore, ns walletdb.ReadWriteBucket) (
				wtxmgr.TxStore, error) {

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
			f: func(s wtxmgr.TxStore, _ walletdb.ReadWriteBucket) (
				wtxmgr.TxStore, error) {

				return s, nil
			},
			expectedErr: ErrNoTx,
		},
	}
	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			w := testWallet(t)

			err := walletdb.Update(w.db, func(rw walletdb.ReadWriteTx) error {
				ns := rw.ReadWriteBucket(wtxmgrNamespaceKey)
				_, err := test.f(w.txStore, ns)
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
			w := testWallet(t)

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

					return w.addrStore.SetSyncedTo(
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

					return w.txStore.InsertTx(
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
	w := testWallet(t)
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
					addr, err := w.NewAddressDeprecated(
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

// TestEndRecovery verifies that wallet shutdown interrupts recovery cleanly.
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

	w := testWallet(t)

	blockHashCalled := make(chan struct{})

	chainClient := &bwmock.Chain{}
	// Force the loop to iterate about forever.
	chainClient.On("GetBestBlock").Return(
		(*chainhash.Hash)(nil), int32(math.MaxInt32), error(nil),
	)
	// Get control of when the loop iterates by signaling on each call.
	chainClient.On("GetBlockHash", mock.Anything).Run(
		func(args mock.Arguments) {
			blockHashCalled <- struct{}{}
		},
	).Return(&chainhash.Hash{}, error(nil))
	// Avoid a panic when the recovery loop inspects the block header.
	chainClient.On("GetBlockHeader", mock.Anything).Return(
		&wire.BlockHeader{}, error(nil),
	)

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

	// Try again.
	w = testWallet(t)

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

// mockBirthdayStore is a mock in-memory implementation of the birthdayStore interface
// that will be used for the birthday block sanity check tests.
type mockBirthdayStore struct {
	birthday              time.Time
	birthdayBlock         *waddrmgr.BlockStamp
	birthdayBlockVerified bool
	syncedTo              waddrmgr.BlockStamp
}

var _ birthdayStore = (*mockBirthdayStore)(nil)

// Birthday returns the birthday timestamp of the wallet.
func (s *mockBirthdayStore) Birthday() time.Time {
	return s.birthday
}

// BirthdayBlock returns the birthday block of the wallet.
func (s *mockBirthdayStore) BirthdayBlock() (waddrmgr.BlockStamp, bool, error) {
	if s.birthdayBlock == nil {
		err := waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrBirthdayBlockNotSet,
		}
		return waddrmgr.BlockStamp{}, false, err
	}

	return *s.birthdayBlock, s.birthdayBlockVerified, nil
}

// SetBirthdayBlock updates the birthday block of the wallet to the given block.
// The boolean can be used to signal whether this block should be sanity checked
// the next time the wallet starts.
func (s *mockBirthdayStore) SetBirthdayBlock(block waddrmgr.BlockStamp) error {
	s.birthdayBlock = &block
	s.birthdayBlockVerified = true
	s.syncedTo = block
	return nil
}

// TestBirthdaySanityCheckEmptyBirthdayBlock ensures that a sanity check is not
// done if the birthday block does not exist in the first place.
func TestBirthdaySanityCheckEmptyBirthdayBlock(t *testing.T) {
	t.Parallel()

	chainConn := &mockChainConn{}

	// Our birthday store will reflect that we don't have a birthday block
	// set, so we should not attempt a sanity check.
	birthdayStore := &mockBirthdayStore{}

	birthdayBlock, err := birthdaySanityCheck(chainConn, birthdayStore)
	if !waddrmgr.IsError(err, waddrmgr.ErrBirthdayBlockNotSet) {
		t.Fatalf("expected ErrBirthdayBlockNotSet, got %v", err)
	}

	if birthdayBlock != nil {
		t.Fatalf("expected birthday block to be nil due to not being "+
			"set, got %v", *birthdayBlock)
	}
}

// TestBirthdaySanityCheckVerifiedBirthdayBlock ensures that a sanity check is
// not performed if the birthday block has already been verified.
func TestBirthdaySanityCheckVerifiedBirthdayBlock(t *testing.T) {
	t.Parallel()

	const chainTip = 5000
	const defaultBlockInterval = 10 * time.Minute
	chainConn := createMockChainConn(
		chainParams.GenesisBlock, chainTip, defaultBlockInterval,
	)
	expectedBirthdayBlock := waddrmgr.BlockStamp{Height: 1337}

	// Our birthday store reflects that our birthday block has already been
	// verified and should not require a sanity check.
	birthdayStore := &mockBirthdayStore{
		birthdayBlock:         &expectedBirthdayBlock,
		birthdayBlockVerified: true,
		syncedTo: waddrmgr.BlockStamp{
			Height: chainTip,
		},
	}

	// Now, we'll run the sanity check. We should see that the birthday
	// block hasn't changed.
	birthdayBlock, err := birthdaySanityCheck(chainConn, birthdayStore)
	if err != nil {
		t.Fatalf("unable to sanity check birthday block: %v", err)
	}
	if !reflect.DeepEqual(*birthdayBlock, expectedBirthdayBlock) {
		t.Fatalf("expected birthday block %v, got %v",
			expectedBirthdayBlock, birthdayBlock)
	}

	// To ensure the sanity check didn't proceed, we'll check our synced to
	// height, as this value should have been modified if a new candidate
	// was found.
	if birthdayStore.syncedTo.Height != chainTip {
		t.Fatalf("expected synced height remain the same (%d), got %d",
			chainTip, birthdayStore.syncedTo.Height)
	}
}

// TestBirthdaySanityCheckLowerEstimate ensures that we can properly locate a
// better birthday block candidate if our estimate happens to be too far back in
// the chain.
func TestBirthdaySanityCheckLowerEstimate(t *testing.T) {
	t.Parallel()

	const defaultBlockInterval = 10 * time.Minute

	// We'll start by defining our birthday timestamp to be around the
	// timestamp of the 1337th block.
	genesisTimestamp := chainParams.GenesisBlock.Header.Timestamp
	birthday := genesisTimestamp.Add(1337 * defaultBlockInterval)

	// We'll establish a connection to a mock chain of 5000 blocks.
	chainConn := createMockChainConn(
		chainParams.GenesisBlock, 5000, defaultBlockInterval,
	)

	// Our birthday store will reflect that our birthday block is currently
	// set as the genesis block. This value is too low and should be
	// adjusted by the sanity check.
	birthdayStore := &mockBirthdayStore{
		birthday: birthday,
		birthdayBlock: &waddrmgr.BlockStamp{
			Hash:      *chainParams.GenesisHash,
			Height:    0,
			Timestamp: genesisTimestamp,
		},
		birthdayBlockVerified: false,
		syncedTo: waddrmgr.BlockStamp{
			Height: 5000,
		},
	}

	// We'll perform the sanity check and determine whether we were able to
	// find a better birthday block candidate.
	birthdayBlock, err := birthdaySanityCheck(chainConn, birthdayStore)
	if err != nil {
		t.Fatalf("unable to sanity check birthday block: %v", err)
	}
	if birthday.Sub(birthdayBlock.Timestamp) >= birthdayBlockDelta {
		t.Fatalf("expected birthday block timestamp=%v to be within "+
			"%v of birthday timestamp=%v", birthdayBlock.Timestamp,
			birthdayBlockDelta, birthday)
	}

	// Finally, our synced to height should now reflect our new birthday
	// block to ensure the wallet doesn't miss any events from this point
	// forward.
	if !reflect.DeepEqual(birthdayStore.syncedTo, *birthdayBlock) {
		t.Fatalf("expected syncedTo and birthday block to match: "+
			"%v vs %v", birthdayStore.syncedTo, birthdayBlock)
	}
}

// TestBirthdaySanityCheckHigherEstimate ensures that we can properly locate a
// better birthday block candidate if our estimate happens to be too far in the
// chain.
func TestBirthdaySanityCheckHigherEstimate(t *testing.T) {
	t.Parallel()

	const defaultBlockInterval = 10 * time.Minute

	// We'll start by defining our birthday timestamp to be around the
	// timestamp of the 1337th block.
	genesisTimestamp := chainParams.GenesisBlock.Header.Timestamp
	birthday := genesisTimestamp.Add(1337 * defaultBlockInterval)

	// We'll establish a connection to a mock chain of 5000 blocks.
	chainConn := createMockChainConn(
		chainParams.GenesisBlock, 5000, defaultBlockInterval,
	)

	// Our birthday store will reflect that our birthday block is currently
	// set as the chain tip. This value is too high and should be adjusted
	// by the sanity check.
	bestBlock := chainConn.blocks[chainConn.blockHashes[5000]]
	birthdayStore := &mockBirthdayStore{
		birthday: birthday,
		birthdayBlock: &waddrmgr.BlockStamp{
			Hash:      bestBlock.BlockHash(),
			Height:    5000,
			Timestamp: bestBlock.Header.Timestamp,
		},
		birthdayBlockVerified: false,
		syncedTo: waddrmgr.BlockStamp{
			Height: 5000,
		},
	}

	// We'll perform the sanity check and determine whether we were able to
	// find a better birthday block candidate.
	birthdayBlock, err := birthdaySanityCheck(chainConn, birthdayStore)
	if err != nil {
		t.Fatalf("unable to sanity check birthday block: %v", err)
	}
	if birthday.Sub(birthdayBlock.Timestamp) >= birthdayBlockDelta {
		t.Fatalf("expected birthday block timestamp=%v to be within "+
			"%v of birthday timestamp=%v", birthdayBlock.Timestamp,
			birthdayBlockDelta, birthday)
	}

	// Finally, our synced to height should now reflect our new birthday
	// block to ensure the wallet doesn't miss any events from this point
	// forward.
	if !reflect.DeepEqual(birthdayStore.syncedTo, *birthdayBlock) {
		t.Fatalf("expected syncedTo and birthday block to match: "+
			"%v vs %v", birthdayStore.syncedTo, birthdayBlock)
	}
}

type testCase struct {
	name               string
	masterPriv         string
	accountIndex       uint32
	addrType           waddrmgr.AddressType
	expectedScope      waddrmgr.KeyScope
	expectedAddr       string
	expectedChangeAddr string
}

var (
	//nolint:lll
	testCases = []*testCase{{
		name: "bip44 with nested witness address type",
		masterPriv: "tprv8ZgxMBicQKsPeWwrFuNjEGTTDSY4mRLwd2KDJAPGa1AY" +
			"quw38bZqNMSuB3V1Va3hqJBo9Pt8Sx7kBQer5cNMrb8SYquoWPt9" +
			"Y3BZdhdtUcw",
		accountIndex:       0,
		addrType:           waddrmgr.NestedWitnessPubKey,
		expectedScope:      waddrmgr.KeyScopeBIP0049Plus,
		expectedAddr:       "2N5YTxG9XtGXx1YyhZb7N2pwEjoZLLMHGKj",
		expectedChangeAddr: "2N7wpz5Gy2zEJTvq2MAuU6BCTEBLXNQ8dUw",
	}, {
		name: "bip44 with witness address type",
		masterPriv: "tprv8ZgxMBicQKsPeWwrFuNjEGTTDSY4mRLwd2KDJAPGa1AY" +
			"quw38bZqNMSuB3V1Va3hqJBo9Pt8Sx7kBQer5cNMrb8SYquoWPt9" +
			"Y3BZdhdtUcw",
		accountIndex:       777,
		addrType:           waddrmgr.WitnessPubKey,
		expectedScope:      waddrmgr.KeyScopeBIP0084,
		expectedAddr:       "bcrt1qllxcutkzsukf8u8c8stkp464j0esu9xquft3s0",
		expectedChangeAddr: "bcrt1qu6jmqglrthscptjqj3egx54wy8xqvzn54ex9eh",
	}, {
		name: "traditional bip49",
		masterPriv: "uprv8tXDerPXZ1QsVp8y6GAMSMYxPQgWi3LSY8qS5ZH9x1YRu" +
			"1kGPFjPzR73CFSbVUhdEwJbtsUgucUJ4hGQoJnNepp3RBcE6Jhdom" +
			"FD2KeY6G9",
		accountIndex:       9,
		addrType:           waddrmgr.NestedWitnessPubKey,
		expectedScope:      waddrmgr.KeyScopeBIP0049Plus,
		expectedAddr:       "2NBCJ9WzGXZqpLpXGq3Hacybj3c4eHRcqgh",
		expectedChangeAddr: "2N3bankFu6F3ZNU41iVJQqyS9MXqp9dvn1M",
	}, {
		name: "bip49+",
		masterPriv: "uprv8tXDerPXZ1QsVp8y6GAMSMYxPQgWi3LSY8qS5ZH9x1YRu" +
			"1kGPFjPzR73CFSbVUhdEwJbtsUgucUJ4hGQoJnNepp3RBcE6Jhdom" +
			"FD2KeY6G9",
		accountIndex:       9,
		addrType:           waddrmgr.WitnessPubKey,
		expectedScope:      waddrmgr.KeyScopeBIP0049Plus,
		expectedAddr:       "2NBCJ9WzGXZqpLpXGq3Hacybj3c4eHRcqgh",
		expectedChangeAddr: "bcrt1qeqn05w2hfq6axpdprhs4y7x65gxkkvfvx0emz4",
	}, {
		name: "bip84",
		masterPriv: "vprv9DMUxX4ShgxMM7L5vcwyeSeTZNpxefKwTFMerxB3L1vJ" +
			"x7ZVdutxcUmBDTQBVPMYeaRQeM5FNGpqwysyX1CPT4VeHXJegDX8" +
			"5VJrQvaFaz3",
		accountIndex:       1,
		addrType:           waddrmgr.WitnessPubKey,
		expectedScope:      waddrmgr.KeyScopeBIP0084,
		expectedAddr:       "bcrt1q5vepvcl0z8xj7kps4rsux722r4dvfwlh5ntexr",
		expectedChangeAddr: "bcrt1qlwe2kgxcsa8x4huu79yff4rze0l5mwaf2apn3y",
	}}
)

// TestImportAccountDeprecated tests that extended public keys can successfully
// be imported into both watch only and normal wallets.
func TestImportAccountDeprecated(t *testing.T) {
	t.Parallel()

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := testWallet(t)

			testImportAccount(t, w, tc, false, tc.name)
		})

		name := tc.name + " watch-only"
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			w := testWalletWatchingOnly(t)

			testImportAccount(t, w, tc, true, name)
		})
	}
}

// testImportAccount exercises legacy account import behavior for one case.
func testImportAccount(t *testing.T, w *Wallet, tc *testCase, watchOnly bool,
	name string) {

	// First derive the master public key of the account we want to import.
	root, err := hdkeychain.NewKeyFromString(tc.masterPriv)
	require.NoError(t, err)

	// Derive the extended private and public key for our target account.
	acct1Pub := deriveAcctPubKey(
		t, root, tc.expectedScope, hardenedKey(tc.accountIndex),
	)

	// We want to make sure we can import and handle multiple accounts, so
	// we create another one.
	acct2Pub := deriveAcctPubKey(
		t, root, tc.expectedScope, hardenedKey(tc.accountIndex+1),
	)

	// And we also want to be able to import loose extended public keys
	// without needing to specify an explicit scope.
	acct3ExternalExtPub := deriveAcctPubKey(
		t, root, tc.expectedScope, hardenedKey(tc.accountIndex+2), 0, 0,
	)
	acct3ExternalPub, err := acct3ExternalExtPub.ECPubKey()
	require.NoError(t, err)

	// Do a dry run import first and check that it results in the expected
	// addresses being derived.
	_, extAddrs, intAddrs, err := w.ImportAccountDryRun(
		name+"1", acct1Pub, root.ParentFingerprint(), &tc.addrType, 1,
	)
	require.NoError(t, err)
	require.Len(t, extAddrs, 1)
	require.Equal(t, tc.expectedAddr, extAddrs[0].Address().String())
	require.Len(t, intAddrs, 1)
	require.Equal(t, tc.expectedChangeAddr, intAddrs[0].Address().String())

	// Import the extended public keys into new accounts.
	acct1, err := w.ImportAccountDeprecated(
		name+"1", acct1Pub, root.ParentFingerprint(), &tc.addrType,
	)
	require.NoError(t, err)
	require.Equal(t, tc.expectedScope, acct1.KeyScope)

	acct2, err := w.ImportAccountDeprecated(
		name+"2", acct2Pub, root.ParentFingerprint(), &tc.addrType,
	)
	require.NoError(t, err)
	require.Equal(t, tc.expectedScope, acct2.KeyScope)

	err = w.ImportPublicKeyDeprecated(acct3ExternalPub, tc.addrType)
	require.NoError(t, err)

	// If the wallet is watch only, there is no default account and our
	// imported account will be index 0.
	firstAccountIndex := uint32(1)
	numAccounts := 2
	if watchOnly {
		firstAccountIndex = 0
		numAccounts = 1
	}

	// We should have 2 additional accounts now.
	acctResult, err := w.Accounts(tc.expectedScope)
	require.NoError(t, err)
	require.Len(t, acctResult.Accounts, numAccounts+2)

	// Validate the state of the accounts.
	require.Equal(t, firstAccountIndex, acct1.AccountNumber)
	require.Equal(t, name+"1", acct1.AccountName)
	require.Equal(t, true, acct1.IsWatchOnly)
	require.Equal(t, root.ParentFingerprint(), acct1.MasterKeyFingerprint)
	require.NotNil(t, acct1.AccountPubKey)
	require.Equal(t, acct1Pub.String(), acct1.AccountPubKey.String())
	require.Equal(t, uint32(0), acct1.InternalKeyCount)
	require.Equal(t, uint32(0), acct1.ExternalKeyCount)
	require.Equal(t, uint32(0), acct1.ImportedKeyCount)

	require.Equal(t, firstAccountIndex+1, acct2.AccountNumber)
	require.Equal(t, name+"2", acct2.AccountName)
	require.Equal(t, true, acct2.IsWatchOnly)
	require.Equal(t, root.ParentFingerprint(), acct2.MasterKeyFingerprint)
	require.NotNil(t, acct2.AccountPubKey)
	require.Equal(t, acct2Pub.String(), acct2.AccountPubKey.String())
	require.Equal(t, uint32(0), acct2.InternalKeyCount)
	require.Equal(t, uint32(0), acct2.ExternalKeyCount)
	require.Equal(t, uint32(0), acct2.ImportedKeyCount)

	// Test address derivation.
	extAddr, err := w.NewAddressDeprecated(
		acct1.AccountNumber, tc.expectedScope,
	)
	require.NoError(t, err)
	require.Equal(t, tc.expectedAddr, extAddr.String())
	intAddr, err := w.NewChangeAddress(acct1.AccountNumber, tc.expectedScope)
	require.NoError(t, err)
	require.Equal(t, tc.expectedChangeAddr, intAddr.String())

	// Make sure the key count was increased.
	acct1, err = w.AccountProperties(tc.expectedScope, acct1.AccountNumber)
	require.NoError(t, err)
	require.Equal(t, uint32(1), acct1.InternalKeyCount)
	require.Equal(t, uint32(1), acct1.ExternalKeyCount)
	require.Equal(t, uint32(0), acct1.ImportedKeyCount)

	// Make sure we can't get private keys for the imported
	// accounts.
	_, err = w.DumpWIFPrivateKey(intAddr)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWatchingOnly))

	// Get the address info for the single key we imported.
	switch tc.addrType {
	case waddrmgr.NestedWitnessPubKey:
		witnessAddr, err := address.NewAddressWitnessPubKeyHash(
			address.Hash160(acct3ExternalPub.SerializeCompressed()),
			w.chainParams,
		)
		require.NoError(t, err)

		witnessProg, err := txscript.PayToAddrScript(witnessAddr)
		require.NoError(t, err)

		intAddr, err = address.NewAddressScriptHash(
			witnessProg, w.chainParams,
		)
		require.NoError(t, err)

	case waddrmgr.WitnessPubKey:
		intAddr, err = address.NewAddressWitnessPubKeyHash(
			address.Hash160(acct3ExternalPub.SerializeCompressed()),
			w.chainParams,
		)
		require.NoError(t, err)

	default:
		t.Fatalf("unhandled address type %v", tc.addrType)
	}

	addrManaged, err := w.AddressInfoDeprecated(intAddr)
	require.NoError(t, err)
	require.Equal(t, true, addrManaged.Imported())
}

// TestCreateWatchingOnly checks that we can construct a watching-only
// wallet.
func TestCreateWatchingOnly(t *testing.T) {
	// Set up a wallet.
	dir := t.TempDir()

	pubPass := []byte("hello")

	loader := NewLoader(
		&chaincfg.TestNet3Params, dir, true, defaultDBTimeout, 250,
		WithWalletSyncRetryInterval(10*time.Millisecond),
	)
	_, err := loader.CreateNewWatchingOnlyWallet(pubPass, time.Now())
	if err != nil {
		t.Fatalf("unable to create wallet: %v", err)
	}
}

// defaultDBTimeout specifies the timeout value when opening the wallet
// database.
var defaultDBTimeout = 10 * time.Second

// testWallet creates a test wallet and unlocks it.
func testWallet(t *testing.T) *Wallet {
	t.Helper()
	// Set up a wallet.
	dir := t.TempDir()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
	if err != nil {
		t.Fatalf("unable to create seed: %v", err)
	}

	pubPass := []byte("hello")
	privPass := []byte("world")

	loader := NewLoader(
		&chainParams, dir, true, defaultDBTimeout, 250,
		WithWalletSyncRetryInterval(10*time.Millisecond),
	)
	w, err := loader.CreateNewWallet(pubPass, privPass, seed, time.Now())
	if err != nil {
		t.Fatalf("unable to create wallet: %v", err)
	}

	chainClient := &bwmock.Chain{}
	chainClient.On("BlockStamp").Return(
		&waddrmgr.BlockStamp{Height: testBlockHeight}, nil,
	).Maybe()
	chainClient.On("NotifyReceived", mock.Anything).Return(nil).Maybe()
	chainClient.On("Stop").Return().Maybe()
	chainClient.On("WaitForShutdown").Return().Maybe()
	chainClient.On("GetBestBlock").Return(
		&chainhash.Hash{}, int32(testBlockHeight), nil,
	).Maybe()
	chainClient.On("GetBlockHeader", mock.Anything).Return(
		&wire.BlockHeader{}, nil,
	).Maybe()
	w.chainClient = chainClient

	// Start the wallet.
	w.StartDeprecated()

	// Add the shutdown to the test's cleanup process.
	t.Cleanup(func() {
		w.StopDeprecated()
		w.WaitForShutdown()
	})

	err = w.UnlockDeprecated(privPass, time.After(10*time.Minute))
	if err != nil {
		t.Fatalf("unable to unlock wallet: %v", err)
	}

	return w
}

// testWalletWatchingOnly creates a test watch only wallet and unlocks it.
func testWalletWatchingOnly(t *testing.T) *Wallet {
	t.Helper()
	// Set up a wallet.
	dir := t.TempDir()

	pubPass := []byte("hello")
	loader := NewLoader(
		&chainParams, dir, true, defaultDBTimeout, 250,
		WithWalletSyncRetryInterval(10*time.Millisecond),
	)
	w, err := loader.CreateNewWatchingOnlyWallet(pubPass, time.Now())
	if err != nil {
		t.Fatalf("unable to create wallet: %v", err)
	}
	chainClient := &bwmock.Chain{}
	chainClient.On("BlockStamp").Return(
		&waddrmgr.BlockStamp{Height: testBlockHeight}, nil,
	).Maybe()
	chainClient.On("NotifyReceived", mock.Anything).Return(nil).Maybe()
	chainClient.On("Stop").Return().Maybe()
	chainClient.On("WaitForShutdown").Return().Maybe()
	chainClient.On("GetBestBlock").Return(
		&chainhash.Hash{}, int32(testBlockHeight), nil,
	).Maybe()
	chainClient.On("GetBlockHeader", mock.Anything).Return(
		&wire.BlockHeader{}, nil,
	).Maybe()
	w.chainClient = chainClient

	err = walletdb.Update(w.Database(), func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		for scope, schema := range waddrmgr.ScopeAddrMap {
			_, err := w.addrStore.NewScopedKeyManager(
				ns, scope, schema,
			)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("unable to create default scopes: %v", err)
	}

	w.StartDeprecated()
	t.Cleanup(func() {
		w.StopDeprecated()
		w.WaitForShutdown()
	})

	return w
}

var (
	testScriptP2WSH, _ = hex.DecodeString(
		"0020d554616badeb46ccd4ce4b115e1c8d098e942d1387212d0af9ff93a1" +
			"9c8f100e",
	)
	testScriptP2WKH, _ = hex.DecodeString(
		"0014e7a43aa41ef6d72dc6baeeaad8362cedf63b79a3",
	)
)

// TestFundPsbt tests that a given PSBT packet is funded correctly.
func TestFundPsbt(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

	// Create a P2WKH address we can use to send some coins to.
	addr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)
	p2wkhAddr, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Also create a nested P2WKH address we can use to send some coins to.
	addr, err = w.CurrentAddress(0, waddrmgr.KeyScopeBIP0049Plus)
	require.NoError(t, err)
	np2wkhAddr, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Register two big UTXO that will be used when funding the PSBT.
	const utxo1Amount = 1000000
	incomingTx1 := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{wire.NewTxOut(utxo1Amount, p2wkhAddr)},
	}
	addUtxo(t, w, incomingTx1)
	utxo1 := wire.OutPoint{
		Hash:  incomingTx1.TxHash(),
		Index: 0,
	}

	const utxo2Amount = 900000
	incomingTx2 := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{wire.NewTxOut(utxo2Amount, np2wkhAddr)},
	}
	addUtxo(t, w, incomingTx2)
	utxo2 := wire.OutPoint{
		Hash:  incomingTx2.TxHash(),
		Index: 0,
	}

	testCases := []struct {
		name                    string
		packet                  *psbt.Packet
		feeRateSatPerKB         btcutil.Amount
		changeKeyScope          *waddrmgr.KeyScope
		expectedErr             string
		validatePackage         bool
		expectedChangeBeforeFee int64
		expectedInputs          []wire.OutPoint
		additionalChecks        func(*testing.T, *psbt.Packet, int32)
	}{{
		name: "no outputs provided",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{},
		},
		feeRateSatPerKB: 0,
		expectedErr: "PSBT packet must contain at least one " +
			"input or output",
	}, {
		name: "single input, no outputs",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: utxo1,
				}},
			},
			Inputs: []psbt.PInput{{}},
		},
		feeRateSatPerKB:         20000,
		validatePackage:         true,
		expectedInputs:          []wire.OutPoint{utxo1},
		expectedChangeBeforeFee: utxo1Amount,
	}, {
		name: "no dust outputs",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxOut: []*wire.TxOut{{
					PkScript: []byte("foo"),
					Value:    100,
				}},
			},
			Outputs: []psbt.POutput{{}},
		},
		feeRateSatPerKB: 0,
		expectedErr:     "transaction output is dust",
	}, {
		name: "two outputs, no inputs",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxOut: []*wire.TxOut{{
					PkScript: testScriptP2WSH,
					Value:    100000,
				}, {
					PkScript: testScriptP2WKH,
					Value:    50000,
				}},
			},
			Outputs: []psbt.POutput{{}, {}},
		},
		feeRateSatPerKB:         2000, // 2 sat/byte
		expectedErr:             "",
		validatePackage:         true,
		expectedChangeBeforeFee: utxo1Amount - 150000,
		expectedInputs:          []wire.OutPoint{utxo1},
	}, {
		name: "large output, no inputs",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxOut: []*wire.TxOut{{
					PkScript: testScriptP2WSH,
					Value:    1500000,
				}},
			},
			Outputs: []psbt.POutput{{}},
		},
		feeRateSatPerKB:         4000, // 4 sat/byte
		expectedErr:             "",
		validatePackage:         true,
		expectedChangeBeforeFee: (utxo1Amount + utxo2Amount) - 1500000,
		expectedInputs:          []wire.OutPoint{utxo1, utxo2},
	}, {
		name: "two outputs, two inputs",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: utxo1,
				}, {
					PreviousOutPoint: utxo2,
				}},
				TxOut: []*wire.TxOut{{
					PkScript: testScriptP2WSH,
					Value:    100000,
				}, {
					PkScript: testScriptP2WKH,
					Value:    50000,
				}},
			},
			Inputs:  []psbt.PInput{{}, {}},
			Outputs: []psbt.POutput{{}, {}},
		},
		feeRateSatPerKB:         2000, // 2 sat/byte
		expectedErr:             "",
		validatePackage:         true,
		expectedChangeBeforeFee: (utxo1Amount + utxo2Amount) - 150000,
		expectedInputs:          []wire.OutPoint{utxo1, utxo2},
		additionalChecks: func(t *testing.T, packet *psbt.Packet,
			changeIndex int32) {

			// Check outputs, find index for each of the 3 expected.
			txOuts := packet.UnsignedTx.TxOut
			require.Len(t, txOuts, 3, "tx outputs")

			p2wkhIndex := -1
			p2wshIndex := -1
			totalOut := int64(0)
			for idx, txOut := range txOuts {
				script := txOut.PkScript
				totalOut += txOut.Value

				switch {
				case bytes.Equal(script, testScriptP2WKH):
					p2wkhIndex = idx

				case bytes.Equal(script, testScriptP2WSH):
					p2wshIndex = idx

				}
			}
			totalIn := int64(0)
			for _, txIn := range packet.Inputs {
				totalIn += txIn.WitnessUtxo.Value
			}

			// All outputs must be found.
			require.Greater(t, p2wkhIndex, -1)
			require.Greater(t, p2wshIndex, -1)
			require.Greater(t, changeIndex, int32(-1))

			// After BIP 69 sorting, the P2WKH output should be
			// before the P2WSH output because the PK script is
			// lexicographically smaller.
			require.Less(
				t, p2wkhIndex, p2wshIndex,
				"index after sorting",
			)
		},
	}, {
		name: "one input and a custom change scope: BIP0084",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: utxo1,
				}},
			},
			Inputs: []psbt.PInput{{}},
		},
		feeRateSatPerKB:         20000,
		validatePackage:         true,
		changeKeyScope:          &waddrmgr.KeyScopeBIP0084,
		expectedInputs:          []wire.OutPoint{utxo1},
		expectedChangeBeforeFee: utxo1Amount,
	}, {
		name: "no inputs and a custom change scope: BIP0084",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxOut: []*wire.TxOut{{
					PkScript: testScriptP2WSH,
					Value:    100000,
				}, {
					PkScript: testScriptP2WKH,
					Value:    50000,
				}},
			},
			Outputs: []psbt.POutput{{}, {}},
		},
		feeRateSatPerKB:         2000, // 2 sat/byte
		expectedErr:             "",
		validatePackage:         true,
		changeKeyScope:          &waddrmgr.KeyScopeBIP0084,
		expectedChangeBeforeFee: utxo1Amount - 150000,
		expectedInputs:          []wire.OutPoint{utxo1},
	}}

	calcFee := func(feeRateSatPerKB btcutil.Amount,
		packet *psbt.Packet) btcutil.Amount {

		var numP2WKHInputs, numNP2WKHInputs int
		for _, txin := range packet.UnsignedTx.TxIn {
			if txin.PreviousOutPoint == utxo1 {
				numP2WKHInputs++
			}
			if txin.PreviousOutPoint == utxo2 {
				numNP2WKHInputs++
			}
		}
		estimatedSize := txsizes.EstimateVirtualSize(
			0, 0, numP2WKHInputs, numNP2WKHInputs,
			packet.UnsignedTx.TxOut, 0,
		)
		return txrules.FeeForSerializeSize(
			feeRateSatPerKB, estimatedSize,
		)
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			changeIndex, err := w.FundPsbtDeprecated(
				tc.packet, nil, 1, 0,
				tc.feeRateSatPerKB, CoinSelectionLargest,
				WithCustomChangeScope(tc.changeKeyScope),
			)

			// In any case, unlock the UTXO before continuing, we
			// don't want to pollute other test iterations.
			for _, in := range tc.packet.UnsignedTx.TxIn {
				w.UnlockOutpoint(in.PreviousOutPoint)
			}

			// Make sure the error is what we expected.
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
				return
			}

			require.NoError(t, err)

			if !tc.validatePackage {
				return
			}

			// Check wire inputs.
			packet := tc.packet
			assertTxInputs(t, packet, tc.expectedInputs)

			// Run any additional tests if available.
			if tc.additionalChecks != nil {
				tc.additionalChecks(t, packet, changeIndex)
			}

			// Finally, check the change output size and fee.
			txOuts := packet.UnsignedTx.TxOut
			totalOut := int64(0)
			for _, txOut := range txOuts {
				totalOut += txOut.Value
			}
			totalIn := int64(0)
			for _, txIn := range packet.Inputs {
				totalIn += txIn.WitnessUtxo.Value
			}
			fee := totalIn - totalOut

			expectedFee := calcFee(tc.feeRateSatPerKB, packet)
			require.EqualValues(t, expectedFee, fee, "fee")
			require.EqualValues(
				t, tc.expectedChangeBeforeFee,
				txOuts[changeIndex].Value+int64(expectedFee),
			)

			changeTxOut := txOuts[changeIndex]
			changeOutput := packet.Outputs[changeIndex]

			require.NotEmpty(t, changeOutput.Bip32Derivation)
			b32d := changeOutput.Bip32Derivation[0]
			require.Len(t, b32d.Bip32Path, 5, "derivation path len")
			require.Len(t, b32d.PubKey, 33, "pubkey len")

			// The third item should be the branch and should belong
			// to a change output.
			require.EqualValues(t, 1, b32d.Bip32Path[3])

			assertChangeOutputScope(
				t, changeTxOut.PkScript, tc.changeKeyScope,
			)

			if txscript.IsPayToTaproot(changeTxOut.PkScript) {
				require.NotEmpty(
					t, changeOutput.TaprootInternalKey,
				)
				require.Len(
					t, changeOutput.TaprootInternalKey, 32,
					"internal key len",
				)
				require.NotEmpty(
					t, changeOutput.TaprootBip32Derivation,
				)

				trb32d := changeOutput.TaprootBip32Derivation[0]
				require.Equal(
					t, b32d.Bip32Path, trb32d.Bip32Path,
				)
				require.Len(
					t, trb32d.XOnlyPubKey, 32,
					"schnorr pubkey len",
				)
				require.Equal(
					t, changeOutput.TaprootInternalKey,
					trb32d.XOnlyPubKey,
				)
			}
		})
	}
}

// assertTxInputs verifies that a PSBT contains the expected unsigned inputs.
func assertTxInputs(t *testing.T, packet *psbt.Packet,
	expected []wire.OutPoint) {

	require.Len(t, packet.UnsignedTx.TxIn, len(expected))

	// The order of the UTXOs is random, we need to loop through each of
	// them to make sure they're found. We also check that no signature data
	// was added yet.
	for _, txIn := range packet.UnsignedTx.TxIn {
		if !containsUtxo(expected, txIn.PreviousOutPoint) {
			t.Fatalf("outpoint %v not found in list of expected "+
				"UTXOs", txIn.PreviousOutPoint)
		}

		require.Empty(t, txIn.SignatureScript)
		require.Empty(t, txIn.Witness)
	}
}

// assertChangeOutputScope checks if the pkScript has the right type.
func assertChangeOutputScope(t *testing.T, pkScript []byte,
	changeScope *waddrmgr.KeyScope) {

	// By default (changeScope == nil), the script should
	// be a pay-to-taproot one.
	switch changeScope {
	case nil, &waddrmgr.KeyScopeBIP0086:
		require.True(t, txscript.IsPayToTaproot(pkScript))

	case &waddrmgr.KeyScopeBIP0049Plus, &waddrmgr.KeyScopeBIP0084:
		require.True(t, txscript.IsPayToWitnessPubKeyHash(pkScript))

	case &waddrmgr.KeyScopeBIP0044:
		require.True(t, txscript.IsPayToPubKeyHash(pkScript))

	default:
		require.Fail(t, "assertChangeOutputScope error",
			"change scope: %s", changeScope.String())
	}
}

// containsUtxo reports whether the candidate outpoint is in the list.
func containsUtxo(list []wire.OutPoint, candidate wire.OutPoint) bool {
	for _, utxo := range list {
		if utxo == candidate {
			return true
		}
	}

	return false
}

// TestFinalizePsbt tests that a given PSBT packet can be finalized.
func TestFinalizePsbt(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

	// Create a P2WKH address we can use to send some coins to.
	addr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	p2wkhAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to p2wkh: %v", err)
	}

	// Also create a nested P2WKH address we can send coins to.
	addr, err = w.CurrentAddress(0, waddrmgr.KeyScopeBIP0049Plus)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	np2wkhAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to np2wkh: %v", err)
	}

	// Register two big UTXO that will be used when funding the PSBT.
	utxOutP2WKH := wire.NewTxOut(1000000, p2wkhAddr)
	utxOutNP2WKH := wire.NewTxOut(1000000, np2wkhAddr)
	incomingTx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{utxOutP2WKH, utxOutNP2WKH},
	}
	addUtxo(t, w, incomingTx)

	// Create the packet that we want to sign.
	packet := &psbt.Packet{
		UnsignedTx: &wire.MsgTx{
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{
					Hash:  incomingTx.TxHash(),
					Index: 0,
				},
			}, {
				PreviousOutPoint: wire.OutPoint{
					Hash:  incomingTx.TxHash(),
					Index: 1,
				},
			}},
			TxOut: []*wire.TxOut{{
				PkScript: testScriptP2WKH,
				Value:    50000,
			}, {
				PkScript: testScriptP2WSH,
				Value:    100000,
			}, {
				PkScript: testScriptP2WKH,
				Value:    849632,
			}},
		},
		Inputs: []psbt.PInput{{
			WitnessUtxo: utxOutP2WKH,
			SighashType: txscript.SigHashAll,
		}, {
			NonWitnessUtxo: incomingTx,
			SighashType:    txscript.SigHashAll,
		}},
		Outputs: []psbt.POutput{{}, {}, {}},
	}

	// Finalize it to add all witness data then extract the final TX.
	err = w.FinalizePsbtDeprecated(nil, 0, packet)
	if err != nil {
		t.Fatalf("error finalizing PSBT packet: %v", err)
	}
	finalTx, err := psbt.Extract(packet)
	if err != nil {
		t.Fatalf("error extracting final TX from PSBT: %v", err)
	}

	// Finally verify that the created witness is valid.
	err = validateMsgTx(
		finalTx, [][]byte{utxOutP2WKH.PkScript, utxOutNP2WKH.PkScript},
		[]btcutil.Amount{1000000, 1000000},
	)
	if err != nil {
		t.Fatalf("error validating tx: %v", err)
	}
}

var (
	testBlockHash, _ = chainhash.NewHashFromStr(
		"00000000000000017188b968a371bab95aa43522665353b646e41865abae" +
			"02a4",
	)
	testBlockHeight int32 = 276425

	alwaysAllowUtxo = func(utxo wtxmgr.Credit) bool { return true }
)

// TestTxToOutputsDryRun checks that no new address is added to the database if
// request a dry run of the txToOutputs call. It also makes sure a subsequent
// non-dry run call produces a similar transaction to the dry-run.
func TestTxToOutputsDryRun(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

	// Create an address we can use to send some coins to.
	keyScope := waddrmgr.KeyScopeBIP0049Plus
	addr, err := w.CurrentAddress(0, keyScope)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	p2shAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to p2sh: %v", err)
	}

	// Add an output paying to the wallet's address to the database.
	txOut := wire.NewTxOut(100000, p2shAddr)
	incomingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{},
		},
		TxOut: []*wire.TxOut{
			txOut,
		},
	}
	addUtxo(t, w, incomingTx)

	// Now tell the wallet to create a transaction paying to the specified
	// outputs.
	txOuts := []*wire.TxOut{
		{
			PkScript: p2shAddr,
			Value:    10000,
		},
		{
			PkScript: p2shAddr,
			Value:    20000,
		},
	}

	// First do a few dry-runs, making sure the number of addresses in the
	// database us not inflated.
	dryRunTx, err := w.txToOutputs(
		txOuts, nil, nil, 0, 1, 1000, CoinSelectionLargest, true,
		nil, alwaysAllowUtxo,
	)
	if err != nil {
		t.Fatalf("unable to author tx: %v", err)
	}
	change := dryRunTx.Tx.TxOut[dryRunTx.ChangeIndex]

	addresses, err := w.AccountAddresses(0)
	if err != nil {
		t.Fatalf("unable to get addresses: %v", err)
	}

	if len(addresses) != 1 {
		t.Fatalf("expected 1 address, found %v", len(addresses))
	}

	dryRunTx2, err := w.txToOutputs(
		txOuts, nil, nil, 0, 1, 1000, CoinSelectionLargest, true,
		nil, alwaysAllowUtxo,
	)
	if err != nil {
		t.Fatalf("unable to author tx: %v", err)
	}
	change2 := dryRunTx2.Tx.TxOut[dryRunTx2.ChangeIndex]

	addresses, err = w.AccountAddresses(0)
	if err != nil {
		t.Fatalf("unable to get addresses: %v", err)
	}

	if len(addresses) != 1 {
		t.Fatalf("expected 1 address, found %v", len(addresses))
	}

	// The two dry-run TXs should be invalid, since they don't have
	// signatures.
	err = validateMsgTx(
		dryRunTx.Tx, dryRunTx.PrevScripts, dryRunTx.PrevInputValues,
	)
	if err == nil {
		t.Fatalf("Expected tx to be invalid")
	}

	err = validateMsgTx(
		dryRunTx2.Tx, dryRunTx2.PrevScripts, dryRunTx2.PrevInputValues,
	)
	if err == nil {
		t.Fatalf("Expected tx to be invalid")
	}

	// Now we do a proper, non-dry run. This should add a change address
	// to the database.
	tx, err := w.txToOutputs(
		txOuts, nil, nil, 0, 1, 1000, CoinSelectionLargest, false,
		nil, alwaysAllowUtxo,
	)
	if err != nil {
		t.Fatalf("unable to author tx: %v", err)
	}
	change3 := tx.Tx.TxOut[tx.ChangeIndex]

	addresses, err = w.AccountAddresses(0)
	if err != nil {
		t.Fatalf("unable to get addresses: %v", err)
	}

	if len(addresses) != 2 {
		t.Fatalf("expected 2 addresses, found %v", len(addresses))
	}

	err = validateMsgTx(tx.Tx, tx.PrevScripts, tx.PrevInputValues)
	if err != nil {
		t.Fatalf("Expected tx to be valid: %v", err)
	}

	// Finally, we check that all the transaction were using the same
	// change address.
	if !bytes.Equal(change.PkScript, change2.PkScript) {
		t.Fatalf("first dry-run using different change address " +
			"than second")
	}
	if !bytes.Equal(change2.PkScript, change3.PkScript) {
		t.Fatalf("dry-run using different change address " +
			"than wet run")
	}
}

// addUtxo add the given transaction to the wallet's database marked as a
// confirmed UTXO .
func addUtxo(t *testing.T, w *Wallet, incomingTx *wire.MsgTx) {
	var b bytes.Buffer
	if err := incomingTx.Serialize(&b); err != nil {
		t.Fatalf("unable to serialize tx: %v", err)
	}
	txBytes := b.Bytes()

	rec, err := wtxmgr.NewTxRecord(txBytes, time.Now())
	if err != nil {
		t.Fatalf("unable to create tx record: %v", err)
	}

	// The block meta will be inserted to tell the wallet this is a
	// confirmed transaction.
	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   *testBlockHash,
			Height: testBlockHeight,
		},
		Time: time.Unix(1387737310, 0),
	}

	if err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		err = w.txStore.InsertTx(ns, rec, block)
		if err != nil {
			return err
		}
		// Add all tx outputs as credits.
		for i := 0; i < len(incomingTx.TxOut); i++ {
			err = w.txStore.AddCredit(
				ns, rec, block, uint32(i), false,
			)
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("failed inserting tx: %v", err)
	}
}

// addTxAndCredit adds the given transaction to the wallet's database marked as
// a confirmed UTXO specified by the creditIndex.
func addTxAndCredit(t *testing.T, w *Wallet, tx *wire.MsgTx,
	creditIndex uint32) {

	var b bytes.Buffer
	require.NoError(t, tx.Serialize(&b), "unable to serialize tx")

	txBytes := b.Bytes()

	rec, err := wtxmgr.NewTxRecord(txBytes, time.Now())
	require.NoError(t, err)

	// The block meta will be inserted to tell the wallet this is a
	// confirmed transaction.
	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   *testBlockHash,
			Height: testBlockHeight,
		},
		Time: time.Unix(1387737310, 0),
	}

	err = walletdb.Update(w.db, func(dbTx walletdb.ReadWriteTx) error {
		ns := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)

		err = w.txStore.InsertTx(ns, rec, block)
		if err != nil {
			return err
		}

		// Add the specified output as credit.
		err = w.txStore.AddCredit(ns, rec, block, creditIndex, false)
		if err != nil {
			return err
		}

		return nil
	})
	require.NoError(t, err, "failed inserting tx")
}

// TestInputYield verifies the functioning of the inputYieldsPositively.
func TestInputYield(t *testing.T) {
	t.Parallel()

	addr, _ := address.DecodeAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", &chaincfg.MainNetParams)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	credit := &wire.TxOut{
		Value:    1000,
		PkScript: pkScript,
	}

	// At 10 sat/b this input is yielding positively.
	require.True(t, inputYieldsPositively(credit, 10000))

	// At 20 sat/b this input is yielding negatively.
	require.False(t, inputYieldsPositively(credit, 20000))
}

// TestTxToOutputsRandom tests random coin selection.
func TestTxToOutputsRandom(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

	// Create an address we can use to send some coins to.
	keyScope := waddrmgr.KeyScopeBIP0049Plus
	addr, err := w.CurrentAddress(0, keyScope)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	p2shAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to p2sh: %v", err)
	}

	// Add a set of utxos to the wallet.
	incomingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{},
		},
		TxOut: []*wire.TxOut{},
	}
	for amt := int64(5000); amt <= 125000; amt += 10000 {
		incomingTx.AddTxOut(wire.NewTxOut(amt, p2shAddr))
	}

	addUtxo(t, w, incomingTx)

	// Now tell the wallet to create a transaction paying to the specified
	// outputs.
	txOuts := []*wire.TxOut{
		{
			PkScript: p2shAddr,
			Value:    50000,
		},
		{
			PkScript: p2shAddr,
			Value:    100000,
		},
	}

	const (
		feeSatPerKb   = 100000
		maxIterations = 100
	)

	createTx := func() *txauthor.AuthoredTx {
		tx, err := w.txToOutputs(
			txOuts, nil, nil, 0, 1, feeSatPerKb,
			CoinSelectionRandom, true, nil, alwaysAllowUtxo,
		)
		require.NoError(t, err)
		return tx
	}

	firstTx := createTx()
	var isRandom bool
	for iteration := 0; iteration < maxIterations; iteration++ {
		tx := createTx()

		// Check to see if we are getting a total input value.
		// We consider this proof that the randomization works.
		if tx.TotalInput != firstTx.TotalInput {
			isRandom = true
		}

		// At the used fee rate of 100 sat/b, the 5000 sat input is
		// negatively yielding. We don't expect it to ever be selected.
		for _, inputValue := range tx.PrevInputValues {
			require.NotEqual(t, inputValue, btcutil.Amount(5000))
		}
	}

	require.True(t, isRandom)
}

// TestCreateSimpleCustomChange tests that it's possible to let the
// CreateSimpleTx use all coins for coin selection, but specify a custom scope
// that isn't the current default scope.
func TestCreateSimpleCustomChange(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

	// First, we'll make a P2TR and a P2WKH address to send some coins to
	// (two different coin scopes).
	p2wkhAddr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)

	p2trAddr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0086)
	require.NoError(t, err)

	// We'll now make a transaction that'll send coins to both outputs,
	// then "credit" the wallet for that send.
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)
	p2trScript, err := txscript.PayToAddrScript(p2trAddr)
	require.NoError(t, err)

	const testAmt = 1_000_000

	incomingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{},
		},
		TxOut: []*wire.TxOut{
			wire.NewTxOut(testAmt, p2wkhScript),
			wire.NewTxOut(testAmt, p2trScript),
		},
	}
	addUtxo(t, w, incomingTx)

	// With the amounts credited to the wallet, we'll now do a dry run coin
	// selection w/o any default args.
	targetTxOut := &wire.TxOut{
		Value:    1_500_000,
		PkScript: p2trScript,
	}
	tx1, err := w.txToOutputs(
		[]*wire.TxOut{targetTxOut}, nil, nil, 0, 1, 1000,
		CoinSelectionLargest, true, nil, alwaysAllowUtxo,
	)
	require.NoError(t, err)

	// We expect that all inputs were used and also the change output is a
	// taproot output (the current default).
	require.Len(t, tx1.Tx.TxIn, 2)
	require.Len(t, tx1.Tx.TxOut, 2)
	for _, txOut := range tx1.Tx.TxOut {
		scriptType, _, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, w.chainParams,
		)
		require.NoError(t, err)

		require.Equal(t, scriptType, txscript.WitnessV1TaprootTy)
	}

	// Next, we'll do another dry run, but this time, specify a custom
	// change key scope. We'll also require that only inputs of P2TR are used.
	targetTxOut = &wire.TxOut{
		Value:    500_000,
		PkScript: p2trScript,
	}
	tx2, err := w.txToOutputs(
		[]*wire.TxOut{targetTxOut}, &waddrmgr.KeyScopeBIP0086,
		&waddrmgr.KeyScopeBIP0084, 0, 1, 1000, CoinSelectionLargest,
		true, nil, alwaysAllowUtxo,
	)
	require.NoError(t, err)

	// The resulting transaction should spend a single input, and use P2WKH
	// as the output script.
	require.Len(t, tx2.Tx.TxIn, 1)
	require.Len(t, tx2.Tx.TxOut, 2)
	for i, txOut := range tx2.Tx.TxOut {
		if i != tx2.ChangeIndex {
			continue
		}

		scriptType, _, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, w.chainParams,
		)
		require.NoError(t, err)

		require.Equal(t, scriptType, txscript.WitnessV0PubKeyHashTy)
	}
}

// TestSelectUtxosTxoToOutpoint tests that it is possible to use passed
// selected utxos to craft a transaction in `txToOutpoint`.
func TestSelectUtxosTxoToOutpoint(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

	// First, we'll make a P2TR and a P2WKH address to send some coins to.
	p2wkhAddr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)

	p2trAddr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0086)
	require.NoError(t, err)

	// We'll now make a transaction that'll send coins to both outputs,
	// then "credit" the wallet for that send.
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	p2trScript, err := txscript.PayToAddrScript(p2trAddr)
	require.NoError(t, err)

	incomingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{},
		},
		TxOut: []*wire.TxOut{
			wire.NewTxOut(1_000_000, p2wkhScript),
			wire.NewTxOut(2_000_000, p2trScript),
			wire.NewTxOut(3_000_000, p2trScript),
			wire.NewTxOut(7_000_000, p2trScript),
		},
	}
	addUtxo(t, w, incomingTx)

	// We expect 4 unspent UTXOs.
	unspent, err := w.ListUnspentDeprecated(0, 80, "")
	require.NoError(t, err)
	require.Len(t, unspent, 4, "expected 4 unspent UTXOs")

	tCases := []struct {
		name        string
		selectUTXOs []wire.OutPoint
		errString   string
	}{
		{
			name: "Duplicate utxo values",
			selectUTXOs: []wire.OutPoint{
				{
					Hash:  incomingTx.TxHash(),
					Index: 1,
				},
				{
					Hash:  incomingTx.TxHash(),
					Index: 1,
				},
			},
			errString: "selected UTXOs contain duplicate values",
		},
		{
			name: "all selected UTXOs not eligible for spending",
			selectUTXOs: []wire.OutPoint{
				{
					Hash:  chainhash.Hash([32]byte{1}),
					Index: 1,
				},
				{
					Hash:  chainhash.Hash([32]byte{3}),
					Index: 1,
				},
			},
			errString: "selected outpoint not eligible for " +
				"spending",
		},
		{
			name: "some select UTXOs not eligible for spending",
			selectUTXOs: []wire.OutPoint{
				{
					Hash:  chainhash.Hash([32]byte{1}),
					Index: 1,
				},
				{
					Hash:  incomingTx.TxHash(),
					Index: 1,
				},
			},
			errString: "selected outpoint not eligible for " +
				"spending",
		},
		{
			name: "select utxo, no duplicates and all eligible " +
				"for spending",
			selectUTXOs: []wire.OutPoint{
				{
					Hash:  incomingTx.TxHash(),
					Index: 1,
				},
				{
					Hash:  incomingTx.TxHash(),
					Index: 2,
				},
			},
		},
	}

	for _, tc := range tCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test by sending 200_000.
			targetTxOut := &wire.TxOut{
				Value:    200_000,
				PkScript: p2trScript,
			}
			tx1, err := w.txToOutputs(
				[]*wire.TxOut{targetTxOut}, nil, nil, 0, 1,
				1000, CoinSelectionLargest, true,
				tc.selectUTXOs, alwaysAllowUtxo,
			)
			if tc.errString != "" {
				require.ErrorContains(t, err, tc.errString)
				require.Nil(t, tx1)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, tx1)

			// We expect all and only our select UTXOs to be input
			// in this transaction.
			require.Len(t, tx1.Tx.TxIn, len(tc.selectUTXOs))

			lookupSelectUtxos := make(map[wire.OutPoint]struct{})
			for _, utxo := range tc.selectUTXOs {
				lookupSelectUtxos[utxo] = struct{}{}
			}

			for _, tx := range tx1.Tx.TxIn {
				_, ok := lookupSelectUtxos[tx.PreviousOutPoint]
				require.True(t, ok)
			}

			// Expect two outputs, change and the actual payment to
			// the address.
			require.Len(t, tx1.Tx.TxOut, 2)
		})
	}
}

// TestComputeInputScript checks that the wallet can create the full
// witness script for a witness output.
func TestComputeInputScript(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

	testCases := []struct {
		name              string
		scope             waddrmgr.KeyScope
		expectedScriptLen int
	}{{
		name:              "BIP084 P2WKH",
		scope:             waddrmgr.KeyScopeBIP0084,
		expectedScriptLen: 0,
	}, {
		name:              "BIP049 nested P2WKH",
		scope:             waddrmgr.KeyScopeBIP0049Plus,
		expectedScriptLen: 23,
	}}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runTestCase(t, w, tc.scope, tc.expectedScriptLen)
		})
	}
}

// runTestCase verifies input script generation for one address scope.
func runTestCase(t *testing.T, w *Wallet, scope waddrmgr.KeyScope,
	scriptLen int) {

	// Create an address we can use to send some coins to.
	addr, err := w.CurrentAddress(0, scope)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	p2shAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to p2sh: %v", err)
	}

	// Add an output paying to the wallet's address to the database.
	utxOut := wire.NewTxOut(100000, p2shAddr)
	incomingTx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{utxOut},
	}
	addUtxo(t, w, incomingTx)

	// Create a transaction that spends the UTXO created above and spends to
	// the same address again.
	prevOut := wire.OutPoint{
		Hash:  incomingTx.TxHash(),
		Index: 0,
	}
	outgoingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: prevOut,
		}},
		TxOut: []*wire.TxOut{utxOut},
	}
	fetcher := txscript.NewCannedPrevOutputFetcher(
		utxOut.PkScript, utxOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(outgoingTx, fetcher)

	// Compute the input script to spend the UTXO now.
	witness, script, err := w.ComputeInputScript(
		outgoingTx, utxOut, 0, sigHashes, txscript.SigHashAll, nil,
	)
	if err != nil {
		t.Fatalf("error computing input script: %v", err)
	}
	if len(script) != scriptLen {
		t.Fatalf("unexpected script length, got %d wanted %d",
			len(script), scriptLen)
	}
	if len(witness) != 2 {
		t.Fatalf("unexpected witness stack length, got %d, wanted %d",
			len(witness), 2)
	}

	// Finally verify that the created witness is valid.
	outgoingTx.TxIn[0].Witness = witness
	outgoingTx.TxIn[0].SignatureScript = script
	err = validateMsgTx(
		outgoingTx, [][]byte{utxOut.PkScript}, []btcutil.Amount{100000},
	)
	if err != nil {
		t.Fatalf("error validating tx: %v", err)
	}
}
