package wallet

import (
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// newRecoveryTestState creates the recovery state and scoped-manager map used
// by a production recovery run, including state already persisted in walletdb.
func newRecoveryTestState(t *testing.T, w *Wallet) (*RecoveryManager,
	map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager) {

	t.Helper()

	recoveryMgr := NewRecoveryManager(
		w.recoveryWindow, recoveryBatchSize, w.chainParams,
	)

	scopedMgrs := make(
		map[waddrmgr.KeyScope]*waddrmgr.ScopedKeyManager,
	)
	for _, scopedMgr := range w.Manager.ActiveScopedKeyManagers() {
		scopedMgrs[scopedMgr.Scope()] = scopedMgr
	}

	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txMgrNS := tx.ReadBucket(wtxmgrNamespaceKey)

		credits, err := w.TxStore.UnspentOutputs(txMgrNS)
		if err != nil {
			return err
		}

		addrMgrNS := tx.ReadBucket(waddrmgrNamespaceKey)

		return recoveryMgr.Resurrect(addrMgrNS, scopedMgrs, credits)
	})
	require.NoError(t, err)

	return recoveryMgr, scopedMgrs
}

// newRecoveryTestBlock returns matching filter and sync records for a block.
func newRecoveryTestBlock(height int32) (wtxmgr.BlockMeta,
	*waddrmgr.BlockStamp) {

	var hash chainhash.Hash

	hash[0] = byte(height)

	timestamp := time.Unix(int64(height), 0)
	blockMeta := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   hash,
			Height: height,
		},
		Time: timestamp,
	}
	blockStamp := &waddrmgr.BlockStamp{
		Hash:      hash,
		Height:    height,
		Timestamp: timestamp,
	}

	return blockMeta, blockStamp
}

// newRecoveryTestResponse builds a filter response for the highest external
// address in a scope and a transaction that pays to that address.
//
//nolint:ireturn
func newRecoveryTestResponse(req *chain.FilterBlocksRequest,
	scope waddrmgr.KeyScope, value int64) (*chain.FilterBlocksResponse,
	address.Address, uint32, *wire.MsgTx, error) {

	var (
		recoveredAddr  address.Address
		recoveredIndex uint32
	)
	for scopedIndex, candidate := range req.ExternalAddrs {
		if scopedIndex.Scope != scope {
			continue
		}

		if recoveredAddr != nil && scopedIndex.Index < recoveredIndex {
			continue
		}

		recoveredAddr = candidate
		recoveredIndex = scopedIndex.Index
	}

	if recoveredAddr == nil {
		return nil, nil, 0, nil, errors.New("missing recovery address")
	}

	pkScript, err := txscript.PayToAddrScript(recoveredAddr)
	if err != nil {
		return nil, nil, 0, nil, err
	}

	relevantTx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{wire.NewTxOut(value, pkScript)},
	}
	response := &chain.FilterBlocksResponse{
		BatchIndex: 0,
		BlockMeta:  req.Blocks[0],
		FoundExternalAddrs: map[waddrmgr.KeyScope]map[uint32]struct{}{
			scope: {recoveredIndex: {}},
		},
		RelevantTxns: []*wire.MsgTx{relevantTx},
	}

	return response, recoveredAddr, recoveredIndex, relevantTx, nil
}

// TestRecoveryFilterBlocksDoesNotHoldWriter verifies that a chain backend can
// obtain a wallet database write transaction while FilterBlocks is running.
// A network-backed backend may block for an unbounded amount of time, so
// holding the writer across this call would also block every unrelated wallet
// operation that needs to persist state.
func TestRecoveryFilterBlocksDoesNotHoldWriter(t *testing.T) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	recoveryMgr, scopedMgrs := newRecoveryTestState(t, w)

	height := w.Manager.SyncedTo().Height + 1
	blockMeta, blockStamp := newRecoveryTestBlock(height)
	batch := []wtxmgr.BlockMeta{blockMeta}
	blocks := []*waddrmgr.BlockStamp{blockStamp}

	errWriterHeld := errors.New("wallet writer held during FilterBlocks")
	filterCalls := 0
	chainClient := &mockChainClient{}
	chainClient.filterBlocksFunc = func(*chain.FilterBlocksRequest) (
		*chain.FilterBlocksResponse, error) {

		filterCalls++

		writerDone := make(chan error, 1)
		go func() {
			writerDone <- walletdb.Update(
				w.db, func(walletdb.ReadWriteTx) error {
					return nil
				},
			)
		}()

		select {
		case err := <-writerDone:
			return nil, err

		case <-time.After(time.Second):
			return nil, errWriterHeld
		}
	}

	err := w.recoverBatch(
		chainClient, batch, blocks, recoveryMgr.State(), scopedMgrs,
	)
	require.NoError(t, err)
	require.Equal(t, 1, filterCalls)
}

// TestRecoveryFilterBlocksSerializesAddressCreation verifies that a recovery
// request's address horizon stays fixed until the batch is committed. Address
// creation may continue as soon as the backend call returns.
func TestRecoveryFilterBlocksSerializesAddressCreation(t *testing.T) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	recoveryMgr, scopedMgrs := newRecoveryTestState(t, w)

	height := w.Manager.SyncedTo().Height + 1
	blockMeta, blockStamp := newRecoveryTestBlock(height)
	batch := []wtxmgr.BlockMeta{blockMeta}
	blocks := []*waddrmgr.BlockStamp{blockStamp}

	errAddressNotSerialized := errors.New(
		"address creation completed before recovery commit",
	)
	addressDone := make(chan error, 1)
	filterCalls := 0
	expectedSync := *blockStamp

	chainClient := &mockChainClient{}
	chainClient.notifyReceivedFunc = func([]address.Address) error {
		if w.Manager.SyncedTo() != expectedSync {
			return errAddressNotSerialized
		}

		return nil
	}
	chainClient.filterBlocksFunc = func(*chain.FilterBlocksRequest) (
		*chain.FilterBlocksResponse, error) {

		filterCalls++

		addressGoroutineStarted := make(chan struct{})
		go func() {
			close(addressGoroutineStarted)

			_, err := w.NewAddress(
				waddrmgr.DefaultAccountNum,
				waddrmgr.KeyScopeBIP0084,
			)
			addressDone <- err
		}()

		<-addressGoroutineStarted

		select {
		case err := <-addressDone:
			if err != nil {
				return nil, err
			}

			return nil, errAddressNotSerialized

		case <-time.After(100 * time.Millisecond):
		}

		return nil, nil //nolint:nilnil
	}
	w.chainClient = chainClient

	err := w.recoverBatch(
		chainClient, batch, blocks, recoveryMgr.State(), scopedMgrs,
	)
	require.NoError(t, err)
	require.Equal(t, 1, filterCalls)
	require.Equal(t, expectedSync, w.Manager.SyncedTo())

	select {
	case err := <-addressDone:
		require.NoError(t, err)

	case <-time.After(time.Second):
		t.Fatal("address creation remained blocked after recovery commit")
	}
}

// TestRecoveryBatchCommitsResults verifies that discoveries from multiple
// backend calls and the synced-to marker are committed together after the
// backend finishes filtering.
func TestRecoveryBatchCommitsResults(t *testing.T) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	recoveryMgr, scopedMgrs := newRecoveryTestState(t, w)

	height := w.Manager.SyncedTo().Height + 1
	firstMeta, firstStamp := newRecoveryTestBlock(height)
	secondMeta, secondStamp := newRecoveryTestBlock(height + 1)
	thirdMeta, thirdStamp := newRecoveryTestBlock(height + 2)
	batch := []wtxmgr.BlockMeta{firstMeta, secondMeta, thirdMeta}
	blocks := []*waddrmgr.BlockStamp{firstStamp, secondStamp, thirdStamp}

	scope := waddrmgr.KeyScopeBIP0084

	var (
		filterCalls      int
		recoveredAddrs   []address.Address
		recoveredIndexes []uint32
		relevantTxns     []*wire.MsgTx
	)

	chainClient := &mockChainClient{}
	chainClient.filterBlocksFunc = func(req *chain.FilterBlocksRequest) (
		*chain.FilterBlocksResponse, error) {

		filterCalls++
		if filterCalls == 3 {
			// A nil response means the backend scanned the rest of the
			// batch without another match.
			return nil, nil //nolint:nilnil
		}

		response, recoveredAddr, recoveredIndex, relevantTx, err :=
			newRecoveryTestResponse(
				req, scope, int64(1000+filterCalls),
			)
		if err != nil {
			return nil, err
		}

		recoveredAddrs = append(
			recoveredAddrs, recoveredAddr,
		)
		recoveredIndexes = append(
			recoveredIndexes, recoveredIndex,
		)
		relevantTxns = append(relevantTxns, relevantTx)

		return response, nil
	}

	err := w.recoverBatch(
		chainClient, batch, blocks, recoveryMgr.State(), scopedMgrs,
	)
	require.NoError(t, err)
	require.Equal(t, 3, filterCalls)
	require.Equal(t, *thirdStamp, w.Manager.SyncedTo())

	var (
		accountProps *waddrmgr.AccountProperties

		addressesUsed []bool
		txDetails     []*wtxmgr.TxDetails
	)

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrMgrNS := tx.ReadBucket(waddrmgrNamespaceKey)
		scopedMgr := scopedMgrs[scope]

		var err error

		accountProps, err = scopedMgr.AccountProperties(
			addrMgrNS, waddrmgr.DefaultAccountNum,
		)
		if err != nil {
			return err
		}

		for _, recoveredAddr := range recoveredAddrs {
			managedAddr, err := scopedMgr.Address(
				addrMgrNS, recoveredAddr,
			)
			if err != nil {
				return err
			}

			addressesUsed = append(
				addressesUsed, managedAddr.Used(addrMgrNS),
			)
		}

		txMgrNS := tx.ReadBucket(wtxmgrNamespaceKey)
		for _, relevantTx := range relevantTxns {
			txHash := relevantTx.TxHash()

			details, err := w.TxStore.TxDetails(txMgrNS, &txHash)
			if err != nil {
				return err
			}

			txDetails = append(txDetails, details)
		}

		return nil
	})
	require.NoError(t, err)
	require.Equal(t, recoveredIndexes[len(recoveredIndexes)-1]+1,
		accountProps.ExternalKeyCount)
	require.Equal(t, []bool{true, true}, addressesUsed)
	require.Len(t, txDetails, 2)
	require.NotNil(t, txDetails[0])
	require.NotNil(t, txDetails[1])
}

// TestRecoveryBatchFilterErrorRollsBack verifies that an error from a later
// backend request cannot leave earlier discoveries or a newer synced-to marker
// in walletdb.
func TestRecoveryBatchFilterErrorRollsBack(t *testing.T) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	recoveryMgr, scopedMgrs := newRecoveryTestState(t, w)

	initialSync := w.Manager.SyncedTo()
	firstMeta, firstStamp := newRecoveryTestBlock(initialSync.Height + 1)
	secondMeta, secondStamp := newRecoveryTestBlock(initialSync.Height + 2)
	batch := []wtxmgr.BlockMeta{firstMeta, secondMeta}
	blocks := []*waddrmgr.BlockStamp{firstStamp, secondStamp}

	scope := waddrmgr.KeyScopeBIP0084

	var (
		filterCalls  int
		relevantTx   *wire.MsgTx
		initialProps *waddrmgr.AccountProperties
	)

	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrMgrNS := tx.ReadBucket(waddrmgrNamespaceKey)

		var err error

		initialProps, err = scopedMgrs[scope].AccountProperties(
			addrMgrNS, waddrmgr.DefaultAccountNum,
		)

		return err
	})
	require.NoError(t, err)

	errLaterFilter := errors.New("later FilterBlocks call failed")
	chainClient := &mockChainClient{}
	chainClient.filterBlocksFunc = func(req *chain.FilterBlocksRequest) (
		*chain.FilterBlocksResponse, error) {

		filterCalls++
		if filterCalls > 1 {
			return nil, errLaterFilter
		}

		response, _, _, transaction, err := newRecoveryTestResponse(
			req, scope, 1000,
		)
		if err != nil {
			return nil, err
		}

		relevantTx = transaction

		return response, nil
	}

	err = w.recoverBatch(
		chainClient, batch, blocks, recoveryMgr.State(), scopedMgrs,
	)
	require.ErrorIs(t, err, errLaterFilter)
	require.Equal(t, 2, filterCalls)
	require.Equal(t, initialSync, w.Manager.SyncedTo())

	var (
		finalProps *waddrmgr.AccountProperties
		txDetails  *wtxmgr.TxDetails
	)

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrMgrNS := tx.ReadBucket(waddrmgrNamespaceKey)

		var err error

		finalProps, err = scopedMgrs[scope].AccountProperties(
			addrMgrNS, waddrmgr.DefaultAccountNum,
		)
		if err != nil {
			return err
		}

		txMgrNS := tx.ReadBucket(wtxmgrNamespaceKey)
		txHash := relevantTx.TxHash()
		txDetails, err = w.TxStore.TxDetails(txMgrNS, &txHash)

		return err
	})
	require.NoError(t, err)
	require.Equal(t, initialProps.ExternalKeyCount,
		finalProps.ExternalKeyCount)
	require.Nil(t, txDetails)
}
