//nolint:unused,revive // TODO(yy): remove it once implemented
package wallet

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// syncState represents the synchronization status of the wallet with the
// blockchain.
type syncState uint32

const (
	// syncStateBackendSyncing indicates the wallet is waiting for the
	// chain backend to finish syncing.
	syncStateBackendSyncing syncState = iota

	// syncStateSyncing indicates the wallet is running but catching up to
	// the chain tip (or rewinding).
	syncStateSyncing

	// syncStateSynced indicates the wallet is running and synced to the
	// chain tip.
	syncStateSynced

	// syncStateRescanning indicates the wallet is running a historical
	// scan for specific user-provided targets, such as accounts or
	// addresses, without rewinding the global synchronization state.
	syncStateRescanning
)

// String returns the string representation of a syncState.
func (s syncState) String() string {
	switch s {
	case syncStateBackendSyncing:
		return "backend-syncing"

	case syncStateSyncing:
		return "syncing"

	case syncStateSynced:
		return "synced"

	case syncStateRescanning:
		return "rescanning"

	default:
		return "unknown sync state"
	}
}

// scanType represents the type of rescan being requested.
type scanType uint8

const (
	// scanTypeRewind represents a full rescan which rewinds the wallet's
	// state to a specific point and scans forward.
	scanTypeRewind scanType = iota

	// scanTypeTargeted represents a targeted rescan for specific addresses
	// or accounts without altering the global sync state.
	scanTypeTargeted
)

// scanReq is an internal request to perform a rescan.
type scanReq struct {
	// typ specifies the type of rescan to perform.
	typ scanType

	// startBlock specifies the block height and hash to start the rescan
	// from.
	startBlock waddrmgr.BlockStamp

	// targets specifies the accounts to scan for. This is only used for
	// targeted rescans.
	targets []waddrmgr.AccountScope
}

// chainSyncer is a private interface that abstracts the chain synchronization
// logic, allowing it to be mocked for testing the wallet and controller.
type chainSyncer interface {
	// run executes the main synchronization loop.
	run(ctx context.Context) error

	// requestScan submits a rescan job to the syncer.
	requestScan(ctx context.Context, req *scanReq) error

	// syncState returns the current synchronization state.
	syncState() syncState
}

// syncer is a stateless blocking worker responsible for synchronizing the
// wallet with the blockchain. It operates within the lifecycle provided by the
// caller via context and manages the chain loop, scanning, and reorg handling.
type syncer struct {
	// cfg holds the configuration parameters for the syncer.
	cfg Config

	// addrStore is the address and key manager.
	addrStore waddrmgr.AddrStore

	// txStore is the transaction manager.
	txStore wtxmgr.TxStore

	// state tracks the chain synchronization status.
	state atomic.Uint32

	// scanReqChan is the internal mailbox used to receive scan requests
	// from the controller. It is buffered to ensure that submitting a
	// request does not unnecessarily block the calling goroutine.
	scanReqChan chan *scanReq

	// publisher is the component responsible for broadcasting transactions
	// to the network. It is primarily used during the maintenance phase to
	// ensure unmined transactions remain in the mempool.
	publisher TxPublisher
}

// newSyncer creates a new syncer instance.
func newSyncer(cfg Config, addrStore waddrmgr.AddrStore,
	txStore wtxmgr.TxStore, publisher TxPublisher) *syncer {

	return &syncer{
		cfg:         cfg,
		addrStore:   addrStore,
		txStore:     txStore,
		scanReqChan: make(chan *scanReq, 1),
		publisher:   publisher,
	}
}

// syncState returns the current synchronization state of the wallet.
func (s *syncer) syncState() syncState {
	return syncState(s.state.Load())
}

// isRecoveryMode returns true if the wallet is currently syncing or
// rescanning.
func (s *syncer) isRecoveryMode() bool {
	status := s.syncState()
	return status == syncStateSyncing || status == syncStateRescanning
}

// run executes the main synchronization loop.
func (s *syncer) run(ctx context.Context) error {
	return nil
}

// requestScan submits a rescan job to the syncer.
func (s *syncer) requestScan(ctx context.Context, req *scanReq) error {
	select {
	case s.scanReqChan <- req:
		return nil

	case <-ctx.Done():
		return fmt.Errorf("context done: %w", ctx.Err())
	}
}
