// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"
	"fmt"
	"sync/atomic"
)

var (
	// ErrStateForbidden is returned when an operation cannot be performed
	// due to the current state of the wallet (e.g., locked, not started,
	// not synced).
	ErrStateForbidden = errors.New("operation forbidden in current state")

	// ErrWalletStopped is returned when an operation targets a Wallet that
	// has begun or completed its terminal shutdown. It is independent from
	// ErrStateForbidden so callers can distinguish terminal shutdown from a
	// generic state rejection.
	ErrWalletStopped = errors.New("wallet stopped")
)

// lifecycle represents the lifecycle state of the wallet's main event loop.
type lifecycle uint32

const (
	// lifecycleInitialized indicates the wallet has not started yet. This is
	// distinct from lifecycleStopped because a stopped Wallet is terminal.
	lifecycleInitialized lifecycle = iota

	// lifecycleStarting indicates the wallet is starting up.
	lifecycleStarting

	// lifecycleStarted indicates the wallet is started.
	lifecycleStarted

	// lifecycleStopping indicates the wallet is currently stopping.
	lifecycleStopping

	// lifecycleStopped indicates the wallet has completed terminal shutdown.
	lifecycleStopped
)

// String returns the string representation of a lifecycle.
func (l lifecycle) String() string {
	switch l {
	case lifecycleInitialized:
		return "initialized"

	case lifecycleStopped:
		return "stopped"

	case lifecycleStarting:
		return "starting"

	case lifecycleStarted:
		return "started"

	case lifecycleStopping:
		return "stopping"

	default:
		return "unknown lifecycle state"
	}
}

// walletState is a thread-safe wrapper that manages the state of the wallet
// across three orthogonal dimensions. These dimensions are independent of each
// other, allowing for a precise representation of the wallet's condition at any
// given moment.
//
// The three dimensions are:
//  1. Lifecycle (System State): Tracks whether the wallet is running, stopped,
//     or in transition. This dictates whether background processes are active.
//  2. Synchronization (Chain State): Tracks the wallet's progress in syncing
//     with the blockchain (e.g., syncing, synced, scanning). This dictates
//     data freshness and availability.
//  3. Authentication (Security State): Tracks whether the wallet is locked or
//     unlocked. This dictates the ability to perform sensitive operations like
//     signing.
type walletState struct {
	// lifecycle tracks the start/stop state of the wallet.
	lifecycle atomic.Uint32

	// syncer is the interface used to retrieve the current chain
	// synchronization status from the synchronization component.
	//
	// This approach is chosen to enforce a strict separation of concerns
	// and ownership:
	// 1. Ownership: The syncer exclusively owns and manages the writes to
	//    the sync state as it is the only component driving the sync.
	// 2. Decoupling: walletState provides a unified view of the wallet's
	//    atomic conditions without needing to know the implementation
	//    details of the synchronization subsystem.
	// 3. Consistency: By reading directly from the syncer's internal
	//    state (via this interface), we ensure that the wallet always
	//    reports a real-time, consistent view of its data freshness.
	syncer chainSyncer

	// unlocked tracks whether the wallet is unlocked (true) or locked
	// (false). The zero value is false (Locked), which is secure by
	// default.
	unlocked atomic.Bool
}

// newWalletState creates a new walletState initialized with the provided
// syncer and secure defaults:
//   - Lifecycle: Initialized (awaiting its one permitted Start call).
//   - Synchronization: BackendSyncing (until syncer is running and connected).
//   - Authentication: Locked (secure by default).
func newWalletState(syncer chainSyncer) walletState {
	return walletState{
		syncer: syncer,
	}
}

// String returns a summary of the wallet's state.
func (s *walletState) String() string {
	lc := lifecycle(s.lifecycle.Load())
	sync := s.syncState()
	unlocked := s.unlocked.Load()

	return fmt.Sprintf("status=%v, sync=%v, locked=%v", lc, sync, !unlocked)
}

// toStarting transitions the wallet state from Initialized to Starting.
// It initializes the synchronization and authentication states to their
// secure defaults. A Wallet that reached Stopped is terminal and cannot start
// again.
func (s *walletState) toStarting() error {
	if lifecycle(s.lifecycle.Load()) == lifecycleStopped {
		return ErrWalletStopped
	}

	// 1. Lifecycle (System State): Atomic transition from Initialized to
	// Starting.
	if !s.lifecycle.CompareAndSwap(
		uint32(lifecycleInitialized), uint32(lifecycleStarting)) {

		return fmt.Errorf("%w: current state is %v",
			ErrWalletAlreadyStarted, lifecycle(s.lifecycle.Load()))
	}

	// 2. Authentication (Security State): Reset to Locked. This ensures
	// the wallet always starts in a secure state.
	s.unlocked.Store(false)

	return nil
}

// toStarted marks the wallet as fully started. This should be called only
// after all resource initialization is complete.
func (s *walletState) toStarted() error {
	if !s.lifecycle.CompareAndSwap(
		uint32(lifecycleStarting), uint32(lifecycleStarted)) {

		return fmt.Errorf("%w: cannot transition to started from %v",
			ErrStateForbidden, lifecycle(s.lifecycle.Load()))
	}

	return nil
}

// toStopping transitions the wallet from Started to Stopping.
// It returns an error if the wallet is not running.
func (s *walletState) toStopping() error {
	// Atomic transition from Started to Stopping.
	if !s.lifecycle.CompareAndSwap(
		uint32(lifecycleStarted), uint32(lifecycleStopping)) {

		// If we are not Started, we cannot Stop.
		// This covers Stopped, Starting, and Stopping.
		return ErrStateForbidden
	}

	// Lock the wallet during shutdown to prevent any further signing
	// operations.
	s.unlocked.Store(false)

	return nil
}

// toStopped marks the wallet as terminally stopped. An Initialized Wallet can
// transition directly to Stopped when Stop is called before Start.
func (s *walletState) toStopped() error {
	// We allow transition from Initialized (stop before start), Stopping
	// (normal shutdown), or Starting (failure during startup).
	//
	// We use a CAS loop here to handle potential races where the state
	// might change between Load and CompareAndSwap.
	//
	// This loop is guaranteed to terminate because:
	// 1. If CAS succeeds, we break.
	// 2. If CAS fails, it means the state changed. We reload the new state.
	// 3. If the new state is not Stopping or Starting (e.g. it became
	//    Started or already Stopped), the validation check fails and we
	//    return an error.
	for {
		current := s.lifecycle.Load()
		lc := lifecycle(current)

		if lc != lifecycleInitialized && lc != lifecycleStopping &&
			lc != lifecycleStarting {

			return fmt.Errorf("%w: cannot transition to stopped "+
				"from %v", ErrStateForbidden, lc)
		}

		if s.lifecycle.CompareAndSwap(
			current, uint32(lifecycleStopped),
		) {

			break
		}
	}

	// Force lock the wallet on shutdown for security.
	s.unlocked.Store(false)

	return nil
}

// toUnlocked marks the wallet as unlocked.
func (s *walletState) toUnlocked() {
	s.unlocked.Store(true)
}

// toLocked marks the wallet as locked.
func (s *walletState) toLocked() {
	s.unlocked.Store(false)
}

// syncState returns the current synchronization state.
func (s *walletState) syncState() syncState {
	if s.syncer == nil {
		return syncStateBackendSyncing
	}

	return s.syncer.syncState()
}

// isSynced returns true if the wallet is fully synchronized with the
// blockchain.
func (s *walletState) isSynced() bool {
	return s.syncState() == syncStateSynced
}

// isUnlocked returns true if the wallet is currently unlocked.
func (s *walletState) isUnlocked() bool {
	return s.unlocked.Load()
}

// isStarted returns true if the wallet is in the Started state.
func (s *walletState) isStarted() bool {
	return lifecycle(s.lifecycle.Load()) == lifecycleStarted
}

// isRunning returns true while the wallet is starting or started.
func (s *walletState) isRunning() bool {
	lc := lifecycle(s.lifecycle.Load())

	return lc == lifecycleStarting || lc == lifecycleStarted
}

// canSign checks if the wallet is in a state allowing message/transaction
// signing. The wallet must be Started and Unlocked.
func (s *walletState) canSign() error {
	err := s.validateStarted()
	if err != nil {
		return err
	}

	if !s.isUnlocked() {
		return fmt.Errorf("%w: wallet locked", ErrStateForbidden)
	}

	return nil
}

// validateSynced checks if the wallet is running and fully synchronized.
// It returns an error if the wallet is not started or if it is currently
// syncing/rescanning.
func (s *walletState) validateSynced() error {
	err := s.validateStarted()
	if err != nil {
		return err
	}

	// TODO(yy): Should we allow creating txs while syncing?
	// Currently we enforce sync to ensure accurate coin selection.
	sync := s.syncState()
	if sync != syncStateSynced {
		return fmt.Errorf("%w: wallet is currently %s",
			ErrStateForbidden, sync)
	}

	return nil
}

// validateStarted checks if the wallet is currently running.
func (s *walletState) validateStarted() error {
	switch lifecycle(s.lifecycle.Load()) {
	case lifecycleStarted:
		return nil

	case lifecycleStopping, lifecycleStopped:
		return ErrWalletStopped

	case lifecycleInitialized, lifecycleStarting:
		return fmt.Errorf("%w: wallet not started", ErrStateForbidden)

	default:
		return fmt.Errorf("%w: unknown wallet lifecycle",
			ErrStateForbidden)
	}
}

// canUnlock checks if the wallet is in a state that allows unlocking.
func (s *walletState) canUnlock() error {
	return s.validateStarted()
}

// canLock checks if the wallet is in a state that allows locking.
func (s *walletState) canLock() error {
	return s.validateStarted()
}

// canChangePassphrase checks if the wallet is in a state that allows changing
// the passphrase.
func (s *walletState) canChangePassphrase() error {
	return s.validateStarted()
}

// isRecoveryMode returns true if the wallet is currently syncing or rescanning.
func (s *walletState) isRecoveryMode() bool {
	sync := s.syncState()
	return sync == syncStateSyncing || sync == syncStateRescanning
}
