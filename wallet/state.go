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
)

// lifecycle represents the lifecycle state of the wallet's main event loop.
type lifecycle uint32

const (
	// lifecycleStopped indicates the wallet is stopped.
	lifecycleStopped lifecycle = iota

	// lifecycleStarting indicates the wallet is starting up.
	lifecycleStarting

	// lifecycleStarted indicates the wallet is started.
	lifecycleStarted

	// lifecycleStopping indicates the wallet is currently stopping.
	lifecycleStopping
)

// String returns the string representation of a lifecycle.
func (l lifecycle) String() string {
	switch l {
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
//   - Lifecycle: Stopped (awaiting Start() call).
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

// toStarting transitions the wallet state from Stopped to Starting.
// It initializes the synchronization and authentication states to their
// secure defaults. It returns an error if the wallet is already started or
// not in the Stopped state.
func (s *walletState) toStarting() error {
	// 1. Lifecycle (System State): Atomic transition from Stopped to
	// Starting.
	if !s.lifecycle.CompareAndSwap(
		uint32(lifecycleStopped), uint32(lifecycleStarting)) {

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
func (s *walletState) toStarted() {
	s.lifecycle.Store(uint32(lifecycleStarted))
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

// toStopped marks the wallet as fully stopped.
func (s *walletState) toStopped() {
	s.lifecycle.Store(uint32(lifecycleStopped))

	// Force lock the wallet on shutdown for security.
	s.unlocked.Store(false)
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

// isRunning returns true if the wallet is in any active state (not stopped
// or stopping).
func (s *walletState) isRunning() bool {
	lc := lifecycle(s.lifecycle.Load())
	return lc != lifecycleStopped && lc != lifecycleStopping
}

// canSign checks if the wallet is in a state allowing message/transaction
// signing. The wallet must be Started and Unlocked.
func (s *walletState) canSign() error {
	if !s.isStarted() {
		return fmt.Errorf("%w: wallet not started", ErrStateForbidden)
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
	if !s.isStarted() {
		return fmt.Errorf("%w: wallet not started", ErrStateForbidden)
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
	if !s.isStarted() {
		return fmt.Errorf("%w: wallet not started", ErrStateForbidden)
	}

	return nil
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
