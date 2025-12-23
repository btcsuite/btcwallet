package wallet

import (
	"context"
	"errors"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

var (
	// ErrWalletNotStopped is returned when an attempt is made to start the
	// wallet when it is not in the stopped state.
	ErrWalletNotStopped = errors.New("wallet not in stopped state")

	// ErrWalletAlreadyStarted is returned when an attempt is made to start
	// the wallet when it is already started.
	ErrWalletAlreadyStarted = errors.New("wallet already started")

	// ErrStateChanged is returned when the wallet state changes
	// unexpectedly during an operation, such as a rescan setup.
	ErrStateChanged = errors.New("wallet state changed unexpectedly")
)

// UnlockRequest contains the parameters for unlocking the wallet.
type UnlockRequest struct {
	// Passphrase is the private passphrase to unlock the wallet.
	Passphrase []byte

	// Timeout defines the duration after which the wallet should
	// automatically lock. If zero, it defaults to the wallet's configured
	// AutoLockDuration. If negative, the wallet remains unlocked until
	// explicitly locked or stopped.
	Timeout time.Duration
}

// Info provides a comprehensive snapshot of the wallet's static configuration
// and dynamic synchronization state.
type Info struct {
	// BirthdayBlock is the block from which the wallet started scanning.
	BirthdayBlock waddrmgr.BlockStamp

	// Backend is the name of the chain backend (e.g. "neutrino",
	// "bitcoind").
	Backend string

	// ChainParams are the parameters of the chain the wallet is connected
	// to.
	ChainParams *chaincfg.Params

	// Locked indicates if the wallet is currently locked.
	Locked bool

	// Synced indicates if the wallet is synced to the chain tip.
	Synced bool

	// SyncedTo is the block to which the wallet is currently synced.
	SyncedTo waddrmgr.BlockStamp

	// IsRecoveryMode indicates if the wallet is currently in recovery
	// mode.
	IsRecoveryMode bool

	// RecoveryProgress is the progress of the recovery (0.0 - 1.0).
	RecoveryProgress float64
}

// ChangePassphraseRequest contains the parameters for changing wallet
// passphrases. It supports changing the public passphrase, the private
// passphrase, or both simultaneously.
type ChangePassphraseRequest struct {
	// ChangePublic indicates whether the public passphrase should be
	// changed.
	ChangePublic bool
	PublicOld    []byte
	PublicNew    []byte

	// ChangePrivate indicates whether the private passphrase should be
	// changed.
	ChangePrivate bool
	PrivateOld    []byte
	PrivateNew    []byte
}

// Controller provides an interface for managing the wallet's lifecycle and
// state.
type Controller interface {
	// Unlock unlocks the wallet with a passphrase. The wallet will remain
	// unlocked until explicitly locked or the provided lock duration
	// expires.
	Unlock(ctx context.Context, req UnlockRequest) error

	// Lock locks the wallet, clearing any cached private key material.
	Lock(ctx context.Context) error

	// ChangePassphrase changes the wallet's passphrases according to the
	// request.
	ChangePassphrase(ctx context.Context, req ChangePassphraseRequest) error

	// Info returns a comprehensive snapshot of the wallet's static
	// configuration and dynamic synchronization state.
	Info(ctx context.Context) (*Info, error)

	// Start starts the background processes necessary to manage the wallet.
	// It returns an error if the wallet is already started.
	Start(ctx context.Context) error

	// Stop signals all wallet background processes to shutdown and blocks
	// until they have all exited. It returns an error if the context is
	// canceled before the shutdown is complete.
	Stop(ctx context.Context) error

	// Resync rewinds the wallet's synchronization state to a specific
	// block height.
	Resync(ctx context.Context, startHeight uint32) error

	// Rescan initiates a targeted rescan for specific accounts or addresses
	// starting from the given block height. This operation scans for
	// relevant transactions without rewinding the wallet's global
	// synchronization state.
	Rescan(ctx context.Context, startHeight uint32,
		targets []waddrmgr.AccountScope) error
}

// mainLoop is the central event loop for the wallet, responsible for
// coordinating and serializing all lifecycle and authentication requests. It
// manages the transition between locked and unlocked states and handles the
// automatic locking of the wallet after a specified duration.
func (w *Wallet) mainLoop() {
	defer w.wg.Done()

	for {
		select {
		case req := <-w.requestChan:
			// Process incoming serialized requests.
			switch r := req.(type) {
			// Perform the unlock.
			case unlockReq:
				w.handleUnlockReq(r)

			// Perform an explicit lock and stop the timer.
			case lockReq:
				w.handleLockReq(r)

			// Rotate wallet passphrases.
			case changePassphraseReq:
				w.handleChangePassphraseReq(r)

			default:
				log.Errorf("Wallet received unknown request "+
					"type: %T", req)
			}

		// The auto-lock timer has expired. We trigger a lock with a
		// dummy response channel to avoid nil checks in the handler.
		case <-w.lockTimer.C:
			log.Infof("Auto-lock timeout fired, locking wallet")
			w.handleLockReq(newLockReq())

		// The wallet is shutting down. We exit the main loop.
		case <-w.lifetimeCtx.Done():
			w.lockTimer.Stop()

			return
		}
	}
}

// resultChan is a generic channel for returning errors to callers.
type resultChan chan error

// unlockReq requests the wallet to be unlocked.
type unlockReq struct {
	req  UnlockRequest
	resp resultChan
}

// lockReq requests the wallet to be locked.
type lockReq struct {
	resp resultChan
}

// changePassphraseReq requests a change of the wallet's passphrases.
type changePassphraseReq struct {
	req  ChangePassphraseRequest
	resp resultChan
}

// newUnlockReq creates a new unlock request with a buffered response channel.
// We use this constructor to ensure that the response channel is always
// correctly initialized and buffered, preventing the main loop from blocking
// when reporting the result.
func newUnlockReq(req UnlockRequest) unlockReq {
	return unlockReq{
		req:  req,
		resp: make(resultChan, 1),
	}
}

// newLockReq creates a new lock request with a buffered response channel.
func newLockReq() lockReq {
	return lockReq{
		resp: make(resultChan, 1),
	}
}

// newChangePassphraseReq creates a new change passphrase request with a
// buffered response channel.
func newChangePassphraseReq(req ChangePassphraseRequest) changePassphraseReq {
	return changePassphraseReq{
		req:  req,
		resp: make(resultChan, 1),
	}
}

// handleUnlockReq processes an incoming request to unlock the wallet. It
// authenticates the provided passphrase against the database and, on success,
// transitions the wallet to the unlocked state.
func (w *Wallet) handleUnlockReq(req unlockReq) {
	// First, validate that the wallet is in a state that allows unlocking.
	err := w.state.canUnlock()
	if err != nil {
		req.resp <- err
		return
	}

	// Attempt to unlock the underlying address manager.
	err = w.DBUnlock(w.lifetimeCtx, req.req.Passphrase)
	if err != nil {
		req.resp <- err
		return
	}

	// On success, update the atomic wallet state to reflect that we are
	// now unlocked.
	w.state.toUnlocked()

	// Handle auto-lock timer. If a timeout is specified, we reset the
	// timer to fire in the future. Otherwise, we stop the timer to disable
	// auto-locking.
	duration := req.req.Timeout
	if duration > 0 {
		w.lockTimer.Reset(duration)
	} else if !w.lockTimer.Stop() {
		// If the timer has already fired, we drain its channel to
		// prevent a stale signal from being processed by the main
		// loop, which would cause an immediate, unexpected lock.
		select {
		case <-w.lockTimer.C:
		default:
		}
	}

	// Always report the result back to the caller.
	req.resp <- nil
}

// handleLockReq processes an incoming request to lock the wallet. It clears
// any cached private key material from memory and transitions the wallet to
// the locked state.
func (w *Wallet) handleLockReq(req lockReq) {
	// First, validate that the wallet is in a state that allows locking.
	err := w.state.canLock()
	if err != nil {
		req.resp <- err
		return
	}

	// Stop the auto-lock timer since the wallet is now explicitly locked.
	if !w.lockTimer.Stop() {
		// Drain the channel if the timer has already fired to ensure
		// we don't process a stale lock signal in the next iteration.
		select {
		case <-w.lockTimer.C:
		default:
		}
	}

	// Signal the address manager to lock, clearing sensitive data.
	err = w.addrStore.Lock()
	if err != nil && !waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		log.Errorf("Could not lock wallet: %v", err)
	}

	// Even if an error occurred (e.g. already locked), we ensure the
	// wallet's high-level state is synchronized to 'locked'.
	if err == nil {
		w.state.toLocked()
	}

	// Report the result back to the caller.
	req.resp <- err
}

// handleChangePassphraseReq processes a request to rotate the wallet's
// passphrases. It can change either the public passphrase, the private
// passphrase, or both in a single atomic database update.
func (w *Wallet) handleChangePassphraseReq(req changePassphraseReq) {
	// First, validate that the wallet is in a state that allows changing
	// the passphrase.
	err := w.state.canChangePassphrase()
	if err != nil {
		req.resp <- err
		return
	}

	// Delegate the cryptographic rotation to the database layer.
	err = w.DBPutPassphrase(w.lifetimeCtx, req.req)

	// Report the result back to the caller.
	req.resp <- err
}
