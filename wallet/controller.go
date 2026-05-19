package wallet

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

const (
	// initialBackoff is the initial delay between synchronization retry
	// attempts.
	initialBackoff = 1 * time.Second

	// maxBackoff is the maximum delay allowed between synchronization retry
	// attempts.
	maxBackoff = 5 * time.Minute

	// stableRunTime is the minimum amount of time the syncer must run
	// without error to be considered "stable", at which point the retry
	// backoff is reset to initialBackoff.
	stableRunTime = 10 * time.Minute
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

// Start starts the background processes necessary to manage the wallet.
//
// This is part of the Controller interface.
func (w *Wallet) Start(startCtx context.Context) error {
	// 1. Attempt to transition from Stopped to Starting.
	err := w.state.toStarting()
	if err != nil {
		return err
	}

	// 2. Setup background resources.
	//
	// w.lifetimeCtx governs the lifecycle of all background goroutines.
	// It is canceled when stop() is called.
	w.lifetimeCtx, w.cancel = context.WithCancel(context.Background())

	// 3. Perform runtime setup.
	//
	// We use startCtx here because these operations must complete
	// synchronously before the wallet is considered "started". If
	// startCtx is canceled, the startup sequence aborts.
	err = w.performRuntimeSetup(startCtx)
	if err != nil {
		// Cleanup resources.
		w.cancel()

		// Revert state if setup fails.
		stopErr := w.state.toStopped()
		if stopErr != nil {
			log.Warnf("Failed to revert state to stopped: %v",
				stopErr)
		}

		return err
	}

	// 4. Start background goroutines.
	w.wg.Add(1)

	go w.mainLoop()

	w.wg.Add(1)

	go func() {
		defer w.wg.Done()

		w.runSyncLoop()
	}()

	// 5. Mark the wallet as fully started.
	err = w.state.toStarted()
	if err != nil {
		return err
	}

	return nil
}

// runSyncLoop executes the main chain synchronization loop with automatic
// retries and exponential backoff. It ensures the wallet attempts to stay
// synced even if the backend connection is flaky.
func (w *Wallet) runSyncLoop() {
	backoff := initialBackoff

	for {
		startTime := time.Now()

		// Block until the syncer exits.
		err := w.sync.run(w.lifetimeCtx)

		// If the wallet is shutting down, we can exit immediately.
		if w.lifetimeCtx.Err() != nil {
			log.Info("Chain sync loop exiting due to wallet shutdown")

			return
		}

		// If the syncer exited cleanly (nil error), it generally means it was
		// requested to stop, so we shouldn't restart.
		if err == nil {
			log.Info("Chain sync loop exited normally")
			return
		}

		log.Errorf("Chain sync loop exited with error: %v", err)

		var shouldContinue bool

		backoff, shouldContinue = w.waitForBackoff(
			startTime, backoff, time.After,
		)
		if !shouldContinue {
			return
		}
	}
}

// waitForBackoff handles the delay between synchronization retry attempts. It
// resets the backoff if the previous run was stable, waits for the calculated
// delay, and then returns the updated backoff duration for the next attempt.
// It returns false if the wallet is shutting down.
func (w *Wallet) waitForBackoff(startTime time.Time, backoff time.Duration,
	timerFn func(time.Duration) <-chan time.Time) (time.Duration, bool) {

	// If the syncer ran for a significant amount of time, we consider it a
	// "stable" run and reset the backoff.
	if time.Since(startTime) > stableRunTime {
		backoff = initialBackoff
	}

	log.Infof("Restarting sync loop in %v...", backoff)

	// Wait for the backoff period or a shutdown signal.
	select {
	case <-timerFn(backoff):
		// Increase backoff for the next attempt, capping it.
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}

		return backoff, true

	case <-w.lifetimeCtx.Done():
		log.Debug("Backoff interrupted by wallet shutdown")

		return 0, false
	}
}

// performRuntimeSetup executes the synchronous initialization tasks required
// before the wallet's main loops can start. This includes sanity checking the
// birthday block, loading accounts into memory, and cleaning up expired locks.
func (w *Wallet) performRuntimeSetup(startCtx context.Context) error {
	// Perform the birthday sanity check synchronously to ensure we are
	// connected and our status is valid before starting the main loop.
	//
	// This also initializes the birthday block cache used by the Info
	// method.
	err := w.verifyBirthday(startCtx)
	if err != nil {
		return err
	}

	// Ensure all accounts are loaded into memory so we can efficiently
	// access them during the scan loop without database lookups.
	err = w.DBGetAllAccounts(startCtx)
	if err != nil {
		return err
	}

	// Cleanup any expired output locks.
	return w.DBDeleteExpiredLockedOutputs(startCtx)
}

// Stop signals all wallet background processes to shutdown and blocks until
// they have all exited. It returns an error if the context is canceled before
// the shutdown is complete.
//
// This is part of the Controller interface.
func (w *Wallet) Stop(stopCtx context.Context) error {
	// Attempt to transition from Started to Stopping.
	err := w.state.toStopping()
	if err != nil {
		// If the wallet is not started, we can consider it stopped.
		log.Warnf("Wallet already stopped: %v", err)
		return nil
	}

	// Signal all background processes to stop.
	//
	// It is safe to call w.cancel() here because the successful transition
	// to Stopping guarantees that we were previously in the Started state,
	// which in turn guarantees that start() has completed initialization
	// of w.lifetimeCtx and w.cancel.
	//
	// Additionally, w.cancel() is idempotent, so it is safe to call even
	// if it has effectively already been called (though the state machine
	// guarantees we only reach this point once).
	w.cancel()

	// Wait for all goroutines to finish.
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-stopCtx.Done():
		return fmt.Errorf("stop request cancelled: %w", stopCtx.Err())
	}

	// Mark the wallet as stopped.
	err = w.state.toStopped()
	if err != nil {
		return err
	}

	return nil
}

// Unlock unlocks the wallet with a passphrase.
//
// This is part of the Controller interface.
func (w *Wallet) Unlock(ctx context.Context, req UnlockRequest) error {
	// Ensure the wallet is in a state that allows unlocking.
	err := w.state.canUnlock()
	if err != nil {
		return err
	}

	// Apply default timeout if none specified.
	if req.Timeout == 0 {
		req.Timeout = w.cfg.AutoLockDuration
		log.Infof("Using default auto-lock timeout of %v", req.Timeout)
	}

	r := newUnlockReq(req)

	// Submit the request.
	err = w.sendReq(ctx, r)
	if err != nil {
		return err
	}

	// Wait for the result from the mainLoop.
	return w.waitForResp(ctx, r.resp)
}

// Lock locks the wallet.
//
// This is part of the Controller interface.
func (w *Wallet) Lock(ctx context.Context) error {
	// Ensure the wallet is in a state that allows locking.
	err := w.state.canLock()
	if err != nil {
		return err
	}

	r := newLockReq()

	err = w.sendReq(ctx, r)
	if err != nil {
		return err
	}

	// Wait for the result.
	return w.waitForResp(ctx, r.resp)
}

// ChangePassphrase changes the wallet's passphrases according to the request.
//
// This is part of the Controller interface.
func (w *Wallet) ChangePassphrase(ctx context.Context,
	req ChangePassphraseRequest) error {

	// Ensure the wallet is in a state that allows changing the passphrase.
	err := w.state.canChangePassphrase()
	if err != nil {
		return err
	}

	r := newChangePassphraseReq(req)

	err = w.sendReq(ctx, r)
	if err != nil {
		return err
	}

	// Wait for the result.
	return w.waitForResp(ctx, r.resp)
}

// Info returns a comprehensive snapshot of the wallet's static configuration
// and dynamic synchronization state.
//
// This is part of the Controller interface.
func (w *Wallet) Info(_ context.Context) (*Info, error) {
	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	info := &Info{
		BirthdayBlock:    w.birthdayBlock,
		Backend:          w.cfg.Chain.BackEnd(),
		ChainParams:      w.cfg.ChainParams,
		Locked:           !w.state.isUnlocked(),
		Synced:           w.state.isSynced(),
		SyncedTo:         w.SyncedTo(),
		IsRecoveryMode:   w.state.isRecoveryMode(),
		RecoveryProgress: 0,
	}

	return info, nil
}

// Resync rewinds the wallet's synchronization state to a specific block
// height.
//
// This is part of the Controller interface.
func (w *Wallet) Resync(ctx context.Context, startHeight uint32) error {
	return w.submitRescanRequest(
		ctx, scanTypeRewind, startHeight, nil,
	)
}

// Rescan initiates a targeted rescan for specific accounts or addresses
// starting from the given block height. This operation scans for
// relevant transactions without rewinding the wallet's global
// synchronization state.
func (w *Wallet) Rescan(ctx context.Context, startHeight uint32,
	targets []waddrmgr.AccountScope) error {

	if len(targets) == 0 {
		return ErrNoScanTargets
	}

	return w.submitRescanRequest(
		ctx, scanTypeTargeted, startHeight, targets,
	)
}

// submitRescanRequest validates the rescan request and submits it to the
// syncer.
func (w *Wallet) submitRescanRequest(ctx context.Context, typ scanType,
	startHeight uint32, targets []waddrmgr.AccountScope) error {

	// Ensure the wallet is running and synced.
	err := w.state.validateSynced()
	if err != nil {
		return err
	}

	// BlockStamp.Height is int32, so we need to ensure the requested
	// startHeight does not exceed math.MaxInt32.
	if startHeight > math.MaxInt32 {
		return fmt.Errorf("%w: %d", ErrStartHeightTooLarge, startHeight)
	}

	startHeightInt32 := int32(startHeight)

	// Fetch the current best block to ensure we don't resync past the tip.
	_, bestHeightInt32, err := w.cfg.Chain.GetBestBlock()
	if err != nil {
		return fmt.Errorf("unable to get chain tip: %w", err)
	}

	if startHeightInt32 > bestHeightInt32 {
		return fmt.Errorf("%w: start height %d is greater than "+
			"current chain tip %d", ErrStartHeightTooHigh,
			startHeight, bestHeightInt32)
	}

	// Submit the rescan request to the syncer.
	req := &scanReq{
		typ: typ,
		startBlock: waddrmgr.BlockStamp{
			Height: startHeightInt32,
		},
		targets: targets,
	}

	return w.sync.requestScan(ctx, req)
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

// verifyBirthday performs a sanity check on the wallet's birthday block to
// ensure it is set and valid.
//
// Logical Steps:
//  1. Fetch the current birthday block from the database.
//  2. If the block is already verified, initialize the memory cache and
//     return.
//  3. If the block is missing or unverified, fetch the wallet's birthday
//     timestamp.
//  4. Use the chain backend to locate a suitable block matching the
//     birthday timestamp.
//  5. Persist the new birthday block, mark it as verified, and update the
//     wallet's sync tip to this point to ensure a clean rescan range.
//  6. Update the memory cache.
func (w *Wallet) verifyBirthday(ctx context.Context) error {
	walletInfo, err := w.store.GetWallet(ctx, w.cfg.Name)
	if err != nil {
		log.Errorf("Unable to sanity check wallet birthday block: %v", err)

		return fmt.Errorf("get wallet birthday: %w", err)
	}

	// If the birthday block has already been verified, we initialize the
	// cache and exit our sanity check to avoid redundant lookups.
	if walletInfo.BirthdayBlock != nil {
		birthdayBlock, err := db.BlockStampFromBlock(
			walletInfo.BirthdayBlock,
		)
		if err != nil {
			return fmt.Errorf("decode birthday block: %w", err)
		}

		log.Infof("Birthday block verified: height=%d, hash=%v",
			birthdayBlock.Height, birthdayBlock.Hash)
		w.birthdayBlock = birthdayBlock

		return nil
	}
	// Otherwise, we'll attempt to locate a better one now that we have
	// access to the chain.
	timestamp := walletInfo.Birthday

	newBirthdayBlock, err := locateBirthdayBlock(w.cfg.Chain, timestamp)
	if err != nil {
		log.Errorf("Unable to sanity check wallet birthday "+
			"block: %v", err)

		return fmt.Errorf("locate birthday block: %w", err)
	}

	storeBlock, err := db.BlockFromBlockStamp(*newBirthdayBlock)
	if err != nil {
		return fmt.Errorf("block from stamp: %w", err)
	}

	// Use walletInfo.ID instead of w.cfg's cached value: Manager.Load
	// currently initializes the in-memory id to zero, but the store row
	// we just read carries the authoritative wallet ID.
	err = w.store.UpdateWallet(
		ctx, db.UpdateWalletParams{
			WalletID:      walletInfo.ID,
			BirthdayBlock: storeBlock,
			SyncedTo:      storeBlock,
		},
	)
	if err != nil {
		log.Errorf("Unable to sanity check wallet birthday "+
			"block: %v", err)

		return fmt.Errorf("update birthday block: %w", err)
	}

	w.birthdayBlock = *newBirthdayBlock

	return nil
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
	if err != nil {
		log.Errorf("Could not lock wallet: %v", err)

		// If the wallet is already locked, we consider this a success
		// (idempotency) and proceed to ensure our state is consistent.
		if !waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			req.resp <- err

			return
		}
	}

	// Even if an error occurred (e.g. already locked), we ensure the
	// wallet's high-level state is synchronized to 'locked'.
	w.state.toLocked()

	// Report the result back to the caller.
	req.resp <- nil
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

// sendReq sends an operation request to the main loop or handles cancellation.
func (w *Wallet) sendReq(ctx context.Context, req any) error {
	select {
	case w.requestChan <- req:
		return nil

	case <-w.lifetimeCtx.Done():
		return ErrWalletShuttingDown

	case <-ctx.Done():
		return ctx.Err()
	}
}

// waitForResp waits for the response from an operation request or handles
// cancellation.
func (w *Wallet) waitForResp(ctx context.Context, resp <-chan error) error {
	select {
	case err := <-resp:
		return err

	case <-w.lifetimeCtx.Done():
		return ErrWalletShuttingDown

	case <-ctx.Done():
		return ctx.Err()
	}
}
