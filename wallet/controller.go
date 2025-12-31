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
