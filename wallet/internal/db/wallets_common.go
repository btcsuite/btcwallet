package db

import (
	"context"
	"fmt"
	"time"
)

// Validate checks wallet creation parameters for store-level invariants.
// Watch-only wallets may keep the script crypto key so they can still encrypt
// imported scripts, but they must not include private wallet secret material.
func (p *CreateWalletParams) Validate() error {
	if !p.IsWatchOnly {
		return nil
	}

	if len(p.MasterKeyPrivParams) == 0 &&
		len(p.EncryptedCryptoPrivKey) == 0 &&
		len(p.EncryptedMasterPrivKey) == 0 {

		return nil
	}

	return fmt.Errorf("watch-only wallet %q private secrets: %w", p.Name,
		ErrWatchOnlyViolation)
}

// Validate checks wallet secret update parameters for store-level invariants.
// Watch-only wallets may keep the script crypto key so they can still encrypt
// imported scripts, but they must not include private wallet secret material.
func (p *UpdateWalletSecretsParams) Validate(walletIsWatchOnly bool) error {
	if !walletIsWatchOnly {
		return nil
	}

	if len(p.MasterPrivParams) == 0 &&
		len(p.EncryptedCryptoPrivKey) == 0 &&
		len(p.EncryptedMasterHdPrivKey) == 0 {

		return nil
	}

	return fmt.Errorf("watch-only wallet %d private secrets: %w", p.WalletID,
		ErrWatchOnlyViolation)
}

// CreateWalletOps is the backend adapter the shared CreateWallet workflow
// uses after the backend has already validated the public request.
//
// The shared creation algorithm is intentionally ordered:
//   - insert the wallet row first to allocate the stable wallet ID
//   - insert wallet secrets second using that allocated ID
//   - insert wallet sync state third using the same ID
//   - fetch the created wallet info last using backend-local row conversion
//
// The adapter methods map directly to those transactional stages so the shared
// helper owns the sequencing while each backend keeps sqlc binding shapes,
// nullable handling, and final wallet-row conversion local.
type CreateWalletOps interface {
	// CreateWallet inserts the wallet row and returns its allocated ID.
	CreateWallet(ctx context.Context, params CreateWalletParams) (int64, error)

	// InsertWalletSecrets inserts the wallet secret row for the allocated
	// wallet ID.
	InsertWalletSecrets(ctx context.Context, walletID int64,
		params CreateWalletParams) error

	// InsertWalletSyncState inserts the initial sync-state row for the
	// allocated wallet ID.
	InsertWalletSyncState(ctx context.Context, walletID int64,
		birthday time.Time) error

	// GetWalletByID fetches and normalizes the created wallet row using
	// backend-local query and conversion logic.
	GetWalletByID(ctx context.Context, walletID int64) (*WalletInfo, error)
}

// CreateWalletWithOps runs the backend-independent CreateWallet write workflow
// once the caller has already validated params and opened a backend-specific
// SQL transaction.
//
// The helper owns only the ordered transactional sequencing. It does not
// validate the public request, but it does fetch the created wallet through the
// adapter after the write stages succeed.
func CreateWalletWithOps(ctx context.Context, params CreateWalletParams,
	ops CreateWalletOps) (*WalletInfo, error) {

	walletID, err := ops.CreateWallet(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("create wallet: %w", err)
	}

	err = ops.InsertWalletSecrets(ctx, walletID, params)
	if err != nil {
		return nil, fmt.Errorf("insert wallet secrets: %w", err)
	}

	err = ops.InsertWalletSyncState(ctx, walletID, params.Birthday)
	if err != nil {
		return nil, fmt.Errorf("upsert wallet sync state: %w", err)
	}

	info, err := ops.GetWalletByID(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("fetch created wallet: %w", err)
	}

	return info, nil
}

// UpdateWalletOps is the backend adapter the shared UpdateWallet workflow uses.
//
// The shared update algorithm is intentionally ordered:
//   - ensure the synced-to block first when present
//   - ensure the birthday block second when present
//   - run the backend-local sync-state update last
//
// The adapter methods map directly to those stages so the shared helper owns
// the sequencing while each backend keeps sqlc update params and row-count
// handling local.
type UpdateWalletOps interface {
	// EnsureBlock inserts the provided block if it does not already exist.
	EnsureBlock(ctx context.Context, block *Block) error

	// UpdateWalletSyncState writes the prepared backend-local sync-state
	// update.
	UpdateWalletSyncState(ctx context.Context, params UpdateWalletParams) error
}

// UpdateWalletWithOps runs the backend-independent UpdateWallet workflow once
// the caller has opened a backend-specific SQL transaction.
func UpdateWalletWithOps(ctx context.Context, params UpdateWalletParams,
	ops UpdateWalletOps) error {

	if params.SyncedTo != nil {
		err := ops.EnsureBlock(ctx, params.SyncedTo)
		if err != nil {
			return fmt.Errorf("ensure synced block: %w", err)
		}
	}

	if params.BirthdayBlock != nil {
		err := ops.EnsureBlock(ctx, params.BirthdayBlock)
		if err != nil {
			return fmt.Errorf("ensure birthday block: %w", err)
		}
	}

	err := ops.UpdateWalletSyncState(ctx, params)
	if err != nil {
		return fmt.Errorf("update wallet sync state: %w", err)
	}

	return nil
}

// UpdateWalletSecretsOps is the backend adapter the shared
// UpdateWalletSecrets workflow uses.
//
// The shared secrets-update algorithm is intentionally ordered:
//   - load the wallet watch-only state first
//   - validate the request against that mode second
//   - run the backend-local secrets update third
//
// The adapter methods map directly to those stages so the shared helper owns
// the sequencing while each backend keeps sqlc query shapes and row-count
// handling local.
type UpdateWalletSecretsOps interface {
	// WalletWatchOnly returns whether the target wallet is watch-only.
	WalletWatchOnly(ctx context.Context, walletID uint32) (bool, error)

	// UpdateWalletSecrets writes the prepared backend-local secrets update.
	UpdateWalletSecrets(ctx context.Context,
		params UpdateWalletSecretsParams) error
}

// UpdateWalletSecretsWithOps runs the backend-independent
// UpdateWalletSecrets workflow once the caller has opened a backend-specific
// SQL transaction.
func UpdateWalletSecretsWithOps(ctx context.Context,
	params UpdateWalletSecretsParams, ops UpdateWalletSecretsOps) error {

	watchOnly, err := ops.WalletWatchOnly(ctx, params.WalletID)
	if err != nil {
		return fmt.Errorf("get wallet: %w", err)
	}

	err = params.Validate(watchOnly)
	if err != nil {
		return err
	}

	err = ops.UpdateWalletSecrets(ctx, params)
	if err != nil {
		return fmt.Errorf("update wallet secrets: %w", err)
	}

	return nil
}

// NextListWalletsQuery returns a query with its pagination cursor advanced to
// the provided value.
func NextListWalletsQuery(q ListWalletsQuery, cursor uint32) ListWalletsQuery {
	q.Page.After = &cursor

	return q
}
