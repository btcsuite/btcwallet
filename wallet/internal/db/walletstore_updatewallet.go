package db

import (
	"context"
	"fmt"
)

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
