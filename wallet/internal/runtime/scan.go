// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package runtime

import (
	"context"

	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
)

// ScanCommit is the result of committing a recovery scan batch through the
// coordinator.
type ScanCommit struct {
	// Tip is the wallet's synced tip after the batch.
	Tip walletstore.BlockRef

	// Replayed is true when the durable state was not changed by this call
	// because the batch had already committed and its result was served from
	// the durable journal.
	Replayed bool

	// Events are the fully materialized post-commit events the batch produced.
	// They are delivered to the notifier after the gate is released and are also
	// returned so the caller can publish them itself.
	Events []walletstore.Event
}

// RewindCommit is the result of committing a wallet rewind through the
// coordinator.
type RewindCommit struct {
	// Tip is the wallet's synced tip after the rewind.
	Tip walletstore.BlockRef

	// Replayed is true when the durable state was not changed by this call
	// because the rewind had already committed.
	Replayed bool

	// Events are the fully materialized post-commit events the rewind produced.
	Events []walletstore.Event
}

// CommitScan commits one prepared recovery scan batch following the Cache And
// Commit Protocol: the batch was prepared without the gate (chain I/O,
// derivation, and parsing all happened outside), then the whole batch commits
// under the exclusive gate and the synced tip and advanced branch indexes are
// published to the caches only after the durable commit agrees. The batch's
// expected base tip and branch indexes are the durable compare-and-swap
// guards, so a stale batch is rejected with the typed error and re-prepared.
func (c *Coordinator) CommitScan(ctx context.Context,
	req walletstore.CommitScanResultsRequest) (ScanCommit, error) {

	return runGated(
		c, ctx, walletstore.ErrStaleTip,
		// commit: apply the prepared batch durably.
		func() (ScanCommit, error) {
			res, err := c.store.CommitScanResults(ctx, req)
			if err != nil {
				return ScanCommit{}, err
			}

			return ScanCommit{
				Tip:      res.Tip,
				Replayed: res.Replayed,
				Events:   res.Events,
			}, nil
		},
		// resolve: reread the durable journal after an ambiguous commit.
		func() (ScanCommit, bool, error) {
			res, found, err := c.store.LookupScanResults(
				ctx, req.OperationID,
			)
			if err != nil || !found {
				return ScanCommit{}, found, err
			}

			return ScanCommit{
				Tip:      res.Tip,
				Replayed: res.Replayed,
				Events:   res.Events,
			}, true, nil
		},
		// reload: refresh the cached tip from durable state after a conflict.
		func() { c.reloadTip(ctx) },
		// publish: record the new tip and advanced horizons under the gate.
		func(r ScanCommit) []walletstore.Event {
			c.publishTip(r.Tip)
			c.publishScanHorizons(req.Horizons)

			return r.Events
		},
	)
}

// CommitRewind reconciles the wallet back to a target block through the
// coordinator following the Cache And Commit Protocol: it commits the rewind
// under the exclusive gate, guarded by the durable compare-and-swap against the
// expected current tip, then publishes the target tip to the cache after the
// commit agrees.
func (c *Coordinator) CommitRewind(ctx context.Context,
	req walletstore.CommitWalletRewindRequest) (RewindCommit, error) {

	return runGated(
		c, ctx, walletstore.ErrStaleTip,
		// commit: reconcile durable state to the target.
		func() (RewindCommit, error) {
			res, err := c.store.CommitWalletRewind(ctx, req)
			if err != nil {
				return RewindCommit{}, err
			}

			return RewindCommit{
				Tip:      res.Tip,
				Replayed: res.Replayed,
				Events:   res.Events,
			}, nil
		},
		// resolve: reread the durable journal after an ambiguous commit.
		func() (RewindCommit, bool, error) {
			res, found, err := c.store.LookupWalletRewind(
				ctx, req.OperationID,
			)
			if err != nil || !found {
				return RewindCommit{}, found, err
			}

			return RewindCommit{
				Tip:      res.Tip,
				Replayed: res.Replayed,
				Events:   res.Events,
			}, true, nil
		},
		// reload: refresh the cached tip from durable state after a conflict.
		func() { c.reloadTip(ctx) },
		// publish: record the target tip under the gate.
		func(r RewindCommit) []walletstore.Event {
			c.publishTip(r.Tip)

			return r.Events
		},
	)
}

// publishScanHorizons records each advanced horizon's new next index into
// the branch cache under the exclusive gate, so subsequent address allocation
// continues from the extended horizon.
func (c *Coordinator) publishScanHorizons(
	horizons []walletstore.BranchHorizon) {

	for _, horizon := range horizons {
		c.publishIndex(BranchKey{
			Scope:   horizon.Scope,
			Account: horizon.Account,
			Branch:  horizon.Branch,
		}, horizon.FinalIndex)
	}
}
