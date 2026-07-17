package sqlstore

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
)

// walletTipDomain names the operation-journal domain the wallet-tip advance
// records its committed operations under.
const walletTipDomain = "wallet-tip"

// factTypeWalletTip is the result-fact type whose payload carries a committed
// tip. Its payload is the canonical wallet-tip event payload, so a replay
// rebuilds the identical committed tip and event.
const factTypeWalletTip = "wallet-tip"

// walletTipRetention is how long a committed tip advance's journal row is
// retained so a late retry is still served from the journal.
const walletTipRetention = 24 * time.Hour

// SyncedTip reads the wallet's current synced block inside the runtime
// transaction. It is the snapshot-read counterpart to AdvanceSyncedTip.
func (r *RuntimeStore) SyncedTip() (walletstore.BlockRef, error) {
	state, err := r.queries.GetSyncState(r.ctx, r.walletID)
	if err != nil {
		return walletstore.BlockRef{}, fmt.Errorf("get sync state: %w", err)
	}

	return walletstore.BlockRef{
		Height:    state.SyncedTo.Height,
		Hash:      state.SyncedTo.Hash,
		Timestamp: state.SyncedTo.Timestamp,
	}, nil
}

// PutBlock records a block by its identity, leaving an existing block with the
// same header hash untouched, so competing same-height blocks coexist and no
// block is ever overwritten. It is the block-commit half of a tip advance.
func (r *RuntimeStore) PutBlock(block walletstore.BlockRef) error {
	err := r.queries.PutBlock(r.ctx, BlockRow{
		Height:    block.Height,
		Hash:      block.Hash[:],
		Timestamp: block.Timestamp.Unix(),
	})
	if err != nil {
		return fmt.Errorf("put block %d: %w", block.Height, err)
	}

	return nil
}

// AdvanceSyncedTip advances the wallet's synced block from expectedHash to
// newHash through an optimistic compare-and-swap: it succeeds only while the
// stored synced block still equals expectedHash. It returns ErrStaleTip when
// the synced block moved, so the caller rereads the tip before preparing the
// advance again. The new block must already be recorded.
func (r *RuntimeStore) AdvanceSyncedTip(expectedHash, newHash []byte) error {
	rows, err := r.queries.AdvanceWalletSyncedTo(
		r.ctx, r.walletID, expectedHash, newHash,
	)
	if err != nil {
		return fmt.Errorf("advance synced tip: %w", err)
	}

	if rows != 1 {
		return fmt.Errorf("expected synced tip %x: %w", expectedHash,
			walletstore.ErrStaleTip)
	}

	return nil
}

// CurrentSyncedTip reads a durable snapshot of the wallet's synced block in a
// read-only transaction.
func (r *runtimeStore) CurrentSyncedTip(ctx context.Context) (
	walletstore.BlockRef, error) {

	var tip walletstore.BlockRef

	err := r.store.RuntimeView(ctx, func(rt *RuntimeStore) error {
		var err error

		tip, err = rt.SyncedTip()

		return err
	}, nil)
	if err != nil {
		return walletstore.BlockRef{}, err
	}

	return tip, nil
}

// AdvanceWalletTip records the new tip block and advances the wallet's synced
// tip to it through an optimistic compare-and-swap, journaling the committed
// operation in the same transaction so the block, the tip move, and its journal
// entry become durable together. A committed operation replays from the journal
// instead of advancing the tip again.
func (r *runtimeStore) AdvanceWalletTip(ctx context.Context,
	req walletstore.AdvanceTipRequest) (walletstore.AdvanceTipResult, error) {

	// The new tip must extend the expected tip by exactly one block. This is a
	// request-shape check made before any durable work, so it never leaves a
	// partial write.
	if req.NewTip.Height != req.ExpectedTip.Height+1 {
		return walletstore.AdvanceTipResult{}, fmt.Errorf(
			"new tip height %d does not follow expected height %d: %w",
			req.NewTip.Height, req.ExpectedTip.Height,
			walletstore.ErrNonContiguousTip,
		)
	}

	var (
		out     walletstore.AdvanceTipResult
		attempt int
	)

	err := r.store.RuntimeUpdate(ctx, func(rt *RuntimeStore) error {
		var err error

		out, err = r.tipAttempt(ctx, rt, req, &attempt)

		return err
	}, nil)
	if err != nil {
		return walletstore.AdvanceTipResult{}, err
	}

	if err := afterCommit(ctx); err != nil {
		return walletstore.AdvanceTipResult{}, err
	}

	return out, nil
}

// tipAttempt runs one transaction attempt of a tip advance: it replays a
// committed operation from the journal, or applies the version guards, records
// the block, advances the tip, and journals the new tip, before applying the
// end-of-attempt failpoints.
func (r *runtimeStore) tipAttempt(ctx context.Context, rt *RuntimeStore,
	req walletstore.AdvanceTipRequest, attempt *int) (
	walletstore.AdvanceTipResult, error) {

	current := *attempt
	*attempt++

	onTxAttempt(ctx, current)

	replayed, found, err := readCommittedTip(rt, req.OperationID)
	if err != nil {
		return walletstore.AdvanceTipResult{}, err
	}

	if found {
		return replayed, nil
	}

	if err := beforeStatement(ctx); err != nil {
		return walletstore.AdvanceTipResult{}, err
	}

	result, err := commitTipAdvance(rt, req)
	if err != nil {
		return walletstore.AdvanceTipResult{}, err
	}

	return result, injectCommitFaults(ctx, current)
}

// LookupTipAdvance reads a committed tip advance from the journal by its
// operation id in a read-only transaction.
func (r *runtimeStore) LookupTipAdvance(ctx context.Context,
	operationID []byte) (walletstore.AdvanceTipResult, bool, error) {

	var (
		out   walletstore.AdvanceTipResult
		found bool
	)

	err := r.store.RuntimeView(ctx, func(rt *RuntimeStore) error {
		var err error

		out, found, err = readCommittedTip(rt, operationID)

		return err
	}, nil)
	if err != nil {
		return walletstore.AdvanceTipResult{}, false, err
	}

	return out, found, nil
}

// commitTipAdvance applies the version guards, records the new block, advances
// the synced tip through the compare-and-swap, and journals the committed tip in
// the current runtime transaction, so every change becomes durable together. A
// stale tip rolls the whole transaction back, so no version is advanced and no
// block reference is left dangling.
func commitTipAdvance(rt *RuntimeStore,
	req walletstore.AdvanceTipRequest) (walletstore.AdvanceTipResult, error) {

	if err := rt.ApplyGuards(req.Guards); err != nil {
		return walletstore.AdvanceTipResult{}, err
	}

	if err := rt.PutBlock(req.NewTip); err != nil {
		return walletstore.AdvanceTipResult{}, err
	}

	err := rt.AdvanceSyncedTip(req.ExpectedTip.Hash[:], req.NewTip.Hash[:])
	if err != nil {
		return walletstore.AdvanceTipResult{}, err
	}

	event := walletstore.WalletTipEvent(req.NewTip)
	result := walletstore.AdvanceTipResult{
		CommittedFacts: walletstore.CommittedFacts{
			Events: []walletstore.Event{event},
		},
		Tip: req.NewTip,
	}

	if err := rt.RecordCommittedOperation(buildTipOp(req, event)); err != nil {
		return walletstore.AdvanceTipResult{}, err
	}

	return result, nil
}

// readCommittedTip reads a committed tip advance from the journal by its
// operation id. The boolean is false when no committed advance exists for the
// id. A replay rebuilds the identical tip and event from the stored fact.
func readCommittedTip(rt *RuntimeStore,
	operationID []byte) (walletstore.AdvanceTipResult, bool, error) {

	result, ok, err := rt.CommittedResult(walletTipDomain, operationID)
	if err != nil || !ok {
		return walletstore.AdvanceTipResult{}, false, err
	}

	tip, err := decodeTipFact(result.Facts)
	if err != nil {
		return walletstore.AdvanceTipResult{}, false, err
	}

	return walletstore.AdvanceTipResult{
		CommittedFacts: walletstore.CommittedFacts{
			Replayed: true,
			Events:   []walletstore.Event{walletstore.WalletTipEvent(tip)},
		},
		Tip: tip,
	}, true, nil
}

// buildTipOp builds the committed-operation journal entry for a tip advance,
// storing the canonical tip event payload as the single result fact and hashing
// it for the result hash.
func buildTipOp(req walletstore.AdvanceTipRequest,
	event walletstore.Event) CommittedOperation {

	resultHash := sha256.Sum256(event.Payload)
	now := time.Now()

	return CommittedOperation{
		Domain:       walletTipDomain,
		OperationID:  req.OperationID,
		RequestHash:  tipRequestHash(req),
		HistoryEpoch: 0,
		ResultRef:    req.OperationID,
		ResultHash:   resultHash[:],
		CreatedAt:    now,
		ExpiresAt:    now.Add(walletTipRetention),
		Facts: []ResultFact{{
			Type:    factTypeWalletTip,
			Payload: event.Payload,
		}},
	}
}

// tipRequestHash returns a stable hash of a tip advance's parameters so reusing
// the operation id with a different expected or new tip is a journal conflict.
func tipRequestHash(req walletstore.AdvanceTipRequest) []byte {
	digest := sha256.New()
	digest.Write(req.ExpectedTip.Hash[:])
	digest.Write(req.NewTip.Hash[:])

	return digest.Sum(nil)
}

// decodeTipFact reads the committed tip from a tip advance's result facts.
func decodeTipFact(facts []ResultFact) (walletstore.BlockRef, error) {
	for _, fact := range facts {
		if fact.Type != factTypeWalletTip {
			continue
		}

		return walletstore.DecodeWalletTip(fact.Payload)
	}

	return walletstore.BlockRef{}, fmt.Errorf("wallet-tip result fact not found")
}
