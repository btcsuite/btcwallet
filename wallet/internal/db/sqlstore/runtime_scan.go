package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
)

// scanDomain names the operation-journal domain a recovery scan batch records
// its committed operations under.
const scanDomain = "scan-batch"

// rewindDomain names the operation-journal domain a wallet rewind records its
// committed operations under.
const rewindDomain = "wallet-rewind"

// factTypeCommittedTip is the result-fact type whose payload is a committed
// operation's resulting synced tip. It is the leading fact of a scan or rewind
// result, so a replay decodes the committed tip before rebuilding the events.
const factTypeCommittedTip = "committed-tip"

// scanRetention and rewindRetention are how long a committed scan or rewind
// journal row is retained so a late retry is still served from the journal.
const (
	scanRetention   = 24 * time.Hour
	rewindRetention = 24 * time.Hour
)

// tx binds a transaction-manager store to this runtime transaction so the
// semantic scan and rewind operations reuse the same validated incidence,
// credit, spend, and rollback logic as the callback-oriented Store, without a
// second transaction.
func (r *RuntimeStore) tx() *txStore {
	return &txStore{
		ctx:              r.ctx,
		walletID:         r.walletID,
		coinbaseMaturity: r.coinbaseMaturity,
		queries:          r.queries,
	}
}

// CommitScanResults commits one prepared recovery scan batch atomically,
// journaling the committed operation in the same transaction so the batch and
// its journal entry become durable together. A committed operation replays from
// the journal instead of reapplying the batch.
func (r *runtimeStore) CommitScanResults(ctx context.Context,
	req walletstore.CommitScanResultsRequest) (
	walletstore.CommitScanResultsResult, error) {

	var (
		out     walletstore.CommitScanResultsResult
		attempt int
	)

	err := r.store.RuntimeUpdate(ctx, func(rt *RuntimeStore) error {
		var err error

		out, err = r.scanAttempt(ctx, rt, req, &attempt)

		return err
	}, nil)
	if err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	if err := afterCommit(ctx); err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	return out, nil
}

// scanAttempt runs one transaction attempt of a scan-batch commit: it replays a
// committed operation from the journal, or applies the whole batch and journals
// it, before applying the end-of-attempt failpoints. The executor re-runs it on
// a serialization error, so the durable state changes exactly once.
func (r *runtimeStore) scanAttempt(ctx context.Context, rt *RuntimeStore,
	req walletstore.CommitScanResultsRequest, attempt *int) (
	walletstore.CommitScanResultsResult, error) {

	current := *attempt
	*attempt++

	onTxAttempt(ctx, current)

	replayed, found, err := readCommittedScan(rt, req.OperationID)
	if err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	if found {
		return replayed, nil
	}

	if err := beforeStatement(ctx); err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	result, err := commitScanResults(rt, req)
	if err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	return result, injectCommitFaults(ctx, current)
}

// LookupScanResults reads a committed scan batch from the journal by its
// operation id in a read-only transaction.
func (r *runtimeStore) LookupScanResults(ctx context.Context,
	operationID []byte) (walletstore.CommitScanResultsResult, bool, error) {

	var (
		out   walletstore.CommitScanResultsResult
		found bool
	)

	err := r.store.RuntimeView(ctx, func(rt *RuntimeStore) error {
		var err error

		out, found, err = readCommittedScan(rt, operationID)

		return err
	}, nil)
	if err != nil {
		return walletstore.CommitScanResultsResult{}, false, err
	}

	return out, found, nil
}

// commitScanResults applies the whole prepared scan batch and journals the
// committed operation in the current runtime transaction. It fails fast on the
// version guards, then the branch-index compare-and-swaps, then the synced-tip
// compare-and-swap, before inserting the addresses, incidences, credits, and
// usage marks, so a stale caller rolls the whole transaction back before it
// touches the address or transaction tables and no partial batch survives.
func commitScanResults(rt *RuntimeStore,
	req walletstore.CommitScanResultsRequest) (
	walletstore.CommitScanResultsResult, error) {

	if err := rt.ApplyGuards(req.Guards); err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	// Advance each branch horizon through its compare-and-swap first, so a
	// concurrent advance is rejected before any address or transaction row is
	// written.
	for _, horizon := range req.Horizons {
		_, err := rt.AdvanceBranchIndex(
			horizon.Scope, horizon.Account, horizon.Branch,
			horizon.ExpectedIndex, horizon.FinalIndex,
		)
		if err != nil {
			return walletstore.CommitScanResultsResult{}, err
		}
	}

	// Record every batch block and the new tip before the tip advance
	// references it. PutBlock is insert-or-return by header hash, so competing
	// same-height blocks coexist and no block is overwritten.
	for _, block := range req.Blocks {
		if err := rt.PutBlock(block); err != nil {
			return walletstore.CommitScanResultsResult{}, err
		}
	}
	if err := rt.PutBlock(req.NewTip); err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	// Advance the synced tip through the optimistic compare-and-swap against the
	// expected base tip. The batch may span many blocks, so this is a reference
	// swap, not a single-block advance.
	err := rt.AdvanceSyncedTip(req.ExpectedTip.Hash[:], req.NewTip.Hash[:])
	if err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	if err := applyScanRecords(rt, req); err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	events := walletstore.ScanResultEvents(req)
	result := walletstore.CommitScanResultsResult{
		CommittedFacts: walletstore.CommittedFacts{Events: events},
		Tip:            req.NewTip,
	}

	facts := eventResultFacts(result.Tip, events)
	if err := rt.RecordCommittedOperation(buildScanOp(req, facts)); err != nil {
		return walletstore.CommitScanResultsResult{}, err
	}

	return result, nil
}

// applyScanRecords inserts the discovered addresses, the transaction incidences
// with their credits, and the sticky usage marks that make up a scan batch,
// reusing the address-store and transaction-store write primitives so the
// incidence, credit, and spend behavior matches the callback-oriented Store.
func applyScanRecords(rt *RuntimeStore,
	req walletstore.CommitScanResultsRequest) error {

	addr := rt.addr()
	for _, prepared := range req.Addresses {
		err := addr.PutAddress(prepared.AddressID, prepared.State)
		if err != nil {
			return err
		}
	}

	tx := rt.tx()
	for i := range req.Transactions {
		scanTx := req.Transactions[i]

		_, err := tx.InsertTxCheckIfExists(scanTx.Record, scanTx.Block)
		if err != nil {
			return fmt.Errorf("insert scan transaction: %w", err)
		}

		for _, credit := range scanTx.Credits {
			err := tx.AddCredit(
				scanTx.Record, scanTx.Block, credit.Index,
				credit.Change,
			)
			if err != nil {
				return fmt.Errorf("add scan credit: %w", err)
			}
		}
	}

	for _, used := range req.UsedAddresses {
		if err := addr.MarkAddressUsed(used.Scope, used.AddressID); err != nil {
			return err
		}
	}

	return nil
}

// readCommittedScan reads a committed scan batch from the journal by its
// operation id. A replay rebuilds the committed tip and events from the stored
// facts; the durable rows are already present, so a replay makes no further
// change.
func readCommittedScan(rt *RuntimeStore, operationID []byte) (
	walletstore.CommitScanResultsResult, bool, error) {

	result, ok, err := rt.CommittedResult(scanDomain, operationID)
	if err != nil || !ok {
		return walletstore.CommitScanResultsResult{}, false, err
	}

	tip, events, err := decodeEventResultFacts(result.Facts)
	if err != nil {
		return walletstore.CommitScanResultsResult{}, false, err
	}

	return walletstore.CommitScanResultsResult{
		CommittedFacts: walletstore.CommittedFacts{
			Replayed: true,
			Events:   events,
		},
		Tip: tip,
	}, true, nil
}

// CommitWalletRewind reconciles the wallet back to a target block, journaling
// the committed operation in the same transaction so the reconciliation and its
// journal entry become durable together. A committed operation replays from the
// journal instead of reapplying the rewind.
func (r *runtimeStore) CommitWalletRewind(ctx context.Context,
	req walletstore.CommitWalletRewindRequest) (
	walletstore.CommitWalletRewindResult, error) {

	var (
		out     walletstore.CommitWalletRewindResult
		attempt int
	)

	err := r.store.RuntimeUpdate(ctx, func(rt *RuntimeStore) error {
		var err error

		out, err = r.rewindAttempt(ctx, rt, req, &attempt)

		return err
	}, nil)
	if err != nil {
		return walletstore.CommitWalletRewindResult{}, err
	}

	if err := afterCommit(ctx); err != nil {
		return walletstore.CommitWalletRewindResult{}, err
	}

	return out, nil
}

// rewindAttempt runs one transaction attempt of a wallet rewind: it replays a
// committed operation from the journal, or reconciles state to the target and
// journals it, before applying the end-of-attempt failpoints.
func (r *runtimeStore) rewindAttempt(ctx context.Context, rt *RuntimeStore,
	req walletstore.CommitWalletRewindRequest, attempt *int) (
	walletstore.CommitWalletRewindResult, error) {

	current := *attempt
	*attempt++

	onTxAttempt(ctx, current)

	replayed, found, err := readCommittedRewind(rt, req.OperationID)
	if err != nil {
		return walletstore.CommitWalletRewindResult{}, err
	}

	if found {
		return replayed, nil
	}

	if err := beforeStatement(ctx); err != nil {
		return walletstore.CommitWalletRewindResult{}, err
	}

	result, err := commitWalletRewind(rt, req)
	if err != nil {
		return walletstore.CommitWalletRewindResult{}, err
	}

	return result, injectCommitFaults(ctx, current)
}

// LookupWalletRewind reads a committed wallet rewind from the journal by its
// operation id in a read-only transaction.
func (r *runtimeStore) LookupWalletRewind(ctx context.Context,
	operationID []byte) (walletstore.CommitWalletRewindResult, bool, error) {

	var (
		out   walletstore.CommitWalletRewindResult
		found bool
	)

	err := r.store.RuntimeView(ctx, func(rt *RuntimeStore) error {
		var err error

		out, found, err = readCommittedRewind(rt, operationID)

		return err
	}, nil)
	if err != nil {
		return walletstore.CommitWalletRewindResult{}, false, err
	}

	return out, found, nil
}

// commitWalletRewind moves the synced tip back to the target block through the
// optimistic compare-and-swap against the expected current tip, which both
// verifies the detached tip and reconciles sync state, then rolls back every
// mined incidence above the target through the shared transaction-store
// rollback, which detaches surviving incidences to the unmined set, removes
// coinbase incidences and their descendants, and clears their credit spends. It
// journals the committed rewind in the same transaction.
func commitWalletRewind(rt *RuntimeStore,
	req walletstore.CommitWalletRewindRequest) (
	walletstore.CommitWalletRewindResult, error) {

	if err := rt.ApplyGuards(req.Guards); err != nil {
		return walletstore.CommitWalletRewindResult{}, err
	}

	// Verify the detached tip and move the synced tip to the target in one
	// compare-and-swap: it succeeds only while the durable synced block still
	// equals the expected tip, so a concurrent advance or reorg is rejected
	// before any incidence is rolled back.
	err := rt.AdvanceSyncedTip(req.ExpectedTip.Hash[:], req.TargetBlock.Hash[:])
	if err != nil {
		return walletstore.CommitWalletRewindResult{}, err
	}

	// Roll back every mined incidence above the target block.
	if err := rt.tx().Rollback(req.TargetBlock.Height + 1); err != nil {
		return walletstore.CommitWalletRewindResult{}, err
	}

	events := []walletstore.Event{
		walletstore.BlockDisconnectedEvent(req.ExpectedTip),
	}
	result := walletstore.CommitWalletRewindResult{
		CommittedFacts: walletstore.CommittedFacts{Events: events},
		Tip:            req.TargetBlock,
	}

	facts := eventResultFacts(result.Tip, events)
	err = rt.RecordCommittedOperation(buildRewindOp(req, facts))
	if err != nil {
		return walletstore.CommitWalletRewindResult{}, err
	}

	return result, nil
}

// readCommittedRewind reads a committed wallet rewind from the journal by its
// operation id. A replay rebuilds the committed tip and event from the stored
// facts.
func readCommittedRewind(rt *RuntimeStore, operationID []byte) (
	walletstore.CommitWalletRewindResult, bool, error) {

	result, ok, err := rt.CommittedResult(rewindDomain, operationID)
	if err != nil || !ok {
		return walletstore.CommitWalletRewindResult{}, false, err
	}

	tip, events, err := decodeEventResultFacts(result.Facts)
	if err != nil {
		return walletstore.CommitWalletRewindResult{}, false, err
	}

	return walletstore.CommitWalletRewindResult{
		CommittedFacts: walletstore.CommittedFacts{
			Replayed: true,
			Events:   events,
		},
		Tip: tip,
	}, true, nil
}

// eventResultFacts encodes a committed operation's resulting tip and events as
// ordered result facts: the committed tip is the leading fact, followed by one
// fact per event. It is shared by the scan and rewind operations so a replay
// decodes the same shape.
func eventResultFacts(tip walletstore.BlockRef,
	events []walletstore.Event) []ResultFact {

	facts := make([]ResultFact, 0, len(events)+1)
	facts = append(facts, ResultFact{
		Type:    factTypeCommittedTip,
		Payload: walletstore.EncodeBlockRef(tip),
	})
	for _, event := range events {
		facts = append(facts, ResultFact{
			Type:    event.Kind,
			Payload: event.Payload,
		})
	}

	return facts
}

// decodeEventResultFacts reconstructs the committed tip and events from a scan
// or rewind result's facts. The leading fact carries the committed tip; each
// remaining fact rebuilds one event with the same deterministic identity.
func decodeEventResultFacts(facts []ResultFact) (walletstore.BlockRef,
	[]walletstore.Event, error) {

	if len(facts) == 0 || facts[0].Type != factTypeCommittedTip {
		return walletstore.BlockRef{}, nil,
			errors.New("committed-tip result fact not found")
	}

	tip, err := walletstore.DecodeBlockRef(facts[0].Payload)
	if err != nil {
		return walletstore.BlockRef{}, nil, err
	}

	events := make([]walletstore.Event, 0, len(facts)-1)
	for _, fact := range facts[1:] {
		events = append(events, walletstore.Event{
			ID:      walletstore.DeriveEventID(fact.Type, fact.Payload),
			Kind:    fact.Type,
			Payload: fact.Payload,
		})
	}

	return tip, events, nil
}

// buildScanOp builds the committed-operation journal entry for a scan batch,
// storing the committed tip and events as ordered result facts and hashing them
// for the result hash.
func buildScanOp(req walletstore.CommitScanResultsRequest,
	facts []ResultFact) CommittedOperation {

	now := time.Now()

	return CommittedOperation{
		Domain:       scanDomain,
		OperationID:  req.OperationID,
		RequestHash:  scanRequestHash(req),
		HistoryEpoch: 0,
		ResultRef:    req.OperationID,
		ResultHash:   factsHash(facts),
		CreatedAt:    now,
		ExpiresAt:    now.Add(scanRetention),
		Facts:        facts,
	}
}

// buildRewindOp builds the committed-operation journal entry for a wallet
// rewind.
func buildRewindOp(req walletstore.CommitWalletRewindRequest,
	facts []ResultFact) CommittedOperation {

	now := time.Now()

	return CommittedOperation{
		Domain:       rewindDomain,
		OperationID:  req.OperationID,
		RequestHash:  rewindRequestHash(req),
		HistoryEpoch: 0,
		ResultRef:    req.OperationID,
		ResultHash:   factsHash(facts),
		CreatedAt:    now,
		ExpiresAt:    now.Add(rewindRetention),
		Facts:        facts,
	}
}

// factsHash returns a stable hash of an ordered result-fact set, committing to
// each fact's type and payload in order.
func factsHash(facts []ResultFact) []byte {
	digest := sha256.New()
	for _, fact := range facts {
		digest.Write([]byte(fact.Type))
		digest.Write(fact.Payload)
	}

	return digest.Sum(nil)
}

// scanRequestHash returns a stable hash of a scan batch's parameters so reusing
// the operation id with a different batch is a journal conflict.
func scanRequestHash(req walletstore.CommitScanResultsRequest) []byte {
	digest := sha256.New()
	digest.Write(walletstore.EncodeBlockRef(req.ExpectedTip))
	digest.Write(walletstore.EncodeBlockRef(req.NewTip))

	for _, block := range req.Blocks {
		digest.Write(walletstore.EncodeBlockRef(block))
	}

	var buf [24]byte
	for _, horizon := range req.Horizons {
		binary.BigEndian.PutUint32(buf[0:4], horizon.Scope.Purpose)
		binary.BigEndian.PutUint32(buf[4:8], horizon.Scope.Coin)
		binary.BigEndian.PutUint32(buf[8:12], horizon.Account)
		binary.BigEndian.PutUint32(buf[12:16], horizon.Branch)
		binary.BigEndian.PutUint32(buf[16:20], horizon.ExpectedIndex)
		binary.BigEndian.PutUint32(buf[20:24], horizon.FinalIndex)
		digest.Write(buf[:])
	}

	for _, prepared := range req.Addresses {
		digest.Write(prepared.AddressID)
	}

	for i := range req.Transactions {
		writeScanTransactionHash(digest, buf[:], req.Transactions[i])
	}

	for _, used := range req.UsedAddresses {
		binary.BigEndian.PutUint32(buf[0:4], used.Scope.Purpose)
		binary.BigEndian.PutUint32(buf[4:8], used.Scope.Coin)
		digest.Write(buf[0:8])
		digest.Write(used.AddressID)
	}

	return digest.Sum(nil)
}

// writeScanTransactionHash folds one scan transaction, its block, and its
// credits into the request digest.
func writeScanTransactionHash(digest io.Writer, buf []byte,
	scanTx walletstore.ScanTransaction) {

	digest.Write(scanTx.Record.Hash[:])

	if scanTx.Block != nil {
		//nolint:gosec // A block height is non-negative.
		binary.BigEndian.PutUint32(buf[0:4], uint32(scanTx.Block.Height))
		digest.Write(buf[0:4])
		digest.Write(scanTx.Block.Hash[:])
	}

	for _, credit := range scanTx.Credits {
		binary.BigEndian.PutUint32(buf[0:4], credit.Index)
		digest.Write(buf[0:4])

		change := byte(0)
		if credit.Change {
			change = 1
		}
		digest.Write([]byte{change})
	}
}

// rewindRequestHash returns a stable hash of a rewind's parameters so reusing
// the operation id with a different rewind is a journal conflict.
func rewindRequestHash(req walletstore.CommitWalletRewindRequest) []byte {
	digest := sha256.New()
	digest.Write(walletstore.EncodeBlockRef(req.ExpectedTip))
	digest.Write(walletstore.EncodeBlockRef(req.TargetBlock))

	return digest.Sum(nil)
}
