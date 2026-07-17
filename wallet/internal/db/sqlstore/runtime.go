package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/lightningnetwork/lnd/sqldb"
)

// operationStatusCommitted is the journal status of a durable, replay-safe
// operation. It matches the literal written by the InsertCommittedOperation
// query.
const operationStatusCommitted = "committed"

// RuntimeStateRow is the backend-neutral runtime-state version snapshot.
type RuntimeStateRow struct {
	StateVersion  int64
	HistoryEpoch  int64
	SecretVersion int64
}

// OperationRow is the backend-neutral operation-journal row returned by a key
// lookup. Nullable result columns are nil until the operation is committed.
type OperationRow struct {
	RequestHash  []byte
	HistoryEpoch int64
	Status       string
	ResultRef    []byte
	ResultHash   []byte
	CreatedAt    int64
	ExpiresAt    int64
}

// InsertCommittedOperationParams contains one committed journal row to persist.
type InsertCommittedOperationParams struct {
	WalletID     int64
	Domain       string
	OperationID  []byte
	RequestHash  []byte
	HistoryEpoch int64
	ResultRef    []byte
	ResultHash   []byte
	CreatedAt    int64
	ExpiresAt    int64
}

// InsertOperationResultFactParams contains one ordered result fact to persist.
type InsertOperationResultFactParams struct {
	WalletID    int64
	Domain      string
	OperationID []byte
	Ordinal     int64
	FactType    string
	FactKey     []byte
	FactPayload []byte
}

// OperationResultFactRow is one persisted operation-result fact.
type OperationResultFactRow struct {
	Ordinal     int64
	FactType    string
	FactKey     []byte
	FactPayload []byte
}

// RuntimeState is the typed snapshot of one wallet's runtime-state versions.
// Callers read a snapshot, prepare work outside the write transaction, then
// guard the commit with a version bump so unrelated changes to other domains do
// not invalidate the preparation. The versions are non-negative monotonic
// counters stored as signed integers, matching the runtime-state columns.
type RuntimeState struct {
	// StateVersion guards address, transaction, and sync state mutations.
	StateVersion int64

	// HistoryEpoch advances whenever transaction history is reset.
	HistoryEpoch int64

	// SecretVersion advances whenever encrypted secret material changes.
	SecretVersion int64
}

// ResultFact is one immutable fact that reproduces a committed operation's
// result after its source rows are gone. Facts are ordered by their position in
// a CommittedOperation.
type ResultFact struct {
	// Type names the fact category, for example a credit or spend fact.
	Type string

	// Key optionally identifies the fact within its type, for example an
	// outpoint. It may be nil for facts that need no sub-key.
	Key []byte

	// Payload carries the fact's canonical data.
	Payload []byte
}

// CommittedOperation is a semantic operation that has committed, ready to be
// recorded in the journal together with its result facts.
type CommittedOperation struct {
	// Domain names the semantic domain, for example the address or scan
	// domain, and forms part of the journal key.
	Domain string

	// OperationID is the caller-supplied stable identifier of the operation
	// within its domain.
	OperationID []byte

	// RequestHash commits to the operation's parameters, including its
	// expiry deadline. A retry with a different request hash is a conflict.
	RequestHash []byte

	// HistoryEpoch is the history epoch under which the operation committed.
	HistoryEpoch int64

	// ResultRef identifies this operation's result-fact set.
	ResultRef []byte

	// ResultHash commits to the canonical order and payloads of the facts.
	ResultHash []byte

	// CreatedAt is when the operation committed.
	CreatedAt time.Time

	// ExpiresAt is the retention deadline after which garbage collection may
	// remove the journal row and its facts.
	ExpiresAt time.Time

	// Facts are the ordered result facts recorded with the operation.
	Facts []ResultFact
}

// CommittedResult is the durable result of a previously committed operation,
// returned to a retry so the mutation is not rerun.
type CommittedResult struct {
	// ResultRef identifies the result-fact set.
	ResultRef []byte

	// ResultHash commits to the canonical order and payloads of the facts.
	ResultHash []byte

	// Facts are the ordered result facts recorded with the operation.
	Facts []ResultFact
}

// RuntimeStore exposes the runtime-state guards and the operation journal bound
// to one SQL transaction. It is the Stage 3 building block the wallet
// orchestration composes; Phase 1 wires its semantic methods and finalizes the
// separate RuntimeStore interface placement.
type RuntimeStore struct {
	// The runtime view is scoped to the transaction callback that created it.
	//
	//nolint:containedctx // Domain methods intentionally omit backend context.
	ctx              context.Context
	walletID         int64
	coinbaseMaturity int32
	queries          Queries
}

// newRuntimeStore binds a runtime store to one transaction's queries.
func (s *Store) newRuntimeStore(ctx context.Context,
	queries Queries) *RuntimeStore {

	return &RuntimeStore{
		ctx:              ctx,
		walletID:         s.walletID,
		coinbaseMaturity: s.coinbaseMaturity,
		queries:          queries,
	}
}

// RuntimeView executes body against a runtime store in a read-only SQL
// transaction.
func (s *Store) RuntimeView(ctx context.Context,
	body func(*RuntimeStore) error, reset func()) error {

	return s.executor.ExecTx(
		ctx, sqldb.ReadTxOpt(), func(queries Queries) error {
			return body(s.newRuntimeStore(ctx, queries))
		}, nonNilReset(reset),
	)
}

// RuntimeUpdate executes body against a runtime store in a read/write SQL
// transaction.
//
// It runs a standalone runtime transaction, which suits version reads,
// retention garbage collection, and recording an operation that has no
// accompanying domain mutation. An operation that does mutate a domain must
// instead record its committed journal row inside the same write transaction as
// that mutation; see RecordCommittedOperation.
func (s *Store) RuntimeUpdate(ctx context.Context,
	body func(*RuntimeStore) error, reset func()) error {

	return s.executor.ExecTx(
		ctx, sqldb.WriteTxOpt(), func(queries Queries) error {
			return body(s.newRuntimeStore(ctx, queries))
		}, nonNilReset(reset),
	)
}

// EnsureState creates the wallet's zeroed runtime-state row if it does not
// exist yet. It is idempotent and is the building block wallet creation uses to
// establish the one-row-per-wallet invariant; existing wallets are already
// backfilled by the runtime-journal migration.
func (r *RuntimeStore) EnsureState() error {
	err := r.queries.EnsureRuntimeState(r.ctx, r.walletID)
	if err != nil {
		return fmt.Errorf("ensure runtime state: %w", err)
	}

	return nil
}

// State returns the wallet's current runtime-state version snapshot.
func (r *RuntimeStore) State() (RuntimeState, error) {
	row, err := r.queries.GetRuntimeState(r.ctx, r.walletID)
	if err != nil {
		return RuntimeState{}, fmt.Errorf("get runtime state: %w", err)
	}

	// RuntimeStateRow and RuntimeState share the same version fields; convert
	// the neutral row directly into the typed snapshot.
	return RuntimeState(row), nil
}

// BumpStateVersion advances the wallet state version, but only while it still
// equals expected. It returns ErrStaleWalletState when the snapshot is stale so
// no version is advanced, matching the optimistic compare-and-swap guard.
func (r *RuntimeStore) BumpStateVersion(expected int64) error {
	return r.bump(
		r.queries.BumpStateVersion, expected,
		walletstore.ErrStaleWalletState,
	)
}

// BumpHistoryEpoch advances the wallet history epoch, but only while it still
// equals expected. It returns ErrStaleHistoryEpoch when the snapshot is stale.
func (r *RuntimeStore) BumpHistoryEpoch(expected int64) error {
	return r.bump(
		r.queries.BumpHistoryEpoch, expected,
		walletstore.ErrStaleHistoryEpoch,
	)
}

// BumpSecretVersion advances the wallet secret version, but only while it still
// equals expected. It returns ErrStaleSecretState when the snapshot is stale.
func (r *RuntimeStore) BumpSecretVersion(expected int64) error {
	return r.bump(
		r.queries.BumpSecretVersion, expected,
		walletstore.ErrStaleSecretState,
	)
}

// ApplyGuards applies the version-domain guards declared in g within the
// current runtime transaction. For each present expected version it runs the
// domain's optimistic compare-and-swap bump, returning the domain's typed stale
// error on a mismatch so a stale operation advances no version. A nil field is
// skipped. It is the reusable version-guard family of the Stage 3 guard set;
// the natural-record guards (expected index, expected tip, reservation
// ownership) live on each operation's own request. The wallet runtime-state row
// must already exist; callers ensure it once at wallet creation.
func (r *RuntimeStore) ApplyGuards(g walletstore.Guards) error {
	if g.ExpectedStateVersion != nil {
		if err := r.BumpStateVersion(*g.ExpectedStateVersion); err != nil {
			return err
		}
	}

	if g.ExpectedHistoryEpoch != nil {
		if err := r.BumpHistoryEpoch(*g.ExpectedHistoryEpoch); err != nil {
			return err
		}
	}

	if g.ExpectedSecretVersion != nil {
		if err := r.BumpSecretVersion(*g.ExpectedSecretVersion); err != nil {
			return err
		}
	}

	return nil
}

// bump runs one guarded version increment, translating a no-op update into the
// domain's typed stale error.
func (r *RuntimeStore) bump(update func(context.Context, int64,
	int64) (int64, error), expected int64, stale error) error {

	rows, err := update(r.ctx, r.walletID, expected)
	if err != nil {
		return fmt.Errorf("bump runtime version: %w", err)
	}

	if rows != 1 {
		return fmt.Errorf("expected version %d: %w", expected, stale)
	}

	return nil
}

// RecordCommittedOperation records a semantic operation that has committed,
// writing its journal row and result facts.
//
// Callers must invoke it inside the same write transaction as the domain
// mutation it commits, so the journal row, its result facts, and the mutation
// become durable together. The started state is therefore never durably
// visible: any failure rolls back the journal insert and the mutation as one.
// RuntimeUpdate provides a standalone transaction only for operations with no
// domain mutation; Phase 1 orchestration invokes this on a runtime store bound
// to the domain write transaction.
//
// Recording is idempotent for an exact retry: if the operation is already
// journaled with the same request hash and history epoch, it is a no-op because
// the result is already durable. Reusing the operation id with a different
// request hash or history epoch returns ErrOperationConflict.
func (r *RuntimeStore) RecordCommittedOperation(op CommittedOperation) error {
	existing, err := r.queries.GetOperation(
		r.ctx, r.walletID, op.Domain, op.OperationID,
	)
	switch {
	case err == nil:
		sameRequest := bytes.Equal(existing.RequestHash, op.RequestHash) &&
			existing.HistoryEpoch == op.HistoryEpoch
		if !sameRequest {
			return fmt.Errorf("operation %s/%x: %w", op.Domain,
				op.OperationID, walletstore.ErrOperationConflict)
		}

		return nil

	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("look up operation: %w", err)
	}

	err = r.queries.InsertCommittedOperation(
		r.ctx, InsertCommittedOperationParams{
			WalletID:     r.walletID,
			Domain:       op.Domain,
			OperationID:  op.OperationID,
			RequestHash:  op.RequestHash,
			HistoryEpoch: op.HistoryEpoch,
			ResultRef:    op.ResultRef,
			ResultHash:   op.ResultHash,
			CreatedAt:    op.CreatedAt.Unix(),
			ExpiresAt:    op.ExpiresAt.Unix(),
		},
	)
	if err != nil {
		return fmt.Errorf("insert committed operation: %w", err)
	}

	for i, fact := range op.Facts {
		err = r.queries.InsertOperationResultFact(
			r.ctx, InsertOperationResultFactParams{
				WalletID:    r.walletID,
				Domain:      op.Domain,
				OperationID: op.OperationID,
				Ordinal:     int64(i),
				FactType:    fact.Type,
				FactKey:     fact.Key,
				FactPayload: fact.Payload,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"insert operation result fact %d: %w", i, err,
			)
		}
	}

	return nil
}

// CommittedResult returns the durable result of a previously committed
// operation so a retry is served from the journal instead of rerunning the
// mutation. The boolean is false when no committed operation exists for the
// key.
func (r *RuntimeStore) CommittedResult(domain string,
	operationID []byte) (CommittedResult, bool, error) {

	row, err := r.queries.GetOperation(
		r.ctx, r.walletID, domain, operationID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return CommittedResult{}, false, nil
	}

	if err != nil {
		return CommittedResult{}, false, fmt.Errorf(
			"look up operation: %w", err,
		)
	}

	if row.Status != operationStatusCommitted {
		return CommittedResult{}, false, nil
	}

	facts, err := r.queries.ListOperationResultFacts(
		r.ctx, r.walletID, domain, operationID,
	)
	if err != nil {
		return CommittedResult{}, false, fmt.Errorf(
			"list operation result facts: %w", err,
		)
	}

	result := CommittedResult{
		ResultRef:  row.ResultRef,
		ResultHash: row.ResultHash,
	}
	for _, fact := range facts {
		result.Facts = append(result.Facts, ResultFact{
			Type:    fact.FactType,
			Key:     fact.FactKey,
			Payload: fact.FactPayload,
		})
	}

	return result, true, nil
}

// CollectExpiredOperations deletes terminal journal rows whose retention
// deadline is at or before now, cascading their result facts, and returns the
// number of journal rows removed. It never collects an unexpired row or an
// in-flight started row.
func (r *RuntimeStore) CollectExpiredOperations(now time.Time) (int64, error) {
	deleted, err := r.queries.CollectExpiredOperations(
		r.ctx, r.walletID, now.Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("collect expired operations: %w", err)
	}

	return deleted, nil
}
