package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/lightningnetwork/lnd/sqldb"
)

// branchIndexDomain names the operation-journal domain the reservation records
// its committed operations under.
const branchIndexDomain = "branch-index"

// factTypeBranchIndex is the result-fact type whose payload carries a
// reservation's allocated and next index.
const factTypeBranchIndex = "branch-index"

// reservationPayloadLen is the byte length of a reservation result fact: a
// big-endian allocated index followed by a big-endian next index.
const reservationPayloadLen = 8

// branchIndexRetention is how long a committed reservation's journal row is
// retained so a late retry is still served from the journal. The value is
// deliberately generous; retention tuning is a later phase.
const branchIndexRetention = 24 * time.Hour

// errForcedRetry is the injected error the retry failpoint wraps in a
// serialization error to force the transaction executor to roll back and re-run
// the commit body.
var errForcedRetry = errors.New("forced serialization retry")

// runtimeStore implements walletstore.RuntimeStore over one SQL wallet store.
// It owns its database transactions through the store's RuntimeUpdate and
// RuntimeView and holds the concrete store as an unexported, non-embedded field
// so it exposes no View/Update boundary or raw transaction handle.
//
// Failure injection is a per-call test seam carried on the operation's context
// (see walletstore.Failpoints), so the concrete store carries no test state and
// the neutral RuntimeStore contract carries no test fields.
type runtimeStore struct {
	store *Store
}

// Compile-time assertion that the semantic runtime store implements the neutral
// RuntimeStore contract.
var _ walletstore.RuntimeStore = (*runtimeStore)(nil)

// NewRuntimeStore constructs a semantic RuntimeStore over a concrete SQL store.
//
//nolint:ireturn // The runtime contract is returned as its neutral interface.
func NewRuntimeStore(store *Store) walletstore.RuntimeStore {
	return &runtimeStore{store: store}
}

// onTxAttempt reports one zero-based transaction attempt to any failpoint
// observer carried on ctx.
func onTxAttempt(ctx context.Context, attempt int) {
	walletstore.FailpointsFromContext(ctx).RunOnTxAttempt(attempt)
}

// beforeStatement applies the before-statement failpoint carried on ctx, if
// any, before an operation's first domain mutation.
func beforeStatement(ctx context.Context) error {
	return walletstore.FailpointsFromContext(ctx).RunBeforeStatement()
}

// injectCommitFaults applies the end-of-attempt failpoints after a transaction
// attempt's durable work has run: an arbitrary rollback through the
// before-commit hook, then a forced serialization retry for the first
// configured attempts, driving the executor's real callback-retry path. It
// returns nil in production.
func injectCommitFaults(ctx context.Context, attempt int) error {
	fp := walletstore.FailpointsFromContext(ctx)

	err := fp.RunBeforeCommit()
	if err != nil {
		return err
	}

	if attempt < fp.Retries() {
		return &sqldb.ErrSerializationError{DBError: errForcedRetry}
	}

	return nil
}

// afterCommit applies the after-commit failpoint carried on ctx, if any, after
// a durable commit and before the result is returned. A test returns
// walletstore.ErrAmbiguousCommit here to model an ambiguous commit.
func afterCommit(ctx context.Context) error {
	return walletstore.FailpointsFromContext(ctx).RunAfterCommit()
}

// beforeCommit applies the before-commit failpoint carried on ctx, if any, at
// the end of a single-attempt operation's transaction body, so a test forces a
// non-retryable rollback. Operations that run the executor's retry loop use
// injectCommitFaults instead; the account, scope, and rename operations keep no
// journal and take no callback retry, so they consult the seam directly.
func beforeCommit(ctx context.Context) error {
	return walletstore.FailpointsFromContext(ctx).RunBeforeCommit()
}

// CurrentBranchIndex reads a durable snapshot of the account's next index for
// one branch in a read-only transaction.
func (r *runtimeStore) CurrentBranchIndex(ctx context.Context,
	scope waddrmgr.KeyScope, account, branch uint32) (uint32, error) {

	var index uint32

	err := r.store.RuntimeView(ctx, func(rt *RuntimeStore) error {
		var err error

		index, err = rt.BranchIndex(scope, account, branch)

		return err
	}, nil)
	if err != nil {
		return 0, err
	}

	return index, nil
}

// ReserveNextBranchIndex allocates the account's next branch index through an
// optimistic compare-and-swap and journals the committed operation in the same
// transaction. A committed operation replays from the journal instead of
// advancing the index again, so the durable state changes exactly once across
// callback retries and operation-level retries alike.
func (r *runtimeStore) ReserveNextBranchIndex(ctx context.Context,
	req walletstore.ReserveBranchIndexRequest) (
	walletstore.ReserveBranchIndexResult, error) {

	var (
		out     walletstore.ReserveBranchIndexResult
		attempt int
	)

	err := r.store.RuntimeUpdate(ctx, func(rt *RuntimeStore) error {
		var err error

		out, err = r.reserveAttempt(ctx, rt, req, &attempt)

		return err
	}, nil)
	if err != nil {
		return walletstore.ReserveBranchIndexResult{}, err
	}

	// A durably committed reservation may still be reported ambiguous so the
	// caller resolves it by durable reread.
	if err := afterCommit(ctx); err != nil {
		return walletstore.ReserveBranchIndexResult{}, err
	}

	return out, nil
}

// reserveAttempt runs one transaction attempt of a reservation commit: it
// replays a committed operation from the journal, or advances the branch index
// and journals the new reservation, before applying the end-of-attempt
// failpoints. The executor re-runs it on a serialization error.
func (r *runtimeStore) reserveAttempt(ctx context.Context, rt *RuntimeStore,
	req walletstore.ReserveBranchIndexRequest, attempt *int) (
	walletstore.ReserveBranchIndexResult, error) {

	current := *attempt
	*attempt++

	onTxAttempt(ctx, current)

	// A committed operation short-circuits the compare-and-swap so a replay
	// is served from the journal instead of advancing again.
	replayed, found, err := readCommittedReservation(rt, req.OperationID)
	if err != nil {
		return walletstore.ReserveBranchIndexResult{}, err
	}

	if found {
		return replayed, nil
	}

	if err := beforeStatement(ctx); err != nil {
		return walletstore.ReserveBranchIndexResult{}, err
	}

	result, err := commitReservation(rt, req)
	if err != nil {
		return walletstore.ReserveBranchIndexResult{}, err
	}

	return result, injectCommitFaults(ctx, current)
}

// LookupBranchIndexReservation reads a committed reservation from the
// journal by its operation id in a read-only transaction.
func (r *runtimeStore) LookupBranchIndexReservation(ctx context.Context,
	operationID []byte) (walletstore.ReserveBranchIndexResult, bool, error) {

	var (
		out   walletstore.ReserveBranchIndexResult
		found bool
	)

	err := r.store.RuntimeView(ctx, func(rt *RuntimeStore) error {
		var err error

		out, found, err = readCommittedReservation(rt, operationID)

		return err
	}, nil)
	if err != nil {
		return walletstore.ReserveBranchIndexResult{}, false, err
	}

	return out, found, nil
}

// commitReservation advances the branch index and journals the committed
// reservation in the current runtime transaction, so the index move and its
// journal entry become durable together.
func commitReservation(rt *RuntimeStore,
	req walletstore.ReserveBranchIndexRequest) (
	walletstore.ReserveBranchIndexResult, error) {

	next, err := rt.AdvanceBranchIndex(
		req.Scope, req.Account, req.Branch,
		req.ExpectedIndex, req.ExpectedIndex+1,
	)
	if err != nil {
		return walletstore.ReserveBranchIndexResult{}, err
	}

	result := walletstore.ReserveBranchIndexResult{
		AllocatedIndex: req.ExpectedIndex,
		NextIndex:      next,
	}

	err = rt.RecordCommittedOperation(buildReservationOp(req, result))
	if err != nil {
		return walletstore.ReserveBranchIndexResult{}, err
	}

	return result, nil
}

// readCommittedReservation reads a committed reservation from the journal by
// its operation id inside a runtime transaction. The boolean is false when no
// committed reservation exists for the id.
func readCommittedReservation(rt *RuntimeStore,
	operationID []byte) (walletstore.ReserveBranchIndexResult, bool, error) {

	result, ok, err := rt.CommittedResult(branchIndexDomain, operationID)
	if err != nil || !ok {
		return walletstore.ReserveBranchIndexResult{}, false, err
	}

	alloc, next, err := decodeReservation(result.Facts)
	if err != nil {
		return walletstore.ReserveBranchIndexResult{}, false, err
	}

	return walletstore.ReserveBranchIndexResult{
		CommittedFacts: walletstore.CommittedFacts{Replayed: true},
		AllocatedIndex: alloc,
		NextIndex:      next,
	}, true, nil
}

// BranchIndex reads the account's current next index for one branch inside the
// runtime transaction. It is the snapshot-read counterpart to
// AdvanceBranchIndex.
func (r *RuntimeStore) BranchIndex(scope waddrmgr.KeyScope,
	account, branch uint32) (uint32, error) {

	acct, err := r.queries.GetAccount(r.ctx, r.walletID, scope, account)
	if err != nil {
		return 0, fmt.Errorf("get account: %w", err)
	}

	switch branch {
	case waddrmgr.ExternalBranch:
		return acct.NextExternalIndex, nil

	case waddrmgr.InternalBranch:
		return acct.NextInternalIndex, nil

	default:
		return 0, fmt.Errorf("unsupported branch %d", branch)
	}
}

// buildReservationOp builds the committed-operation journal entry for a
// reservation, encoding its allocated and next index as the single result fact
// and hashing that payload for the result hash.
func buildReservationOp(req walletstore.ReserveBranchIndexRequest,
	result walletstore.ReserveBranchIndexResult) CommittedOperation {

	payload := encodeReservation(result.AllocatedIndex, result.NextIndex)
	resultHash := sha256.Sum256(payload)
	now := time.Now()

	return CommittedOperation{
		Domain:       branchIndexDomain,
		OperationID:  req.OperationID,
		RequestHash:  reservationRequestHash(req),
		HistoryEpoch: 0,
		ResultRef:    req.OperationID,
		ResultHash:   resultHash[:],
		CreatedAt:    now,
		ExpiresAt:    now.Add(branchIndexRetention),
		Facts: []ResultFact{{
			Type:    factTypeBranchIndex,
			Payload: payload,
		}},
	}
}

// reservationRequestHash returns a stable hash of a reservation's parameters so
// reusing the operation id with different parameters is a journal conflict.
func reservationRequestHash(
	req walletstore.ReserveBranchIndexRequest) []byte {

	var buf [20]byte

	binary.BigEndian.PutUint32(buf[0:4], req.Scope.Purpose)
	binary.BigEndian.PutUint32(buf[4:8], req.Scope.Coin)
	binary.BigEndian.PutUint32(buf[8:12], req.Account)
	binary.BigEndian.PutUint32(buf[12:16], req.Branch)
	binary.BigEndian.PutUint32(buf[16:20], req.ExpectedIndex)
	hash := sha256.Sum256(buf[:])

	return hash[:]
}

// encodeReservation packs an allocated and next index into the reservation
// result-fact payload.
func encodeReservation(allocated, next uint32) []byte {
	var payload [reservationPayloadLen]byte

	binary.BigEndian.PutUint32(payload[0:4], allocated)
	binary.BigEndian.PutUint32(payload[4:8], next)

	return payload[:]
}

// decodeReservation reads the allocated and next index from a reservation's
// result facts.
func decodeReservation(facts []ResultFact) (uint32, uint32, error) {
	for _, fact := range facts {
		if fact.Type != factTypeBranchIndex {
			continue
		}

		if len(fact.Payload) != reservationPayloadLen {
			return 0, 0, fmt.Errorf("branch-index fact payload is "+
				"%d bytes, want %d", len(fact.Payload),
				reservationPayloadLen)
		}

		allocated := binary.BigEndian.Uint32(fact.Payload[0:4])
		next := binary.BigEndian.Uint32(fact.Payload[4:8])

		return allocated, next, nil
	}

	return 0, 0, errors.New("branch-index result fact not found")
}
