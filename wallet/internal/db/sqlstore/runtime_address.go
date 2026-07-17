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
)

// derivedAddressDomain names the operation-journal domain a derived-address
// commit records its committed operations under.
const derivedAddressDomain = "derived-addresses"

// factTypeDerivedRange is the result-fact type whose payload carries a
// committed derivation range: the allocated start and final next index.
const factTypeDerivedRange = "derived-range"

// derivedRangePayloadLen is the byte length of a derivation-range fact: a
// big-endian allocated start index followed by a big-endian final next index.
const derivedRangePayloadLen = 8

// derivedAddressRetention is how long a committed derived-address commit's
// journal row is retained so a late retry is still served from the journal.
const derivedAddressRetention = 24 * time.Hour

// addr binds an address-manager store to this runtime transaction so the
// semantic address and account operations reuse the same validated persistence
// logic as the callback-oriented Store, including the account name-collision
// guard and the SHA256 address identity, without a second transaction.
func (r *RuntimeStore) addr() *addrStore {
	return &addrStore{ctx: r.ctx, walletID: r.walletID, queries: r.queries}
}

// LastAccount reads the scope's last allocated account inside the runtime
// transaction, returning waddrmgr.NoAccountAllocated when the scope has never
// allocated an account.
func (r *RuntimeStore) LastAccount(scope waddrmgr.KeyScope) (uint32, error) {
	state, err := r.addr().KeyScope(scope)
	if err != nil {
		return 0, err
	}

	return state.LastAccount, nil
}

// AllocateAccountNumber advances the scope's last allocated account to
// newAccount through an optimistic compare-and-swap against expected. It returns
// ErrStaleLastAccount when the scope is missing or the last account moved, so
// the caller rereads it before preparing the allocation again.
func (r *RuntimeStore) AllocateAccountNumber(scope waddrmgr.KeyScope, expected,
	newAccount uint32) error {

	rows, err := r.queries.AllocateAccountNumber(
		r.ctx, r.walletID, scope, expected, newAccount,
	)
	if err != nil {
		return fmt.Errorf("allocate account number: %w", err)
	}

	if rows != 1 {
		return fmt.Errorf("scope %s expected last account %d: %w", scope,
			expected, walletstore.ErrStaleLastAccount)
	}

	return nil
}

// CommitDerivedAddresses inserts the prepared derived addresses and advances the
// branch index from the request's expected index to its final index through an
// optimistic compare-and-swap, journaling the committed operation in the same
// transaction so the address rows, the index advance, and the journal entry
// become durable together. A committed operation replays from the journal
// instead of inserting and advancing again.
func (r *runtimeStore) CommitDerivedAddresses(ctx context.Context,
	req walletstore.CommitDerivedAddressesRequest) (
	walletstore.CommitDerivedAddressesResult, error) {

	if err := validateDerivedRange(req); err != nil {
		return walletstore.CommitDerivedAddressesResult{}, err
	}

	var (
		out     walletstore.CommitDerivedAddressesResult
		attempt int
	)

	err := r.store.RuntimeUpdate(ctx, func(rt *RuntimeStore) error {
		var err error

		out, err = r.deriveAttempt(ctx, rt, req, &attempt)

		return err
	}, nil)
	if err != nil {
		return walletstore.CommitDerivedAddressesResult{}, err
	}

	if err := afterCommit(ctx); err != nil {
		return walletstore.CommitDerivedAddressesResult{}, err
	}

	return out, nil
}

// deriveAttempt runs one transaction attempt of a derived-address commit: it
// replays a committed operation from the journal, or inserts the addresses,
// advances the branch, and journals the committed range, before applying the
// end-of-attempt failpoints.
func (r *runtimeStore) deriveAttempt(ctx context.Context, rt *RuntimeStore,
	req walletstore.CommitDerivedAddressesRequest, attempt *int) (
	walletstore.CommitDerivedAddressesResult, error) {

	current := *attempt
	*attempt++

	onTxAttempt(ctx, current)

	replayed, found, err := readCommittedDerivedAddresses(rt, req.OperationID)
	if err != nil {
		return walletstore.CommitDerivedAddressesResult{}, err
	}

	if found {
		return replayed, nil
	}

	if err := beforeStatement(ctx); err != nil {
		return walletstore.CommitDerivedAddressesResult{}, err
	}

	result, err := commitDerivedAddresses(rt, req)
	if err != nil {
		return walletstore.CommitDerivedAddressesResult{}, err
	}

	return result, injectCommitFaults(ctx, current)
}

// LookupDerivedAddresses reads a committed derived-address commit from the
// journal by its operation id in a read-only transaction.
func (r *runtimeStore) LookupDerivedAddresses(ctx context.Context,
	operationID []byte) (walletstore.CommitDerivedAddressesResult, bool,
	error) {

	var (
		out   walletstore.CommitDerivedAddressesResult
		found bool
	)

	err := r.store.RuntimeView(ctx, func(rt *RuntimeStore) error {
		var err error

		out, found, err = readCommittedDerivedAddresses(rt, operationID)

		return err
	}, nil)
	if err != nil {
		return walletstore.CommitDerivedAddressesResult{}, false, err
	}

	return out, found, nil
}

// commitDerivedAddresses advances the branch index through the compare-and-swap,
// inserts each prepared address, and journals the committed range in the current
// runtime transaction. The compare-and-swap advances the branch from the
// expected index to the final index in one step, so a skipped invalid child is
// accounted for. It runs before the inserts so a stale caller bails on the
// conflict before touching the address table; a stale index rolls the whole
// transaction back, so no address row is left dangling.
func commitDerivedAddresses(rt *RuntimeStore,
	req walletstore.CommitDerivedAddressesRequest) (
	walletstore.CommitDerivedAddressesResult, error) {

	_, err := rt.AdvanceBranchIndex(
		req.Scope, req.Account, req.Branch, req.ExpectedIndex,
		req.FinalIndex,
	)
	if err != nil {
		return walletstore.CommitDerivedAddressesResult{}, err
	}

	store := rt.addr()
	for _, prepared := range req.Addresses {
		err := store.PutAddress(prepared.AddressID, prepared.State)
		if err != nil {
			return walletstore.CommitDerivedAddressesResult{}, err
		}
	}

	result := walletstore.CommitDerivedAddressesResult{
		Addresses:      req.Addresses,
		AllocatedStart: req.ExpectedIndex,
		NextIndex:      req.FinalIndex,
	}

	err = rt.RecordCommittedOperation(buildDerivedOp(req))
	if err != nil {
		return walletstore.CommitDerivedAddressesResult{}, err
	}

	return result, nil
}

// readCommittedDerivedAddresses reads a committed derived-address commit from
// the journal by its operation id. A replay rebuilds the committed range from
// the stored fact; the address rows themselves are already durable, so a replay
// returns no address list and the caller reloads them from the address store if
// needed.
func readCommittedDerivedAddresses(rt *RuntimeStore, operationID []byte) (
	walletstore.CommitDerivedAddressesResult, bool, error) {

	result, ok, err := rt.CommittedResult(derivedAddressDomain, operationID)
	if err != nil || !ok {
		return walletstore.CommitDerivedAddressesResult{}, false, err
	}

	start, next, err := decodeDerivedRange(result.Facts)
	if err != nil {
		return walletstore.CommitDerivedAddressesResult{}, false, err
	}

	return walletstore.CommitDerivedAddressesResult{
		CommittedFacts: walletstore.CommittedFacts{Replayed: true},
		AllocatedStart: start,
		NextIndex:      next,
	}, true, nil
}

// validateDerivedRange rejects a request whose prepared addresses do not lie in
// the half-open range the compare-and-swap advances through, so a malformed
// request never reaches the durable transaction.
func validateDerivedRange(
	req walletstore.CommitDerivedAddressesRequest) error {

	if req.FinalIndex < req.ExpectedIndex {
		return fmt.Errorf("final index %d precedes expected index %d",
			req.FinalIndex, req.ExpectedIndex)
	}

	for _, prepared := range req.Addresses {
		if prepared.State.Index == nil {
			return errors.New("derived address has no index")
		}

		index := *prepared.State.Index
		if index < req.ExpectedIndex || index >= req.FinalIndex {
			return fmt.Errorf("derived index %d outside range [%d, %d)",
				index, req.ExpectedIndex, req.FinalIndex)
		}
	}

	return nil
}

// buildDerivedOp builds the committed-operation journal entry for a
// derived-address commit, encoding its allocated start and final index as the
// single result fact and hashing that payload for the result hash.
func buildDerivedOp(
	req walletstore.CommitDerivedAddressesRequest) CommittedOperation {

	payload := encodeDerivedRange(req.ExpectedIndex, req.FinalIndex)
	resultHash := sha256.Sum256(payload)
	now := time.Now()

	return CommittedOperation{
		Domain:       derivedAddressDomain,
		OperationID:  req.OperationID,
		RequestHash:  derivedRequestHash(req),
		HistoryEpoch: 0,
		ResultRef:    req.OperationID,
		ResultHash:   resultHash[:],
		CreatedAt:    now,
		ExpiresAt:    now.Add(derivedAddressRetention),
		Facts: []ResultFact{{
			Type:    factTypeDerivedRange,
			Payload: payload,
		}},
	}
}

// derivedRequestHash returns a stable hash of a derived-address commit's
// parameters, including the derived address identities, so reusing the operation
// id with different parameters is a journal conflict.
func derivedRequestHash(
	req walletstore.CommitDerivedAddressesRequest) []byte {

	digest := sha256.New()

	var buf [20]byte
	binary.BigEndian.PutUint32(buf[0:4], req.Scope.Purpose)
	binary.BigEndian.PutUint32(buf[4:8], req.Scope.Coin)
	binary.BigEndian.PutUint32(buf[8:12], req.Account)
	binary.BigEndian.PutUint32(buf[12:16], req.Branch)
	binary.BigEndian.PutUint32(buf[16:20], req.ExpectedIndex)
	digest.Write(buf[:])

	var final [4]byte
	binary.BigEndian.PutUint32(final[:], req.FinalIndex)
	digest.Write(final[:])

	for _, prepared := range req.Addresses {
		digest.Write(prepared.AddressID)
	}

	return digest.Sum(nil)
}

// encodeDerivedRange packs an allocated start and final index into the
// derivation-range result-fact payload.
func encodeDerivedRange(start, final uint32) []byte {
	var payload [derivedRangePayloadLen]byte

	binary.BigEndian.PutUint32(payload[0:4], start)
	binary.BigEndian.PutUint32(payload[4:8], final)

	return payload[:]
}

// decodeDerivedRange reads the allocated start and final index from a committed
// derived-address commit's result facts.
func decodeDerivedRange(facts []ResultFact) (uint32, uint32, error) {
	for _, fact := range facts {
		if fact.Type != factTypeDerivedRange {
			continue
		}

		if len(fact.Payload) != derivedRangePayloadLen {
			return 0, 0, fmt.Errorf("derived-range fact payload is "+
				"%d bytes, want %d", len(fact.Payload),
				derivedRangePayloadLen)
		}

		start := binary.BigEndian.Uint32(fact.Payload[0:4])
		final := binary.BigEndian.Uint32(fact.Payload[4:8])

		return start, final, nil
	}

	return 0, 0, errors.New("derived-range result fact not found")
}

// CurrentLastAccount reads a durable snapshot of the scope's last allocated
// account in a read-only transaction.
func (r *runtimeStore) CurrentLastAccount(ctx context.Context,
	scope waddrmgr.KeyScope) (uint32, error) {

	var last uint32

	err := r.store.RuntimeView(ctx, func(rt *RuntimeStore) error {
		var err error

		last, err = rt.LastAccount(scope)

		return err
	}, nil)
	if err != nil {
		return 0, err
	}

	return last, nil
}

// EnsureScope creates the key scope if it is absent and is otherwise a no-op.
// It reuses the address store's scope read and write, so the created scope is
// byte-identical to one created through the callback-oriented Store.
func (r *runtimeStore) EnsureScope(ctx context.Context,
	req walletstore.EnsureScopeRequest) (walletstore.EnsureScopeResult, error) {

	var out walletstore.EnsureScopeResult

	err := r.store.RuntimeUpdate(ctx, func(rt *RuntimeStore) error {
		store := rt.addr()

		_, err := store.KeyScope(req.State.Scope)
		switch {
		case err == nil:
			out = walletstore.EnsureScopeResult{Created: false}

			return nil

		case !waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound):
			return err
		}

		if err := beforeStatement(ctx); err != nil {
			return err
		}

		if err := store.PutKeyScope(req.State); err != nil {
			return err
		}

		out = walletstore.EnsureScopeResult{Created: true}

		return beforeCommit(ctx)
	}, nil)
	if err != nil {
		return walletstore.EnsureScopeResult{}, err
	}

	if err := afterCommit(ctx); err != nil {
		return walletstore.EnsureScopeResult{}, err
	}

	return out, nil
}

// EnsureAccount ensures an account with the requested name exists in the scope.
// An existing account with that name is returned unchanged; otherwise the next
// account number is allocated through the compare-and-swap and the account is
// created at it, all in one transaction so allocation and creation are atomic.
func (r *runtimeStore) EnsureAccount(ctx context.Context,
	req walletstore.EnsureAccountRequest) (walletstore.EnsureAccountResult,
	error) {

	var out walletstore.EnsureAccountResult

	err := r.store.RuntimeUpdate(ctx, func(rt *RuntimeStore) error {
		store := rt.addr()

		// Idempotency: an account already exists with the requested name.
		existing, err := store.AccountByName(req.Scope, req.Name)
		switch {
		case err == nil:
			out = walletstore.EnsureAccountResult{
				Account: existing.Account,
				Created: false,
			}

			return nil

		case !waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound):
			return err
		}

		if err := beforeStatement(ctx); err != nil {
			return err
		}

		newAccount, err := walletstore.NextAccountNumber(
			req.ExpectedLastAccount,
		)
		if err != nil {
			return err
		}

		// Allocate the number first, so a stale caller never writes an
		// account row it does not own.
		err = rt.AllocateAccountNumber(
			req.Scope, req.ExpectedLastAccount, newAccount,
		)
		if err != nil {
			return err
		}

		account := req.Template
		account.Scope = req.Scope
		account.Account = newAccount

		account.Name = req.Name
		if err := store.PutAccount(account); err != nil {
			return err
		}

		out = walletstore.EnsureAccountResult{
			Account: newAccount,
			Created: true,
		}

		return beforeCommit(ctx)
	}, nil)
	if err != nil {
		return walletstore.EnsureAccountResult{}, err
	}

	if err := afterCommit(ctx); err != nil {
		return walletstore.EnsureAccountResult{}, err
	}

	return out, nil
}

// RenameAccount renames one account, reusing the address store's rename, which
// rejects a name owned by a different account with waddrmgr.ErrDuplicateAccount
// and keeps the name index consistent atomically with the rename.
func (r *runtimeStore) RenameAccount(ctx context.Context,
	req walletstore.RenameAccountRequest) (walletstore.RenameAccountResult,
	error) {

	err := r.store.RuntimeUpdate(ctx, func(rt *RuntimeStore) error {
		if err := beforeStatement(ctx); err != nil {
			return err
		}

		err := rt.addr().RenameAccount(req.Scope, req.Account, req.NewName)
		if err != nil {
			return err
		}

		return beforeCommit(ctx)
	}, nil)
	if err != nil {
		return walletstore.RenameAccountResult{}, err
	}

	if err := afterCommit(ctx); err != nil {
		return walletstore.RenameAccountResult{}, err
	}

	return walletstore.RenameAccountResult{}, nil
}
