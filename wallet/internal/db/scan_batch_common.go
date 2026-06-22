package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
)

// externalBranch and internalBranch are the BIP44 branch numbers the horizon
// extension distinguishes when picking the address type and next-index column.
const (
	externalBranch uint32 = 0
	internalBranch uint32 = 1
)

// HorizonAccount carries the account state a single horizon extension needs:
// the row ID, the account-level extended public key, the effective address
// schema, and the branch next-index counters as they stand before extension.
type HorizonAccount struct {
	// AccountID is the database row ID of the account.
	AccountID int64

	// AccountNumber is the wallet-derived BIP44 account number used by the
	// derivation callback. It is nil for imported xpub accounts, which have
	// no wallet-derived number and derive children from AccountPubKey alone,
	// mirroring AddressDerivationParams.DerivedAccountNumber.
	AccountNumber *uint32

	// AccountPubKey is the plaintext account-level extended public key the
	// derivation callback derives child addresses from.
	AccountPubKey []byte

	// AddrSchema is the account's effective external/internal address schema.
	AddrSchema ScopeAddrSchema

	// NextExternalIndex is the next unused external (branch 0) child index.
	NextExternalIndex uint32

	// NextInternalIndex is the next unused internal (branch 1) child index.
	NextInternalIndex uint32
}

// branchState returns the address type and current next index for the
// requested branch.
func (a *HorizonAccount) branchState(branch uint32) (AddressType, uint32) {
	if branch == internalBranch {
		return a.AddrSchema.InternalAddrType, a.NextInternalIndex
	}

	return a.AddrSchema.ExternalAddrType, a.NextExternalIndex
}

// ScanHorizonOps abstracts the backend SQL operations one recovery horizon
// extension performs. Implementations run inside the caller's write
// transaction so the whole scan batch stays atomic.
type ScanHorizonOps interface {
	// GetHorizonAccount loads the account a horizon targets. Implementations
	// must resolve by horizon.AccountID, which is the stable account row
	// identity. AccountName is mutable and Account does not identify imported
	// xpub accounts, so neither field may be used as the durable target.
	// Implementations return ErrAccountNotFound when no such account exists.
	GetHorizonAccount(ctx context.Context,
		horizon ScanHorizon) (*HorizonAccount, error)

	// InsertDerivedAddress persists one HD-derived address row at the given
	// branch and child index.
	InsertDerivedAddress(ctx context.Context, accountID int64,
		addrType AddressType, branch uint32, index uint32,
		scriptPubKey []byte, pubKey []byte) error

	// AdvanceNextIndex moves the branch's next-index counter up to nextIndex.
	// Implementations apply a monotonic guard so a concurrent slower writer
	// cannot regress the counter.
	AdvanceNextIndex(ctx context.Context, accountID int64, branch uint32,
		nextIndex uint32) error
}

// ExtendScanHorizon ensures every valid child through horizon.Index is derived
// and persisted on the requested branch, mirroring the legacy
// ScopedKeyManager.ExtendAddresses semantics used by the kvdb backend:
//
//   - Derivation starts from the branch's current next-index and runs through
//     horizon.Index inclusive.
//   - When horizon.Index is already below the current next-index the call is a
//     no-op, so replaying a horizon never inserts duplicate rows.
//   - HD-invalid child indices are skipped (the next-index simply advances)
//     instead of failing, so the SQL path matches the kvdb invalid-child skip.
//   - After derivation the branch next-index advances to one past the last
//     derived child, leaving the same terminal counter the legacy path would.
func ExtendScanHorizon(ctx context.Context, ops ScanHorizonOps,
	deriveFn AddressDerivationFunc, horizon ScanHorizon) error {

	branch, err := validateHorizon(deriveFn, horizon)
	if err != nil {
		return err
	}

	account, err := ops.GetHorizonAccount(ctx, horizon)
	if err != nil {
		return fmt.Errorf("extend horizon: %w", err)
	}

	addrType, nextIndex := account.branchState(branch)

	// Nothing to do when the scan did not advance past the persisted tip.
	if horizon.Index < nextIndex {
		return nil
	}

	// kvdb caps a single extension at MaxAddressesPerAccount; mirror the bound
	// for horizons that actually require new derivation work.
	if horizon.Index > MaxAddressIndex {
		return fmt.Errorf("extend horizon: %w", ErrMaxAddressIndexReached)
	}

	nextIndex, err = deriveHorizonRange(
		ctx, ops, deriveFn, account, horizon, branch, addrType, nextIndex,
	)
	if err != nil {
		return err
	}

	// Persist the advanced next-index so subsequent address allocation and
	// horizon replays resume past the derived range.
	err = ops.AdvanceNextIndex(ctx, account.AccountID, branch, nextIndex)
	if err != nil {
		return fmt.Errorf("extend horizon: advance next index: %w", err)
	}

	return nil
}

// validateHorizon checks the derivation callback and branch number, returning
// the validated branch number.
func validateHorizon(deriveFn AddressDerivationFunc,
	horizon ScanHorizon) (uint32, error) {

	if deriveFn == nil {
		return 0, fmt.Errorf("extend horizon: %w",
			errNilAddressDerivationFunc)
	}

	// Recovery only ever reports the external or internal branch; reject
	// anything else up front so an unexpected branch cannot silently derive
	// against the wrong next-index column.
	branch := horizon.Branch
	if branch != externalBranch && branch != internalBranch {
		return 0, fmt.Errorf("extend horizon: %w: branch %d",
			ErrInvalidParam, branch)
	}

	return branch, nil
}

// deriveHorizonRange derives and persists one valid child per index from
// nextIndex through horizon.Index inclusive and returns the advanced next
// index. It mirrors the nested loop in the legacy extendAddresses: each outer
// step finds the next valid child, skipping HD-invalid indices even past
// horizon.Index, so the terminal next index matches the address manager.
func deriveHorizonRange(ctx context.Context, ops ScanHorizonOps,
	deriveFn AddressDerivationFunc, account *HorizonAccount,
	horizon ScanHorizon, branch uint32, addrType AddressType,
	nextIndex uint32) (uint32, error) {

	for nextIndex <= horizon.Index {
		next, err := deriveNextValidChild(
			ctx, ops, deriveFn, account, horizon.Scope, branch, addrType,
			nextIndex,
		)
		if err != nil {
			return 0, err
		}

		nextIndex = next
	}

	return nextIndex, nil
}

// deriveNextValidChild derives and persists the first valid child at or after
// startIndex, returning the index immediately past the persisted child.
// HD-invalid children are skipped without persisting a row, exactly like the
// inner loop of the legacy extendAddresses.
func deriveNextValidChild(ctx context.Context, ops ScanHorizonOps,
	deriveFn AddressDerivationFunc, account *HorizonAccount, scope KeyScope,
	branch uint32, addrType AddressType, startIndex uint32) (uint32, error) {

	accountID, err := Int64ToUint32(account.AccountID)
	if err != nil {
		return 0, fmt.Errorf("extend horizon: account id: %w", err)
	}

	for index := startIndex; ; index++ {
		// Re-check the recovery bound on every candidate: an invalid-child
		// skip below can advance index to MaxAddressIndex+1, and without
		// this guard the loop would derive and persist an out-of-range
		// child past the bound ExtendScanHorizon enforced for horizon.Index.
		if index > MaxAddressIndex {
			return 0, fmt.Errorf("extend horizon: %w",
				ErrMaxAddressIndexReached)
		}

		derived, err := deriveFn(ctx, AddressDerivationParams{
			AccountID:            &accountID,
			Scope:                scope,
			DerivedAccountNumber: account.AccountNumber,
			Branch:               branch,
			Index:                index,
			AddrType:             addrType,
			AccountPubKey:        account.AccountPubKey,
		})
		if errors.Is(err, hdkeychain.ErrInvalidChild) {
			continue
		}

		if err != nil {
			return 0, fmt.Errorf("extend horizon: derive index %d: %w",
				index, err)
		}

		if derived == nil {
			return 0, fmt.Errorf("extend horizon: derive index %d: %w",
				index, errNilDerivedAddressData)
		}

		err = ops.InsertDerivedAddress(
			ctx, account.AccountID, addrType, branch, index,
			derived.ScriptPubKey, derived.PubKey,
		)
		if err != nil {
			return 0, fmt.Errorf("extend horizon: insert index %d: %w",
				index, err)
		}

		return index + 1, nil
	}
}
