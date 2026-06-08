package db

import (
	"context"
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

	// AccountNumber is the BIP44 account number used by the derivation
	// callback.
	AccountNumber uint32

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
	// GetHorizonAccount loads the account a horizon targets. The durable,
	// scope-unique horizon.AccountName is the source of truth: both backends
	// mask an imported account's number to 0 when emitting a horizon, so
	// resolving by horizon.Account alone would silently extend the default
	// derived account (also 0). Implementations MUST prefer AccountName
	// whenever it is set and fail (never fall back to Account) on a name
	// miss; horizon.Account is a fast path used only when no name is carried.
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
