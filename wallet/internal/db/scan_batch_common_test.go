package db

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/stretchr/testify/require"
)

// fakeHorizonOps is a minimal ScanHorizonOps used by the ExtendScanHorizon
// tests. It records the inserted child indices and the final advanced
// next-index so each scenario can assert the exact derivation work performed.
type fakeHorizonOps struct {
	account *HorizonAccount

	inserted    []uint32
	advancedTo  uint32
	advanceCall bool
}

// GetHorizonAccount returns the preconfigured account.
func (o *fakeHorizonOps) GetHorizonAccount(_ context.Context,
	_ ScanHorizon) (*HorizonAccount, error) {

	return o.account, nil
}

// InsertDerivedAddress records the child index that was derived and persisted.
func (o *fakeHorizonOps) InsertDerivedAddress(_ context.Context, _ int64,
	_ AddressType, _ uint32, index uint32, _ []byte, _ []byte) error {

	o.inserted = append(o.inserted, index)

	return nil
}

// AdvanceNextIndex records the advanced next-index value.
func (o *fakeHorizonOps) AdvanceNextIndex(_ context.Context, _ int64,
	_ uint32, nextIndex uint32) error {

	o.advanceCall = true
	o.advancedTo = nextIndex

	return nil
}

// validChildDeriveFunc returns a derivation callback that always derives a
// valid address, recording nothing of the input.
func validChildDeriveFunc() AddressDerivationFunc {
	return func(_ context.Context,
		_ AddressDerivationParams) (*DerivedAddressData, error) {

		return &DerivedAddressData{
			ScriptPubKey: []byte{0x00, 0x14},
			PubKey:       []byte{0x02},
		}, nil
	}
}

// TestExtendScanHorizonNoOpBelowNextIndex verifies that ExtendScanHorizon does
// nothing when the discovered index is below the branch's current next index,
// so replaying an already-covered horizon never re-derives or advances.
func TestExtendScanHorizonNoOpBelowNextIndex(t *testing.T) {
	t.Parallel()

	ops := &fakeHorizonOps{
		account: &HorizonAccount{
			AccountID:         7,
			NextExternalIndex: 5,
		},
	}

	// The horizon index is below the persisted next-external index, so the
	// call must be a no-op.
	err := ExtendScanHorizon(t.Context(), ops, validChildDeriveFunc(),
		ScanHorizon{Branch: externalBranch, Index: 3})
	require.NoError(t, err)

	require.Empty(t, ops.inserted)
	require.False(t, ops.advanceCall)
}

// TestExtendScanHorizonNoOpAboveMaxBelowNextIndex verifies that a horizon above
// MaxAddressIndex is still accepted when the branch's next index already covers
// it, because no new recovery derivation is needed.
func TestExtendScanHorizonNoOpAboveMaxBelowNextIndex(t *testing.T) {
	t.Parallel()

	ops := &fakeHorizonOps{
		account: &HorizonAccount{
			AccountID:         7,
			NextExternalIndex: MaxAddressIndex + 2,
		},
	}

	err := ExtendScanHorizon(t.Context(), ops, validChildDeriveFunc(),
		ScanHorizon{Branch: externalBranch, Index: MaxAddressIndex + 1})
	require.NoError(t, err)

	require.Empty(t, ops.inserted)
	require.False(t, ops.advanceCall)
}

// TestExtendScanHorizonRejectsInvalidBranch verifies that a branch other than
// external or internal is rejected with ErrInvalidParam before any account
// load or derivation.
func TestExtendScanHorizonRejectsInvalidBranch(t *testing.T) {
	t.Parallel()

	ops := &fakeHorizonOps{account: &HorizonAccount{AccountID: 7}}

	err := ExtendScanHorizon(t.Context(), ops, validChildDeriveFunc(),
		ScanHorizon{Branch: 2, Index: 1})
	require.ErrorIs(t, err, ErrInvalidParam)

	require.Empty(t, ops.inserted)
	require.False(t, ops.advanceCall)
}

// TestExtendScanHorizonRejectsMaxIndex verifies that a horizon index above
// MaxAddressIndex is rejected with ErrMaxAddressIndexReached, matching the
// legacy address manager's per-account child bound.
func TestExtendScanHorizonRejectsMaxIndex(t *testing.T) {
	t.Parallel()

	ops := &fakeHorizonOps{account: &HorizonAccount{AccountID: 7}}

	err := ExtendScanHorizon(t.Context(), ops, validChildDeriveFunc(),
		ScanHorizon{Branch: externalBranch, Index: MaxAddressIndex + 1})
	require.ErrorIs(t, err, ErrMaxAddressIndexReached)

	require.Empty(t, ops.inserted)
	require.False(t, ops.advanceCall)
}

// TestExtendScanHorizonSkipsInvalidChild verifies that an HD-invalid child
// index is skipped without persisting a row while derivation advances to the
// next valid child, mirroring the legacy extendAddresses inner loop.
func TestExtendScanHorizonSkipsInvalidChild(t *testing.T) {
	t.Parallel()

	ops := &fakeHorizonOps{
		account: &HorizonAccount{
			AccountID:         7,
			NextExternalIndex: 0,
		},
	}

	// Index 1 derives an ErrInvalidChild, so it must be skipped: only indices
	// 0 and 2 are persisted while the loop still reaches horizon index 2.
	deriveFn := func(_ context.Context,
		params AddressDerivationParams) (*DerivedAddressData, error) {

		if params.Index == 1 {
			return nil, hdkeychain.ErrInvalidChild
		}

		return &DerivedAddressData{
			ScriptPubKey: []byte{0x00, 0x14},
			PubKey:       []byte{0x02},
		}, nil
	}

	err := ExtendScanHorizon(t.Context(), ops, deriveFn,
		ScanHorizon{Branch: externalBranch, Index: 2})
	require.NoError(t, err)

	// Index 1 was skipped; indices 0 and 2 were persisted.
	require.Equal(t, []uint32{0, 2}, ops.inserted)

	// The next index advanced past the last derived child.
	require.True(t, ops.advanceCall)
	require.Equal(t, uint32(3), ops.advancedTo)
}

// TestExtendScanHorizonInvalidChildSkipRespectsMaxIndex verifies that an
// invalid-child skip cannot derive or persist a child past MaxAddressIndex.
// The horizon index sits exactly at the bound, but the child there is
// HD-invalid; skipping it advances the candidate to MaxAddressIndex+1, which
// the extension must reject with ErrMaxAddressIndexReached rather than derive
// and insert an out-of-range row. Without the per-candidate bound re-check the
// loop would persist a child at MaxAddressIndex+1, exceeding the recovery
// bound validateHorizon enforces for the horizon index itself.
func TestExtendScanHorizonInvalidChildSkipRespectsMaxIndex(t *testing.T) {
	t.Parallel()

	// The branch's next index is already the bound, so the only candidate in
	// range is MaxAddressIndex itself.
	ops := &fakeHorizonOps{
		account: &HorizonAccount{
			AccountID:         7,
			NextExternalIndex: MaxAddressIndex,
		},
	}

	// The child at the bound is HD-invalid, so the inner loop skips it and
	// steps to MaxAddressIndex+1. The stub then reports a perfectly valid
	// child there: an unguarded loop would derive and INSERT that out-of-range
	// row before terminating, so the bound re-check, not the stub, must be
	// what stops the loop.
	deriveFn := func(_ context.Context,
		params AddressDerivationParams) (*DerivedAddressData, error) {

		if params.Index == MaxAddressIndex {
			return nil, hdkeychain.ErrInvalidChild
		}

		return &DerivedAddressData{
			ScriptPubKey: []byte{0x00, 0x14},
			PubKey:       []byte{0x02},
		}, nil
	}

	// The horizon index sits at the bound, so validateHorizon admits it and
	// the failure can only come from the post-skip candidate at
	// MaxAddressIndex+1.
	err := ExtendScanHorizon(t.Context(), ops, deriveFn,
		ScanHorizon{Branch: externalBranch, Index: MaxAddressIndex})
	require.ErrorIs(t, err, ErrMaxAddressIndexReached)

	// No child was persisted at or past the bound, and the next-index was
	// never advanced.
	require.Empty(t, ops.inserted)
	require.False(t, ops.advanceCall)
}

// TestExtendScanHorizonAdvancesAfterInserts verifies that, after deriving the
// full range, ExtendScanHorizon persists every child and advances the branch
// next-index to one past the last derived child.
func TestExtendScanHorizonAdvancesAfterInserts(t *testing.T) {
	t.Parallel()

	ops := &fakeHorizonOps{
		account: &HorizonAccount{
			AccountID:         7,
			NextInternalIndex: 1,
			AddrSchema: ScopeAddrSchema{
				InternalAddrType: WitnessPubKey,
				ExternalAddrType: WitnessPubKey,
			},
		},
	}

	// Extend the internal branch from its next index 1 through index 3.
	err := ExtendScanHorizon(t.Context(), ops, validChildDeriveFunc(),
		ScanHorizon{Branch: internalBranch, Index: 3})
	require.NoError(t, err)

	require.Equal(t, []uint32{1, 2, 3}, ops.inserted)
	require.True(t, ops.advanceCall)
	require.Equal(t, uint32(4), ops.advancedTo)
}

// capturingDeriveFunc returns a derivation callback that appends every
// DerivedAccountNumber it is handed to seen and, when requested, every
// AccountID it is handed to seenIDs. It lets tests assert the exact account
// identities the shared extension presents per child.
func capturingDeriveFunc(seen *[]*uint32,
	seenIDs ...*[]*uint32) AddressDerivationFunc {

	return func(_ context.Context,
		params AddressDerivationParams) (*DerivedAddressData, error) {

		*seen = append(*seen, params.DerivedAccountNumber)
		if len(seenIDs) > 0 {
			*seenIDs[0] = append(*seenIDs[0], params.AccountID)
		}

		return &DerivedAddressData{
			ScriptPubKey: []byte{0x00, 0x14},
			PubKey:       []byte{0x02},
		}, nil
	}
}

// TestExtendScanHorizonImportedAccountNilNumber verifies that extending the
// horizon of an imported xpub account presents a nil DerivedAccountNumber to
// the derivation callback. An imported account has no wallet-derived BIP44
// number (HorizonAccount.AccountNumber is nil), so the shared extension must
// forward nil and let derivation key off the account public key alone,
// honouring the AddressDerivationParams.DerivedAccountNumber contract. The old
// non-pointer field forced a literal account 0 here, masking an imported
// account as the default derived account.
func TestExtendScanHorizonImportedAccountNilNumber(t *testing.T) {
	t.Parallel()

	// An imported xpub account: no wallet-derived number.
	ops := &fakeHorizonOps{
		account: &HorizonAccount{
			AccountID:         7,
			AccountNumber:     nil,
			NextExternalIndex: 0,
			AddrSchema: ScopeAddrSchema{
				ExternalAddrType: WitnessPubKey,
				InternalAddrType: WitnessPubKey,
			},
		},
	}

	var (
		seen    []*uint32
		seenIDs []*uint32
	)

	err := ExtendScanHorizon(t.Context(), ops,
		capturingDeriveFunc(&seen, &seenIDs),
		ScanHorizon{Branch: externalBranch, Index: 1})
	require.NoError(t, err)

	// Two children were derived, and each must have been handed a nil
	// account number rather than a pointer to a fabricated account 0. The
	// Store account ID remains available for callbacks that need stable row
	// identity.
	require.Equal(t, []uint32{0, 1}, ops.inserted)
	require.Len(t, seen, 2)
	require.Len(t, seenIDs, 2)

	for i, num := range seen {
		require.Nilf(t, num, "child %d must carry a nil account number", i)
		require.NotNilf(t, seenIDs[i], "child %d must carry an account ID", i)
		require.Equalf(t, uint32(7), *seenIDs[i],
			"child %d must carry the store account ID", i)
	}
}

// TestExtendScanHorizonDerivedAccountKeepsNumber verifies that extending a
// wallet-derived account's horizon presents that account's real BIP44 number
// to the derivation callback, the contrasting shape to the imported-account
// case. It guards against a regression that would drop the derived number to
// nil along with the imported fix.
func TestExtendScanHorizonDerivedAccountKeepsNumber(t *testing.T) {
	t.Parallel()

	accountNumber := uint32(5)

	// A wallet-derived account: a real BIP44 number is present.
	ops := &fakeHorizonOps{
		account: &HorizonAccount{
			AccountID:         9,
			AccountNumber:     &accountNumber,
			NextExternalIndex: 0,
			AddrSchema: ScopeAddrSchema{
				ExternalAddrType: WitnessPubKey,
				InternalAddrType: WitnessPubKey,
			},
		},
	}

	var seen []*uint32

	err := ExtendScanHorizon(t.Context(), ops, capturingDeriveFunc(&seen),
		ScanHorizon{Branch: externalBranch, Index: 1})
	require.NoError(t, err)

	require.Equal(t, []uint32{0, 1}, ops.inserted)
	require.Len(t, seen, 2)

	for i, num := range seen {
		require.NotNilf(t, num, "child %d must carry an account number", i)
		require.Equalf(t, accountNumber, *num,
			"child %d must carry the derived account number", i)
	}
}
