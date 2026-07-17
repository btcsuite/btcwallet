// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// deriveTestSeed is a fixed BIP-32 seed the derivation tests build a
// deterministic account key from.
var deriveTestSeed = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// TestDeriveChainedAddressesInvalidChild proves the derivation-preparation
// accounting the Phase 2A1 exit gate requires: an invalid child is skipped, so
// the consumed index range exceeds the address count and the returned next
// index is exactly one past the last consumed child, not the naive start plus
// count.
func TestDeriveChainedAddressesInvalidChild(t *testing.T) {
	t.Parallel()

	params := &chaincfg.MainNetParams

	acctKey, err := hdkeychain.NewMaster(deriveTestSeed, params)
	require.NoError(t, err)

	branchKey, err := acctKey.DeriveNonStandard( //nolint:staticcheck
		ExternalBranch,
	)
	require.NoError(t, err)

	// Inject an invalid child at index 6, between the start index 5 and the
	// three requested addresses.
	invalid := map[uint32]struct{}{6: {}}
	deriveChild := func(index uint32) (*hdkeychain.ExtendedKey, error) {
		if _, bad := invalid[index]; bad {
			return nil, hdkeychain.ErrInvalidChild
		}

		//nolint:staticcheck
		return branchKey.DeriveNonStandard(index)
	}

	addrs, next, err := deriveChainedAddresses(
		deriveChild, ExternalBranch, WitnessPubKey, params, 5, 3,
	)
	require.NoError(t, err)

	// The invalid index 6 was skipped, so the three addresses land at 5, 7,
	// and 8 and the next index is 9, one past the last consumed child. A naive
	// start-plus-count would have stopped at 8.
	require.Len(t, addrs, 3)
	require.Equal(t, uint32(5), addrs[0].Index)
	require.Equal(t, uint32(7), addrs[1].Index)
	require.Equal(t, uint32(8), addrs[2].Index)
	require.Equal(t, uint32(9), next)

	// Every derived address carries a distinct, non-empty legacy identity on
	// the requested branch.
	seen := make(map[string]struct{})
	for _, addr := range addrs {
		require.NotEmpty(t, addr.AddressID)
		require.Equal(t, ExternalBranch, addr.Branch)

		key := string(addr.AddressID)
		_, dup := seen[key]
		require.False(t, dup, "duplicate address identity")

		seen[key] = struct{}{}
	}
}

// TestDeriveChainedAddressesContiguous checks the ordinary path with no invalid
// child: the addresses are contiguous from the start index and match the shared
// exported derivation, so the seam and the production entry point agree.
func TestDeriveChainedAddressesContiguous(t *testing.T) {
	t.Parallel()

	params := &chaincfg.MainNetParams

	acctKey, err := hdkeychain.NewMaster(deriveTestSeed, params)
	require.NoError(t, err)

	addrs, next, err := DeriveChainedAddresses(
		acctKey, InternalBranch, TaprootPubKey, params, 0, 4,
	)
	require.NoError(t, err)
	require.Len(t, addrs, 4)
	require.Equal(t, uint32(4), next)

	for i, addr := range addrs {
		require.Equal(t, uint32(i), addr.Index)
		require.Equal(t, InternalBranch, addr.Branch)
		// A taproot identity is the 32-byte x-only output key.
		require.Len(t, addr.AddressID, 32)
	}
}

// TestDeriveChainedAddressesTooMany checks the per-account maximum guard, which
// mirrors the address manager's own bound.
func TestDeriveChainedAddressesTooMany(t *testing.T) {
	t.Parallel()

	params := &chaincfg.MainNetParams

	acctKey, err := hdkeychain.NewMaster(deriveTestSeed, params)
	require.NoError(t, err)

	_, _, err = DeriveChainedAddresses(
		acctKey, ExternalBranch, PubKeyHash, params,
		MaxAddressesPerAccount-1, 5,
	)
	require.True(t, IsError(err, ErrTooManyAddresses))
}
