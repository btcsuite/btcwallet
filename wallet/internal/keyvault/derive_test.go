package keyvault

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// TestDeriveChildMatchesLegacyOnCleanParent regression-guards the
// runtime-check helper: for a 32-byte parent (the common case for every
// existing wallet), DeriveChild must produce the exact same child
// bytes that the legacy DeriveNonStandard path would have, because that
// path is what every previously-persisted btcwallet key was derived
// under. Diverging here would silently lose UTXOs at any address that
// already lives on disk.
func TestDeriveChildMatchesLegacyOnCleanParent(t *testing.T) {
	t.Parallel()

	seed := bytes.Repeat([]byte{0xAA}, hdkeychain.RecommendedSeedLen)
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)
	require.False(
		t, masterKey.IsAffectedByIssue172(),
		"test seed should produce a full 32-byte master key",
	)

	for _, i := range []uint32{
		hdkeychain.HardenedKeyStart,
		hdkeychain.HardenedKeyStart + 1,
		hdkeychain.HardenedKeyStart + 7,
		hdkeychain.HardenedKeyStart + 49,
		hdkeychain.HardenedKeyStart + 84,
	} {
		got, err := DeriveChild(masterKey, i)
		require.NoError(t, err)

		//nolint:staticcheck
		want, err := masterKey.DeriveNonStandard(i)
		require.NoError(t, err)

		require.Equal(
			t, want.String(), got.String(),
			"DeriveChild(%d) must match DeriveNonStandard on a clean parent",
			i,
		)
	}
}
