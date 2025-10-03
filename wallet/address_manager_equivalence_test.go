package wallet

import (
	"bytes"
	"context"
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestEquivalence_NewAndChangeAddress compares the new NewAddress API with the
// deprecated NewAddressDeprecated/NewChangeAddress APIs for multiple address
// types.
func TestEquivalence_NewAndChangeAddress(t *testing.T) {
	t.Parallel()

	// Use the same seed for both wallets to ensure they generate identical
	// address sequences, allowing us to verify API equivalence.
	seed := bytes.Repeat([]byte{0x42}, 32)

	cases := []struct {
		name     string
		addrType waddrmgr.AddressType
		scope    waddrmgr.KeyScope
	}{
		{"p2pkh", waddrmgr.PubKeyHash, waddrmgr.KeyScopeBIP0044},
		{"p2wkh", waddrmgr.WitnessPubKey, waddrmgr.KeyScopeBIP0084},
		{
			"np2wkh",
			waddrmgr.NestedWitnessPubKey,
			waddrmgr.KeyScopeBIP0049Plus,
		},
		{"p2tr", waddrmgr.TaprootPubKey, waddrmgr.KeyScopeBIP0086},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wNewWallet, cleanup := testWalletWithSeed(t, seed)
			t.Cleanup(cleanup)

			var wNew AddressManager = wNewWallet

			wOld, cleanupOld := testWalletWithSeed(t, seed)
			t.Cleanup(cleanupOld)

			gotNew, err := wNew.NewAddress(
				context.Background(),
				"default",
				tc.addrType,
				false,
			)
			require.NoError(t, err)

			gotOld, err := wOld.NewAddressDeprecated(0, tc.scope)
			require.NoError(t, err)
			require.Equal(t, gotOld.String(), gotNew.String())

			gotNewChg, err := wNew.NewAddress(
				context.Background(),
				"default",
				tc.addrType,
				true,
			)
			require.NoError(t, err)

			gotOldChg, err := wOld.NewChangeAddress(0, tc.scope)
			require.NoError(t, err)
			require.Equal(t, gotOldChg.String(), gotNewChg.String())
		})
	}
}
