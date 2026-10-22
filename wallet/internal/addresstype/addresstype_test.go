package addresstype

import (
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestFromWallet verifies wallet-facing address types map to store address
// types and script metadata.
func TestFromWallet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		addrType   waddrmgr.AddressType
		wantType   db.AddressType
		wantScript bool
		wantErr    bool
	}{
		{
			name:     "raw pubkey",
			addrType: waddrmgr.RawPubKey,
			wantType: db.RawPubKey,
		},
		{
			name:     "pubkey hash",
			addrType: waddrmgr.PubKeyHash,
			wantType: db.PubKeyHash,
		},
		{
			name:       "script hash",
			addrType:   waddrmgr.Script,
			wantType:   db.ScriptHash,
			wantScript: true,
		},
		{
			name:     "nested witness pubkey",
			addrType: waddrmgr.NestedWitnessPubKey,
			wantType: db.NestedWitnessPubKey,
		},
		{
			name:     "witness pubkey",
			addrType: waddrmgr.WitnessPubKey,
			wantType: db.WitnessPubKey,
		},
		{
			name:       "witness script",
			addrType:   waddrmgr.WitnessScript,
			wantType:   db.WitnessScript,
			wantScript: true,
		},
		{
			name:     "taproot pubkey",
			addrType: waddrmgr.TaprootPubKey,
			wantType: db.TaprootPubKey,
		},
		{
			name:       "taproot script",
			addrType:   waddrmgr.TaprootScript,
			wantType:   db.TaprootPubKey,
			wantScript: true,
		},
		{
			name:     "unknown",
			addrType: waddrmgr.AddressType(255),
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := FromWallet(tc.addrType)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrUnknown)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantType, got.Type)
			require.Equal(t, tc.wantScript, got.HasScript)
		})
	}
}

// TestToWallet verifies store address types and script metadata map back to
// wallet-facing address types.
func TestToWallet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		addrType  db.AddressType
		hasScript bool
		want      waddrmgr.AddressType
		wantErr   bool
	}{
		{
			name:     "raw pubkey",
			addrType: db.RawPubKey,
			want:     waddrmgr.RawPubKey,
		},
		{
			name:     "pubkey hash",
			addrType: db.PubKeyHash,
			want:     waddrmgr.PubKeyHash,
		},
		{
			name:      "script hash with metadata",
			addrType:  db.ScriptHash,
			hasScript: true,
			want:      waddrmgr.Script,
		},
		{
			name:     "nested witness pubkey",
			addrType: db.NestedWitnessPubKey,
			want:     waddrmgr.NestedWitnessPubKey,
		},
		{
			name:     "witness pubkey",
			addrType: db.WitnessPubKey,
			want:     waddrmgr.WitnessPubKey,
		},
		{
			name:      "witness script with metadata",
			addrType:  db.WitnessScript,
			hasScript: true,
			want:      waddrmgr.WitnessScript,
		},
		{
			name:     "taproot pubkey",
			addrType: db.TaprootPubKey,
			want:     waddrmgr.TaprootPubKey,
		},
		{
			name:      "taproot script",
			addrType:  db.TaprootPubKey,
			hasScript: true,
			want:      waddrmgr.TaprootScript,
		},
		{
			name:     "anchor unsupported",
			addrType: db.Anchor,
			wantErr:  true,
		},
		{
			name:     "unknown",
			addrType: db.AddressType(255),
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ToWallet(tc.addrType, tc.hasScript)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrUnknown)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
