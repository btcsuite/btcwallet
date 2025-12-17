//go:build itest

package itest

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

func TestListAddressTypes(t *testing.T) {
	t.Parallel()
	store, _ := NewTestStore(t)

	types, err := store.ListAddressTypes(t.Context())
	require.NoError(t, err)

	want := []db.AddressTypeInfo{
		{Type: db.RawPubKey, Description: "P2PK"},
		{Type: db.PubKeyHash, Description: "P2PKH"},
		{Type: db.ScriptHash, Description: "P2SH"},
		{Type: db.NestedWitnessPubKey, Description: "P2SH-P2WPKH"},
		{Type: db.WitnessPubKey, Description: "P2WPKH"},
		{Type: db.WitnessScript, Description: "P2WSH"},
		{Type: db.TaprootPubKey, Description: "P2TR"},
		{Type: db.Anchor, Description: "P2A"},
	}

	require.Equal(t, want, types)
}

func TestGetAddressType(t *testing.T) {
	t.Parallel()
	store, _ := NewTestStore(t)

	tests := []struct {
		id         db.AddressType
		wantResult *db.AddressTypeInfo
		wantErr    error
	}{
		{
			id: 0,
			wantResult: &db.AddressTypeInfo{
				Type:        db.RawPubKey,
				Description: "P2PK",
			},
		},
		{
			id: 1,
			wantResult: &db.AddressTypeInfo{
				Type:        db.PubKeyHash,
				Description: "P2PKH",
			},
		},
		{
			id: 2,
			wantResult: &db.AddressTypeInfo{
				Type:        db.ScriptHash,
				Description: "P2SH",
			},
		},
		{
			id: 3,
			wantResult: &db.AddressTypeInfo{
				Type:        db.NestedWitnessPubKey,
				Description: "P2SH-P2WPKH",
			},
		},
		{
			id: 4,
			wantResult: &db.AddressTypeInfo{
				Type:        db.WitnessPubKey,
				Description: "P2WPKH",
			},
		},
		{
			id: 5,
			wantResult: &db.AddressTypeInfo{
				Type:        db.WitnessScript,
				Description: "P2WSH",
			},
		},
		{
			id: 6,
			wantResult: &db.AddressTypeInfo{
				Type:        db.TaprootPubKey,
				Description: "P2TR",
			},
		},
		{
			id: 7,
			wantResult: &db.AddressTypeInfo{
				Type:        db.Anchor,
				Description: "P2A",
			},
		},
		{
			// Means last valid plus one, so it should be invalid
			id:      8,
			wantErr: db.ErrAddressTypeNotFound,
		},
		{
			// some other invalid id
			id:      100,
			wantErr: db.ErrAddressTypeNotFound,
		},
	}

	for _, tc := range tests {
		name := fmt.Sprintf("id_%d_expect_", tc.id)
		if tc.wantResult != nil {
			name += tc.wantResult.Description
		} else {
			name += tc.wantErr.Error()
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := store.GetAddressType(t.Context(), tc.id)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, *tc.wantResult, got)
		})
	}
}
