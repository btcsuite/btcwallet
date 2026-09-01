package db

import (
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestAccountRowToInfoPopulatesAddrSchema verifies SQL account rows expose the
// effective key-scope address schema on AccountInfo, including the schema
// values returned by AccountRowToInfo.
func TestAccountRowToInfoPopulatesAddrSchema(t *testing.T) {
	t.Parallel()

	row := AccountInfoRow[int16]{
		RowID:            42,
		AccountNumber:    sql.NullInt64{Int64: 7, Valid: true},
		AccountName:      "strict",
		IsDerived:        true,
		ExternalKeyCount: 1,
		InternalKeyCount: 2,
		CreatedAt:        time.Unix(123, 0).UTC(),
		Purpose:          49,
		CoinType:         0,
		InternalTypeID:   int16(NestedWitnessPubKey),
		ExternalTypeID:   int16(NestedWitnessPubKey),
	}

	info, err := AccountRowToInfo(row)
	require.NoError(t, err)
	require.Equal(t, ScopeAddrSchema{
		ExternalAddrType: NestedWitnessPubKey,
		InternalAddrType: NestedWitnessPubKey,
	}, info.AddrSchema)
	require.Equal(t, int64(42), info.rowID)
}

// TestAccountInfoConversionsPreserveNoChainSync verifies both normalized SQL
// row shapes carry the stored synchronization policy into AccountInfo without
// interpreting or applying it.
func TestAccountInfoConversionsPreserveNoChainSync(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		noChainSync bool
	}{
		{
			name:        "chain synchronized",
			noChainSync: false,
		},
		{
			name:        "automatic sync disabled",
			noChainSync: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: build both row shapes from the same valid derived
			// account identity, varying only the persisted policy bit. The
			// address type IDs keep conversion focused on policy propagation.
			accountNumber := sql.NullInt64{Int64: 7, Valid: true}
			infoRow := AccountInfoRow[int16]{
				AccountNumber:  accountNumber,
				AccountName:    "derived",
				IsDerived:      true,
				NoChainSync:    test.noChainSync,
				InternalTypeID: int16(WitnessPubKey),
				ExternalTypeID: int16(WitnessPubKey),
			}
			propsRow := AccountPropsRow[int16]{
				AccountNumber:  accountNumber,
				AccountName:    "derived",
				IsDerived:      true,
				NoChainSync:    test.noChainSync,
				InternalTypeID: int16(WitnessPubKey),
				ExternalTypeID: int16(WitnessPubKey),
			}

			// Act: convert the list/get row and the property row through
			// their independent normalization paths.
			info, infoErr := AccountRowToInfo(infoRow)
			props, propsErr := AccountPropsRowToInfo(propsRow)

			// Assert: both conversions succeed and preserve the exact stored
			// value, proving neither path falls back to Go's false zero value.
			require.NoError(t, infoErr)
			require.NoError(t, propsErr)
			require.Equal(t, test.noChainSync, info.NoChainSync)
			require.Equal(t, test.noChainSync, props.NoChainSync)
		})
	}
}

// TestOptionalMasterFingerprintPreservesPresence verifies SQL NULL and valid
// values remain distinguishable, including a valid zero fingerprint.
func TestOptionalMasterFingerprintPreservesPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value sql.NullInt64
		want  *uint32
	}{
		{
			name: "absent",
		},
		{
			name:  "present zero",
			value: sql.NullInt64{Valid: true},
			want:  ptrUint32(0),
		},
		{
			name: "present nonzero",
			value: sql.NullInt64{
				Int64: 42,
				Valid: true,
			},
			want: ptrUint32(42),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := optionalMasterFingerprint(test.value)

			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

// TestScopeAddrSchemaFromWaddrmgr verifies legacy address-manager schemas are
// converted into the database account schema shape.
func TestScopeAddrSchemaFromWaddrmgr(t *testing.T) {
	t.Parallel()

	schema, err := ScopeAddrSchemaFromWaddrmgr(waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.NestedWitnessPubKey,
		InternalAddrType: waddrmgr.WitnessPubKey,
	})
	require.NoError(t, err)
	require.Equal(t, ScopeAddrSchema{
		ExternalAddrType: NestedWitnessPubKey,
		InternalAddrType: WitnessPubKey,
	}, schema)

	// BIP44 schemas (waddrmgr.PubKeyHash external + waddrmgr.PubKeyHash
	// internal) regression test for the enum-ordinal mismatch.
	schema, err = ScopeAddrSchemaFromWaddrmgr(waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.PubKeyHash,
		InternalAddrType: waddrmgr.PubKeyHash,
	})
	require.NoError(t, err)
	require.Equal(t, ScopeAddrSchema{
		ExternalAddrType: PubKeyHash,
		InternalAddrType: PubKeyHash,
	}, schema)
}

// TestAddrTypeToWaddrmgr verifies every database address type with a
// legacy waddrmgr representation maps explicitly rather than by ordinal.
func TestAddrTypeToWaddrmgr(t *testing.T) {
	t.Parallel()

	// The three legacy values below have different ordinals in the database
	// and waddrmgr enums, which is why this conversion cannot use a cast.
	require.NotEqual(t, uint8(RawPubKey), uint8(waddrmgr.RawPubKey))
	require.NotEqual(t, uint8(PubKeyHash), uint8(waddrmgr.PubKeyHash))
	require.NotEqual(t, uint8(ScriptHash), uint8(waddrmgr.Script))

	testCases := []struct {
		name  string
		input AddressType
		want  waddrmgr.AddressType
	}{
		{
			name:  "raw pubkey",
			input: RawPubKey,
			want:  waddrmgr.RawPubKey,
		},
		{
			name:  "pubkey hash",
			input: PubKeyHash,
			want:  waddrmgr.PubKeyHash,
		},
		{
			name:  "script hash",
			input: ScriptHash,
			want:  waddrmgr.Script,
		},
		{
			name:  "nested witness pubkey",
			input: NestedWitnessPubKey,
			want:  waddrmgr.NestedWitnessPubKey,
		},
		{
			name:  "witness pubkey",
			input: WitnessPubKey,
			want:  waddrmgr.WitnessPubKey,
		},
		{
			name:  "witness script",
			input: WitnessScript,
			want:  waddrmgr.WitnessScript,
		},
		{
			name:  "taproot pubkey",
			input: TaprootPubKey,
			want:  waddrmgr.TaprootPubKey,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := addrTypeToWaddrmgr(testCase.input)

			require.NoError(t, err)
			require.Equal(t, testCase.want, got)
		})
	}
}

// TestAddrTypeToWaddrmgrRejectsUnrepresentable verifies address types that
// have no legacy waddrmgr representation return ErrInvalidParam.
func TestAddrTypeToWaddrmgrRejectsUnrepresentable(t *testing.T) {
	t.Parallel()

	testCases := []AddressType{
		Anchor,
		AddressType(255),
	}
	for _, testCase := range testCases {
		_, err := addrTypeToWaddrmgr(testCase)

		require.ErrorIs(t, err, ErrInvalidParam)
	}
}

// TestScopeAddrSchemaToWaddrmgr verifies database schemas are converted into
// the legacy address-manager shape with branch-specific conversion errors.
func TestScopeAddrSchemaToWaddrmgr(t *testing.T) {
	t.Parallel()

	schema, err := ScopeAddrSchemaToWaddrmgr(
		ScopeAddrSchema{
			ExternalAddrType: PubKeyHash,
			InternalAddrType: PubKeyHash,
		},
	)
	require.NoError(t, err)
	require.Equal(
		t, waddrmgr.ScopeAddrSchema{
			ExternalAddrType: waddrmgr.PubKeyHash,
			InternalAddrType: waddrmgr.PubKeyHash,
		}, schema,
	)

	_, err = ScopeAddrSchemaToWaddrmgr(
		ScopeAddrSchema{
			ExternalAddrType: Anchor,
			InternalAddrType: WitnessPubKey,
		},
	)
	require.ErrorIs(t, err, ErrInvalidParam)
	require.ErrorContains(t, err, "external:")

	_, err = ScopeAddrSchemaToWaddrmgr(
		ScopeAddrSchema{
			ExternalAddrType: WitnessPubKey,
			InternalAddrType: Anchor,
		},
	)
	require.ErrorIs(t, err, ErrInvalidParam)
	require.ErrorContains(t, err, "internal:")
}
