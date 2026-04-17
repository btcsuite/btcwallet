package waddrmgr

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPubKeyAddressTypeMetadata verifies the common metadata for pubkey address
// types.
func TestPubKeyAddressTypeMetadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		addrType          AddressType
		spendType         SpendType
		derivationScheme  DerivationScheme
		pkScriptSize      int
		hasWitnessVersion bool
		witnessVersion    byte
	}{
		{
			name:             "pubkey hash",
			addrType:         PubKeyHash,
			spendType:        SpendTypeLegacyKey,
			derivationScheme: DerivationSchemeBIP44,
			pkScriptSize:     p2pkhPkScriptSize,
		},
		{
			name:              "nested witness pubkey",
			addrType:          NestedWitnessPubKey,
			spendType:         SpendTypeNestedWitnessKey,
			derivationScheme:  DerivationSchemeBIP49,
			pkScriptSize:      nestedP2WPKHPkScriptSize,
			hasWitnessVersion: true,
			witnessVersion:    witnessVersionV0,
		},
		{
			name:              "witness pubkey",
			addrType:          WitnessPubKey,
			spendType:         SpendTypeWitnessKey,
			derivationScheme:  DerivationSchemeBIP84,
			pkScriptSize:      p2wpkhPkScriptSize,
			hasWitnessVersion: true,
			witnessVersion:    witnessVersionV0,
		},
		{
			name:              "taproot pubkey",
			addrType:          TaprootPubKey,
			spendType:         SpendTypeTaprootKeyPath,
			derivationScheme:  DerivationSchemeBIP86,
			pkScriptSize:      p2trPkScriptSize,
			hasWitnessVersion: true,
			witnessVersion:    witnessVersionV1,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, testCase.spendType,
				testCase.addrType.SpendType())
			require.Equal(t, testCase.derivationScheme,
				testCase.addrType.DerivationScheme())

			pkScriptSize, err := testCase.addrType.ScriptPubKeySize()
			require.NoError(t, err)
			require.Equal(t, testCase.pkScriptSize, pkScriptSize)

			version, err := testCase.addrType.WitnessVersion()
			if testCase.hasWitnessVersion {
				require.NoError(t, err)
				require.Equal(t, testCase.witnessVersion, version)
			} else {
				require.ErrorIs(t, err, ErrUnsupportedAddressType)
			}
		})
	}
}

// TestScriptAddressTypeMetadata verifies the common metadata for script-driven
// address types.
func TestScriptAddressTypeMetadata(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		addrType          AddressType
		spendType         SpendType
		pkScriptSize      int
		hasWitnessVersion bool
		witnessVersion    byte
	}{
		{
			name:         "script hash",
			addrType:     Script,
			spendType:    SpendTypeScriptHash,
			pkScriptSize: p2shPkScriptSize,
		},
		{
			name:              "witness script hash",
			addrType:          WitnessScript,
			spendType:         SpendTypeWitnessScript,
			pkScriptSize:      p2wshPkScriptSize,
			hasWitnessVersion: true,
			witnessVersion:    witnessVersionV0,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, testCase.spendType,
				testCase.addrType.SpendType())

			pkScriptSize, err := testCase.addrType.ScriptPubKeySize()
			require.NoError(t, err)
			require.Equal(t, testCase.pkScriptSize, pkScriptSize)

			version, err := testCase.addrType.WitnessVersion()
			if testCase.hasWitnessVersion {
				require.NoError(t, err)
				require.Equal(t, testCase.witnessVersion, version)
			} else {
				require.ErrorIs(t, err, ErrUnsupportedAddressType)
			}
		})
	}
}

// TestTaprootScriptAddressType verifies the taproot script type still has
// meaningful common metadata.
func TestTaprootScriptAddressType(t *testing.T) {
	t.Parallel()

	require.Equal(t, SpendTypeTaprootScriptPath, TaprootScript.SpendType())
	require.Equal(t, DerivationSchemeNone, TaprootScript.DerivationScheme())

	size, err := TaprootScript.ScriptPubKeySize()
	require.NoError(t, err)
	require.Equal(t, p2trPkScriptSize, size)

	version, err := TaprootScript.WitnessVersion()
	require.NoError(t, err)
	require.Equal(t, witnessVersionV1, version)
}

// TestRawPubKeyAddressType verifies the raw-pubkey address type retains only
// the common metadata that naturally applies to it.
func TestRawPubKeyAddressType(t *testing.T) {
	t.Parallel()

	require.Equal(t, SpendTypeUnknown, RawPubKey.SpendType())
	require.Equal(t, DerivationSchemeNone, RawPubKey.DerivationScheme())

	_, err := RawPubKey.ScriptPubKeySize()
	require.ErrorIs(t, err, ErrUnsupportedAddressType)

	_, err = RawPubKey.WitnessVersion()
	require.ErrorIs(t, err, ErrUnsupportedAddressType)
}
