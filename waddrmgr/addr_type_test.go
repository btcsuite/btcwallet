package waddrmgr

import (
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
)

var testChainParams = chaincfg.RegressionNetParams

// TestAddressTypeLookups verifies the supported address-type lookup paths.
func TestAddressTypeLookups(t *testing.T) {
	t.Parallel()

	scope, err := PubKeyHash.KeyScope()
	require.NoError(t, err)
	require.Equal(t, KeyScopeBIP0044, scope)

	schema, err := NestedWitnessPubKey.ScopeAddrSchema()
	require.NoError(t, err)
	require.Equal(t, NestedWitnessPubKey, schema.ExternalAddrType)
	require.Equal(t, WitnessPubKey, schema.InternalAddrType)

	addrTypeByScope, err := AddressTypeForScope(KeyScopeBIP0049Plus)
	require.NoError(t, err)
	require.Equal(t, NestedWitnessPubKey, addrTypeByScope)

	addrTypeByPurpose, err := AddressTypeForPurpose(KeyScopeBIP0086.Purpose)
	require.NoError(t, err)
	require.Equal(t, TaprootPubKey, addrTypeByPurpose)

	_, err = AddressType(255).AddrFromPubKeyBytes(nil, &testChainParams)
	require.ErrorIs(t, err, ErrUnknownAddressType)

	_, err = AddressTypeForScope(KeyScope{Purpose: 1017, Coin: 0})
	require.ErrorIs(t, err, ErrUnknownAddressType)

	_, err = AddressTypeForPurpose(1017)
	require.ErrorIs(t, err, ErrUnknownAddressType)

	_, err = Script.AddrFromPubKeyBytes(nil, &testChainParams)
	require.ErrorIs(t, err, ErrUnsupportedAddressType)
}

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

// TestSupportedSigningAddressType verifies signing metadata for the supported
// pubkey address types.
func TestSupportedSigningAddressType(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		addrType      AddressType
		signingMethod SigningMethod
	}{
		{
			name:          "pubkey hash",
			addrType:      PubKeyHash,
			signingMethod: SigningMethodLegacy,
		},
		{
			name:          "nested witness pubkey",
			addrType:      NestedWitnessPubKey,
			signingMethod: SigningMethodWitnessV0,
		},
		{
			name:          "witness pubkey",
			addrType:      WitnessPubKey,
			signingMethod: SigningMethodWitnessV0,
		},
		{
			name:          "taproot pubkey",
			addrType:      TaprootPubKey,
			signingMethod: SigningMethodTaprootKeySpend,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			signingMethod, err := testCase.addrType.SigningMethod()
			require.NoError(t, err)
			require.Equal(t, testCase.signingMethod, signingMethod)
		})
	}
}

// TestUnsupportedSigningAddressType verifies unsupported address types report
// no wallet signing path.
func TestUnsupportedSigningAddressType(t *testing.T) {
	t.Parallel()

	_, err := WitnessScript.SigningMethod()
	require.ErrorIs(t, err, ErrUnsupportedAddressType)

	_, err = AddressType(255).SigningMethod()
	require.ErrorIs(t, err, ErrUnknownAddressType)
}

// TestAddrFromPubKeyBytes verifies address reconstruction from the wallet's
// stored pubkey bytes for supported pubkey address types.
func TestAddrFromPubKeyBytes(t *testing.T) {
	t.Parallel()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	serializedPubKey := privKey.PubKey().SerializeCompressed()

	testCases := []struct {
		name     string
		addrType AddressType
		want     []byte
	}{
		{
			name:     "pubkey hash",
			addrType: PubKeyHash,
			want:     address.Hash160(serializedPubKey),
		},
		{
			name:     "nested witness pubkey",
			addrType: NestedWitnessPubKey,
			want: func() []byte {
				witnessProgram, err := nestedWitnessProgramFromPubKeyBytes(
					serializedPubKey, &testChainParams,
				)
				require.NoError(t, err)

				return address.Hash160(witnessProgram)
			}(),
		},
		{
			name:     "witness pubkey",
			addrType: WitnessPubKey,
			want:     address.Hash160(serializedPubKey),
		},
		{
			name:     "taproot pubkey",
			addrType: TaprootPubKey,
			want: schnorr.SerializePubKey(
				txscript.ComputeTaprootKeyNoScript(privKey.PubKey()),
			),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			address, err := testCase.addrType.AddrFromPubKeyBytes(
				serializedPubKey, &testChainParams,
			)
			require.NoError(t, err)

			require.Equal(t, testCase.want, address.ScriptAddress())
		})
	}
}
