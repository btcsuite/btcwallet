package waddrmgr

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

const (
	// p2pkhPkScriptSize is the fixed scriptPubKey size for P2PKH outputs.
	// 25 bytes = OP_DUP (1) + OP_HASH160 (1) + OP_DATA_20 (1) +
	// <pubkey hash> (20) + OP_EQUALVERIFY (1) + OP_CHECKSIG (1).
	p2pkhPkScriptSize = 25

	// p2shPkScriptSize is the fixed scriptPubKey size for P2SH outputs.
	// 23 bytes = OP_HASH160 (1) + OP_DATA_20 (1) + <script hash> (20) +
	// OP_EQUAL (1).
	p2shPkScriptSize = 23

	// p2wpkhPkScriptSize is the fixed scriptPubKey size for native P2WPKH
	// outputs.
	// 22 bytes = OP_0 (1) + OP_DATA_20 (1) + <pubkey hash> (20).
	p2wpkhPkScriptSize = 22

	// p2wshPkScriptSize is the fixed scriptPubKey size for native P2WSH
	// outputs.
	// 34 bytes = OP_0 (1) + OP_DATA_32 (1) + <script hash> (32).
	p2wshPkScriptSize = 34

	// p2trPkScriptSize is the fixed scriptPubKey size for P2TR outputs.
	// 34 bytes = OP_1 (1) + OP_DATA_32 (1) + <x-only output key> (32).
	p2trPkScriptSize = 34

	// nestedP2WPKHPkScriptSize is the outer P2SH scriptPubKey size used by
	// nested P2WPKH outputs.
	// 23 bytes = OP_HASH160 (1) + OP_DATA_20 (1) +
	// HASH160(<inner witness program>) (20) + OP_EQUAL (1).
	nestedP2WPKHPkScriptSize = p2shPkScriptSize
)

var (
	// ErrUnknownAddressType is returned when no supported address type exists
	// for a lookup key.
	ErrUnknownAddressType = errors.New("unknown address type")

	// ErrUnsupportedAddressType is returned when an address type is known but a
	// specific API does not support it.
	ErrUnsupportedAddressType = errors.New("unsupported address type")
)

// SpendType captures the spend behavior implied by an address type.
type SpendType uint8

const (
	// SpendTypeUnknown is used when no standard spend template applies, such as
	// RawPubKey.
	SpendTypeUnknown SpendType = iota

	// SpendTypeLegacyKey is a direct legacy key spend, for example PubKeyHash.
	SpendTypeLegacyKey

	// SpendTypeScriptHash is a generic redeem-script spend, for example Script.
	SpendTypeScriptHash

	// SpendTypeNestedWitnessKey is a nested P2WPKH-in-P2SH spend, for example
	// NestedWitnessPubKey.
	SpendTypeNestedWitnessKey

	// SpendTypeWitnessKey is a native witness key spend, for example
	// WitnessPubKey.
	SpendTypeWitnessKey

	// SpendTypeWitnessScript is a witness-script spend, for example
	// WitnessScript.
	SpendTypeWitnessScript

	// SpendTypeTaprootKeyPath is a taproot key-path spend, for example
	// TaprootPubKey.
	SpendTypeTaprootKeyPath

	// SpendTypeTaprootScriptPath is a taproot script-path spend, for example
	// TaprootScript.
	SpendTypeTaprootScriptPath

	// SpendTypeAnyoneCanSpend is an anyone-can-spend policy output, for
	// example a future anchor-only address type.
	SpendTypeAnyoneCanSpend
)

// DerivationScheme captures the wallet derivation policy implied by an address
// type.
type DerivationScheme uint8

const (
	// DerivationSchemeNone indicates that no standard account derivation scheme
	// applies, for example Script or TaprootScript.
	DerivationSchemeNone DerivationScheme = iota

	// DerivationSchemeBIP44 indicates BIP44 account derivation, for example the
	// mainnet path m/44'/0'/0'/0/7.
	DerivationSchemeBIP44

	// DerivationSchemeBIP49 indicates BIP49 account derivation, for example the
	// mainnet path m/49'/0'/0'/0/7.
	DerivationSchemeBIP49

	// DerivationSchemeBIP84 indicates BIP84 account derivation, for example the
	// mainnet path m/84'/0'/0'/0/7.
	DerivationSchemeBIP84

	// DerivationSchemeBIP86 indicates BIP86 account derivation, for example the
	// mainnet path m/86'/0'/0'/0/7.
	DerivationSchemeBIP86
)

// SigningMethod identifies the wallet signing flow currently supported for an
// address type.
type SigningMethod uint8

const (
	// SigningMethodLegacy indicates legacy ECDSA signing against a non-witness
	// pkScript, for example PubKeyHash.
	SigningMethodLegacy SigningMethod = iota

	// SigningMethodWitnessV0 indicates SegWit v0 ECDSA signing, for example
	// WitnessPubKey or NestedWitnessPubKey.
	SigningMethodWitnessV0

	// SigningMethodTaprootKeySpend indicates Taproot key-path Schnorr signing,
	// for example TaprootPubKey.
	SigningMethodTaprootKeySpend
)

// AddressTypeForScope returns the default address type used by the given key
// scope.
func AddressTypeForScope(scope KeyScope) (AddressType, error) {
	switch scope {
	case KeyScopeBIP0044:
		return PubKeyHash, nil

	case KeyScopeBIP0049Plus:
		return NestedWitnessPubKey, nil

	case KeyScopeBIP0084:
		return WitnessPubKey, nil

	case KeyScopeBIP0086:
		return TaprootPubKey, nil

	default:
		return 0, fmt.Errorf("%w: %v", ErrUnknownAddressType, scope)
	}
}

// AddressTypeForPurpose returns the default address type used by the given BIP
// purpose.
func AddressTypeForPurpose(purpose uint32) (AddressType, error) {
	switch purpose {
	case KeyScopeBIP0044.Purpose:
		return PubKeyHash, nil

	case KeyScopeBIP0049Plus.Purpose:
		return NestedWitnessPubKey, nil

	case KeyScopeBIP0084.Purpose:
		return WitnessPubKey, nil

	case KeyScopeBIP0086.Purpose:
		return TaprootPubKey, nil

	default:
		return 0, fmt.Errorf("%w: %d", ErrUnknownAddressType, purpose)
	}
}

// SpendType returns the spend behavior implied by the address type. Unknown
// address types return SpendTypeUnknown.
func (a AddressType) SpendType() SpendType {
	switch a {
	case PubKeyHash:
		return SpendTypeLegacyKey

	case Script:
		return SpendTypeScriptHash

	case NestedWitnessPubKey:
		return SpendTypeNestedWitnessKey

	case WitnessPubKey:
		return SpendTypeWitnessKey

	case WitnessScript:
		return SpendTypeWitnessScript

	case TaprootPubKey:
		return SpendTypeTaprootKeyPath

	case TaprootScript:
		return SpendTypeTaprootScriptPath

	case RawPubKey:
		return SpendTypeUnknown

	default:
		return SpendTypeUnknown
	}
}

// DerivationScheme returns the wallet derivation scheme implied by the address
// type. Unknown address types return DerivationSchemeNone.
func (a AddressType) DerivationScheme() DerivationScheme {
	switch a {
	case PubKeyHash:
		return DerivationSchemeBIP44

	case NestedWitnessPubKey:
		return DerivationSchemeBIP49

	case WitnessPubKey:
		return DerivationSchemeBIP84

	case TaprootPubKey:
		return DerivationSchemeBIP86

	case Script, RawPubKey, WitnessScript, TaprootScript:
		return DerivationSchemeNone

	default:
		return DerivationSchemeNone
	}
}

// KeyScope returns the preferred scoped-manager key scope for the address type.
func (a AddressType) KeyScope() (KeyScope, error) {
	switch a {
	case PubKeyHash:
		return KeyScopeBIP0044, nil

	case NestedWitnessPubKey:
		return KeyScopeBIP0049Plus, nil

	case WitnessPubKey:
		return KeyScopeBIP0084, nil

	case TaprootPubKey:
		return KeyScopeBIP0086, nil

	case Script, RawPubKey, WitnessScript, TaprootScript:
		return KeyScope{}, fmt.Errorf("%w: %v", ErrUnsupportedAddressType, a)

	default:
		return KeyScope{}, fmt.Errorf("%w: %v", ErrUnknownAddressType, a)
	}
}

// ScopeAddrSchema returns the scoped-manager external/internal schema for the
// address type.
func (a AddressType) ScopeAddrSchema() (*ScopeAddrSchema, error) {
	switch a {
	// BIP49 keeps nested witness on the external branch but uses native
	// witness change outputs on the internal branch.
	case NestedWitnessPubKey:
		return &ScopeAddrSchema{
			ExternalAddrType: NestedWitnessPubKey,
			InternalAddrType: WitnessPubKey,
		}, nil

	// The other key-derived scopes use the same address type for both
	// external receives and internal change.
	case PubKeyHash, WitnessPubKey, TaprootPubKey:
		return &ScopeAddrSchema{
			ExternalAddrType: a,
			InternalAddrType: a,
		}, nil

	case Script, RawPubKey, WitnessScript, TaprootScript:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAddressType, a)

	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownAddressType, a)
	}
}

// ScriptPubKeySize returns the fixed outer scriptPubKey size for the address
// type, if the outer form has one.
func (a AddressType) ScriptPubKeySize() (int, error) {
	switch a {
	case PubKeyHash:
		return p2pkhPkScriptSize, nil

	case Script, NestedWitnessPubKey:
		return p2shPkScriptSize, nil

	case WitnessPubKey:
		return p2wpkhPkScriptSize, nil

	case WitnessScript:
		return p2wshPkScriptSize, nil

	case TaprootPubKey, TaprootScript:
		return p2trPkScriptSize, nil

	case RawPubKey:
		return 0, fmt.Errorf("%w: %v", ErrUnsupportedAddressType, a)

	default:
		return 0, fmt.Errorf("%w: %v", ErrUnknownAddressType, a)
	}
}

// WitnessVersion returns the witness version for the address type, if it uses
// a witness program.
func (a AddressType) WitnessVersion() (byte, error) {
	switch a {
	case NestedWitnessPubKey, WitnessPubKey, WitnessScript:
		return witnessVersionV0, nil

	case TaprootPubKey, TaprootScript:
		return witnessVersionV1, nil

	case PubKeyHash, Script, RawPubKey:
		return 0, fmt.Errorf("%w: %v", ErrUnsupportedAddressType, a)

	default:
		return 0, fmt.Errorf("%w: %v", ErrUnknownAddressType, a)
	}
}

// SigningMethod returns the wallet signing method for the address type.
func (a AddressType) SigningMethod() (SigningMethod, error) {
	switch a {
	case PubKeyHash:
		return SigningMethodLegacy, nil

	case NestedWitnessPubKey, WitnessPubKey:
		return SigningMethodWitnessV0, nil

	case TaprootPubKey:
		return SigningMethodTaprootKeySpend, nil

	case Script, RawPubKey, WitnessScript, TaprootScript:
		return 0, fmt.Errorf("%w: %v", ErrUnsupportedAddressType, a)

	default:
		return 0, fmt.Errorf("%w: %v", ErrUnknownAddressType, a)
	}
}

// AddrFromPubKeyBytes reconstructs the standard address from the serialized
// public key form stored by the wallet.
func (a AddressType) AddrFromPubKeyBytes(pubKeyBytes []byte,
	net *chaincfg.Params) (btcutil.Address, error) {

	switch a {
	case PubKeyHash:
		address, err := btcutil.NewAddressPubKeyHash(
			btcutil.Hash160(pubKeyBytes), net,
		)
		if err != nil {
			return nil, fmt.Errorf("new pubkey hash address: %w", err)
		}

		return address, nil

	case NestedWitnessPubKey:
		return nestedWitnessAddrFromPubKeyBytes(pubKeyBytes, net)

	case WitnessPubKey:
		address, err := btcutil.NewAddressWitnessPubKeyHash(
			btcutil.Hash160(pubKeyBytes), net,
		)
		if err != nil {
			return nil, fmt.Errorf("new witness pubkey hash address: %w", err)
		}

		return address, nil

	case TaprootPubKey:
		return taprootAddrFromPubKeyBytes(pubKeyBytes, net)

	case Script, RawPubKey, WitnessScript, TaprootScript:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAddressType, a)

	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownAddressType, a)
	}
}

// nestedWitnessProgramFromPubKeyBytes builds the nested witness redeem program
// from serialized pubkey bytes.
func nestedWitnessProgramFromPubKeyBytes(pubKeyBytes []byte,
	net *chaincfg.Params) ([]byte, error) {

	witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKeyBytes), net,
	)
	if err != nil {
		return nil, fmt.Errorf("new witness pubkey hash: %w", err)
	}

	script, err := txscript.PayToAddrScript(witnessAddr)
	if err != nil {
		return nil, fmt.Errorf("pay to witness address: %w", err)
	}

	return script, nil
}

// nestedWitnessAddrFromPubKeyBytes builds the outer P2SH address for a nested
// witness pubkey-hash spend.
func nestedWitnessAddrFromPubKeyBytes(pubKeyBytes []byte,
	net *chaincfg.Params) (btcutil.Address, error) {

	witnessProgram, err := nestedWitnessProgramFromPubKeyBytes(
		pubKeyBytes, net,
	)
	if err != nil {
		return nil, fmt.Errorf("build nested witness program: %w", err)
	}

	address, err := btcutil.NewAddressScriptHash(witnessProgram, net)
	if err != nil {
		return nil, fmt.Errorf("new nested witness address: %w", err)
	}

	return address, nil
}

// taprootAddrFromPubKeyBytes builds a P2TR address from serialized internal
// pubkey bytes.
func taprootAddrFromPubKeyBytes(pubKeyBytes []byte,
	net *chaincfg.Params) (btcutil.Address, error) {

	internalPubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse taproot internal pubkey: %w", err)
	}

	outputKey := schnorr.SerializePubKey(
		txscript.ComputeTaprootKeyNoScript(internalPubKey),
	)

	address, err := btcutil.NewAddressTaproot(outputKey, net)
	if err != nil {
		return nil, fmt.Errorf("new taproot address: %w", err)
	}

	return address, nil
}
