package waddrmgr

import (
	"errors"
	"fmt"
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

	default:
		return DerivationSchemeNone
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

	default:
		return 0, fmt.Errorf("%w: %v", ErrUnsupportedAddressType, a)
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

	default:
		return 0, fmt.Errorf("%w: %v", ErrUnsupportedAddressType, a)
	}
}
