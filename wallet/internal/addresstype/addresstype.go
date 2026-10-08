// Package addresstype bridges wallet-facing and store-facing address type
// enums.
package addresstype

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// ErrUnknown is returned when an address type has no supported wallet/store
// mapping.
var ErrUnknown = errors.New("unknown address type")

// StoreType is the store representation of a wallet-facing address type.
type StoreType struct {
	// Type is the database-native address type.
	Type db.AddressType

	// HasScript reports whether this address type requires script metadata in
	// addition to Type to round-trip back to the wallet representation.
	HasScript bool
}

// FromWallet maps one wallet-facing address type to the store representation.
func FromWallet(addrType waddrmgr.AddressType) (StoreType, error) {
	switch addrType {
	case waddrmgr.RawPubKey:
		return StoreType{Type: db.RawPubKey}, nil

	case waddrmgr.PubKeyHash:
		return StoreType{Type: db.PubKeyHash}, nil

	case waddrmgr.Script:
		return StoreType{Type: db.ScriptHash, HasScript: true}, nil

	case waddrmgr.NestedWitnessPubKey:
		return StoreType{Type: db.NestedWitnessPubKey}, nil

	case waddrmgr.WitnessPubKey:
		return StoreType{Type: db.WitnessPubKey}, nil

	case waddrmgr.WitnessScript:
		return StoreType{Type: db.WitnessScript, HasScript: true}, nil

	case waddrmgr.TaprootPubKey:
		return StoreType{Type: db.TaprootPubKey}, nil

	case waddrmgr.TaprootScript:
		return StoreType{Type: db.TaprootPubKey, HasScript: true}, nil

	default:
		return StoreType{}, fmt.Errorf("wallet address type %d: %w",
			addrType, ErrUnknown)
	}
}

// ToWallet maps one store address type and script marker to the wallet-facing
// address type.
//
//nolint:cyclop // This switch intentionally covers every store address type.
func ToWallet(addrType db.AddressType,
	hasScript bool) (waddrmgr.AddressType, error) {

	switch addrType {
	case db.RawPubKey:
		return waddrmgr.RawPubKey, nil

	case db.PubKeyHash:
		return waddrmgr.PubKeyHash, nil

	case db.ScriptHash:
		return waddrmgr.Script, nil

	case db.NestedWitnessPubKey:
		return waddrmgr.NestedWitnessPubKey, nil

	case db.WitnessPubKey:
		return waddrmgr.WitnessPubKey, nil

	case db.WitnessScript:
		return waddrmgr.WitnessScript, nil

	case db.TaprootPubKey:
		if hasScript {
			return waddrmgr.TaprootScript, nil
		}

		return waddrmgr.TaprootPubKey, nil

	case db.Anchor:
		return 0, fmt.Errorf("store address type %d: %w", addrType,
			ErrUnknown)

	default:
		return 0, fmt.Errorf("store address type %d: %w", addrType,
			ErrUnknown)
	}
}
