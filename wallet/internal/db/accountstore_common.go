package db

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
)

// MasterKeyFingerprint returns the BIP32 fingerprint for a master public key.
// The fingerprint is the first four bytes of the HASH160 of the compressed
// public key, interpreted in big-endian byte order.
func MasterKeyFingerprint(pubKey *btcec.PublicKey) uint32 {
	hash := address.Hash160(pubKey.SerializeCompressed())

	return binary.BigEndian.Uint32(hash[:4])
}

// MapGetAccountSecretErr returns the typed ErrAccountNotFound when err is
// sql.ErrNoRows, describing the selector the caller queried by, and falls back
// to a wrapped form otherwise.
//
// It is shared rather than per backend because it names no generated query or
// driver type: sql.ErrNoRows is the database/sql sentinel both SQL backends
// return for a missing row. Backend-specific classification of driver error
// codes stays in each backend's ClassifyError.
func MapGetAccountSecretErr(err error, query GetAccountSecretQuery) error {
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("get account secret: %w", err)
	}

	return fmt.Errorf("account %d in scope %d/%d: %w",
		query.AccountNumber, query.Scope.Purpose, query.Scope.Coin,
		ErrAccountNotFound)
}
