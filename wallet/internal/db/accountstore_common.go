package db

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
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

// CheckAccountIdentity compares all wallet accounts in a serialized write,
// excluding the candidate's own scoped Store ID. Equal XPub payloads conflict
// when corresponding branch schemas overlap, regardless of chain-sync policy.
func CheckAccountIdentity(candidate AccountInfo, accounts []AccountInfo) error {
	payload := accountXPubPayload(candidate.PublicKey)
	if payload == nil {
		return nil
	}

	// Cross-branch equality cannot collide: /0 and /1 derive different keys.
	for _, account := range accounts {
		if candidate.AccountID != nil && account.AccountID != nil &&
			candidate.KeyScope == account.KeyScope &&
			*candidate.AccountID == *account.AccountID {

			continue
		}

		if bytes.Equal(payload, accountXPubPayload(account.PublicKey)) &&
			(candidate.AddrSchema.ExternalAddrType ==
				account.AddrSchema.ExternalAddrType ||
				candidate.AddrSchema.InternalAddrType ==
					account.AddrSchema.InternalAddrType) {

			return ErrAccountIdentityCollision
		}
	}

	return nil
}

// accountXPubPayload recognizes serialized public keys without tightening the
// SQL Store's existing opaque-byte input contract. Removing serialization
// metadata leaves exactly the chain code and compressed public key.
func accountXPubPayload(serialized []byte) []byte {
	key, err := hdkeychain.NewKeyFromString(string(serialized))
	if err != nil || key.IsPrivate() {
		return nil
	}

	pubKey, err := key.ECPubKey()
	if err != nil {
		return nil
	}

	return append(key.ChainCode(), pubKey.SerializeCompressed()...)
}
