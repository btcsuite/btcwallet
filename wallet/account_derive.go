// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
)

// errWatchOnlyAccountDerivation is returned by the wallet-side account
// derivation helper when called against a watch-only wallet. Hardened
// derivation along m/purpose'/coin'/account' requires the master HD private
// key, which a watch-only wallet does not hold; new derived accounts must
// instead be imported through the watch-only account import path.
var errWatchOnlyAccountDerivation = errors.New(
	"cannot derive new account: wallet is watch-only",
)

// newAccountDeriveFn returns a db.AccountDerivationFunc closure that the
// shared store workflow invokes after allocating an account number. The
// closure derives the account-level extended keys at
// m/purpose'/coin'/account' from the captured master HD private key,
// encrypts the resulting private key via vault, and returns the
// DerivedAccountData that the backend persists alongside the row.
//
// masterPrivKey must be the wallet's decrypted master HD private key,
// loaded by Wallet.NewAccount before opening the store transaction. The
// closure does not access w.store or open any database transaction, so it
// is safe for the backend to invoke from inside its write tx.
//
// The fingerprint argument is the BIP32 master-key fingerprint corresponding
// to masterPrivKey (computed once by Wallet.NewAccount via
// masterKeyFingerprint).
//
// TODO(yy): Replace masterPrivKey with a KeyLocator once the vault grows
// full secret-management support; callers should hand off a locator and
// let the vault perform the hardened derivation internally so the
// plaintext master HD private key never leaves the vault boundary.
func newAccountDeriveFn(masterPrivKey *hdkeychain.ExtendedKey,
	vault keyvault.Vault, fingerprint uint32) db.AccountDerivationFunc {

	return func(_ context.Context, scope db.KeyScope, accountNumber uint32,
		walletIsWatchOnly bool) (*db.DerivedAccountData, error) {

		if walletIsWatchOnly {
			return nil, errWatchOnlyAccountDerivation
		}

		if !masterPrivKey.IsPrivate() {
			return nil, fmt.Errorf("derive account: %w",
				hdkeychain.ErrNotPrivExtKey)
		}

		acctPriv, err := deriveBIP44AccountKey(
			masterPrivKey, scope, accountNumber,
		)
		if err != nil {
			return nil, fmt.Errorf("derive account: %w", err)
		}
		defer acctPriv.Zero()

		acctPub, err := acctPriv.Neuter()
		if err != nil {
			return nil, fmt.Errorf("neuter account key: %w", err)
		}

		encPriv, err := vault.Encrypt(
			waddrmgr.CKTPrivate, []byte(acctPriv.String()),
		)
		if err != nil {
			return nil, fmt.Errorf("encrypt account priv: %w", err)
		}

		return &db.DerivedAccountData{
			PublicKey:            []byte(acctPub.String()),
			EncryptedPrivateKey:  encPriv,
			MasterKeyFingerprint: fingerprint,
		}, nil
	}
}

// deriveBIP44AccountKey returns the extended account key derived along
// the BIP44 path m/purpose'/coin'/account' from the given master key.
// All steps are hardened, so masterKey must be a private extended key.
// Each level goes through deriveChildKey so legacy waddrmgr-derived
// accounts round-trip exactly; see deriveChildKey's doc for the BIP-32
// issue #172 details.
func deriveBIP44AccountKey(masterKey *hdkeychain.ExtendedKey,
	scope db.KeyScope, account uint32) (*hdkeychain.ExtendedKey, error) {

	if account > db.MaxAccountNumber {
		return nil, fmt.Errorf("%w: account number %d exceeds max %d",
			db.ErrMaxAccountNumberReached, account, db.MaxAccountNumber)
	}

	purposeKey, err := deriveChildKey(
		masterKey, scope.Purpose+hdkeychain.HardenedKeyStart,
	)
	if err != nil {
		return nil, fmt.Errorf("purpose: %w", err)
	}
	defer purposeKey.Zero()

	coinKey, err := deriveChildKey(
		purposeKey, scope.Coin+hdkeychain.HardenedKeyStart,
	)
	if err != nil {
		return nil, fmt.Errorf("coin type: %w", err)
	}
	defer coinKey.Zero()

	acctKey, err := deriveChildKey(
		coinKey, account+hdkeychain.HardenedKeyStart,
	)
	if err != nil {
		return nil, fmt.Errorf("account: %w", err)
	}

	return acctKey, nil
}

// deriveChildKey derives child index i from parent using the
// BIP-32-spec-compliant Derive when safe, falling back to the legacy
// DeriveNonStandard path for parents flagged by IsAffectedByIssue172.
//
// Background: an early version of btcd's hdkeychain (and any wallet
// built on top of it, including every wallet that ever ran through
// waddrmgr) used a buggy CKDpriv implementation — see BIP-32 issue
// #172. The bug: when the secp256k1 modular reduction of the derived
// scalar happened to produce a value < 2^248, big.Int.Bytes() stripped
// the leading zero byte(s) and the persisted private key came out
// shorter than 32 bytes. Probability per hardened derivation is
// ~1 in 256.
//
// The two algorithms diverge ONLY when len(parent.key) < 32: Derive
// right-aligns the parent's key into the 33-byte HMAC input buffer
// (left-padding with zeros, per spec), while DeriveNonStandard
// left-aligns (leaving the high byte zero). For full 32-byte parents
// the two algorithms produce byte-identical output. So:
//
//   - All existing btcwallet wallets had every hardened derivation go
//     through DeriveNonStandard. Any parent that already lives on
//     disk and is 32 bytes long would produce the same child under
//     either algorithm. Any parent that is <32 bytes (flagged by
//     IsAffectedByIssue172) was derived under the buggy path, so its
//     existing on-disk children were also computed under that path;
//     re-deriving them under Derive would yield different keys and
//     the wallet would lose track of the UTXOs at the affected
//     addresses. Hence the runtime fallback.
//
//   - New wallets created today start with a 32-byte master key and,
//     through this helper, never go through DeriveNonStandard
//     unnecessarily. They organically end up on the spec path. The
//     occasional short child Derive itself produces is then routed
//     back to DeriveNonStandard for its descendants, keeping the
//     wallet self-consistent.
//
// We cannot eliminate the DeriveNonStandard fallback until every
// supported wallet's persisted key set passes IsAffectedByIssue172
// (i.e. every persisted ext-key is full-width). That's a future
// migration / deprecation step; this helper bridges the two worlds
// in the meantime.
func deriveChildKey(parent *hdkeychain.ExtendedKey,
	i uint32) (*hdkeychain.ExtendedKey, error) {

	if parent.IsAffectedByIssue172() {
		//nolint:wrapcheck,staticcheck
		return parent.DeriveNonStandard(i)
	}

	return parent.Derive(i) //nolint:wrapcheck
}

// masterKeyFingerprint returns the BIP32 master-key fingerprint (the first
// four bytes of HASH160(serialized compressed master pubkey)) for the given
// master extended key. The fingerprint identifies the BIP32 root in a key
// origin reference and is stored on each derived account row so PSBT signing
// and hardware-wallet flows can present a proper origin path.
func masterKeyFingerprint(masterKey *hdkeychain.ExtendedKey) (uint32, error) {
	pubKey, err := masterKey.ECPubKey()
	if err != nil {
		return 0, fmt.Errorf("master pubkey: %w", err)
	}

	hash := btcutil.Hash160(pubKey.SerializeCompressed())

	return binary.BigEndian.Uint32(hash[:4]), nil
}
