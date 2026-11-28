// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// accountMasterFingerprintBucketKey is the sub-bucket under the
// waddrmgr namespace that holds the per-account BIP32 master-key
// fingerprint for derived accounts. waddrmgr's default-account row
// has no fingerprint column at all; the kvdb adapter stores the value
// here so the db.AccountInfo.MasterKeyFingerprint contract is
// satisfied without changing waddrmgr's bucket layout.
//
// Imported (watch-only) accounts persist the fingerprint in waddrmgr's
// accountWatchOnly row; this side bucket is derived-only.
var accountMasterFingerprintBucketKey = []byte("account-master-fingerprint")

// masterFingerprintValueLen is the on-disk byte width of a master-
// fingerprint entry encoded as a big-endian uint32.
const masterFingerprintValueLen = 4

// errMasterFingerprintUnexpectedSize is returned when the side
// bucket's value for an existing (scope, account) key has an
// unexpected byte width. The kvdb adapter rejects rather than
// silently truncating because a short value would decode as an
// arbitrary uint32.
var errMasterFingerprintUnexpectedSize = errors.New(
	"master-fingerprint bucket value has unexpected byte width",
)

// putAccountMasterFingerprint writes the master fingerprint for an
// account to the side bucket. The caller must hold a
// walletdb.ReadWriteTx and pass the waddrmgr namespace bucket; the
// helper creates the sub-bucket on first use.
func putAccountMasterFingerprint(ns walletdb.ReadWriteBucket,
	scope waddrmgr.KeyScope, account uint32, fingerprint uint32) error {

	bucket, err := ns.CreateBucketIfNotExists(
		accountMasterFingerprintBucketKey,
	)
	if err != nil {
		return fmt.Errorf("create fingerprint bucket: %w", err)
	}

	// Reuse the timestamp key shape: (scope.Purpose, scope.Coin,
	// account) packed big-endian — same per-(scope, account) layout.
	key := newAccountCreatedAtKey(scope, account)

	var value [masterFingerprintValueLen]byte
	binary.BigEndian.PutUint32(value[:], fingerprint)

	err = bucket.Put(key[:], value[:])
	if err != nil {
		return fmt.Errorf("put fingerprint: %w", err)
	}

	return nil
}

// getAccountMasterFingerprint returns the master fingerprint for an
// account. If no entry exists for (scope, account) the helper returns
// (0, false, nil) meaning "no side-bucket entry". Callers MUST treat
// a false ok as "fall back to whatever waddrmgr has" — for legacy
// derived rows that value is 0 (waddrmgr's default-account row has no
// fingerprint column), so the wallet-layer override remains the
// compatibility path for legacy data.
func getAccountMasterFingerprint(ns walletdb.ReadBucket,
	scope waddrmgr.KeyScope,
	account uint32) (uint32, bool, error) {

	bucket := ns.NestedReadBucket(accountMasterFingerprintBucketKey)
	if bucket == nil {
		return 0, false, nil
	}

	key := newAccountCreatedAtKey(scope, account)
	raw := bucket.Get(key[:])

	if raw == nil {
		return 0, false, nil
	}

	if len(raw) != masterFingerprintValueLen {
		return 0, false, fmt.Errorf(
			"%w: scope=%v account=%d: expected %d bytes, got %d",
			errMasterFingerprintUnexpectedSize, scope, account,
			masterFingerprintValueLen, len(raw),
		)
	}

	return binary.BigEndian.Uint32(raw), true, nil
}
