// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// kvdbAccountCreatedAtBucketKey is the sub-bucket under the waddrmgr
// namespace that holds per-account creation timestamps. waddrmgr's
// account row layout does not include a creation timestamp; the kvdb
// adapter stores it here so the db.AccountInfo.CreatedAt contract is
// satisfied without changing waddrmgr's bucket layout.
//
// See ADR (forthcoming) and task 102.
var kvdbAccountCreatedAtBucketKey = []byte("kvdb-account-created-at")

// accountCreatedAtKey is the 12-byte key used inside the side bucket,
// matching the accountBalanceKey shape so future per-(scope, account)
// kvdb-owned metadata can use the same layout.
type accountCreatedAtKey [12]byte

// newAccountCreatedAtKey packs (scope, account) into the bucket key
// format: <purpose:4 BE><coin:4 BE><account:4 BE>.
func newAccountCreatedAtKey(scope waddrmgr.KeyScope,
	account uint32) accountCreatedAtKey {

	var k accountCreatedAtKey
	binary.BigEndian.PutUint32(k[0:4], scope.Purpose)
	binary.BigEndian.PutUint32(k[4:8], scope.Coin)
	binary.BigEndian.PutUint32(k[8:12], account)
	return k
}

// putAccountCreatedAt writes the creation timestamp for an account to
// the side bucket. The caller must hold a walletdb.ReadWriteTx and
// pass the waddrmgr namespace bucket; the helper creates the
// sub-bucket on first use.
func putAccountCreatedAt(ns walletdb.ReadWriteBucket,
	scope waddrmgr.KeyScope, account uint32, t time.Time) error {

	bucket, err := ns.CreateBucketIfNotExists(kvdbAccountCreatedAtBucketKey)
	if err != nil {
		return fmt.Errorf("create created-at bucket: %w", err)
	}

	key := newAccountCreatedAtKey(scope, account)

	var value [8]byte
	binary.BigEndian.PutUint64(value[:], uint64(t.UTC().UnixNano()))

	if err := bucket.Put(key[:], value[:]); err != nil {
		return fmt.Errorf("put created-at: %w", err)
	}

	return nil
}

// readAccountCreatedAt returns the creation timestamp for an account.
// If no entry exists for (scope, account) — either because the row
// pre-dates this shim or the wallet is in a pathological state — the
// helper returns time.Time{} (Go's zero value) and a nil error. The
// read path treats the entry-missing signal as "unknown", not as the
// epoch (which is what decoding 0 nanos would imply); see task 102.
func readAccountCreatedAt(ns walletdb.ReadBucket,
	scope waddrmgr.KeyScope, account uint32) (time.Time, error) {

	bucket := ns.NestedReadBucket(kvdbAccountCreatedAtBucketKey)
	if bucket == nil {
		return time.Time{}, nil
	}

	key := newAccountCreatedAtKey(scope, account)
	raw := bucket.Get(key[:])
	if raw == nil {
		return time.Time{}, nil
	}

	if len(raw) != 8 {
		return time.Time{}, fmt.Errorf(
			"created-at bucket value for scope=%v account=%d: "+
				"expected 8 bytes, got %d",
			scope, account, len(raw),
		)
	}

	nanos := int64(binary.BigEndian.Uint64(raw))

	return time.Unix(0, nanos).UTC(), nil
}
