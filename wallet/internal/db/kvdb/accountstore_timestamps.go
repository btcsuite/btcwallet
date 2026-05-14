// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// accountCreatedAtBucketKey is the sub-bucket under the waddrmgr
// namespace that holds per-account creation timestamps. waddrmgr's
// account row layout does not include a creation timestamp; the kvdb
// adapter stores it here so the db.AccountInfo.CreatedAt contract is
// satisfied without changing waddrmgr's bucket layout.
var accountCreatedAtBucketKey = []byte("account-created-at")

// createdAtValueLen is the on-disk byte width of a per-account creation
// timestamp encoded as a big-endian int64 nanosecond offset from the
// Unix epoch.
const createdAtValueLen = 8

// errCreatedAtUnexpectedSize is returned when the side bucket's value
// for an existing (scope, account) key has an unexpected byte width.
// The kvdb adapter rejects rather than silently truncates because a
// short value would decode as an arbitrary time.
var errCreatedAtUnexpectedSize = errors.New(
	"created-at bucket value has unexpected byte width",
)

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

// readAccountCreatedAt returns the creation timestamp for an account.
// If no entry exists for (scope, account) the helper returns
// time.Time{} (Go's zero value) and a nil error, meaning "unknown".
// Decoding zero nanos is reserved for legitimate epoch timestamps.
func readAccountCreatedAt(ns walletdb.ReadBucket,
	scope waddrmgr.KeyScope, account uint32) (time.Time, error) {

	bucket := ns.NestedReadBucket(accountCreatedAtBucketKey)
	if bucket == nil {
		return time.Time{}, nil
	}

	key := newAccountCreatedAtKey(scope, account)
	raw := bucket.Get(key[:])

	if raw == nil {
		return time.Time{}, nil
	}

	if len(raw) != createdAtValueLen {
		return time.Time{}, fmt.Errorf(
			"%w: scope=%v account=%d: expected %d bytes, got %d",
			errCreatedAtUnexpectedSize, scope, account,
			createdAtValueLen, len(raw),
		)
	}

	//nolint:gosec // Stored values are written via UnixNano() of
	// time.Now() in putAccountCreatedAt; round-tripping fits int64.
	nanos := int64(binary.BigEndian.Uint64(raw))

	return time.Unix(0, nanos).UTC(), nil
}
