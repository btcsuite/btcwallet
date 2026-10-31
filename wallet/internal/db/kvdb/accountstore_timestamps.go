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
// satisfied without changing waddrmgr's bucket layout. Declared imports append
// their known number; old and inferred imports keep timestamp-only data.
var accountCreatedAtBucketKey = []byte("account-created-at")

// createdAtValueLen is the on-disk byte width of a per-account creation
// timestamp encoded as a big-endian int64 nanosecond offset from the
// Unix epoch.
const createdAtValueLen = 8

// numberedCreatedAtValueLen includes the declared uint32 account number after
// the existing timestamp, allowing old and numberless values to stay unchanged.
const numberedCreatedAtValueLen = createdAtValueLen + 4

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

// putAccountCreatedAt writes the creation timestamp for an account to
// the side bucket. The caller must hold a walletdb.ReadWriteTx and
// pass the waddrmgr namespace bucket; the helper creates the
// sub-bucket on first use. A known number is stored with the timestamp so its
// presence survives reopen without inferring a path from legacy account IDs.
func putAccountCreatedAt(ns walletdb.ReadWriteBucket,
	scope waddrmgr.KeyScope, account uint32, t time.Time,
	knownNumber *uint32) error {

	bucket, err := ns.CreateBucketIfNotExists(accountCreatedAtBucketKey)
	if err != nil {
		return fmt.Errorf("create created-at bucket: %w", err)
	}

	key := newAccountCreatedAtKey(scope, account)

	// Preserve the old encoding unless the caller explicitly supplied a path.
	length := createdAtValueLen
	if knownNumber != nil {
		length = numberedCreatedAtValueLen
	}

	value := make([]byte, length)
	//nolint:gosec // UnixNano() always fits in uint64 for times after 1970.
	binary.BigEndian.PutUint64(value, uint64(t.UTC().UnixNano()))

	if knownNumber != nil {
		binary.BigEndian.PutUint32(value[createdAtValueLen:], *knownNumber)
	}

	err = bucket.Put(key[:], value)
	if err != nil {
		return fmt.Errorf("put created-at: %w", err)
	}

	return nil
}

// readAccountCreatedAt returns the timestamp and optional declared number.
// Missing metadata means an unknown timestamp and number; old timestamp-only
// records retain an unknown number even when their internal ID matches a key.
func readAccountCreatedAt(ns walletdb.ReadBucket,
	scope waddrmgr.KeyScope, account uint32) (time.Time, *uint32, error) {

	bucket := ns.NestedReadBucket(accountCreatedAtBucketKey)
	if bucket == nil {
		return time.Time{}, nil, nil
	}

	key := newAccountCreatedAtKey(scope, account)
	raw := bucket.Get(key[:])

	if raw == nil {
		return time.Time{}, nil, nil
	}

	if len(raw) != createdAtValueLen && len(raw) != numberedCreatedAtValueLen {
		return time.Time{}, nil, fmt.Errorf(
			"%w: scope=%v account=%d: expected %d or %d bytes, got %d",
			errCreatedAtUnexpectedSize, scope, account,
			createdAtValueLen, numberedCreatedAtValueLen, len(raw),
		)
	}

	//nolint:gosec // Stored values are written via UnixNano() of
	// time.Now() in putAccountCreatedAt; round-tripping fits int64.
	nanos := int64(binary.BigEndian.Uint64(raw))

	// Only the explicit tail establishes a known number for an imported key.
	var knownNumber *uint32
	if len(raw) > createdAtValueLen {
		number := binary.BigEndian.Uint32(raw[createdAtValueLen:])
		knownNumber = &number
	}

	return time.Unix(0, nanos).UTC(), knownNumber, nil
}
