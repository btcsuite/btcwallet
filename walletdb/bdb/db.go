// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bdb

import (
	"io"
	"os"

	"github.com/boltdb/bolt"
	"github.com/jadeblaquiere/ctcwallet/walletdb"
)

// convertErr converts some bolt errors to the equivalent walletdb error.
func convertErr(err error) error {
	switch err {
	// Database open/create errors.
	case bolt.ErrDatabaseNotOpen:
		return walletdb.ErrDbNotOpen
	case bolt.ErrInvalid:
		return walletdb.ErrInvalid

	// Transaction errors.
	case bolt.ErrTxNotWritable:
		return walletdb.ErrTxNotWritable
	case bolt.ErrTxClosed:
		return walletdb.ErrTxClosed

	// Value/bucket errors.
	case bolt.ErrBucketNotFound:
		return walletdb.ErrBucketNotFound
	case bolt.ErrBucketExists:
		return walletdb.ErrBucketExists
	case bolt.ErrBucketNameRequired:
		return walletdb.ErrBucketNameRequired
	case bolt.ErrKeyRequired:
		return walletdb.ErrKeyRequired
	case bolt.ErrKeyTooLarge:
		return walletdb.ErrKeyTooLarge
	case bolt.ErrValueTooLarge:
		return walletdb.ErrValueTooLarge
	case bolt.ErrIncompatibleValue:
		return walletdb.ErrIncompatibleValue
	}

	// Return the original error if none of the above applies.
	return err
}

// bucket is an internal type used to represent a collection of key/value pairs
// and implements the walletdb.Bucket interface.
type bucket bolt.Bucket

// Enforce bucket implements the walletdb.Bucket interface.
var _ walletdb.Bucket = (*bucket)(nil)

// Bucket retrieves a nested bucket with the given key.  Returns nil if
// the bucket does not exist.
//
// This function is part of the walletdb.Bucket interface implementation.
func (b *bucket) Bucket(key []byte) walletdb.Bucket {
	// This nil check is intentional so the return value can be checked
	// against nil directly.
	boltBucket := (*bolt.Bucket)(b).Bucket(key)
	if boltBucket == nil {
		return nil
	}
	return (*bucket)(boltBucket)
}

// CreateBucket creates and returns a new nested bucket with the given key.
// Returns ErrBucketExists if the bucket already exists, ErrBucketNameRequired
// if the key is empty, or ErrIncompatibleValue if the key value is otherwise
// invalid.
//
// This function is part of the walletdb.Bucket interface implementation.
func (b *bucket) CreateBucket(key []byte) (walletdb.Bucket, error) {
	boltBucket, err := (*bolt.Bucket)(b).CreateBucket(key)
	if err != nil {
		return nil, convertErr(err)
	}
	return (*bucket)(boltBucket), nil
}

// CreateBucketIfNotExists creates and returns a new nested bucket with the
// given key if it does not already exist.  Returns ErrBucketNameRequired if the
// key is empty or ErrIncompatibleValue if the key value is otherwise invalid.
//
// This function is part of the walletdb.Bucket interface implementation.
func (b *bucket) CreateBucketIfNotExists(key []byte) (walletdb.Bucket, error) {
	boltBucket, err := (*bolt.Bucket)(b).CreateBucketIfNotExists(key)
	if err != nil {
		return nil, convertErr(err)
	}
	return (*bucket)(boltBucket), nil
}

// DeleteBucket removes a nested bucket with the given key.  Returns
// ErrTxNotWritable if attempted against a read-only transaction and
// ErrBucketNotFound if the specified bucket does not exist.
//
// This function is part of the walletdb.Bucket interface implementation.
func (b *bucket) DeleteBucket(key []byte) error {
	return convertErr((*bolt.Bucket)(b).DeleteBucket(key))
}

// ForEach invokes the passed function with every key/value pair in the bucket.
// This includes nested buckets, in which case the value is nil, but it does not
// include the key/value pairs within those nested buckets.
//
// NOTE: The values returned by this function are only valid during a
// transaction.  Attempting to access them after a transaction has ended will
// likely result in an access violation.
//
// This function is part of the walletdb.Bucket interface implementation.
func (b *bucket) ForEach(fn func(k, v []byte) error) error {
	return convertErr((*bolt.Bucket)(b).ForEach(fn))
}

// Writable returns whether or not the bucket is writable.
//
// This function is part of the walletdb.Bucket interface implementation.
func (b *bucket) Writable() bool {
	return (*bolt.Bucket)(b).Writable()
}

// Put saves the specified key/value pair to the bucket.  Keys that do not
// already exist are added and keys that already exist are overwritten.  Returns
// ErrTxNotWritable if attempted against a read-only transaction.
//
// This function is part of the walletdb.Bucket interface implementation.
func (b *bucket) Put(key, value []byte) error {
	return convertErr((*bolt.Bucket)(b).Put(key, value))
}

// Get returns the value for the given key.  Returns nil if the key does
// not exist in this bucket (or nested buckets).
//
// NOTE: The value returned by this function is only valid during a
// transaction.  Attempting to access it after a transaction has ended
// will likely result in an access violation.
//
// This function is part of the walletdb.Bucket interface implementation.
func (b *bucket) Get(key []byte) []byte {
	return (*bolt.Bucket)(b).Get(key)
}

// Delete removes the specified key from the bucket.  Deleting a key that does
// not exist does not return an error.  Returns ErrTxNotWritable if attempted
// against a read-only transaction.
//
// This function is part of the walletdb.Bucket interface implementation.
func (b *bucket) Delete(key []byte) error {
	return convertErr((*bolt.Bucket)(b).Delete(key))
}

// Cursor returns a new cursor, allowing for iteration over the bucket's
// key/value pairs and nested buckets in forward or backward order.
//
// This function is part of the walletdb.Bucket interface implementation.
func (b *bucket) Cursor() walletdb.Cursor {
	return (*cursor)((*bolt.Bucket)(b).Cursor())
}

// cursor represents a cursor over key/value pairs and nested buckets of a
// bucket.
//
// Note that open cursors are not tracked on bucket changes and any
// modifications to the bucket, with the exception of cursor.Delete, invalidate
// the cursor. After invalidation, the cursor must be repositioned, or the keys
// and values returned may be unpredictable.
type cursor bolt.Cursor

// Bucket returns the bucket the cursor was created for.
//
// This function is part of the walletdb.Cursor interface implementation.
func (c *cursor) Bucket() walletdb.Bucket {
	return (*bucket)((*bolt.Cursor)(c).Bucket())
}

// Delete removes the current key/value pair the cursor is at without
// invalidating the cursor. Returns ErrTxNotWritable if attempted on a read-only
// transaction, or ErrIncompatibleValue if attempted when the cursor points to a
// nested bucket.
//
// This function is part of the walletdb.Cursor interface implementation.
func (c *cursor) Delete() error {
	return convertErr((*bolt.Cursor)(c).Delete())
}

// First positions the cursor at the first key/value pair and returns the pair.
//
// This function is part of the walletdb.Cursor interface implementation.
func (c *cursor) First() (key, value []byte) {
	return (*bolt.Cursor)(c).First()
}

// Last positions the cursor at the last key/value pair and returns the pair.
//
// This function is part of the walletdb.Cursor interface implementation.
func (c *cursor) Last() (key, value []byte) {
	return (*bolt.Cursor)(c).Last()
}

// Next moves the cursor one key/value pair forward and returns the new pair.
//
// This function is part of the walletdb.Cursor interface implementation.
func (c *cursor) Next() (key, value []byte) {
	return (*bolt.Cursor)(c).Next()
}

// Prev moves the cursor one key/value pair backward and returns the new pair.
//
// This function is part of the walletdb.Cursor interface implementation.
func (c *cursor) Prev() (key, value []byte) {
	return (*bolt.Cursor)(c).Prev()
}

// Seek positions the cursor at the passed seek key. If the key does not exist,
// the cursor is moved to the next key after seek. Returns the new pair.
//
// This function is part of the walletdb.Cursor interface implementation.
func (c *cursor) Seek(seek []byte) (key, value []byte) {
	return (*bolt.Cursor)(c).Seek(seek)
}

// transaction represents a database transaction.  It can either by read-only or
// read-write and implements the walletdb.Bucket interface.  The transaction
// provides a root bucket against which all read and writes occur.
type transaction struct {
	boltTx     *bolt.Tx
	rootBucket *bolt.Bucket
}

// Enforce transaction implements the walletdb.Tx interface.
var _ walletdb.Tx = (*transaction)(nil)

// RootBucket returns the top-most bucket for the namespace the transaction was
// created from.
//
// This function is part of the walletdb.Tx interface implementation.
func (tx *transaction) RootBucket() walletdb.Bucket {
	return (*bucket)(tx.rootBucket)
}

// Commit commits all changes that have been made through the root bucket and
// all of its sub-buckets to persistent storage.
//
// This function is part of the walletdb.Tx interface implementation.
func (tx *transaction) Commit() error {
	return convertErr(tx.boltTx.Commit())
}

// Rollback undoes all changes that have been made to the root bucket and all of
// its sub-buckets.
//
// This function is part of the walletdb.Tx interface implementation.
func (tx *transaction) Rollback() error {
	return convertErr(tx.boltTx.Rollback())
}

// namespace represents a database namespace that is inteded to support the
// concept of a single entity that controls the opening, creating, and closing
// of a database while providing other entities their own namespace to work in.
// It implements the walletdb.Namespace interface.
type namespace struct {
	db  *bolt.DB
	key []byte
}

// Enforce namespace implements the walletdb.Namespace interface.
var _ walletdb.Namespace = (*namespace)(nil)

// Begin starts a transaction which is either read-only or read-write depending
// on the specified flag.  Multiple read-only transactions can be started
// simultaneously while only a single read-write transaction can be started at a
// time.  The call will block when starting a read-write transaction when one is
// already open.
//
// NOTE: The transaction must be closed by calling Rollback or Commit on it when
// it is no longer needed.  Failure to do so will result in unclaimed memory.
//
// This function is part of the walletdb.Namespace interface implementation.
func (ns *namespace) Begin(writable bool) (walletdb.Tx, error) {
	boltTx, err := ns.db.Begin(writable)
	if err != nil {
		return nil, convertErr(err)
	}

	bucket := boltTx.Bucket(ns.key)
	if bucket == nil {
		boltTx.Rollback()
		return nil, walletdb.ErrBucketNotFound
	}

	return &transaction{boltTx: boltTx, rootBucket: bucket}, nil
}

// View invokes the passed function in the context of a managed read-only
// transaction.  Any errors returned from the user-supplied function are
// returned from this function.
//
// Calling Rollback on the transaction passed to the user-supplied function will
// result in a panic.
//
// This function is part of the walletdb.Namespace interface implementation.
func (ns *namespace) View(fn func(walletdb.Tx) error) error {
	return convertErr(ns.db.View(func(boltTx *bolt.Tx) error {
		bucket := boltTx.Bucket(ns.key)
		if bucket == nil {
			return walletdb.ErrBucketNotFound
		}

		return fn(&transaction{boltTx: boltTx, rootBucket: bucket})
	}))
}

// Update invokes the passed function in the context of a managed read-write
// transaction.  Any errors returned from the user-supplied function will cause
// the transaction to be rolled back and are returned from this function.
// Otherwise, the transaction is commited when the user-supplied function
// returns a nil error.
//
// Calling Rollback on the transaction passed to the user-supplied function will
// result in a panic.
//
// This function is part of the walletdb.Namespace interface implementation.
func (ns *namespace) Update(fn func(walletdb.Tx) error) error {
	return convertErr(ns.db.Update(func(boltTx *bolt.Tx) error {
		bucket := boltTx.Bucket(ns.key)
		if bucket == nil {
			return walletdb.ErrBucketNotFound
		}

		return fn(&transaction{boltTx: boltTx, rootBucket: bucket})
	}))
}

// db represents a collection of namespaces which are persisted and implements
// the walletdb.Db interface.  All database access is performed through
// transactions which are obtained through the specific Namespace.
type db bolt.DB

// Enforce db implements the walletdb.Db interface.
var _ walletdb.DB = (*db)(nil)

// Namespace returns a Namespace interface for the provided key.  See the
// Namespace interface documentation for more details.  Attempting to access a
// Namespace on a database that is not open yet or has been closed will result
// in ErrDbNotOpen.  Namespaces are created in the database on first access.
//
// This function is part of the walletdb.Db interface implementation.
func (db *db) Namespace(key []byte) (walletdb.Namespace, error) {
	// Check if the namespace needs to be created using a read-only
	// transaction.  This is done because read-only transactions are faster
	// and don't block like write transactions.
	var doCreate bool
	err := (*bolt.DB)(db).View(func(tx *bolt.Tx) error {
		boltBucket := tx.Bucket(key)
		if boltBucket == nil {
			doCreate = true
		}
		return nil
	})
	if err != nil {
		return nil, convertErr(err)
	}

	// Create the namespace if needed by using an writable update
	// transaction.
	if doCreate {
		err := (*bolt.DB)(db).Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucket(key)
			return err
		})
		if err != nil {
			return nil, convertErr(err)
		}
	}

	return &namespace{db: (*bolt.DB)(db), key: key}, nil
}

// DeleteNamespace deletes the namespace for the passed key.  ErrBucketNotFound
// will be returned if the namespace does not exist.
//
// This function is part of the walletdb.Db interface implementation.
func (db *db) DeleteNamespace(key []byte) error {
	return convertErr((*bolt.DB)(db).Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket(key)
	}))
}

// Copy writes a copy of the database to the provided writer.  This call will
// start a read-only transaction to perform all operations.
//
// This function is part of the walletdb.Db interface implementation.
func (db *db) Copy(w io.Writer) error {
	return convertErr((*bolt.DB)(db).View(func(tx *bolt.Tx) error {
		return tx.Copy(w)
	}))
}

// Close cleanly shuts down the database and syncs all data.
//
// This function is part of the walletdb.Db interface implementation.
func (db *db) Close() error {
	return convertErr((*bolt.DB)(db).Close())
}

// filesExists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// openDB opens the database at the provided path.  walletdb.ErrDbDoesNotExist
// is returned if the database doesn't exist and the create flag is not set.
func openDB(dbPath string, create bool) (walletdb.DB, error) {
	if !create && !fileExists(dbPath) {
		return nil, walletdb.ErrDbDoesNotExist
	}

	boltDB, err := bolt.Open(dbPath, 0600, nil)
	return (*db)(boltDB), convertErr(err)
}
