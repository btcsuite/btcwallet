// Copyright (c) 2014 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// This interface was inspired heavily by the excellent boltdb project at
// https://github.com/boltdb/bolt by Ben B. Johnson.

package walletdb

import "io"

// Bucket represents a collection of key/value pairs.
type Bucket interface {
	// Bucket retrieves a nested bucket with the given key.  Returns nil if
	// the bucket does not exist.
	Bucket(key []byte) Bucket

	// CreateBucket creates and returns a new nested bucket with the given
	// key.  Returns ErrBucketExists if the bucket already exists,
	// ErrBucketNameRequired if the key is empty, or ErrIncompatibleValue
	// if the key value is otherwise invalid for the particular database
	// implementation.  Other errors are possible depending on the
	// implementation.
	CreateBucket(key []byte) (Bucket, error)

	// CreateBucketIfNotExists creates and returns a new nested bucket with
	// the given key if it does not already exist.  Returns
	// ErrBucketNameRequired if the key is empty or ErrIncompatibleValue
	// if the key value is otherwise invalid for the particular database
	// backend.  Other errors are possible depending on the implementation.
	CreateBucketIfNotExists(key []byte) (Bucket, error)

	// DeleteBucket removes a nested bucket with the given key.  Returns
	// ErrTxNotWritable if attempted against a read-only transaction and
	// ErrBucketNotFound if the specified bucket does not exist.
	DeleteBucket(key []byte) error

	// ForEach invokes the passed function with every key/value pair in
	// the bucket.  This includes nested buckets, in which case the value
	// is nil, but it does not include the key/value pairs within those
	// nested buckets.
	//
	// NOTE: The values returned by this function are only valid during a
	// transaction.  Attempting to access them after a transaction has ended
	// results in undefined behavior.  This constraint prevents additional
	// data copies and allows support for memory-mapped database
	// implementations.
	ForEach(func(k, v []byte) error) error

	// Writable returns whether or not the bucket is writable.
	Writable() bool

	// Put saves the specified key/value pair to the bucket.  Keys that do
	// not already exist are added and keys that already exist are
	// overwritten.  Returns ErrTxNotWritable if attempted against a
	// read-only transaction.
	Put(key, value []byte) error

	// Get returns the value for the given key.  Returns nil if the key does
	// not exist in this bucket (or nested buckets).
	//
	// NOTE: The value returned by this function is only valid during a
	// transaction.  Attempting to access it after a transaction has ended
	// results in undefined behavior.  This constraint prevents additional
	// data copies and allows support for memory-mapped database
	// implementations.
	Get(key []byte) []byte

	// Delete removes the specified key from the bucket.  Deleting a key
	// that does not exist does not return an error.  Returns
	// ErrTxNotWritable if attempted against a read-only transaction.
	Delete(key []byte) error

	// Cursor returns a new cursor, allowing for iteration over the bucket's
	// key/value pairs and nested buckets in forward or backward order.
	Cursor() Cursor
}

// Cursor represents a cursor over key/value pairs and nested buckets of a
// bucket.
//
// Note that open cursors are not tracked on bucket changes and any
// modifications to the bucket, with the exception of Cursor.Delete, invalidate
// the cursor.  After invalidation, the cursor must be repositioned, or the keys
// and values returned may be unpredictable.
type Cursor interface {
	// Bucket returns the bucket the cursor was created for.
	Bucket() Bucket

	// Delete removes the current key/value pair the cursor is at without
	// invalidating the cursor.  Returns ErrTxNotWritable if attempted on a
	// read-only transaction, or ErrIncompatibleValue if attempted when the
	// cursor points to a nested bucket.
	Delete() error

	// First positions the cursor at the first key/value pair and returns
	// the pair.
	First() (key, value []byte)

	// Last positions the cursor at the last key/value pair and returns the
	// pair.
	Last() (key, value []byte)

	// Next moves the cursor one key/value pair forward and returns the new
	// pair.
	Next() (key, value []byte)

	// Prev moves the cursor one key/value pair backward and returns the new
	// pair.
	Prev() (key, value []byte)

	// Seek positions the cursor at the passed seek key.  If the key does
	// not exist, the cursor is moved to the next key after seek.  Returns
	// the new pair.
	Seek(seek []byte) (key, value []byte)
}

// Tx represents a database transaction.  It can either by read-only or
// read-write.  The transaction provides a root bucket against which all read
// and writes occur.
//
// As would be expected with a transaction, no changes will be saved to the
// database until it has been committed.  The transaction will only provide a
// view of the database at the time it was created.  Transactions should not be
// long running operations.
type Tx interface {
	// RootBucket returns the top-most bucket for the namespace the
	// transaction was created from.
	RootBucket() Bucket

	// Commit commits all changes that have been made through the root
	// bucket and all of its sub-buckets to persistent storage.
	Commit() error

	// Rollback undoes all changes that have been made to the root bucket
	// and all of its sub-buckets.
	Rollback() error
}

// Namespace represents a database namespace that is inteded to support the
// concept of a single entity that controls the opening, creating, and closing
// of a database while providing other entities their own namespace to work in.
type Namespace interface {
	// Begin starts a transaction which is either read-only or read-write
	// depending on the specified flag.  Multiple read-only transactions
	// can be started simultaneously while only a single read-write
	// transaction can be started at a time.  The call will block when
	// starting a read-write transaction when one is already open.
	//
	// NOTE: The transaction must be closed by calling Rollback or Commit on
	// it when it is no longer needed.  Failure to do so can result in
	// unclaimed memory depending on the specific database implementation.
	Begin(writable bool) (Tx, error)

	// View invokes the passed function in the context of a managed
	// read-only transaction.  Any errors returned from the user-supplied
	// function are returned from this function.
	//
	// Calling Rollback on the transaction passed to the user-supplied
	// function will result in a panic.
	View(fn func(Tx) error) error

	// Update invokes the passed function in the context of a managed
	// read-write transaction.  Any errors returned from the user-supplied
	// function will cause the transaction to be rolled back and are
	// returned from this function.  Otherwise, the transaction is commited
	// when the user-supplied function returns a nil error.
	//
	// Calling Rollback on the transaction passed to the user-supplied
	// function will result in a panic.
	Update(fn func(Tx) error) error
}

// NamespaceIsEmpty returns whether the namespace is empty, that is, whether there
// are no key/value pairs or nested buckets.
func NamespaceIsEmpty(namespace Namespace) (bool, error) {
	var empty bool
	err := namespace.View(func(tx Tx) error {
		k, v := tx.RootBucket().Cursor().First()
		empty = k == nil && v == nil
		return nil
	})
	return empty, err
}

// DB represents a collection of namespaces which are persisted.  All database
// access is performed through transactions which are obtained through the
// specific Namespace.
type DB interface {
	// Namespace returns a Namespace interface for the provided key.  See
	// the Namespace interface documentation for more details.  Attempting
	// to access a Namespace on a database that is not open yet or has been
	// closed will result in ErrDbNotOpen.  Namespaces are created in the
	// database on first access.
	Namespace(key []byte) (Namespace, error)

	// DeleteNamespace deletes the namespace for the passed key.
	// ErrBucketNotFound will be returned if the namespace does not exist.
	DeleteNamespace(key []byte) error

	// Copy writes a copy of the database to the provided writer.  This
	// call will start a read-only transaction to perform all operations.
	Copy(w io.Writer) error

	// Close cleanly shuts down the database and syncs all data.
	Close() error
}

// Driver defines a structure for backend drivers to use when they registered
// themselves as a backend which implements the Db interface.
type Driver struct {
	// DbType is the identifier used to uniquely identify a specific
	// database driver.  There can be only one driver with the same name.
	DbType string

	// Create is the function that will be invoked with all user-specified
	// arguments to create the database.  This function must return
	// ErrDbExists if the database already exists.
	Create func(args ...interface{}) (DB, error)

	// Open is the function that will be invoked with all user-specified
	// arguments to open the database.  This function must return
	// ErrDbDoesNotExist if the database has not already been created.
	Open func(args ...interface{}) (DB, error)
}

// driverList holds all of the registered database backends.
var drivers = make(map[string]*Driver)

// RegisterDriver adds a backend database driver to available interfaces.
// ErrDbTypeRegistered will be retruned if the database type for the driver has
// already been registered.
func RegisterDriver(driver Driver) error {
	if _, exists := drivers[driver.DbType]; exists {
		return ErrDbTypeRegistered
	}

	drivers[driver.DbType] = &driver
	return nil
}

// SupportedDrivers returns a slice of strings that represent the database
// drivers that have been registered and are therefore supported.
func SupportedDrivers() []string {
	supportedDBs := make([]string, 0, len(drivers))
	for _, drv := range drivers {
		supportedDBs = append(supportedDBs, drv.DbType)
	}
	return supportedDBs
}

// Create intializes and opens a database for the specified type.  The arguments
// are specific to the database type driver.  See the documentation for the
// database driver for further details.
//
// ErrDbUnknownType will be returned if the the database type is not registered.
func Create(dbType string, args ...interface{}) (DB, error) {
	drv, exists := drivers[dbType]
	if !exists {
		return nil, ErrDbUnknownType
	}

	return drv.Create(args...)
}

// Open opens an existing database for the specified type.  The arguments are
// specific to the database type driver.  See the documentation for the database
// driver for further details.
//
// ErrDbUnknownType will be returned if the the database type is not registered.
func Open(dbType string, args ...interface{}) (DB, error) {
	drv, exists := drivers[dbType]
	if !exists {
		return nil, ErrDbUnknownType
	}

	return drv.Open(args...)
}
