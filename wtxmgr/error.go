// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import "fmt"

// ErrorCode identifies a category of error.
type ErrorCode uint8

// These constants are used to identify a specific Error.
const (
	// ErrDatabase indicates an error with the underlying database.  When
	// this error code is set, the Err field of the Error will be
	// set to the underlying error returned from the database.
	ErrDatabase ErrorCode = iota

	// ErrData describes an error where data stored in the transaction
	// database is incorrect.  This may be due to missing values, values of
	// wrong sizes, or data from different buckets that is inconsistent with
	// itself.  Recovering from an ErrData requires rebuilding all
	// transaction history or manual database surgery.  If the failure was
	// not due to data corruption, this error category indicates a
	// programming error in this package.
	ErrData

	// ErrInput describes an error where the variables passed into this
	// function by the caller are obviously incorrect.  Examples include
	// passing transactions which do not serialize, or attempting to insert
	// a credit at an index for which no transaction output exists.
	ErrInput

	// ErrAlreadyExists describes an error where creating the store cannot
	// continue because a store already exists in the namespace.
	ErrAlreadyExists

	// ErrNoExists describes an error where the store cannot be opened due to
	// it not already existing in the namespace.  This error should be
	// handled by creating a new store.
	ErrNoExists

	// ErrValueNoExists describes an error indicating that the value for
	// a given key does not exist in the database queried.
	ErrValueNoExists

	// ErrDoubleSpend indicates that an output was attempted to be spent
	// twice.
	ErrDoubleSpend

	// ErrNeedsUpgrade describes an error during store opening where the
	// database contains an older version of the store.
	ErrNeedsUpgrade

	// ErrUnknownVersion describes an error where the store already exists
	// but the database version is newer than latest version known to this
	// software.  This likely indicates an outdated binary.
	ErrUnknownVersion

	// ErrIsClosed indicates that the transaction manager is closed.
	ErrIsClosed

	// ErrDuplicate describes an error inserting an item into the store due to
	// the data already existing.
	//
	// This error code is a late addition to the API and at the moment only a
	// select number of APIs use it.  Methods that might return this error
	// documents the behavior in a doc comment.
	ErrDuplicate
)

var errStrs = [...]string{
	ErrDatabase:       "ErrDatabase",
	ErrData:           "ErrData",
	ErrInput:          "ErrInput",
	ErrAlreadyExists:  "ErrAlreadyExists",
	ErrNoExists:       "ErrNoExists",
	ErrValueNoExists:  "ErrValueNoExists",
	ErrDoubleSpend:    "ErrDoubleSpend",
	ErrUnknownVersion: "ErrUnknownVersion",
	ErrIsClosed:       "ErrIsClosed",
	ErrDuplicate:      "ErrDuplicate",
}

// String returns the ErrorCode as a human-readable name.
func (e ErrorCode) String() string {
	if e < ErrorCode(len(errStrs)) {
		return errStrs[e]
	}
	return fmt.Sprintf("ErrorCode(%d)", e)
}

// Error provides a single type for errors that can happen during Store
// operation.
type Error struct {
	Code ErrorCode // Describes the kind of error
	Desc string    // Human readable description of the issue
	Err  error     // Underlying error, optional
}

// Error satisfies the error interface and prints human-readable errors.
func (e Error) Error() string {
	if e.Err != nil {
		return e.Desc + ": " + e.Err.Error()
	}
	return e.Desc
}

func storeError(c ErrorCode, desc string, err error) Error {
	return Error{Code: c, Desc: desc, Err: err}
}

// IsNoExists returns whether an error is a Error with the ErrNoExists error
// code.
func IsNoExists(err error) bool {
	serr, ok := err.(Error)
	return ok && serr.Code == ErrNoExists
}

// IsError returns whether err is an Error with a matching error code.
func IsError(err error, code ErrorCode) bool {
	e, ok := err.(Error)
	return ok && e.Code == code
}
