/*
 * Copyright (c) 2014 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package wtxmgr

import "fmt"

// ErrorCode identifies a kind of error.
type ErrorCode int

// These constants are used to identify a specific TxStoreError.
const (
	// ErrDatabase indicates an error with the underlying database.  When
	// this error code is set, the Err field of the TxStoreError will be
	// set to the underlying error returned from the database.
	ErrDatabase ErrorCode = iota

	// ErrNoExist indicates that the specified database does not exist.
	ErrNoExist

	// ErrAlreadyExists indicates that the specified database already exists.
	ErrAlreadyExists

	// ErrBlockNotFound indicates that the requested block is not known to
	// the tx store.
	ErrBlockNotFound

	// ErrTxHashNotFound indicates that the requested tx hash is not known to
	// the tx store.
	ErrTxHashNotFound

	// ErrTxRecordNotFound indicates that the requested tx record is not known to
	// the tx store.
	ErrTxRecordNotFound

	// ErrBlockTxKeyNotFound indicates that the requested block tx key is not known to
	// the tx store.
	ErrBlockTxKeyNotFound
)

// Map of ErrorCode values back to their constant names for pretty printing.
var errorCodeStrings = map[ErrorCode]string{
	ErrDatabase:           "ErrDatabase",
	ErrNoExist:            "ErrNoExist",
	ErrAlreadyExists:      "ErrAlreadyExists",
	ErrBlockNotFound:      "ErrBlockNotFound",
	ErrTxHashNotFound:     "ErrTxHashNotFound",
	ErrTxRecordNotFound:   "ErrTxRecordNotFound",
	ErrBlockTxKeyNotFound: "ErrBlockTxKeyNotFound",
}

// String returns the ErrorCode as a human-readable name.
func (e ErrorCode) String() string {
	if s := errorCodeStrings[e]; s != "" {
		return s
	}
	return fmt.Sprintf("Unknown ErrorCode (%d)", int(e))
}

// TxStoreError provides a single type for errors that can happen during tx
// store operation. It is similar to waddrmgr.ManagerError.
type TxStoreError struct {
	ErrorCode   ErrorCode // Describes the kind of error
	Description string    // Human readable description of the issue
	Err         error     // Underlying error
}

// Error satisfies the error interface and prints human-readable errors.
func (e TxStoreError) Error() string {
	if e.Err != nil {
		return e.Description + ": " + e.Err.Error()
	}
	return e.Description
}

// txstoreError creates a TxStoreError given a set of arguments.
func txStoreError(c ErrorCode, desc string, err error) TxStoreError {
	return TxStoreError{ErrorCode: c, Description: desc, Err: err}
}
