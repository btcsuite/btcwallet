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

package waddrmgr

// XXX: All errors defined here will soon be moved to the votingpool package, where they
// belong.

// Constants that identify voting pool-related errors.
// The codes start from 1000 to avoid confusion with the ones in error.go.
const (
	// ErrSeriesStorage indicates that an error occurred while serializing
	// or deserializing one or more series for storing into database.
	ErrSeriesStorage ErrorCode = iota + 1000

	// ErrSeriesVersion indicates that we've been asked to deal with
	// a series whose version is unsupported
	ErrSeriesVersion

	// ErrSeriesNotExists indicates that an attempt has been made to access
	// a series that does not exist.
	ErrSeriesNotExists

	// ErrSeriesAlreadyExists indicates that an attempt has been made to create
	// a series that already exists.
	ErrSeriesAlreadyExists

	// ErrSeriesAlreadyEmpowered indicates that an already empowered series
	// was used where a not empowered one was expected.
	ErrSeriesAlreadyEmpowered

	// ErrKeyIsPrivate indicates that a private key was used where a public
	// one was expected.
	ErrKeyIsPrivate

	// ErrKeyIsPublic indicates that a public key was used where a private
	// one was expected.
	ErrKeyIsPublic

	// ErrKeyNeuter indicates a problem when trying to neuter a private key.
	ErrKeyNeuter

	// ErrKeyMismatch indicates that the key is not the expected one.
	ErrKeyMismatch

	// ErrKeysPrivatePublicMismatch indicates that the number of private and
	// public keys is not the same.
	ErrKeysPrivatePublicMismatch

	// ErrKeyDuplicate indicates that a key is duplicated.
	ErrKeyDuplicate

	// ErrTooFewPublicKeys indicates that a required minimum of public
	// keys was not met.
	ErrTooFewPublicKeys

	// ErrVotingPoolAlreadyExists indicates that an attempt has been made to
	// create a voting pool that already exists.
	ErrVotingPoolAlreadyExists

	// ErrVotingPoolNotExists indicates that an attempt has been made to access
	// a voting pool that does not exist.
	ErrVotingPoolNotExists

	// ErrScriptCreation indicates that the creation of a deposit script failed.
	ErrScriptCreation

	// ErrTooManyReqSignatures indicates that too many required
	// signatures are requested.
	ErrTooManyReqSignatures

	// ErrInvalidBranch indicates that the given branch number is not valid
	// for a given set of public keys.
	ErrInvalidBranch

	// ErrInvalidValue indicates that the value of a given function argument
	// is invalid.
	ErrInvalidValue
)
