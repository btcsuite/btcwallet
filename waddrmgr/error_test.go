// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

// TestErrorCodeStringer tests the stringized output for the ErrorCode type.
func TestErrorCodeStringer(t *testing.T) {
	tests := []struct {
		in   waddrmgr.ErrorCode
		want string
	}{
		{waddrmgr.ErrDatabase, "ErrDatabase"},
		{waddrmgr.ErrUpgrade, "ErrUpgrade"},
		{waddrmgr.ErrKeyChain, "ErrKeyChain"},
		{waddrmgr.ErrCrypto, "ErrCrypto"},
		{waddrmgr.ErrInvalidKeyType, "ErrInvalidKeyType"},
		{waddrmgr.ErrNoExist, "ErrNoExist"},
		{waddrmgr.ErrAlreadyExists, "ErrAlreadyExists"},
		{waddrmgr.ErrCoinTypeTooHigh, "ErrCoinTypeTooHigh"},
		{waddrmgr.ErrAccountNumTooHigh, "ErrAccountNumTooHigh"},
		{waddrmgr.ErrLocked, "ErrLocked"},
		{waddrmgr.ErrWatchingOnly, "ErrWatchingOnly"},
		{waddrmgr.ErrInvalidAccount, "ErrInvalidAccount"},
		{waddrmgr.ErrAddressNotFound, "ErrAddressNotFound"},
		{waddrmgr.ErrAccountNotFound, "ErrAccountNotFound"},
		{waddrmgr.ErrDuplicateAddress, "ErrDuplicateAddress"},
		{waddrmgr.ErrDuplicateAccount, "ErrDuplicateAccount"},
		{waddrmgr.ErrTooManyAddresses, "ErrTooManyAddresses"},
		{waddrmgr.ErrWrongPassphrase, "ErrWrongPassphrase"},
		{waddrmgr.ErrWrongNet, "ErrWrongNet"},
		{waddrmgr.ErrCallBackBreak, "ErrCallBackBreak"},
		{waddrmgr.ErrEmptyPassphrase, "ErrEmptyPassphrase"},
		{0xffff, "Unknown ErrorCode (65535)"},
	}
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.String()
		if result != test.want {
			t.Errorf("String #%d\ngot: %s\nwant: %s", i, result,
				test.want)
			continue
		}
	}
}

// TestManagerError tests the error output for the ManagerError type.
func TestManagerError(t *testing.T) {
	tests := []struct {
		in   waddrmgr.ManagerError
		want string
	}{
		// Manager level error.
		{
			waddrmgr.ManagerError{Description: "human-readable error"},
			"human-readable error",
		},

		// Encapsulated database error.
		{
			waddrmgr.ManagerError{
				Description: "failed to store master private " +
					"key parameters",
				ErrorCode: waddrmgr.ErrDatabase,
				Err:       fmt.Errorf("underlying db error"),
			},
			"failed to store master private key parameters: " +
				"underlying db error",
		},

		// Encapsulated key chain error.
		{
			waddrmgr.ManagerError{
				Description: "failed to derive extended key " +
					"branch 0",
				ErrorCode: waddrmgr.ErrKeyChain,
				Err:       fmt.Errorf("underlying error"),
			},
			"failed to derive extended key branch 0: underlying " +
				"error",
		},

		// Encapsulated crypto error.
		{
			waddrmgr.ManagerError{
				Description: "failed to decrypt account 0 " +
					"private key",
				ErrorCode: waddrmgr.ErrCrypto,
				Err:       fmt.Errorf("underlying error"),
			},
			"failed to decrypt account 0 private key: underlying " +
				"error",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("Error #%d\ngot: %s\nwant: %s", i, result,
				test.want)
			continue
		}
	}
}

// TestIsError tests the IsError func.
func TestIsError(t *testing.T) {
	tests := []struct {
		err  error
		code waddrmgr.ErrorCode
		exp  bool
	}{
		{
			err: waddrmgr.ManagerError{
				ErrorCode: waddrmgr.ErrDatabase,
			},
			code: waddrmgr.ErrDatabase,
			exp:  true,
		},
		{
			// package should never return *ManagerError
			err: &waddrmgr.ManagerError{
				ErrorCode: waddrmgr.ErrDatabase,
			},
			code: waddrmgr.ErrDatabase,
			exp:  false,
		},
		{
			err: waddrmgr.ManagerError{
				ErrorCode: waddrmgr.ErrCrypto,
			},
			code: waddrmgr.ErrDatabase,
			exp:  false,
		},
		{
			err:  errors.New("not a ManagerError"),
			code: waddrmgr.ErrDatabase,
			exp:  false,
		},
	}

	for i, test := range tests {
		got := waddrmgr.IsError(test.err, test.code)
		if got != test.exp {
			t.Errorf("Test %d: got %v expected %v", i, got, test.exp)
		}
	}
}
