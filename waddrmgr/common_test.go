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

package waddrmgr_test

import (
	"encoding/hex"
	"testing"

	"github.com/conformal/btcwallet/waddrmgr"
)

var (
	// seed is the master seed used throughout the tests.
	seed = []byte{
		0x2a, 0x64, 0xdf, 0x08, 0x5e, 0xef, 0xed, 0xd8, 0xbf,
		0xdb, 0xb3, 0x31, 0x76, 0xb5, 0xba, 0x2e, 0x62, 0xe8,
		0xbe, 0x8b, 0x56, 0xc8, 0x83, 0x77, 0x95, 0x59, 0x8b,
		0xb6, 0xc4, 0x40, 0xc0, 0x64,
	}

	pubPassphrase   = []byte("_DJr{fL4H0O}*-0\n:V1izc)(6BomK")
	privPassphrase  = []byte("81lUHXnOMZ@?XXd7O9xyDIWIbXX-lj")
	pubPassphrase2  = []byte("-0NV4P~VSJBWbunw}%<Z]fuGpbN[ZI")
	privPassphrase2 = []byte("~{<]08%6!-?2s<$(8$8:f(5[4/!/{Y")
)

// checkManagerError ensures the passed error is a ManagerError with an error
// code that matches the passed  error code.
func checkManagerError(t *testing.T, testName string, gotErr error, wantErrCode waddrmgr.ErrorCode) bool {
	merr, ok := gotErr.(waddrmgr.ManagerError)
	if !ok {
		t.Errorf("%s: unexpected error type - got %T, want %T",
			testName, gotErr, waddrmgr.ManagerError{})
		return false
	}
	if merr.ErrorCode != wantErrCode {
		t.Errorf("%s: unexpected error code - got %s, want %s",
			testName, merr.ErrorCode, wantErrCode)
		return false
	}

	return true
}

// hexToBytes is a wrapper around hex.DecodeString that panics if there is an
// error.  It MUST only be used with hard coded values in the tests.
func hexToBytes(origHex string) []byte {
	buf, err := hex.DecodeString(origHex)
	if err != nil {
		panic(err)
	}
	return buf
}

func init() {
	// Tune the scrypt params down for tests so they execute quickly.
	waddrmgr.TstSetScryptParams(16, 8, 1)
}
