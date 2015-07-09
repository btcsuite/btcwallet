/*
 * Copyright (c) 2014 The btcsuite developers
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

package votingpool

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Enable logging (Debug level) to aid debugging failing tests.
	logger, err := btclog.NewLoggerFromWriter(os.Stdout, btclog.DebugLvl)
	if err != nil {
		fmt.Printf("Failed to initialize stdout logger: %v\n", err)
		os.Exit(1)
	}
	UseLogger(logger)
}

// TstCheckError ensures the passed error is a votingpool.Error with an error
// code that matches the passed error code.
func TstCheckError(t *testing.T, testName string, gotErr error, wantErrCode ErrorCode) {
	vpErr, ok := gotErr.(Error)
	if !ok {
		t.Errorf("%s: unexpected error type - got %T (%s), want %T",
			testName, gotErr, gotErr, Error{})
	}
	if vpErr.ErrorCode != wantErrCode {
		t.Errorf("%s: unexpected error code - got %s (%s), want %s",
			testName, vpErr.ErrorCode, vpErr, wantErrCode)
	}
}

// TstRunWithManagerUnlocked calls the given callback with the manager unlocked,
// and locks it again before returning.
func TstRunWithManagerUnlocked(t *testing.T, mgr *waddrmgr.Manager, callback func()) {
	if err := mgr.Unlock(privPassphrase); err != nil {
		t.Fatal(err)
	}
	defer mgr.Lock()
	callback()
}

// TstCheckWithdrawalStatusMatches compares the individual fields of the two
// WithdrawalStatus given (using reflect.DeepEqual) and calls t.Fatal() if
// any of them don't match.
func TstCheckWithdrawalStatusMatches(t *testing.T, got, want WithdrawalStatus) {
	if got.Fees() != want.Fees() {
		t.Fatalf("Wrong amount of network fees; got %d, want %d", got.Fees(), want.Fees())
	}

	if !reflect.DeepEqual(got.Sigs(), want.Sigs()) {
		t.Fatalf("Wrong tx signatures; got %x, want %x", got.Sigs(), want.Sigs())
	}

	if !reflect.DeepEqual(got.NextInputAddr(), want.NextInputAddr()) {
		t.Fatalf("Wrong NextInputAddr; got %v, want %v", got.NextInputAddr(), want.NextInputAddr())
	}

	if !reflect.DeepEqual(got.NextChangeAddr(), want.NextChangeAddr()) {
		t.Fatalf("Wrong NextChangeAddr; got %v, want %v", got.NextChangeAddr(), want.NextChangeAddr())
	}

	if !reflect.DeepEqual(got.Outputs(), want.Outputs()) {
		t.Fatalf("Wrong WithdrawalOutputs; got %v, want %v", got.Outputs(), want.Outputs())
	}

	if !reflect.DeepEqual(got.transactions, want.transactions) {
		t.Fatalf("Wrong transactions; got %v, want %v", got.transactions, want.transactions)
	}

	// The above checks could be replaced by this one, but when they fail the
	// failure msg wouldn't give us much clue as to what is not equal, so we do
	// the individual checks above and use this one as a catch-all check in case
	// we forget to check any of the individual fields.
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Wrong WithdrawalStatus; got %v, want %v", got, want)
	}
}

func TstCheckAddressIdentifier(t *testing.T, addr AddressIdentifier, seriesID uint32,
	branch Branch, index Index) {

	if addr.SeriesID() != seriesID {
		t.Fatalf("Wrong SeriesID; got %d, want %d", addr.SeriesID(), seriesID)
	}
	if addr.Branch() != branch {
		t.Fatalf("Wrong Branch; got %d, want %d", addr.Branch(), branch)
	}
	if addr.Index() != index {
		t.Fatalf("Wrong Index; got %d, want %d", addr.Index(), index)
	}
}
