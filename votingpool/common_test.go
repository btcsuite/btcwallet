// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

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
