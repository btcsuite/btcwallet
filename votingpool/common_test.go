// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package votingpool

import (
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Enable logging (Debug level) to aid debugging failing tests.
	logger := btclog.NewBackend(os.Stdout).Logger("TEST")
	logger.SetLevel(btclog.LevelDebug)
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
func TstRunWithManagerUnlocked(t *testing.T, mgr *waddrmgr.Manager, addrmgrNs walletdb.ReadBucket, callback func()) {
	if err := mgr.Unlock(addrmgrNs, privPassphrase); err != nil {
		t.Fatal(err)
	}
	defer mgr.Lock()
	callback()
}

// TstCheckWithdrawalStatusMatches compares s1 and s2 using reflect.DeepEqual
// and calls t.Fatal() if they're not identical.
func TstCheckWithdrawalStatusMatches(t *testing.T, s1, s2 WithdrawalStatus) {
	if s1.Fees() != s2.Fees() {
		t.Fatalf("Wrong amount of network fees; want %d, got %d", s1.Fees(), s2.Fees())
	}

	if !reflect.DeepEqual(s1.Sigs(), s2.Sigs()) {
		t.Fatalf("Wrong tx signatures; got %x, want %x", s1.Sigs(), s2.Sigs())
	}

	if !reflect.DeepEqual(s1.NextInputAddr(), s2.NextInputAddr()) {
		t.Fatalf("Wrong NextInputAddr; got %v, want %v", s1.NextInputAddr(), s2.NextInputAddr())
	}

	if !reflect.DeepEqual(s1.NextChangeAddr(), s2.NextChangeAddr()) {
		t.Fatalf("Wrong NextChangeAddr; got %v, want %v", s1.NextChangeAddr(), s2.NextChangeAddr())
	}

	if !reflect.DeepEqual(s1.Outputs(), s2.Outputs()) {
		t.Fatalf("Wrong WithdrawalOutputs; got %v, want %v", s1.Outputs(), s2.Outputs())
	}

	if !reflect.DeepEqual(s1.transactions, s2.transactions) {
		t.Fatalf("Wrong transactions; got %v, want %v", s1.transactions, s2.transactions)
	}

	// The above checks could be replaced by this one, but when they fail the
	// failure msg wouldn't give us much clue as to what is not equal, so we do
	// the individual checks above and use this one as a catch-all check in case
	// we forget to check any of the individual fields.
	if !reflect.DeepEqual(s1, s2) {
		t.Fatalf("Wrong WithdrawalStatus; got %v, want %v", s1, s2)
	}
}
