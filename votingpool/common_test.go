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

package votingpool

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcutil"
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

// replaceCalculateTxFee replaces the calculateTxFee func with the given one
// and returns a function that restores it to the original one.
func replaceCalculateTxFee(f func(*withdrawalTx) btcutil.Amount) func() {
	orig := calculateTxFee
	calculateTxFee = f
	return func() { calculateTxFee = orig }
}

// replaceIsTxTooBig replaces the isTxTooBig func with the given one
// and returns a function that restores it to the original one.
func replaceIsTxTooBig(f func(*withdrawalTx) bool) func() {
	orig := isTxTooBig
	isTxTooBig = f
	return func() { isTxTooBig = orig }
}

// replaceCalculateTxSize replaces the calculateTxSize func with the given one
// and returns a function that restores it to the original one.
func replaceCalculateTxSize(f func(*withdrawalTx) int) func() {
	orig := calculateTxSize
	calculateTxSize = f
	return func() { calculateTxSize = orig }
}
