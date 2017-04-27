// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package votingpool_test

import (
	"testing"

	vp "github.com/btcsuite/btcwallet/votingpool"
)

// TestErrorCodeStringer tests that all error codes has a text
// representation and that text representation is still correct,
// ie. that a refactoring and renaming of the error code has not
// drifted from the textual representation.
func TestErrorCodeStringer(t *testing.T) {
	// All the errors in ths
	tests := []struct {
		in   vp.ErrorCode
		want string
	}{
		{vp.ErrInputSelection, "ErrInputSelection"},
		{vp.ErrWithdrawalProcessing, "ErrWithdrawalProcessing"},
		{vp.ErrUnknownPubKey, "ErrUnknownPubKey"},
		{vp.ErrSeriesSerialization, "ErrSeriesSerialization"},
		{vp.ErrSeriesVersion, "ErrSeriesVersion"},
		{vp.ErrSeriesNotExists, "ErrSeriesNotExists"},
		{vp.ErrSeriesAlreadyExists, "ErrSeriesAlreadyExists"},
		{vp.ErrSeriesAlreadyEmpowered, "ErrSeriesAlreadyEmpowered"},
		{vp.ErrSeriesIDNotSequential, "ErrSeriesIDNotSequential"},
		{vp.ErrSeriesIDInvalid, "ErrSeriesIDInvalid"},
		{vp.ErrSeriesNotActive, "ErrSeriesNotActive"},
		{vp.ErrKeyIsPrivate, "ErrKeyIsPrivate"},
		{vp.ErrKeyIsPublic, "ErrKeyIsPublic"},
		{vp.ErrKeyNeuter, "ErrKeyNeuter"},
		{vp.ErrKeyMismatch, "ErrKeyMismatch"},
		{vp.ErrKeysPrivatePublicMismatch, "ErrKeysPrivatePublicMismatch"},
		{vp.ErrKeyDuplicate, "ErrKeyDuplicate"},
		{vp.ErrTooFewPublicKeys, "ErrTooFewPublicKeys"},
		{vp.ErrPoolAlreadyExists, "ErrPoolAlreadyExists"},
		{vp.ErrPoolNotExists, "ErrPoolNotExists"},
		{vp.ErrScriptCreation, "ErrScriptCreation"},
		{vp.ErrTooManyReqSignatures, "ErrTooManyReqSignatures"},
		{vp.ErrInvalidBranch, "ErrInvalidBranch"},
		{vp.ErrInvalidValue, "ErrInvalidValue"},
		{vp.ErrDatabase, "ErrDatabase"},
		{vp.ErrKeyChain, "ErrKeyChain"},
		{vp.ErrCrypto, "ErrCrypto"},
		{vp.ErrRawSigning, "ErrRawSigning"},
		{vp.ErrPreconditionNotMet, "ErrPreconditionNotMet"},
		{vp.ErrTxSigning, "ErrTxSigning"},
		{vp.ErrInvalidScriptHash, "ErrInvalidScriptHash"},
		{vp.ErrWithdrawFromUnusedAddr, "ErrWithdrawFromUnusedAddr"},
		{vp.ErrWithdrawalTxStorage, "ErrWithdrawalTxStorage"},
		{vp.ErrWithdrawalStorage, "ErrWithdrawalStorage"},
		{0xffff, "Unknown ErrorCode (65535)"},
	}

	if int(vp.TstLastErr) != len(tests)-1 {
		t.Errorf("Wrong number of errorCodeStrings. Got: %d, want: %d",
			int(vp.TstLastErr), len(tests))
	}

	for i, test := range tests {
		result := test.in.String()
		if result != test.want {
			t.Errorf("String #%d\ngot: %s\nwant: %s", i, result,
				test.want)
		}
	}
}
