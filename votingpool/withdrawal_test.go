// Copyright (c) 2014 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package votingpool_test

import (
	"bytes"
	"testing"

	"github.com/decred/dcrutil"
	"github.com/decred/dcrutil/hdkeychain"
	vp "github.com/decred/dcrwallet/votingpool"
)

func TestStartWithdrawal(t *testing.T) {
	tearDown, pool, store := vp.TstCreatePoolAndTxStore(t)
	defer tearDown()
	mgr := pool.Manager()

	masters := []*hdkeychain.ExtendedKey{
		vp.TstCreateMasterKey(t, bytes.Repeat([]byte{0x00, 0x01}, 16)),
		vp.TstCreateMasterKey(t, bytes.Repeat([]byte{0x02, 0x01}, 16)),
		vp.TstCreateMasterKey(t, bytes.Repeat([]byte{0x03, 0x01}, 16))}
	def := vp.TstCreateSeriesDef(t, pool, 2, masters)
	vp.TstCreateSeries(t, pool, []vp.TstSeriesDef{def})
	// Create eligible inputs and the list of outputs we need to fulfil.
	vp.TstCreateSeriesCreditsOnStore(t, pool, def.SeriesID, []int64{5e6, 4e6}, store)
	address1 := "34eVkREKgvvGASZW7hkgE2uNc1yycntMK6"
	address2 := "3PbExiaztsSYgh6zeMswC49hLUwhTQ86XG"
	requests := []vp.OutputRequest{
		vp.TstNewOutputRequest(t, 1, address1, 4e6, mgr.ChainParams()),
		vp.TstNewOutputRequest(t, 2, address2, 1e6, mgr.ChainParams()),
	}
	changeStart := vp.TstNewChangeAddress(t, pool, def.SeriesID, 0)

	startAddr := vp.TstNewWithdrawalAddress(t, pool, def.SeriesID, 0, 0)
	lastSeriesID := def.SeriesID
	dustThreshold := dcrutil.Amount(1e4)
	currentBlock := int32(vp.TstInputsBlock + vp.TstEligibleInputMinConfirmations + 1)
	var status *vp.WithdrawalStatus
	var err error
	vp.TstRunWithManagerUnlocked(t, mgr, func() {
		status, err = pool.StartWithdrawal(0, requests, *startAddr, lastSeriesID, *changeStart,
			store, currentBlock, dustThreshold)
	})
	if err != nil {
		t.Fatal(err)
	}

	// Check that all outputs were successfully fulfilled.
	checkWithdrawalOutputs(t, status, map[string]dcrutil.Amount{address1: 4e6, address2: 1e6})

	if status.Fees() != dcrutil.Amount(1e3) {
		t.Fatalf("Wrong amount for fees; got %v, want %v", status.Fees(), dcrutil.Amount(1e3))
	}

	// This withdrawal generated a single transaction with just one change
	// output, so the next change address will be on the same series with the
	// index incremented by 1.
	nextChangeAddr := status.NextChangeAddr()
	if nextChangeAddr.SeriesID() != changeStart.SeriesID() {
		t.Fatalf("Wrong nextChangeStart series; got %d, want %d", nextChangeAddr.SeriesID(),
			changeStart.SeriesID())
	}
	if nextChangeAddr.Index() != changeStart.Index()+1 {
		t.Fatalf("Wrong nextChangeStart index; got %d, want %d", nextChangeAddr.Index(),
			changeStart.Index()+1)
	}

	// NOTE: The ntxid is deterministic so we hardcode it here, but if the test
	// or the code is changed in a way that causes the generated transaction to
	// change (e.g. different inputs/outputs), the ntxid will change too and
	// this will have to be updated.
	ntxid := vp.Ntxid("d81876caf7b3214e10c1465ac701ae62205797dee249d5a3a2d035013bff03d7")
	txSigs := status.Sigs()[ntxid]

	// Finally we use SignTx() to construct the SignatureScripts (using the raw
	// signatures).  Must unlock the manager as signing involves looking up the
	// redeem script, which is stored encrypted.
	msgtx := status.TstGetMsgTx(ntxid)
	vp.TstRunWithManagerUnlocked(t, mgr, func() {
		if err = vp.SignTx(msgtx, txSigs, mgr, store); err != nil {
			t.Fatal(err)
		}
	})

	// Any subsequent StartWithdrawal() calls with the same parameters will
	// return the previously stored WithdrawalStatus.
	var status2 *vp.WithdrawalStatus
	vp.TstRunWithManagerUnlocked(t, mgr, func() {
		status2, err = pool.StartWithdrawal(0, requests, *startAddr, lastSeriesID, *changeStart,
			store, currentBlock, dustThreshold)
	})
	if err != nil {
		t.Fatal(err)
	}
	vp.TstCheckWithdrawalStatusMatches(t, *status, *status2)
}

func checkWithdrawalOutputs(
	t *testing.T, wStatus *vp.WithdrawalStatus, amounts map[string]dcrutil.Amount) {
	fulfilled := wStatus.Outputs()
	if len(fulfilled) != 2 {
		t.Fatalf("Unexpected number of outputs in WithdrawalStatus; got %d, want %d",
			len(fulfilled), 2)
	}
	for _, output := range fulfilled {
		addr := output.Address()
		amount, ok := amounts[addr]
		if !ok {
			t.Fatalf("Unexpected output addr: %s", addr)
		}

		status := output.Status()
		if status != "success" {
			t.Fatalf(
				"Unexpected status for output %v; got '%s', want 'success'", output, status)
		}

		outpoints := output.Outpoints()
		if len(outpoints) != 1 {
			t.Fatalf(
				"Unexpected number of outpoints for output %v; got %d, want 1", output,
				len(outpoints))
		}

		gotAmount := outpoints[0].Amount()
		if gotAmount != amount {
			t.Fatalf("Unexpected amount for output %v; got %v, want %v", output, gotAmount, amount)
		}
	}
}
