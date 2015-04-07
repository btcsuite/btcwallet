/*
 * Copyright (c) 2015 Conformal Systems LLC <info@conformal.com>
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
	"bytes"
	"reflect"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// TestOutputSplittingNotEnoughInputs checks that an output will get split if we
// don't have enough inputs to fulfil it.
func TestOutputSplittingNotEnoughInputs(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	net := pool.Manager().ChainParams()
	output1Amount := btcutil.Amount(2)
	output2Amount := btcutil.Amount(3)
	requests := []OutputRequest{
		// These output requests will have the same server ID, so we know
		// they'll be fulfilled in the order they're defined here, which is
		// important for this test.
		TstNewOutputRequest(t, 1, "34eVkREKgvvGASZW7hkgE2uNc1yycntMK6", output1Amount, net),
		TstNewOutputRequest(t, 2, "34eVkREKgvvGASZW7hkgE2uNc1yycntMK6", output2Amount, net),
	}
	seriesID, eligible := TstCreateCreditsOnNewSeries(t, pool, []int64{7})
	w := newWithdrawal(0, requests, eligible, *TstNewChangeAddress(t, pool, seriesID, 0))

	// Trigger an output split because of lack of inputs by forcing a high fee.
	// If we just started with not enough inputs for the requested outputs,
	// fulfillRequests() would drop outputs until we had enough.
	restoreCalculateTxFee := replaceCalculateTxFee(TstConstantFee(3))
	defer restoreCalculateTxFee()
	if err := w.fulfillRequests(); err != nil {
		t.Fatal(err)
	}

	if len(w.transactions) != 1 {
		t.Fatalf("Wrong number of finalized transactions; got %d, want 1", len(w.transactions))
	}

	tx := w.transactions[0]
	if len(tx.outputs) != 2 {
		t.Fatalf("Wrong number of outputs; got %d, want 2", len(tx.outputs))
	}

	// The first output should've been left untouched.
	if tx.outputs[0].amount != output1Amount {
		t.Fatalf("Wrong amount for first tx output; got %v, want %v",
			tx.outputs[0].amount, output1Amount)
	}

	// The last output should have had its amount updated to whatever we had
	// left after satisfying all previous outputs.
	newAmount := tx.inputTotal() - output1Amount - calculateTxFee(tx)
	checkLastOutputWasSplit(t, w, tx, output2Amount, newAmount)
}

func TestOutputSplittingOversizeTx(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	requestAmount := btcutil.Amount(5)
	bigInput := int64(3)
	smallInput := int64(2)
	request := TstNewOutputRequest(
		t, 1, "34eVkREKgvvGASZW7hkgE2uNc1yycntMK6", requestAmount, pool.Manager().ChainParams())
	seriesID, eligible := TstCreateCreditsOnNewSeries(t, pool, []int64{bigInput, smallInput})
	changeStart := TstNewChangeAddress(t, pool, seriesID, 0)
	w := newWithdrawal(0, []OutputRequest{request}, eligible, *changeStart)
	restoreCalculateTxFee := replaceCalculateTxFee(TstConstantFee(0))
	defer restoreCalculateTxFee()
	restoreIsTxTooBig := replaceIsTxTooBig(func(tx *withdrawalTx) bool {
		// Trigger an output split right after the second input is added.
		return len(tx.inputs) == 2
	})
	defer restoreIsTxTooBig()

	if err := w.fulfillRequests(); err != nil {
		t.Fatal(err)
	}

	if len(w.transactions) != 2 {
		t.Fatalf("Wrong number of finalized transactions; got %d, want 2", len(w.transactions))
	}

	tx1 := w.transactions[0]
	if len(tx1.outputs) != 1 {
		t.Fatalf("Wrong number of outputs on tx1; got %d, want 1", len(tx1.outputs))
	}
	if tx1.outputs[0].amount != btcutil.Amount(bigInput) {
		t.Fatalf("Wrong amount for output in tx1; got %d, want %d", tx1.outputs[0].amount,
			bigInput)
	}

	tx2 := w.transactions[1]
	if len(tx2.outputs) != 1 {
		t.Fatalf("Wrong number of outputs on tx2; got %d, want 1", len(tx2.outputs))
	}
	if tx2.outputs[0].amount != btcutil.Amount(smallInput) {
		t.Fatalf("Wrong amount for output in tx2; got %d, want %d", tx2.outputs[0].amount,
			smallInput)
	}

	if len(w.status.outputs) != 1 {
		t.Fatalf("Wrong number of output statuses; got %d, want 1", len(w.status.outputs))
	}
	status := w.status.outputs[request.outBailmentID()].status
	if status != statusSplit {
		t.Fatalf("Wrong output status; got '%s', want '%s'", status, statusSplit)
	}
}

func TestSplitLastOutputNoOutputs(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	w := newWithdrawal(0, []OutputRequest{}, []credit{}, ChangeAddress{})
	w.current = createWithdrawalTx(t, pool, []int64{}, []int64{})

	err := w.splitLastOutput()

	TstCheckError(t, "", err, ErrPreconditionNotMet)
}

// Check that all outputs requested in a withdrawal match the outputs of the generated
// transaction(s).
func TestWithdrawalTxOutputs(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()
	net := pool.Manager().ChainParams()

	// Create eligible inputs and the list of outputs we need to fulfil.
	seriesID, eligible := TstCreateCreditsOnNewSeries(t, pool, []int64{2e6, 4e6})
	outputs := []OutputRequest{
		TstNewOutputRequest(t, 1, "34eVkREKgvvGASZW7hkgE2uNc1yycntMK6", 3e6, net),
		TstNewOutputRequest(t, 2, "3PbExiaztsSYgh6zeMswC49hLUwhTQ86XG", 2e6, net),
	}
	changeStart := TstNewChangeAddress(t, pool, seriesID, 0)

	w := newWithdrawal(0, outputs, eligible, *changeStart)
	if err := w.fulfillRequests(); err != nil {
		t.Fatal(err)
	}

	if len(w.transactions) != 1 {
		t.Fatalf("Unexpected number of transactions; got %d, want 1", len(w.transactions))
	}

	tx := w.transactions[0]
	// The created tx should include both eligible credits, so we expect it to have
	// an input amount of 2e6+4e6 satoshis.
	inputAmount := eligible[0].Amount + eligible[1].Amount
	change := inputAmount - (outputs[0].Amount + outputs[1].Amount + calculateTxFee(tx))
	expectedOutputs := append(
		outputs, TstNewOutputRequest(t, 3, changeStart.addr.String(), change, net))
	msgtx := tx.toMsgTx()
	checkMsgTxOutputs(t, msgtx, expectedOutputs)
}

// Check that withdrawal.status correctly states that no outputs were fulfilled when we
// don't have enough eligible credits for any of them.
func TestFulfillRequestsNoSatisfiableOutputs(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	seriesID, eligible := TstCreateCreditsOnNewSeries(t, pool, []int64{1e6})
	request := TstNewOutputRequest(
		t, 1, "3Qt1EaKRD9g9FeL2DGkLLswhK1AKmmXFSe", btcutil.Amount(3e6), pool.Manager().ChainParams())
	changeStart := TstNewChangeAddress(t, pool, seriesID, 0)

	w := newWithdrawal(0, []OutputRequest{request}, eligible, *changeStart)
	if err := w.fulfillRequests(); err != nil {
		t.Fatal(err)
	}

	if len(w.transactions) != 0 {
		t.Fatalf("Unexpected number of transactions; got %d, want 0", len(w.transactions))
	}

	if len(w.status.outputs) != 1 {
		t.Fatalf("Unexpected number of outputs in WithdrawalStatus; got %d, want 1",
			len(w.status.outputs))
	}

	status := w.status.outputs[request.outBailmentID()].status
	if status != statusPartial {
		t.Fatalf("Unexpected status for requested outputs; got '%s', want '%s'",
			status, statusPartial)
	}
}

// Check that some requested outputs are not fulfilled when we don't have credits for all
// of them.
func TestFulfillRequestsNotEnoughCreditsForAllRequests(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()
	net := pool.Manager().ChainParams()

	// Create eligible inputs and the list of outputs we need to fulfil.
	seriesID, eligible := TstCreateCreditsOnNewSeries(t, pool, []int64{2e6, 4e6})
	out1 := TstNewOutputRequest(
		t, 1, "34eVkREKgvvGASZW7hkgE2uNc1yycntMK6", btcutil.Amount(3e6), net)
	out2 := TstNewOutputRequest(
		t, 2, "3PbExiaztsSYgh6zeMswC49hLUwhTQ86XG", btcutil.Amount(2e6), net)
	out3 := TstNewOutputRequest(
		t, 3, "3Qt1EaKRD9g9FeL2DGkLLswhK1AKmmXFSe", btcutil.Amount(5e6), net)
	outputs := []OutputRequest{out1, out2, out3}
	changeStart := TstNewChangeAddress(t, pool, seriesID, 0)

	w := newWithdrawal(0, outputs, eligible, *changeStart)
	if err := w.fulfillRequests(); err != nil {
		t.Fatal(err)
	}

	tx := w.transactions[0]
	// The created tx should spend both eligible credits, so we expect it to have
	// an input amount of 2e6+4e6 satoshis.
	inputAmount := eligible[0].Amount + eligible[1].Amount
	// We expect it to include outputs for requests 1 and 2, plus a change output, but
	// output request #3 should not be there because we don't have enough credits.
	change := inputAmount - (out1.Amount + out2.Amount + calculateTxFee(tx))
	expectedOutputs := []OutputRequest{out1, out2}
	sort.Sort(byOutBailmentID(expectedOutputs))
	expectedOutputs = append(
		expectedOutputs, TstNewOutputRequest(t, 4, changeStart.addr.String(), change, net))
	msgtx := tx.toMsgTx()
	checkMsgTxOutputs(t, msgtx, expectedOutputs)

	// withdrawal.status should state that outputs 1 and 2 were successfully fulfilled,
	// and that output 3 was not.
	expectedStatuses := map[OutBailmentID]outputStatus{
		out1.outBailmentID(): statusSuccess,
		out2.outBailmentID(): statusSuccess,
		out3.outBailmentID(): statusPartial}
	for _, wOutput := range w.status.outputs {
		if wOutput.status != expectedStatuses[wOutput.request.outBailmentID()] {
			t.Fatalf("Unexpected status for %v; got '%s', want '%s'", wOutput.request,
				wOutput.status, expectedStatuses[wOutput.request.outBailmentID()])
		}
	}
}

// TestRollbackLastOutput tests the case where we rollback one output
// and one input, such that sum(in) >= sum(out) + fee.
func TestRollbackLastOutput(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{3, 3, 2, 1, 3}, []int64{3, 3, 2, 2})
	initialInputs := tx.inputs
	initialOutputs := tx.outputs

	restoreCalcTxFee := replaceCalculateTxFee(TstConstantFee(1))
	defer restoreCalcTxFee()
	removedInputs, removedOutput, err := tx.rollBackLastOutput()
	if err != nil {
		t.Fatal("Unexpected error:", err)
	}

	// The above rollBackLastOutput() call should have removed the last output
	// and the last input.
	lastOutput := initialOutputs[len(initialOutputs)-1]
	if removedOutput != lastOutput {
		t.Fatalf("Wrong rolled back output; got %s want %s", removedOutput, lastOutput)
	}
	if len(removedInputs) != 1 {
		t.Fatalf("Unexpected number of inputs removed; got %d, want 1", len(removedInputs))
	}
	lastInput := initialInputs[len(initialInputs)-1]
	if !reflect.DeepEqual(removedInputs[0], lastInput) {
		t.Fatalf("Wrong rolled back input; got %s want %s", removedInputs[0], lastInput)
	}

	// Now check that the inputs and outputs left in the tx match what we
	// expect.
	checkTxOutputs(t, tx, initialOutputs[:len(initialOutputs)-1])
	checkTxInputs(t, tx, initialInputs[:len(initialInputs)-1])
}

func TestRollbackLastOutputMultipleInputsRolledBack(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	// This tx will need the 3 last inputs to fulfill the second output, so they
	// should all be rolled back and returned in the reverse order they were added.
	tx := createWithdrawalTx(t, pool, []int64{1, 2, 3, 4}, []int64{1, 8})
	initialInputs := tx.inputs
	initialOutputs := tx.outputs

	restoreCalcTxFee := replaceCalculateTxFee(TstConstantFee(0))
	defer restoreCalcTxFee()
	removedInputs, _, err := tx.rollBackLastOutput()
	if err != nil {
		t.Fatal("Unexpected error:", err)
	}

	if len(removedInputs) != 3 {
		t.Fatalf("Unexpected number of inputs removed; got %d, want 3", len(removedInputs))
	}
	for i, amount := range []btcutil.Amount{4, 3, 2} {
		if removedInputs[i].Amount != amount {
			t.Fatalf("Unexpected input amount; got %v, want %v", removedInputs[i].Amount, amount)
		}
	}

	// Now check that the inputs and outputs left in the tx match what we
	// expect.
	checkTxOutputs(t, tx, initialOutputs[:len(initialOutputs)-1])
	checkTxInputs(t, tx, initialInputs[:len(initialInputs)-len(removedInputs)])
}

// TestRollbackLastOutputNoInputsRolledBack tests the case where we roll back
// one output but don't need to roll back any inputs.
func TestRollbackLastOutputNoInputsRolledBack(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{4}, []int64{2, 3})
	initialInputs := tx.inputs
	initialOutputs := tx.outputs

	restoreCalcTxFee := replaceCalculateTxFee(TstConstantFee(1))
	defer restoreCalcTxFee()
	removedInputs, removedOutput, err := tx.rollBackLastOutput()
	if err != nil {
		t.Fatal("Unexpected error:", err)
	}

	// The above rollBackLastOutput() call should have removed the
	// last output but no inputs.
	lastOutput := initialOutputs[len(initialOutputs)-1]
	if removedOutput != lastOutput {
		t.Fatalf("Wrong output; got %s want %s", removedOutput, lastOutput)
	}
	if len(removedInputs) != 0 {
		t.Fatalf("Expected no removed inputs, but got %d inputs", len(removedInputs))
	}

	// Now check that the inputs and outputs left in the tx match what we
	// expect.
	checkTxOutputs(t, tx, initialOutputs[:len(initialOutputs)-1])
	checkTxInputs(t, tx, initialInputs)
}

// TestRollBackLastOutputInsufficientOutputs checks that
// rollBackLastOutput returns an error if there are less than two
// outputs in the transaction.
func TestRollBackLastOutputInsufficientOutputs(t *testing.T) {
	tx := newWithdrawalTx()
	_, _, err := tx.rollBackLastOutput()
	TstCheckError(t, "", err, ErrPreconditionNotMet)

	output := &WithdrawalOutput{request: TstNewOutputRequest(
		t, 1, "34eVkREKgvvGASZW7hkgE2uNc1yycntMK6", btcutil.Amount(3), &chaincfg.MainNetParams)}
	tx.addOutput(output.request)
	_, _, err = tx.rollBackLastOutput()
	TstCheckError(t, "", err, ErrPreconditionNotMet)
}

// TestRollbackLastOutputWhenNewOutputAdded checks that we roll back the last
// output if a tx becomes too big right after we add a new output to it.
func TestRollbackLastOutputWhenNewOutputAdded(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	net := pool.Manager().ChainParams()
	series, eligible := TstCreateCreditsOnNewSeries(t, pool, []int64{5, 5})
	requests := []OutputRequest{
		// This is ordered by bailment ID
		TstNewOutputRequest(t, 1, "34eVkREKgvvGASZW7hkgE2uNc1yycntMK6", 1, net),
		TstNewOutputRequest(t, 2, "3PbExiaztsSYgh6zeMswC49hLUwhTQ86XG", 2, net),
	}
	changeStart := TstNewChangeAddress(t, pool, series, 0)

	w := newWithdrawal(0, requests, eligible, *changeStart)
	restoreCalculateTxFee := replaceCalculateTxFee(TstConstantFee(0))
	defer restoreCalculateTxFee()
	restoreIsTxTooBig := replaceIsTxTooBig(func(tx *withdrawalTx) bool {
		return len(tx.outputs) > 1
	})
	defer restoreIsTxTooBig()

	if err := w.fulfillRequests(); err != nil {
		t.Fatal("Unexpected error:", err)
	}

	// At this point we should have two finalized transactions.
	if len(w.transactions) != 2 {
		t.Fatalf("Wrong number of finalized transactions; got %d, want 2", len(w.transactions))
	}

	// First tx should have one output with 1 and one change output with 4
	// satoshis.
	firstTx := w.transactions[0]
	req1 := requests[0]
	checkTxOutputs(t, firstTx,
		[]*withdrawalTxOut{&withdrawalTxOut{request: req1, amount: req1.Amount}})
	checkTxChangeAmount(t, firstTx, btcutil.Amount(4))

	// Second tx should have one output with 2 and one changeoutput with 3 satoshis.
	secondTx := w.transactions[1]
	req2 := requests[1]
	checkTxOutputs(t, secondTx,
		[]*withdrawalTxOut{&withdrawalTxOut{request: req2, amount: req2.Amount}})
	checkTxChangeAmount(t, secondTx, btcutil.Amount(3))
}

// TestRollbackLastOutputWhenNewInputAdded checks that we roll back the last
// output if a tx becomes too big right after we add a new input to it.
func TestRollbackLastOutputWhenNewInputAdded(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	net := pool.Manager().ChainParams()
	series, eligible := TstCreateCreditsOnNewSeries(t, pool, []int64{1, 2, 3, 4, 5, 6})
	requests := []OutputRequest{
		// This is manually ordered by outBailmentIDHash, which is the order in
		// which they're going to be fulfilled by w.fulfillRequests().
		TstNewOutputRequest(t, 1, "34eVkREKgvvGASZW7hkgE2uNc1yycntMK6", 1, net),
		TstNewOutputRequest(t, 3, "3Qt1EaKRD9g9FeL2DGkLLswhK1AKmmXFSe", 6, net),
		TstNewOutputRequest(t, 2, "3PbExiaztsSYgh6zeMswC49hLUwhTQ86XG", 3, net),
	}
	changeStart := TstNewChangeAddress(t, pool, series, 0)

	w := newWithdrawal(0, requests, eligible, *changeStart)
	restoreCalculateTxFee := replaceCalculateTxFee(TstConstantFee(0))
	defer restoreCalculateTxFee()
	restoreIsTxTooBig := replaceIsTxTooBig(func(tx *withdrawalTx) bool {
		// Make a transaction too big as soon as a fourth input is added to it.
		return len(tx.inputs) > 3
	})
	defer restoreIsTxTooBig()

	// The rollback should be triggered right after the 4th input is added in
	// order to fulfill the second request.
	if err := w.fulfillRequests(); err != nil {
		t.Fatal("Unexpected error:", err)
	}

	// At this point we should have two finalized transactions.
	if len(w.transactions) != 2 {
		t.Fatalf("Wrong number of finalized transactions; got %d, want 2", len(w.transactions))
	}

	// First tx should have one output with amount of 1, the first input from
	// the list of eligible inputs, and no change output.
	firstTx := w.transactions[0]
	req1 := requests[0]
	checkTxOutputs(t, firstTx,
		[]*withdrawalTxOut{&withdrawalTxOut{request: req1, amount: req1.Amount}})
	checkTxInputs(t, firstTx, eligible[0:1])

	// Second tx should have outputs for the two last requests (in the same
	// order they were passed to newWithdrawal), and the 3 inputs needed to
	// fulfill that (also in the same order as they were passed to
	// newWithdrawal) and no change output.
	secondTx := w.transactions[1]
	wantOutputs := []*withdrawalTxOut{
		&withdrawalTxOut{request: requests[1], amount: requests[1].Amount},
		&withdrawalTxOut{request: requests[2], amount: requests[2].Amount}}
	checkTxOutputs(t, secondTx, wantOutputs)
	checkTxInputs(t, secondTx, eligible[1:4])
}

func TestWithdrawalTxRemoveOutput(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{}, []int64{1, 2})
	outputs := tx.outputs
	// Make sure we have created the transaction with the expected
	// outputs.
	checkTxOutputs(t, tx, outputs)

	remainingOutput := tx.outputs[0]
	wantRemovedOutput := tx.outputs[1]

	gotRemovedOutput := tx.removeOutput()

	// Check the popped output looks correct.
	if gotRemovedOutput != wantRemovedOutput {
		t.Fatalf("Removed output wrong; got %v, want %v", gotRemovedOutput, wantRemovedOutput)
	}
	// And that the remaining output is correct.
	checkTxOutputs(t, tx, []*withdrawalTxOut{remainingOutput})

	// Make sure that the remaining output is really the right one.
	if tx.outputs[0] != remainingOutput {
		t.Fatalf("Wrong output: got %v, want %v", tx.outputs[0], remainingOutput)
	}
}

func TestWithdrawalTxRemoveInput(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{1, 2}, []int64{})
	inputs := tx.inputs
	// Make sure we have created the transaction with the expected inputs
	checkTxInputs(t, tx, inputs)

	remainingInput := tx.inputs[0]
	wantRemovedInput := tx.inputs[1]

	gotRemovedInput := tx.removeInput()

	// Check the popped input looks correct.
	if !reflect.DeepEqual(gotRemovedInput, wantRemovedInput) {
		t.Fatalf("Popped input wrong; got %v, want %v", gotRemovedInput, wantRemovedInput)
	}
	checkTxInputs(t, tx, inputs[0:1])

	// Make sure that the remaining input is really the right one.
	if !reflect.DeepEqual(tx.inputs[0], remainingInput) {
		t.Fatalf("Wrong input: got %v, want %v", tx.inputs[0], remainingInput)
	}
}

func TestWithdrawalTxAddChange(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	input, output, fee := int64(4e6), int64(3e6), int64(10)
	tx := createWithdrawalTx(t, pool, []int64{input}, []int64{output})
	restoreCalcTxFee := replaceCalculateTxFee(TstConstantFee(btcutil.Amount(fee)))
	defer restoreCalcTxFee()

	if !tx.addChange([]byte{}) {
		t.Fatal("tx.addChange() returned false, meaning it did not add a change output")
	}

	msgtx := tx.toMsgTx()
	if len(msgtx.TxOut) != 2 {
		t.Fatalf("Unexpected number of txouts; got %d, want 2", len(msgtx.TxOut))
	}
	gotChange := msgtx.TxOut[1].Value
	wantChange := input - output - fee
	if gotChange != wantChange {
		t.Fatalf("Unexpected change amount; got %v, want %v", gotChange, wantChange)
	}
}

// TestWithdrawalTxAddChangeNoChange checks that withdrawalTx.addChange() does not
// add a change output when there's no satoshis left after paying all
// outputs+fees.
func TestWithdrawalTxAddChangeNoChange(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	input, output, fee := int64(4e6), int64(4e6), int64(0)
	tx := createWithdrawalTx(t, pool, []int64{input}, []int64{output})
	restoreCalcTxFee := replaceCalculateTxFee(TstConstantFee(btcutil.Amount(fee)))
	defer restoreCalcTxFee()

	if tx.addChange([]byte{}) {
		t.Fatal("tx.addChange() returned true, meaning it added a change output")
	}
	msgtx := tx.toMsgTx()
	if len(msgtx.TxOut) != 1 {
		t.Fatalf("Unexpected number of txouts; got %d, want 1", len(msgtx.TxOut))
	}
}

func TestWithdrawalTxToMsgTxNoInputsOrOutputsOrChange(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{}, []int64{})
	msgtx := tx.toMsgTx()
	compareMsgTxAndWithdrawalTxOutputs(t, msgtx, tx)
	compareMsgTxAndWithdrawalTxInputs(t, msgtx, tx)
}

func TestWithdrawalTxToMsgTxNoInputsOrOutputsWithChange(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{}, []int64{})
	tx.changeOutput = wire.NewTxOut(int64(1), []byte{})

	msgtx := tx.toMsgTx()

	compareMsgTxAndWithdrawalTxOutputs(t, msgtx, tx)
	compareMsgTxAndWithdrawalTxInputs(t, msgtx, tx)
}

func TestWithdrawalTxToMsgTxWithInputButNoOutputsWithChange(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{1}, []int64{})
	tx.changeOutput = wire.NewTxOut(int64(1), []byte{})

	msgtx := tx.toMsgTx()

	compareMsgTxAndWithdrawalTxOutputs(t, msgtx, tx)
	compareMsgTxAndWithdrawalTxInputs(t, msgtx, tx)
}

func TestWithdrawalTxToMsgTxWithInputOutputsAndChange(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)

	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{1, 2, 3}, []int64{4, 5, 6})
	tx.changeOutput = wire.NewTxOut(int64(7), []byte{})

	msgtx := tx.toMsgTx()

	compareMsgTxAndWithdrawalTxOutputs(t, msgtx, tx)
	compareMsgTxAndWithdrawalTxInputs(t, msgtx, tx)
}

func TestWithdrawalTxInputTotal(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{5}, []int64{})

	if tx.inputTotal() != btcutil.Amount(5) {
		t.Fatalf("Wrong total output; got %v, want %v", tx.outputTotal(), btcutil.Amount(5))
	}
}

func TestWithdrawalTxOutputTotal(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{}, []int64{4})
	tx.changeOutput = wire.NewTxOut(int64(1), []byte{})

	if tx.outputTotal() != btcutil.Amount(4) {
		t.Fatalf("Wrong total output; got %v, want %v", tx.outputTotal(), btcutil.Amount(4))
	}
}

func TestSignMultiSigUTXO(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	// Create a new tx with a single input that we're going to sign.
	mgr := pool.Manager()
	tx := createWithdrawalTx(t, pool, []int64{4e6}, []int64{4e6})
	sigs, err := getRawSigs([]*withdrawalTx{tx})
	if err != nil {
		t.Fatal(err)
	}

	msgtx := tx.toMsgTx()
	txSigs := sigs[tx.ntxid()]

	idx := 0 // The index of the tx input we're going to sign.
	pkScript := tx.inputs[idx].PkScript
	TstRunWithManagerUnlocked(t, mgr, func() {
		if err = signMultiSigUTXO(mgr, msgtx, idx, pkScript, txSigs[idx]); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSignMultiSigUTXOUnparseablePkScript(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	mgr := pool.Manager()
	tx := createWithdrawalTx(t, pool, []int64{4e6}, []int64{})
	msgtx := tx.toMsgTx()

	unparseablePkScript := []byte{0x01}
	err := signMultiSigUTXO(mgr, msgtx, 0, unparseablePkScript, []RawSig{RawSig{}})

	TstCheckError(t, "", err, ErrTxSigning)
}

func TestSignMultiSigUTXOPkScriptNotP2SH(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	mgr := pool.Manager()
	tx := createWithdrawalTx(t, pool, []int64{4e6}, []int64{})
	addr, _ := btcutil.DecodeAddress("1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX", mgr.ChainParams())
	pubKeyHashPkScript, _ := txscript.PayToAddrScript(addr.(*btcutil.AddressPubKeyHash))
	msgtx := tx.toMsgTx()

	err := signMultiSigUTXO(mgr, msgtx, 0, pubKeyHashPkScript, []RawSig{RawSig{}})

	TstCheckError(t, "", err, ErrTxSigning)
}

func TestSignMultiSigUTXORedeemScriptNotFound(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	mgr := pool.Manager()
	tx := createWithdrawalTx(t, pool, []int64{4e6}, []int64{})
	// This is a P2SH address for which the addr manager doesn't have the redeem
	// script.
	addr, _ := btcutil.DecodeAddress("3Hb4xcebcKg4DiETJfwjh8sF4uDw9rqtVC", mgr.ChainParams())
	if _, err := mgr.Address(addr); err == nil {
		t.Fatalf("Address %s found in manager when it shouldn't", addr)
	}
	msgtx := tx.toMsgTx()

	pkScript, _ := txscript.PayToAddrScript(addr.(*btcutil.AddressScriptHash))
	err := signMultiSigUTXO(mgr, msgtx, 0, pkScript, []RawSig{RawSig{}})

	TstCheckError(t, "", err, ErrTxSigning)
}

func TestSignMultiSigUTXONotEnoughSigs(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	mgr := pool.Manager()
	tx := createWithdrawalTx(t, pool, []int64{4e6}, []int64{})
	sigs, err := getRawSigs([]*withdrawalTx{tx})
	if err != nil {
		t.Fatal(err)
	}
	msgtx := tx.toMsgTx()
	txSigs := sigs[tx.ntxid()]

	idx := 0 // The index of the tx input we're going to sign.
	// Here we provide reqSigs-1 signatures to SignMultiSigUTXO()
	reqSigs := tx.inputs[idx].addr.series().TstGetReqSigs()
	txInSigs := txSigs[idx][:reqSigs-1]
	pkScript := tx.inputs[idx].PkScript
	TstRunWithManagerUnlocked(t, mgr, func() {
		err = signMultiSigUTXO(mgr, msgtx, idx, pkScript, txInSigs)
	})

	TstCheckError(t, "", err, ErrTxSigning)
}

func TestSignMultiSigUTXOWrongRawSigs(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	mgr := pool.Manager()
	tx := createWithdrawalTx(t, pool, []int64{4e6}, []int64{})
	sigs := []RawSig{RawSig{0x00}, RawSig{0x01}}

	idx := 0 // The index of the tx input we're going to sign.
	pkScript := tx.inputs[idx].PkScript
	var err error
	TstRunWithManagerUnlocked(t, mgr, func() {
		err = signMultiSigUTXO(mgr, tx.toMsgTx(), idx, pkScript, sigs)
	})

	TstCheckError(t, "", err, ErrTxSigning)
}

func TestGetRawSigs(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{5e6, 4e6}, []int64{})

	sigs, err := getRawSigs([]*withdrawalTx{tx})
	if err != nil {
		t.Fatal(err)
	}
	msgtx := tx.toMsgTx()
	txSigs := sigs[tx.ntxid()]
	if len(txSigs) != len(tx.inputs) {
		t.Fatalf("Unexpected number of sig lists; got %d, want %d", len(txSigs), len(tx.inputs))
	}

	checkNonEmptySigsForPrivKeys(t, txSigs, tx.inputs[0].addr.series().privateKeys)

	// Since we have all the necessary signatures (m-of-n), we construct the
	// sigsnature scripts and execute them to make sure the raw signatures are
	// valid.
	signTxAndValidate(t, pool.Manager(), msgtx, txSigs, tx.inputs)
}

func TestGetRawSigsOnlyOnePrivKeyAvailable(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{5e6, 4e6}, []int64{})
	// Remove all private keys but the first one from the credit's series.
	series := tx.inputs[0].addr.series()
	for i := range series.privateKeys[1:] {
		series.privateKeys[i] = nil
	}

	sigs, err := getRawSigs([]*withdrawalTx{tx})
	if err != nil {
		t.Fatal(err)
	}

	txSigs := sigs[tx.ntxid()]
	if len(txSigs) != len(tx.inputs) {
		t.Fatalf("Unexpected number of sig lists; got %d, want %d", len(txSigs), len(tx.inputs))
	}

	checkNonEmptySigsForPrivKeys(t, txSigs, series.privateKeys)
}

func TestGetRawSigsUnparseableRedeemScript(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{5e6, 4e6}, []int64{})
	// Change the redeem script for one of our tx inputs, to force an error in
	// getRawSigs().
	tx.inputs[0].addr.script = []byte{0x01}

	_, err := getRawSigs([]*withdrawalTx{tx})

	TstCheckError(t, "", err, ErrRawSigning)
}

func TestGetRawSigsInvalidAddrBranch(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{5e6, 4e6}, []int64{})
	// Change the branch of our input's address to an invalid value, to force
	// an error in getRawSigs().
	tx.inputs[0].addr.branch = Branch(999)

	_, err := getRawSigs([]*withdrawalTx{tx})

	TstCheckError(t, "", err, ErrInvalidBranch)
}

// TestOutBailmentIDSort tests that we can correctly sort a slice
// of output requests by the hash of the outbailmentID.
func TestOutBailmentIDSort(t *testing.T) {
	or00 := OutputRequest{cachedHash: []byte{0, 0}}
	or01 := OutputRequest{cachedHash: []byte{0, 1}}
	or10 := OutputRequest{cachedHash: []byte{1, 0}}
	or11 := OutputRequest{cachedHash: []byte{1, 1}}

	want := []OutputRequest{or00, or01, or10, or11}
	random := []OutputRequest{or11, or00, or10, or01}

	sort.Sort(byOutBailmentID(random))

	if !reflect.DeepEqual(random, want) {
		t.Fatalf("Sort failed; got %v, want %v", random, want)
	}
}

func TestTxTooBig(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{5}, []int64{1})

	restoreCalcTxSize := replaceCalculateTxSize(func(tx *withdrawalTx) int { return txMaxSize - 1 })
	if isTxTooBig(tx) {
		t.Fatalf("Tx is smaller than max size (%d < %d) but was considered too big",
			calculateTxSize(tx), txMaxSize)
	}
	restoreCalcTxSize()

	// A tx whose size is equal to txMaxSize should be considered too big.
	restoreCalcTxSize = replaceCalculateTxSize(func(tx *withdrawalTx) int { return txMaxSize })
	if !isTxTooBig(tx) {
		t.Fatalf("Tx size is equal to the max size (%d == %d) but was not considered too big",
			calculateTxSize(tx), txMaxSize)
	}
	restoreCalcTxSize()

	restoreCalcTxSize = replaceCalculateTxSize(func(tx *withdrawalTx) int { return txMaxSize + 1 })
	if !isTxTooBig(tx) {
		t.Fatalf("Tx size is bigger than max size (%d > %d) but was not considered too big",
			calculateTxSize(tx), txMaxSize)
	}
	restoreCalcTxSize()
}

func TestTxSizeCalculation(t *testing.T) {
	tearDown, pool, _ := TstCreatePoolAndTxStore(t)
	defer tearDown()

	tx := createWithdrawalTx(t, pool, []int64{1, 5}, []int64{2})

	size := calculateTxSize(tx)

	// Now add a change output, get a msgtx, sign it and get its SerializedSize
	// to compare with the value above. We need to replace the calculateTxFee
	// function so that the tx.addChange() call below always adds a change
	// output.
	restoreCalcTxFee := replaceCalculateTxFee(TstConstantFee(1))
	defer restoreCalcTxFee()
	seriesID := tx.inputs[0].addr.SeriesID()
	tx.addChange(TstNewChangeAddress(t, pool, seriesID, 0).addr.ScriptAddress())
	msgtx := tx.toMsgTx()
	sigs, err := getRawSigs([]*withdrawalTx{tx})
	if err != nil {
		t.Fatal(err)
	}
	signTxAndValidate(t, pool.Manager(), msgtx, sigs[tx.ntxid()], tx.inputs)

	// ECDSA signatures have variable length (71-73 bytes) but in
	// calculateTxSize() we use a dummy signature for the worst-case scenario (73
	// bytes) so the estimate here can be up to 2 bytes bigger for every
	// signature in every input's SigScript.
	maxDiff := 2 * len(msgtx.TxIn) * int(tx.inputs[0].addr.series().reqSigs)
	// To make things worse, there's a possibility that the length of the
	// actual SignatureScript is at the upper boundary of one of the uint*
	// types, and when that happens our dummy SignatureScript is likely to have
	// a length that cannot be represented in the same uint* type as that of the
	// actual one, so we need to account for that here too. As per
	// wire.VarIntSerializeSize(), the biggest difference would be of 4
	// bytes, when the actual SigScript size fits in a uint32 but the dummy one
	// needs a uint64.
	maxDiff += 4 * len(msgtx.TxIn)
	if size-msgtx.SerializeSize() > maxDiff {
		t.Fatalf("Size difference bigger than maximum expected: %d - %d > %d",
			size, msgtx.SerializeSize(), maxDiff)
	} else if size-msgtx.SerializeSize() < 0 {
		t.Fatalf("Tx size (%d) bigger than estimated size (%d)", msgtx.SerializeSize(), size)
	}
}

func TestTxFeeEstimationForSmallTx(t *testing.T) {
	tx := newWithdrawalTx()

	// A tx that is smaller than 1000 bytes in size should have a fee of 10000
	// satoshis.
	restoreCalcTxSize := replaceCalculateTxSize(func(tx *withdrawalTx) int { return 999 })
	defer restoreCalcTxSize()
	fee := calculateTxFee(tx)

	wantFee := btcutil.Amount(1e3)
	if fee != wantFee {
		t.Fatalf("Unexpected tx fee; got %v, want %v", fee, wantFee)
	}
}

func TestTxFeeEstimationForLargeTx(t *testing.T) {
	tx := newWithdrawalTx()

	// A tx that is larger than 1000 bytes in size should have a fee of 1e3
	// satoshis plus 1e3 for every 1000 bytes.
	restoreCalcTxSize := replaceCalculateTxSize(func(tx *withdrawalTx) int { return 3000 })
	defer restoreCalcTxSize()
	fee := calculateTxFee(tx)

	wantFee := btcutil.Amount(4e3)
	if fee != wantFee {
		t.Fatalf("Unexpected tx fee; got %v, want %v", fee, wantFee)
	}
}

// checkNonEmptySigsForPrivKeys checks that every signature list in txSigs has
// one non-empty signature for every non-nil private key in the given list. This
// is to make sure every signature list matches the specification at
// http://opentransactions.org/wiki/index.php/Siglist.
func checkNonEmptySigsForPrivKeys(t *testing.T, txSigs TxSigs, privKeys []*hdkeychain.ExtendedKey) {
	for _, txInSigs := range txSigs {
		if len(txInSigs) != len(privKeys) {
			t.Fatalf("Number of items in sig list (%d) does not match number of privkeys (%d)",
				len(txInSigs), len(privKeys))
		}
		for sigIdx, sig := range txInSigs {
			key := privKeys[sigIdx]
			if bytes.Equal(sig, []byte{}) && key != nil {
				t.Fatalf("Empty signature (idx=%d) but key (%s) is available",
					sigIdx, key.String())
			} else if !bytes.Equal(sig, []byte{}) && key == nil {
				t.Fatalf("Signature not empty (idx=%d) but key is not available", sigIdx)
			}
		}
	}
}

// checkTxOutputs uses reflect.DeepEqual() to ensure that the tx outputs match
// the given slice of withdrawalTxOuts.
func checkTxOutputs(t *testing.T, tx *withdrawalTx, outputs []*withdrawalTxOut) {
	nOutputs := len(outputs)
	if len(tx.outputs) != nOutputs {
		t.Fatalf("Wrong number of outputs in tx; got %d, want %d", len(tx.outputs), nOutputs)
	}
	for i, output := range tx.outputs {
		if !reflect.DeepEqual(output, outputs[i]) {
			t.Fatalf("Unexpected output; got %s, want %s", output, outputs[i])
		}
	}
}

// checkMsgTxOutputs checks that the pkScript and amount of every output in the
// given msgtx match the pkScript and amount of every item in the slice of
// OutputRequests.
func checkMsgTxOutputs(t *testing.T, msgtx *wire.MsgTx, requests []OutputRequest) {
	nRequests := len(requests)
	if len(msgtx.TxOut) != nRequests {
		t.Fatalf("Unexpected number of TxOuts; got %d, want %d", len(msgtx.TxOut), nRequests)
	}
	for i, request := range requests {
		txOut := msgtx.TxOut[i]
		if !bytes.Equal(txOut.PkScript, request.PkScript) {
			t.Fatalf(
				"Unexpected pkScript for request %d; got %v, want %v", i, txOut.PkScript,
				request.PkScript)
		}
		gotAmount := btcutil.Amount(txOut.Value)
		if gotAmount != request.Amount {
			t.Fatalf(
				"Unexpected amount for request %d; got %v, want %v", i, gotAmount, request.Amount)
		}
	}
}

// checkTxInputs ensures that the tx.inputs match the given inputs.
func checkTxInputs(t *testing.T, tx *withdrawalTx, inputs []credit) {
	if len(tx.inputs) != len(inputs) {
		t.Fatalf("Wrong number of inputs in tx; got %d, want %d", len(tx.inputs), len(inputs))
	}
	for i, input := range tx.inputs {
		if !reflect.DeepEqual(input, inputs[i]) {
			t.Fatalf("Unexpected input; got %s, want %s", input, inputs[i])
		}
	}
}

// signTxAndValidate will construct the signature script for each input of the given
// transaction (using the given raw signatures and the pkScripts from credits) and execute
// those scripts to validate them.
func signTxAndValidate(t *testing.T, mgr *waddrmgr.Manager, tx *wire.MsgTx, txSigs TxSigs,
	credits []credit) {
	for i := range tx.TxIn {
		pkScript := credits[i].PkScript
		TstRunWithManagerUnlocked(t, mgr, func() {
			if err := signMultiSigUTXO(mgr, tx, i, pkScript, txSigs[i]); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func compareMsgTxAndWithdrawalTxInputs(t *testing.T, msgtx *wire.MsgTx, tx *withdrawalTx) {
	if len(msgtx.TxIn) != len(tx.inputs) {
		t.Fatalf("Wrong number of inputs; got %d, want %d", len(msgtx.TxIn), len(tx.inputs))
	}

	for i, txin := range msgtx.TxIn {
		outpoint := tx.inputs[i].OutPoint
		if txin.PreviousOutPoint != outpoint {
			t.Fatalf("Wrong outpoint; got %v expected %v", txin.PreviousOutPoint, outpoint)
		}
	}
}

func compareMsgTxAndWithdrawalTxOutputs(t *testing.T, msgtx *wire.MsgTx, tx *withdrawalTx) {
	nOutputs := len(tx.outputs)

	if tx.changeOutput != nil {
		nOutputs++
	}

	if len(msgtx.TxOut) != nOutputs {
		t.Fatalf("Unexpected number of TxOuts; got %d, want %d", len(msgtx.TxOut), nOutputs)
	}

	for i, output := range tx.outputs {
		outputRequest := output.request
		txOut := msgtx.TxOut[i]
		if !bytes.Equal(txOut.PkScript, outputRequest.PkScript) {
			t.Fatalf(
				"Unexpected pkScript for outputRequest %d; got %x, want %x",
				i, txOut.PkScript, outputRequest.PkScript)
		}
		gotAmount := btcutil.Amount(txOut.Value)
		if gotAmount != outputRequest.Amount {
			t.Fatalf(
				"Unexpected amount for outputRequest %d; got %v, want %v",
				i, gotAmount, outputRequest.Amount)
		}
	}

	// Finally check the change output if it exists
	if tx.changeOutput != nil {
		msgTxChange := msgtx.TxOut[len(msgtx.TxOut)-1]
		if msgTxChange != tx.changeOutput {
			t.Fatalf("wrong TxOut in msgtx; got %v, want %v", msgTxChange, tx.changeOutput)
		}
	}
}

func checkTxChangeAmount(t *testing.T, tx *withdrawalTx, amount btcutil.Amount) {
	if !tx.hasChange() {
		t.Fatalf("Transaction has no change.")
	}
	if tx.changeOutput.Value != int64(amount) {
		t.Fatalf("Wrong change output amount; got %d, want %d",
			tx.changeOutput.Value, int64(amount))
	}
}

// checkLastOutputWasSplit ensures that the amount of the last output in the
// given tx matches newAmount and that the splitRequest amount is equal to
// origAmount - newAmount. It also checks that splitRequest is identical (except
// for its amount) to the request of the last output in the tx.
func checkLastOutputWasSplit(t *testing.T, w *withdrawal, tx *withdrawalTx,
	origAmount, newAmount btcutil.Amount) {
	splitRequest := w.pendingRequests[0]
	lastOutput := tx.outputs[len(tx.outputs)-1]
	if lastOutput.amount != newAmount {
		t.Fatalf("Wrong amount in last output; got %s, want %s", lastOutput.amount, newAmount)
	}

	wantSplitAmount := origAmount - newAmount
	if splitRequest.Amount != wantSplitAmount {
		t.Fatalf("Wrong amount in split output; got %v, want %v", splitRequest.Amount,
			wantSplitAmount)
	}

	// Check that the split request is identical (except for its amount) to the
	// original one.
	origRequest := lastOutput.request
	if !bytes.Equal(origRequest.PkScript, splitRequest.PkScript) {
		t.Fatalf("Wrong pkScript in split request; got %x, want %x", splitRequest.PkScript,
			origRequest.PkScript)
	}
	if origRequest.Server != splitRequest.Server {
		t.Fatalf("Wrong server in split request; got %s, want %s", splitRequest.Server,
			origRequest.Server)
	}
	if origRequest.Transaction != splitRequest.Transaction {
		t.Fatalf("Wrong transaction # in split request; got %d, want %d", splitRequest.Transaction,
			origRequest.Transaction)
	}

	status := w.status.outputs[origRequest.outBailmentID()].status
	if status != statusPartial {
		t.Fatalf("Wrong output status; got '%s', want '%s'", status, statusPartial)
	}
}
