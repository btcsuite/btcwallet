package txauthor

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// txSelectionError is defined so that we can signal the missing
// amount to the calling software, so that one can easily create
// transactions which satisfy the fee requirements.
type txSelectionError struct {
	targetAmount btcutil.Amount
	txFee        btcutil.Amount
	availableAmt btcutil.Amount
}

func (txSelectionError) InputSourceError() {

}

func (e txSelectionError) Error() string {
	return fmt.Sprintf("insufficient funds available to construct "+
		"transaction: amount: %v, minimum fee: %v, available amount: %v",
		e.targetAmount, e.txFee, e.availableAmt)
}

// InputSelectionStrategy defines how funds are selected when
// building a UnsignedTransaction. Its analogous to CoinSelectionStrategy
// which should be deprecated in the furture using this type.
type InputSelectionStrategy int

const (
	// PositiveYieldingSelection requires the inputs to be
	// ordered by amount so that we can fail early in case
	// an input is not positive yielding. This means the selection
	// does not care of follow up inputs as soon as the first is negative
	// yielding.
	PositiveYieldingSelection InputSelectionStrategy = iota

	// RandomSelection means there could still be some inputs
	// which are larger than the previous ones therefore this strategy
	// considers all inputs as long as the target amount is not
	// reached.
	RandomSelection

	// ConstantSelection should use all inputs which are present when
	// creating the transaction, also the ones which are negative yielding.
	// All inputs are added although less would be also sufficient to create
	// the transaction.
	ConstantSelection
)

// inputState holds the current state of the transaction including all inputs
// which were selected so far.
type inputState struct {
	// feeRatePerKb is the feerate which is used for fee calculation.
	feeRatePerKb btcutil.Amount

	// txFee is the fee of the current transaction state
	// when serialized in satoshis.
	txFee btcutil.Amount

	// inputTotal is the total value of all selected inputs.
	inputTotal btcutil.Amount

	// targetAmount is the amount we want to fund with the transaction
	// not include the change.
	targetAmount btcutil.Amount

	// changeOutpoint is the  change output of the transaction. This will
	// be what is left over after subtracting the targetAmount and
	// the tx fee from the inputTotal.
	//
	// NOTE: This (value) might be below the dust limit, or even negative
	// since it is the change remaining in case we pay the fee for a change
	// output.
	changeOutpoint wire.TxOut

	// inputs is the set of tx inputs which will be used to create the
	// transaction. We used the Credit type here because we need to know
	// which type the unspent inputs are (P2WKH, P2TR etc.) to calculate the
	// fees correctly.
	//
	// NOTE: Depending on the selection strategy it can contain negative
	// yielding inputs (ConstantSelection)
	inputs []wtxmgr.Credit

	// outputs are the outputs of the transaction not including the change.
	//
	// NOTE: This might also be empty in case we sweep a wallet for example.
	outputs []*wire.TxOut

	// selectionStrategy determines which criteria is used to make the
	// input selection.
	selectionStrategy InputSelectionStrategy
}

// virutalSizeEstimate is the (worst case) tx size with the current set of
// inputs. It takes a parameter whether to add a change output or not.
func (t *inputState) virutalSizeEstimate(change bool) int {
	// We count the types of inputs, which we'll use to estimate
	// the vsize of the transaction.
	var (
		nested, p2wpkh, p2tr, p2pkh int
		changeScriptSize            int = len(t.changeOutpoint.PkScript)
	)
	for _, input := range t.inputs {
		pkScript := input.PkScript
		switch {
		// If this is a p2sh output, we assume this is a
		// nested P2WKH.
		case txscript.IsPayToScriptHash(pkScript):
			nested++
		case txscript.IsPayToWitnessPubKeyHash(pkScript):
			p2wpkh++
		case txscript.IsPayToTaproot(pkScript):
			p2tr++
		default:
			p2pkh++
		}
	}

	// maxSignedSize is the worst case size estimate including the
	// witness data for the transaction.
	var maxSignedSize int
	if change {
		maxSignedSize = txsizes.EstimateVirtualSize(
			p2pkh, p2tr, p2wpkh, nested, t.outputs, changeScriptSize,
		)
	} else {
		maxSignedSize = txsizes.EstimateVirtualSize(
			p2pkh, p2tr, p2wpkh, nested, t.outputs, 0,
		)
	}

	return maxSignedSize
}

// enoughInput returns true if we've accumulated enough inputs to pay the fees
// and have at least one output that meets the dust limit.
func (t *inputState) enoughInput() bool {
	// If we have a change output above dust, then we certainly have enough
	// inputs to the transaction.
	if !txrules.IsDustOutput(&t.changeOutpoint,
		txrules.DefaultRelayFeePerKb) {
		return true
	}

	// We did not have enough input for a change output. Check if we have
	// enough input to pay the fees for a transaction with no change
	// output.
	t.txFee = txrules.FeeForSerializeSize(
		t.feeRatePerKb, t.virutalSizeEstimate(false),
	)

	if t.inputTotal < t.targetAmount+t.txFee {
		return false
	}

	// We still have to check whether we have an output when we could not
	// create change output.
	if len(t.outputs) == 0 {
		return false
	}

	// We passed all and can create a valid transaction paying for the fees.
	return true
}

// clone copies the inputState.
func (t *inputState) clone() inputState {
	s := inputState{
		feeRatePerKb:      t.feeRatePerKb,
		txFee:             t.txFee,
		inputTotal:        t.inputTotal,
		changeOutpoint:    t.changeOutpoint,
		selectionStrategy: t.selectionStrategy,
		targetAmount:      t.targetAmount,
		outputs:           make([]*wire.TxOut, len(t.outputs)),
		inputs:            make([]wtxmgr.Credit, len(t.inputs)),
	}

	// we deepcopy outputs otherwise changing the clone would lead to
	// changing the initial state of the outputs.
	for idx, out := range t.outputs {
		cpy := *out
		s.outputs[idx] = &cpy
	}

	copy(s.inputs, t.inputs)

	return s
}

// totalOutput returns the total amount of the current tx selection meaning the
// sum of all outputs including the change output.
//
// NOTE: This might be dust or even negativ when adding a negative yielding.
func (t *inputState) totalOutput() btcutil.Amount {
	// When there are still no inputs added we default to a total amount
	// of 0 to bootstrap the tx selection process. Otherwise the addition
	// of inputs fail unless they overshoot the target amount. This happens
	// because the change output can be negative until the final target
	// amount is not met.
	if len(t.inputs) == 0 {
		return 0
	}

	return t.targetAmount + btcutil.Amount(t.changeOutpoint.Value)
}

// addToState adds a new input to the set. It returns a bool indicating whether
// the input was added to the set successfully. An input is rejected if it
// decreases the tx output value after paying fees (depending on the
// input selection strategy).
func (t *inputState) addToState(inputs ...wtxmgr.Credit) *inputState {
	// Clone the current set state.
	tempInputState := t.clone()

	for _, input := range inputs {
		tempInputState.inputs = append(tempInputState.inputs, input)
		tempInputState.inputTotal += input.Amount
	}

	// Recalculate the tx fee.
	tempInputState.txFee = txrules.FeeForSerializeSize(
		tempInputState.feeRatePerKb,
		tempInputState.virutalSizeEstimate(true),
	)

	tempInputState.changeOutpoint.Value = int64(tempInputState.inputTotal -
		tempInputState.targetAmount - tempInputState.txFee)

	// Calculate the yield of this input from the change in total tx output
	// value.
	inputYield := tempInputState.totalOutput() - t.totalOutput()

	switch t.selectionStrategy {
	// Don't add inputs that cost more for us to use when selecting
	// inputs via positive yield or random selection.
	case PositiveYieldingSelection, RandomSelection:
		if inputYield <= 0 {
			return nil
		}

	// ConstantSelection does not include an yield check. All inputs
	// are used for the transaction.
	case ConstantSelection:
	}

	return &tempInputState
}

func (t *inputState) add(inputs ...wtxmgr.Credit) bool {
	newState := t.addToState(inputs...)
	if newState == nil {
		return false
	}

	// We copy the contents of the new state to our main inputState.
	// just copying the pointer would lead to information loss.
	*t = newState.clone()
	return true
}
