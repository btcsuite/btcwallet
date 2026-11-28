// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txsizes

import (
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// Worst case script and input/output size estimates.
const (
	// RedeemP2PKHSigScriptSize is the worst case (largest) serialize size
	// of a transaction input script that redeems a compressed P2PKH output.
	// It is calculated as:
	//
	//   - OP_DATA_73
	//   - 72 bytes DER signature + 1 byte sighash
	//   - OP_DATA_33
	//   - 33 bytes serialized compressed pubkey
	RedeemP2PKHSigScriptSize = 1 + 73 + 1 + 33

	// P2PKHPkScriptSize is the size of a transaction output script that
	// pays to a compressed pubkey hash.  It is calculated as:
	//
	//   - OP_DUP
	//   - OP_HASH160
	//   - OP_DATA_20
	//   - 20 bytes pubkey hash
	//   - OP_EQUALVERIFY
	//   - OP_CHECKSIG
	P2PKHPkScriptSize = 1 + 1 + 1 + 20 + 1 + 1

	// RedeemP2PKHInputSize is the worst case (largest) serialize size of a
	// transaction input redeeming a compressed P2PKH output.  It is
	// calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte compact int encoding value 107
	//   - 107 bytes signature script
	//   - 4 bytes sequence
	RedeemP2PKHInputSize = 32 + 4 + 1 + RedeemP2PKHSigScriptSize + 4

	// P2PKHOutputSize is the serialize size of a transaction output with a
	// P2PKH output script.  It is calculated as:
	//
	//   - 8 bytes output value
	//   - 1 byte compact int encoding value 25
	//   - 25 bytes P2PKH output script
	P2PKHOutputSize = 8 + 1 + P2PKHPkScriptSize

	// P2WPKHPkScriptSize is the size of a transaction output script that
	// pays to a witness pubkey hash. It is calculated as:
	//
	//   - OP_0
	//   - OP_DATA_20
	//   - 20 bytes pubkey hash
	P2WPKHPkScriptSize = 1 + 1 + 20

	// P2WPKHOutputSize is the serialize size of a transaction output with a
	// P2WPKH output script. It is calculated as:
	//
	//   - 8 bytes output value
	//   - 1 byte compact int encoding value 22
	//   - 22 bytes P2PKH output script
	P2WPKHOutputSize = 8 + 1 + P2WPKHPkScriptSize

	// RedeemP2WPKHScriptSize is the size of a transaction input script
	// that spends a pay-to-witness-public-key hash (P2WPKH). The redeem
	// script for P2WPKH spends MUST be empty.
	RedeemP2WPKHScriptSize = 0

	// RedeemP2WPKHInputSize is the worst case size of a transaction
	// input redeeming a P2WPKH output. It is calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte encoding empty redeem script
	//   - 0 bytes redeem script
	//   - 4 bytes sequence
	RedeemP2WPKHInputSize = 32 + 4 + 1 + RedeemP2WPKHScriptSize + 4

	// P2TRPkScriptSize is the size of a transaction output script that
	// pays to a taproot pubkey. It is calculated as:
	//
	//   - OP_1
	//   - OP_DATA_32
	//   - 32 bytes pubkey
	P2TRPkScriptSize = 1 + 1 + 32

	// P2TROutputSize is the serialize size of a transaction output with a
	// P2TR output script. It is calculated as:
	//
	//   - 8 bytes output value
	//   - 1 byte compact int encoding value 34
	//   - 34 bytes P2TR output script
	P2TROutputSize = 8 + 1 + P2TRPkScriptSize

	// RedeemP2TRScriptSize is the size of a transaction input script
	// that spends a pay-to-taproot hash (P2TR). The redeem
	// script for P2TR spends MUST be empty.
	RedeemP2TRScriptSize = 0

	// RedeemP2TRInputSize is the worst case size of a transaction
	// input redeeming a P2TR output. It is calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte encoding empty redeem script
	//   - 0 bytes redeem script
	//   - 4 bytes sequence
	RedeemP2TRInputSize = 32 + 4 + 1 + RedeemP2TRScriptSize + 4

	// NestedP2WPKHPkScriptSize is the size of a transaction output script
	// that pays to a pay-to-witness-key hash nested in P2SH (P2SH-P2WPKH).
	// It is calculated as:
	//
	//   - OP_HASH160
	//   - OP_DATA_20
	//   - 20 bytes script hash
	//   - OP_EQUAL
	NestedP2WPKHPkScriptSize = 1 + 1 + 20 + 1

	// RedeemNestedP2WPKHScriptSize is the worst case size of a transaction
	// input script that redeems a pay-to-witness-key hash nested in P2SH
	// (P2SH-P2WPKH). It is calculated as:
	//
	//   - 1 byte compact int encoding value 22
	//   - OP_0
	//   - 1 byte compact int encoding value 20
	//   - 20 byte key hash
	RedeemNestedP2WPKHScriptSize = 1 + 1 + 1 + 20

	// RedeemNestedP2WPKHInputSize is the worst case size of a
	// transaction input redeeming a P2SH-P2WPKH output. It is
	// calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte compact int encoding value 23
	//   - 23 bytes redeem script (scriptSig)
	//   - 4 bytes sequence
	RedeemNestedP2WPKHInputSize = 32 + 4 + 1 +
		RedeemNestedP2WPKHScriptSize + 4

	// RedeemP2WPKHInputWitnessWeight is the worst case weight of
	// a witness for spending P2WPKH and nested P2WPKH outputs. It
	// is calculated as:
	//
	//   - 1 wu compact int encoding value 2 (number of items)
	//   - 1 wu compact int encoding value 73
	//   - 72 wu DER signature + 1 wu sighash
	//   - 1 wu compact int encoding value 33
	//   - 33 wu serialized compressed pubkey
	RedeemP2WPKHInputWitnessWeight = 1 + 1 + 73 + 1 + 33

	// RedeemP2TRInputWitnessWeight is the worst case weight of
	// a witness for spending P2TR outputs. It
	// is calculated as:
	//
	//   - 1 wu compact int encoding value 1 (number of items)
	//   - 1 wu compact int encoding value 65
	//   - 64 wu BIP-340 schnorr signature + 1 wu sighash
	RedeemP2TRInputWitnessWeight = 1 + 1 + 65
)

// SumOutputSerializeSizes sums up the serialized size of the supplied outputs.
func SumOutputSerializeSizes(outputs []*wire.TxOut) (serializeSize int) {
	for _, txOut := range outputs {
		serializeSize += txOut.SerializeSize()
	}
	return serializeSize
}

// EstimateSerializeSize returns a worst case serialize size estimate for a
// signed transaction that spends inputCount number of compressed P2PKH outputs
// and contains each transaction output from txOuts.  The estimated size is
// incremented for an additional P2PKH change output if addChangeOutput is true.
func EstimateSerializeSize(inputCount int, txOuts []*wire.TxOut, addChangeOutput bool) int {
	changeSize := 0
	outputCount := len(txOuts)
	if addChangeOutput {
		changeSize = P2PKHOutputSize
		outputCount++
	}

	// 8 additional bytes are for version and locktime
	return 8 + wire.VarIntSerializeSize(uint64(inputCount)) +
		wire.VarIntSerializeSize(uint64(outputCount)) +
		inputCount*RedeemP2PKHInputSize +
		SumOutputSerializeSizes(txOuts) +
		changeSize
}

// EstimateVirtualSize returns a worst case virtual size estimate for a
// signed transaction that spends the given number of P2PKH, P2TR, P2WPKH and
// (nested) P2SH-P2WPKH outputs, and contains each transaction output
// from txOuts. The estimate is incremented for an additional change output
// if changeScriptSize is greater than zero.
//
// The virtual size is the transaction weight defined by BIP 141, rounded up
// to whole units:
//
//	weight = base size * (witness scale factor - 1) + total size
//	vsize  = ceil(weight / witness scale factor)
//
// Since the total size is the base size plus the witness data, this is the
// same as charging a full unit for every byte serialized outside the witness
// and a quarter of a unit for every byte serialized inside it. The estimate
// is accumulated in those two parts: baseSize counts the non-witness bytes,
// which are already whole virtual bytes, and witnessWeight counts the witness
// bytes in weight units, which are scaled down at the end.
func EstimateVirtualSize(numP2PKHIns, numP2TRIns, numP2WPKHIns, numNestedP2WPKHIns int,
	txOuts []*wire.TxOut, changeScriptSize int) int {

	inputCount := numP2PKHIns + numP2TRIns + numP2WPKHIns + numNestedP2WPKHIns
	outputCount := len(txOuts)

	changeOutputSize := 0
	if changeScriptSize > 0 {
		changeOutputSize = 8 +
			wire.VarIntSerializeSize(uint64(changeScriptSize)) +
			changeScriptSize
		outputCount++
	}

	// The base size is everything serialized outside the witness: the
	// 4-byte version and the 4-byte locktime, the compact int encoding the
	// number of inputs and the one encoding the number of outputs, the
	// inputs with their worst case redeem scripts, and the outputs from
	// txOuts along with the change output.
	//
	// Note that the change output must be part of the output count, since
	// including it may widen that compact int, e.g. from one byte to three
	// bytes when it is the 253rd output.
	baseSize := 8 +
		wire.VarIntSerializeSize(uint64(inputCount)) +
		wire.VarIntSerializeSize(uint64(outputCount)) +
		numP2PKHIns*RedeemP2PKHInputSize +
		numP2WPKHIns*RedeemP2WPKHInputSize +
		numP2TRIns*RedeemP2TRInputSize +
		numNestedP2WPKHIns*RedeemNestedP2WPKHInputSize +
		SumOutputSerializeSizes(txOuts) +
		changeOutputSize

	// A transaction is only serialized in the BIP 144 format if at least
	// one of its inputs is spent with a witness. That format inserts a
	// marker and a flag byte after the version, which cost 1 weight unit
	// each, and appends one witness stack per input after the outputs.
	//
	// Every input owns a stack, including the legacy P2PKH inputs that
	// have no witness data: their stack is serialized as a compact int
	// encoding zero items, which is a single byte. The stacks of the
	// witness inputs already include their own item counts, as documented
	// on the Redeem*InputWitnessWeight constants.
	witnessWeight := 0
	if numP2WPKHIns+numNestedP2WPKHIns+numP2TRIns > 0 {
		witnessWeight = 2 +
			numP2PKHIns +
			numP2WPKHIns*RedeemP2WPKHInputWitnessWeight +
			numP2TRIns*RedeemP2TRInputWitnessWeight +
			numNestedP2WPKHIns*RedeemP2WPKHInputWitnessWeight
	}

	// The base size is already counted in virtual bytes, so only the
	// witness weight is scaled down. We add 3 to it to make sure the
	// result is always rounded up.
	return baseSize + (witnessWeight+3)/blockchain.WitnessScaleFactor
}

// GetMinInputVirtualSize returns the minimum number of vbytes that this input
// adds to a transaction.
func GetMinInputVirtualSize(pkScript []byte) uint64 {
	var baseSize, witnessWeight uint64
	switch {
	// If this is a p2sh output, we assume this is a
	// nested P2WKH.
	case txscript.IsPayToScriptHash(pkScript):
		baseSize = RedeemNestedP2WPKHInputSize
		witnessWeight = RedeemP2WPKHInputWitnessWeight

	case txscript.IsPayToWitnessPubKeyHash(pkScript):
		baseSize = RedeemP2WPKHInputSize
		witnessWeight = RedeemP2WPKHInputWitnessWeight

	case txscript.IsPayToTaproot(pkScript):
		baseSize = RedeemP2TRInputSize
		witnessWeight = RedeemP2TRInputWitnessWeight

	default:
		baseSize = RedeemP2PKHInputSize
	}

	return baseSize + (witnessWeight+blockchain.WitnessScaleFactor-1)/
		blockchain.WitnessScaleFactor
}
