/*
 * Copyright (c) 2016 The Decred developers
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

package main

const (
	// All transactions have 4 bytes for version, 4 bytes of locktime,
	// 4 bytes of expiry, and 2 varints for the number of inputs and
	// outputs, and 1 varint for the witnesses.
	txOverheadEstimate = 4 + 4 + 4 + 1 + 1 + 1

	// A worst case signature script to redeem a P2PKH output for a
	// compressed pubkey has 73 bytes of the possible DER signature
	// (with no leading 0 bytes for R and S), 65 bytes of serialized pubkey,
	// and data push opcodes for both, plus one byte for the hash type flag
	// appended to the end of the signature.
	sigScriptEstimate = 1 + 73 + 1 + 65 + 1

	// A best case tx input serialization cost is 32 bytes of sha, 4 bytes
	// of output index, 1 byte for tree, 4 bytes of sequence, 12 bytes for
	// fraud proof, one byte for both the txin signature size (0) and the
	// witness signature script size, and the estimated signature script
	// size.
	txInEstimate = 32 + 4 + 1 + 12 + 4 + 1 + 1 + sigScriptEstimate

	// A P2PKH pkScript contains the following bytes:
	//  - OP_DUP
	//  - OP_HASH160
	//  - OP_DATA_20 + 20 bytes of pubkey hash
	//  - OP_EQUALVERIFY
	//  - OP_CHECKSIG
	pkScriptEstimate = 1 + 1 + 1 + 20 + 1 + 1

	// txOutEstimate is a best case tx output serialization cost is 8 bytes
	// of value, two bytes of version, one byte of varint, and the pkScript
	// size.
	txOutEstimate = 8 + 2 + 1 + pkScriptEstimate
)

var (
	// maxTxSize is the maximum size of a transaction we can
	// build with the wallet.
	maxTxSize int
)

func estimateTxSize(numInputs, numOutputs int) int {
	return txOverheadEstimate + txInEstimate*numInputs + txOutEstimate*numOutputs
}
