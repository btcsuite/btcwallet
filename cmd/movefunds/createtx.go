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

import (
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
)

// makeTx generates a transaction spending outputs to a single address.
func makeTx(params *chaincfg.Params,
	inputs []*extendedOutPoint,
	addr dcrutil.Address,
	txFee int64) (*wire.MsgTx, error) {
	mtx := wire.NewMsgTx()

	allInAmts := int64(0)
	for _, input := range inputs {
		txIn := wire.NewTxIn(input.op, []byte{})
		mtx.AddTxIn(txIn)
		allInAmts += input.amt
	}

	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}
	txOut := wire.NewTxOut(allInAmts-txFee, pkScript)
	txOut.Version = txscript.DefaultScriptVersion
	mtx.AddTxOut(txOut)

	return mtx, nil

}
