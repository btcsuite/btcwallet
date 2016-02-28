// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package helpers provides convenience functions to simplify wallet code.  This
// package is intended for internal wallet use only.
package helpers

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

func SumOutputValues(outputs []*wire.TxOut) (totalOutput btcutil.Amount) {
	for _, txOut := range outputs {
		totalOutput += btcutil.Amount(txOut.Value)
	}
	return totalOutput
}

func SumOutputSerializeSizes(outputs []*wire.TxOut) (serializeSize int) {
	for _, txOut := range outputs {
		serializeSize += txOut.SerializeSize()
	}
	return serializeSize
}
