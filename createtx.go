/*
 * Copyright (c) 2013 Conformal Systems LLC <info@conformal.com>
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
	"bytes"
	"errors"
	"fmt"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwire"
	"sort"
	"sync"
	"time"
)

// ErrInsufficientFunds represents an error where there are not enough
// funds from unspent tx outputs for a wallet to create a transaction.
var ErrInsufficientFunds = errors.New("insufficient funds")

// ErrUnknownBitcoinNet represents an error where the parsed or
// requested bitcoin network is invalid (neither mainnet nor testnet).
var ErrUnknownBitcoinNet = errors.New("unknown bitcoin network")

// TxFee represents the global transaction fee added to newly-created
// transactions and sent as a reward to the block miner.
var TxFee struct {
	sync.Mutex
	i int64
}

// ByAmount defines the methods needed to satisify sort.Interface to
// sort a slice of Utxos by their amount.
type ByAmount []*tx.Utxo

func (u ByAmount) Len() int {
	return len(u)
}

func (u ByAmount) Less(i, j int) bool {
	return u[i].Amt < u[j].Amt
}

func (u ByAmount) Swap(i, j int) {
	u[i], u[j] = u[j], u[i]
}

// selectInputs selects the minimum number possible of unspent
// outputs to use to create a new transaction that spends amt satoshis.
// Previous outputs with less than minconf confirmations are ignored.  btcout
// is the total number of satoshis which would be spent by the combination
// of all selected previous outputs.  err will equal ErrInsufficientFunds if there
// are not enough unspent outputs to spend amt.
func selectInputs(s tx.UtxoStore, amt uint64, minconf int) (inputs []*tx.Utxo, btcout uint64, err error) {
	height := getCurHeight()

	// Create list of eligible unspent previous outputs to use as tx
	// inputs, and sort by the amount in reverse order so a minimum number
	// of inputs is needed.
	var eligible []*tx.Utxo
	for _, utxo := range s {
		if int(height-utxo.Height) >= minconf {
			eligible = append(eligible, utxo)
		}
	}
	sort.Sort(sort.Reverse(ByAmount(eligible)))

	// Iterate throguh eligible transactions, appending to outputs and
	// increasing btcout.  This is finished when btcout is greater than the
	// requested amt to spend.
	for _, u := range eligible {
		inputs = append(inputs, u)
		if btcout += u.Amt; btcout >= amt {
			return inputs, btcout, nil
		}
	}
	if btcout < amt {
		return nil, 0, ErrInsufficientFunds
	}

	return inputs, btcout, nil
}

// txToPairs creates a raw transaction sending the amounts for each
// address/amount pair and fee to each address and the miner.  minconf
// specifies the minimum number of confirmations required before an
// unspent output is eligible for spending. Leftover input funds not sent
// to addr or as a fee for the miner are sent to a newly generated
// address. ErrInsufficientFunds is returned if there are not enough
// eligible unspent outputs to create the transaction.
func (w *BtcWallet) txToPairs(pairs map[string]uint64, fee uint64, minconf int) (rawtx []byte, inputs []*tx.Utxo, err error) {
	// Recorded unspent transactions should not be modified until this
	// finishes.
	w.UtxoStore.RLock()
	defer w.UtxoStore.RUnlock()

	// Create a new transaction which will include all input scripts.
	msgtx := btcwire.NewMsgTx()

	// Calculate minimum amount needed for inputs.
	var amt uint64
	for _, v := range pairs {
		amt += v
	}

	// Select unspent outputs to be used in transaction.
	inputs, btcout, err := selectInputs(w.UtxoStore.s, amt+fee, minconf)
	if err != nil {
		return nil, nil, err
	}

	// Add outputs to new tx.
	for addr, amt := range pairs {
		addr160, _, err := btcutil.DecodeAddress(addr)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot decode address: %s", err)
		}

		// Spend amt to addr160
		pkScript, err := btcscript.PayToPubKeyHashScript(addr160)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot create txout script: %s", err)
		}
		txout := btcwire.NewTxOut(int64(amt), pkScript)
		msgtx.AddTxOut(txout)
	}

	// Check if there are leftover unspent outputs, and return coins back to
	// a new address we own.
	if btcout > amt+fee {
		// Create a new address to spend leftover outputs to.
		// TODO(jrick): use the next chained address, not the next unused.
		newaddr, err := w.NextUnusedAddress()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get next unused address: %s", err)
		}

		// Spend change
		change := btcout - (amt + fee)
		newaddr160, _, err := btcutil.DecodeAddress(newaddr)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot decode new address: %s", err)
		}
		pkScript, err := btcscript.PayToPubKeyHashScript(newaddr160)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot create txout script: %s", err)
		}
		msgtx.AddTxOut(btcwire.NewTxOut(int64(change), pkScript))
	}

	// Selected unspent outputs become new transaction's inputs.
	for _, ip := range inputs {
		msgtx.AddTxIn(btcwire.NewTxIn((*btcwire.OutPoint)(&ip.Out), nil))
	}
	for i, ip := range inputs {
		addrstr, err := btcutil.EncodeAddress(ip.AddrHash[:], w.Wallet.Net())
		if err != nil {
			return nil, nil, err
		}
		privkey, err := w.GetAddressKey(addrstr)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot get address key: %v", err)
		}

		// TODO(jrick): we want compressed pubkeys.  Switch wallet to
		// generate addresses from the compressed key.  This will break
		// armory wallet compat but oh well.
		sigscript, err := btcscript.SignatureScript(msgtx, i,
			ip.Subscript, btcscript.SigHashAll, privkey, false)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot create sigscript: %s", err)
		}
		msgtx.TxIn[i].SignatureScript = sigscript
	}

	// Validate msgtx before returning the raw transaction.
	bip16 := time.Now().After(btcscript.Bip16Activation)
	for i, txin := range msgtx.TxIn {
		engine, err := btcscript.NewScript(txin.SignatureScript, inputs[i].Subscript, i,
			msgtx, bip16)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot create script engine: %s", err)
		}
		if err = engine.Execute(); err != nil {
			return nil, nil, fmt.Errorf("cannot validate transaction: %s", err)
		}
	}

	buf := new(bytes.Buffer)
	msgtx.BtcEncode(buf, btcwire.ProtocolVersion)
	return buf.Bytes(), inputs, nil
}
