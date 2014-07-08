/*
 * Copyright (c) 2013, 2014 Conformal Systems LLC <info@conformal.com>
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
	badrand "math/rand"
	"sort"
	"time"

	"github.com/conformal/btcchain"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/keystore"
	"github.com/conformal/btcwallet/txstore"
	"github.com/conformal/btcwire"
)

// InsufficientFunds represents an error where there are not enough
// funds from unspent tx outputs for a wallet to create a transaction.
// This may be caused by not enough inputs for all of the desired total
// transaction output amount, or due to
type InsufficientFunds struct {
	in, out, fee btcutil.Amount
}

// Error satisifies the builtin error interface.
func (e InsufficientFunds) Error() string {
	total := e.out + e.fee
	if e.fee == 0 {
		return fmt.Sprintf("insufficient funds: transaction requires "+
			"%s input but only %v spendable", total, e.in)
	}
	return fmt.Sprintf("insufficient funds: transaction requires %s input "+
		"(%v output + %v fee) but only %v spendable", total, e.out,
		e.fee, e.in)
}

// ErrNonPositiveAmount represents an error where a bitcoin amount is
// not positive (either negative, or zero).
var ErrNonPositiveAmount = errors.New("amount is not positive")

// ErrNegativeFee represents an error where a fee is erroneously
// negative.
var ErrNegativeFee = errors.New("fee is negative")

// defaultFeeIncrement is the default minimum transation fee (0.0001 BTC,
// measured in satoshis) added to transactions requiring a fee.
const defaultFeeIncrement = 10000

type CreatedTx struct {
	tx         *btcutil.Tx
	inputs     []txstore.Credit
	changeAddr btcutil.Address
}

// ByAmount defines the methods needed to satisify sort.Interface to
// sort a slice of Utxos by their amount.
type ByAmount []txstore.Credit

func (u ByAmount) Len() int           { return len(u) }
func (u ByAmount) Less(i, j int) bool { return u[i].Amount() < u[j].Amount() }
func (u ByAmount) Swap(i, j int)      { u[i], u[j] = u[j], u[i] }

// selectInputs selects the minimum number possible of unspent
// outputs to use to create a new transaction that spends amt satoshis.
// btcout is the total number of satoshis which would be spent by the
// combination of all selected previous outputs.  err will equal
// ErrInsufficientFunds if there are not enough unspent outputs to spend amt
// amt.
func selectInputs(eligible []txstore.Credit, amt, fee btcutil.Amount,
	minconf int) (selected []txstore.Credit, out btcutil.Amount, err error) {

	// Iterate throguh eligible transactions, appending to outputs and
	// increasing out.  This is finished when out is greater than the
	// requested amt to spend.
	selected = make([]txstore.Credit, 0, len(eligible))
	for _, e := range eligible {
		selected = append(selected, e)
		out += e.Amount()
		if out >= amt+fee {
			return selected, out, nil
		}
	}
	if out < amt+fee {
		return nil, 0, InsufficientFunds{out, amt, fee}
	}

	return selected, out, nil
}

// txToPairs creates a raw transaction sending the amounts for each
// address/amount pair and fee to each address and the miner.  minconf
// specifies the minimum number of confirmations required before an
// unspent output is eligible for spending. Leftover input funds not sent
// to addr or as a fee for the miner are sent to a newly generated
// address. If change is needed to return funds back to an owned
// address, changeUtxo will point to a unconfirmed (height = -1, zeroed
// block hash) Utxo.  ErrInsufficientFunds is returned if there are not
// enough eligible unspent outputs to create the transaction.
func (a *Account) txToPairs(pairs map[string]btcutil.Amount,
	minconf int) (*CreatedTx, error) {

	// Wallet must be unlocked to compose transaction.
	if a.KeyStore.IsLocked() {
		return nil, keystore.ErrLocked
	}

	// Create a new transaction which will include all input scripts.
	msgtx := btcwire.NewMsgTx()

	// Calculate minimum amount needed for inputs.
	var amt btcutil.Amount
	for _, v := range pairs {
		// Error out if any amount is negative.
		if v <= 0 {
			return nil, ErrNonPositiveAmount
		}
		amt += v
	}

	// Add outputs to new tx.
	for addrStr, amt := range pairs {
		addr, err := btcutil.DecodeAddress(addrStr, activeNet.Params)
		if err != nil {
			return nil, fmt.Errorf("cannot decode address: %s", err)
		}

		// Add output to spend amt to addr.
		pkScript, err := btcscript.PayToAddrScript(addr)
		if err != nil {
			return nil, fmt.Errorf("cannot create txout script: %s", err)
		}
		txout := btcwire.NewTxOut(int64(amt), pkScript)
		msgtx.AddTxOut(txout)
	}

	// Get current block's height and hash.
	rpcc, err := accessClient()
	if err != nil {
		return nil, err
	}
	bs, err := rpcc.BlockStamp()
	if err != nil {
		return nil, err
	}

	// Make a copy of msgtx before any inputs are added.  This will be
	// used as a starting point when trying a fee and starting over with
	// a higher fee if not enough was originally chosen.
	txNoInputs := msgtx.Copy()

	unspent, err := a.TxStore.UnspentOutputs()
	if err != nil {
		return nil, err
	}

	// Filter out unspendable outputs, that is, remove those that (at this
	// time) are not P2PKH outputs.  Other inputs must be manually included
	// in transactions and sent (for example, using createrawtransaction,
	// signrawtransaction, and sendrawtransaction).
	eligible := make([]txstore.Credit, 0, len(unspent))
	for i := range unspent {
		switch btcscript.GetScriptClass(unspent[i].TxOut().PkScript) {
		case btcscript.PubKeyHashTy:
			if !unspent[i].Confirmed(minconf, bs.Height) {
				continue
			}
			// Coinbase transactions must have have reached maturity
			// before their outputs may be spent.
			if unspent[i].IsCoinbase() {
				target := btcchain.CoinbaseMaturity
				if !unspent[i].Confirmed(target, bs.Height) {
					continue
				}
			}

			// Locked unspent outputs are skipped.
			if a.LockedOutpoint(*unspent[i].OutPoint()) {
				continue
			}

			eligible = append(eligible, unspent[i])
		}
	}

	// Sort eligible inputs, as selectInputs expects these to be sorted
	// by amount in reverse order.
	sort.Sort(sort.Reverse(ByAmount(eligible)))

	var selectedInputs []txstore.Credit
	// changeAddr is nil/zeroed until a change address is needed, and reused
	// again in case a change utxo has already been chosen.
	var changeAddr btcutil.Address

	// Get the number of satoshis to increment fee by when searching for
	// the minimum tx fee needed.
	fee := btcutil.Amount(0)
	for {
		msgtx = txNoInputs.Copy()

		// Select eligible outputs to be used in transaction based on the amount
		// neededing to sent, and the current fee estimation.
		inputs, btcin, err := selectInputs(eligible, amt, fee, minconf)
		if err != nil {
			return nil, err
		}

		// Check if there are leftover unspent outputs, and return coins back to
		// a new address we own.
		change := btcin - amt - fee
		if change > 0 {
			// Get a new change address if one has not already been found.
			if changeAddr == nil {
				changeAddr, err = a.KeyStore.ChangeAddress(&bs, cfg.KeypoolSize)
				if err != nil {
					return nil, fmt.Errorf("failed to get next address: %s", err)
				}

				// Mark change address as belonging to this account.
				AcctMgr.MarkAddressForAccount(changeAddr, a)
			}

			// Spend change.
			pkScript, err := btcscript.PayToAddrScript(changeAddr)
			if err != nil {
				return nil, fmt.Errorf("cannot create txout script: %s", err)
			}
			msgtx.AddTxOut(btcwire.NewTxOut(int64(change), pkScript))

			// Randomize index of the change output.
			rng := badrand.New(badrand.NewSource(time.Now().UnixNano()))
			r := rng.Int31n(int32(len(msgtx.TxOut))) // random index
			c := len(msgtx.TxOut) - 1                // change index
			msgtx.TxOut[r], msgtx.TxOut[c] = msgtx.TxOut[c], msgtx.TxOut[r]
		}

		// Selected unspent outputs become new transaction's inputs.
		for _, ip := range inputs {
			msgtx.AddTxIn(btcwire.NewTxIn(ip.OutPoint(), nil))
		}
		for i, input := range inputs {
			// Errors don't matter here, as we only consider the
			// case where len(addrs) == 1.
			_, addrs, _, _ := input.Addresses(activeNet.Params)
			if len(addrs) != 1 {
				continue
			}
			apkh, ok := addrs[0].(*btcutil.AddressPubKeyHash)
			if !ok {
				continue // don't handle inputs to this yes
			}

			ai, err := a.KeyStore.Address(apkh)
			if err != nil {
				return nil, fmt.Errorf("cannot get address info: %v", err)
			}

			pka := ai.(keystore.PubKeyAddress)

			privkey, err := pka.PrivKey()
			if err == keystore.ErrLocked {
				return nil, keystore.ErrLocked
			} else if err != nil {
				return nil, fmt.Errorf("cannot get address key: %v", err)
			}

			sigscript, err := btcscript.SignatureScript(msgtx, i,
				input.TxOut().PkScript, btcscript.SigHashAll, privkey,
				ai.Compressed())
			if err != nil {
				return nil, fmt.Errorf("cannot create sigscript: %s", err)
			}
			msgtx.TxIn[i].SignatureScript = sigscript
		}

		noFeeAllowed := false
		if !cfg.DisallowFree {
			noFeeAllowed = allowFree(bs.Height, inputs, msgtx.SerializeSize())
		}
		if minFee := minimumFee(a.FeeIncrement, msgtx, noFeeAllowed); fee < minFee {
			fee = minFee
		} else {
			selectedInputs = inputs
			break
		}
	}

	// Validate msgtx before returning the raw transaction.
	flags := btcscript.ScriptCanonicalSignatures
	bip16 := time.Now().After(btcscript.Bip16Activation)
	if bip16 {
		flags |= btcscript.ScriptBip16
	}
	for i, txin := range msgtx.TxIn {
		engine, err := btcscript.NewScript(txin.SignatureScript,
			selectedInputs[i].TxOut().PkScript, i, msgtx, flags)
		if err != nil {
			return nil, fmt.Errorf("cannot create script engine: %s", err)
		}
		if err = engine.Execute(); err != nil {
			return nil, fmt.Errorf("cannot validate transaction: %s", err)
		}
	}

	buf := bytes.Buffer{}
	buf.Grow(msgtx.SerializeSize())
	if err := msgtx.BtcEncode(&buf, btcwire.ProtocolVersion); err != nil {
		// Hitting OOM by growing or writing to a bytes.Buffer already
		// panics, and all returned errors are unexpected.
		panic(err)
	}
	info := &CreatedTx{
		tx:         btcutil.NewTx(msgtx),
		inputs:     selectedInputs,
		changeAddr: changeAddr,
	}
	return info, nil
}

// minimumFee calculates the minimum fee required for a transaction.
// If allowFree is true, a fee may be zero so long as the entire
// transaction has a serialized length less than 1 kilobyte
// and none of the outputs contain a value less than 1 bitcent.
// Otherwise, the fee will be calculated using TxFeeIncrement,
// incrementing the fee for each kilobyte of transaction.
func minimumFee(incr btcutil.Amount, tx *btcwire.MsgTx, allowFree bool) btcutil.Amount {
	txLen := tx.SerializeSize()
	fee := btcutil.Amount(int64(1+txLen/1000) * int64(incr))

	if allowFree && txLen < 1000 {
		fee = 0
	}

	if fee < incr {
		for _, txOut := range tx.TxOut {
			if txOut.Value < btcutil.SatoshiPerBitcent {
				return incr
			}
		}
	}

	if fee < 0 || fee > btcutil.MaxSatoshi {
		fee = btcutil.MaxSatoshi
	}

	return fee
}

// allowFree calculates the transaction priority and checks that the
// priority reaches a certain threshold.  If the threshhold is
// reached, a free transaction fee is allowed.
func allowFree(curHeight int32, txouts []txstore.Credit, txSize int) bool {
	const blocksPerDayEstimate = 144.0
	const txSizeEstimate = 250.0
	const threshold = btcutil.SatoshiPerBitcoin * blocksPerDayEstimate / txSizeEstimate

	var weightedSum int64
	for _, txout := range txouts {
		depth := chainDepth(txout.BlockHeight, curHeight)
		weightedSum += int64(txout.Amount()) * int64(depth)
	}
	priority := float64(weightedSum) / float64(txSize)
	return priority > threshold
}

// chainDepth returns the chaindepth of a target given the current
// blockchain height.
func chainDepth(target, current int32) int32 {
	if target == -1 {
		// target is not yet in a block.
		return 0
	}

	// target is in a block.
	return current - target + 1
}
