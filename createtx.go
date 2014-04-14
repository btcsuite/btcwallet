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
	"github.com/conformal/btcchain"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
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

// ErrNonPositiveAmount represents an error where a bitcoin amount is
// not positive (either negative, or zero).
var ErrNonPositiveAmount = errors.New("amount is not positive")

// ErrNegativeFee represents an error where a fee is erroneously
// negative.
var ErrNegativeFee = errors.New("fee is negative")

// minTxFee is the default minimum transation fee (0.0001 BTC,
// measured in satoshis) added to transactions requiring a fee.
const minTxFee = 10000

// TxFeeIncrement represents the global transaction fee per KB of Tx
// added to newly-created transactions and sent as a reward to the block
// miner.  i is measured in satoshis.
var TxFeeIncrement = struct {
	sync.Mutex
	i int64
}{
	i: minTxFee,
}

type CreatedTx struct {
	tx         *btcutil.Tx
	time       time.Time
	changeAddr btcutil.Address
}

// ByAmount defines the methods needed to satisify sort.Interface to
// sort a slice of Utxos by their amount.
type ByAmount []*tx.RecvTxOut

func (u ByAmount) Len() int {
	return len(u)
}

func (u ByAmount) Less(i, j int) bool {
	return u[i].Value() < u[j].Value()
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
func selectInputs(utxos []*tx.RecvTxOut, amt int64,
	minconf int) (selected []*tx.RecvTxOut, btcout int64, err error) {

	bs, err := GetCurBlock()
	if err != nil {
		return nil, 0, err
	}

	// Create list of eligible unspent previous outputs to use as tx
	// inputs, and sort by the amount in reverse order so a minimum number
	// of inputs is needed.
	eligible := make([]*tx.RecvTxOut, 0, len(utxos))
	for _, utxo := range utxos {
		if confirmed(minconf, utxo.Height(), bs.Height) {
			// Coinbase transactions must have have reached maturity
			// before their outputs may be spent.
			if utxo.IsCoinbase() {
				confs := confirms(utxo.Height(), bs.Height)
				if confs < btcchain.CoinbaseMaturity {
					continue
				}
			}
			eligible = append(eligible, utxo)
		}
	}
	sort.Sort(sort.Reverse(ByAmount(eligible)))

	// Iterate throguh eligible transactions, appending to outputs and
	// increasing btcout.  This is finished when btcout is greater than the
	// requested amt to spend.
	for _, e := range eligible {
		selected = append(selected, e)
		btcout += e.Value()
		if btcout >= amt {
			return selected, btcout, nil
		}
	}
	if btcout < amt {
		return nil, 0, ErrInsufficientFunds
	}

	return selected, btcout, nil
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
func (a *Account) txToPairs(pairs map[string]int64, minconf int) (*CreatedTx, error) {
	// Wallet must be unlocked to compose transaction.
	if a.IsLocked() {
		return nil, wallet.ErrWalletLocked
	}

	// Create a new transaction which will include all input scripts.
	msgtx := btcwire.NewMsgTx()

	// Calculate minimum amount needed for inputs.
	var amt int64
	for _, v := range pairs {
		// Error out if any amount is negative.
		if v <= 0 {
			return nil, ErrNonPositiveAmount
		}
		amt += v
	}

	// Add outputs to new tx.
	for addrStr, amt := range pairs {
		addr, err := btcutil.DecodeAddress(addrStr, cfg.Net())
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
	bs, err := GetCurBlock()
	if err != nil {
		return nil, err
	}

	// Make a copy of msgtx before any inputs are added.  This will be
	// used as a starting point when trying a fee and starting over with
	// a higher fee if not enough was originally chosen.
	txNoInputs := msgtx.Copy()

	var selectedInputs []*tx.RecvTxOut
	// These are nil/zeroed until a change address is needed, and reused
	// again in case a change utxo has already been chosen.
	var changeAddr btcutil.Address

	// Get the number of satoshis to increment fee by when searching for
	// the minimum tx fee needed.
	fee := int64(0)
	for {
		msgtx = txNoInputs.Copy()

		// Select unspent outputs to be used in transaction based on the amount
		// neededing to sent, and the current fee estimation.
		inputs, btcin, err := selectInputs(a.TxStore.UnspentOutputs(),
			amt+fee, minconf)
		if err != nil {
			return nil, err
		}

		// Check if there are leftover unspent outputs, and return coins back to
		// a new address we own.
		//
		// TODO: change needs to be inserted into a random txout index, or else
		// this is a privacy risk.
		change := btcin - amt - fee
		if change > 0 {
			// Get a new change address if one has not already been found.
			if changeAddr == nil {
				changeAddr, err = a.ChangeAddress(&bs, cfg.KeypoolSize)
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
		}

		// Selected unspent outputs become new transaction's inputs.
		for _, ip := range inputs {
			msgtx.AddTxIn(btcwire.NewTxIn(ip.OutPoint(), nil))
		}
		for i, input := range inputs {
			_, addrs, _, _ := input.Addresses(cfg.Net())
			if len(addrs) != 1 {
				continue
			}
			apkh, ok := addrs[0].(*btcutil.AddressPubKeyHash)
			if !ok {
				continue // don't handle inputs to this yes
			}

			ai, err := a.Address(apkh)
			if err != nil {
				return nil, fmt.Errorf("cannot get address info: %v", err)
			}

			pka := ai.(wallet.PubKeyAddress)

			privkey, err := pka.PrivKey()
			if err == wallet.ErrWalletLocked {
				return nil, wallet.ErrWalletLocked
			} else if err != nil {
				return nil, fmt.Errorf("cannot get address key: %v", err)
			}

			sigscript, err := btcscript.SignatureScript(msgtx, i,
				input.PkScript(), btcscript.SigHashAll, privkey,
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
		if minFee := minimumFee(msgtx, noFeeAllowed); fee < minFee {
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
			selectedInputs[i].PkScript(), i, msgtx, flags)
		if err != nil {
			return nil, fmt.Errorf("cannot create script engine: %s", err)
		}
		if err = engine.Execute(); err != nil {
			return nil, fmt.Errorf("cannot validate transaction: %s", err)
		}
	}

	buf := new(bytes.Buffer)
	msgtx.BtcEncode(buf, btcwire.ProtocolVersion)
	info := &CreatedTx{
		tx:         btcutil.NewTx(msgtx),
		time:       time.Now(),
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
func minimumFee(tx *btcwire.MsgTx, allowFree bool) int64 {
	txLen := tx.SerializeSize()
	TxFeeIncrement.Lock()
	incr := TxFeeIncrement.i
	TxFeeIncrement.Unlock()
	fee := int64(1+txLen/1000) * incr

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
// priority reaches a certain threshhold.  If the threshhold is
// reached, a free transaction fee is allowed.
func allowFree(curHeight int32, txouts []*tx.RecvTxOut, txSize int) bool {
	const blocksPerDayEstimate = 144
	const txSizeEstimate = 250

	var weightedSum int64
	for _, txout := range txouts {
		depth := chainDepth(txout.Height(), curHeight)
		weightedSum += txout.Value() * int64(depth)
	}
	priority := float64(weightedSum) / float64(txSize)
	return priority > float64(btcutil.SatoshiPerBitcoin)*blocksPerDayEstimate/txSizeEstimate
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
