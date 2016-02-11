/*
 * Copyright (c) 2013-2015 The btcsuite developers
 * Copyright (c) 2015-2016 The Decred developers
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

package wallet

import (
	"errors"
	"fmt"
	badrand "math/rand"
	"sort"
	"strings"
	"time"

	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/wstakemgr"
	"github.com/decred/dcrwallet/wtxmgr"
)

// --------------------------------------------------------------------------------
// Constants and simple functions

const (
	// All transactions have 4 bytes for version, 4 bytes of locktime,
	// and 2 varints for the number of inputs and outputs, and 1 varint
	// for the witnesses.
	txOverheadEstimate = 4 + 4 + 1 + 1 + 1

	// A worst case signature script to redeem a P2PKH output for a
	// compressed pubkey has 73 bytes of the possible DER signature
	// (with no leading 0 bytes for R and S), 65 bytes of serialized pubkey,
	// and data push opcodes for both, plus one byte for the hash type flag
	// appended to the end of the signature.
	sigScriptEstimate = 1 + 73 + 1 + 65 + 1

	// A best case tx input serialization cost is 32 bytes of sha, 4 bytes
	// of output index, 1 byte for tree, 4 bytes of sequence, and the
	// estimated signature script size.
	txInEstimate = 32 + 4 + 1 + 4 + sigScriptEstimate

	// A P2PKH pkScript contains the following bytes:
	//  - OP_DUP
	//  - OP_HASH160
	//  - OP_DATA_20 + 20 bytes of pubkey hash
	//  - OP_EQUALVERIFY
	//  - OP_CHECKSIG
	pkScriptEstimate = 1 + 1 + 1 + 20 + 1 + 1

	// pkScriptEstimateSS
	pkScriptEstimateSS = 1 + 1 + 1 + 1 + 20 + 1 + 1

	// txOutEstimate is a best case tx output serialization cost is 8 bytes of value, one
	// byte of varint, and the pkScript size.
	txOutEstimate = 8 + 1 + pkScriptEstimate

	// ssTxOutEsimate
	ssTxOutEsimate = 8 + 1 + pkScriptEstimateSS
)

var (
	// maxTxSize is the maximum size of a transaction we can
	// build with the wallet.
	maxTxSize = chaincfg.MainNetParams.MaximumBlockSize - 75000
)

func estimateTxSize(numInputs, numOutputs int) int {
	return txOverheadEstimate + txInEstimate*numInputs + txOutEstimate*numOutputs
}

func EstimateTxSize(numInputs, numOutputs int) int {
	return estimateTxSize(numInputs, numOutputs)
}

func estimateSSTxSize(numInputs, numOutputs int) int {
	return txOverheadEstimate + txInEstimate*numInputs + ssTxOutEsimate*numOutputs
}

func feeForSize(incr dcrutil.Amount, sz int) dcrutil.Amount {
	return dcrutil.Amount(1+sz/1000) * incr
}

func FeeForSize(incr dcrutil.Amount, sz int) dcrutil.Amount {
	return feeForSize(incr, sz)
}

// FeeIncrementMainnet is the default minimum transation fee (0.05 coin,
// measured in atoms) added to transactions requiring a fee for MainNet.
const FeeIncrementMainnet = 5e6

// FeeIncrementTestnet is the default minimum transation fee (0.00001 coin,
// measured in atoms) added to transactions requiring a fee for TestNet.
const FeeIncrementTestnet = 1e3

// --------------------------------------------------------------------------------
// Error Handling

// InsufficientFundsError represents an error where there are not enough
// funds from unspent tx outputs for a wallet to create a transaction.
// This may be caused by not enough inputs for all of the desired total
// transaction output amount, or due to
type InsufficientFundsError struct {
	in, out, fee dcrutil.Amount
}

// Error satisifies the builtin error interface.
func (e InsufficientFundsError) Error() string {
	total := e.out + e.fee
	if e.fee == 0 {
		return fmt.Sprintf("insufficient funds: transaction requires "+
			"%s input but only %v spendable", total, e.in)
	}
	return fmt.Sprintf("insufficient funds: transaction requires %s input "+
		"(%v output + %v fee) but only %v spendable", total, e.out,
		e.fee, e.in)
}

// ErrUnsupportedTransactionType represents an error where a transaction
// cannot be signed as the API only supports spending P2PKH outputs.
var ErrUnsupportedTransactionType = errors.New("Only P2PKH transactions " +
	"are supported")

// ErrNonPositiveAmount represents an error where an amount is
// not positive (either negative, or zero).
var ErrNonPositiveAmount = errors.New("amount is not positive")

// ErrNegativeFee represents an error where a fee is erroneously
// negative.
var ErrNegativeFee = errors.New("fee is negative")

// ErrSStxNotEnoughFunds indicates that not enough funds were available in the
// wallet to purchase a ticket.
var ErrSStxNotEnoughFunds = errors.New("not enough to purchase sstx")

// ErrSStxPriceExceedsSpendLimit indicates that the current ticket price exceeds
// the specified spend maximum spend limit.
var ErrSStxPriceExceedsSpendLimit = errors.New("ticket price exceeds spend limit")

// ErrSStxInputOverflow indicates that too many inputs were used to generate
// a ticket.
var ErrSStxInputOverflow = errors.New("too many inputs to purchase ticket with")

// ErrNoOutsToConsolidate indicates that there were no outputs available
// to compress.
var ErrNoOutsToConsolidate = errors.New("no outputs to consolidate")

// ErrBlockchainReorganizing indicates that the blockchain is currently
// reorganizing.
var ErrBlockchainReorganizing = errors.New("blockchain is currently " +
	"reorganizing")

// ErrTicketPriceNotSet indicates that the wallet was recently connected
// and that the ticket price has not yet been set.
var ErrTicketPriceNotSet = errors.New("ticket price not yet established")

// ErrClientPurchaseTicket is the error returned when the daemon has
// disconnected from the
var ErrClientPurchaseTicket = errors.New("sendrawtransaction failed: the " +
	"client has been shutdown")

// --------------------------------------------------------------------------------
// Transaction creation

// CreatedTx holds the state of a newly-created transaction and the change
// output (if one was added).
type CreatedTx struct {
	MsgTx       *wire.MsgTx
	ChangeAddr  dcrutil.Address
	ChangeIndex int // negative if no change
}

// ByAmount defines the methods needed to satisify sort.Interface to
// sort a slice of Utxos by their amount.
type ByAmount []wtxmgr.Credit

func (u ByAmount) Len() int           { return len(u) }
func (u ByAmount) Less(i, j int) bool { return u[i].Amount < u[j].Amount }
func (u ByAmount) Swap(i, j int)      { u[i], u[j] = u[j], u[i] }

// insertIntoTxMgr inserts a newly created transaction into the tx store
// as unconfirmed.
func (w *Wallet) insertIntoTxMgr(msgTx *wire.MsgTx) (*wtxmgr.TxRecord, error) {
	// Create transaction record and insert into the db.
	rec, err := wtxmgr.NewTxRecordFromMsgTx(msgTx, time.Now())
	if err != nil {
		return nil, dcrjson.ErrInternal
	}

	return rec, w.TxStore.InsertTx(rec, nil)
}

func (w *Wallet) insertCreditsIntoTxMgr(msgTx *wire.MsgTx,
	rec *wtxmgr.TxRecord) error {
	// Check every output to determine whether it is controlled by a wallet
	// key.  If so, mark the output as a credit.
	for i, output := range msgTx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.Version,
			output.PkScript, w.chainParams)
		if err != nil {
			// Non-standard outputs are skipped.
			continue
		}
		for _, addr := range addrs {
			ma, err := w.Manager.Address(addr)
			if err == nil {
				// TODO: Credits should be added with the
				// account they belong to, so wtxmgr is able to
				// track per-account balances.
				err = w.TxStore.AddCredit(rec, nil, uint32(i),
					ma.Internal())
				if err != nil {
					return err
				}
				err = w.Manager.MarkUsed(addr)
				if err != nil {
					return err
				}
				log.Debugf("Marked address %v used", addr)
				continue
			}

			// Missing addresses are skipped.  Other errors should
			// be propagated.
			code := err.(waddrmgr.ManagerError).ErrorCode
			if code != waddrmgr.ErrAddressNotFound {
				return err
			}
		}
	}

	return nil
}

// insertMultisigOutIntoTxMgr inserts a multisignature output into the
// transaction store database.
func (w *Wallet) insertMultisigOutIntoTxMgr(msgTx *wire.MsgTx,
	index uint32) error {
	// Create transaction record and insert into the db.
	rec, err := wtxmgr.NewTxRecordFromMsgTx(msgTx, time.Now())
	if err != nil {
		return dcrjson.ErrInternal
	}

	return w.TxStore.AddMultisigOut(rec, nil, index)
}

// NewAddress returns the next external chained address for a wallet.
func (w *Wallet) NewAddress(account uint32) (dcrutil.Address, error) {
	// Get next address from wallet.
	addrs, err := w.Manager.NextExternalAddresses(account, 1)
	if err != nil {
		return nil, err
	}

	// Request updates from dcrd for new transactions sent to this address.
	utilAddrs := make([]dcrutil.Address, len(addrs))
	for i, addr := range addrs {
		utilAddrs[i] = addr.Address()
	}
	if err := w.chainSvr.NotifyReceived(utilAddrs); err != nil {
		return nil, err
	}

	return utilAddrs[0], nil
}

// NewChangeAddress returns a new change address for a wallet.
func (w *Wallet) NewChangeAddress(account uint32) (dcrutil.Address, error) {
	// Get next chained change address from wallet for account.
	addrs, err := w.Manager.NextInternalAddresses(account, 1)
	if err != nil {
		return nil, err
	}

	// Request updates from dcrd for new transactions sent to this address.
	utilAddrs := make([]dcrutil.Address, len(addrs))
	for i, addr := range addrs {
		utilAddrs[i] = addr.Address()
	}

	if err := w.chainSvr.NotifyReceived(utilAddrs); err != nil {
		return nil, err
	}

	return utilAddrs[0], nil
}

// ReusedAddress returns an address that is reused from the external
// branch of the wallet, to cut down on new address usage for wallets.
// Should be used judiciously.
func (w *Wallet) ReusedAddress() (dcrutil.Address, error) {
	addr, err := w.Manager.GetAddress(0, waddrmgr.DefaultAccountNum,
		waddrmgr.ExternalBranch)
	if err != nil {
		return nil, err
	}

	return addr, err
}

// txToPairs creates a raw transaction sending the amounts for each
// address/amount pair and fee to each address and the miner.  minconf
// specifies the minimum number of confirmations required before an
// unspent output is eligible for spending. Leftover input funds not sent
// to addr or as a fee for the miner are sent to a newly generated
// address. InsufficientFundsError is returned if there are not enough
// eligible unspent outputs to create the transaction.
func (w *Wallet) txToPairs(pairs map[string]dcrutil.Amount, account uint32,
	minconf int32, addrFunc func() (dcrutil.Address, error)) (*CreatedTx,
	error) {
	isReorganizing, _ := w.chainSvr.GetReorganizing()
	if isReorganizing {
		return nil, ErrBlockchainReorganizing
	}

	// Address manager must be unlocked to compose transaction.  Grab
	// the unlock if possible (to prevent future unlocks), or return the
	// error if already locked.
	heldUnlock, err := w.HoldUnlock()
	if err != nil {
		return nil, err
	}
	defer heldUnlock.Release()

	// Get current block's height and hash.
	bs, err := w.chainSvr.BlockStamp()
	if err != nil {
		return nil, err
	}

	needed := dcrutil.Amount(0)
	for _, amt := range pairs {
		needed += amt
	}

	// Simple fee guesstimate.
	var feeIncrement dcrutil.Amount
	switch {
	case w.chainParams == &chaincfg.MainNetParams:
		feeIncrement = FeeIncrementMainnet
	case w.chainParams == &chaincfg.TestNetParams:
		feeIncrement = FeeIncrementTestnet
	default:
		feeIncrement = FeeIncrementTestnet
	}
	needed += feeForSize(feeIncrement,
		estimateTxSize(len(pairs), len(pairs)))

	eligible, err := w.findEligibleOutputsAmount(account, minconf, needed, bs)
	if err != nil {
		return nil, err
	}

	return w.createTx(eligible, pairs, bs, w.FeeIncrement(), account,
		addrFunc, w.chainParams, w.DisallowFree)
}

// createTx selects inputs (from the given slice of eligible utxos)
// whose amount are sufficient to fulfil all the desired outputs plus
// the mining fee. It then creates and returns a CreatedTx containing
// the selected inputs and the given outputs, validating it (using
// validateMsgTx) as well.
func (w *Wallet) createTx(eligible []wtxmgr.Credit,
	outputs map[string]dcrutil.Amount, bs *waddrmgr.BlockStamp,
	feeIncrement dcrutil.Amount, account uint32,
	addrFunc func() (dcrutil.Address, error), chainParams *chaincfg.Params,
	disallowFree bool) (*CreatedTx, error) {

	msgtx := wire.NewMsgTx()
	minAmount, err := addOutputs(msgtx, outputs, chainParams)
	if err != nil {
		return nil, err
	}

	// Sort eligible inputs so that we first pick the ones with highest
	// amount, thus reducing number of inputs.
	sort.Sort(sort.Reverse(ByAmount(eligible)))

	// Start by adding enough inputs to cover for the total amount of all
	// desired outputs.
	var input wtxmgr.Credit
	var inputs []wtxmgr.Credit
	totalAdded := dcrutil.Amount(0)
	for totalAdded < minAmount {
		if len(eligible) == 0 {
			bal, err := w.TxStore.Balance(1, bs.Height,
				wtxmgr.BFBalanceSpendable)
			if err != nil {
				return nil, err
			}
			return nil, InsufficientFundsError{bal, minAmount, 0}
		}
		input, eligible = eligible[0], eligible[1:]
		inputs = append(inputs, input)
		msgtx.AddTxIn(wire.NewTxIn(&input.OutPoint, nil))
		totalAdded += input.Amount
	}

	// Get an initial fee estimate based on the number of selected inputs
	// and added outputs, with no change.
	szEst := estimateTxSize(len(inputs), len(msgtx.TxOut))
	feeEst := minimumFee(feeIncrement, szEst, msgtx.TxOut, inputs, bs.Height,
		disallowFree)

	// Now make sure the sum amount of all our inputs is enough for the
	// sum amount of all outputs plus the fee. If necessary we add more,
	// inputs, but in that case we also need to recalculate the fee.
	for totalAdded < minAmount+feeEst {
		if len(eligible) == 0 {
			return nil, InsufficientFundsError{totalAdded, minAmount, feeEst}
		}
		input, eligible = eligible[0], eligible[1:]
		inputs = append(inputs, input)
		msgtx.AddTxIn(wire.NewTxIn(&input.OutPoint, nil))
		szEst += txInEstimate
		totalAdded += input.Amount
		feeEst = minimumFee(feeIncrement, szEst, msgtx.TxOut, inputs, bs.Height,
			disallowFree)
	}

	// If we're spending the outputs of an imported address, we default
	// to generating change addresses from the default account.
	if account == waddrmgr.ImportedAddrAccount {
		account = waddrmgr.DefaultAccountNum
	}

	var changeAddr dcrutil.Address
	// changeIdx is -1 unless there's a change output.
	changeIdx := -1

	for {
		change := totalAdded - minAmount - feeEst
		if change > 0 {
			if changeAddr == nil {
				changeAddr, err = addrFunc()
				if err != nil {
					return nil, err
				}
			}

			changeIdx, err = addChange(msgtx, change, changeAddr)
			if err != nil {
				return nil, err
			}
		}

		if err = signMsgTx(msgtx, inputs, w.Manager, chainParams); err != nil {
			return nil, err
		}

		if feeForSize(feeIncrement, msgtx.SerializeSize()) <= feeEst {
			// The required fee for this size is less than or equal to what
			// we guessed, so we're done.
			break
		}

		if change > 0 {
			// Remove the change output since the next iteration will add
			// it again (with a new amount) if necessary.
			tmp := msgtx.TxOut[:changeIdx]
			tmp = append(tmp, msgtx.TxOut[changeIdx+1:]...)
			msgtx.TxOut = tmp
		}

		feeEst += feeIncrement
		for totalAdded < minAmount+feeEst {
			if len(eligible) == 0 {
				return nil, InsufficientFundsError{totalAdded, minAmount, feeEst}
			}
			input, eligible = eligible[0], eligible[1:]
			inputs = append(inputs, input)
			msgtx.AddTxIn(wire.NewTxIn(&input.OutPoint, nil))
			szEst += txInEstimate
			totalAdded += input.Amount
			feeEst = minimumFee(feeIncrement, szEst, msgtx.TxOut, inputs,
				bs.Height, disallowFree)
		}
	}

	if err := validateMsgTx(msgtx, inputs); err != nil {
		return nil, err
	}

	_, err = w.chainSvr.SendRawTransaction(msgtx, false)
	if err != nil {
		return nil, err
	}

	// Create transaction record and insert into the db.
	rec, err := wtxmgr.NewTxRecordFromMsgTx(msgtx, time.Now())
	if err != nil {
		return nil, fmt.Errorf("Cannot create record for created transaction: %v",
			err)
	}
	err = w.TxStore.InsertTx(rec, nil)
	if err != nil {
		return nil, fmt.Errorf("Error adding sent tx history: %v", err)
	}
	err = w.insertCreditsIntoTxMgr(msgtx, rec)
	if err != nil {
		return nil, err
	}

	info := &CreatedTx{
		MsgTx:       msgtx,
		ChangeAddr:  changeAddr,
		ChangeIndex: changeIdx,
	}
	return info, nil
}

// addChange adds a new output with the given amount and address, and
// randomizes the index (and returns it) of the newly added output.
func addChange(msgtx *wire.MsgTx, change dcrutil.Amount,
	changeAddr dcrutil.Address) (int, error) {
	pkScript, err := txscript.PayToAddrScript(changeAddr)
	if err != nil {
		return 0, fmt.Errorf("cannot create txout script: %s", err)
	}
	msgtx.AddTxOut(wire.NewTxOut(int64(change), pkScript))

	// Randomize index of the change output.
	rng := badrand.New(badrand.NewSource(time.Now().UnixNano()))
	r := rng.Int31n(int32(len(msgtx.TxOut))) // random index
	c := len(msgtx.TxOut) - 1                // change index
	msgtx.TxOut[r], msgtx.TxOut[c] = msgtx.TxOut[c], msgtx.TxOut[r]
	return int(r), nil
}

// addOutputs adds the given address/amount pairs as outputs to msgtx,
// returning their total amount.
func addOutputs(msgtx *wire.MsgTx, pairs map[string]dcrutil.Amount,
	chainParams *chaincfg.Params) (dcrutil.Amount, error) {
	var minAmount dcrutil.Amount
	for addrStr, amt := range pairs {
		if amt <= 0 {
			return minAmount, ErrNonPositiveAmount
		}
		minAmount += amt
		addr, err := dcrutil.DecodeAddress(addrStr, chainParams)
		if err != nil {
			return minAmount, fmt.Errorf("cannot decode address: %s", err)
		}

		// Add output to spend amt to addr.
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return minAmount, fmt.Errorf("cannot create txout script: %s", err)
		}
		txout := wire.NewTxOut(int64(amt), pkScript)
		msgtx.AddTxOut(txout)
	}
	return minAmount, nil
}

// constructMultiSigScript create a multisignature output script from a
// given list of public keys.
func constructMultiSigScript(keys []dcrutil.AddressSecpPubKey,
	nRequired int) ([]byte, error) {
	keysesPrecious := make([]*dcrutil.AddressSecpPubKey, len(keys))

	return txscript.MultiSigScript(keysesPrecious, nRequired)
}

// txToMultisig spends funds to a multisig output, partially signs the
// transaction, then returns fund
func (w *Wallet) txToMultisig(account uint32, amount dcrutil.Amount,
	pubkeys []*dcrutil.AddressSecpPubKey, nRequired int8,
	minconf int32) (*CreatedTx, dcrutil.Address, []byte, error) {
	// Initialize the address pool for use.
	pool := w.internalPool
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	defer func() {
		// For multisig, assumed it succeeded even
		// if SendRawTransaction fails. There may
		// be not enough signatures.
		pool.BatchFinish()
	}()
	addrFunc := pool.GetNewAddress

	errorOut :=
		func(err error) (*CreatedTx, dcrutil.Address, []byte, error) {
			return nil, nil, nil, err
		}

	isReorganizing, _ := w.chainSvr.GetReorganizing()
	if isReorganizing {
		return errorOut(ErrBlockchainReorganizing)
	}

	// Address manager must be unlocked to compose transaction.  Grab
	// the unlock if possible (to prevent future unlocks), or return the
	// error if already locked.
	heldUnlock, err := w.HoldUnlock()
	if err != nil {
		return errorOut(err)
	}
	defer heldUnlock.Release()

	// Get current block's height and hash.
	bs, err := w.chainSvr.BlockStamp()
	if err != nil {
		return errorOut(err)
	}

	// Add in some extra for fees. TODO In the future, make a better
	// fee estimator.
	var feeEstForTx dcrutil.Amount
	switch {
	case w.chainParams == &chaincfg.MainNetParams:
		feeEstForTx = 5e7
	case w.chainParams == &chaincfg.TestNetParams:
		feeEstForTx = 5e7
	default:
		feeEstForTx = 3e4
	}
	amountRequired := amount + feeEstForTx

	// Instead of taking reward addresses by arg, just create them now  and
	// automatically find all eligible outputs from all current utxos.
	eligible, err := w.findEligibleOutputsAmount(account, minconf,
		amountRequired, bs)
	if err != nil {
		return errorOut(err)
	}
	if eligible == nil {
		return errorOut(
			fmt.Errorf("Not enough funds to send to multisig address"))
	}

	msgtx := wire.NewMsgTx()

	// Fill out inputs.
	var forSigning []wtxmgr.Credit
	totalInput := dcrutil.Amount(0)
	numInputs := 0
	for _, e := range eligible {
		msgtx.AddTxIn(wire.NewTxIn(&e.OutPoint, nil))
		totalInput += e.Amount
		forSigning = append(forSigning, e)

		numInputs++
	}

	// Insert a multi-signature output, then insert this P2SH
	// hash160 into the address manager and the transaction
	// manager.
	totalOutput := dcrutil.Amount(0)
	msScript, err := txscript.MultiSigScript(pubkeys, int(nRequired))
	if err != nil {
		return errorOut(err)
	}
	_, err = w.Manager.ImportScript(msScript, bs)
	if err != nil {
		// We don't care if we've already used this address.
		if err.(waddrmgr.ManagerError).ErrorCode !=
			waddrmgr.ErrDuplicateAddress {
			return errorOut(err)
		}
	}
	err = w.TxStore.InsertTxScript(msScript)
	if err != nil {
		return errorOut(err)
	}
	scAddr, err := dcrutil.NewAddressScriptHash(msScript, w.chainParams)
	if err != nil {
		return errorOut(err)
	}
	p2shScript, err := txscript.PayToAddrScript(scAddr)
	if err != nil {
		return errorOut(err)
	}
	txout := wire.NewTxOut(int64(amount), p2shScript)
	msgtx.AddTxOut(txout)
	totalOutput += amount

	// Add change if we need it. The case in which
	// totalInput == amount+feeEst is skipped because
	// we don't need to add a change output in this
	// case.
	feeSize := estimateTxSize(numInputs, 2)
	var feeIncrement dcrutil.Amount
	switch {
	case w.chainParams == &chaincfg.MainNetParams:
		feeIncrement = FeeIncrementMainnet
	case w.chainParams == &chaincfg.TestNetParams:
		feeIncrement = FeeIncrementTestnet
	default:
		feeIncrement = FeeIncrementTestnet
	}
	feeEst := feeForSize(feeIncrement, feeSize)

	if totalInput < amount+feeEst {
		return errorOut(fmt.Errorf("Not enough funds to send to " +
			"multisig address after accounting for fees"))
	}
	if totalInput > amount+feeEst {
		changeAddr, err := addrFunc()
		if err != nil {
			return errorOut(err)
		}
		change := totalInput - (amount + feeEst)
		pkScript, err := txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return errorOut(fmt.Errorf("cannot create txout script: %s", err))
		}
		msgtx.AddTxOut(wire.NewTxOut(int64(change), pkScript))
	}

	if err = signMsgTx(msgtx, forSigning, w.Manager,
		w.chainParams); err != nil {
		return errorOut(err)
	}

	_, err = w.chainSvr.SendRawTransaction(msgtx, false)
	if err != nil {
		return errorOut(err)
	}

	// Request updates from dcrd for new transactions sent to this
	// script hash address.
	utilAddrs := make([]dcrutil.Address, 1)
	utilAddrs[0] = scAddr
	if err := w.chainSvr.NotifyReceived(utilAddrs); err != nil {
		return errorOut(err)
	}

	err = w.insertMultisigOutIntoTxMgr(msgtx, 0)
	if err != nil {
		return errorOut(err)
	}

	ctx := &CreatedTx{
		MsgTx:       msgtx,
		ChangeAddr:  nil,
		ChangeIndex: -1,
	}

	return ctx, scAddr, msScript, nil
}

// compressWallet compresses all the utxos in a wallet into a single change
// address. For use when it becomes dusty.
func (w *Wallet) compressWallet(maxNumIns int) error {
	isReorganizing, _ := w.chainSvr.GetReorganizing()
	if isReorganizing {
		return ErrBlockchainReorganizing
	}

	// Get current block's height and hash.
	bs, err := w.chainSvr.BlockStamp()
	if err != nil {
		return err
	}

	// Initialize the address pool for use.
	pool := w.internalPool
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	txSucceeded := false
	defer func() {
		if txSucceeded {
			pool.BatchFinish()
		} else {
			pool.BatchRollback()
		}
	}()
	addrFunc := pool.GetNewAddress

	account := uint32(waddrmgr.DefaultAccountNum)
	minconf := int32(1)
	eligible, err := w.findEligibleOutputs(account, minconf, bs)
	if err != nil {
		return err
	}

	if len(eligible) == 0 {
		return ErrNoOutsToConsolidate
	}

	txInCount := len(eligible)
	if maxNumIns < txInCount {
		txInCount = maxNumIns
	}

	// Get an initial fee estimate based on the number of selected inputs
	// and added outputs, with no change.
	szEst := estimateTxSize(txInCount, 1)
	var feeIncrement dcrutil.Amount
	switch {
	case w.chainParams == &chaincfg.MainNetParams:
		feeIncrement = FeeIncrementMainnet
	case w.chainParams == &chaincfg.TestNetParams:
		feeIncrement = FeeIncrementTestnet
	default:
		feeIncrement = FeeIncrementTestnet
	}
	feeEst := feeForSize(feeIncrement, szEst)

	msgtx := wire.NewMsgTx()

	// Add the txins using all the eligible outputs.
	totalAdded := dcrutil.Amount(0)
	count := 0
	var forSigning []wtxmgr.Credit
	for _, e := range eligible {
		if count >= maxNumIns {
			break
		}
		msgtx.AddTxIn(wire.NewTxIn(&e.OutPoint, nil))
		totalAdded += e.Amount
		forSigning = append(forSigning, e)

		count++
	}

	outputAmt := totalAdded - feeEst

	changeAddr, err := addrFunc()
	if err != nil {
		return err
	}

	pkScript, err := txscript.PayToAddrScript(changeAddr)
	if err != nil {
		return fmt.Errorf("cannot create txout script: %s", err)
	}
	msgtx.AddTxOut(wire.NewTxOut(int64(outputAmt), pkScript))

	if err = signMsgTx(msgtx, forSigning, w.Manager,
		w.chainParams); err != nil {
		return err
	}
	if err := validateMsgTx(msgtx, forSigning); err != nil {
		return err
	}

	txSha, err := w.chainSvr.SendRawTransaction(msgtx, false)
	if err != nil {
		return err
	}
	txSucceeded = true

	// Insert the transaction and credits into the transaction manager.
	rec, err := w.insertIntoTxMgr(msgtx)
	if err != nil {
		return err
	}
	err = w.insertCreditsIntoTxMgr(msgtx, rec)
	if err != nil {
		return err
	}

	log.Infof("Successfully consolidated funds in transaction %v", txSha)

	return nil
}

// compressEligible compresses all the utxos passed to it into a single
// output back to the wallet.
func (w *Wallet) compressEligible(eligible []wtxmgr.Credit) error {
	// Initialize the address pool for use.
	pool := w.internalPool
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	txSucceeded := false
	defer func() {
		if txSucceeded {
			pool.BatchFinish()
		} else {
			pool.BatchRollback()
		}
	}()
	addrFunc := pool.GetNewAddress

	if len(eligible) == 0 {
		return ErrNoOutsToConsolidate
	}

	txInCount := len(eligible)

	// Get an initial fee estimate based on the number of selected inputs
	// and added outputs, with no change.
	szEst := estimateTxSize(txInCount, 1)
	var feeIncrement dcrutil.Amount
	switch {
	case w.chainParams == &chaincfg.MainNetParams:
		feeIncrement = FeeIncrementMainnet
	case w.chainParams == &chaincfg.TestNetParams:
		feeIncrement = FeeIncrementTestnet
	default:
		feeIncrement = FeeIncrementTestnet
	}
	feeEst := feeForSize(feeIncrement, szEst)

	msgtx := wire.NewMsgTx()

	// Add the txins using all the eligible outputs.
	totalAdded := dcrutil.Amount(0)
	var forSigning []wtxmgr.Credit
	for _, e := range eligible {
		msgtx.AddTxIn(wire.NewTxIn(&e.OutPoint, nil))
		totalAdded += e.Amount
		forSigning = append(forSigning, e)
	}

	outputAmt := totalAdded - feeEst

	changeAddr, err := addrFunc()
	if err != nil {
		return err
	}

	pkScript, err := txscript.PayToAddrScript(changeAddr)
	if err != nil {
		return fmt.Errorf("cannot create txout script: %s", err)
	}
	msgtx.AddTxOut(wire.NewTxOut(int64(outputAmt), pkScript))

	if err = signMsgTx(msgtx, forSigning, w.Manager,
		w.chainParams); err != nil {
		return err
	}
	if err := validateMsgTx(msgtx, forSigning); err != nil {
		return err
	}

	txSha, err := w.chainSvr.SendRawTransaction(msgtx, false)
	if err != nil {
		return err
	}
	txSucceeded = true

	// Insert the transaction and credits into the transaction manager.
	rec, err := w.insertIntoTxMgr(msgtx)
	if err != nil {
		return err
	}
	err = w.insertCreditsIntoTxMgr(msgtx, rec)
	if err != nil {
		return err
	}

	log.Infof("Successfully consolidated funds in transaction %v", txSha)

	return nil
}

// txToSStx creates a raw SStx transaction sending the amounts for each
// address/amount pair and fee to each address and the miner.  minconf
// specifies the minimum number of confirmations required before an
// unspent output is eligible for spending. Leftover input funds not sent
// to addr or as a fee for the miner are sent to a newly generated
// address. If change is needed to return funds back to an owned
// address, changeUtxo will point to a unconfirmed (height = -1, zeroed
// block hash) Utxo.  ErrInsufficientFunds is returned if there are not
// enough eligible unspent outputs to create the transaction.
func (w *Wallet) txToSStx(pair map[string]dcrutil.Amount,
	inputCredits []wtxmgr.Credit, inputs []dcrjson.SStxInput,
	payouts []dcrjson.SStxCommitOut, account uint32,
	addrFunc func() (dcrutil.Address, error), minconf int32) (*CreatedTx,
	error) {

	// Quit if the blockchain is reorganizing.
	isReorganizing, _ := w.chainSvr.GetReorganizing()
	if isReorganizing {
		return nil, ErrBlockchainReorganizing
	}

	// Address manager must be unlocked to compose transaction.  Grab
	// the unlock if possible (to prevent future unlocks), or return the
	// error if already locked.
	heldUnlock, err := w.HoldUnlock()
	if err != nil {
		return nil, err
	}
	defer heldUnlock.Release()

	if len(inputs) != len(payouts) {
		return nil, fmt.Errorf("input and payout must have the same length")
	}

	// create new empty msgTx
	msgtx := wire.NewMsgTx()
	var minAmount dcrutil.Amount
	// create tx output from pair addr given
	for addrStr, amt := range pair {
		if amt <= 0 {
			return nil, ErrNonPositiveAmount
		}
		minAmount += amt
		addr, err := dcrutil.DecodeAddress(addrStr, w.chainParams)
		if err != nil {
			return nil, fmt.Errorf("cannot decode address: %s", err)
		}

		// Add output to spend amt to addr.
		pkScript, err := txscript.PayToSStx(addr)
		if err != nil {
			return nil, fmt.Errorf("cannot create txout script: %s", err)
		}
		txout := wire.NewTxOut(int64(amt), pkScript)

		msgtx.AddTxOut(txout)
	}
	// totalAdded is the total amount from utxos
	totalAdded := dcrutil.Amount(0)

	// Range over all eligible utxos to add all to sstx inputs
	for _, input := range inputs {
		txHash, err := chainhash.NewHashFromStr(input.Txid)
		if err != nil {
			return nil, dcrjson.ErrDecodeHexString
		}

		if input.Vout < 0 {
			return nil, dcrjson.Error{
				Code:    dcrjson.ErrInvalidParameter.Code,
				Message: "Invalid parameter, vout must be positive",
			}
		}

		if !(int8(input.Tree) == dcrutil.TxTreeRegular ||
			int8(input.Tree) == dcrutil.TxTreeStake) {
			return nil, dcrjson.Error{
				Code:    dcrjson.ErrInvalidParameter.Code,
				Message: "Invalid parameter, tx tree must be regular or stake",
			}
		}

		prevOut := wire.NewOutPoint(txHash, uint32(input.Vout), int8(input.Tree))
		msgtx.AddTxIn(wire.NewTxIn(prevOut, nil))
		totalAdded += dcrutil.Amount(input.Amt)
	}

	if totalAdded < minAmount {
		return nil, ErrSStxNotEnoughFunds
	}
	rewards := []string{}
	for _, value := range payouts {
		rewards = append(rewards, value.Addr)
	}

	var changeAddr dcrutil.Address

	for i := range inputs {
		// Add the OP_RETURN commitment amounts and payout to
		// addresses.
		var addr dcrutil.Address

		if payouts[i].Addr == "" {
			addr, err = addrFunc()
			if err != nil {
				return nil, err
			}
		} else {
			addr, err = dcrutil.DecodeAddress(payouts[i].Addr,
				w.chainParams)
			if err != nil {
				return nil, fmt.Errorf("cannot decode address: %s", err)
			}

			// Ensure the address is one of the supported types and that
			// the network encoded with the address matches the network the
			// server is currently on.
			switch addr.(type) {
			case *dcrutil.AddressPubKeyHash:
			default:
				return nil, dcrjson.ErrInvalidAddressOrKey
			}
		}

		// Create an OP_RETURN push containing the pubkeyhash to send rewards to.
		// Apply limits to revocations for fees while not allowing
		// fees for votes.
		// Revocations (foremost byte)
		// 0x58 = 01 (Enabled)  010100 = 0x18 or 24
		//                              (2^24 or 16777216 atoms fee allowance)
		//                                 --> 0.16777216 coins
		// Votes (last byte)
		// 0x00 = 00 (Disabled) 000000
		limits := uint16(0x5800)
		pkScript, err := txscript.GenerateSStxAddrPush(addr,
			dcrutil.Amount(payouts[i].CommitAmt), limits)
		if err != nil {
			return nil, fmt.Errorf("cannot create txout script: %s", err)
		}
		txout := wire.NewTxOut(int64(0), pkScript)
		msgtx.AddTxOut(txout)

		// Add change to txouts.
		if payouts[i].ChangeAddr == "" {
			changeAddr, err = addrFunc()
			if err != nil {
				return nil, err
			}
		} else {
			a, err := dcrutil.DecodeAddress(payouts[i].ChangeAddr, w.chainParams)
			if err != nil {
				return nil, err
			}
			// Ensure the address is one of the supported types and that
			// the network encoded with the address matches the network the
			// server is currently on.
			switch a.(type) {
			case *dcrutil.AddressPubKeyHash:
			case *dcrutil.AddressScriptHash:
			default:
				return nil, dcrjson.ErrInvalidAddressOrKey
			}
			changeAddr = a
		}

		err = addSStxChange(msgtx,
			dcrutil.Amount(payouts[i].ChangeAmt),
			changeAddr)
		if err != nil {
			return nil, err
		}

	}
	if _, err := stake.IsSStx(dcrutil.NewTx(msgtx)); err != nil {
		return nil, err
	}
	if err = signMsgTx(msgtx, inputCredits, w.Manager,
		w.chainParams); err != nil {
		return nil, err
	}
	if err := validateMsgTx(msgtx, inputCredits); err != nil {
		return nil, err
	}
	info := &CreatedTx{
		MsgTx:       msgtx,
		ChangeAddr:  nil,
		ChangeIndex: -1,
	}

	// TODO: Add to the stake manager

	return info, nil
}

// purchaseTicket indicates to the wallet that a ticket should be purchased
// using all currently available funds.  The ticket address parameter in the
// request can be nil in which case the ticket address associated with the
// wallet instance will be used.  Also, when the spend limit in the request is
// greater than or equal to 0, tickets that cost more than that limit will
// return an error that not enough funds are available.
func (w *Wallet) purchaseTicket(req purchaseTicketRequest) (interface{},
	error) {

	// Initialize the address pool for use.
	pool := w.internalPool
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	txSucceeded := false
	defer func() {
		if txSucceeded {
			pool.BatchFinish()
		} else {
			pool.BatchRollback()
		}
	}()
	addrFunc := pool.GetNewAddress

	if w.addressReuse {
		addrFunc = w.ReusedAddress
	}

	isReorganizing, _ := w.chainSvr.GetReorganizing()
	if isReorganizing {
		return "", ErrBlockchainReorganizing
	}

	account := uint32(waddrmgr.DefaultAccountNum)

	// Ensure the minimum number of required confirmations is positive.
	if req.minConf < 0 {
		return nil, fmt.Errorf("Need positive minconf")
	}

	// Get the current ticket price.
	ticketPrice := dcrutil.Amount(w.GetStakeDifficulty().StakeDifficulty)
	if ticketPrice == -1 {
		return nil, ErrTicketPriceNotSet
	}

	// Ensure the ticket price does not exceed the spend limit if set.
	if req.spendLimit >= 0 && ticketPrice > req.spendLimit {
		return nil, ErrSStxPriceExceedsSpendLimit
	}

	// Get current block's height and hash.
	bs, err := w.chainSvr.BlockStamp()
	if err != nil {
		return nil, err
	}

	// Prefer using the ticket address passed to this function.  When one
	// was not passed, attempt to use the ticket address specified on the
	// command line.  When that one is not specified either, fall back to
	// generating a new one.
	ticketAddr := req.ticketAddr
	if ticketAddr == nil {
		if w.ticketAddress != nil {
			ticketAddr = w.ticketAddress
		} else {
			newAddress, err := addrFunc()
			if err != nil {
				return nil, err
			}
			ticketAddr = newAddress
		}
	}

	// Recreate address/amount pairs, using btcutil.Amount.
	pair := make(map[string]dcrutil.Amount, 1)
	pair[ticketAddr.String()] = ticketPrice

	// Instead of taking reward addresses by arg, just create them now and
	// automatically find all eligible outputs from all current utxos.
	amountNeeded := req.minBalance + ticketPrice
	eligible, err := w.findEligibleOutputsAmount(account, req.minConf,
		amountNeeded, bs)
	if err != nil {
		return nil, err
	}

	if len(eligible) == 0 {
		return nil, ErrSStxNotEnoughFunds
	}
	if len(eligible) > stake.MaxInputsPerSStx {
		return eligible, ErrSStxInputOverflow
	}

	// Prepare inputs and commit outs to create new sstx.
	couts := []dcrjson.SStxCommitOut{}
	inputs := []dcrjson.SStxInput{}
	usedCredits := []wtxmgr.Credit{}
	inputSum := int64(0)
	outputSum := int64(0)
	for i, credit := range eligible {
		newAddress, err := addrFunc()
		if err != nil {
			return nil, err
		}
		newChangeAddress, err := addrFunc()
		if err != nil {
			return nil, err
		}

		creditAmount := int64(credit.Amount)
		inputSum += creditAmount

		newInput := dcrjson.SStxInput{
			credit.Hash.String(),
			credit.Index,
			credit.Tree,
			creditAmount}

		inputs = append(inputs, newInput)
		usedCredits = append(usedCredits, credit)

		// All credits used that are not the last credit.
		if outputSum+creditAmount <= int64(ticketPrice) {
			cout := dcrjson.SStxCommitOut{
				Addr:       newAddress.String(),
				CommitAmt:  creditAmount,
				ChangeAddr: newChangeAddress.String(),
				ChangeAmt:  0,
			}
			couts = append(couts, cout)

			outputSum += creditAmount
		} else {
			// We've gone over what we needed to use and
			// so we'll have to change to pop in the
			// last output.

			// Calculate the amount of fees needed.
			s := estimateSSTxSize(i, i)
			var feeIncrement dcrutil.Amount
			switch {
			case w.chainParams == &chaincfg.MainNetParams:
				feeIncrement = FeeIncrementMainnet
			case w.chainParams == &chaincfg.TestNetParams:
				feeIncrement = FeeIncrementTestnet
			default:
				feeIncrement = FeeIncrementTestnet
			}
			fee := feeForSize(feeIncrement, s)

			// Not enough funds after taking fee into account.
			// Should retry instead of failing, Decred TODO
			totalWithThisCredit := creditAmount + outputSum
			if (totalWithThisCredit - int64(fee) - int64(ticketPrice)) < 0 {
				return nil, ErrSStxNotEnoughFunds
			}

			remaining := int64(ticketPrice) - outputSum
			change := creditAmount - remaining - int64(fee)
			cout := dcrjson.SStxCommitOut{
				Addr:       newAddress.String(),
				CommitAmt:  creditAmount - change,
				ChangeAddr: newChangeAddress.String(),
				ChangeAmt:  change,
			}
			couts = append(couts, cout)

			outputSum += remaining + change

			break
		}
	}
	if len(inputs) == 0 {
		return nil, ErrSStxNotEnoughFunds
	}

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := w.txToSStx(pair, usedCredits, inputs, couts, account,
		addrFunc, req.minConf)
	if err != nil {
		switch {
		case err == ErrNonPositiveAmount:
			return nil, fmt.Errorf("Need positive amount")
		default:
			return nil, err
		}
	}

	txSha, err := w.chainSvr.SendRawTransaction(createdTx.MsgTx, false)
	if err != nil {
		log.Warnf("Failed to send raw transaction: %v", err.Error())
		inconsistent := strings.Contains(err.Error(),
			"transaction spends unknown inputs")
		if inconsistent {
			errFix := w.attemptToRepairInconsistencies()
			if errFix != nil {
				log.Warnf("Failed to fix wallet inconsistencies!")
			}
		}
		return nil, ErrClientPurchaseTicket
	}
	txSucceeded = true

	// Insert the transaction and credits into the transaction manager.
	rec, err := w.insertIntoTxMgr(createdTx.MsgTx)
	if err != nil {
		return nil, err
	}
	err = w.insertCreditsIntoTxMgr(createdTx.MsgTx, rec)
	if err != nil {
		return nil, err
	}
	txTemp := dcrutil.NewTx(createdTx.MsgTx)

	// The ticket address may be for another wallet. Don't insert the
	// ticket into the stake manager unless we actually own output zero
	// of it. If this is the case, the chainntfns.go handlers will
	// automatically insert it.
	if _, err := w.Manager.Address(ticketAddr); err == nil {
		if w.ticketAddress == nil {
			err = w.StakeMgr.InsertSStx(txTemp)
			if err != nil {
				return nil, fmt.Errorf("Failed to insert SStx %v"+
					"into the stake store", txTemp.Sha())
			}
		}
	}

	log.Infof("Successfully sent SStx purchase transaction %v", txSha)

	// Send a notification via the RPC.
	ntfn := wstakemgr.StakeNotification{
		TxType:    int8(stake.TxTypeSStx),
		TxHash:    *txSha,
		BlockHash: chainhash.Hash{},
		Height:    0,
		Amount:    int64(ticketPrice),
		SStxIn:    chainhash.Hash{},
		VoteBits:  0,
	}
	w.notifyTicketPurchase(ntfn)

	return txSha.String(), nil
}

// addOutputsSStx is used to add outputs for a stake SStx.
// DECRED TODO
func addOutputsSStx(msgtx *wire.MsgTx,
	pair map[string]dcrutil.Amount,
	amountsIn []int64,
	payouts map[string]string) error {

	return nil
}

// txToSSGen ...
// DECRED TODO
func (w *Wallet) txToSSGen(ticketHash chainhash.Hash, blockHash chainhash.Hash,
	height int64, votebits uint16) (*CreatedTx, error) {
	isReorganizing, _ := w.chainSvr.GetReorganizing()
	if isReorganizing {
		return nil, ErrBlockchainReorganizing
	}

	return nil, nil
}

// txToSSRtx ...
// DECRED TODO
func (w *Wallet) txToSSRtx(ticketHash chainhash.Hash) (*CreatedTx, error) {
	isReorganizing, _ := w.chainSvr.GetReorganizing()
	if isReorganizing {
		return nil, ErrBlockchainReorganizing
	}

	return nil, nil
}

// addSStxChange adds a new output with the given amount and address, and
// randomizes the index (and returns it) of the newly added output.
func addSStxChange(msgtx *wire.MsgTx, change dcrutil.Amount,
	changeAddr dcrutil.Address) error {
	pkScript, err := txscript.PayToSStxChange(changeAddr)
	if err != nil {
		return fmt.Errorf("cannot create txout script: %s", err)
	}
	msgtx.AddTxOut(wire.NewTxOut(int64(change), pkScript))

	return nil
}

func (w *Wallet) findEligibleOutputs(account uint32, minconf int32,
	bs *waddrmgr.BlockStamp) ([]wtxmgr.Credit, error) {
	unspent, err := w.TxStore.UnspentOutputs()
	if err != nil {
		errRepair := w.attemptToRepairInconsistencies()
		if errRepair != nil {
			log.Warnf("Wallet found database corruption but was unable to " +
				"repair itself. Please restore your wallet from seed.")
			return nil, errRepair
		}
		return nil, err
	}

	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependancy and requesting unspent outputs for a single account.
	eligible := make([]wtxmgr.Credit, 0, len(unspent))
	for i := range unspent {
		output := unspent[i]

		// Only include this output if it meets the required number of
		// confirmations.  Coinbase transactions must have have reached
		// maturity before their outputs may be spent.
		if !confirmed(minconf, output.Height, bs.Height) {
			continue
		}

		// Locked unspent outputs are skipped.
		if w.LockedOutpoint(output.OutPoint) {
			continue
		}

		// Filter out unspendable outputs, that is, remove those that
		// (at this time) are not P2PKH outputs.  Other inputs must be
		// manually included in transactions and sent (for example,
		// using createrawtransaction, signrawtransaction, and
		// sendrawtransaction).
		class, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txscript.DefaultScriptVersion, output.PkScript, w.chainParams)
		if err != nil {
			continue
		}

		// Make sure everything we're trying to spend is actually mature.
		switch {
		case class == txscript.StakeSubmissionTy:
			continue
		case class == txscript.StakeGenTy:
			target := int32(w.chainParams.CoinbaseMaturity)
			if !confirmed(target, output.Height, bs.Height) {
				continue
			}
		case class == txscript.StakeRevocationTy:
			target := int32(w.chainParams.CoinbaseMaturity)
			if !confirmed(target, output.Height, bs.Height) {
				continue
			}
		case class == txscript.StakeSubChangeTy:
			target := int32(w.chainParams.SStxChangeMaturity)
			if !confirmed(target, output.Height, bs.Height) {
				continue
			}
		case class == txscript.PubKeyHashTy:
			if output.FromCoinBase {
				target := int32(w.chainParams.CoinbaseMaturity)
				if !confirmed(target, output.Height, bs.Height) {
					continue
				}
			}
		default:
			continue
		}

		// Only include the output if it is associated with the passed
		// account.  There should only be one address since this is a
		// P2PKH script.
		addrAcct, err := w.Manager.AddrAccount(addrs[0])
		if err != nil || addrAcct != account {
			continue
		}

		eligible = append(eligible, *output)
	}
	return eligible, nil
}

// Exported version of findEligibleOutputs.
func (w *Wallet) FindEligibleOutputs(account uint32, minconf int32,
	bs *waddrmgr.BlockStamp) ([]wtxmgr.Credit, error) {
	return w.findEligibleOutputs(account, minconf, bs)
}

// findEligibleOutputsAmount uses wtxmgr to find a number of unspent
// outputs while doing maturity checks there.
func (w *Wallet) findEligibleOutputsAmount(account uint32, minconf int32,
	amount dcrutil.Amount, bs *waddrmgr.BlockStamp) ([]wtxmgr.Credit, error) {

	unspent, err := w.TxStore.UnspentOutputsForAmount(amount, bs.Height, minconf)
	if err != nil {
		errRepair := w.attemptToRepairInconsistencies()
		if errRepair != nil {
			log.Warnf("Wallet found database corruption but was unable to " +
				"repair itself. Please restore your wallet from seed.")
			return nil, errRepair
		}
		return nil, err
	}

	eligible := make([]wtxmgr.Credit, 0, len(unspent))
	for i := range unspent {
		output := unspent[i]

		// Locked unspent outputs are skipped.
		if w.LockedOutpoint(output.OutPoint) {
			continue
		}

		// Filter out unspendable outputs, that is, remove those that
		// (at this time) are not P2PKH outputs.  Other inputs must be
		// manually included in transactions and sent (for example,
		// using createrawtransaction, signrawtransaction, and
		// sendrawtransaction).
		class, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txscript.DefaultScriptVersion, output.PkScript, w.chainParams)
		if err != nil ||
			!(class == txscript.PubKeyHashTy ||
				class == txscript.StakeGenTy ||
				class == txscript.StakeRevocationTy ||
				class == txscript.StakeSubChangeTy) {
			continue
		}

		// Only include the output if it is associated with the passed
		// account.  There should only be one address since this is a
		// P2PKH script.
		addrAcct, err := w.Manager.AddrAccount(addrs[0])
		if err != nil || addrAcct != account {
			continue
		}

		eligible = append(eligible, *output)
	}

	return eligible, nil
}

// signMsgTx sets the SignatureScript for every item in msgtx.TxIn.
// It must be called every time a msgtx is changed.
// Only P2PKH outputs are supported at this point.
func signMsgTx(msgtx *wire.MsgTx, prevOutputs []wtxmgr.Credit,
	mgr *waddrmgr.Manager, chainParams *chaincfg.Params) error {
	if len(prevOutputs) != len(msgtx.TxIn) {
		return fmt.Errorf(
			"Number of prevOutputs (%d) does not match number of tx inputs (%d)",
			len(prevOutputs), len(msgtx.TxIn))
	}
	for i, output := range prevOutputs {
		// Errors don't matter here, as we only consider the
		// case where len(addrs) == 1.
		_, addrs, _, _ := txscript.ExtractPkScriptAddrs(
			txscript.DefaultScriptVersion, output.PkScript, chainParams)
		if len(addrs) != 1 {
			continue
		}
		apkh, ok := addrs[0].(*dcrutil.AddressPubKeyHash)
		if !ok {
			return ErrUnsupportedTransactionType
		}

		ai, err := mgr.Address(apkh)
		if err != nil {
			return fmt.Errorf("cannot get address info: %v", err)
		}

		pka := ai.(waddrmgr.ManagedPubKeyAddress)
		privkey, err := pka.PrivKey()
		if err != nil {
			return fmt.Errorf("cannot get private key: %v", err)
		}

		sigscript, err := txscript.SignatureScript(msgtx, i,
			output.PkScript, txscript.SigHashAll, privkey,
			ai.Compressed())
		if err != nil {
			return fmt.Errorf("cannot create sigscript: %s", err)
		}
		msgtx.TxIn[i].SignatureScript = sigscript
	}

	return nil
}

func validateMsgTx(msgtx *wire.MsgTx, prevOutputs []wtxmgr.Credit) error {
	for i := range msgtx.TxIn {
		vm, err := txscript.NewEngine(prevOutputs[i].PkScript, msgtx,
			i, txscript.StandardVerifyFlags, txscript.DefaultScriptVersion)
		if err != nil {
			return fmt.Errorf("cannot create script engine for input %v: %s"+
				" (pkscript %x, sigscript %x)",
				i,
				err,
				prevOutputs[i].PkScript,
				msgtx.TxIn[i].SignatureScript)
		}
		if err = vm.Execute(); err != nil {
			return fmt.Errorf("cannot validate input script for input %v: %s"+
				" (pkscript %x, sigscript %x)",
				i,
				err,
				prevOutputs[i].PkScript,
				msgtx.TxIn[i].SignatureScript)
		}
	}

	if msgtx.SerializeSize() > maxTxSize {
		return fmt.Errorf("transaction generated was too big; try sending " +
			"smaller amount")
	}
	return nil
}

// minimumFee estimates the minimum fee required for a transaction.
// If cfg.DisallowFree is false, a fee may be zero so long as txLen
// s less than 1 kilobyte and none of the outputs contain a value
// less than 1 bitcent. Otherwise, the fee will be calculated using
// incr, incrementing the fee for each kilobyte of transaction.
func minimumFee(incr dcrutil.Amount, txLen int, outputs []*wire.TxOut,
	prevOutputs []wtxmgr.Credit, height int32, disallowFree bool) dcrutil.Amount {
	allowFree := false
	if !disallowFree {
		allowFree = allowNoFeeTx(height, prevOutputs, txLen)
	}
	fee := feeForSize(incr, txLen)

	if allowFree && txLen < 1000 {
		fee = 0
	}

	if fee < incr {
		for _, txOut := range outputs {
			if txOut.Value < dcrutil.AtomsPerCent {
				return incr
			}
		}
	}

	// How can fee be smaller than 0 here?
	if fee < 0 || fee > dcrutil.MaxAmount {
		fee = dcrutil.MaxAmount
	}

	return fee
}

// allowNoFeeTx calculates the transaction priority and checks that the
// priority reaches a certain threshold.  If the threshhold is
// reached, a free transaction fee is allowed.
func allowNoFeeTx(curHeight int32, txouts []wtxmgr.Credit, txSize int) bool {
	const blocksPerDayEstimate = 144.0
	const txSizeEstimate = 250.0
	const threshold = dcrutil.AtomsPerCoin * blocksPerDayEstimate / txSizeEstimate

	var weightedSum int64
	for _, txout := range txouts {
		depth := chainDepth(txout.Height, curHeight)
		weightedSum += int64(txout.Amount) * int64(depth)
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
