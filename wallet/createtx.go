// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/golangcrypto/ripemd160"

	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/wallet/txauthor"
	"github.com/decred/dcrwallet/wtxmgr"
)

// --------------------------------------------------------------------------------
// Constants and simple functions

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
	// fraud proof, and the estimated signature script size.
	txInEstimate = 32 + 4 + 1 + 12 + 4 + sigScriptEstimate

	// sstxTicketCommitmentEstimate =
	// - version + amount +
	// OP_SSTX OP_DUP OP_HASH160 OP_DATA_20 OP_EQUALVERIFY OP_CHECKSIG
	sstxTicketCommitmentEstimate = 2 + 8 + 1 + 1 + 1 + 1 + 20 + 1 + 1

	// sstxSubsidyCommitmentEstimate =
	// version + amount + OP_RETURN OP_DATA_30
	sstxSubsidyCommitmentEstimate = 2 + 8 + 2 + 30

	// sstxChangeOutputEstimate =
	// version + amount + OP_SSTXCHANGE OP_DUP OP_HASH160 OP_DATA_20
	//	OP_EQUALVERIFY OP_CHECKSIG
	sstxChangeOutputEstimate = 2 + 8 + 1 + 1 + 1 + 1 + 20 + 1 + 1

	// A P2PKH pkScript contains the following bytes:
	//  - OP_DUP
	//  - OP_HASH160
	//  - OP_DATA_20 + 20 bytes of pubkey hash
	//  - OP_EQUALVERIFY
	//  - OP_CHECKSIG
	pkScriptEstimate = 1 + 1 + 1 + 20 + 1 + 1

	// pkScriptEstimateSS is the estimated size of a ticket P2PKH output script.
	pkScriptEstimateSS = 1 + 1 + 1 + 1 + 20 + 1 + 1

	// txOutEstimate is a best case tx output serialization cost is 8 bytes
	// of value, two bytes of version, one byte of varint, and the pkScript
	// size.
	txOutEstimate = 8 + 2 + 1 + pkScriptEstimate

	// ssTxOutEsimate is the estimated size of a P2PKH ticket output.
	ssTxOutEsimate = 8 + 2 + 1 + pkScriptEstimateSS

	// singleInputTicketSize is the typical size of a normal P2PKH ticket
	// in bytes when the ticket has one input, rounded up.
	singleInputTicketSize = 300

	// doubleInputTicketSize is the typical size of a normal P2PKH ticket
	// in bytes when the ticket has two inputs, rounded up.
	doubleInputTicketSize = 550

	// defaultTicketFeeLimits is the default byte string for the default
	// fee limits imposed on a ticket.
	defaultTicketFeeLimits = 0x5800
)

var (
	// maxTxSize is the maximum size of a transaction we can
	// build with the wallet.
	maxTxSize = chaincfg.MainNetParams.MaximumBlockSize - 75000
)

func estimateTxSize(numInputs, numOutputs int) int {
	return txOverheadEstimate + txInEstimate*numInputs + txOutEstimate*numOutputs
}

// EstimateTxSize is the exported version of estimateTxSize which provides
// an estimate of the tx size based on the number of inputs, outputs, and some
// assumed overhead.
func EstimateTxSize(numInputs, numOutputs int) int {
	return estimateTxSize(numInputs, numOutputs)
}

func estimateSSTxSize(numInputs int) int {
	return txOverheadEstimate + txInEstimate*numInputs +
		sstxTicketCommitmentEstimate +
		(sstxSubsidyCommitmentEstimate+
			sstxChangeOutputEstimate)*numInputs
}

func feeForSize(incr dcrutil.Amount, sz int) dcrutil.Amount {
	return dcrutil.Amount(1+sz/1000) * incr
}

// FeeForSize is the exported version of feeForSize which returns a fee
// based on the provided feeIncrement and provided size.
func FeeForSize(incr dcrutil.Amount, sz int) dcrutil.Amount {
	return feeForSize(incr, sz)
}

// FeeIncrementMainnet is the default minimum transation fees per KB (0.01 coin,
// measured in atoms) added to transactions requiring a fee for MainNet.
const FeeIncrementMainnet = 1e6

// FeeIncrementTestnet is the default minimum transation fees per KB (0.00001
// coin, measured in atoms) added to transactions requiring a fee for TestNet.
const FeeIncrementTestnet = 1e3

// TicketFeeIncrement is the default minimum stake transation fees per KB (0.01
// coin, measured in atoms).
const TicketFeeIncrement = 1e6

// EstMaxTicketFeeAmount is the estimated max ticket fee to be used for size
// calculation for eligible utxos for ticket purchasing.
const EstMaxTicketFeeAmount = 0.1 * 1e8

// extendedOutPoint is a UTXO with an amount.
type extendedOutPoint struct {
	op       *wire.OutPoint
	amt      int64
	pkScript []byte
}

// --------------------------------------------------------------------------------
// Error Handling

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

// secretSource is an implementation of txauthor.SecretSource for the wallet's
// address manager.
type secretSource struct {
	*waddrmgr.Manager
}

func (s secretSource) GetKey(addr dcrutil.Address) (chainec.PrivateKey, bool, error) {
	ma, err := s.Address(addr)
	if err != nil {
		return nil, false, err
	}
	mpka, ok := ma.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		e := fmt.Errorf("managed address type for %v is `%T` but "+
			"want waddrmgr.ManagedPubKeyAddress", addr, ma)
		return nil, false, e
	}
	privKey, err := mpka.PrivKey()
	if err != nil {
		return nil, false, err
	}
	return privKey, ma.Compressed(), nil
}

func (s secretSource) GetScript(addr dcrutil.Address) ([]byte, error) {
	ma, err := s.Address(addr)
	if err != nil {
		return nil, err
	}
	msa, ok := ma.(waddrmgr.ManagedScriptAddress)
	if !ok {
		e := fmt.Errorf("managed address type for %v is `%T` but "+
			"want waddrmgr.ManagedScriptAddress", addr, ma)
		return nil, e
	}
	return msa.Script()
}

// CreatedTx holds the state of a newly-created transaction and the change
// output (if one was added).
type CreatedTx struct {
	MsgTx       *wire.MsgTx
	ChangeAddr  dcrutil.Address
	ChangeIndex int // negative if no change
	Fee         dcrutil.Amount
}

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
					ma.Internal(), ma.Account())
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

// txToOutputs creates a signed transaction which includes each output from
// outputs.  Previous outputs to reedeem are chosen from the passed account's
// UTXO set and minconf policy. An additional output may be added to return
// change to the wallet.  An appropriate fee is included based on the wallet's
// current relay fee.  The wallet must be unlocked to create the transaction.
//
// Decred: This func also sends the transaction, and if successful, inserts it
// into the database, rather than delegating this work to the caller as
// btcwallet does.
func (w *Wallet) txToOutputs(outputs []*wire.TxOut, account uint32, minconf int32,
	randomizeChangeIdx bool) (atx *txauthor.AuthoredTx, err error) {
	// Address manager must be unlocked to compose transaction.  Grab
	// the unlock if possible (to prevent future unlocks), or return the
	// error if already locked.
	heldUnlock, err := w.HoldUnlock()
	if err != nil {
		return nil, err
	}
	defer heldUnlock.Release()

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	isReorganizing, _ := chainClient.GetReorganizing()
	if isReorganizing {
		return nil, ErrBlockchainReorganizing
	}

	// Get current block's height and hash.
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	// Initialize the address pool for use. If we
	// are using an imported account, loopback to
	// the default account to create change.
	var pool *addressPool
	if account == waddrmgr.ImportedAddrAccount {
		err := w.CheckAddressPoolsInitialized(waddrmgr.DefaultAccountNum)
		if err != nil {
			return nil, err
		}
		pool = w.addrPools[waddrmgr.DefaultAccountNum].internal
	} else {
		err := w.CheckAddressPoolsInitialized(account)
		if err != nil {
			return nil, err
		}
		pool = w.addrPools[account].internal
	}
	changeAddrUsed := false
	txSucceeded := false
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	defer func() {
		if txSucceeded && changeAddrUsed {
			pool.BatchFinish()
		} else {
			pool.BatchRollback()
		}
	}()

	// The change address is pulled here rather than after
	// MakeInputSource is called because MakeInputSource
	// accesses the database in a way that deadlocks other
	// packages that also access the database like waddmgr.
	// Because the address pool occasionally makes calls
	// to the address manager to replenish the address pool,
	// calling the address function after MakeInputSource
	// and before inputSource.CloseTransaction() will
	// sometimes cause a lockup.
	changeAddr, err := pool.getNewAddress()
	if err != nil {
		return nil, err
	}
	changeSource := func() ([]byte, error) {
		changeAddrUsed = true
		return txscript.PayToAddrScript(changeAddr)
	}

	inputSource := w.TxStore.MakeInputSource(account, minconf, bs.Height)
	tx, err := txauthor.NewUnsignedTransaction(outputs, w.RelayFee(),
		inputSource.SelectInputs, changeSource)
	closeErr := inputSource.CloseTransaction()
	if closeErr != nil {
		log.Errorf("Failed to close view: %v", closeErr)
	}
	if err != nil {
		return nil, err
	}

	// Randomize change position, if change exists, before signing.  This
	// doesn't affect the serialize size, so the change amount will still be
	// valid.
	if tx.ChangeIndex >= 0 && randomizeChangeIdx {
		tx.RandomizeChangePosition()
	}

	err = tx.AddAllInputScripts(secretSource{w.Manager})
	if err != nil {
		return nil, err
	}

	err = validateMsgTx(tx.Tx, tx.PrevScripts)
	if err != nil {
		return nil, err
	}

	if tx.ChangeIndex >= 0 && account == waddrmgr.ImportedAddrAccount {
		changeAmount := dcrutil.Amount(tx.Tx.TxOut[tx.ChangeIndex].Value)
		log.Warnf("Spend from imported account produced change: moving"+
			" %v from imported account into default account.", changeAmount)
	}

	_, err = chainClient.SendRawTransaction(tx.Tx, false)
	if err != nil {
		return nil, err
	}
	txSucceeded = true

	// Create transaction record and insert into the db.
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx.Tx, time.Now())
	if err != nil {
		return nil, fmt.Errorf("Cannot create record for created transaction: %v",
			err)
	}
	err = w.TxStore.InsertTx(rec, nil)
	if err != nil {
		return nil, fmt.Errorf("Error adding sent tx history: %v", err)
	}
	err = w.insertCreditsIntoTxMgr(tx.Tx, rec)
	if err != nil {
		return nil, err
	}

	return tx, nil
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
	txToMultisigError :=
		func(err error) (*CreatedTx, dcrutil.Address, []byte, error) {
			return nil, nil, nil, err
		}

	// Initialize the address pool for use. If we
	// are using an imported account, loopback to
	// the default account to create change.
	var pool *addressPool
	if account == waddrmgr.ImportedAddrAccount {
		err := w.CheckAddressPoolsInitialized(waddrmgr.DefaultAccountNum)
		if err != nil {
			return txToMultisigError(err)
		}
		pool = w.addrPools[waddrmgr.DefaultAccountNum].internal
	} else {
		err := w.CheckAddressPoolsInitialized(account)
		if err != nil {
			return txToMultisigError(err)
		}
		pool = w.addrPools[account].internal
	}
	txSucceeded := false
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	defer func() {
		if txSucceeded {
			pool.BatchFinish()
		} else {
			pool.BatchRollback()
		}
	}()
	addrFunc := pool.getNewAddress

	chainClient, err := w.requireChainClient()
	if err != nil {
		return txToMultisigError(err)
	}

	isReorganizing, _ := chainClient.GetReorganizing()
	if isReorganizing {
		return txToMultisigError(err)
	}

	// Address manager must be unlocked to compose transaction.  Grab
	// the unlock if possible (to prevent future unlocks), or return the
	// error if already locked.
	heldUnlock, err := w.HoldUnlock()
	if err != nil {
		return txToMultisigError(err)
	}
	defer heldUnlock.Release()

	// Get current block's height and hash.
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return txToMultisigError(err)
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
		return txToMultisigError(err)
	}
	if eligible == nil {
		return txToMultisigError(
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
		return txToMultisigError(err)
	}
	_, err = w.Manager.ImportScript(msScript, bs)
	if err != nil {
		// We don't care if we've already used this address.
		if err.(waddrmgr.ManagerError).ErrorCode !=
			waddrmgr.ErrDuplicateAddress {
			return txToMultisigError(err)
		}
	}
	err = w.TxStore.InsertTxScript(msScript)
	if err != nil {
		return txToMultisigError(err)
	}
	scAddr, err := dcrutil.NewAddressScriptHash(msScript, w.chainParams)
	if err != nil {
		return txToMultisigError(err)
	}
	p2shScript, err := txscript.PayToAddrScript(scAddr)
	if err != nil {
		return txToMultisigError(err)
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
	feeIncrement = w.RelayFee()

	feeEst := feeForSize(feeIncrement, feeSize)

	if totalInput < amount+feeEst {
		return txToMultisigError(fmt.Errorf("Not enough funds to send to " +
			"multisig address after accounting for fees"))
	}
	if totalInput > amount+feeEst {
		changeAddr, err := addrFunc()
		if err != nil {
			return txToMultisigError(err)
		}
		change := totalInput - (amount + feeEst)
		pkScript, err := txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return txToMultisigError(
				fmt.Errorf("cannot create txout script: %s", err))
		}
		msgtx.AddTxOut(wire.NewTxOut(int64(change), pkScript))
	}

	if err = signMsgTx(msgtx, forSigning, w.Manager,
		w.chainParams); err != nil {
		return txToMultisigError(err)
	}

	_, err = chainClient.SendRawTransaction(msgtx, false)
	if err != nil {
		return txToMultisigError(err)
	}

	// Request updates from dcrd for new transactions sent to this
	// script hash address.
	utilAddrs := make([]dcrutil.Address, 1)
	utilAddrs[0] = scAddr
	if err := chainClient.NotifyReceived(utilAddrs); err != nil {
		return txToMultisigError(err)
	}

	err = w.insertMultisigOutIntoTxMgr(msgtx, 0)
	if err != nil {
		return txToMultisigError(err)
	}

	ctx := &CreatedTx{
		MsgTx:       msgtx,
		ChangeAddr:  nil,
		ChangeIndex: -1,
	}

	return ctx, scAddr, msScript, nil
}

// validateMsgTx verifies transaction input scripts for tx.  All previous output
// scripts from outputs redeemed by the transaction, in the same order they are
// spent, must be passed in the prevScripts slice.
func validateMsgTx(tx *wire.MsgTx, prevScripts [][]byte) error {
	for i, prevScript := range prevScripts {
		vm, err := txscript.NewEngine(prevScript, tx, i,
			txscript.StandardVerifyFlags, txscript.DefaultScriptVersion)
		if err != nil {
			return fmt.Errorf("cannot create script engine: %s", err)
		}
		err = vm.Execute()
		if err != nil {
			return fmt.Errorf("cannot validate transaction: %s", err)
		}
	}
	return nil
}

func validateMsgTxCredits(tx *wire.MsgTx, prevCredits []wtxmgr.Credit) error {
	prevScripts := make([][]byte, 0, len(prevCredits))
	for _, c := range prevCredits {
		prevScripts = append(prevScripts, c.PkScript)
	}
	return validateMsgTx(tx, prevScripts)
}

// compressWallet compresses all the utxos in a wallet into a single change
// address. For use when it becomes dusty.
func (w *Wallet) compressWallet(maxNumIns int, account uint32) (*chainhash.Hash,
	error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	isReorganizing, _ := chainClient.GetReorganizing()
	if isReorganizing {
		return nil, ErrBlockchainReorganizing
	}

	// Get current block's height and hash.
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	// Initialize the address pool for use. If we
	// are using an imported account, loopback to
	// the default account to create change.
	var pool *addressPool
	if account == waddrmgr.ImportedAddrAccount {
		err := w.CheckAddressPoolsInitialized(waddrmgr.DefaultAccountNum)
		if err != nil {
			return nil, err
		}
		pool = w.addrPools[waddrmgr.DefaultAccountNum].internal
	} else {
		err := w.CheckAddressPoolsInitialized(account)
		if err != nil {
			return nil, err
		}
		pool = w.addrPools[account].internal
	}
	txSucceeded := false
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	defer func() {
		if txSucceeded {
			pool.BatchFinish()
		} else {
			pool.BatchRollback()
		}
	}()
	addrFunc := pool.getNewAddress

	minconf := int32(1)
	eligible, err := w.findEligibleOutputs(account, minconf, bs)
	if err != nil {
		return nil, err
	}

	if len(eligible) == 0 {
		return nil, ErrNoOutsToConsolidate
	}

	txInCount := len(eligible)
	if maxNumIns < txInCount {
		txInCount = maxNumIns
	}

	// Get an initial fee estimate based on the number of selected inputs
	// and added outputs, with no change.
	szEst := estimateTxSize(txInCount, 1)
	var feeIncrement dcrutil.Amount
	feeIncrement = w.RelayFee()

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
		return nil, err
	}

	pkScript, err := txscript.PayToAddrScript(changeAddr)
	if err != nil {
		return nil, fmt.Errorf("cannot create txout script: %s", err)
	}
	msgtx.AddTxOut(wire.NewTxOut(int64(outputAmt), pkScript))

	if err = signMsgTx(msgtx, forSigning, w.Manager,
		w.chainParams); err != nil {
		return nil, err
	}
	if err := validateMsgTxCredits(msgtx, forSigning); err != nil {
		return nil, err
	}

	txSha, err := chainClient.SendRawTransaction(msgtx, false)
	if err != nil {
		return nil, err
	}
	txSucceeded = true

	// Insert the transaction and credits into the transaction manager.
	rec, err := w.insertIntoTxMgr(msgtx)
	if err != nil {
		return nil, err
	}
	err = w.insertCreditsIntoTxMgr(msgtx, rec)
	if err != nil {
		return nil, err
	}

	log.Infof("Successfully consolidated funds in transaction %v", txSha)

	return txSha, nil
}

// compressEligible compresses all the utxos passed to it into a single
// output back to the wallet.
func (w *Wallet) compressEligible(eligible []wtxmgr.Credit) error {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return err
	}

	// Initialize the address pool for use.
	var pool *addressPool
	err = w.CheckAddressPoolsInitialized(waddrmgr.DefaultAccountNum)
	if err != nil {
		return err
	}
	pool = w.addrPools[waddrmgr.DefaultAccountNum].internal
	if pool == nil {
		log.Errorf("tried to use uninitialized pool for acct %v "+
			"when attempting to make a transaction",
			waddrmgr.DefaultAccountNum)
	}
	txSucceeded := false
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	defer func() {
		if txSucceeded {
			pool.BatchFinish()
		} else {
			pool.BatchRollback()
		}
	}()
	addrFunc := pool.getNewAddress

	if len(eligible) == 0 {
		return ErrNoOutsToConsolidate
	}

	txInCount := len(eligible)

	// Get an initial fee estimate based on the number of selected inputs
	// and added outputs, with no change.
	szEst := estimateTxSize(txInCount, 1)
	var feeIncrement dcrutil.Amount
	feeIncrement = w.RelayFee()

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
	if err := validateMsgTxCredits(msgtx, forSigning); err != nil {
		return err
	}

	txSha, err := chainClient.SendRawTransaction(msgtx, false)
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

// makeTicket creates a ticket from a split transaction output. It can optionally
// create a ticket that pays a fee to a pool if a pool input and pool address are
// passed.
func makeTicket(params *chaincfg.Params, inputPool *extendedOutPoint,
	input *extendedOutPoint, addrVote dcrutil.Address, addrSubsidy dcrutil.Address,
	ticketCost int64, addrPool dcrutil.Address) (*wire.MsgTx, error) {
	mtx := wire.NewMsgTx()

	if addrPool != nil && inputPool != nil {
		txIn := wire.NewTxIn(inputPool.op, []byte{})
		mtx.AddTxIn(txIn)
	}

	txIn := wire.NewTxIn(input.op, []byte{})
	mtx.AddTxIn(txIn)

	// Create a new script which pays to the provided address with an
	// SStx tagged output.
	pkScript, err := txscript.PayToSStx(addrVote)
	if err != nil {
		return nil, err
	}

	txOut := wire.NewTxOut(ticketCost, pkScript)
	txOut.Version = txscript.DefaultScriptVersion
	mtx.AddTxOut(txOut)

	// Obtain the commitment amounts.
	var amountsCommitted []int64
	userSubsidyNullIdx := 0
	if addrPool == nil {
		_, amountsCommitted, err = stake.GetSStxNullOutputAmounts(
			[]int64{input.amt}, []int64{0}, ticketCost)
		if err != nil {
			return nil, err
		}

	} else {
		_, amountsCommitted, err = stake.GetSStxNullOutputAmounts(
			[]int64{inputPool.amt, input.amt}, []int64{0, 0}, ticketCost)
		if err != nil {
			return nil, err
		}
		userSubsidyNullIdx = 1
	}

	// Zero value P2PKH addr.
	zeroed := [20]byte{}
	addrZeroed, err := dcrutil.NewAddressPubKeyHash(zeroed[:], params, 0)
	if err != nil {
		return nil, err
	}

	// 2. (Optional) If we're passed a pool address, make an extra
	// commitment to the pool.
	limits := uint16(defaultTicketFeeLimits)
	if addrPool != nil {
		pkScript, err = txscript.GenerateSStxAddrPush(addrPool,
			dcrutil.Amount(amountsCommitted[0]), limits)
		if err != nil {
			return nil, fmt.Errorf("cannot create pool txout script: %s", err)
		}
		txout := wire.NewTxOut(int64(0), pkScript)
		mtx.AddTxOut(txout)

		// Create a new script which pays to the provided address with an
		// SStx change tagged output.
		pkScript, err = txscript.PayToSStxChange(addrZeroed)
		if err != nil {
			return nil, err
		}

		txOut = wire.NewTxOut(0, pkScript)
		txOut.Version = txscript.DefaultScriptVersion
		mtx.AddTxOut(txOut)
	}

	// 3. Create the commitment and change output paying to the user.
	//
	// Create an OP_RETURN push containing the pubkeyhash to send rewards to.
	// Apply limits to revocations for fees while not allowing
	// fees for votes.
	pkScript, err = txscript.GenerateSStxAddrPush(addrSubsidy,
		dcrutil.Amount(amountsCommitted[userSubsidyNullIdx]), limits)
	if err != nil {
		return nil, fmt.Errorf("cannot create user txout script: %s", err)
	}
	txout := wire.NewTxOut(int64(0), pkScript)
	mtx.AddTxOut(txout)

	// Create a new script which pays to the provided address with an
	// SStx change tagged output.
	pkScript, err = txscript.PayToSStxChange(addrZeroed)
	if err != nil {
		return nil, err
	}

	txOut = wire.NewTxOut(0, pkScript)
	txOut.Version = txscript.DefaultScriptVersion
	mtx.AddTxOut(txOut)

	// Make sure we generated a valid SStx.
	if _, err := stake.IsSStx(dcrutil.NewTx(mtx)); err != nil {
		return nil, err
	}

	return mtx, nil
}

// purchaseTicket indicates to the wallet that a ticket should be purchased
// using all currently available funds.  The ticket address parameter in the
// request can be nil in which case the ticket address associated with the
// wallet instance will be used.  Also, when the spend limit in the request is
// greater than or equal to 0, tickets that cost more than that limit will
// return an error that not enough funds are available.
func (w *Wallet) purchaseTicket(req purchaseTicketRequest) (interface{},
	error) {
	// Ensure the minimum number of required confirmations is positive.
	if req.minConf < 0 {
		return nil, fmt.Errorf("need positive minconf")
	}

	// Need a positive or zero expiry that is higher than the next block to
	// generate.
	if req.expiry < 0 {
		return nil, fmt.Errorf("need positive expiry")
	}
	bs := w.Manager.SyncedTo()
	if req.expiry <= bs.Height+1 && req.expiry > 0 {
		return nil, fmt.Errorf("need expiry that is beyond next height ("+
			"given: %v, next height %v)", req.expiry, bs.Height+1)
	}

	// Initialize the address pool for use.
	var pool *addressPool
	err := w.CheckAddressPoolsInitialized(req.account)
	if err != nil {
		return nil, err
	}
	pool = w.addrPools[req.account].internal

	// Fetch a new address for creating a split transaction. Then,
	// make a split transaction that contains exact outputs for use
	// in ticket generation. Cache its hash to use below when
	// generating a ticket. The account balance is checked first
	// in case there is not enough money to generate the split
	// even without fees.
	// TODO This can still sometimes fail if the split amount
	// required plus fees for the split is larger than the
	// balance we have, wasting an address. In the future,
	// address this better and prevent address burning.
	account := req.account

	// Get the current ticket price.
	ticketPrice := dcrutil.Amount(w.GetStakeDifficulty().StakeDifficulty)
	if ticketPrice == -1 {
		return nil, ErrTicketPriceNotSet
	}

	// Ensure the ticket price does not exceed the spend limit if set.
	if req.spendLimit >= 0 && ticketPrice > req.spendLimit {
		return nil, ErrSStxPriceExceedsSpendLimit
	}

	// Try to get the pool address from the request. If none exists
	// in the request, try to get the global pool address. Then do
	// the same for pool fees, but check sanity too.
	poolAddress := req.poolAddress
	if poolAddress == nil {
		poolAddress = w.PoolAddress()
	}
	poolFees := req.poolFees
	if poolFees == 0 {
		poolFees = w.PoolFees()
	}
	if poolAddress != nil && poolFees == 0 {
		return nil, fmt.Errorf("pool address given, but pool fees not set")
	}
	if poolFees >= ticketPrice {
		return nil, fmt.Errorf("pool fees of %v >= than current "+
			"ticket price of %v", poolFees, ticketPrice)
	}

	// Make sure that we have enough funds. Calculate different
	// ticket required amounts depending on whether or not a
	// pool output is needed.
	neededPerTicket := dcrutil.Amount(0)
	ticketFee := dcrutil.Amount(0)
	if poolAddress == nil {
		ticketFee = ((w.TicketFeeIncrement() * singleInputTicketSize) /
			1000)
		neededPerTicket = ticketFee + ticketPrice
	} else {
		ticketFee = ((w.TicketFeeIncrement() * doubleInputTicketSize) /
			1000)
		neededPerTicket = ticketFee + ticketPrice
	}

	// Make sure this doesn't over spend based on the balance to
	// maintain. This component of the API is inaccessible to the
	// end user through the legacy RPC, so it should only ever be
	// set by internal calls e.g. automatic ticket purchase.
	if req.minBalance > 0 {
		bal, err := w.CalculateAccountBalance(account, req.minConf,
			wtxmgr.BFBalanceSpendable)
		if err != nil {
			return nil, err
		}

		estimatedFundsUsed := neededPerTicket * dcrutil.Amount(req.numTickets)
		if req.minBalance+estimatedFundsUsed > bal {
			notEnoughFundsStr := fmt.Sprintf("not enough funds; balance to "+
				"maintain is %v and estimated cost is %v (resulting in %v "+
				"funds needed) but wallet account %v only has %v",
				req.minBalance.ToCoin(), estimatedFundsUsed.ToCoin(),
				req.minBalance.ToCoin()+estimatedFundsUsed.ToCoin(),
				account, bal.ToCoin())
			log.Debugf("%s", notEnoughFundsStr)
			return nil, txauthor.InsufficientFundsError{}
		}
	}

	// Fetch the single use split address to break tickets into, to
	// immediately be consumed as tickets.
	splitTxAddr, err := pool.GetNewAddress()
	if err != nil {
		return nil, err
	}

	// Create the split transaction by using txToOutputs. This varies
	// based upon whether or not the user is using a stake pool or not.
	// For the default stake pool implementation, the user pays out the
	// first ticket commitment of a smaller amount to the pool, while
	// paying themselves with the larger ticket commitment.
	var splitOuts []*wire.TxOut
	for i := 0; i < req.numTickets; i++ {
		// No pool used.
		if poolAddress == nil {
			pkScript, err := txscript.PayToAddrScript(splitTxAddr)
			if err != nil {
				return nil, fmt.Errorf("cannot create txout script: %s", err)
			}

			splitOuts = append(splitOuts,
				wire.NewTxOut(int64(neededPerTicket), pkScript))
		} else {
			// Stake pool used.
			userAmt := neededPerTicket - poolFees
			poolAmt := poolFees

			// Pool amount.
			pkScript, err := txscript.PayToAddrScript(splitTxAddr)
			if err != nil {
				return nil, fmt.Errorf("cannot create txout script: %s", err)
			}

			splitOuts = append(splitOuts, wire.NewTxOut(int64(poolAmt), pkScript))

			// User amount.
			pkScript, err = txscript.PayToAddrScript(splitTxAddr)
			if err != nil {
				return nil, fmt.Errorf("cannot create txout script: %s", err)
			}

			splitOuts = append(splitOuts, wire.NewTxOut(int64(userAmt), pkScript))
		}

	}
	splitTx, err := w.txToOutputs(splitOuts, account, req.minConf, false)
	if err != nil {
		return nil, err
	}

	// Address manager must be unlocked to compose tickets.  Grab
	// the unlock if possible (to prevent future unlocks), or return the
	// error if already locked.
	heldUnlock, err := w.HoldUnlock()
	if err != nil {
		return nil, err
	}
	defer heldUnlock.Release()

	// Fire up the address pool for usage in generating tickets.
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
	addrFunc := pool.getNewAddress

	if w.addressReuse {
		addrFunc = w.ReusedAddress
	}

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	isReorganizing, _ := chainClient.GetReorganizing()
	if isReorganizing {
		return "", ErrBlockchainReorganizing
	}

	// Generate the tickets individually.
	ticketHashes := make([]string, req.numTickets)
	for i := 0; i < req.numTickets; i++ {
		// Generate the extended outpoints that we
		// need to use for ticket inputs. There are
		// two inputs for pool tickets corresponding
		// to the fees and the user subsidy, while
		// user-handled tickets have only one input.
		var eopPool, eop *extendedOutPoint
		if poolAddress == nil {
			txOut := splitTx.Tx.TxOut[i]

			eop = &extendedOutPoint{
				op: &wire.OutPoint{
					Hash:  splitTx.Tx.TxSha(),
					Index: uint32(i),
					Tree:  dcrutil.TxTreeRegular,
				},
				amt:      txOut.Value,
				pkScript: txOut.PkScript,
			}
		} else {
			poolIdx := i * 2
			poolTxOut := splitTx.Tx.TxOut[poolIdx]
			userIdx := i*2 + 1
			txOut := splitTx.Tx.TxOut[userIdx]

			eopPool = &extendedOutPoint{
				op: &wire.OutPoint{
					Hash:  splitTx.Tx.TxSha(),
					Index: uint32(poolIdx),
					Tree:  dcrutil.TxTreeRegular,
				},
				amt:      poolTxOut.Value,
				pkScript: poolTxOut.PkScript,
			}
			eop = &extendedOutPoint{
				op: &wire.OutPoint{
					Hash:  splitTx.Tx.TxSha(),
					Index: uint32(userIdx),
					Tree:  dcrutil.TxTreeRegular,
				},
				amt:      txOut.Value,
				pkScript: txOut.PkScript,
			}
		}

		// If the user hasn't specified a voting address
		// to delegate voting to, just use an address from
		// this wallet. Check the passed address from the
		// request first, then check the ticket address
		// stored from the configuation. Finally, generate
		// an address.
		addrVote := req.ticketAddr
		if addrVote == nil {
			addrVote = w.ticketAddress
			if addrVote == nil {
				addrVote, err = addrFunc()
				if err != nil {
					return nil, err
				}
			}
		}

		addrSubsidy, err := addrFunc()
		if err != nil {
			return nil, err
		}

		// Generate the ticket msgTx and sign it.
		ticket, err := makeTicket(w.ChainParams(), eopPool, eop, addrVote,
			addrSubsidy, int64(ticketPrice), poolAddress)
		if err != nil {
			return nil, err
		}
		var forSigning []wtxmgr.Credit
		if eopPool != nil {
			eopPoolCredit := wtxmgr.Credit{
				*eopPool.op,
				wtxmgr.BlockMeta{},
				dcrutil.Amount(eopPool.amt),
				eopPool.pkScript,
				time.Now(),
				false,
			}
			forSigning = append(forSigning, eopPoolCredit)
		}
		eopCredit := wtxmgr.Credit{
			*eop.op,
			wtxmgr.BlockMeta{},
			dcrutil.Amount(eop.amt),
			eop.pkScript,
			time.Now(),
			false,
		}
		forSigning = append(forSigning, eopCredit)

		// Set the expiry.
		ticket.Expiry = uint32(req.expiry)

		if err = signMsgTx(ticket, forSigning, w.Manager,
			w.chainParams); err != nil {
			return nil, err
		}
		if err := validateMsgTxCredits(ticket, forSigning); err != nil {
			return nil, err
		}

		// Send the ticket over the network.
		txSha, err := chainClient.SendRawTransaction(ticket, false)
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
		rec, err := w.insertIntoTxMgr(ticket)
		if err != nil {
			return nil, err
		}
		err = w.insertCreditsIntoTxMgr(ticket, rec)
		if err != nil {
			return nil, err
		}
		txTemp := dcrutil.NewTx(ticket)

		// The ticket address may be for another wallet. Don't insert the
		// ticket into the stake manager unless we actually own output zero
		// of it. If this is the case, the chainntfns.go handlers will
		// automatically insert it.
		if _, err := w.Manager.Address(addrVote); err == nil {
			if w.ticketAddress == nil {
				err = w.StakeMgr.InsertSStx(txTemp, w.VoteBits)
				if err != nil {
					return nil, fmt.Errorf("Failed to insert SStx %v"+
						"into the stake store", txTemp.Sha())
				}
			}
		}

		log.Infof("Successfully sent SStx purchase transaction %v", txSha)
		ticketHashes[i] = txSha.String()
	}

	return ticketHashes, nil
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

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// Quit if the blockchain is reorganizing.
	isReorganizing, _ := chainClient.GetReorganizing()
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
	if err := validateMsgTxCredits(msgtx, inputCredits); err != nil {
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
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}
	isReorganizing, _ := chainClient.GetReorganizing()
	if isReorganizing {
		return nil, ErrBlockchainReorganizing
	}

	return nil, nil
}

// txToSSRtx ...
// DECRED TODO
func (w *Wallet) txToSSRtx(ticketHash chainhash.Hash) (*CreatedTx, error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}
	isReorganizing, _ := chainClient.GetReorganizing()
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
		if err != nil || len(addrs) != 1 {
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
		// account.
		//
		// TODO: Handle multisig outputs by determining if enough of the
		// addresses are controlled.
		addrAcct, err := w.Manager.AddrAccount(addrs[0])
		if err != nil || addrAcct != account {
			continue
		}

		eligible = append(eligible, *output)
	}
	return eligible, nil
}

// FindEligibleOutputs is the exported version of findEligibleOutputs (which
// tried to find unspent outputs that pass a maturity check).
func (w *Wallet) FindEligibleOutputs(account uint32, minconf int32,
	bs *waddrmgr.BlockStamp) ([]wtxmgr.Credit, error) {
	return w.findEligibleOutputs(account, minconf, bs)
}

// findEligibleOutputsAmount uses wtxmgr to find a number of unspent
// outputs while doing maturity checks there.
func (w *Wallet) findEligibleOutputsAmount(account uint32, minconf int32,
	amount dcrutil.Amount, bs *waddrmgr.BlockStamp) ([]wtxmgr.Credit, error) {

	unspent, err := w.TxStore.UnspentOutputsForAmount(amount, bs.Height, minconf,
		false, account)
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

// randomAddress returns a random address. Mainly used for 0-value (unspendable)
// OP_SSTXCHANGE tagged outputs.
func randomAddress(params *chaincfg.Params) (dcrutil.Address, error) {
	b := make([]byte, ripemd160.Size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return dcrutil.NewAddressPubKeyHash(b, params,
		chainec.ECTypeSecp256k1)
}
