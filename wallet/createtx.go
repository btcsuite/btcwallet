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

	// pkScriptEstimateSS
	pkScriptEstimateSS = 1 + 1 + 1 + 1 + 20 + 1 + 1

	// txOutEstimate is a best case tx output serialization cost is 8 bytes
	// of value, two bytes of version, one byte of varint, and the pkScript
	// size.
	txOutEstimate = 8 + 2 + 1 + pkScriptEstimate

	// ssTxOutEsimate
	ssTxOutEsimate = 8 + 2 + 1 + pkScriptEstimateSS
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

func estimateSSTxSize(numInputs int) int {
	return txOverheadEstimate + txInEstimate*numInputs +
		sstxTicketCommitmentEstimate +
		(sstxSubsidyCommitmentEstimate+
			sstxChangeOutputEstimate)*numInputs
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

// TicketFeeIncrement is the default minimum stake transation fee (0.05 coin,
// measured in atoms).
const TicketFeeIncrement = 5e6

// EstMaxTicketFeeAmount is the estimated max ticket fee to be used for size
// calculation for eligible utxos for ticket purchasing
const EstMaxTicketFeeAmount = 0.1 * 1e8

// --------------------------------------------------------------------------------
// Error Handling

// InsufficientFundsError represents an error where there are not enough
// funds from unspent tx outputs for a wallet to create a transaction.
// This may be caused by not enough inputs for all of the desired total
// transaction output amount, or due to
type InsufficientFundsError struct {
	in, out, fee dcrutil.Amount
}

// CreateTxFundsError represents an error where there are not enough
// funds from unspent tx outputs for a wallet to create a transaction
// through createtx. The amount needed and the fee required are passed
// back.
type CreateTxFundsError struct {
	needed, fee dcrutil.Amount
}

// Error satisifies the builtin error interface.
func (e CreateTxFundsError) Error() string {
	return fmt.Sprintf("insufficient funds")
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
func (w *Wallet) txToOutputs(outputs []*wire.TxOut, account uint32, minconf int32) (atx *txauthor.AuthoredTx, err error) {
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

	// Initialize the address pool for use.
	pool := w.internalPool
	pool.mutex.Lock()
	defer func() {
		if err == nil {
			pool.BatchFinish()
		} else {
			pool.BatchRollback()
		}
		pool.mutex.Unlock()
	}()

	inputSource := w.TxStore.MakeInputSource(account, minconf, bs.Height)
	changeSource := func() ([]byte, error) {
		// Derive the change output script.  As a hack to allow spending from
		// the imported account, change addresses are created from account 0.
		var changeAddr dcrutil.Address
		var err error
		switch account {
		case waddrmgr.DefaultAccountNum, waddrmgr.ImportedAddrAccount:
			changeAddr, err = pool.GetNewAddress()
		default:
			// TODO: In the future, this should be replaced with a
			// tracking address pool for this account.
			changeAddr, err = w.NewChangeAddress(account)
		}
		if err != nil {
			return nil, err
		}
		return txscript.PayToAddrScript(changeAddr)
	}
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
	if tx.ChangeIndex >= 0 {
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

	chainClient, err := w.requireChainClient()
	if err != nil {
		return errorOut(err)
	}

	isReorganizing, _ := chainClient.GetReorganizing()
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
	bs, err := chainClient.BlockStamp()
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
	feeIncrement = w.RelayFee()

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

	_, err = chainClient.SendRawTransaction(msgtx, false)
	if err != nil {
		return errorOut(err)
	}

	// Request updates from dcrd for new transactions sent to this
	// script hash address.
	utilAddrs := make([]dcrutil.Address, 1)
	utilAddrs[0] = scAddr
	if err := chainClient.NotifyReceived(utilAddrs); err != nil {
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
	var addrFunc func() (dcrutil.Address, error)
	if account == waddrmgr.DefaultAccountNum ||
		account == waddrmgr.ImportedAddrAccount {
		addrFunc = pool.GetNewAddress
	} else {
		// A pass through to enable the user to get a
		// change address for a non-default account.
		// In the future, this should be replaced with
		// a tracking address pool for this account.
		addrFunc = func() (dcrutil.Address, error) {
			return w.NewChangeAddress(account)
		}
	}

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
	var addrFunc func() (dcrutil.Address, error)
	if req.account == waddrmgr.DefaultAccountNum ||
		req.account == waddrmgr.ImportedAddrAccount {
		addrFunc = pool.GetNewAddress
	} else {
		// A pass through to enable the user to get a
		// change address for a non-default account.
		// In the future, this should be replaced with
		// a tracking address pool for this account.
		addrFunc = func() (dcrutil.Address, error) {
			return w.NewChangeAddress(req.account)
		}
	}

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

	account := req.account

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
	bs, err := chainClient.BlockStamp()
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

	// Recreate address/amount pairs, using dcrutil.Amount.
	pair := make(map[string]dcrutil.Amount, 1)
	pair[ticketAddr.String()] = ticketPrice

	// TODO Currently we are using an estimated max ticket size
	// to get estimate fees to make sure we have enough eligible
	// utxos
	var estFee dcrutil.Amount
	estFee = EstMaxTicketFeeAmount

	// Instead of taking reward addresses by arg, just create them now and
	// automatically find all eligible outputs from all current utxos.
	amountNeeded := req.minBalance + ticketPrice + estFee
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
			// Use a random address if the change amount is
			// unspendable. This is the case if it's not
			// the last credit.
			newChangeAddress, err := randomAddress(w.chainParams)
			if err != nil {
				return nil, err
			}

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

			estSize := estimateSSTxSize(i)
			var feeIncrement dcrutil.Amount
			feeIncrement = w.TicketFeeIncrement()

			fee := feeForSize(feeIncrement, estSize)

			// Not enough funds after taking fee into account.
			// Should retry instead of failing, Decred TODO
			totalWithThisCredit := creditAmount + outputSum
			if (totalWithThisCredit - int64(fee) - int64(ticketPrice)) < 0 {
				return nil, ErrSStxNotEnoughFunds
			}

			remaining := int64(ticketPrice) - outputSum
			change := creditAmount - remaining - int64(fee)

			newChangeAddress, err := addrFunc()
			if err != nil {
				return nil, err
			}
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

	txSha, err := chainClient.SendRawTransaction(createdTx.MsgTx, false)
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
			err = w.StakeMgr.InsertSStx(txTemp, w.VoteBits)
			if err != nil {
				return nil, fmt.Errorf("Failed to insert SStx %v"+
					"into the stake store", txTemp.Sha())
			}
		}
	}

	log.Infof("Successfully sent SStx purchase transaction %v", txSha)

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

// Exported version of findEligibleOutputs.
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
