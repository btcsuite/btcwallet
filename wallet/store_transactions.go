// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// storeAccountName returns the account name controlling an address. Address
// lookup failures intentionally produce an empty name to preserve the legacy
// transaction-listing behavior.
func storeAccountName(tx walletstore.ReadTx, w *Wallet,
	addr address.Address) string {

	manager, account, err := w.Manager.AddrAccountFromStore(tx.Addr(), addr)
	if err != nil {
		return ""
	}

	name, err := manager.AccountNameFromStore(tx.Addr(), account)
	if err != nil {
		return ""
	}

	return name
}

// listTransactionsFromStore formats transaction details for the legacy JSON
// transaction-listing APIs through a closure Store transaction.
//
//nolint:cyclop,gocognit // This mirrors the established result classification.
func listTransactionsFromStore(tx walletstore.ReadTx, w *Wallet,
	details *wtxmgr.TxDetails,
	syncHeight int32) []btcjson.ListTransactionsResult {

	var (
		blockHashStr  string
		blockTime     int64
		confirmations int64
	)
	if details.Block.Height != -1 {
		blockHashStr = details.Block.Hash.String()
		blockTime = details.Block.Time.Unix()
		confirmations = int64(calcConf(details.Block.Height, syncHeight))
	}

	results := []btcjson.ListTransactionsResult{}
	txHashStr := details.Hash.String()
	received := details.Received.Unix()
	generated := blockchain.IsCoinBaseTx(&details.MsgTx)
	recvCategory := RecvCategory(
		details, syncHeight, w.chainParams,
	).String()
	send := len(details.Debits) != 0

	// A fee is known only when every input debits a wallet credit.
	var fee float64
	if len(details.Debits) == len(details.MsgTx.TxIn) {
		var debitTotal btcutil.Amount
		for _, debit := range details.Debits {
			debitTotal += debit.Amount
		}

		var outputTotal btcutil.Amount
		for _, output := range details.MsgTx.TxOut {
			outputTotal += btcutil.Amount(output.Value)
		}

		fee = (outputTotal - debitTotal).ToBTC()
	}

outputs:
	for i, output := range details.MsgTx.TxOut {
		var (
			isCredit    bool
			spentCredit bool
		)
		for _, credit := range details.Credits {
			if credit.Index != uint32(i) {
				continue
			}
			if credit.Change {
				continue outputs
			}

			isCredit = true
			spentCredit = credit.Spent

			break
		}

		var (
			addressString string
			accountName   string
		)
		_, addrs, _, _ := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams,
		)
		if len(addrs) == 1 {
			addressString = addrs[0].EncodeAddress()
			accountName = storeAccountName(tx, w, addrs[0])
		}

		amount := btcutil.Amount(output.Value).ToBTC()
		result := btcjson.ListTransactionsResult{
			Address:         addressString,
			Vout:            uint32(i),
			Confirmations:   confirmations,
			Generated:       generated,
			BlockHash:       blockHashStr,
			BlockTime:       blockTime,
			TxID:            txHashStr,
			WalletConflicts: []string{},
			Time:            received,
			TimeReceived:    received,
		}

		if send || spentCredit {
			result.Category = "send"
			result.Amount = -amount
			result.Fee = &fee
			results = append(results, result)
		}
		if isCredit {
			result.Account = accountName
			result.Category = recvCategory
			result.Amount = amount
			result.Fee = nil
			results = append(results, result)
		}
	}

	return results
}

// lookupInputAccountFromStore resolves the account debited by one transaction
// input through the transaction and address views sharing the same snapshot.
func lookupInputAccountFromStore(tx walletstore.ReadTx, w *Wallet,
	details *wtxmgr.TxDetails, debit wtxmgr.DebitRecord) uint32 {

	prevOut := &details.MsgTx.TxIn[debit.Index].PreviousOutPoint
	previous, err := tx.Tx().TxDetails(&prevOut.Hash)
	if err != nil {
		log.Errorf("Cannot query previous transaction details for %v: %v",
			prevOut.Hash, err)
		return 0
	}
	if previous == nil {
		log.Errorf("Missing previous transaction %v", prevOut.Hash)
		return 0
	}

	output := previous.MsgTx.TxOut[prevOut.Index]
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		output.PkScript, w.chainParams,
	)
	if err != nil || len(addrs) == 0 {
		if err != nil {
			log.Errorf("Cannot parse previous output %v: %v", prevOut, err)
		}

		return 0
	}

	_, account, err := w.Manager.AddrAccountFromStore(tx.Addr(), addrs[0])
	if err != nil {
		log.Errorf("Cannot fetch account for previous output %v: %v",
			prevOut, err)
		return 0
	}

	return account
}

// lookupOutputChainFromStore resolves the account and branch for one wallet
// credit through the address view sharing the transaction snapshot.
func lookupOutputChainFromStore(tx walletstore.ReadTx, w *Wallet,
	details *wtxmgr.TxDetails,
	credit wtxmgr.CreditRecord) (uint32, bool) {

	output := details.MsgTx.TxOut[credit.Index]
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		output.PkScript, w.chainParams,
	)
	if err != nil || len(addrs) == 0 {
		if err != nil {
			log.Errorf("Cannot parse wallet output: %v", err)
		}

		return 0, false
	}

	managed, err := w.Manager.AddressFromStore(tx.Addr(), addrs[0])
	if err != nil {
		log.Errorf("Cannot fetch account for wallet output: %v", err)
		return 0, false
	}

	return managed.InternalAccount(), managed.Internal()
}

// makeTxSummaryFromStore creates the public transaction summary through a
// closure Store snapshot.
//
//nolint:cyclop // This mirrors the established transaction summary logic.
func makeTxSummaryFromStore(tx walletstore.ReadTx, w *Wallet,
	details *wtxmgr.TxDetails) TransactionSummary {

	serializedTx := details.SerializedTx
	if serializedTx == nil {
		var buffer bytes.Buffer
		err := details.MsgTx.Serialize(&buffer)
		if err != nil {
			log.Errorf("Transaction serialization: %v", err)
		}
		serializedTx = buffer.Bytes()
	}

	var fee btcutil.Amount
	if len(details.Debits) == len(details.MsgTx.TxIn) {
		for _, debit := range details.Debits {
			fee += debit.Amount
		}
		for _, output := range details.MsgTx.TxOut {
			fee -= btcutil.Amount(output.Value)
		}
	}

	var inputs []TransactionSummaryInput
	if len(details.Debits) != 0 {
		inputs = make([]TransactionSummaryInput, len(details.Debits))
		for i, debit := range details.Debits {
			inputs[i] = TransactionSummaryInput{
				Index: debit.Index,
				PreviousAccount: lookupInputAccountFromStore(
					tx, w, details, debit,
				),
				PreviousAmount: debit.Amount,
			}
		}
	}

	outputs := make([]TransactionSummaryOutput, 0, len(details.MsgTx.TxOut))
	for i := range details.MsgTx.TxOut {
		creditIndex := len(outputs)
		isCredit := len(details.Credits) > creditIndex &&
			details.Credits[creditIndex].Index == uint32(i)
		if !isCredit {
			continue
		}

		account, internal := lookupOutputChainFromStore(
			tx, w, details, details.Credits[creditIndex],
		)
		outputs = append(outputs, TransactionSummaryOutput{
			Index:    uint32(i),
			Account:  account,
			Internal: internal,
		})
	}

	return TransactionSummary{
		Hash:        &details.Hash,
		Transaction: serializedTx,
		MyInputs:    inputs,
		MyOutputs:   outputs,
		Fee:         fee,
		Timestamp:   details.Received.Unix(),
		Label:       details.Label,
		Tx:          &details.MsgTx,
	}
}

// storeTotalBalances fills balances for the requested accounts from spendable
// credits in the transaction snapshot.
func storeTotalBalances(tx walletstore.ReadTx, w *Wallet,
	balances map[uint32]btcutil.Amount) error {

	unspent, err := tx.Tx().UnspentOutputs()
	if err != nil {
		return err
	}

	for i := range unspent {
		output := &unspent[i]
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams,
		)
		if err != nil || len(addrs) == 0 {
			continue
		}

		_, account, err := w.Manager.AddrAccountFromStore(
			tx.Addr(), addrs[0],
		)
		if err != nil {
			continue
		}
		if _, ok := balances[account]; ok {
			balances[account] += output.Amount
		}
	}

	return nil
}
