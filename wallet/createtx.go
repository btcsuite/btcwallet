// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"
	"fmt"
	"math/rand"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

func makeInputSource(eligible []Coin) txauthor.InputSource {
	// Current inputs and their total value. These are closed over by the
	// returned input source and reused across multiple calls.
	currentTotal := btcutil.Amount(0)
	currentInputs := make([]*wire.TxIn, 0, len(eligible))
	currentScripts := make([][]byte, 0, len(eligible))
	currentInputValues := make([]btcutil.Amount, 0, len(eligible))

	return func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
		[]btcutil.Amount, [][]byte, error) {

		for currentTotal < target && len(eligible) != 0 {
			nextCredit := eligible[0]
			prevOut := nextCredit.TxOut
			outpoint := nextCredit.OutPoint
			eligible = eligible[1:]

			nextInput := wire.NewTxIn(&outpoint, nil, nil)
			currentTotal += btcutil.Amount(prevOut.Value)
			currentInputs = append(currentInputs, nextInput)
			currentScripts = append(
				currentScripts, prevOut.PkScript,
			)
			currentInputValues = append(
				currentInputValues,
				btcutil.Amount(prevOut.Value),
			)
		}

		return currentTotal, currentInputs, currentInputValues,
			currentScripts, nil
	}
}

// secretSource is an implementation of txauthor.SecretSource for the wallet's
// address manager.
type secretSource struct {
	*waddrmgr.Manager
	addrmgrNs walletdb.ReadBucket
}

func (s secretSource) GetKey(addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
	ma, err := s.Address(s.addrmgrNs, addr)
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

func (s secretSource) GetScript(addr btcutil.Address) ([]byte, error) {
	ma, err := s.Address(s.addrmgrNs, addr)
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

// txToOutputs creates a signed transaction which includes each output from
// outputs. Previous outputs to redeem are chosen from the passed account's
// UTXO set and minconf policy. An additional output may be added to return
// change to the wallet. This output will have an address generated from the
// given key scope and account. If a key scope is not specified, the address
// will always be generated from the P2WKH key scope. An appropriate fee is
// included based on the wallet's current relay fee. The wallet must be
// unlocked to create the transaction.
//
// NOTE: The dryRun argument can be set true to create a tx that doesn't alter
// the database. A tx created with this set to true will intentionally have no
// input scripts added and SHOULD NOT be broadcasted.
func (w *Wallet) txToOutputs(outputs []*wire.TxOut,
	coinSelectKeyScope, changeKeyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, feeSatPerKb btcutil.Amount,
	coinSelectionStrategy CoinSelectionStrategy, dryRun bool) (
	*txauthor.AuthoredTx, error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// Get current block's height and hash.
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	// Fall back to default coin selection strategy if none is supplied.
	if coinSelectionStrategy == nil {
		coinSelectionStrategy = CoinSelectionLargest
	}

	var tx *txauthor.AuthoredTx
	err = walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
		addrmgrNs, changeSource, err := w.addrMgrWithChangeSource(
			dbtx, changeKeyScope, account,
		)
		if err != nil {
			return err
		}

		eligible, err := w.findEligibleOutputs(
			dbtx, coinSelectKeyScope, account, minconf, bs,
		)
		if err != nil {
			return err
		}

		// Wrap our coins in a type that implements the SelectableCoin
		// interface, so we can arrange them according to the selected
		// coin selection strategy.
		wrappedEligible := make([]Coin, len(eligible))
		for i := range eligible {
			wrappedEligible[i] = Coin{
				TxOut: wire.TxOut{
					Value:    int64(eligible[i].Amount),
					PkScript: eligible[i].PkScript,
				},
				OutPoint: eligible[i].OutPoint,
			}
		}
		arrangedCoins, err := coinSelectionStrategy.ArrangeCoins(
			wrappedEligible, feeSatPerKb,
		)
		if err != nil {
			return err
		}

		inputSource := makeInputSource(arrangedCoins)

		tx, err = txauthor.NewUnsignedTransaction(
			outputs, feeSatPerKb, inputSource, changeSource,
		)
		if err != nil {
			return err
		}

		// Randomize change position, if change exists, before signing.
		// This doesn't affect the serialize size, so the change amount
		// will still be valid.
		if tx.ChangeIndex >= 0 {
			tx.RandomizeChangePosition()
		}

		// If a dry run was requested, we return now before adding the
		// input scripts, and don't commit the database transaction.
		// By returning an error, we make sure the walletdb.Update call
		// rolls back the transaction. But we'll react to this specific
		// error outside of the DB transaction so we can still return
		// the produced chain TX.
		if dryRun {
			return walletdb.ErrDryRunRollBack
		}

		// Before committing the transaction, we'll sign our inputs. If
		// the inputs are part of a watch-only account, there's no
		// private key information stored, so we'll skip signing such.
		var watchOnly bool
		if coinSelectKeyScope == nil {
			// If a key scope wasn't specified, then coin selection
			// was performed from the default wallet accounts
			// (NP2WKH, P2WKH, P2TR), so any key scope provided
			// doesn't impact the result of this call.
			watchOnly, err = w.Manager.IsWatchOnlyAccount(
				addrmgrNs, waddrmgr.KeyScopeBIP0086, account,
			)
		} else {
			watchOnly, err = w.Manager.IsWatchOnlyAccount(
				addrmgrNs, *coinSelectKeyScope, account,
			)
		}
		if err != nil {
			return err
		}
		if !watchOnly {
			err = tx.AddAllInputScripts(
				secretSource{w.Manager, addrmgrNs},
			)
			if err != nil {
				return err
			}

			err = validateMsgTx(
				tx.Tx, tx.PrevScripts, tx.PrevInputValues,
			)
			if err != nil {
				return err
			}
		}

		if tx.ChangeIndex >= 0 && account == waddrmgr.ImportedAddrAccount {
			changeAmount := btcutil.Amount(
				tx.Tx.TxOut[tx.ChangeIndex].Value,
			)
			log.Warnf("Spend from imported account produced "+
				"change: moving %v from imported account into "+
				"default account.", changeAmount)
		}

		// Finally, we'll request the backend to notify us of the
		// transaction that pays to the change address, if there is one,
		// when it confirms.
		if tx.ChangeIndex >= 0 {
			changePkScript := tx.Tx.TxOut[tx.ChangeIndex].PkScript
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				changePkScript, w.chainParams,
			)
			if err != nil {
				return err
			}
			if err := chainClient.NotifyReceived(addrs); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil && !errors.Is(err, walletdb.ErrDryRunRollBack) {
		return nil, err
	}

	return tx, nil
}

func (w *Wallet) findEligibleOutputs(dbtx walletdb.ReadTx,
	keyScope *waddrmgr.KeyScope, account uint32, minconf int32,
	bs *waddrmgr.BlockStamp) ([]wtxmgr.Credit, error) {

	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

	unspent, err := w.TxStore.UnspentOutputs(txmgrNs)
	if err != nil {
		return nil, err
	}

	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependency and requesting unspent outputs for a single account.
	eligible := make([]wtxmgr.Credit, 0, len(unspent))
	for i := range unspent {
		output := &unspent[i]

		// Only include this output if it meets the required number of
		// confirmations. Coinbase transactions must have reached
		// maturity before their outputs may be spent.
		if !confirmed(minconf, output.Height, bs.Height) {
			continue
		}
		if output.FromCoinBase {
			target := int32(w.chainParams.CoinbaseMaturity)
			if !confirmed(target, output.Height, bs.Height) {
				continue
			}
		}

		// Locked unspent outputs are skipped.
		if w.LockedOutpoint(output.OutPoint) {
			continue
		}

		// Only include the output if it is associated with the passed
		// account.
		//
		// TODO: Handle multisig outputs by determining if enough of the
		// addresses are controlled.
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams)
		if err != nil || len(addrs) != 1 {
			continue
		}
		scopedMgr, addrAcct, err := w.Manager.AddrAccount(addrmgrNs, addrs[0])
		if err != nil {
			continue
		}
		if keyScope != nil && scopedMgr.Scope() != *keyScope {
			continue
		}
		if addrAcct != account {
			continue
		}
		eligible = append(eligible, *output)
	}
	return eligible, nil
}

// inputYieldsPositively returns a boolean indicating whether this input yields
// positively if added to a transaction. This determination is based on the
// best-case added virtual size. For edge cases this function can return true
// while the input is yielding slightly negative as part of the final
// transaction.
func inputYieldsPositively(credit *wire.TxOut,
	feeRatePerKb btcutil.Amount) bool {

	inputSize := txsizes.GetMinInputVirtualSize(credit.PkScript)
	inputFee := feeRatePerKb * btcutil.Amount(inputSize) / 1000

	return inputFee < btcutil.Amount(credit.Value)
}

// addrMgrWithChangeSource returns the address manager bucket and a change
// source that returns change addresses from said address manager. The change
// addresses will come from the specified key scope and account, unless a key
// scope is not specified. In that case, change addresses will always come from
// the P2WKH key scope.
func (w *Wallet) addrMgrWithChangeSource(dbtx walletdb.ReadWriteTx,
	changeKeyScope *waddrmgr.KeyScope, account uint32) (
	walletdb.ReadWriteBucket, *txauthor.ChangeSource, error) {

	// Determine the address type for change addresses of the given
	// account.
	if changeKeyScope == nil {
		changeKeyScope = &waddrmgr.KeyScopeBIP0086
	}
	addrType := waddrmgr.ScopeAddrMap[*changeKeyScope].InternalAddrType

	// It's possible for the account to have an address schema override, so
	// prefer that if it exists.
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	scopeMgr, err := w.Manager.FetchScopedKeyManager(*changeKeyScope)
	if err != nil {
		return nil, nil, err
	}
	accountInfo, err := scopeMgr.AccountProperties(addrmgrNs, account)
	if err != nil {
		return nil, nil, err
	}
	if accountInfo.AddrSchema != nil {
		addrType = accountInfo.AddrSchema.InternalAddrType
	}

	// Compute the expected size of the script for the change address type.
	var scriptSize int
	switch addrType {
	case waddrmgr.PubKeyHash:
		scriptSize = txsizes.P2PKHPkScriptSize
	case waddrmgr.NestedWitnessPubKey:
		scriptSize = txsizes.NestedP2WPKHPkScriptSize
	case waddrmgr.WitnessPubKey:
		scriptSize = txsizes.P2WPKHPkScriptSize
	case waddrmgr.TaprootPubKey:
		scriptSize = txsizes.P2TRPkScriptSize
	default:
		return nil, nil, fmt.Errorf("unsupported address type: %v",
			addrType)
	}

	newChangeScript := func() ([]byte, error) {
		// Derive the change output script. As a hack to allow spending
		// from the imported account, change addresses are created from
		// account 0.
		var (
			changeAddr btcutil.Address
			err        error
		)
		if account == waddrmgr.ImportedAddrAccount {
			changeAddr, err = w.newChangeAddress(
				addrmgrNs, 0, *changeKeyScope,
			)
		} else {
			changeAddr, err = w.newChangeAddress(
				addrmgrNs, account, *changeKeyScope,
			)
		}
		if err != nil {
			return nil, err
		}
		return txscript.PayToAddrScript(changeAddr)
	}

	return addrmgrNs, &txauthor.ChangeSource{
		ScriptSize: scriptSize,
		NewScript:  newChangeScript,
	}, nil
}

// validateMsgTx verifies transaction input scripts for tx.  All previous output
// scripts from outputs redeemed by the transaction, in the same order they are
// spent, must be passed in the prevScripts slice.
func validateMsgTx(tx *wire.MsgTx, prevScripts [][]byte,
	inputValues []btcutil.Amount) error {

	inputFetcher, err := txauthor.TXPrevOutFetcher(
		tx, prevScripts, inputValues,
	)
	if err != nil {
		return err
	}

	hashCache := txscript.NewTxSigHashes(tx, inputFetcher)
	for i, prevScript := range prevScripts {
		vm, err := txscript.NewEngine(
			prevScript, tx, i, txscript.StandardVerifyFlags, nil,
			hashCache, int64(inputValues[i]), inputFetcher,
		)
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

// sortByAmount is a generic sortable type for sorting coins by their amount.
type sortByAmount []Coin

func (s sortByAmount) Len() int { return len(s) }
func (s sortByAmount) Less(i, j int) bool {
	return s[i].Value < s[j].Value
}
func (s sortByAmount) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// LargestFirstCoinSelector is an implementation of the CoinSelectionStrategy
// that always selects the largest coins first.
type LargestFirstCoinSelector struct{}

// ArrangeCoins takes a list of coins and arranges them according to the
// specified coin selection strategy and fee rate.
func (*LargestFirstCoinSelector) ArrangeCoins(eligible []Coin,
	_ btcutil.Amount) ([]Coin, error) {

	sort.Sort(sort.Reverse(sortByAmount(eligible)))

	return eligible, nil
}

// RandomCoinSelector is an implementation of the CoinSelectionStrategy that
// selects coins at random. This prevents the creation of ever smaller UTXOs
// over time that may never become economical to spend.
type RandomCoinSelector struct{}

// ArrangeCoins takes a list of coins and arranges them according to the
// specified coin selection strategy and fee rate.
func (*RandomCoinSelector) ArrangeCoins(eligible []Coin,
	feeSatPerKb btcutil.Amount) ([]Coin, error) {

	// Skip inputs that do not raise the total transaction output
	// value at the requested fee rate.
	positivelyYielding := make([]Coin, 0, len(eligible))
	for _, output := range eligible {
		output := output

		if !inputYieldsPositively(&output.TxOut, feeSatPerKb) {
			continue
		}

		positivelyYielding = append(positivelyYielding, output)
	}

	rand.Shuffle(len(positivelyYielding), func(i, j int) {
		positivelyYielding[i], positivelyYielding[j] =
			positivelyYielding[j], positivelyYielding[i]
	})

	return positivelyYielding, nil
}
