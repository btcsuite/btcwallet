// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet provides a bitcoin wallet that is capable of fulfilling all
// the duties of a typical bitcoin wallet such as creating and managing keys,
// creating and signing transactions, and customizing of transaction fees.
//
// TODO(yy): bring wrapcheck back when implementing the `Store` interface.
//
//nolint:wrapcheck,cyclop,gocognit
package wallet

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/walletdb/migration"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/davecgh/go-spew/spew"
)

const (
	// InsecurePubPassphrase is the default outer encryption passphrase used
	// for public data (everything but private keys).  Using a non-default
	// public passphrase can prevent an attacker without the public
	// passphrase from discovering all past and future wallet addresses if
	// they gain access to the wallet database.
	//
	// NOTE: at time of writing, public encryption only applies to public
	// data in the waddrmgr namespace.  Transactions are not yet encrypted.
	InsecurePubPassphrase = "public"

	// recoveryBatchSize is the default number of blocks that will be
	// scanned successively by the recovery manager, in the event that the
	// wallet is started in recovery mode.
	recoveryBatchSize = 2000

	// defaultSyncRetryInterval is the default amount of time to wait
	// between re-tries on errors during initial sync.
	defaultSyncRetryInterval = 5 * time.Second
)

var (
	// ErrWalletShuttingDown is an error returned when we attempt to make a
	// request to the wallet but it is in the process of or has already shut
	// down.
	ErrWalletShuttingDown = errors.New("wallet shutting down")

	// ErrUnknownTransaction is returned when an attempt is made to label
	// a transaction that is not known to the wallet.
	ErrUnknownTransaction = errors.New("cannot label transaction not " +
		"known to wallet")

	// ErrTxLabelExists is returned when a transaction already has a label
	// and an attempt has been made to label it without setting overwrite
	// to true.
	ErrTxLabelExists = errors.New("transaction already labelled")

	// ErrNoTx is returned when a transaction can not be found.
	ErrNoTx = errors.New("can not find transaction")

	// ErrTxUnsigned is returned when a transaction is created in the
	// watch-only mode where we can select coins but not sign any inputs.
	ErrTxUnsigned = errors.New("watch-only wallet, transaction not signed")

	// ErrNoAssocPrivateKey is returned when a private key is requested for
	// an address that has no associated private key.
	ErrNoAssocPrivateKey = errors.New("address does not have an " +
		"associated private key")

	// Namespace bucket keys.
	waddrmgrNamespaceKey = []byte("waddrmgr")
	wtxmgrNamespaceKey   = []byte("wtxmgr")
)

// Coin represents a spendable UTXO which is available for coin selection.
type Coin struct {
	wire.TxOut

	wire.OutPoint
}

// CoinSelectionStrategy is an interface that represents a coin selection
// strategy. A coin selection strategy is responsible for ordering, shuffling or
// filtering a list of coins before they are passed to the coin selection
// algorithm.
type CoinSelectionStrategy interface {
	// ArrangeCoins takes a list of coins and arranges them according to the
	// specified coin selection strategy and fee rate.
	ArrangeCoins(eligible []Coin, feeSatPerKb btcutil.Amount) ([]Coin,
		error)
}

var (
	// CoinSelectionLargest always picks the largest available utxo to add
	// to the transaction next.
	CoinSelectionLargest CoinSelectionStrategy = &LargestFirstCoinSelector{}

	// CoinSelectionRandom randomly selects the next utxo to add to the
	// transaction. This strategy prevents the creation of ever smaller
	// utxos over time.
	CoinSelectionRandom CoinSelectionStrategy = &RandomCoinSelector{}
)

// locateBirthdayBlock returns a block that meets the given birthday timestamp
// by a margin of +/-2 hours. This is safe to do as the timestamp is already 2
// days in the past of the actual timestamp.
func locateBirthdayBlock(chainClient chainConn,
	birthday time.Time) (*waddrmgr.BlockStamp, error) {

	// Retrieve the lookup range for our block.
	startHeight := int32(0)
	_, bestHeight, err := chainClient.GetBestBlock()
	if err != nil {
		return nil, err
	}

	log.Debugf("Locating suitable block for birthday %v between blocks "+
		"%v-%v", birthday, startHeight, bestHeight)

	var (
		birthdayBlock *waddrmgr.BlockStamp
		left, right   = startHeight, bestHeight
	)

	// Binary search for a block that meets the birthday timestamp by a
	// margin of +/-2 hours.
	for {
		// Retrieve the timestamp for the block halfway through our
		// range.
		mid := left + (right-left)/2
		hash, err := chainClient.GetBlockHash(int64(mid))
		if err != nil {
			return nil, err
		}
		header, err := chainClient.GetBlockHeader(hash)
		if err != nil {
			return nil, err
		}

		log.Debugf("Checking candidate block: height=%v, hash=%v, "+
			"timestamp=%v", mid, hash, header.Timestamp)

		// If the search happened to reach either of our range extremes,
		// then we'll just use that as there's nothing left to search.
		if mid == startHeight || mid == bestHeight || mid == left {
			birthdayBlock = &waddrmgr.BlockStamp{
				Hash:      *hash,
				Height:    mid,
				Timestamp: header.Timestamp,
			}
			break
		}

		// The block's timestamp is more than 2 hours after the
		// birthday, so look for a lower block.
		if header.Timestamp.Sub(birthday) > birthdayBlockDelta {
			right = mid
			continue
		}

		// The birthday is more than 2 hours before the block's
		// timestamp, so look for a higher block.
		if header.Timestamp.Sub(birthday) < -birthdayBlockDelta {
			left = mid
			continue
		}

		birthdayBlock = &waddrmgr.BlockStamp{
			Hash:      *hash,
			Height:    mid,
			Timestamp: header.Timestamp,
		}
		break
	}

	log.Debugf("Found birthday block: height=%d, hash=%v, timestamp=%v",
		birthdayBlock.Height, birthdayBlock.Hash,
		birthdayBlock.Timestamp)

	return birthdayBlock, nil
}

// Wallet is a structure containing all the components for a
// complete wallet.  It contains the Armory-style key store
// addresses and keys),
// Wallet is a structure containing all the components for a complete wallet.
// It manages the cryptographic keys, transaction history, and synchronization
// with the blockchain.
type Wallet struct {
	// walletDeprecated embeds the legacy state and channels. Access to
	// these should be phased out as refactoring progresses.
	*walletDeprecated

	// publicPassphrase is the passphrase used to encrypt and decrypt public
	// data in the address manager.
	publicPassphrase []byte

	// db is the underlying key-value database where all wallet data is
	// persisted.
	db walletdb.DB

	// addrStore is the address and key manager responsible for hierarchical
	// deterministic (HD) derivation and storage of cryptographic keys.
	addrStore waddrmgr.AddrStore

	// txStore is the transaction manager responsible for storing and
	// querying the wallet's transaction history and unspent outputs.
	txStore wtxmgr.TxStore

	// recoveryWindow specifies the number of additional keys to derive
	// beyond the last used one to look for previously used addresses
	// during a rescan or recovery.
	recoveryWindow uint32

	// NtfnServer handles the delivery of wallet-related events (e.g., new
	// transactions, block connections) to connected clients.
	NtfnServer *NotificationServer

	// wg is a wait group used to track and wait for all long-running
	// background goroutines to finish during a graceful shutdown.
	wg sync.WaitGroup
}

// AccountAddresses returns the addresses for every created address for an
// account.
func (w *Wallet) AccountAddresses(account uint32) (addrs []btcutil.Address, err error) {
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		return w.addrStore.ForEachAccountAddress(
			addrmgrNs, account,
			func(maddr waddrmgr.ManagedAddress) error {
				addrs = append(addrs, maddr.Address())
				return nil
			})
	})
	return
}

// AccountManagedAddresses returns the managed addresses for every created
// address for an account.
func (w *Wallet) AccountManagedAddresses(scope waddrmgr.KeyScope,
	accountNum uint32) ([]waddrmgr.ManagedAddress, error) {

	scopedMgr, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	addrs := make([]waddrmgr.ManagedAddress, 0)

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		return scopedMgr.ForEachAccountAddress(
			addrmgrNs, accountNum,
			func(a waddrmgr.ManagedAddress) error {
				addrs = append(addrs, a)

				return nil
			},
		)
	},
	)
	if err != nil {
		return nil, err
	}

	return addrs, nil
}

// CalculateBalance sums the amounts of all unspent transaction
// outputs to addresses of a wallet and returns the balance.
//
// If confirmations is 0, all UTXOs, even those not present in a
// block (height -1), will be used to get the balance.  Otherwise,
// a UTXO must be in a block.  If confirmations is 1 or greater,
// the balance will be calculated based on how many how many blocks
// include a UTXO.
func (w *Wallet) CalculateBalance(confirms int32) (btcutil.Amount, error) {
	var balance btcutil.Amount
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		var err error

		blk := w.addrStore.SyncedTo()
		balance, err = w.txStore.Balance(txmgrNs, confirms, blk.Height)

		return err
	})
	return balance, err
}

// Balances records total, spendable (by policy), and immature coinbase
// reward balance amounts.
type Balances struct {
	Total          btcutil.Amount
	Spendable      btcutil.Amount
	ImmatureReward btcutil.Amount
}

// CalculateAccountBalances sums the amounts of all unspent transaction
// outputs to the given account of a wallet and returns the balance.
//
// This function is much slower than it needs to be since transactions outputs
// are not indexed by the accounts they credit to, and all unspent transaction
// outputs must be iterated.
func (w *Wallet) CalculateAccountBalances(account uint32, confirms int32) (Balances, error) {
	var bals Balances
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// Get current block.  The block height used for calculating
		// the number of tx confirmations.
		syncBlock := w.addrStore.SyncedTo()

		unspent, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		for i := range unspent {
			output := &unspent[i]

			var outputAcct uint32
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				output.PkScript, w.chainParams)
			if err == nil && len(addrs) > 0 {
				_, outputAcct, err = w.addrStore.AddrAccount(
					addrmgrNs, addrs[0],
				)
			}
			if err != nil || outputAcct != account {
				continue
			}

			bals.Total += output.Amount
			if output.FromCoinBase && !hasMinConfs(
				uint32(w.chainParams.CoinbaseMaturity),
				output.Height, syncBlock.Height,
			) {

				bals.ImmatureReward += output.Amount
			} else if hasMinConfs(
				//nolint:gosec
				uint32(confirms), output.Height,
				syncBlock.Height,
			) {

				bals.Spendable += output.Amount
			}
		}
		return nil
	})
	return bals, err
}

// CurrentAddress gets the most recently requested Bitcoin payment address
// from a wallet for a particular key-chain scope.  If the address has already
// been used (there is at least one transaction spending to it in the
// blockchain or btcd mempool), the next chained address is returned.
func (w *Wallet) CurrentAddress(account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	// The address manager uses OnCommit on the walletdb tx to update the
	// in-memory state of the account state. But because the commit happens
	// _after_ the account manager internal lock has been released, there
	// is a chance for the address index to be accessed concurrently, even
	// though the closure in OnCommit re-acquires the lock. To avoid this
	// issue, we surround the whole address creation process with a lock.
	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var (
		addr  btcutil.Address
		props *waddrmgr.AccountProperties
	)
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		maddr, err := manager.LastExternalAddress(addrmgrNs, account)
		if err != nil {
			// If no address exists yet, create the first external
			// address.
			if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
				addr, props, err = w.newAddressDeprecated(
					addrmgrNs, account, scope,
				)
			}
			return err
		}

		// Get next chained address if the last one has already been
		// used.
		if maddr.Used(addrmgrNs) {
			addr, props, err = w.newAddressDeprecated(
				addrmgrNs, account, scope,
			)
			return err
		}

		addr = maddr.Address()
		return nil
	})
	if err != nil {
		return nil, err
	}

	// If the props have been initially, then we had to create a new address
	// to satisfy the query. Notify the rpc server about the new address.
	if props != nil {
		err = chainClient.NotifyReceived([]btcutil.Address{addr})
		if err != nil {
			return nil, err
		}

		w.NtfnServer.notifyAccountProperties(props)
	}

	return addr, nil
}

// PubKeyForAddress looks up the associated public key for a P2PKH address.
func (w *Wallet) PubKeyForAddress(a btcutil.Address) (*btcec.PublicKey, error) {
	var pubKey *btcec.PublicKey
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		managedAddr, err := w.addrStore.Address(addrmgrNs, a)
		if err != nil {
			return err
		}
		managedPubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return errors.New("address does not have an associated public key")
		}
		pubKey = managedPubKeyAddr.PubKey()
		return nil
	})
	return pubKey, err
}

// LabelTransaction adds a label to the transaction with the hash provided. The
// call will fail if the label is too long, or if the transaction already has
// a label and the overwrite boolean is not set.
func (w *Wallet) LabelTransaction(hash chainhash.Hash, label string,
	overwrite bool) error {

	// Check that the transaction is known to the wallet, and fail if it is
	// unknown. If the transaction is known, check whether it already has
	// a label.
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		dbTx, err := w.txStore.TxDetails(txmgrNs, &hash)
		if err != nil {
			return err
		}

		// If the transaction looked up is nil, it was not found. We
		// do not allow labelling of unknown transactions so we fail.
		if dbTx == nil {
			return ErrUnknownTransaction
		}

		_, err = w.txStore.FetchTxLabel(txmgrNs, hash)
		return err
	})

	switch err {
	// If no labels have been written yet, we can silence the error.
	// Likewise if there is no label, we do not need to do any overwrite
	// checks.
	case wtxmgr.ErrNoLabelBucket:
	case wtxmgr.ErrTxLabelNotFound:

	// If we successfully looked up a label, fail if the overwrite param
	// is not set.
	case nil:
		if !overwrite {
			return ErrTxLabelExists
		}

	// In another unrelated error occurred, return it.
	default:
		return err
	}

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		return w.txStore.PutTxLabel(txmgrNs, hash, label)
	})
}

// PrivKeyForAddress looks up the associated private key for a P2PKH or P2PK
// address.
func (w *Wallet) PrivKeyForAddress(a btcutil.Address) (*btcec.PrivateKey, error) {
	var privKey *btcec.PrivateKey
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		addr, err := w.addrStore.Address(addrmgrNs, a)
		if err != nil {
			return err
		}

		managedPubKeyAddr, ok := addr.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return ErrNoAssocPrivateKey
		}

		privKey, err = managedPubKeyAddr.PrivKey()
		return err
	})

	return privKey, err
}

// HaveAddress returns whether the wallet is the owner of the address a.
func (w *Wallet) HaveAddress(a btcutil.Address) (bool, error) {
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		_, err := w.addrStore.Address(addrmgrNs, a)
		return err
	})
	if err == nil {
		return true, nil
	}
	if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
		return false, nil
	}
	return false, err
}

// AccountOfAddress finds the account that an address is associated with.
func (w *Wallet) AccountOfAddress(a btcutil.Address) (uint32, error) {
	var account uint32
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error

		_, account, err = w.addrStore.AddrAccount(addrmgrNs, a)
		return err
	})
	return account, err
}

// AccountNumber returns the account number for an account name under a
// particular key scope.
func (w *Wallet) AccountNumber(scope waddrmgr.KeyScope, accountName string) (uint32, error) {
	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return 0, err
	}

	var account uint32
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error
		account, err = manager.LookupAccount(addrmgrNs, accountName)
		return err
	})
	return account, err
}

// AccountName returns the name of an account.
func (w *Wallet) AccountName(scope waddrmgr.KeyScope, accountNumber uint32) (string, error) {
	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return "", err
	}

	var accountName string
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error
		accountName, err = manager.AccountName(addrmgrNs, accountNumber)
		return err
	})
	return accountName, err
}

// AccountProperties returns the properties of an account, including address
// indexes and name. It first fetches the desynced information from the address
// manager, then updates the indexes based on the address pools.
func (w *Wallet) AccountProperties(scope waddrmgr.KeyScope, acct uint32) (*waddrmgr.AccountProperties, error) {
	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var props *waddrmgr.AccountProperties
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		waddrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error
		props, err = manager.AccountProperties(waddrmgrNs, acct)
		return err
	})
	return props, err
}

// AccountPropertiesByName returns the properties of an account by its name. It
// first fetches the desynced information from the address manager, then updates
// the indexes based on the address pools.
func (w *Wallet) AccountPropertiesByName(scope waddrmgr.KeyScope,
	name string) (*waddrmgr.AccountProperties, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var props *waddrmgr.AccountProperties
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		waddrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		acct, err := manager.LookupAccount(waddrmgrNs, name)
		if err != nil {
			return err
		}
		props, err = manager.AccountProperties(waddrmgrNs, acct)
		return err
	})
	return props, err
}

// LookupAccount returns the corresponding key scope and account number for the
// account with the given name.
func (w *Wallet) LookupAccount(name string) (waddrmgr.KeyScope, uint32, error) {
	var (
		keyScope waddrmgr.KeyScope
		account  uint32
	)
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error

		keyScope, account, err = w.addrStore.LookupAccount(ns, name)
		return err
	})

	return keyScope, account, err
}

// CreditCategory describes the type of wallet transaction output.  The category
// of "sent transactions" (debits) is always "send", and is not expressed by
// this type.
//
// TODO: This is a requirement of the RPC server and should be moved.
type CreditCategory byte

// These constants define the possible credit categories.
const (
	CreditReceive CreditCategory = iota
	CreditGenerate
	CreditImmature
)

// String returns the category as a string.  This string may be used as the
// JSON string for categories as part of listtransactions and gettransaction
// RPC responses.
func (c CreditCategory) String() string {
	switch c {
	case CreditReceive:
		return "receive"
	case CreditGenerate:
		return "generate"
	case CreditImmature:
		return "immature"
	default:
		return "unknown"
	}
}

// RecvCategory returns the category of received credit outputs from a
// transaction record.  The passed block chain height is used to distinguish
// immature from mature coinbase outputs.
//
// TODO: This is intended for use by the RPC server and should be moved out of
// this package at a later time.
func RecvCategory(details *wtxmgr.TxDetails, syncHeight int32, net *chaincfg.Params) CreditCategory {
	if blockchain.IsCoinBaseTx(&details.MsgTx) {
		if hasMinConfs(uint32(net.CoinbaseMaturity),
			details.Block.Height, syncHeight) {

			return CreditGenerate
		}
		return CreditImmature
	}
	return CreditReceive
}

// listTransactions creates a object that may be marshalled to a response result
// for a listtransactions RPC.
//
// TODO: This should be moved to the legacyrpc package.
func listTransactions(tx walletdb.ReadTx, details *wtxmgr.TxDetails,
	addrMgr waddrmgr.AddrStore, syncHeight int32,
	net *chaincfg.Params) []btcjson.ListTransactionsResult {

	addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

	var (
		blockHashStr  string
		blockTime     int64
		confirmations int64
	)
	if details.Block.Height != -1 {
		blockHashStr = details.Block.Hash.String()
		blockTime = details.Block.Time.Unix()
		confirmations = int64(
			calcConf(details.Block.Height, syncHeight),
		)
	}

	results := []btcjson.ListTransactionsResult{}
	txHashStr := details.Hash.String()
	received := details.Received.Unix()
	generated := blockchain.IsCoinBaseTx(&details.MsgTx)
	recvCat := RecvCategory(details, syncHeight, net).String()

	send := len(details.Debits) != 0

	// Fee can only be determined if every input is a debit.
	var feeF64 float64
	if len(details.Debits) == len(details.MsgTx.TxIn) {
		var debitTotal btcutil.Amount
		for _, deb := range details.Debits {
			debitTotal += deb.Amount
		}
		var outputTotal btcutil.Amount
		for _, output := range details.MsgTx.TxOut {
			outputTotal += btcutil.Amount(output.Value)
		}
		// Note: The actual fee is debitTotal - outputTotal.  However,
		// this RPC reports negative numbers for fees, so the inverse
		// is calculated.
		feeF64 = (outputTotal - debitTotal).ToBTC()
	}

outputs:
	for i, output := range details.MsgTx.TxOut {
		// Determine if this output is a credit, and if so, determine
		// its spentness.
		var isCredit bool
		var spentCredit bool
		for _, cred := range details.Credits {
			if cred.Index == uint32(i) {
				// Change outputs are ignored.
				if cred.Change {
					continue outputs
				}

				isCredit = true
				spentCredit = cred.Spent
				break
			}
		}

		var address string
		var accountName string
		_, addrs, _, _ := txscript.ExtractPkScriptAddrs(output.PkScript, net)
		if len(addrs) == 1 {
			addr := addrs[0]
			address = addr.EncodeAddress()
			mgr, account, err := addrMgr.AddrAccount(addrmgrNs, addrs[0])
			if err == nil {
				accountName, err = mgr.AccountName(addrmgrNs, account)
				if err != nil {
					accountName = ""
				}
			}
		}

		amountF64 := btcutil.Amount(output.Value).ToBTC()
		result := btcjson.ListTransactionsResult{
			// Fields left zeroed:
			//   InvolvesWatchOnly
			//   BlockIndex
			//
			// Fields set below:
			//   Account (only for non-"send" categories)
			//   Category
			//   Amount
			//   Fee
			Address:         address,
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

		// Add a received/generated/immature result if this is a credit.
		// If the output was spent, create a second result under the
		// send category with the inverse of the output amount.  It is
		// therefore possible that a single output may be included in
		// the results set zero, one, or two times.
		//
		// Since credits are not saved for outputs that are not
		// controlled by this wallet, all non-credits from transactions
		// with debits are grouped under the send category.

		if send || spentCredit {
			result.Category = "send"
			result.Amount = -amountF64
			result.Fee = &feeF64
			results = append(results, result)
		}
		if isCredit {
			result.Account = accountName
			result.Category = recvCat
			result.Amount = amountF64
			result.Fee = nil
			results = append(results, result)
		}
	}
	return results
}

// ListSinceBlock returns a slice of objects with details about transactions
// since the given block. If the block is -1 then all transactions are included.
// This is intended to be used for listsinceblock RPC replies.
func (w *Wallet) ListSinceBlock(start, end, syncHeight int32) ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			for _, detail := range details {
				detail := detail

				jsonResults := listTransactions(
					tx, &detail, w.addrStore, syncHeight,
					w.chainParams,
				)
				txList = append(txList, jsonResults...)
			}
			return false, nil
		}

		return w.txStore.RangeTransactions(txmgrNs, start, end, rangeFn)
	})
	return txList, err
}

// ListTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listtransactions RPC
// replies.
func (w *Wallet) ListTransactions(from, count int) ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}

	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// Get current block.  The block height used for calculating
		// the number of tx confirmations.
		syncBlock := w.addrStore.SyncedTo()

		// Need to skip the first from transactions, and after those, only
		// include the next count transactions.
		skipped := 0
		n := 0

		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			// Iterate over transactions at this height in reverse order.
			// This does nothing for unmined transactions, which are
			// unsorted, but it will process mined transactions in the
			// reverse order they were marked mined.
			for i := len(details) - 1; i >= 0; i-- {
				if from > skipped {
					skipped++
					continue
				}

				n++
				if n > count {
					return true, nil
				}

				jsonResults := listTransactions(
					tx, &details[i], w.addrStore,
					syncBlock.Height, w.chainParams,
				)
				txList = append(txList, jsonResults...)

				if len(jsonResults) > 0 {
					n++
				}
			}

			return false, nil
		}

		// Return newer results first by starting at mempool height and working
		// down to the genesis block.
		return w.txStore.RangeTransactions(txmgrNs, -1, 0, rangeFn)
	})
	return txList, err
}

// ListAddressTransactions returns a slice of objects with details about
// recorded transactions to or from any address belonging to a set.  This is
// intended to be used for listaddresstransactions RPC replies.
func (w *Wallet) ListAddressTransactions(pkHashes map[string]struct{}) ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// Get current block.  The block height used for calculating
		// the number of tx confirmations.
		syncBlock := w.addrStore.SyncedTo()
		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
		loopDetails:
			for i := range details {
				detail := &details[i]

				for _, cred := range detail.Credits {
					pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
					_, addrs, _, err := txscript.ExtractPkScriptAddrs(
						pkScript, w.chainParams)
					if err != nil || len(addrs) != 1 {
						continue
					}
					apkh, ok := addrs[0].(*btcutil.AddressPubKeyHash)
					if !ok {
						continue
					}
					_, ok = pkHashes[string(apkh.ScriptAddress())]
					if !ok {
						continue
					}

					jsonResults := listTransactions(
						tx, detail, w.addrStore,
						syncBlock.Height, w.chainParams,
					)
					txList = append(txList, jsonResults...)
					continue loopDetails
				}
			}
			return false, nil
		}

		return w.txStore.RangeTransactions(txmgrNs, 0, -1, rangeFn)
	})
	return txList, err
}

// ListAllTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listalltransactions RPC
// replies.
func (w *Wallet) ListAllTransactions() ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// Get current block.  The block height used for calculating
		// the number of tx confirmations.
		syncBlock := w.addrStore.SyncedTo()

		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			// Iterate over transactions at this height in reverse order.
			// This does nothing for unmined transactions, which are
			// unsorted, but it will process mined transactions in the
			// reverse order they were marked mined.
			for i := len(details) - 1; i >= 0; i-- {
				jsonResults := listTransactions(
					tx, &details[i], w.addrStore,
					syncBlock.Height, w.chainParams,
				)
				txList = append(txList, jsonResults...)
			}
			return false, nil
		}

		// Return newer results first by starting at mempool height and
		// working down to the genesis block.
		return w.txStore.RangeTransactions(txmgrNs, -1, 0, rangeFn)
	})
	return txList, err
}

// BlockIdentifier identifies a block by either a height or a hash.
type BlockIdentifier struct {
	height int32
	hash   *chainhash.Hash
}

// NewBlockIdentifierFromHeight constructs a BlockIdentifier for a block height.
func NewBlockIdentifierFromHeight(height int32) *BlockIdentifier {
	return &BlockIdentifier{height: height}
}

// NewBlockIdentifierFromHash constructs a BlockIdentifier for a block hash.
func NewBlockIdentifierFromHash(hash *chainhash.Hash) *BlockIdentifier {
	return &BlockIdentifier{hash: hash}
}

// GetTransactionsResult is the result of the wallet's GetTransactions method.
// See GetTransactions for more details.
type GetTransactionsResult struct {
	MinedTransactions   []Block
	UnminedTransactions []TransactionSummary
}

// GetTransactions returns transaction results between a starting and ending
// block.  Blocks in the block range may be specified by either a height or a
// hash.
//
// Because this is a possibly lenghtly operation, a cancel channel is provided
// to cancel the task.  If this channel unblocks, the results created thus far
// will be returned.
//
// Transaction results are organized by blocks in ascending order and unmined
// transactions in an unspecified order.  Mined transactions are saved in a
// Block structure which records properties about the block.
func (w *Wallet) GetTransactions(startBlock, endBlock *BlockIdentifier,
	accountName string, cancel <-chan struct{}) (*GetTransactionsResult, error) {

	var start, end int32 = 0, -1

	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()

	// TODO: Fetching block heights by their hashes is inherently racy
	// because not all block headers are saved but when they are for SPV the
	// db can be queried directly without this.
	if startBlock != nil {
		if startBlock.hash == nil {
			start = startBlock.height
		} else {
			if chainClient == nil {
				return nil, errors.New("no chain server client")
			}
			switch client := chainClient.(type) {
			case *chain.RPCClient:
				startHeader, err := client.GetBlockHeaderVerbose(
					startBlock.hash,
				)
				if err != nil {
					return nil, err
				}
				start = startHeader.Height
			case *chain.BitcoindClient:
				var err error
				start, err = client.GetBlockHeight(startBlock.hash)
				if err != nil {
					return nil, err
				}
			case *chain.NeutrinoClient:
				var err error
				start, err = client.GetBlockHeight(startBlock.hash)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	if endBlock != nil {
		if endBlock.hash == nil {
			end = endBlock.height
		} else {
			if chainClient == nil {
				return nil, errors.New("no chain server client")
			}
			switch client := chainClient.(type) {
			case *chain.RPCClient:
				endHeader, err := client.GetBlockHeaderVerbose(
					endBlock.hash,
				)
				if err != nil {
					return nil, err
				}
				end = endHeader.Height
			case *chain.BitcoindClient:
				var err error
				start, err = client.GetBlockHeight(endBlock.hash)
				if err != nil {
					return nil, err
				}
			case *chain.NeutrinoClient:
				var err error
				end, err = client.GetBlockHeight(endBlock.hash)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	var res GetTransactionsResult
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			// TODO: probably should make RangeTransactions not reuse the
			// details backing array memory.
			dets := make([]wtxmgr.TxDetails, len(details))
			copy(dets, details)
			details = dets

			txs := make([]TransactionSummary, 0, len(details))
			for i := range details {
				txs = append(txs, makeTxSummary(dbtx, w, &details[i]))
			}

			if details[0].Block.Height != -1 {
				blockHash := details[0].Block.Hash
				res.MinedTransactions = append(res.MinedTransactions, Block{
					Hash:         &blockHash,
					Height:       details[0].Block.Height,
					Timestamp:    details[0].Block.Time.Unix(),
					Transactions: txs,
				})
			} else {
				res.UnminedTransactions = txs
			}

			select {
			case <-cancel:
				return true, nil
			default:
				return false, nil
			}
		}

		return w.txStore.RangeTransactions(txmgrNs, start, end, rangeFn)
	})
	return &res, err
}

// GetTransactionResult returns a summary of the transaction along with
// other block properties.
type GetTransactionResult struct {
	Summary       TransactionSummary
	Height        int32
	BlockHash     *chainhash.Hash
	Confirmations int32
	Timestamp     int64
}

// GetTransaction returns detailed data of a transaction given its id. In
// addition it returns properties about its block.
func (w *Wallet) GetTransaction(txHash chainhash.Hash) (*GetTransactionResult,
	error) {

	var res GetTransactionResult
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		txDetail, err := w.txStore.TxDetails(txmgrNs, &txHash)
		if err != nil {
			return err
		}

		// If the transaction was not found we return an error.
		if txDetail == nil {
			return fmt.Errorf("%w: txid %v", ErrNoTx, txHash)
		}

		res = GetTransactionResult{
			Summary:       makeTxSummary(dbtx, w, txDetail),
			BlockHash:     nil,
			Height:        -1,
			Confirmations: 0,
			Timestamp:     0,
		}

		// If it is a confirmed transaction we set the corresponding
		// block height, timestamp, hash, and confirmations.
		if txDetail.Block.Height != -1 {
			res.Height = txDetail.Block.Height
			res.Timestamp = txDetail.Block.Time.Unix()
			res.BlockHash = &txDetail.Block.Hash

			bestBlock := w.SyncedTo()
			blockHeight := txDetail.Block.Height
			res.Confirmations = calcConf(
				blockHeight, bestBlock.Height,
			)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// AccountBalanceResult is a single result for the Wallet.AccountBalances method.
type AccountBalanceResult struct {
	AccountNumber  uint32
	AccountName    string
	AccountBalance btcutil.Amount
}

// AccountBalances returns all accounts in the wallet and their balances.
// Balances are determined by excluding transactions that have not met
// requiredConfs confirmations.
func (w *Wallet) AccountBalances(scope waddrmgr.KeyScope,
	requiredConfs int32) ([]AccountBalanceResult, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var results []AccountBalanceResult
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.addrStore.SyncedTo()

		// Fill out all account info except for the balances.
		lastAcct, err := manager.LastAccount(addrmgrNs)
		if err != nil {
			return err
		}
		results = make([]AccountBalanceResult, lastAcct+2)
		for i := range results[:len(results)-1] {
			accountName, err := manager.AccountName(addrmgrNs, uint32(i))
			if err != nil {
				return err
			}
			results[i].AccountNumber = uint32(i)
			results[i].AccountName = accountName
		}
		results[len(results)-1].AccountNumber = waddrmgr.ImportedAddrAccount
		results[len(results)-1].AccountName = waddrmgr.ImportedAddrAccountName

		// Fetch all unspent outputs, and iterate over them tallying each
		// account's balance where the output script pays to an account address
		// and the required number of confirmations is met.
		unspentOutputs, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		for i := range unspentOutputs {
			output := &unspentOutputs[i]
			if !hasMinConfs(
				//nolint:gosec
				uint32(requiredConfs), output.Height,
				syncBlock.Height,
			) {

				continue
			}

			if output.FromCoinBase && !hasMinConfs(
				uint32(w.ChainParams().CoinbaseMaturity),
				output.Height, syncBlock.Height,
			) {

				continue
			}
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript, w.chainParams)
			if err != nil || len(addrs) == 0 {
				continue
			}
			outputAcct, err := manager.AddrAccount(addrmgrNs, addrs[0])
			if err != nil {
				continue
			}
			switch {
			case outputAcct == waddrmgr.ImportedAddrAccount:
				results[len(results)-1].AccountBalance += output.Amount
			case outputAcct > lastAcct:
				return errors.New("waddrmgr.Manager.AddrAccount returned account " +
					"beyond recorded last account")
			default:
				results[outputAcct].AccountBalance += output.Amount
			}
		}
		return nil
	})
	return results, err
}

// creditSlice satisifies the sort.Interface interface to provide sorting
// transaction credits from oldest to newest.  Credits with the same receive
// time and mined in the same block are not guaranteed to be sorted by the order
// they appear in the block.  Credits from the same transaction are sorted by
// output index.
type creditSlice []wtxmgr.Credit

func (s creditSlice) Len() int {
	return len(s)
}

func (s creditSlice) Less(i, j int) bool {
	switch {
	// If both credits are from the same tx, sort by output index.
	case s[i].OutPoint.Hash == s[j].OutPoint.Hash:
		return s[i].OutPoint.Index < s[j].OutPoint.Index

	// If both transactions are unmined, sort by their received date.
	case s[i].Height == -1 && s[j].Height == -1:
		return s[i].Received.Before(s[j].Received)

	// Unmined (newer) txs always come last.
	case s[i].Height == -1:
		return false
	case s[j].Height == -1:
		return true

	// If both txs are mined in different blocks, sort by block height.
	default:
		return s[i].Height < s[j].Height
	}
}

func (s creditSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// ListUnspentDeprecated returns a slice of objects representing the
// unspent wallet transactions fitting the given criteria. The confirmations
// will be more than
// minconf, less than maxconf and if addresses is populated only the addresses
// contained within it will be considered.  If we know nothing about a
// transaction an empty array will be returned.
//
// Deprecated: Use UtxoManager.ListUnspent instead.
//
//nolint:funlen
func (w *Wallet) ListUnspentDeprecated(minconf, maxconf int32,
	accountName string) ([]*btcjson.ListUnspentResult, error) {

	var results []*btcjson.ListUnspentResult
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.addrStore.SyncedTo()

		filter := accountName != ""

		unspent, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		sort.Sort(sort.Reverse(creditSlice(unspent)))

		defaultAccountName := "default"

		results = make([]*btcjson.ListUnspentResult, 0, len(unspent))
		for i := range unspent {
			output := unspent[i]

			// Outputs with fewer confirmations than the minimum or
			// more confs than the maximum are excluded.
			confs := calcConf(output.Height, syncBlock.Height)
			if confs < minconf || confs > maxconf {
				continue
			}

			// Only mature coinbase outputs are included.
			if output.FromCoinBase {
				target := uint32(
					w.ChainParams().CoinbaseMaturity,
				)
				if !hasMinConfs(
					target, output.Height, syncBlock.Height,
				) {

					continue
				}
			}

			// Exclude locked outputs from the result set.
			if w.LockedOutpoint(output.OutPoint) {
				continue
			}

			// Lookup the associated account for the output.  Use the
			// default account name in case there is no associated account
			// for some reason, although this should never happen.
			//
			// This will be unnecessary once transactions and outputs are
			// grouped under the associated account in the db.
			outputAcctName := defaultAccountName
			sc, addrs, _, err := txscript.ExtractPkScriptAddrs(
				output.PkScript, w.chainParams)
			if err != nil {
				continue
			}
			if len(addrs) > 0 {
				smgr, acct, err := w.addrStore.AddrAccount(
					addrmgrNs, addrs[0],
				)
				if err == nil {
					s, err := smgr.AccountName(addrmgrNs, acct)
					if err == nil {
						outputAcctName = s
					}
				}
			}

			if filter && outputAcctName != accountName {
				continue
			}

			// At the moment watch-only addresses are not supported, so all
			// recorded outputs that are not multisig are "spendable".
			// Multisig outputs are only "spendable" if all keys are
			// controlled by this wallet.
			//
			// TODO: Each case will need updates when watch-only addrs
			// is added.  For P2PK, P2PKH, and P2SH, the address must be
			// looked up and not be watching-only.  For multisig, all
			// pubkeys must belong to the manager with the associated
			// private key (currently it only checks whether the pubkey
			// exists, since the private key is required at the moment).
			var spendable bool
		scSwitch:
			switch sc {
			case txscript.PubKeyHashTy:
				spendable = true
			case txscript.PubKeyTy:
				spendable = true
			case txscript.WitnessV0ScriptHashTy:
				spendable = true
			case txscript.WitnessV0PubKeyHashTy:
				spendable = true
			case txscript.MultiSigTy:
				for _, a := range addrs {
					_, err := w.addrStore.Address(
						addrmgrNs, a,
					)
					if err == nil {
						continue
					}
					if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
						break scSwitch
					}
					return err
				}
				spendable = true
			}

			result := &btcjson.ListUnspentResult{
				TxID:          output.OutPoint.Hash.String(),
				Vout:          output.OutPoint.Index,
				Account:       outputAcctName,
				ScriptPubKey:  hex.EncodeToString(output.PkScript),
				Amount:        output.Amount.ToBTC(),
				Confirmations: int64(confs),
				Spendable:     spendable,
			}

			// BUG: this should be a JSON array so that all
			// addresses can be included, or removed (and the
			// caller extracts addresses from the pkScript).
			if len(addrs) > 0 {
				result.Address = addrs[0].EncodeAddress()
			}

			results = append(results, result)
		}
		return nil
	})
	return results, err
}

// ListLeasedOutputResult is a single result for the Wallet.ListLeasedOutputs method.
// See that method for more details.
type ListLeasedOutputResult struct {
	*wtxmgr.LockedOutput
	Value    int64
	PkScript []byte
}

// ListLeasedOutputsDeprecated returns a list of objects representing the
// currently locked utxos.
//
// Deprecated: Use UtxoManager.ListLeasedOutputs instead.
func (w *Wallet) ListLeasedOutputsDeprecated() (
	[]*ListLeasedOutputResult, error) {

	var results []*ListLeasedOutputResult
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)

		outputs, err := w.txStore.ListLockedOutputs(ns)
		if err != nil {
			return err
		}

		for _, output := range outputs {
			details, err := w.txStore.TxDetails(
				ns, &output.Outpoint.Hash,
			)
			if err != nil {
				return err
			}

			if details == nil {
				log.Infof("unable to find tx details for "+
					"%v:%v", output.Outpoint.Hash,
					output.Outpoint.Index)
				continue
			}

			txOut := details.MsgTx.TxOut[output.Outpoint.Index]

			result := &ListLeasedOutputResult{
				LockedOutput: output,
				Value:        txOut.Value,
				PkScript:     txOut.PkScript,
			}

			results = append(results, result)
		}

		return nil
	})
	return results, err
}

// DumpPrivKeys returns the WIF-encoded private keys for all addresses with
// private keys in a wallet.
func (w *Wallet) DumpPrivKeys() ([]string, error) {
	var privkeys []string
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		// Iterate over each active address, appending the private key to
		return w.addrStore.ForEachActiveAddress(
			addrmgrNs, func(addr btcutil.Address) error {
				ma, err := w.addrStore.Address(addrmgrNs, addr)
				if err != nil {
					return err
				}

				// Only those addresses with keys needed.
				pka, ok := ma.(waddrmgr.ManagedPubKeyAddress)
				if !ok {
					return nil
				}

				wif, err := pka.ExportPrivKey()
				if err != nil {
					// It would be nice to zero out the
					// array here. However, since strings
					// in go are immutable, and we have no
					// control over the caller I don't
					// think we can. :(
					return err
				}

				privkeys = append(privkeys, wif.String())

				return nil
			})
	})
	return privkeys, err
}

// DumpWIFPrivateKey returns the WIF encoded private key for a
// single wallet address.
func (w *Wallet) DumpWIFPrivateKey(addr btcutil.Address) (string, error) {
	var maddr waddrmgr.ManagedAddress
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		waddrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		// Get private key from wallet if it exists.
		var err error

		maddr, err = w.addrStore.Address(waddrmgrNs, addr)
		return err
	})
	if err != nil {
		return "", err
	}

	pka, ok := maddr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return "", fmt.Errorf("address %s is not a key type", addr)
	}

	wif, err := pka.ExportPrivKey()
	if err != nil {
		return "", err
	}
	return wif.String(), nil
}

// LockedOutpoint returns whether an outpoint has been marked as locked and
// should not be used as an input for created transactions.
func (w *Wallet) LockedOutpoint(op wire.OutPoint) bool {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	_, locked := w.lockedOutpoints[op]
	return locked
}

// LockOutpoint marks an outpoint as locked, that is, it should not be used as
// an input for newly created transactions.
func (w *Wallet) LockOutpoint(op wire.OutPoint) {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	w.lockedOutpoints[op] = struct{}{}
}

// UnlockOutpoint marks an outpoint as unlocked, that is, it may be used as an
// input for newly created transactions.
func (w *Wallet) UnlockOutpoint(op wire.OutPoint) {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	delete(w.lockedOutpoints, op)
}

// ResetLockedOutpoints resets the set of locked outpoints so all may be used
// as inputs for new transactions.
func (w *Wallet) ResetLockedOutpoints() {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	w.lockedOutpoints = map[wire.OutPoint]struct{}{}
}

// LockedOutpoints returns a slice of currently locked outpoints.  This is
// intended to be used by marshaling the result as a JSON array for
// listlockunspent RPC results.
func (w *Wallet) LockedOutpoints() []btcjson.TransactionInput {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	locked := make([]btcjson.TransactionInput, len(w.lockedOutpoints))
	i := 0
	for op := range w.lockedOutpoints {
		locked[i] = btcjson.TransactionInput{
			Txid: op.Hash.String(),
			Vout: op.Index,
		}
		i++
	}
	return locked
}

// LeaseOutputDeprecated locks an output to the given ID, preventing it from
// being available for coin selection. The absolute time of the lock's
// expiration is
// returned. The expiration of the lock can be extended by successive
// invocations of this call.
//
// Outputs can be unlocked before their expiration through `UnlockOutput`.
// Otherwise, they are unlocked lazily through calls which iterate through all
// known outputs, e.g., `CalculateBalance`, `ListUnspent`.
//
// If the output is not known, ErrUnknownOutput is returned. If the output has
// already been locked to a different ID, then ErrOutputAlreadyLocked is
// returned.
//
// NOTE: This differs from LockOutpoint in that outputs are locked for a limited
// amount of time and their locks are persisted to disk.
//
// Deprecated: Use UtxoManager.LeaseOutput instead.
func (w *Wallet) LeaseOutputDeprecated(id wtxmgr.LockID, op wire.OutPoint,
	duration time.Duration) (time.Time, error) {

	var expiry time.Time
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		var err error

		expiry, err = w.txStore.LockOutput(ns, id, op, duration)
		return err
	})
	return expiry, err
}

// ReleaseOutputDeprecated unlocks an output, allowing it to be available for
// coin selection if it remains unspent. The ID should match the one used to
// originally lock the output.
//
// Deprecated: Use UtxoManager.ReleaseOutput instead.
func (w *Wallet) ReleaseOutputDeprecated(
	id wtxmgr.LockID, op wire.OutPoint) error {

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		return w.txStore.UnlockOutput(ns, id, op)
	})
}

// resendUnminedTxs iterates through all transactions that spend from wallet
// credits that are not known to have been mined into a block, and attempts
// to send each to the chain server for relay.
func (w *Wallet) resendUnminedTxs() {
	var txs []*wire.MsgTx
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		var err error

		txs, err = w.txStore.UnminedTxs(txmgrNs)
		return err
	})
	if err != nil {
		log.Errorf("Unable to retrieve unconfirmed transactions to "+
			"resend: %v", err)
		return
	}

	for _, tx := range txs {
		txHash, err := w.publishTransaction(tx)
		if err != nil {
			log.Debugf("Unable to rebroadcast transaction %v: %v",
				tx.TxHash(), err)
			continue
		}

		log.Debugf("Successfully rebroadcast unconfirmed transaction %v",
			txHash)
	}
}

// SortedActivePaymentAddresses returns a slice of all active payment
// addresses in a wallet.
func (w *Wallet) SortedActivePaymentAddresses() ([]string, error) {
	var addrStrs []string
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		return w.addrStore.ForEachActiveAddress(
			addrmgrNs, func(addr btcutil.Address) error {
				addrStrs = append(
					addrStrs, addr.EncodeAddress(),
				)

				return nil
			})
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(addrStrs)
	return addrStrs, nil
}

// NewAddressDeprecated returns the next external chained address for a wallet.
func (w *Wallet) NewAddressDeprecated(account uint32,
	scope waddrmgr.KeyScope) (btcutil.Address, error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// The address manager uses OnCommit on the walletdb tx to update the
	// in-memory state of the account state. But because the commit happens
	// _after_ the account manager internal lock has been released, there
	// is a chance for the address index to be accessed concurrently, even
	// though the closure in OnCommit re-acquires the lock. To avoid this
	// issue, we surround the whole address creation process with a lock.
	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var (
		addr  btcutil.Address
		props *waddrmgr.AccountProperties
	)
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		var err error

		addr, props, err = w.newAddressDeprecated(
			addrmgrNs, account, scope,
		)
		return err
	})
	if err != nil {
		return nil, err
	}

	// Notify the rpc server about the newly created address.
	err = chainClient.NotifyReceived([]btcutil.Address{addr})
	if err != nil {
		return nil, err
	}

	w.NtfnServer.notifyAccountProperties(props)

	return addr, nil
}

// NewChangeAddress returns a new change address for a wallet.
func (w *Wallet) NewChangeAddress(account uint32,
	scope waddrmgr.KeyScope) (btcutil.Address, error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// The address manager uses OnCommit on the walletdb tx to update the
	// in-memory state of the account state. But because the commit happens
	// _after_ the account manager internal lock has been released, there
	// is a chance for the address index to be accessed concurrently, even
	// though the closure in OnCommit re-acquires the lock. To avoid this
	// issue, we surround the whole address creation process with a lock.
	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var addr btcutil.Address
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		var err error
		addr, err = w.newChangeAddress(addrmgrNs, account, scope)
		return err
	})
	if err != nil {
		return nil, err
	}

	// Notify the rpc server about the newly created address.
	err = chainClient.NotifyReceived([]btcutil.Address{addr})
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// newChangeAddress returns a new change address for the wallet.
//
// NOTE: This method requires the caller to use the backend's NotifyReceived
// method in order to detect when an on-chain transaction pays to the address
// being created.
func (w *Wallet) newChangeAddress(addrmgrNs walletdb.ReadWriteBucket,
	account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	// Get next chained change address from wallet for account.
	addrs, err := manager.NextInternalAddresses(addrmgrNs, account, 1)
	if err != nil {
		return nil, err
	}

	return addrs[0].Address(), nil
}

// hasMinConfs checks whether a transaction at height txHeight has met minconf
// confirmations for a blockchain at height curHeight.
func hasMinConfs(minconf uint32, txHeight, curHeight int32) bool {
	confs := calcConf(txHeight, curHeight)
	if confs < 0 {
		return false
	}

	return uint32(confs) >= minconf
}

// calcConf returns the number of confirmations for a transaction given its
// containing block height and the current best block height. Unconfirmed
// transactions have a height of -1 and are considered to have 0 confirmations.
func calcConf(txHeight, curHeight int32) int32 {
	switch {
	// Unconfirmed transactions have 0 confirmations.
	case txHeight == -1:
		return 0

	// A transaction in a block after the current best block is considered
	// unconfirmed. This can happen during a chain reorg.
	case txHeight > curHeight:
		return 0

	// Confirmed transactions have at least one confirmation.
	default:
		return curHeight - txHeight + 1
	}
}

// AccountTotalReceivedResult is a single result for the
// Wallet.TotalReceivedForAccounts method.
type AccountTotalReceivedResult struct {
	AccountNumber    uint32
	AccountName      string
	TotalReceived    btcutil.Amount
	LastConfirmation int32
}

// TotalReceivedForAccounts iterates through a wallet's transaction history,
// returning the total amount of Bitcoin received for all accounts.
func (w *Wallet) TotalReceivedForAccounts(scope waddrmgr.KeyScope,
	minConf int32) ([]AccountTotalReceivedResult, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var results []AccountTotalReceivedResult
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.addrStore.SyncedTo()

		err := manager.ForEachAccount(addrmgrNs, func(account uint32) error {
			accountName, err := manager.AccountName(addrmgrNs, account)
			if err != nil {
				return err
			}
			results = append(results, AccountTotalReceivedResult{
				AccountNumber: account,
				AccountName:   accountName,
			})
			return nil
		})
		if err != nil {
			return err
		}

		var stopHeight int32

		if minConf > 0 {
			stopHeight = syncBlock.Height - minConf + 1
		} else {
			stopHeight = -1
		}

		//nolint:lll
		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			for i := range details {
				detail := &details[i]
				for _, cred := range detail.Credits {
					pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
					var outputAcct uint32
					_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, w.chainParams)
					if err == nil && len(addrs) > 0 {
						_, outputAcct, err = w.addrStore.AddrAccount(addrmgrNs, addrs[0])
					}
					if err == nil {
						acctIndex := int(outputAcct)
						if outputAcct == waddrmgr.ImportedAddrAccount {
							acctIndex = len(results) - 1
						}
						res := &results[acctIndex]
						res.TotalReceived += cred.Amount

						confs := calcConf(
							detail.Block.Height,
							syncBlock.Height,
						)
						res.LastConfirmation = confs
					}
				}
			}
			return false, nil
		}

		return w.txStore.RangeTransactions(
			txmgrNs, 0, stopHeight, rangeFn,
		)
	})
	return results, err
}

// TotalReceivedForAddr iterates through a wallet's transaction history,
// returning the total amount of bitcoins received for a single wallet
// address.
func (w *Wallet) TotalReceivedForAddr(addr btcutil.Address, minConf int32) (btcutil.Amount, error) {
	var amount btcutil.Amount
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.addrStore.SyncedTo()

		var (
			addrStr    = addr.EncodeAddress()
			stopHeight int32
		)

		if minConf > 0 {
			stopHeight = syncBlock.Height - minConf + 1
		} else {
			stopHeight = -1
		}
		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			for i := range details {
				detail := &details[i]
				for _, cred := range detail.Credits {
					pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
					_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
						w.chainParams)
					// An error creating addresses from the output script only
					// indicates a non-standard script, so ignore this credit.
					if err != nil {
						continue
					}
					for _, a := range addrs {
						if addrStr == a.EncodeAddress() {
							amount += cred.Amount
							break
						}
					}
				}
			}
			return false, nil
		}

		return w.txStore.RangeTransactions(
			txmgrNs, 0, stopHeight, rangeFn,
		)
	})
	return amount, err
}

// SendOutputs creates and sends payment transactions. Coin selection is
// performed by the wallet, choosing inputs that belong to the given key scope
// and account, unless a key scope is not specified. In that case, inputs from
// accounts matching the account number provided across all key scopes may be
// selected. This is done to handle the default account case, where a user wants
// to fund a PSBT with inputs regardless of their type (NP2WKH, P2WKH, etc.). It
// returns the transaction upon success.
func (w *Wallet) SendOutputs(outputs []*wire.TxOut, keyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, satPerKb btcutil.Amount,
	coinSelectionStrategy CoinSelectionStrategy, label string) (*wire.MsgTx,
	error) {

	return w.sendOutputs(
		outputs, keyScope, account, minconf, satPerKb,
		coinSelectionStrategy, label,
	)
}

// SendOutputsWithInput creates and sends payment transactions using the
// provided selected utxos. It returns the transaction upon success.
func (w *Wallet) SendOutputsWithInput(outputs []*wire.TxOut,
	keyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, satPerKb btcutil.Amount,
	coinSelectionStrategy CoinSelectionStrategy, label string,
	selectedUtxos []wire.OutPoint) (*wire.MsgTx, error) {

	return w.sendOutputs(outputs, keyScope, account, minconf, satPerKb,
		coinSelectionStrategy, label, selectedUtxos...)
}

// sendOutputs creates and sends payment transactions. It returns the
// transaction upon success.
func (w *Wallet) sendOutputs(outputs []*wire.TxOut, keyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, satPerKb btcutil.Amount,
	coinSelectionStrategy CoinSelectionStrategy, label string,
	selectedUtxos ...wire.OutPoint) (*wire.MsgTx, error) {

	// Ensure the outputs to be created adhere to the network's consensus
	// rules.
	for _, output := range outputs {
		err := txrules.CheckOutput(
			output, txrules.DefaultRelayFeePerKb,
		)
		if err != nil {
			return nil, err
		}
	}

	// Create the transaction and broadcast it to the network. The
	// transaction will be added to the database in order to ensure that we
	// continue to re-broadcast the transaction upon restarts until it has
	// been confirmed.
	createdTx, err := w.CreateSimpleTx(
		keyScope, account, outputs, minconf, satPerKb,
		coinSelectionStrategy, false, WithCustomSelectUtxos(
			selectedUtxos,
		),
	)
	if err != nil {
		return nil, err
	}

	// If our wallet is read-only, we'll get a transaction with coins
	// selected but no witness data. In such a case we need to inform our
	// caller that they'll actually need to go ahead and sign the TX.
	if w.addrStore.WatchOnly() {
		return createdTx.Tx, ErrTxUnsigned
	}

	txHash, err := w.reliablyPublishTransaction(createdTx.Tx, label)
	if err != nil {
		return nil, err
	}

	// Sanity check on the returned tx hash.
	if *txHash != createdTx.Tx.TxHash() {
		return nil, errors.New("tx hash mismatch")
	}

	return createdTx.Tx, nil
}

// SignatureError records the underlying error when validating a transaction
// input signature.
type SignatureError struct {
	InputIndex uint32
	Error      error
}

// SignTransaction uses secrets of the wallet, as well as additional secrets
// passed in by the caller, to create and add input signatures to a transaction.
//
// Transaction input script validation is used to confirm that all signatures
// are valid.  For any invalid input, a SignatureError is added to the returns.
// The final error return is reserved for unexpected or fatal errors, such as
// being unable to determine a previous output script to redeem.
//
// The transaction pointed to by tx is modified by this function.
func (w *Wallet) SignTransaction(tx *wire.MsgTx, hashType txscript.SigHashType,
	additionalPrevScripts map[wire.OutPoint][]byte,
	additionalKeysByAddress map[string]*btcutil.WIF,
	p2shRedeemScriptsByAddress map[string][]byte) ([]SignatureError, error) {

	var signErrors []SignatureError
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		inputFetcher := txscript.NewMultiPrevOutFetcher(nil)
		for i, txIn := range tx.TxIn {
			prevOutScript, ok := additionalPrevScripts[txIn.PreviousOutPoint]
			if !ok {
				prevHash := &txIn.PreviousOutPoint.Hash
				prevIndex := txIn.PreviousOutPoint.Index

				txDetails, err := w.txStore.TxDetails(
					txmgrNs, prevHash,
				)
				if err != nil {
					return fmt.Errorf("cannot query previous transaction "+
						"details for %v: %w", txIn.PreviousOutPoint, err)
				}
				if txDetails == nil {
					return fmt.Errorf("%v not found",
						txIn.PreviousOutPoint)
				}
				prevOutScript = txDetails.MsgTx.TxOut[prevIndex].PkScript
			}
			inputFetcher.AddPrevOut(txIn.PreviousOutPoint, &wire.TxOut{
				PkScript: prevOutScript,
			})

			// Set up our callbacks that we pass to txscript so it can
			// look up the appropriate keys and scripts by address.
			//
			//nolint:lll
			getKey := txscript.KeyClosure(func(addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
				if len(additionalKeysByAddress) != 0 {
					addrStr := addr.EncodeAddress()
					wif, ok := additionalKeysByAddress[addrStr]
					if !ok {
						return nil, false,
							errors.New("no key for address")
					}
					return wif.PrivKey, wif.CompressPubKey, nil
				}

				address, err := w.addrStore.Address(addrmgrNs, addr)
				if err != nil {
					return nil, false, err
				}

				pka, ok := address.(waddrmgr.ManagedPubKeyAddress)
				if !ok {
					return nil, false, fmt.Errorf("address %v is not "+
						"a pubkey address", address.Address().EncodeAddress())
				}

				key, err := pka.PrivKey()
				if err != nil {
					return nil, false, err
				}

				return key, pka.Compressed(), nil
			})
			//nolint:lll
			getScript := txscript.ScriptClosure(func(addr btcutil.Address) ([]byte, error) {
				// If keys were provided then we can only use the
				// redeem scripts provided with our inputs, too.
				if len(additionalKeysByAddress) != 0 {
					addrStr := addr.EncodeAddress()
					script, ok := p2shRedeemScriptsByAddress[addrStr]
					if !ok {
						return nil, errors.New("no script for address")
					}
					return script, nil
				}

				address, err := w.addrStore.Address(addrmgrNs, addr)
				if err != nil {
					return nil, err
				}
				sa, ok := address.(waddrmgr.ManagedScriptAddress)
				if !ok {
					return nil, errors.New("address is not a script" +
						" address")
				}

				return sa.Script()
			})

			// SigHashSingle inputs can only be signed if there's a
			// corresponding output. However this could be already signed,
			// so we always verify the output.
			if (hashType&txscript.SigHashSingle) !=
				txscript.SigHashSingle || i < len(tx.TxOut) {

				script, err := txscript.SignTxOutput(w.ChainParams(),
					tx, i, prevOutScript, hashType, getKey,
					getScript, txIn.SignatureScript)
				// Failure to sign isn't an error, it just means that
				// the tx isn't complete.
				if err != nil {
					signErrors = append(signErrors, SignatureError{
						InputIndex: uint32(i),
						Error:      err,
					})
					continue
				}
				txIn.SignatureScript = script
			}

			// Either it was already signed or we just signed it.
			// Find out if it is completely satisfied or still needs more.
			vm, err := txscript.NewEngine(
				prevOutScript, tx, i,
				txscript.StandardVerifyFlags, nil, nil, 0,
				inputFetcher,
			)
			if err == nil {
				err = vm.Execute()
			}
			if err != nil {
				signErrors = append(signErrors, SignatureError{
					InputIndex: uint32(i),
					Error:      err,
				})
			}
		}
		return nil
	})
	return signErrors, err
}

// ErrDoubleSpend is an error returned from PublishTransaction in case the
// published transaction failed to propagate since it was double spending a
// confirmed transaction or a transaction in the mempool.
type ErrDoubleSpend struct {
	backendError error
}

// Error returns the string representation of ErrDoubleSpend.
//
// NOTE: Satisfies the error interface.
func (e *ErrDoubleSpend) Error() string {
	return fmt.Sprintf("double spend: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrDoubleSpend) Unwrap() error {
	return e.backendError
}

// ErrMempoolFee is an error returned from PublishTransaction in case the
// published transaction failed to propagate since it did not match the
// current mempool fee requirement.
type ErrMempoolFee struct {
	backendError error
}

// Error returns the string representation of ErrMempoolFee.
//
// NOTE: Satisfies the error interface.
func (e *ErrMempoolFee) Error() string {
	return fmt.Sprintf("mempool fee not met: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrMempoolFee) Unwrap() error {
	return e.backendError
}

// ErrAlreadyConfirmed is an error returned from PublishTransaction in case
// a transaction is already confirmed in the blockchain.
type ErrAlreadyConfirmed struct {
	backendError error
}

// Error returns the string representation of ErrAlreadyConfirmed.
//
// NOTE: Satisfies the error interface.
func (e *ErrAlreadyConfirmed) Error() string {
	return fmt.Sprintf("tx already confirmed: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrAlreadyConfirmed) Unwrap() error {
	return e.backendError
}

// ErrInMempool is an error returned from PublishTransaction in case a
// transaction is already in the mempool.
type ErrInMempool struct {
	backendError error
}

// Error returns the string representation of ErrInMempool.
//
// NOTE: Satisfies the error interface.
func (e *ErrInMempool) Error() string {
	return fmt.Sprintf("tx already in mempool: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrInMempool) Unwrap() error {
	return e.backendError
}

// PublishTransaction sends the transaction to the consensus RPC server so it
// can be propagated to other nodes and eventually mined.
//
// This function is unstable and will be removed once syncing code is moved out
// of the wallet.
func (w *Wallet) PublishTransaction(tx *wire.MsgTx, label string) error {
	_, err := w.reliablyPublishTransaction(tx, label)
	return err
}

// reliablyPublishTransaction is a superset of publishTransaction which contains
// the primary logic required for publishing a transaction, updating the
// relevant database state, and finally possible removing the transaction from
// the database (along with cleaning up all inputs used, and outputs created) if
// the transaction is rejected by the backend.
func (w *Wallet) reliablyPublishTransaction(tx *wire.MsgTx,
	label string) (*chainhash.Hash, error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// As we aim for this to be general reliable transaction broadcast API,
	// we'll write this tx to disk as an unconfirmed transaction. This way,
	// upon restarts, we'll always rebroadcast it, and also add it to our
	// set of records.
	txRec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	if err != nil {
		return nil, err
	}

	// Along the way, we'll extract our relevant destination addresses from
	// the transaction.
	var ourAddrs []btcutil.Address
	err = walletdb.Update(w.db, func(dbTx walletdb.ReadWriteTx) error {
		addrmgrNs := dbTx.ReadWriteBucket(waddrmgrNamespaceKey)
		for _, txOut := range tx.TxOut {
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				txOut.PkScript, w.chainParams,
			)
			if err != nil {
				// Non-standard outputs can safely be skipped
				// because they're not supported by the wallet.
				log.Warnf("Non-standard pkScript=%x in tx=%v",
					txOut.PkScript, tx.TxHash())

				continue
			}
			for _, addr := range addrs {
				// Skip any addresses which are not relevant to
				// us.
				_, err := w.addrStore.Address(addrmgrNs, addr)
				if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				ourAddrs = append(ourAddrs, addr)
			}
		}

		// If there is a label we should write, get the namespace key
		// and record it in the tx store.
		if len(label) != 0 {
			txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)

			err = w.txStore.PutTxLabel(txmgrNs, tx.TxHash(), label)
			if err != nil {
				return err
			}
		}

		return w.addRelevantTx(dbTx, txRec, nil)
	})
	if err != nil {
		return nil, err
	}

	// We'll also ask to be notified of the transaction once it confirms
	// on-chain. This is done outside of the database transaction to prevent
	// backend interaction within it.
	if err := chainClient.NotifyReceived(ourAddrs); err != nil {
		return nil, err
	}

	return w.publishTransaction(tx)
}

// publishTransaction attempts to send an unconfirmed transaction to the
// wallet's current backend. In the event that sending the transaction fails for
// whatever reason, it will be removed from the wallet's unconfirmed transaction
// store.
func (w *Wallet) publishTransaction(tx *wire.MsgTx) (*chainhash.Hash, error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	txid := tx.TxHash()
	_, rpcErr := chainClient.SendRawTransaction(tx, false)
	if rpcErr == nil {
		return &txid, nil
	}

	switch {
	case errors.Is(rpcErr, chain.ErrTxAlreadyInMempool):
		log.Infof("%v: tx already in mempool", txid)
		return &txid, nil

	case errors.Is(rpcErr, chain.ErrTxAlreadyKnown),
		errors.Is(rpcErr, chain.ErrTxAlreadyConfirmed):

		dbErr := walletdb.Update(w.db, func(dbTx walletdb.ReadWriteTx) error {
			txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)
			txRec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
			if err != nil {
				return err
			}

			return w.txStore.RemoveUnminedTx(txmgrNs, txRec)
		})
		if dbErr != nil {
			log.Warnf("Unable to remove confirmed transaction %v "+
				"from unconfirmed store: %v", tx.TxHash(), dbErr)
		}

		log.Infof("%v: tx already confirmed", txid)

		return &txid, nil

	}

	// Log the causing error, even if we know how to handle it.
	log.Infof("%v: broadcast failed because of: %v", txid, rpcErr)

	// If the transaction was rejected for whatever other reason, then
	// we'll remove it from the transaction store, as otherwise, we'll
	// attempt to continually re-broadcast it, and the UTXO state of the
	// wallet won't be accurate.
	dbErr := walletdb.Update(w.db, func(dbTx walletdb.ReadWriteTx) error {
		txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)
		txRec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			return err
		}

		return w.txStore.RemoveUnminedTx(txmgrNs, txRec)
	})
	if dbErr != nil {
		log.Warnf("Unable to remove invalid transaction %v: %v",
			tx.TxHash(), dbErr)
	} else {
		log.Infof("Removed invalid transaction: %v", tx.TxHash())

		// The serialized transaction is for logging only, don't fail
		// on the error.
		var txRaw bytes.Buffer
		_ = tx.Serialize(&txRaw)

		// Optionally log the tx in debug when the size is manageable.
		if txRaw.Len() < 1_000_000 {
			log.Debugf("Removed invalid transaction: %v \n hex=%x",
				newLogClosure(func() string {
					return spew.Sdump(tx)
				}), txRaw.Bytes())
		} else {
			log.Debug("Removed invalid transaction due to size " +
				"too large")
		}
	}

	return nil, rpcErr
}

// ChainParams returns the network parameters for the blockchain the wallet
// belongs to.
func (w *Wallet) ChainParams() *chaincfg.Params {
	return w.chainParams
}

// Database returns the underlying walletdb database. This method is provided
// in order to allow applications wrapping btcwallet to store app-specific data
// with the wallet's database.
func (w *Wallet) Database() walletdb.DB {
	return w.db
}

// RemoveDescendants attempts to remove any transaction from the wallet's tx
// store (that may be unconfirmed) that spends outputs created by the passed
// transaction. This remove propagates recursively down the chain of descendent
// transactions.
func (w *Wallet) RemoveDescendants(tx *wire.MsgTx) error {
	txRecord, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	if err != nil {
		return err
	}

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		wtxmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		return w.txStore.RemoveUnminedTx(wtxmgrNs, txRecord)
	})
}

// BirthdayBlock returns the birthday block of the wallet.
//
// NOTE: The wallet won't start until the backend is synced, thus the birthday
// block won't be set and `ErrBirthdayBlockNotSet` will be returned.
func (w *Wallet) BirthdayBlock() (*waddrmgr.BlockStamp, error) {
	var birthdayBlock waddrmgr.BlockStamp

	// Query the wallet's birthday block height from db.
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		bb, _, err := w.addrStore.BirthdayBlock(addrmgrNs)
		birthdayBlock = bb

		return err
	})
	if err != nil {
		return nil, err
	}

	return &birthdayBlock, nil
}

// AddScopeManager creates a new scoped key manager from the root manager.
func (w *Wallet) AddScopeManager(scope waddrmgr.KeyScope,
	addrSchema waddrmgr.ScopeAddrSchema) (
	waddrmgr.AccountStore, error) {

	var scopedManager waddrmgr.AccountStore

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		manager, err := w.addrStore.NewScopedKeyManager(
			addrmgrNs, scope, addrSchema,
		)
		scopedManager = manager

		return err
	})
	if err != nil {
		return nil, err
	}

	return scopedManager, nil
}

// InitAccounts creates a number of accounts specified by `num`, with account
// number ranges from 1 to `num`.
func (w *Wallet) InitAccounts(scope *waddrmgr.ScopedKeyManager,
	watchOnly bool, num uint32) error {

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		// Generate all accounts that we could ever need. This includes
		// all key families.
		for account := uint32(1); account <= num; account++ {
			// Otherwise, we'll check if the account already exists,
			// if so, we can once again bail early.
			_, err := scope.AccountName(addrmgrNs, account)
			if err == nil {
				continue
			}

			// If we reach this point, then the account hasn't yet
			// been created, so we'll need to create it before we
			// can proceed.
			err = scope.NewRawAccount(addrmgrNs, account)
			if err != nil {
				return err
			}
		}

		// If this is the first startup with remote signing and wallet
		// migration turned on and the wallet wasn't previously
		// migrated, we can do that now that we made sure all accounts
		// that we need were derived correctly.
		if watchOnly {
			log.Infof("Migrating wallet to watch-only mode, " +
				"purging all private key material")

			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			return w.addrStore.ConvertToWatchingOnly(ns)
		}

		return nil
	})
}

// DeriveFromKeyPath derives a private key using the given derivation path.
func (w *Wallet) DeriveFromKeyPath(scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	scopedMgr, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, fmt.Errorf("error fetching manager for scope %v: "+
			"%w", scope, err)
	}

	// Let's see if we can hit the private key cache.
	privKey, err := scopedMgr.DeriveFromKeyPathCache(path)
	if err == nil {
		return privKey, nil
	}

	// The key wasn't in the cache, let's fully derive it now.
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		addr, err := scopedMgr.DeriveFromKeyPath(addrmgrNs, path)
		if err != nil {
			return fmt.Errorf("error deriving private key: %w", err)
		}

		mpka, ok := addr.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			err := fmt.Errorf("managed address type for %v is "+
				"`%T` but want waddrmgr.ManagedPubKeyAddress",
				addr, addr)

			return err
		}

		privKey, err = mpka.PrivKey()

		return err
	})
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// DeriveFromKeyPathAddAccount derives a private key using the given derivation
// path. The account will be created if it doesn't exist.
func (w *Wallet) DeriveFromKeyPathAddAccount(scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	scopedMgr, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, fmt.Errorf("error fetching manager for scope %v: "+
			"%w", scope, err)
	}

	// Let's see if we can hit the private key cache.
	privKey, err := scopedMgr.DeriveFromKeyPathCache(path)
	if err == nil {
		return privKey, nil
	}

	derivePrivKey := func(addrmgrNs walletdb.ReadWriteBucket) error {
		addr, err := scopedMgr.DeriveFromKeyPath(addrmgrNs, path)

		// Exit early if there's no error.
		if err == nil {
			key, ok := addr.(waddrmgr.ManagedPubKeyAddress)
			if !ok {
				return nil
			}

			// Overwrite the returned private key variable.
			privKey, err = key.PrivKey()

			return err
		}

		return err
	}

	// The key wasn't in the cache, let's fully derive it now.
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := derivePrivKey(addrmgrNs)

		// Exit early if there's no error.
		if err == nil {
			return nil
		}

		// Exit with the error if it's not account not found.
		if !waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return fmt.Errorf("error deriving private key: %w", err)
		}

		// If we've reached this point, then the account doesn't yet
		// exist, so we'll create it now to ensure we can sign.
		err = scopedMgr.NewRawAccount(addrmgrNs, path.Account)
		if err != nil {
			return err
		}

		// Now that we know the account exists, we'll attempt to
		// re-derive the private key.
		return derivePrivKey(addrmgrNs)
	})
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// SyncedTo calls the `SyncedTo` method on the wallet's manager.
func (w *Wallet) SyncedTo() waddrmgr.BlockStamp {
	return w.addrStore.SyncedTo()
}

// AddrManager returns the internal address manager.
//
// TODO(yy): Refactor it in lnd and remove the method.
func (w *Wallet) AddrManager() waddrmgr.AddrStore {
	return w.addrStore
}

// NotificationServer returns the internal NotificationServer.
//
// TODO(yy): Refactor it in lnd and remove the method.
func (w *Wallet) NotificationServer() *NotificationServer {
	return w.NtfnServer
}

func (w *Wallet) newAddressDeprecated(addrmgrNs walletdb.ReadWriteBucket,
	account uint32, scope waddrmgr.KeyScope) (btcutil.Address,
	*waddrmgr.AccountProperties, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, nil, err
	}

	// Get next address from wallet.
	addrs, err := manager.NextExternalAddresses(addrmgrNs, account, 1)
	if err != nil {
		return nil, nil, err
	}

	props, err := manager.AccountProperties(addrmgrNs, account)
	if err != nil {
		log.Errorf("Cannot fetch account properties for notification "+
			"after deriving next external address: %v", err)

		return nil, nil, err
	}

	return addrs[0].Address(), props, nil
}

// CreateWithCallback is the same as Create with an added callback that will be
// called in the same transaction the wallet structure is initialized.
func CreateWithCallback(db walletdb.DB, pubPass, privPass []byte,
	rootKey *hdkeychain.ExtendedKey, params *chaincfg.Params,
	birthday time.Time, cb func(walletdb.ReadWriteTx) error) error {

	return create(
		db, pubPass, privPass, rootKey, params, birthday, false, cb,
	)
}

// CreateWatchingOnlyWithCallback is the same as CreateWatchingOnly with an
// added callback that will be called in the same transaction the wallet
// structure is initialized.
func CreateWatchingOnlyWithCallback(db walletdb.DB, pubPass []byte,
	params *chaincfg.Params, birthday time.Time,
	cb func(walletdb.ReadWriteTx) error) error {

	return create(
		db, pubPass, nil, nil, params, birthday, true, cb,
	)
}

// CreateDeprecated creates an new wallet, writing it to an empty database.
// If the passed root key is non-nil, it is used.  Otherwise, a secure
// random seed of the recommended length is generated.
//
// Deprecated: Use wallet.Create instead.
func CreateDeprecated(db walletdb.DB, pubPass, privPass []byte,
	rootKey *hdkeychain.ExtendedKey, params *chaincfg.Params,
	birthday time.Time) error {

	return create(
		db, pubPass, privPass, rootKey, params, birthday, false, nil,
	)
}

// CreateWatchingOnly creates an new watch-only wallet, writing it to
// an empty database. No root key can be provided as this wallet will be
// watching only.  Likewise no private passphrase may be provided
// either.
func CreateWatchingOnly(db walletdb.DB, pubPass []byte,
	params *chaincfg.Params, birthday time.Time) error {

	return create(
		db, pubPass, nil, nil, params, birthday, true, nil,
	)
}

func create(db walletdb.DB, pubPass, privPass []byte,
	rootKey *hdkeychain.ExtendedKey, params *chaincfg.Params,
	birthday time.Time, isWatchingOnly bool,
	cb func(walletdb.ReadWriteTx) error) error {

	// If no root key was provided, we create one now from a random seed.
	// But only if this is not a watching-only wallet where the accounts are
	// created individually from their xpubs.
	if !isWatchingOnly && rootKey == nil {
		hdSeed, err := hdkeychain.GenerateSeed(
			hdkeychain.RecommendedSeedLen,
		)
		if err != nil {
			return err
		}

		// Derive the master extended key from the seed.
		rootKey, err = hdkeychain.NewMaster(hdSeed, params)
		if err != nil {
			return fmt.Errorf("failed to derive master extended " +
				"key")
		}
	}

	// We need a private key if this isn't a watching only wallet.
	if !isWatchingOnly && rootKey != nil && !rootKey.IsPrivate() {
		return fmt.Errorf("need extended private key for wallet that " +
			"is not watching only")
	}

	return walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return err
		}
		txmgrNs, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if err != nil {
			return err
		}

		err = waddrmgr.Create(
			addrmgrNs, rootKey, pubPass, privPass, params, nil,
			birthday,
		)
		if err != nil {
			return err
		}

		err = wtxmgr.Create(txmgrNs)
		if err != nil {
			return err
		}

		if cb != nil {
			return cb(tx)
		}

		return nil
	})
}

// Open loads an already-created wallet from the passed database and namespaces.
func Open(db walletdb.DB, pubPass []byte, cbs *waddrmgr.OpenCallbacks,
	params *chaincfg.Params, recoveryWindow uint32) (*Wallet, error) {

	return OpenWithRetry(
		db, pubPass, cbs, params, recoveryWindow,
		defaultSyncRetryInterval,
	)
}

// OpenWithRetry loads an already-created wallet from the passed database and
// namespaces and re-tries on errors during initial sync.
func OpenWithRetry(db walletdb.DB, pubPass []byte, cbs *waddrmgr.OpenCallbacks,
	params *chaincfg.Params, recoveryWindow uint32,
	syncRetryInterval time.Duration) (*Wallet, error) {

	var (
		addrMgr *waddrmgr.Manager
		txMgr   *wtxmgr.Store
	)

	// Before attempting to open the wallet, we'll check if there are any
	// database upgrades for us to proceed. We'll also create our references
	// to the address and transaction managers, as they are backed by the
	// database.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		addrMgrBucket := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if addrMgrBucket == nil {
			return errors.New("missing address manager namespace")
		}
		txMgrBucket := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if txMgrBucket == nil {
			return errors.New("missing transaction manager namespace")
		}

		addrMgrUpgrader := waddrmgr.NewMigrationManager(addrMgrBucket)
		txMgrUpgrader := wtxmgr.NewMigrationManager(txMgrBucket)
		err := migration.Upgrade(txMgrUpgrader, addrMgrUpgrader)
		if err != nil {
			return err
		}

		addrMgr, err = waddrmgr.Open(addrMgrBucket, pubPass, params)
		if err != nil {
			return err
		}
		txMgr, err = wtxmgr.Open(txMgrBucket, params)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	log.Infof("Opened wallet") // TODO: log balance? last sync height?

	deprecated := &walletDeprecated{
		lockedOutpoints:     map[wire.OutPoint]struct{}{},
		rescanAddJob:        make(chan *RescanJob),
		rescanBatch:         make(chan *rescanBatch),
		rescanNotifications: make(chan interface{}),
		rescanProgress:      make(chan *RescanProgressMsg),
		rescanFinished:      make(chan *RescanFinishedMsg),
		createTxRequests:    make(chan createTxRequest),
		unlockRequests:      make(chan unlockRequest),
		lockRequests:        make(chan struct{}),
		holdUnlockRequests:  make(chan chan heldUnlock),
		lockState:           make(chan bool),
		changePassphrase:    make(chan changePassphraseRequest),
		changePassphrases:   make(chan changePassphrasesRequest),
		chainParams:         params,
		quit:                make(chan struct{}),
		syncRetryInterval:   syncRetryInterval,
	}

	w := &Wallet{
		publicPassphrase: pubPass,
		db:               db,
		addrStore:        addrMgr,
		txStore:          txMgr,
		recoveryWindow:   recoveryWindow,
		walletDeprecated: deprecated,
	}

	w.NtfnServer = newNotificationServer(w)
	txMgr.NotifyUnspent = func(hash *chainhash.Hash, index uint32) {
		w.NtfnServer.notifyUnspentOutput(0, hash, index)
	}

	return w, nil
}
