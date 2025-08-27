// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// NewAccount creates the next account and returns its account number. The name
// must be unique under the kep scope. In order to support automatic seed
// restoring, new accounts may not be created when all of the previous 100
// accounts have no transaction history (this is a deviation from the BIP0044
// spec, which allows no unused account gaps).
func (w *Wallet) NewAccount(_ context.Context, scope waddrmgr.KeyScope,
	name string) (uint32, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return 0, err
	}

	// Validate that the scope manager can add this new account.
	err = manager.CanAddAccount()
	if err != nil {
		return 0, err
	}

	var (
		accountIndex uint32
	)
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		// Create a new account under the current key scope.
		accountID, err := manager.NewAccount(addrmgrNs, name)
		accountIndex = accountID

		return err
	})

	return accountIndex, err
}

// AccountResult is the result of a ListAccounts query.
type AccountResult struct {
	// AccountProperties is the account's properties.
	waddrmgr.AccountProperties

	// TotalBalance is the total balance of the account.
	TotalBalance btcutil.Amount
}

// AccountsResult is the result of a ListAccounts query. It contains a list of
// accounts and the current block height and hash.
type AccountsResult struct {
	// Accounts is a list of accounts.
	Accounts []AccountResult

	// CurrentBlockHash is the hash of the current block.
	CurrentBlockHash chainhash.Hash

	// CurrentBlockHeight is the height of the current block.
	CurrentBlockHeight int32
}

// ListAccounts returns a list of all accounts for the wallet, including
// accounts with a zero balance. The current chain tip is included in the
// result for reference.
//
// The implementation is optimized for performance by first building a map of
// balances for all addresses with unspent outputs and then iterating through
// all known accounts to tally up their final balances.
//
// The time complexity of this method is O(U + A), where U is the number of
// UTXOs and A is the number of addresses in the wallet. This is a significant
// improvement over a naive implementation that would have a complexity of
// O(U * A), e.g., the old `Accounts` method.
//
// A potential future improvement would be to index UTXOs by account directly
// in the database, which would reduce the complexity to O(A).
func (w *Wallet) ListAccounts(_ context.Context) (*AccountsResult, error) {
	managers := w.addrStore.ActiveScopedKeyManagers()

	var accounts []AccountResult
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// First, we'll create a map of all addresses to their balances
		// by iterating through all unspent outputs. This is more
		// efficient than iterating through all addresses and looking
		// up their balances individually.
		addrToBalance := make(map[string]btcutil.Amount)
		utxos, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		for _, utxo := range utxos {
			// Decode the script to find the address.
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				utxo.PkScript, w.chainParams,
			)
			if err != nil {
				// Silently ignore outputs with scripts that
				// cannot be parsed.
				continue
			}

			if len(addrs) == 0 {
				continue
			}

			// Add the UTXO's value to the address's balance.
			addrStr := addrs[0].String()
			addrToBalance[addrStr] += utxo.Amount
		}

		// Now, we'll iterate through all the accounts and calculate
		// their balances by summing up the balances of all their
		// addresses.
		for _, scopeMgr := range managers {
			results, err := createResultForScope(
				scopeMgr, addrmgrNs, addrToBalance,
			)
			if err != nil {
				return err
			}

			accounts = append(accounts, results...)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Get the sync tip to ensure atomicity.
	syncBlock := w.addrStore.SyncedTo()

	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   syncBlock.Hash,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
}

// createResultForScope creates a slice of AccountResult for a given key
// scope. This function will iterate through all accounts in the scope, and
// calculate the balance for each of them.
//
// The addrToBalance map is a map of all addresses to their balances. This is
// used to efficiently calculate the balance for each account.
//
// The function returns a slice of AccountResult, and an error if any occurred.
func createResultForScope(scopeMgr *waddrmgr.ScopedKeyManager,
	addrmgrNs walletdb.ReadBucket,
	addrToBalance map[string]btcutil.Amount) ([]AccountResult, error) {

	var accounts []AccountResult

	// We'll start by getting the last account in the scope, so we can
	// iterate from the first account to the last.
	lastAccount, err := scopeMgr.LastAccount(addrmgrNs)
	if err != nil {
		return accounts, err
	}

	for acctNum := uint32(0); acctNum <= lastAccount; acctNum++ {
		// Get the account's properties.
		props, err := scopeMgr.AccountProperties(
			addrmgrNs, acctNum,
		)
		if err != nil {
			return accounts, err
		}

		acctResult := AccountResult{
			AccountProperties: *props,
		}

		// Iterate through all addresses of the account
		// and sum up their balances.
		err = scopeMgr.ForEachAccountAddress(
			addrmgrNs, acctNum,
			func(addr waddrmgr.ManagedAddress) error {
				acctResult.TotalBalance +=
					addrToBalance[addr.Address().String()]
				return nil
			},
		)
		if err != nil {
			return accounts, err
		}

		accounts = append(accounts, acctResult)
	}

	return accounts, nil
}

// ListAccountsByScope returns a list of all accounts for a given scope for the
// wallet, including accounts with a zero balance. The current chain tip is
// included in the result for reference.
//
// The implementation is optimized for performance by first building a map of
// balances for all addresses with unspent outputs and then iterating through
// all known accounts to tally up their final balances.
//
// The time complexity of this method is O(U + A), where U is the number of
// UTXOs and A is the number of addresses in the wallet. This is a significant
// improvement over a naive implementation that would have a complexity of
// O(U * A), e.g., the old `Accounts` method.
//
// A potential future improvement would be to index UTXOs by account directly
// in the database, which would reduce the complexity to O(A).
func (w *Wallet) ListAccountsByScope(_ context.Context,
	scope waddrmgr.KeyScope) (*AccountsResult, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var accounts []AccountResult
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// First, we'll create a map of all addresses to their balances
		// by iterating through all unspent outputs. This is more
		// efficient than iterating through all addresses and looking
		// up their balances individually.
		addrToBalance := make(map[string]btcutil.Amount)
		utxos, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		for _, utxo := range utxos {
			// Decode the script to find the address.
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				utxo.PkScript, w.chainParams,
			)
			if err != nil {
				// Silently ignore outputs with scripts that
				// cannot be parsed.
				continue
			}

			if len(addrs) == 0 {
				continue
			}

			// Add the UTXO's value to the address's balance.
			addrStr := addrs[0].String()
			addrToBalance[addrStr] += utxo.Amount
		}

		// Now, we'll iterate through all the accounts and calculate
		// their balances by summing up the balances of all their
		// addresses.
		results, err := createResultForScope(
			manager, addrmgrNs, addrToBalance,
		)
		if err != nil {
			return err
		}

		accounts = append(accounts, results...)

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Get the sync tip to ensure atomicity.
	syncBlock := w.addrStore.SyncedTo()

	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   syncBlock.Hash,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
}

// ListAccountsByName returns a list of all accounts for a given account name
// for the wallet, including accounts with a zero balance. The current chain
// tip is included in the result for reference.
//
// The implementation is optimized for performance by first building a map of
// balances for all addresses with unspent outputs and then iterating through
// all known accounts to tally up their final balances.
//
// The time complexity of this method is O(U + A), where U is the number of
// UTXOs and A is the number of addresses in the wallet. This is a significant
// improvement over a naive implementation that would have a complexity of
// O(U * A), e.g., the old `Accounts` method.
//
// A potential future improvement would be to index UTXOs by account directly
// in the database, which would reduce the complexity to O(A).
func (w *Wallet) ListAccountsByName(_ context.Context,
	name string) (*AccountsResult, error) {

	managers := w.addrStore.ActiveScopedKeyManagers()

	var accounts []AccountResult
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// First, we'll create a map of all addresses to their balances
		// by iterating through all unspent outputs. This is more
		// efficient than iterating through all addresses and looking
		// up their balances individually.
		addrToBalance := make(map[string]btcutil.Amount)
		utxos, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		for _, utxo := range utxos {
			// Decode the script to find the address.
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				utxo.PkScript, w.chainParams,
			)
			if err != nil {
				// Silently ignore outputs with scripts that
				// cannot be parsed.
				continue
			}

			if len(addrs) == 0 {
				continue
			}

			// Add the UTXO's value to the address's balance.
			addrStr := addrs[0].String()
			addrToBalance[addrStr] += utxo.Amount
		}

		// Now, we'll iterate through all the accounts and calculate
		// their balances by summing up the balances of all their
		// addresses.
		for _, scopeMgr := range managers {
			results, err := createResultForScope(
				scopeMgr, addrmgrNs, addrToBalance,
			)
			if err != nil {
				return err
			}

			for _, acc := range results {
				if acc.AccountName == name {
					accounts = append(accounts, acc)
				}
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Get the sync tip to ensure atomicity.
	syncBlock := w.addrStore.SyncedTo()

	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   syncBlock.Hash,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
}

// GetAccount returns the account for a given account name and scope.
//
// The time complexity of this method is O(U + A_a), where U is the number of
// UTXOs in the wallet and A_a is the number of addresses in the account.
func (w *Wallet) GetAccount(_ context.Context, scope waddrmgr.KeyScope,
	name string) (*AccountResult, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var account *AccountResult
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// First, we'll look up the account number for the given name.
		accNum, err := manager.LookupAccount(addrmgrNs, name)
		if err != nil {
			return err
		}

		// Get the account's properties.
		props, err := manager.AccountProperties(addrmgrNs, accNum)
		if err != nil {
			return err
		}

		account = &AccountResult{
			AccountProperties: *props,
		}

		// Now, we'll create a set of all addresses in the account.
		// This is more efficient than iterating through all UTXOs and
		// looking up the account for each one.
		accountAddrs := make(map[string]struct{})
		err = manager.ForEachAccountAddress(
			addrmgrNs, accNum,
			func(addr waddrmgr.ManagedAddress) error {
				addrStr := addr.Address().String()
				accountAddrs[addrStr] = struct{}{}
				return nil
			},
		)
		if err != nil {
			return err
		}

		// Finally, we'll iterate through all unspent outputs and sum
		// up the balances for the addresses in our set.
		utxos, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		for _, utxo := range utxos {
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				utxo.PkScript, w.chainParams,
			)
			if err != nil || len(addrs) == 0 {
				continue
			}

			addrStr := addrs[0].String()
			if _, ok := accountAddrs[addrStr]; ok {
				account.TotalBalance += utxo.Amount
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return account, nil
}

// RenameAccount renames an existing account.
//
// The time complexity of this method is dominated by the database lookup for
// the old account name.
func (w *Wallet) RenameAccount(_ context.Context, scope waddrmgr.KeyScope,
	oldName, newName string) error {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return err
	}

	// Validate new account name.
	if err := waddrmgr.ValidateAccountName(newName); err != nil {
		return err
	}

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		// First, we'll look up the account number for the given name.
		accNum, err := manager.LookupAccount(addrmgrNs, oldName)
		if err != nil {
			return err
		}

		return manager.RenameAccount(addrmgrNs, accNum, newName)
	})
}

// Balance returns the balance for a specific account.
//
// The time complexity of this method is O(U + A_a), where U is the number of
// UTXOs in the wallet and A_a is the number of addresses in the account.
func (w *Wallet) Balance(_ context.Context, conf int32,
	scope waddrmgr.KeyScope, accountName string) (btcutil.Amount, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return 0, err
	}

	var balance btcutil.Amount
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// First, we'll look up the account number for the given name.
		accNum, err := manager.LookupAccount(addrmgrNs, accountName)
		if err != nil {
			return err
		}

		// Now, we'll create a set of all addresses in the account.
		accountAddrs := make(map[string]struct{})
		err = manager.ForEachAccountAddress(
			addrmgrNs, accNum,
			func(addr waddrmgr.ManagedAddress) error {
				addrStr := addr.Address().String()
				accountAddrs[addrStr] = struct{}{}
				return nil
			},
		)
		if err != nil {
			return err
		}

		// Finally, we'll iterate through all unspent outputs and sum
		// up the balances for the addresses in our set.
		syncBlock := w.addrStore.SyncedTo()
		utxos, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		for _, utxo := range utxos {
			if !confirmed(conf, utxo.Height, syncBlock.Height) {
				continue
			}

			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				utxo.PkScript, w.chainParams,
			)
			if err != nil || len(addrs) == 0 {
				continue
			}

			addrStr := addrs[0].String()
			if _, ok := accountAddrs[addrStr]; ok {
				balance += utxo.Amount
			}
		}

		return nil
	})
	if err != nil {
		return 0, err
	}

	return balance, nil
}

// ImportAccount imports a watch-only account from an extended public key.
//
// The time complexity of this method is dominated by the database lookup to
// ensure the account name is unique within the scope.
func (w *Wallet) ImportAccount(_ context.Context,
	name string, accountPubKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrType *waddrmgr.AddressType,
	dryRun bool) (*waddrmgr.AccountProperties, error) {

	var (
		props *waddrmgr.AccountProperties
		err   error
	)

	if dryRun {
		props, _, _, err = w.ImportAccountDryRun(
			name, accountPubKey, masterKeyFingerprint, addrType, 0,
		)
	} else {
		props, err = w.ImportAccountDeprecated(
			name, accountPubKey, masterKeyFingerprint, addrType,
		)
	}

	return props, err
}
