// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet implements the account management for the wallet.
//
// TODO(yy): bring wrapcheck back when implementing the `Store` interface.
//
//nolint:wrapcheck
package wallet

import (
	"context"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// AccountManager provides a high-level interface for managing wallet
// accounts.
//
// # Account Derivation
//
// The wallet uses a hierarchical deterministic (HD) key generation scheme based
// on BIP-44. Addresses are derived from a path with the following structure:
//
//	m / purpose' / coin_type' / account' / change / address_index
//
// The AccountManager abstracts this complexity by mapping a human-readable
// name to the cryptographic `account'` index within a given KeyScope.
//
// # Key Scopes
//
// The `purpose'` and `coin_type'` fields of the derivation path are defined by
// a waddrmgr.KeyScope. This allows the wallet to manage different kinds of
// accounts (and address types) simultaneously. The wallet initializes a set of
// default scopes upon creation:
//   - KeyScopeBIP0044: For legacy P2PKH addresses.
//   - KeyScopeBIP0049Plus: For P2WPKH addresses nested in P2SH (NP2WKH).
//   - KeyScopeBIP0084: For native SegWit v0 P2WPKH addresses.
//   - KeyScopeBIP0086: For native Taproot v1 P2TR addresses.
//
// # Account Names and Reserved Accounts
//
// An account name is a human-readable identifier that is unique *within its
// KeyScope*. The wallet initializes two special, reserved accounts:
//   - "default": The first user-created account (account number 0). This
//     account is created for each of the default key scopes and CAN be renamed.
//   - "imported": A special account that holds all individually imported keys.
//     This account is global and CANNOT be renamed.
type AccountManager interface {
	// NewAccount creates a new account for a given key scope and name. The
	// provided name must be unique within that key scope.
	NewAccount(ctx context.Context, scope waddrmgr.KeyScope, name string) (
		*waddrmgr.AccountProperties, error)

	// ListAccounts returns a list of all accounts managed by the wallet.
	ListAccounts(ctx context.Context) (*AccountsResult, error)

	// ListAccountsByScope returns a list of all accounts for a given key
	// scope.
	ListAccountsByScope(ctx context.Context, scope waddrmgr.KeyScope) (
		*AccountsResult, error)

	// ListAccountsByName searches for accounts with the given name across
	// all key scopes. Because names are not globally unique, this may
	// return multiple results.
	ListAccountsByName(ctx context.Context, name string) (
		*AccountsResult, error)

	// GetAccount returns the properties for a specific account, looked up
	// by its key scope and unique name within that scope.
	GetAccount(ctx context.Context, scope waddrmgr.KeyScope, name string) (
		*AccountResult, error)

	// RenameAccount renames an existing account. To uniquely identify the
	// account, the key scope must be provided. The new name must be unique
	// within that same key scope. The reserved "imported" account cannot
	// be renamed.
	RenameAccount(ctx context.Context, scope waddrmgr.KeyScope,
		oldName string, newName string) error

	// Balance returns the balance for a specific account, identified by its
	// scope and name, for a given number of required confirmations.
	Balance(ctx context.Context, conf int32, scope waddrmgr.KeyScope,
		name string) (btcutil.Amount, error)

	// ImportAccount imports an account from an extended public or private
	// key. The key scope is derived from the version bytes of the
	// extended key. The account name must be unique within the derived
	// scope. If dryRun is true, the import is validated but not persisted.
	ImportAccount(ctx context.Context, name string,
		accountKey *hdkeychain.ExtendedKey,
		masterKeyFingerprint uint32, addrType waddrmgr.AddressType,
		dryRun bool) (*waddrmgr.AccountProperties, error)
}

// A compile time check to ensure that Wallet implements the interface.
var _ AccountManager = (*Wallet)(nil)

// NewAccount creates the next account and returns its account number. The name
// must be unique under the kep scope. In order to support automatic seed
// restoring, new accounts may not be created when all of the previous 100
// accounts have no transaction history (this is a deviation from the BIP0044
// spec, which allows no unused account gaps).
func (w *Wallet) NewAccount(_ context.Context, scope waddrmgr.KeyScope,
	name string) (*waddrmgr.AccountProperties, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	// Validate that the scope manager can add this new account.
	err = manager.CanAddAccount()
	if err != nil {
		return nil, err
	}

	var props *waddrmgr.AccountProperties

	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		// Create a new account under the current key scope.
		accNum, err := manager.NewAccount(addrmgrNs, name)
		if err != nil {
			return err
		}

		// Get the account's properties.
		props, err = manager.AccountProperties(addrmgrNs, accNum)

		return err
	})

	return props, err
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

// ListAccounts returns a list of all accounts for the wallet, including those
// with a zero balance. The current chain tip is included in the result for
// reference.
//
// The function calculates balances by first creating a comprehensive map of
// balances for all accounts that currently own UTXOs. It then iterates through
// all known accounts across all key scopes, retrieving their properties and
// assigning the pre-calculated balance. Accounts with no UTXOs will correctly
// be assigned a zero balance.
//
// The time complexity of this method is O(U*logA + A), where U is the number of
// UTXOs and A is the number of accounts in the wallet. A potential future
// improvement is to make the balance calculation optional.
func (w *Wallet) ListAccounts(_ context.Context) (*AccountsResult, error) {
	// Get all active key scope managers to iterate through all available
	// scopes.
	scopes := w.addrStore.ActiveScopedKeyManagers()

	var accounts []AccountResult

	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		// First, build a map of balances for all accounts that own at
		// least one UTXO. This is done by iterating through the UTXO
		// set and aggregating the values by account.
		scopedBalances, err := w.fetchAccountBalances(tx)
		if err != nil {
			return err
		}

		// Now, iterate through each key scope to assemble the final list
		// of accounts with their properties and balances.
		for _, scopeMgr := range scopes {
			scope := scopeMgr.Scope()
			accountBalances := scopedBalances[scope]

			// For the current scope, retrieve the properties for
			// each account and combine them with the
			// pre-calculated balances.
			scopedAccounts, err := listAccountsWithBalances(
				scopeMgr, addrmgrNs, accountBalances,
			)
			if err != nil {
				return err
			}

			// Append the accounts from this scope to the final
			// list.
			accounts = append(accounts, scopedAccounts...)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Include the wallet's current sync state in the result to provide a
	// point-in-time reference for the balances.
	syncBlock := w.addrStore.SyncedTo()

	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   syncBlock.Hash,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
}

// ListAccountsByScope returns a list of all accounts for a given key scope,
// including those with a zero balance. The current chain tip is included for
// reference.
//
// The function first fetches the balances for all accounts within the given
// scope by iterating over the wallet's UTXO set. It then retrieves the
// properties for each account in that scope and combines them with the
// pre-calculated balances.
//
// The time complexity of this method is O(U*logA + A), where U is the number of
// UTXOs and A is the number of accounts in the wallet.
func (w *Wallet) ListAccountsByScope(_ context.Context,
	scope waddrmgr.KeyScope) (*AccountsResult, error) {

	// First, we'll fetch the scoped key manager for the given scope. This
	// manager will be used to list the accounts.
	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var accounts []AccountResult

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		// Calculate the balances for all accounts, but only for the
		// key scope we are interested in.
		scopedBalances, err := w.fetchAccountBalances(
			tx, withScope(scope),
		)
		if err != nil {
			return err
		}

		// Now, retrieve the properties for each account in the scope
		// and combine them with the balances calculated above.
		accounts, err = listAccountsWithBalances(
			manager, addrmgrNs, scopedBalances[scope],
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	// Include the wallet's current sync state in the result.
	syncBlock := w.addrStore.SyncedTo()

	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   syncBlock.Hash,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
}

// ListAccountsByName returns a list of all accounts that have a given name.
// Since account names are only unique within a key scope, this can return
// multiple accounts. The current chain tip is included for reference.
//
// The function first calculates the balances for any accounts matching the
// given name, and then iterates through all key scopes to find and retrieve
// the properties of those accounts.
//
// The time complexity of this method is O(U*logA), where U is the number of
// UTXOs and logA is the cost of an account lookup.
func (w *Wallet) ListAccountsByName(_ context.Context,
	name string) (*AccountsResult, error) {

	scopes := w.addrStore.ActiveScopedKeyManagers()

	var accounts []AccountResult

	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		// First, calculate the balances for any accounts that match the
		// given name. This is efficient as it iterates over the UTXO
		// set, not accounts.
		scopedBalances, err := w.fetchAccountBalances(tx)
		if err != nil {
			return err
		}

		// Now, find all accounts that match the given name by iterating
		// through all active scopes.
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		for _, scopeMgr := range scopes {
			// Look up the account number for the given name in the
			// current scope.
			accNum, err := scopeMgr.LookupAccount(addrmgrNs, name)
			if err != nil {
				// If the account is not found in this scope,
				// we can safely continue to the next one.
				if waddrmgr.IsError(
					err, waddrmgr.ErrAccountNotFound) {

					continue
				}

				return err
			}

			// Retrieve the account's properties.
			props, err := scopeMgr.AccountProperties(
				addrmgrNs, accNum,
			)
			if err != nil {
				return err
			}

			// Get the pre-calculated balance for this account. If
			// the account has no balance, it will be zero.
			var balance btcutil.Amount

			balances, ok := scopedBalances[scopeMgr.Scope()]
			if ok {
				balance = balances[accNum]
			}

			accounts = append(accounts, AccountResult{
				AccountProperties: *props,
				TotalBalance:      balance,
			})
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	syncBlock := w.addrStore.SyncedTo()

	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   syncBlock.Hash,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
}

// GetAccount returns the account for a given account name and key scope.
//
// The function first looks up the account's properties and then calculates its
// balance by iterating over the wallet's UTXO set.
//
// The time complexity of this method is O(U*logA), where U is the number of
// UTXOs and logA is the cost of an account lookup.
func (w *Wallet) GetAccount(_ context.Context, scope waddrmgr.KeyScope,
	name string) (*AccountResult, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var account *AccountResult

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		// Look up the account number for the given name and scope. This
		// is a fast, indexed lookup.
		accNum, err := manager.LookupAccount(addrmgrNs, name)
		if err != nil {
			return err
		}

		// Retrieve the static properties for the account.
		props, err := manager.AccountProperties(addrmgrNs, accNum)
		if err != nil {
			return err
		}

		account = &AccountResult{
			AccountProperties: *props,
		}

		// Calculate the balance for this specific account by fetching
		// the UTXOs that belong to it.
		scopedBalances, err := w.fetchAccountBalances(
			tx, withScope(scope),
		)
		if err != nil {
			return err
		}

		// Assign the balance to the account result. If the account has
		// no UTXOs, the balance will be zero.
		if balances, ok := scopedBalances[scope]; ok {
			if balance, ok := balances[accNum]; ok {
				account.TotalBalance = balance
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return account, nil
}

// RenameAccount renames an existing account. The new name must be unique within
// the same key scope. The reserved "imported" account cannot be renamed.
//
// The time complexity of this method is dominated by the database lookup for
// the old account name.
func (w *Wallet) RenameAccount(_ context.Context, scope waddrmgr.KeyScope,
	oldName, newName string) error {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return err
	}

	// Validate the new account name to ensure it meets the required
	// criteria.
	err = waddrmgr.ValidateAccountName(newName)
	if err != nil {
		return err
	}

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		// Look up the account number for the given name. This is
		// required to perform the rename operation.
		accNum, err := manager.LookupAccount(addrmgrNs, oldName)
		if err != nil {
			return err
		}

		// Perform the rename operation in the address manager.
		return manager.RenameAccount(addrmgrNs, accNum, newName)
	})
}

// Balance returns the balance for a specific account, identified by its scope
// and name, for a given number of required confirmations.
//
// The function first looks up the account number and then iterates through all
// unspent transaction outputs (UTXOs), summing the values of those that belong
// to the account and meet the required number of confirmations.
//
// The time complexity of this method is O(U*logA), where U is the number of
// UTXOs and logA is the cost of an account lookup.
func (w *Wallet) Balance(_ context.Context, conf int32,
	scope waddrmgr.KeyScope, name string) (btcutil.Amount, error) {

	var balance btcutil.Amount

	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// Look up the account number for the given name and scope.
		manager, err := w.addrStore.FetchScopedKeyManager(scope)
		if err != nil {
			return err
		}

		accNum, err := manager.LookupAccount(addrmgrNs, name)
		if err != nil {
			return err
		}

		// Iterate through all unspent outputs and sum the balances for
		// the addresses that belong to the target account.
		syncBlock := w.addrStore.SyncedTo()

		utxos, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}

		for _, utxo := range utxos {
			// Skip any UTXOs that have not yet reached the required
			// number of confirmations.
			if !confirmed(conf, utxo.Height, syncBlock.Height) {
				continue
			}

			balance += w.balanceForUTXO(
				addrmgrNs, scope, accNum, utxo,
			)
		}

		return nil
	})
	if err != nil {
		return 0, err
	}

	return balance, nil
}

// balanceForUTXO is a helper function for Balance that calculates the balance
// of a single UTXO if it belongs to the target account.
func (w *Wallet) balanceForUTXO(addrmgrNs walletdb.ReadBucket,
	scope waddrmgr.KeyScope, accNum uint32,
	utxo wtxmgr.Credit) btcutil.Amount {

	// Extract the address from the UTXO's public key script.
	addr := extractAddrFromPKScript(utxo.PkScript, w.chainParams)
	if addr == nil {
		return 0
	}

	// Look up the account that owns the address.
	addrScope, addrAcc, err := w.addrStore.AddrAccount(addrmgrNs, addr)
	if err != nil {
		// Ignore addresses that are not found in the wallet.
		return 0
	}

	// If the address belongs to the target account, add the UTXO's value
	// to the total balance.
	if addrScope.Scope() == scope && addrAcc == accNum {
		return utxo.Amount
	}

	return 0
}

// ImportAccount imports an account from an extended public or private key.
//
// The time complexity of this method is dominated by the database lookup
// to ensure the account name is unique within the scope.
func (w *Wallet) ImportAccount(_ context.Context,
	name string, accountKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrType waddrmgr.AddressType,
	dryRun bool) (*waddrmgr.AccountProperties, error) {

	var (
		props *waddrmgr.AccountProperties
		err   error
	)

	if dryRun {
		props, _, _, err = w.ImportAccountDryRun(
			name, accountKey, masterKeyFingerprint, &addrType, 0,
		)
	} else {
		props, err = w.ImportAccountDeprecated(
			name, accountKey, masterKeyFingerprint, &addrType,
		)
	}

	return props, err
}

// extractAddrFromPKScript extracts an address from a public key script. If the
// script cannot be parsed or does not contain any addresses, it returns nil.
//
// The btcutil.Address is an interface that abstracts over different address
// types. Returning the interface is idiomatic in this context.
//
//nolint:ireturn
func extractAddrFromPKScript(pkScript []byte,
	chainParams *chaincfg.Params) btcutil.Address {

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		pkScript, chainParams,
	)
	if err != nil {
		// We'll log the error and return nil to prevent a single
		// un-parsable script from failing a larger operation.
		log.Errorf("Unable to parse pkscript: %v", err)
		return nil
	}

	// This can happen for scripts that don't resolve to a standard address,
	// such as OP_RETURN outputs. We can safely ignore these.
	if len(addrs) == 0 {
		return nil
	}

	// TODO(yy): For bare multisig outputs, ExtractPkScriptAddrs can
	// return more than one address. Currently, we are only considering
	// the first address, which could lead to incorrect balance
	// attribution. However, since bare multisig is rare and modern
	// wallets almost exclusively use P2SH or P2WSH for multisig (which
	// are correctly handled as a single address), this is a low-priority
	// issue.
	return addrs[0]
}

// accountFilter is an internal struct used to specify filters for account
// balance queries.
type accountFilter struct {
	scope *waddrmgr.KeyScope
}

// filterOption is a functional option type for account filtering.
type filterOption func(*accountFilter)

// withScope is a filter option to limit account queries to a specific key
// scope.
func withScope(scope waddrmgr.KeyScope) filterOption {
	return func(f *accountFilter) {
		f.scope = &scope
	}
}

// scopedBalances is a type alias for a map of key scopes to a map of account
// numbers to their total balance.
type scopedBalances map[waddrmgr.KeyScope]map[uint32]btcutil.Amount

// fetchAccountBalances creates a nested map of account balances, keyed by scope
// and account number.
//
// This function is a core component of the wallet's balance calculation
// logic. It is designed to be efficient, especially for wallets with a large
// number of addresses.
//
// Design Rationale:
// The primary performance consideration is the trade-off between iterating
// through all Unspent Transaction Outputs (UTXOs) versus iterating through all
// derived addresses for all accounts. A mature wallet may have millions of used
// addresses, but a relatively small set of UTXOs. Therefore, this function is
// optimized for this common case.
//
// The algorithm works as follows:
// 1. Make a single pass over all UTXOs in the wallet.
// 2. For each UTXO, look up the address and its corresponding account.
// 3. Aggregate the UTXO values into a map of balances per account.
//
// This approach avoids iterating through a potentially massive number of
// addresses and performing a database lookup for each one to check for a
// balance. Instead, it starts with the smaller, known set of UTXOs and works
// backward to the accounts.
//
// Filters:
// The function's behavior can be customized by passing one or more filterOption
// functions. This allows the caller to restrict the balance calculation to:
//   - A specific key scope (withScope).
//
// If no filters are provided, balances for all accounts across all scopes will
// be fetched.
//
// TODO(yy): With a future SQL backend, this entire function could be
// replaced by a single, more efficient query. By adding `account_id` and
// `key_scope` columns to the `outputs` table, we could perform a direct
// aggregation in the database, like:
// `SELECT key_scope, account_id, SUM(value) FROM outputs
// WHERE is_spent = false GROUP BY key_scope, account_id;`.
// This would be significantly faster as the database is optimized for
// these types of operations.
//
// TODO(yy): The current UTXO-first approach is optimal for mature wallets where
// the number of addresses greatly exceeds the number of UTXOs. For new wallets
// or accounts, an address-first approach might be more efficient. A future
// improvement could be to dynamically choose the strategy based on the relative
// counts of addresses and UTXOs for the accounts in question.
func (w *Wallet) fetchAccountBalances(tx walletdb.ReadTx,
	opts ...filterOption) (scopedBalances, error) {

	// Apply the filter options.
	filter := &accountFilter{}
	for _, opt := range opts {
		opt(filter)
	}

	addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
	txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

	// First, fetch all unspent outputs.
	utxos, err := w.txStore.UnspentOutputs(txmgrNs)
	if err != nil {
		return nil, err
	}

	// Now, create the nested map to hold the balances.
	scopedBalances := make(scopedBalances)

	// Iterate through all UTXOs, mapping them back to their owning account
	// to aggregate the total balance for each.
	for _, utxo := range utxos {
		addr := extractAddrFromPKScript(utxo.PkScript, w.chainParams)
		if addr == nil {
			// This can happen for non-standard script types.
			continue
		}

		// Now that we have the address, we'll look up which account it
		// belongs to.
		scope, accNum, err := w.addrStore.AddrAccount(addrmgrNs, addr)
		if err != nil {
			log.Errorf("Unable to query account using address %v: "+
				"%v", addr, err)

			continue
		}

		// If a scope filter was provided, apply it now.
		if filter.scope != nil {
			if scope.Scope() != *filter.scope {
				continue
			}
		}

		// We'll use a nested map to store balances. If this is the
		// first time we've seen this key scope, we'll need to
		// initialize the inner map.
		keyScope := scope.Scope()
		if _, ok := scopedBalances[keyScope]; !ok {
			scopedBalances[keyScope] = make(
				map[uint32]btcutil.Amount,
			)
		}

		// Finally, we'll add the UTXO's value to the account's
		// balance.
		scopedBalances[keyScope][accNum] += utxo.Amount
	}

	return scopedBalances, nil
}

// listAccountsWithBalances is a helper function that iterates through all
// accounts in a given scope, fetches their properties, and combines them with
// the provided account balances.
//
// This function is designed to be called after the balances for all relevant
// accounts have already been computed by a function like fetchAccountBalances.
// It serves as the final step to assemble the complete AccountResult objects.
//
// The function operates as follows:
//  1. It determines the last account number for the given scope.
//  2. It iterates from account number 0 to the last account.
//  3. For each account, it retrieves its properties from the database.
//  4. It looks up the pre-calculated balance from the accountBalances map.
//  5. It constructs an AccountResult object with both the properties and the
//     balance.
//
// This separation of concerns (first calculating all balances, then assembling
// the results) is a key part of the overall optimization strategy. It ensures
// that we can efficiently gather all necessary data in distinct phases, rather
// than mixing database reads and balance calculations in a less efficient
// manner.
func listAccountsWithBalances(scopeMgr *waddrmgr.ScopedKeyManager,
	addrmgrNs walletdb.ReadBucket,
	accountBalances map[uint32]btcutil.Amount) ([]AccountResult, error) {

	var accounts []AccountResult

	lastAccount, err := scopeMgr.LastAccount(addrmgrNs)
	if err != nil {
		// If the scope has no accounts, we can just return an empty
		// slice. This is a normal condition and not an error.
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return nil, nil
		}

		return nil, err
	}

	// Iterate through all accounts from 0 to the last known account
	// number for this scope.
	for accNum := uint32(0); accNum <= lastAccount; accNum++ {
		// For each account number, we'll fetch its full set of
		// properties from the database.
		props, err := scopeMgr.AccountProperties(addrmgrNs, accNum)
		if err != nil {
			return nil, err
		}

		// We'll look up the pre-calculated balance for this account.
		// If the account has no UTXOs, it won't be in the map, so
		// we'll default to a balance of 0.
		balance, ok := accountBalances[accNum]
		if !ok {
			balance = 0
		}

		// Finally, we'll construct the full account result and add it
		// to our list.
		accounts = append(accounts, AccountResult{
			AccountProperties: *props,
			TotalBalance:      balance,
		})
	}

	return accounts, nil
}
