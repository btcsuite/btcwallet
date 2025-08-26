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
		accountName string) (btcutil.Amount, error)

	// ImportAccount imports an account from an extended public or private
	// key. The key scope is derived from the version bytes of the
	// extended key. The account name must be unique within the derived
	// scope. If dryRun is true, the import is validated but not persisted.
	ImportAccount(ctx context.Context, name string,
		accountKey *hdkeychain.ExtendedKey,
		masterKeyFingerprint uint32, addrType waddrmgr.AddressType,
		dryRun bool) (*waddrmgr.AccountProperties, error)
}

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
		accountID, err := manager.NewAccount(addrmgrNs, name)
		if err != nil {
			return err
		}

		// Get the account's properties.
		props, err = manager.AccountProperties(addrmgrNs, accountID)
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
				// We'll log the error and skip this UTXO. This
				// is to prevent a single un-parsable UTXO from
				// failing the entire call, which would be a
				// poor user experience.
				log.Errorf("Unable to parse pkscript for UTXO "+
					"%v: %v", utxo.OutPoint, err)
				continue
			}

			// This can happen for scripts that don't resolve to a
			// standard address, such as OP_RETURN outputs. We can
			// safely ignore these.
			if len(addrs) == 0 {
				continue
			}

			// TODO(yy): For bare multisig outputs,
			// ExtractPkScriptAddrs can return more than one
			// address. Currently, we are only considering the
			// first address, which could lead to incorrect balance
			// attribution. However, since bare multisig is rare
			// and modern wallets almost exclusively use P2SH or
			// P2WSH for multisig (which are correctly handled as a
			// single address), this is a low-priority issue.
			//
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
// balances for all addresses with unspent outputs and then iterating
//
// through all known accounts to tally up their final balances.
// UTXOs and A is the number of addresses in the wallet. This is a significant
// UTXOs and A is the number of addresses in the wallet. This is a
// significant improvement over a naive implementation that would have a
//
// complexity of O(U * A), e.g., the old `Accounts` method.
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
				// We'll log the error and skip this UTXO. This
				// is to prevent a single un-parsable UTXO from
				// failing the entire call, which would be a
				// poor user experience.
				log.Errorf("Unable to parse pkscript for UTXO "+
					"%v: %v", utxo.OutPoint, err)
				continue
			}

			// This can happen for scripts that don't resolve to a
			// standard address, such as OP_RETURN outputs. We can
			// safely ignore these.
			if len(addrs) == 0 {
				continue
			}

			// TODO(yy): For bare multisig outputs,
			// ExtractPkScriptAddrs can return more than one
			// address. Currently, we are only considering the
			// first address, which could lead to incorrect balance
			// attribution. However, since bare multisig is rare
			// and modern wallets almost exclusively use P2SH or
			// P2WSH for multisig (which are correctly handled as a
			// single address), this is a low-priority issue.
			//
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
// balances for all addresses with unspent outputs and then iterating
// through all known accounts to tally up their final balances.
//
// The time complexity of this method is O(U + A), where U is the number of
// UTXOs and A is the number of addresses in the wallet. This is a
// significant improvement over a naive implementation that would have a
// complexity of O(U * A), e.g., the old `Accounts` method.
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
				// We'll log the error and skip this UTXO. This
				// is to prevent a single un-parsable UTXO from
				// failing the entire call, which would be a
				// poor user experience.
				log.Errorf("Unable to parse pkscript for UTXO "+
					"%v: %v", utxo.OutPoint, err)
				continue
			}

			// This can happen for scripts that don't resolve to a
			// standard address, such as OP_RETURN outputs. We can
			// safely ignore these.
			if len(addrs) == 0 {
				continue
			}

			// TODO(yy): For bare multisig outputs,
			// ExtractPkScriptAddrs can return more than one
			// address. Currently, we are only considering the
			// first address, which could lead to incorrect balance
			// attribution. However, since bare multisig is rare
			// and modern wallets almost exclusively use P2SH or
			// P2WSH for multisig (which are correctly handled as a
			// single address), this is a low-priority issue.
			//
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
