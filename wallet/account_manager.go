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
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/netparams"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// errNilAccountInfo is returned when accountInfoToProperties receives a nil
// snapshot.
var errNilAccountInfo = errors.New("nil account info")

// errDryRunImportNotSupported is returned when callers try the simulate-and-
// rollback dry-run on the new ImportAccount entrypoint.
var errDryRunImportNotSupported = errors.New(
	"ImportAccount: dry-run is not supported on the new account " +
		"manager; use Wallet.ImportAccountDryRun (deprecated)",
)

// toDBKeyScope adapts a waddrmgr.KeyScope to the db.KeyScope contract.
func toDBKeyScope(scope waddrmgr.KeyScope) db.KeyScope {
	return db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
}

// accountInfoToProperties converts a db.AccountInfo into the legacy
// waddrmgr.AccountProperties shape the public wallet API still returns.
func accountInfoToProperties(
	info *db.AccountInfo) (*waddrmgr.AccountProperties, error) {

	if info == nil {
		return nil, errNilAccountInfo
	}

	var pubKey *hdkeychain.ExtendedKey
	if len(info.PublicKey) > 0 {
		parsed, err := hdkeychain.NewKeyFromString(
			string(info.PublicKey),
		)
		if err != nil {
			return nil, fmt.Errorf("parse account pub key: %w",
				err)
		}

		pubKey = parsed
	}

	return &waddrmgr.AccountProperties{
		AccountNumber:        info.AccountNumber,
		AccountName:          info.AccountName,
		ExternalKeyCount:     info.ExternalKeyCount,
		InternalKeyCount:     info.InternalKeyCount,
		ImportedKeyCount:     info.ImportedKeyCount,
		AccountPubKey:        pubKey,
		MasterKeyFingerprint: info.MasterKeyFingerprint,
		KeyScope: waddrmgr.KeyScope{
			Purpose: info.KeyScope.Purpose,
			Coin:    info.KeyScope.Coin,
		},
		IsWatchOnly: info.IsWatchOnly,
	}, nil
}

// buildAccountDeriveFn pre-loads the wallet's master HD private key and
// returns an AccountDerivationFunc closure. Watch-only wallets get a closure
// that rejects derivation.
func (w *Wallet) buildAccountDeriveFn(
	ctx context.Context) (db.AccountDerivationFunc, error) {

	if w.addrStore.WatchOnly() {
		return func(_ context.Context, _ db.KeyScope, _ uint32,
			_ bool) (*db.DerivedAccountData, error) {

			return nil, errWatchOnlyAccountDerivation
		}, nil
	}

	encrypted, err := w.store.GetEncryptedHDSeed(ctx, w.id)
	if err != nil {
		return nil, fmt.Errorf("load encrypted master HD priv: %w",
			err)
	}

	plaintext, err := w.keyVault.Decrypt(waddrmgr.CKTPrivate, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt master HD priv: %w", err)
	}

	masterKey, err := hdkeychain.NewKeyFromString(string(plaintext))
	zero.Bytes(plaintext)

	if err != nil {
		return nil, fmt.Errorf("parse master HD priv: %w", err)
	}

	fingerprint, err := masterKeyFingerprint(masterKey)
	if err != nil {
		return nil, fmt.Errorf("master key fingerprint: %w", err)
	}

	return newAccountDeriveFn(masterKey, w.keyVault, fingerprint), nil
}

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
	Balance(ctx context.Context, conf uint32, scope waddrmgr.KeyScope,
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
func (w *Wallet) NewAccount(ctx context.Context, scope waddrmgr.KeyScope,
	name string) (*waddrmgr.AccountProperties, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	deriveFn, err := w.buildAccountDeriveFn(ctx)
	if err != nil {
		return nil, err
	}

	info, err := w.store.CreateDerivedAccount(ctx,
		db.CreateDerivedAccountParams{
			WalletID: w.id,
			Scope:    toDBKeyScope(scope),
			Name:     name,
		}, deriveFn,
	)
	if err != nil {
		// Preserve the legacy waddrmgr.ManagerError contract so that
		// callers using waddrmgr.IsError(err, ...) keep working after
		// kvdb wraps the underlying manager error via fmt.Errorf.
		var mErr waddrmgr.ManagerError
		if errors.As(err, &mErr) {
			return nil, mErr
		}

		return nil, err
	}

	return accountInfoToProperties(info)
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

// ListAccounts returns every account across all key scopes with its balance.
func (w *Wallet) ListAccounts(ctx context.Context) (*AccountsResult, error) {
	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	return w.assembleAccountsResult(ctx, db.ListAccountsQuery{
		WalletID: w.id,
	})
}

// assembleAccountsResult pairs cache.ListAccounts snapshots with the
// balance fields the SQL backend now populates on each AccountInfo for
// the wallet's list-style account APIs.
func (w *Wallet) assembleAccountsResult(ctx context.Context,
	query db.ListAccountsQuery) (*AccountsResult, error) {

	infos, err := w.cache.ListAccounts(ctx, query)
	if err != nil {
		return nil, err
	}

	results := make([]AccountResult, 0, len(infos))
	for i := range infos {
		props, err := accountInfoToProperties(&infos[i])
		if err != nil {
			return nil, err
		}

		results = append(results, AccountResult{
			AccountProperties: *props,
			TotalBalance: infos[i].ConfirmedBalance +
				infos[i].UnconfirmedBalance,
		})
	}

	syncBlock := w.addrStore.SyncedTo()

	return &AccountsResult{
		Accounts:           results,
		CurrentBlockHash:   syncBlock.Hash,
		CurrentBlockHeight: syncBlock.Height,
	}, nil
}

// ListAccountsByScope returns all accounts for the given key scope.
func (w *Wallet) ListAccountsByScope(ctx context.Context,
	scope waddrmgr.KeyScope) (*AccountsResult, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	dbScope := toDBKeyScope(scope)

	_, err = w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	return w.assembleAccountsResult(ctx, db.ListAccountsQuery{
		WalletID: w.id,
		Scope:    &dbScope,
	})
}

// ListAccountsByName returns every account matching name across all scopes.
func (w *Wallet) ListAccountsByName(ctx context.Context,
	name string) (*AccountsResult, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	return w.assembleAccountsResult(ctx, db.ListAccountsQuery{
		WalletID: w.id,
		Name:     &name,
	})
}

// GetAccount returns the account for a given account name and key scope.
//
// The function first looks up the account's properties and then calculates its
// balance by iterating over the wallet's UTXO set.
//
// The time complexity of this method is O(U*logA), where U is the number of
// UTXOs and logA is the cost of an account lookup.
func (w *Wallet) GetAccount(ctx context.Context, scope waddrmgr.KeyScope,
	name string) (*AccountResult, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	info, err := w.cache.GetAccount(ctx, db.GetAccountQuery{
		WalletID: w.id,
		Scope:    toDBKeyScope(scope),
		Name:     &name,
	})
	if err != nil {
		return nil, err
	}

	props, err := accountInfoToProperties(info)
	if err != nil {
		return nil, err
	}

	minConfs := int32(0)
	dbScope := toDBKeyScope(scope)

	result, err := w.store.Balance(ctx, db.BalanceParams{
		WalletID: w.id,
		Scope:    &dbScope,
		Account:  &info.AccountNumber,
		MinConfs: &minConfs,
	})
	if err != nil {
		return nil, err
	}

	return &AccountResult{
		AccountProperties: *props,
		TotalBalance:      result.Total,
	}, nil
}

// RenameAccount renames an existing account. The new name must be unique within
// the same key scope. The reserved "imported" account cannot be renamed.
//
// The time complexity of this method is dominated by the database lookup for
// the old account name.
func (w *Wallet) RenameAccount(ctx context.Context,
	scope waddrmgr.KeyScope, oldName, newName string) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	err = waddrmgr.ValidateAccountName(newName)
	if err != nil {
		return err
	}

	return w.store.RenameAccount(ctx, db.RenameAccountParams{
		WalletID: w.id,
		Scope:    toDBKeyScope(scope),
		OldName:  oldName,
		NewName:  newName,
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
func (w *Wallet) Balance(ctx context.Context, conf uint32,
	scope waddrmgr.KeyScope, name string) (btcutil.Amount, error) {

	err := w.state.validateStarted()
	if err != nil {
		return 0, err
	}

	info, err := w.cache.GetAccount(ctx, db.GetAccountQuery{
		WalletID: w.id,
		Scope:    toDBKeyScope(scope),
		Name:     &name,
	})
	if err != nil {
		return 0, err
	}

	if conf > math.MaxInt32 {
		return 0, nil
	}

	minConfs := int32(conf)
	dbScope := toDBKeyScope(scope)

	result, err := w.store.Balance(ctx, db.BalanceParams{
		WalletID: w.id,
		Scope:    &dbScope,
		Account:  &info.AccountNumber,
		MinConfs: &minConfs,
	})
	if err != nil {
		return 0, err
	}

	return result.Total, nil
}

// ImportAccount imports an account from an extended public or private key. The
// key scope is derived from the version bytes of the extended key. The account
// name must be unique within the derived scope. If dryRun is true, the import
// is validated but not persisted.
//
// The time complexity of this method is dominated by the database lookup to
// ensure the account name is unique within the scope.
func (w *Wallet) ImportAccount(ctx context.Context,
	name string, accountKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrType waddrmgr.AddressType,
	dryRun bool) (*waddrmgr.AccountProperties, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	return w.importAccountInternal(
		ctx, name, accountKey, masterKeyFingerprint, addrType, dryRun,
	)
}

// importAccountInternal is the internal implementation of ImportAccount,
// allowing Manager.Create to bypass the started check.
//
// dryRun is not supported on the new path; callers that need
// simulate-and-rollback should use Wallet.ImportAccountDryRun (deprecated)
// which still operates directly on waddrmgr buckets.
func (w *Wallet) importAccountInternal(ctx context.Context,
	name string, accountKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrType waddrmgr.AddressType,
	dryRun bool) (*waddrmgr.AccountProperties, error) {

	if dryRun {
		return nil, errDryRunImportNotSupported
	}

	err := validateExtendedPubKey(
		accountKey, true, w.cfg.ChainParams,
	)
	if err != nil {
		return nil, err
	}

	keyScope, _, err := keyScopeFromPubKey(accountKey, &addrType)
	if err != nil {
		return nil, err
	}

	info, err := w.store.CreateImportedAccount(ctx,
		db.CreateImportedAccountParams{
			WalletID:          w.id,
			Name:              name,
			Scope:             toDBKeyScope(keyScope),
			MasterFingerprint: masterKeyFingerprint,
			PublicKey:         []byte(accountKey.String()),
		},
	)
	if err != nil {
		// Preserve waddrmgr.ManagerError semantics so callers using
		// waddrmgr.IsError(err, ...) keep working when kvdb wraps the
		// underlying manager error via fmt.Errorf.
		var mErr waddrmgr.ManagerError
		if errors.As(err, &mErr) {
			return nil, mErr
		}

		return nil, err
	}

	return accountInfoToProperties(info)
}

// validateExtendedPubKey ensures a sane derived public key is provided.
func validateExtendedPubKey(pubKey *hdkeychain.ExtendedKey,
	isAccountKey bool, chainParams *chaincfg.Params) error {

	// Private keys are not allowed.
	if pubKey.IsPrivate() {
		return fmt.Errorf("%w: private keys cannot be imported",
			ErrInvalidAccountKey)
	}

	// The public key must have a version corresponding to the current
	// chain.
	if !isPubKeyForNet(pubKey, chainParams) {
		return fmt.Errorf("%w: expected extended public key for current "+
			"network %v", ErrInvalidAccountKey, chainParams.Name)
	}

	// Verify the extended public key's depth and child index based on
	// whether it's an account key or not.
	if isAccountKey {
		if pubKey.Depth() != accountPubKeyDepth {
			return fmt.Errorf("%w: must be of the form "+
				"m/purpose'/coin_type'/account'", ErrInvalidAccountKey)
		}

		if pubKey.ChildIndex() < hdkeychain.HardenedKeyStart {
			return fmt.Errorf("%w: must be hardened", ErrInvalidAccountKey)
		}

		return nil
	}

	if pubKey.Depth() != pubKeyDepth {
		return fmt.Errorf("%w: must be of the form "+
			"m/purpose'/coin_type'/account'/change/address_index",
			ErrInvalidAccountKey)
	}

	if pubKey.ChildIndex() >= hdkeychain.HardenedKeyStart {
		return fmt.Errorf("%w: must not be hardened", ErrInvalidAccountKey)
	}

	return nil
}

// isPubKeyForNet determines if the given public key is for the current network
// the wallet is operating under.
//
// Ignore exhaustive linter as the `wire.SigNet` is covered by `SigNetWire`.
//
//nolint:exhaustive,cyclop
func isPubKeyForNet(pubKey *hdkeychain.ExtendedKey,
	chainParams *chaincfg.Params) bool {

	version := waddrmgr.HDVersion(binary.BigEndian.Uint32(pubKey.Version()))
	switch chainParams.Net {
	case wire.MainNet:
		return version == waddrmgr.HDVersionMainNetBIP0044 ||
			version == waddrmgr.HDVersionMainNetBIP0049 ||
			version == waddrmgr.HDVersionMainNetBIP0084

	case wire.TestNet, wire.TestNet3, wire.TestNet4,
		netparams.SigNetWire(chainParams):

		return version == waddrmgr.HDVersionTestNetBIP0044 ||
			version == waddrmgr.HDVersionTestNetBIP0049 ||
			version == waddrmgr.HDVersionTestNetBIP0084

	// For simnet, we'll also allow the mainnet versions since simnet
	// doesn't have defined versions for some of our key scopes, and the
	// mainnet versions are usually used as the default regardless of the
	// network/key scope.
	case wire.SimNet:
		return version == waddrmgr.HDVersionSimNetBIP0044 ||
			version == waddrmgr.HDVersionMainNetBIP0049 ||
			version == waddrmgr.HDVersionMainNetBIP0084

	default:
		return false
	}
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
