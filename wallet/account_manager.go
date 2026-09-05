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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/netparams"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/addresstype"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
)

var (
	// ErrAccountAlreadyExists is returned when an account operation would
	// take a name that is already used within the same key scope. Renaming
	// an account to its current name reports the same outcome.
	ErrAccountAlreadyExists = errors.New("account already exists")

	// ErrAccountOperationUnsupported is returned when the requested account
	// operation cannot be served by the wallet in its current mode, such as
	// deriving a new account on a watch-only wallet or importing an
	// XPub-only account into a spendable SQL wallet.
	ErrAccountOperationUnsupported = errors.New(
		"account operation unsupported by this wallet",
	)

	// ErrAccountDerivationExhausted is returned when a key scope has no
	// account number left to allocate.
	ErrAccountDerivationExhausted = errors.New(
		"account derivation range exhausted",
	)
)

// accountManagerErr preserves diagnostic text while exposing only the wallet
// identity for a supported outcome. Unclassified errors retain no identity;
// cancellation and deadlines retain their caller-owned identities.
func accountManagerErr(err error) error {
	if err == nil {
		return nil
	}

	contextErr := accountManagerContextErr(err)
	if contextErr != nil {
		return contextErr
	}

	switch {
	case errors.Is(err, db.ErrAccountNotFound),
		errors.Is(err, db.ErrKeyScopeNotFound),
		isManagerErr(err, waddrmgr.ErrAccountNotFound),
		isManagerErr(err, waddrmgr.ErrScopeNotFound):

		return accountErr(ErrAccountNotFound, err.Error())

	case dberr.IsAccountNameConflict(err),
		isManagerErr(err, waddrmgr.ErrDuplicateAccount),
		isManagerErr(err, waddrmgr.ErrAlreadyExists):

		return accountErr(ErrAccountAlreadyExists, err.Error())

	case errors.Is(err, errWatchOnlyAccountDerivation),
		errors.Is(err, db.ErrWatchOnlyViolation),
		errors.Is(err, db.ErrSpendableWalletNeedsAccountPrivKey),
		isManagerErr(err, waddrmgr.ErrWatchingOnly):

		return accountErr(ErrAccountOperationUnsupported, err.Error())

	case errors.Is(err, db.ErrMaxAccountNumberReached),
		isManagerErr(err, waddrmgr.ErrAccountNumTooHigh):

		return accountErr(ErrAccountDerivationExhausted, err.Error())

	case errors.Is(err, keyvault.ErrVaultLocked),
		isManagerErr(err, waddrmgr.ErrLocked):

		return accountErr(ErrStateForbidden, err.Error())

	case isInvalidAccountRequest(err):
		return accountErr(ErrInvalidParam, err.Error())

	default:
		return errors.New(err.Error())
	}
}

// accountManagerContextErr preserves a caller's cancellation identity while
// scrubbing any backend identity that may have been joined to it.
func accountManagerContextErr(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return accountErr(context.Canceled, err.Error())

	case errors.Is(err, context.DeadlineExceeded):
		return accountErr(context.DeadlineExceeded, err.Error())

	default:
		return nil
	}
}

// isManagerErr reports whether err carries a waddrmgr.ManagerError with the
// given code. waddrmgr.IsError is a bare type assertion, so it cannot see a
// manager error that a store wrapped for context — which is how the legacy
// backend returns every one of them.
func isManagerErr(err error, code waddrmgr.ErrorCode) bool {
	var mErr waddrmgr.ManagerError
	if !errors.As(err, &mErr) {
		return false
	}

	return mErr.ErrorCode == code
}

// isInvalidAccountRequest reports whether err describes a request the store
// refused to even attempt: a missing, reserved, or malformed field, or a
// selector combination that identifies no single account.
func isInvalidAccountRequest(err error) bool {
	switch {
	case errors.Is(err, db.ErrMissingAccountName),
		errors.Is(err, db.ErrMissingAccountPublicKey),
		errors.Is(err, db.ErrMissingField),
		errors.Is(err, db.ErrInvalidParam),
		errors.Is(err, db.ErrReservedAccountName),
		errors.Is(err, db.ErrInvalidAccountQuery),
		errors.Is(err, db.ErrUnknownKeyScope):

		return true

	// waddrmgr reports every account-name rule violation, including the
	// reserved and empty-name cases, under this one code.
	case isManagerErr(err, waddrmgr.ErrInvalidAccount):
		return true

	default:
		return false
	}
}

// accountErr joins a public identity with diagnostic text. Accepting text
// rather than the source error prevents an internal identity from being
// wrapped across the AccountManager boundary.
func accountErr(identity error, diagnostic string) error {
	if diagnostic == identity.Error() {
		return identity
	}

	return fmt.Errorf("%w: %s", identity, diagnostic)
}

// buildAccountDeriveFn returns an AccountDerivationFunc closure. Spendable
// wallets normally preload the master HD private key before the store opens
// its write transaction. Neutered-root kvdb wallets are the exception: they
// need to defer a missing-root-key error to the store callback so kvdb can
// derive from the scoped coin-type key inside its walletdb transaction.
func (w *Wallet) buildAccountDeriveFn(
	ctx context.Context) (db.AccountDerivationFunc, error) {

	if w.IsWatchOnly() {
		return func(_ context.Context, _ db.KeyScope, _ uint32,
			_ bool) (*db.DerivedAccountData, error) {

			return nil, errWatchOnlyAccountDerivation
		}, nil
	}

	encrypted, err := w.store.GetEncryptedHDSeed(ctx, w.id)
	switch {
	case err == nil:

	case errors.Is(err, db.ErrSecretNotFound):
		return func(_ context.Context, _ db.KeyScope, _ uint32,
			_ bool) (*db.DerivedAccountData, error) {

			return nil, fmt.Errorf("load encrypted master HD priv: %w",
				err)
		}, nil

	default:
		return nil, fmt.Errorf("load encrypted master HD priv: %w", err)
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
//
// # Errors
//
// Named failures are reported through wallet-owned sentinels —
// ErrAccountNotFound, ErrAccountAlreadyExists,
// ErrAccountOperationUnsupported, ErrAccountDerivationExhausted,
// ErrInvalidParam and ErrStateForbidden — so callers match on the wallet
// contract rather than on whichever store backend happens to be mounted. An
// outcome the contract does not name matches no stable sentinel and carries
// its diagnostic text alone. Either way no store or waddrmgr error identity
// crosses this surface, context cancellation excepted, since that identity
// belongs to the caller.
type AccountManager interface {
	// NewAccount creates a new account for a given key scope and name. The
	// provided name must be unique within that key scope.
	NewAccount(ctx context.Context, scope waddrmgr.KeyScope, name string) (
		*AccountInfo, error)

	// ListAccounts returns a list of all accounts managed by the wallet.
	ListAccounts(ctx context.Context) ([]AccountInfo, error)

	// ListAccountsByScope returns a list of all accounts for a given key
	// scope.
	ListAccountsByScope(ctx context.Context, scope waddrmgr.KeyScope) (
		[]AccountInfo, error)

	// ListAccountsByName searches for accounts with the given name across
	// all key scopes. Because names are not globally unique, this may
	// return multiple results.
	ListAccountsByName(ctx context.Context, name string) (
		[]AccountInfo, error)

	// GetAccount returns the snapshot for a specific account, looked up
	// by its key scope and unique name within that scope.
	GetAccount(ctx context.Context, scope waddrmgr.KeyScope, name string) (
		*AccountInfo, error)

	// RenameAccount renames an existing account. To uniquely identify the
	// account, the key scope must be provided. The new name must be unique
	// within that same key scope, including against the account's own
	// current name. The reserved "imported" account cannot be renamed.
	RenameAccount(ctx context.Context, scope waddrmgr.KeyScope,
		oldName string, newName string) error

	// ImportAccount imports an account from an extended public key.
	// Private extended keys are rejected. The key scope is derived from
	// the version bytes of the extended key. The account name must be
	// unique within the derived scope. If dryRun is true, the import is
	// validated but not persisted. SQL wallets accept this XPub-only
	// material only when the wallet is watch-only under ADR 0012. The
	// legacy kvdb backend retains its grandfathered mixed-mode import
	// behavior until migration; neither path imports signing material.
	ImportAccount(ctx context.Context, name string,
		accountKey *hdkeychain.ExtendedKey,
		masterKeyFingerprint uint32, addrType waddrmgr.AddressType,
		dryRun bool) (*AccountInfo, error)
}

// A compile time check to ensure that Wallet implements the interface.
var _ AccountManager = (*Wallet)(nil)

// canonicalStoreAccountInfo returns an internal Store snapshot whose derived
// account fingerprint comes from the Wallet cache. Legacy Store snapshots can
// contain an absent, zero, or stale fingerprint, while w.masterFingerprint is
// loaded from the wallet's master HD public key and is canonical.
func (w *Wallet) canonicalStoreAccountInfo(
	storeInfo db.AccountInfo) db.AccountInfo {

	if storeInfo.IsImported {
		return storeInfo
	}

	fingerprint := w.masterFingerprint
	storeInfo.MasterKeyFingerprint = &fingerprint

	return storeInfo
}

// accountInfoFromStore converts one Store account snapshot into the public
// wallet-owned result. Every pointer and byte slice in the result is copied so
// callers cannot mutate Store-owned data or another independently converted
// result.
//
// Its failures are internal identities such as addresstype.ErrUnknown, so
// public callers route the result through accountManagerErr rather than
// returning it directly.
func (w *Wallet) accountInfoFromStore(
	storeInfo *db.AccountInfo) (*AccountInfo, error) {

	if storeInfo == nil {
		return nil, errors.New("store account info is nil")
	}

	canonicalStoreInfo := w.canonicalStoreAccountInfo(*storeInfo)
	storeInfo = &canonicalStoreInfo

	externalAddrType, err := addresstype.ToWallet(
		storeInfo.AddrSchema.ExternalAddrType, false,
	)
	if err != nil {
		return nil, fmt.Errorf("external account address schema: %w", err)
	}

	internalAddrType, err := addresstype.ToWallet(
		storeInfo.AddrSchema.InternalAddrType, false,
	)
	if err != nil {
		return nil, fmt.Errorf("internal account address schema: %w", err)
	}

	var accountNumber *AccountNumber
	if storeInfo.AccountNumber != nil {
		number := AccountNumber(*storeInfo.AccountNumber)
		accountNumber = &number
	}

	var masterFingerprint *MasterFingerprint
	if storeInfo.MasterKeyFingerprint != nil {
		fingerprint := MasterFingerprint(*storeInfo.MasterKeyFingerprint)
		masterFingerprint = &fingerprint
	}

	return &AccountInfo{
		AccountNumber:      accountNumber,
		AccountName:        storeInfo.AccountName,
		IsImported:         storeInfo.IsImported,
		ExternalKeyCount:   storeInfo.ExternalKeyCount,
		InternalKeyCount:   storeInfo.InternalKeyCount,
		ImportedKeyCount:   storeInfo.ImportedKeyCount,
		ConfirmedBalance:   storeInfo.ConfirmedBalance,
		UnconfirmedBalance: storeInfo.UnconfirmedBalance,
		IsWatchOnly:        storeInfo.IsWatchOnly,
		CreatedAt:          storeInfo.CreatedAt,
		KeyScope:           waddrmgr.KeyScope(storeInfo.KeyScope),
		AddrSchema: waddrmgr.ScopeAddrSchema{
			ExternalAddrType: externalAddrType,
			InternalAddrType: internalAddrType,
		},
		PublicKey:            bytes.Clone(storeInfo.PublicKey),
		MasterKeyFingerprint: masterFingerprint,
	}, nil
}

// NewAccount creates the next account and returns its account info. The name
// must be unique under the key scope. In order to support automatic seed
// restoring, new accounts may not be created when all of the previous 100
// accounts have no transaction history (this is a deviation from the BIP0044
// spec, which allows no unused account gaps).
func (w *Wallet) NewAccount(ctx context.Context, scope waddrmgr.KeyScope,
	name string) (*AccountInfo, error) {

	err := w.validateNewAccountRequest(ctx, scope, name)
	if err != nil {
		return nil, err
	}

	deriveFn, err := w.buildAccountDeriveFn(ctx)
	if err != nil {
		return nil, accountManagerErr(err)
	}

	info, err := w.store.CreateDerivedAccount(ctx,
		db.CreateDerivedAccountParams{
			WalletID: w.id,
			Scope:    db.KeyScope(scope),
			Name:     name,
		}, deriveFn,
	)
	if err != nil {
		return nil, accountManagerErr(err)
	}

	result, err := w.accountInfoFromStore(info)
	if err != nil {
		return nil, accountManagerErr(err)
	}

	return result, nil
}

// validateNewAccountRequest fixes admission precedence before derivation or
// mutation: caller and request errors win first, followed by lock state, name
// collisions, and finally the watch-only restriction.
func (w *Wallet) validateNewAccountRequest(ctx context.Context,
	scope waddrmgr.KeyScope, name string) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	// The watch-only refusal below short-circuits every ctx-aware and
	// request-shape step the store would otherwise run, so both are
	// answered first: a caller that cancelled must hear about the
	// cancellation, and a malformed request is malformed whether or not
	// the wallet could have served a well-formed one.
	err = ctx.Err()
	if err != nil {
		return err
	}

	err = waddrmgr.ValidateAccountName(name)
	if err != nil {
		return accountManagerErr(err)
	}

	// A spendable wallet must reject its already-locked state before reading
	// encrypted seed material. If it locks after this check, NewAccount still
	// translates a Vault preparation failure.
	if !w.IsWatchOnly() && w.keyVault.IsLocked() {
		return fmt.Errorf("%w: wallet is locked", ErrStateForbidden)
	}

	err = w.ensureAccountNameAvailable(ctx, scope, name)
	if err != nil {
		return err
	}

	// Refuse before the store is touched. Hardened derivation along
	// m/purpose'/coin'/account' needs the master HD private key, which a
	// watch-only wallet does not hold, and the backends otherwise refuse at
	// different points: the SQL stores reach the derivation callback while a
	// rootless legacy wallet fails its scope lookup first and would report a
	// missing account instead.
	if w.IsWatchOnly() {
		return accountManagerErr(errWatchOnlyAccountDerivation)
	}

	return nil
}

// propertiesToAccountInfo wraps a waddrmgr.AccountProperties + total balance
// into the internal Store snapshot shape converted at the Wallet boundary.
// The legacy waddrmgr path does not separate confirmed/unconfirmed balances,
// so the supplied total is reported on ConfirmedBalance; UnconfirmedBalance
// stays zero. For derived accounts, wallet-level watch-only and
// master-fingerprint state takes precedence over lock-state-dependent
// waddrmgr account properties.
func propertiesToAccountInfo(props *waddrmgr.AccountProperties,
	total btcutil.Amount, isImported bool, walletWatchOnly bool,
	masterFingerprint uint32) db.AccountInfo {

	var pubKey []byte
	if props.AccountPubKey != nil {
		pubKey = []byte(props.AccountPubKey.String())
	}

	var accountNumber *uint32
	if !isImported {
		accountNumber = &props.AccountNumber
	}

	isWatchOnly := walletWatchOnly

	fingerprint := props.MasterKeyFingerprint
	if masterFingerprint != 0 {
		fingerprint = masterFingerprint
	}

	if isImported {
		isWatchOnly = walletWatchOnly || props.IsWatchOnly

		// Imported accounts are not derived from the wallet seed, so their
		// waddrmgr fingerprint takes precedence over the cached seed value.
		fingerprint = props.MasterKeyFingerprint
	}

	var fingerprintResult *uint32
	// AccountPubKey distinguishes an imported XPub, whose fingerprint is
	// present, from the keyless imported-address pseudo-account.
	if !isImported || props.AccountPubKey != nil {
		fingerprintResult = &fingerprint
	}

	scope := db.KeyScope(props.KeyScope)
	addrSchema := db.ScopeAddrMap[scope]

	if props.AddrSchema != nil {
		override, err := db.ScopeAddrSchemaFromWaddrmgr(*props.AddrSchema)
		if err != nil {
			log.Errorf("propertiesToAccountInfo: skipping invalid "+
				"AddrSchema override (%v); falling back to scope "+
				"default", err)
		} else {
			addrSchema = override
		}
	}

	return db.AccountInfo{
		AccountNumber:        accountNumber,
		AccountName:          props.AccountName,
		IsImported:           isImported,
		ExternalKeyCount:     props.ExternalKeyCount,
		InternalKeyCount:     props.InternalKeyCount,
		ImportedKeyCount:     props.ImportedKeyCount,
		IsWatchOnly:          isWatchOnly,
		KeyScope:             scope,
		AddrSchema:           addrSchema,
		PublicKey:            pubKey,
		MasterKeyFingerprint: fingerprintResult,
		ConfirmedBalance:     total,
	}
}

// ListAccounts returns every account across all key scopes with its balance.
func (w *Wallet) ListAccounts(ctx context.Context) ([]AccountInfo, error) {
	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	return w.listAccountInfos(ctx, db.ListAccountsQuery{
		WalletID: w.id,
	})
}

// listAccountInfos converts cache.ListAccounts snapshots into wallet-owned
// results while preserving a nil Store slice.
func (w *Wallet) listAccountInfos(ctx context.Context,
	query db.ListAccountsQuery) ([]AccountInfo, error) {

	infos, err := w.cache.ListAccounts(ctx, query)
	if err != nil {
		return nil, accountManagerErr(err)
	}

	if infos == nil {
		return nil, nil
	}

	results := make([]AccountInfo, len(infos))
	for i := range infos {
		result, err := w.accountInfoFromStore(&infos[i])
		if err != nil {
			return nil, accountManagerErr(err)
		}

		results[i] = *result
	}

	return results, nil
}

// ListAccountsByScope returns all accounts for the given key scope.
func (w *Wallet) ListAccountsByScope(ctx context.Context,
	scope waddrmgr.KeyScope) ([]AccountInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	dbScope := db.KeyScope(scope)

	return w.listAccountInfos(ctx, db.ListAccountsQuery{
		WalletID: w.id,
		Scope:    &dbScope,
	})
}

// ListAccountsByName returns every account matching name across all scopes.
func (w *Wallet) ListAccountsByName(ctx context.Context,
	name string) ([]AccountInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	return w.listAccountInfos(ctx, db.ListAccountsQuery{
		WalletID: w.id,
		Name:     &name,
	})
}

// GetAccount returns the account for a given account name and key scope.
// The account snapshot, including the running balance, is fetched in a
// single Store read.
func (w *Wallet) GetAccount(ctx context.Context, scope waddrmgr.KeyScope,
	name string) (*AccountInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	info, err := w.cache.GetAccount(ctx, db.GetAccountQuery{
		WalletID: w.id,
		Scope:    db.KeyScope(scope),
		Name:     &name,
	})
	if err != nil {
		return nil, accountManagerErr(err)
	}

	result, err := w.accountInfoFromStore(info)
	if err != nil {
		return nil, accountManagerErr(err)
	}

	return result, nil
}

// selfRenameErr reports the outcome of a rename whose old and new names match.
// A name conflict presumes the account exists, so an absent account is still
// reported as missing rather than being masked by the conflict.
func (w *Wallet) selfRenameErr(ctx context.Context, scope waddrmgr.KeyScope,
	name string) error {

	// SkipBalance keeps this to the single existence check the conflict
	// answer depends on; no balance is read and nothing is mutated.
	_, err := w.cache.GetAccount(ctx, db.GetAccountQuery{
		WalletID:    w.id,
		Scope:       db.KeyScope(scope),
		Name:        &name,
		SkipBalance: true,
	})
	if err != nil {
		return accountManagerErr(err)
	}

	return fmt.Errorf("%w: %q in scope %d/%d", ErrAccountAlreadyExists,
		name, scope.Purpose, scope.Coin)
}

// ensureAccountNameAvailable resolves occupied names before mutation. A racing
// writer can still cause a constraint error, translated at the public exit.
// A missing scope is available because creation may establish it later.
func (w *Wallet) ensureAccountNameAvailable(ctx context.Context,
	scope waddrmgr.KeyScope, name string) error {

	_, err := w.cache.GetAccount(ctx, db.GetAccountQuery{
		WalletID:    w.id,
		Scope:       db.KeyScope(scope),
		Name:        &name,
		SkipBalance: true,
	})
	switch {
	case err == nil:
		return fmt.Errorf("%w: %q in scope %d/%d",
			ErrAccountAlreadyExists, name, scope.Purpose, scope.Coin)

	case errors.Is(err, db.ErrAccountNotFound),
		errors.Is(err, db.ErrKeyScopeNotFound),
		isManagerErr(err, waddrmgr.ErrAccountNotFound),
		isManagerErr(err, waddrmgr.ErrScopeNotFound):

		return nil

	default:
		return accountManagerErr(err)
	}
}

// RenameAccount renames an existing account. The new name must be unique within
// the same key scope, so renaming an account to the name it already holds
// returns ErrAccountAlreadyExists. The reserved "imported" account cannot be
// renamed.
func (w *Wallet) RenameAccount(ctx context.Context,
	scope waddrmgr.KeyScope, oldName, newName string) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	err = ctx.Err()
	if err != nil {
		return err
	}

	err = waddrmgr.ValidateAccountName(oldName)
	if err != nil {
		return accountManagerErr(err)
	}

	err = waddrmgr.ValidateAccountName(newName)
	if err != nil {
		return accountManagerErr(err)
	}

	// Renaming an account to the name it already holds is a name conflict
	// with itself. The backends disagree on this shape: the legacy store
	// rejects it as a duplicate while the SQL stores update the row to its
	// current value and report success. Settle it here so the answer no
	// longer depends on which backend is mounted.
	if oldName == newName {
		return w.selfRenameErr(ctx, scope, newName)
	}

	err = w.ensureAccountNameAvailable(ctx, scope, newName)
	if err != nil {
		return err
	}

	err = w.store.RenameAccount(ctx, db.RenameAccountParams{
		WalletID: w.id,
		Scope:    db.KeyScope(scope),
		OldName:  oldName,
		NewName:  newName,
	})
	if err != nil {
		return accountManagerErr(err)
	}

	return nil
}

// ImportAccount imports an account from an extended public key. Private
// extended keys are rejected. The key scope is derived from the version
// bytes of the extended key. The account name must be unique within the
// derived scope.
//
// SQL wallets accept this XPub-only material only when the wallet is
// watch-only under ADR 0012. The legacy kvdb backend retains its grandfathered
// mixed-mode import behavior until migration; neither path imports signing
// material.
//
// dryRun=true validates the import through the store and rolls the transaction
// back; no account row is persisted.
//
// The time complexity of this method is dominated by the database lookup
// to ensure the account name is unique within the scope.
func (w *Wallet) ImportAccount(ctx context.Context,
	name string, accountKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrType waddrmgr.AddressType,
	dryRun bool) (*AccountInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	err = ctx.Err()
	if err != nil {
		return nil, err
	}

	err = waddrmgr.ValidateAccountName(name)
	if err != nil {
		return nil, accountManagerErr(err)
	}

	keyScope, dbAddrSchema, err := w.prepareImportedAccount(
		accountKey, addrType,
	)
	if err != nil {
		if errors.Is(err, ErrInvalidAccountKey) {
			return nil, err
		}

		return nil, accountErr(ErrInvalidParam, err.Error())
	}

	err = w.ensureAccountNameAvailable(ctx, keyScope, name)
	if err != nil {
		return nil, err
	}

	result, err := w.persistImportedAccount(
		ctx, name, accountKey, masterKeyFingerprint, keyScope, dbAddrSchema,
		dryRun,
	)
	if err != nil {
		return nil, accountManagerErr(err)
	}

	return result, nil
}

// importAccountInternal is the internal implementation of ImportAccount,
// allowing Manager.Create to bypass the started check.
func (w *Wallet) importAccountInternal(ctx context.Context,
	name string, accountKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrType waddrmgr.AddressType,
	dryRun bool) (*AccountInfo, error) {

	keyScope, dbAddrSchema, err := w.prepareImportedAccount(
		accountKey, addrType,
	)
	if err != nil {
		return nil, err
	}

	return w.persistImportedAccount(
		ctx, name, accountKey, masterKeyFingerprint, keyScope, dbAddrSchema,
		dryRun,
	)
}

// prepareImportedAccount validates an imported account key and converts its
// derived scope schema before either the public preflight or Store write runs.
func (w *Wallet) prepareImportedAccount(accountKey *hdkeychain.ExtendedKey,
	addrType waddrmgr.AddressType) (waddrmgr.KeyScope,
	*db.ScopeAddrSchema, error) {

	err := validateExtendedPubKey(
		accountKey, true, w.cfg.ChainParams,
	)
	if err != nil {
		return waddrmgr.KeyScope{}, nil, err
	}

	keyScope, addrSchema, err := keyScopeFromPubKey(
		accountKey, &addrType,
	)
	if err != nil {
		return waddrmgr.KeyScope{}, nil, err
	}

	dbAddrSchema, err := dbScopeAddrSchema(addrSchema)
	if err != nil {
		return waddrmgr.KeyScope{}, nil, err
	}

	return keyScope, dbAddrSchema, nil
}

// persistImportedAccount performs the Store write shared by public imports and
// Manager initialization. It leaves Store and conversion errors untranslated
// so only the public AccountManager method applies its error contract.
func (w *Wallet) persistImportedAccount(ctx context.Context, name string,
	accountKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32,
	keyScope waddrmgr.KeyScope, dbAddrSchema *db.ScopeAddrSchema,
	dryRun bool) (*AccountInfo, error) {

	info, err := w.store.CreateImportedAccount(ctx,
		db.CreateImportedAccountParams{
			WalletID:          w.id,
			Name:              name,
			Scope:             db.KeyScope(keyScope),
			MasterFingerprint: masterKeyFingerprint,
			PublicKey:         []byte(accountKey.String()),
			DryRun:            dryRun,
			AddrSchema:        dbAddrSchema,
		},
	)
	if err != nil {
		return nil, err
	}

	result, err := w.accountInfoFromStore(info)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// dbScopeAddrSchema converts a waddrmgr per-account address schema override
// into the account-store contract type.
//
// The waddrmgr and db AddressType enums share names but not ordinals (e.g.
// waddrmgr.PubKeyHash is 0 while db.RawPubKey is 0), so a direct cast would
// silently corrupt the stored schema. The explicit wallet->store mapping is
// used instead, matching propertiesToAccountInfo's derived-account schema
// conversion.
func dbScopeAddrSchema(
	schema *waddrmgr.ScopeAddrSchema) (*db.ScopeAddrSchema, error) {

	if schema == nil {
		// A nil schema means the account opts into the scope's default
		// address schema; nil value with a nil error is the intended
		// "no override" signal, not a missing-value bug.
		//nolint:nilnil
		return nil, nil
	}

	converted, err := db.ScopeAddrSchemaFromWaddrmgr(*schema)
	if err != nil {
		return nil, err
	}

	return &converted, nil
}

// validateExtendedPubKey ensures a sane derived public key is provided.
func validateExtendedPubKey(pubKey *hdkeychain.ExtendedKey,
	isAccountKey bool, chainParams *chaincfg.Params) error {

	// A nil key cannot be validated and would otherwise panic on the
	// IsPrivate call below.
	if pubKey == nil {
		return fmt.Errorf("%w: account key cannot be nil",
			ErrInvalidAccountKey)
	}

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
// The address.Address is an interface that abstracts over different address
// types. Returning the interface is idiomatic in this context.
//
//nolint:ireturn
func extractAddrFromPKScript(pkScript []byte,
	chainParams *chaincfg.Params) address.Address {

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
