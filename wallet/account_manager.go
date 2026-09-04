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
)

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
	// within that same key scope. The reserved "imported" account cannot
	// be renamed.
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

// newAccountReq carries derived-account inputs and a buffered result across
// the Wallet's terminal admission boundary.
type newAccountReq struct {
	reqCtx

	scope waddrmgr.KeyScope
	name  string
	resp  chan accountResp
}

// NewAccount creates the next account and returns its account info. The name
// must be unique under the key scope. In order to support automatic seed
// restoring, new accounts may not be created when all of the previous 100
// accounts have no transaction history (this is a deviation from the BIP0044
// spec, which allows no unused account gaps).
func (w *Wallet) NewAccount(ctx context.Context, scope waddrmgr.KeyScope,
	name string) (*AccountInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	req := newAccountReq{
		reqCtx: reqCtx{ctx: ctx},
		scope:  scope,
		name:   name,
		resp:   make(chan accountResp, 1),
	}

	err = w.sendReq(ctx, req)
	if err != nil {
		return nil, err
	}

	resp, err := waitForReq(ctx, req.resp)
	if err != nil {
		return nil, err
	}

	return resp.info, resp.err
}

// handleNewAccount performs derivation and persistence only after mainLoop
// admits the request; handleReq owns its shutdown completion.
func (w *Wallet) handleNewAccount(req newAccountReq) {
	deriveFn, err := w.buildAccountDeriveFn(req.ctx)
	if err != nil {
		req.resp <- accountResp{err: err}

		return
	}

	info, err := w.store.CreateDerivedAccount(req.ctx,
		db.CreateDerivedAccountParams{
			WalletID: w.id,
			Scope:    db.KeyScope(req.scope),
			Name:     req.name,
		}, deriveFn,
	)
	if err != nil {
		// Preserve the legacy waddrmgr.ManagerError contract so that
		// callers using waddrmgr.IsError(err, ...) keep working after
		// kvdb wraps the underlying manager error via fmt.Errorf.
		var mErr waddrmgr.ManagerError
		if errors.As(err, &mErr) {
			req.resp <- accountResp{err: mErr}

			return
		}

		req.resp <- accountResp{err: err}

		return
	}

	account, err := w.accountInfoFromStore(info)
	req.resp <- accountResp{
		info: account,
		err:  err,
	}
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

// listAccountsResp lets a list handler finish even if caller cancellation
// causes the public method to stop receiving its result.
type listAccountsResp struct {
	infos []AccountInfo
	err   error
}

// listAccountsReq carries one fully formed Store query so every public list
// variant shares the same admitted handler without losing its filter.
type listAccountsReq struct {
	reqCtx

	query db.ListAccountsQuery
	resp  chan listAccountsResp
}

// ListAccounts returns every account across all key scopes with its balance.
func (w *Wallet) ListAccounts(ctx context.Context) ([]AccountInfo, error) {
	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	req := listAccountsReq{
		reqCtx: reqCtx{ctx: ctx},
		query: db.ListAccountsQuery{
			WalletID: w.id,
		},
		resp: make(chan listAccountsResp, 1),
	}

	err = w.sendReq(ctx, req)
	if err != nil {
		return nil, err
	}

	resp, err := waitForReq(ctx, req.resp)
	if err != nil {
		return nil, err
	}

	return resp.infos, resp.err
}

// listAccountInfos converts cache.ListAccounts snapshots into wallet-owned
// results while preserving a nil Store slice.
func (w *Wallet) listAccountInfos(ctx context.Context,
	query db.ListAccountsQuery) ([]AccountInfo, error) {

	infos, err := w.cache.ListAccounts(ctx, query)
	if err != nil {
		return nil, err
	}

	if infos == nil {
		return nil, nil
	}

	results := make([]AccountInfo, len(infos))
	for i := range infos {
		result, err := w.accountInfoFromStore(&infos[i])
		if err != nil {
			return nil, err
		}

		results[i] = *result
	}

	return results, nil
}

// handleListAccounts performs the Store read for any admitted list variant;
// handleReq owns the matching shutdown accounting.
func (w *Wallet) handleListAccounts(req listAccountsReq) {
	infos, err := w.listAccountInfos(req.ctx, req.query)
	req.resp <- listAccountsResp{
		infos: infos,
		err:   err,
	}
}

// ListAccountsByScope returns all accounts for the given key scope.
func (w *Wallet) ListAccountsByScope(ctx context.Context,
	scope waddrmgr.KeyScope) ([]AccountInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	dbScope := db.KeyScope(scope)

	req := listAccountsReq{
		reqCtx: reqCtx{ctx: ctx},
		query: db.ListAccountsQuery{
			WalletID: w.id,
			Scope:    &dbScope,
		},
		resp: make(chan listAccountsResp, 1),
	}

	err = w.sendReq(ctx, req)
	if err != nil {
		return nil, err
	}

	resp, err := waitForReq(ctx, req.resp)
	if err != nil {
		return nil, err
	}

	return resp.infos, resp.err
}

// ListAccountsByName returns every account matching name across all scopes.
func (w *Wallet) ListAccountsByName(ctx context.Context,
	name string) ([]AccountInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	req := listAccountsReq{
		reqCtx: reqCtx{ctx: ctx},
		query: db.ListAccountsQuery{
			WalletID: w.id,
			Name:     &name,
		},
		resp: make(chan listAccountsResp, 1),
	}

	err = w.sendReq(ctx, req)
	if err != nil {
		return nil, err
	}

	resp, err := waitForReq(ctx, req.resp)
	if err != nil {
		return nil, err
	}

	return resp.infos, resp.err
}

// accountResp carries one account snapshot or the lookup error so an accepted
// handler can always finish even when its caller stops waiting.
type accountResp struct {
	info *AccountInfo
	err  error
}

// getAccountReq owns the immutable lookup inputs and buffered response path
// that cross the Wallet's request boundary.
type getAccountReq struct {
	reqCtx

	scope waddrmgr.KeyScope
	name  string
	resp  chan accountResp
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

	req := getAccountReq{
		reqCtx: reqCtx{ctx: ctx},
		scope:  scope,
		name:   name,
		resp:   make(chan accountResp, 1),
	}

	err = w.sendReq(ctx, req)
	if err != nil {
		return nil, err
	}

	resp, err := waitForReq(ctx, req.resp)
	if err != nil {
		return nil, err
	}

	return resp.info, resp.err
}

// handleGetAccount executes an accepted lookup with its caller context and
// sends exactly one buffered response so shutdown never depends on a receiver.
func (w *Wallet) handleGetAccount(req getAccountReq) {
	info, err := w.cache.GetAccount(req.ctx, db.GetAccountQuery{
		WalletID: w.id,
		Scope:    db.KeyScope(req.scope),
		Name:     &req.name,
	})
	if err != nil {
		// Preserve waddrmgr.ManagerError semantics so callers using
		// waddrmgr.IsError(err, ...) keep working when kvdb wraps the
		// underlying manager error via fmt.Errorf.
		var mErr waddrmgr.ManagerError
		if errors.As(err, &mErr) {
			req.resp <- accountResp{err: mErr}
			return
		}

		req.resp <- accountResp{err: err}

		return
	}

	account, err := w.accountInfoFromStore(info)
	req.resp <- accountResp{
		info: account,
		err:  err,
	}
}

// renameAccountReq carries immutable rename inputs and a buffered error result
// so handler completion never depends on the caller remaining present.
type renameAccountReq struct {
	reqCtx

	scope   waddrmgr.KeyScope
	oldName string
	newName string
	resp    chan error
}

// RenameAccount renames an existing account. The new name must be unique within
// the same key scope. The reserved "imported" account cannot be renamed.
func (w *Wallet) RenameAccount(ctx context.Context,
	scope waddrmgr.KeyScope, oldName, newName string) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	req := renameAccountReq{
		reqCtx:  reqCtx{ctx: ctx},
		scope:   scope,
		oldName: oldName,
		newName: newName,
		resp:    make(chan error, 1),
	}

	err = w.sendReq(ctx, req)
	if err != nil {
		return err
	}

	respErr, err := waitForReq(ctx, req.resp)
	if err != nil {
		return err
	}

	return respErr
}

// handleRenameAccount validates and applies an admitted rename while
// handleReq retains responsibility for releasing the Wallet WaitGroup.
func (w *Wallet) handleRenameAccount(req renameAccountReq) {
	err := waddrmgr.ValidateAccountName(req.newName)
	if err != nil {
		req.resp <- err

		return
	}

	err = w.store.RenameAccount(req.ctx, db.RenameAccountParams{
		WalletID: w.id,
		Scope:    db.KeyScope(req.scope),
		OldName:  req.oldName,
		NewName:  req.newName,
	})
	if err != nil {
		// Preserve waddrmgr.ManagerError semantics so callers using
		// waddrmgr.IsError(err, ...) keep working when kvdb wraps the
		// underlying manager error via fmt.Errorf.
		var mErr waddrmgr.ManagerError
		if errors.As(err, &mErr) {
			req.resp <- mErr

			return
		}
	}

	req.resp <- err
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

	return w.importAccountInternal(
		ctx, name, accountKey, masterKeyFingerprint, addrType, dryRun,
	)
}

// importAccountInternal is the internal implementation of ImportAccount,
// allowing Manager.Create to bypass the started check.
func (w *Wallet) importAccountInternal(ctx context.Context,
	name string, accountKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrType waddrmgr.AddressType,
	dryRun bool) (*AccountInfo, error) {

	err := validateExtendedPubKey(
		accountKey, true, w.cfg.ChainParams,
	)
	if err != nil {
		return nil, err
	}

	keyScope, addrSchema, err := keyScopeFromPubKey(
		accountKey, &addrType,
	)
	if err != nil {
		return nil, err
	}

	dbAddrSchema, err := dbScopeAddrSchema(addrSchema)
	if err != nil {
		return nil, err
	}

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
		// Preserve waddrmgr.ManagerError semantics so callers using
		// waddrmgr.IsError(err, ...) keep working when kvdb wraps the
		// underlying manager error via fmt.Errorf.
		var mErr waddrmgr.ManagerError
		if errors.As(err, &mErr) {
			return nil, mErr
		}

		return nil, err
	}

	return w.accountInfoFromStore(info)
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
