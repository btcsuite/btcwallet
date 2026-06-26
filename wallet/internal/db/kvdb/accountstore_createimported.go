package kvdb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

// CreateImportedAccount persists an imported account into waddrmgr as a
// watch-only row. kvdb does not persist an encrypted account private key
// for imported accounts; spendable wallets that supply one get an error.
func (s *Store) CreateImportedAccount(_ context.Context,
	params db.CreateImportedAccountParams) (*db.AccountInfo, error) {

	mgr := s.addrStore
	walletIsWatchOnly := mgr.WatchOnly()

	pubKey, err := validateImportedAccountParams(
		params, walletIsWatchOnly,
	)
	if err != nil {
		return nil, err
	}

	scope := waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}

	var info *db.AccountInfo

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return db.ErrAccountNotFound
		}

		built, err := s.putImportedAccount(
			ns, scope, params, pubKey, walletIsWatchOnly,
		)
		if err != nil {
			return err
		}

		info = built

		if params.DryRun {
			return walletdb.ErrDryRunRollBack
		}

		return nil
	})
	if err != nil {
		if params.DryRun && errors.Is(err, walletdb.ErrDryRunRollBack) {
			return info, nil
		}

		return nil, err
	}

	return info, nil
}

// validateImportedAccountParams performs kvdb-specific import validation and
// returns the parsed account public key.
func validateImportedAccountParams(params db.CreateImportedAccountParams,
	walletIsWatchOnly bool) (*hdkeychain.ExtendedKey, error) {

	err := params.Validate()
	if err != nil {
		return nil, err
	}

	err = params.ValidateWatchOnly(walletIsWatchOnly)
	if err != nil {
		return nil, err
	}

	if len(params.EncryptedPrivateKey) > 0 && !walletIsWatchOnly {
		return nil, errImportedAccountWithPriv
	}

	pubKey, err := hdkeychain.NewKeyFromString(string(params.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("parse account public key: %w", err)
	}

	if pubKey.IsPrivate() {
		return nil, errImportedAccountWithPriv
	}

	return pubKey, nil
}

// putImportedAccount writes a validated imported account using waddrmgr's
// legacy watch-only account creation path.
func (s *Store) putImportedAccount(ns walletdb.ReadWriteBucket,
	scope waddrmgr.KeyScope, params db.CreateImportedAccountParams,
	pubKey *hdkeychain.ExtendedKey,
	walletIsWatchOnly bool) (*db.AccountInfo, error) {

	addrSchema := waddrmgrScopeAddrSchema(params.AddrSchema)

	scopedMgr, err := s.scopedManagerOrCreate(
		ns, scope, addrSchema, params.DryRun,
	)
	if err != nil {
		return nil, err
	}

	accountNumber, err := scopedMgr.NewAccountWatchingOnly(
		ns, params.Name, pubKey, params.MasterFingerprint, addrSchema,
	)
	if err != nil {
		return nil, err
	}

	if params.DryRun {
		return dryRunImportedAccount(
			ns, scopedMgr, accountNumber, walletIsWatchOnly,
		)
	}

	// Persist the creation timestamp into the kvdb-owned side
	// bucket. The subsequent loadAccountInfo call reads it back.
	err = putAccountCreatedAt(
		ns, scope, accountNumber, time.Now().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("persist created-at: %w", err)
	}

	return loadAccountInfo(
		ns, scopedMgr, accountNumber, walletIsWatchOnly,
	)
}

// scopedManagerOrCreate returns the scoped key manager for the given scope.
// It falls back to creating the scope on persisted imports, but not on dry
// runs because NewScopedKeyManager mutates the in-memory manager before the
// surrounding walletdb transaction can roll back.
func (s *Store) scopedManagerOrCreate(ns walletdb.ReadWriteBucket,
	scope waddrmgr.KeyScope,
	addrSchema *waddrmgr.ScopeAddrSchema,
	dryRun bool) (waddrmgr.AccountStore, error) {

	scopedMgr, err := s.addrStore.FetchScopedKeyManager(scope)
	if err == nil {
		return scopedMgr, nil
	}

	if !waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound) {
		return nil, translateAccountErr(err, db.ErrAccountNotFound)
	}

	if dryRun {
		return nil, translateAccountErr(err, db.ErrKeyScopeNotFound)
	}

	if addrSchema == nil {
		defaultSchema, ok := waddrmgr.ScopeAddrMap[scope]
		if !ok {
			return nil, fmt.Errorf("%w %s", errNoDefaultSchema, scope)
		}

		addrSchema = &defaultSchema
	}

	scopedMgr, err = s.addrStore.NewScopedKeyManager(
		ns, scope, *addrSchema,
	)
	if err != nil {
		return nil, fmt.Errorf("new scoped key manager: %w", err)
	}

	return scopedMgr, nil
}

// dryRunImportedAccount validates an imported account by deriving one external
// and one internal address, then returns the refreshed account snapshot. The
// caller rolls back the surrounding transaction.
func dryRunImportedAccount(ns walletdb.ReadWriteBucket,
	scopedMgr waddrmgr.AccountStore, accountNumber uint32,
	walletIsWatchOnly bool) (*db.AccountInfo, error) {

	defer scopedMgr.InvalidateAccountCache(accountNumber)

	_, err := scopedMgr.NextExternalAddresses(ns, accountNumber, 1)
	if err != nil {
		return nil, fmt.Errorf("derive external address: %w", err)
	}

	_, err = scopedMgr.NextInternalAddresses(ns, accountNumber, 1)
	if err != nil {
		return nil, fmt.Errorf("derive internal address: %w", err)
	}

	return loadAccountInfo(
		ns, scopedMgr, accountNumber, walletIsWatchOnly,
	)
}

// waddrmgrScopeAddrSchema converts the account-store schema type into the
// waddrmgr per-account address schema type.
func waddrmgrScopeAddrSchema(
	schema *db.ScopeAddrSchema) *waddrmgr.ScopeAddrSchema {

	if schema == nil {
		return nil
	}

	return &waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.AddressType(schema.ExternalAddrType),
		InternalAddrType: waddrmgr.AddressType(schema.InternalAddrType),
	}
}
