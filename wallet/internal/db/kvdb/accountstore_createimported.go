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

	pubKey, addrSchema, err := validateImportedAccountParams(
		params, walletIsWatchOnly,
	)
	if err != nil {
		return nil, err
	}

	scope := waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}

	// bbolt releases its writer before OnCommit registers new scopes.
	// Serialize admission through those callbacks with other Store writes.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var info *db.AccountInfo

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return db.ErrAccountNotFound
		}

		built, err := s.putImportedAccount(
			ns, scope, params, pubKey, addrSchema, walletIsWatchOnly,
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
		// Keep Store capacity errors independent of the native writer.
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNumTooHigh) {
			return nil, fmt.Errorf("%w: %w",
				db.ErrMaxAccountNumberReached, err)
		}

		if params.DryRun && errors.Is(err, walletdb.ErrDryRunRollBack) {
			return info, nil
		}

		return nil, err
	}

	return info, nil
}

// validateImportedAccountParams performs kvdb-specific import validation and
// returns the parsed key and native schema before opening a write transaction.
func validateImportedAccountParams(params db.CreateImportedAccountParams,
	walletIsWatchOnly bool) (*hdkeychain.ExtendedKey,
	*waddrmgr.ScopeAddrSchema, error) {

	err := params.Validate()
	if err != nil {
		return nil, nil, err
	}

	err = params.ValidateWatchOnly(walletIsWatchOnly)
	if err != nil {
		return nil, nil, err
	}

	if len(params.EncryptedPrivateKey) > 0 && !walletIsWatchOnly {
		return nil, nil, errImportedAccountWithPriv
	}

	pubKey, err := hdkeychain.NewKeyFromString(string(params.PublicKey))
	if err != nil {
		return nil, nil, fmt.Errorf("parse account public key: %w", err)
	}

	if pubKey.IsPrivate() {
		return nil, nil, errImportedAccountWithPriv
	}

	// Schema conversion belongs to validation, so persistence can reuse the
	// native value without another conversion helper.
	var addrSchema *waddrmgr.ScopeAddrSchema
	if params.AddrSchema != nil {
		converted, err := db.ScopeAddrSchemaToWaddrmgr(
			*params.AddrSchema,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("address schema: %w", err)
		}

		addrSchema = &converted
	}

	return pubKey, addrSchema, nil
}

// putImportedAccount writes a validated imported account using waddrmgr's
// legacy watch-only account creation path.
func (s *Store) putImportedAccount(ns walletdb.ReadWriteBucket,
	scope waddrmgr.KeyScope, params db.CreateImportedAccountParams,
	pubKey *hdkeychain.ExtendedKey, addrSchema *waddrmgr.ScopeAddrSchema,
	walletIsWatchOnly bool) (*db.AccountInfo, error) {

	// Resolve once so admission and registration use the same scope schema.
	scopedMgr, scopeSchema, err := s.resolveImportedAccountScope(
		scope, addrSchema, params, walletIsWatchOnly,
	)
	if err != nil {
		return nil, err
	}

	schema, err := effectiveAddrSchema(scopeSchema, addrSchema)
	if err != nil {
		return nil, err
	}

	// Keep the admitted request for comparison with a missing scope's default.
	candidate := db.AccountInfo{
		KeyScope:      params.Scope,
		AccountName:   params.Name,
		AccountNumber: params.AccountNumber,
		PublicKey:     params.PublicKey,
		AddrSchema:    schema,
	}

	err = checkAccountIdentity(ns, s.addrStore, candidate)
	if err != nil {
		return nil, err
	}

	// Register after admission so a collision cannot publish a scope.
	scopedMgr, err = s.scopedManagerOrCreate(
		ns, scope, scopedMgr, scopeSchema, candidate,
	)
	if err != nil {
		return nil, err
	}

	// Native watch-only rows have no presence bit. Preserve kvdb's legacy
	// zero default; SQL retains absence in its nullable account row.
	var masterFingerprint uint32
	if params.MasterFingerprint != nil {
		masterFingerprint = *params.MasterFingerprint
	}

	// Known paths reuse the native exact-slot writer. Inferred imports keep
	// the legacy sequential assignment, including its allocation limit.
	var accountNumber uint32
	if params.AccountNumber != nil {
		accountNumber = *params.AccountNumber
		err = scopedMgr.PutWatchOnlyAccountWithKeys(
			ns, accountNumber, params.Name, pubKey,
			masterFingerprint, addrSchema,
		)
	} else {
		accountNumber, err = scopedMgr.NewAccountWatchingOnly(
			ns, params.Name, pubKey, masterFingerprint, addrSchema,
		)
	}

	if err != nil {
		return nil, err
	}

	if params.DryRun {
		return dryRunImportedAccount(
			ns, scopedMgr, accountNumber, params.AccountNumber,
			walletIsWatchOnly,
		)
	}

	// Retain a declared number with the timestamp in the same transaction;
	// numberless imports continue writing the original timestamp-only value.
	err = putAccountCreatedAt(
		ns, scope, accountNumber, time.Now().UTC(), params.AccountNumber,
	)
	if err != nil {
		return nil, fmt.Errorf("persist account metadata: %w", err)
	}

	return loadAccountInfo(
		ns, scopedMgr, accountNumber, walletIsWatchOnly,
	)
}

// scopedManagerOrCreate admits the actual native default before commit can
// publish a new scope, using its returned transaction-local manager.
func (s *Store) scopedManagerOrCreate(ns walletdb.ReadWriteBucket,
	scope waddrmgr.KeyScope, scopedMgr waddrmgr.AccountStore,
	schema waddrmgr.ScopeAddrSchema, candidate db.AccountInfo) (
	waddrmgr.AccountStore, error) {

	if scopedMgr != nil {
		return scopedMgr, nil
	}

	// Native creation supplies the default key without publishing the scope.
	// Reuse that account for admission instead of deriving a second copy.
	scopedMgr, err := s.addrStore.NewScopedKeyManager(ns, scope, schema)
	if err != nil {
		return nil, fmt.Errorf("new scoped key manager: %w", err)
	}

	err = s.checkDefaultAccountIdentity(ns, scopedMgr, candidate)
	if err != nil {
		return nil, err
	}

	return scopedMgr, nil
}

// checkDefaultAccountIdentity reads the new scope's seed-derived default before
// commit, then checks its keys against the request and existing owners.
func (s *Store) checkDefaultAccountIdentity(ns walletdb.ReadBucket,
	scopedMgr waddrmgr.AccountStore, candidate db.AccountInfo) error {

	// Watch-only scopes create no seed-derived default, so only the supplied
	// account needs the existing import admission check.
	if s.addrStore.WatchOnly() {
		return nil
	}

	// Admission must not leave a cached default for the legacy numberless
	// allocator, which can reuse this scope's first account slot.
	defer scopedMgr.InvalidateAccountCache(waddrmgr.DefaultAccountNum)

	account, err := loadAccountInfo(
		ns, scopedMgr, waddrmgr.DefaultAccountNum, false,
	)
	if err != nil {
		return fmt.Errorf("read default account: %w", err)
	}

	// Neither new account is globally visible yet. Compare the native default
	// with the request explicitly before checking the committed owners.
	err = db.CheckAccountIdentity(*account, []db.AccountInfo{candidate})
	if err != nil {
		return err
	}

	return checkAccountIdentity(ns, s.addrStore, *account)
}

// dryRunImportedAccount validates an imported account by deriving one external
// and one internal address, then returns the refreshed account snapshot. The
// caller rolls back the surrounding transaction.
func dryRunImportedAccount(ns walletdb.ReadWriteBucket,
	scopedMgr waddrmgr.AccountStore, accountNumber uint32, knownNumber *uint32,
	walletIsWatchOnly bool) (*db.AccountInfo, error) {

	defer scopedMgr.InvalidateAccountCache(accountNumber)

	// A numbered preview needs declaration metadata for its returned account
	// path. Rollback removes the record; ordinary previews stay unchanged.
	if knownNumber != nil {
		err := putAccountCreatedAt(
			ns, scopedMgr.Scope(), accountNumber, time.Now().UTC(),
			knownNumber,
		)
		if err != nil {
			return nil, fmt.Errorf("preview account metadata: %w", err)
		}
	}

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

// resolveImportedAccountScope returns the existing manager or the schema for
// a missing scope, letting admission finish before registration mutates it.
func (s *Store) resolveImportedAccountScope(scope waddrmgr.KeyScope,
	override *waddrmgr.ScopeAddrSchema, params db.CreateImportedAccountParams,
	walletIsWatchOnly bool) (
	waddrmgr.AccountStore, waddrmgr.ScopeAddrSchema, error) {

	existing, err := s.addrStore.FetchScopedKeyManager(scope)
	if err == nil {
		return existing, existing.AddrSchema(), nil
	}

	var empty waddrmgr.ScopeAddrSchema

	if !waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound) {
		return nil, empty, translateAccountErr(err, db.ErrAccountNotFound)
	}

	var schema waddrmgr.ScopeAddrSchema
	if override != nil {
		schema = *override
	} else {
		var ok bool

		schema, ok = waddrmgr.ScopeAddrMap[scope]
		if !ok {
			return nil, empty, fmt.Errorf("%w %s", errNoDefaultSchema, scope)
		}
	}

	// A new spendable scope seeds account zero named default. Refuse either
	// collision before registration: a duplicate name would roll back the
	// database but leave a live scope, while an exact zero would replace it.
	if !walletIsWatchOnly {
		if params.Name == waddrmgr.DefaultAccountName {
			return nil, empty, db.ErrAccountNameConflict
		}

		if params.AccountNumber != nil &&
			*params.AccountNumber == waddrmgr.DefaultAccountNum {

			return nil, empty, db.ErrAccountNumberConflict
		}
	}

	return nil, schema, nil
}
