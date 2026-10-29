package kvdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

// CreateDerivedAccount runs the shared CreateDerivedAccountWithOps workflow
// on top of waddrmgr's bucket layout via the createDerivedAccountOps
// adapter.
func (s *Store) CreateDerivedAccount(ctx context.Context,
	params db.CreateDerivedAccountParams,
	deriveFn db.AccountDerivationFunc) (*db.AccountInfo, error) {

	// The legacy format has no per-account synchronization policy. Normalize
	// the by-value request so the shared workflow also returns the stored false
	// value while kvdb silently retains its historical behavior.
	params.NoChainSync = false

	mgr := s.addrStore

	// Ownership checks need every committed scope registered. Reuse the
	// Store write lock until Update has run its commit callbacks.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var info *db.AccountInfo

	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return db.ErrAccountNotFound
		}

		ops := &createDerivedAccountOps{mgr: mgr, ns: ns}
		deriveFn = ops.deriveWithScopedFallback(deriveFn)

		built, err := db.CreateDerivedAccountWithOps(
			ctx, params, ops, deriveFn,
		)
		if err != nil {
			return err
		}

		// Use the read path's scope-specific public key serialization while
		// still in the creation transaction. Preserve the other fields
		// returned by the shared workflow.
		stored, err := loadAccountInfo(
			ns, ops.scopedMgr, *built.AccountNumber, mgr.WatchOnly(),
		)
		if err != nil {
			return err
		}

		built.PublicKey = stored.PublicKey
		info = built

		return nil
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// createDerivedAccountOps adapts the shared workflow to waddrmgr. The
// same walletdb tx (via ns) covers every step so allocation and
// persistence roll back together on failure.
type createDerivedAccountOps struct {
	mgr       waddrmgr.AddrStore
	ns        walletdb.ReadWriteBucket
	scope     waddrmgr.KeyScope
	scopedMgr waddrmgr.AccountStore

	// scopeIsNew records creation by EnsureScope in this write, permitting
	// reuse only of that scope's newly seeded default account.
	scopeIsNew bool
}

type derivedAccountKeyDeriver interface {
	DeriveAccountKeys(ns walletdb.ReadBucket,
		account uint32) ([]byte, []byte, error)
}

// PrepareWalletForAccountCreation implements db.CreateDerivedAccountOps;
// the Store lock serializes account writes through their commit callbacks.
func (o *createDerivedAccountOps) PrepareWalletForAccountCreation(
	_ context.Context, _ uint32) (bool, error) {

	return o.mgr.WatchOnly(), nil
}

// EnsureScope implements db.CreateDerivedAccountOps using native scope
// creation. The shared workflow checks the persisted schema before allocation.
func (o *createDerivedAccountOps) EnsureScope(_ context.Context, _ uint32,
	scope db.KeyScope, schema *db.ScopeAddrSchema) (int64, db.ScopeAddrSchema,
	error) {

	waddrScope := waddrmgr.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}

	scopedMgr, err := o.mgr.FetchScopedKeyManager(waddrScope)
	if waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound) {
		// The native manager owns coin-type keys and commit-time scope
		// publication. An unknown custom scope must supply its schema.
		selected, known := db.ScopeAddrMap[scope]
		if schema != nil {
			selected = *schema
		} else if !known {
			return 0, db.ScopeAddrSchema{}, db.ErrInvalidParam
		}

		converted, convErr := db.ScopeAddrSchemaToWaddrmgr(selected)
		if convErr != nil {
			return 0, db.ScopeAddrSchema{}, convErr
		}

		scopedMgr, err = o.mgr.NewScopedKeyManager(
			o.ns, waddrScope, converted,
		)
		o.scopeIsNew = err == nil
	}

	if err != nil {
		return 0, db.ScopeAddrSchema{}, translateAccountErr(
			err, db.ErrAccountNotFound,
		)
	}

	o.scope = waddrScope
	o.scopedMgr = scopedMgr

	// A new spendable scope includes a real default account. Admit its key
	// against committed owners before the scope can become globally visible.
	if o.scopeIsNew {
		initial, err := loadAccountInfo(
			o.ns, scopedMgr, waddrmgr.DefaultAccountNum, false,
		)
		if err != nil {
			return 0, db.ScopeAddrSchema{}, err
		}

		err = checkAccountIdentity(o.ns, o.mgr, *initial)
		if err != nil {
			return 0, db.ScopeAddrSchema{}, err
		}
	}

	// Read the persisted scope schema from the waddrmgr scoped manager
	// instead of the global ScopeAddrMap default. A scope that was
	// created with a non-default schema (e.g. a custom BIP49 variant)
	// surfaces its actual schema here rather than getting recomputed.
	// per-account overrides ride on props.AddrSchema at load time.
	waddrSchema := scopedMgr.AddrSchema()

	addrSchema, err := db.ScopeAddrSchemaFromWaddrmgr(waddrSchema)
	if err != nil {
		return 0, db.ScopeAddrSchema{}, fmt.Errorf("scope schema: %w",
			err)
	}

	return 0, addrSchema, nil
}

// AllocateAccountNumber implements db.CreateDerivedAccountOps. Exact writes
// use the requested slot; the native writer advances its cursor on persistence.
func (o *createDerivedAccountOps) AllocateAccountNumber(_ context.Context,
	_ int64, number *uint32) (int64, error) {

	if o.scopedMgr == nil {
		return 0, errScopedMgrUninitialized
	}

	// Keep sparse requests independent of sequential allocation. Existing
	// identity admission below rejects occupied slots before any key write.
	if number != nil {
		// The native default's cursor starts unset. Allocate its zero once
		// when reusing that new account, so later sequential calls start at 1.
		if o.scopeIsNew && *number == waddrmgr.DefaultAccountNum {
			account, err := o.scopedMgr.AllocateDerivedAccountNumber(o.ns)
			return int64(account), err
		}

		return int64(*number), nil
	}

	// Missing scopes remain unavailable to sequential creation. In
	// particular, do not allocate zero over a newly seeded native default.
	if o.scopeIsNew {
		return 0, db.ErrAccountNotFound
	}

	account, err := o.scopedMgr.AllocateDerivedAccountNumber(o.ns)
	if err != nil {
		return 0, fmt.Errorf("allocate account number: %w", err)
	}

	return int64(account), nil
}

// CreateDerivedAccount implements db.CreateDerivedAccountOps. The plaintext
// public key is encrypted via waddrmgr cryptoKeyPub inside
// PutDerivedAccountWithKeys.
func (o *createDerivedAccountOps) CreateDerivedAccount(_ context.Context,
	_ int64, accountNumber int64, name string, _ bool,
	derived *db.DerivedAccountData) (db.CreateDerivedAccountRow, error) {

	if o.scopedMgr == nil {
		return db.CreateDerivedAccountRow{}, errScopedMgrUninitialized
	}

	// Refuse duplicate ownership before PutDerivedAccountWithKeys publishes
	// its cache entry. The existing write rolls back the allocated number.
	schema, err := effectiveAddrSchema(o.scopedMgr.AddrSchema(), nil)
	if err != nil {
		return db.CreateDerivedAccountRow{}, err
	}

	// Use the existing checked conversion for the native uint32 slot; the
	// shared workflow has already enforced the narrower derived-account limit.
	number, err := db.Int64ToUint32(accountNumber)
	if err != nil {
		return db.CreateDerivedAccountRow{}, err
	}

	candidate := db.AccountInfo{
		KeyScope:      db.KeyScope(o.scope),
		AccountNumber: &number,
		AccountName:   name,
		PublicKey:     derived.PublicKey,
		AddrSchema:    schema,
	}

	err = checkAccountIdentity(o.ns, o.mgr, candidate)
	if err != nil {
		return db.CreateDerivedAccountRow{}, err
	}

	// Keep native default reuse and key persistence behind the same writer.
	err = o.putDerivedAccount(candidate, derived.EncryptedPrivateKey)
	if err != nil {
		return db.CreateDerivedAccountRow{}, fmt.Errorf(
			"put derived account: %w", err,
		)
	}

	// Store the creation time in the same write as the keys, so creation and
	// later reads describe the same committed account.
	now := time.Now().UTC()
	scope := o.scopedMgr.Scope()

	err = putAccountCreatedAt(o.ns, scope, number, now, nil)
	if err != nil {
		return db.CreateDerivedAccountRow{}, fmt.Errorf(
			"persist created-at: %w", err,
		)
	}

	// Persist the master fingerprint into a parallel kvdb-owned
	// side bucket. waddrmgr's default-account row has no
	// fingerprint column, so without this the derived round-trip
	// would read back 0 from props on every subsequent
	// GetAccount/ListAccount; the wallet layer would then have to
	// fill it in via the legacy override. New rows written through
	// this path round-trip the value natively; legacy rows
	// (created before this side bucket existed) still rely on the
	// wallet-layer override as the canonical compatibility fallback.
	err = putAccountMasterFingerprint(
		o.ns, scope, number,
		derived.MasterKeyFingerprint,
	)
	if err != nil {
		return db.CreateDerivedAccountRow{}, fmt.Errorf(
			"persist master fingerprint: %w", err,
		)
	}

	return db.CreateDerivedAccountRow{
		AccountNumber: sql.NullInt64{
			Int64: accountNumber,
			Valid: true,
		},
		CreatedAt: now,
	}, nil
}

// putDerivedAccount writes admitted keys or reuses the native default created
// in this transaction. Committed account slots are never eligible for reuse.
func (o *createDerivedAccountOps) putDerivedAccount(candidate db.AccountInfo,
	encryptedPrivateKey []byte) error {

	number := *candidate.AccountNumber
	if !o.scopeIsNew {
		return o.scopedMgr.PutDerivedAccountWithKeys(
			o.ns, number, candidate.AccountName,
			candidate.PublicKey, encryptedPrivateKey,
		)
	}

	// The provisional default is absent from the root manager's committed
	// list, so compare it explicitly before a new scope can publish either key.
	initial, err := loadAccountInfo(
		o.ns, o.scopedMgr, waddrmgr.DefaultAccountNum, false,
	)
	if err != nil {
		return err
	}

	if number != waddrmgr.DefaultAccountNum {
		err = db.CheckAccountIdentity(candidate, []db.AccountInfo{*initial})
		if err != nil {
			return err
		}

		return o.scopedMgr.PutDerivedAccountWithKeys(
			o.ns, number, candidate.AccountName,
			candidate.PublicKey, encryptedPrivateKey,
		)
	}

	// A zero request must use the real root-derived default, rather than
	// replacing that key with unrelated material from a derivation callback.
	if !bytes.Equal(
		db.AccountXPubPayload(initial.PublicKey),
		db.AccountXPubPayload(candidate.PublicKey),
	) {

		return db.ErrInvalidParam
	}

	if candidate.AccountName == initial.AccountName {
		return nil
	}

	return o.scopedMgr.RenameAccount(o.ns, number, candidate.AccountName)
}

// deriveWithScopedFallback wraps the wallet-supplied derivation callback with
// the legacy kvdb fallback. Neutered-root wallets no longer have the master HD
// private key, but their scoped coin-type private keys remain and are the
// legacy source for deriving additional accounts within an existing scope.
func (o *createDerivedAccountOps) deriveWithScopedFallback(
	deriveFn db.AccountDerivationFunc) db.AccountDerivationFunc {

	if deriveFn == nil {
		return nil
	}

	return func(ctx context.Context, scope db.KeyScope, account uint32,
		walletIsWatchOnly bool) (*db.DerivedAccountData, error) {

		derived, err := deriveFn(
			ctx, scope, account, walletIsWatchOnly,
		)
		if err == nil || !errors.Is(err, db.ErrSecretNotFound) {
			return derived, err
		}

		return o.deriveAccountFromScopedKey(account)
	}
}

// deriveAccountFromScopedKey derives account material from waddrmgr's scoped
// coin-type private key after the shared workflow has allocated the next
// account number.
func (o *createDerivedAccountOps) deriveAccountFromScopedKey(
	account uint32) (*db.DerivedAccountData, error) {

	if o.scopedMgr == nil {
		return nil, errScopedMgrUninitialized
	}

	deriver, ok := o.scopedMgr.(derivedAccountKeyDeriver)
	if !ok {
		return nil, errScopedAccountDeriverUnsupported
	}

	pubKey, encPrivKey, err := deriver.DeriveAccountKeys(o.ns, account)
	if err != nil {
		return nil, fmt.Errorf("derive scoped account: %w", err)
	}

	masterPubKey, err := readMasterPubKey(o.mgr, o.ns)
	if err != nil {
		return nil, err
	}

	var fingerprint uint32
	if len(masterPubKey) > 0 {
		rootKey, err := hdkeychain.NewKeyFromString(string(masterPubKey))
		if err != nil {
			return nil, fmt.Errorf("parse master HD pubkey: %w", err)
		}

		rootPubKey, err := rootKey.ECPubKey()
		if err != nil {
			return nil, fmt.Errorf("master pubkey: %w", err)
		}

		fingerprint = db.MasterKeyFingerprint(rootPubKey)
	}

	return &db.DerivedAccountData{
		PublicKey:            pubKey,
		EncryptedPrivateKey:  encPrivKey,
		MasterKeyFingerprint: fingerprint,
	}, nil
}
