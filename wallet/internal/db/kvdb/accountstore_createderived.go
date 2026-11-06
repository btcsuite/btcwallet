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

// CreateInitialDerivedAccounts prepares a fresh, unpublished Wallet's native
// scopes and then commits its account set in one write. The owner must close
// the address manager on failure: native writers warm caches before commit.
func (s *Store) CreateInitialDerivedAccounts(ctx context.Context,
	walletID uint32, accounts []db.CreateDerivedAccountParams,
	deriveFn db.AccountDerivationFunc) error {

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Scope registration happens OnCommit. Finish that write before any
	// account cache is warmed, so failed account writes have one close owner.
	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		return s.prepareInitialScopes(
			ctx, tx.ReadWriteBucket(waddrmgr.NamespaceKey), accounts,
		)
	})
	if err != nil {
		return err
	}

	return walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		defaults := make(map[db.KeyScope]string)

		for _, account := range accounts {
			account.WalletID = walletID
			account.NoChainSync = false

			// Native zero is already root-derived. Reuse it only once per
			// requested scope; later declarations remain ordinary conflicts.
			if account.AccountNumber != nil && *account.AccountNumber == 0 {
				switch name, exists := defaults[account.Scope]; {
				case exists && name == account.Name:
					return db.ErrAccountNameConflict
				case exists:
					return db.ErrAccountNumberConflict
				}

				err := s.initializeNativeDefault(ctx, ns, account, deriveFn)
				if err != nil {
					return err
				}

				defaults[account.Scope] = account.Name

				continue
			}

			ops := &createDerivedAccountOps{
				mgr: s.addrStore,
				ns:  ns,
			}

			_, err := db.CreateDerivedAccountWithOps(
				ctx, account, ops, deriveFn,
			)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

// prepareInitialScopes registers each requested scope once without loading
// account keys. The caller commits before using the newly registered managers.
func (s *Store) prepareInitialScopes(ctx context.Context,
	ns walletdb.ReadWriteBucket,
	accounts []db.CreateDerivedAccountParams) error {

	schemas := make(map[db.KeyScope]db.ScopeAddrSchema)
	for _, account := range accounts {
		err := ctx.Err()
		if err != nil {
			return err
		}

		err = account.Validate()
		if err != nil {
			return err
		}

		schema, known := schemas[account.Scope]
		if !known {
			manager, _, err := ensureLegacyScope(
				s.addrStore, ns, account.Scope, account.AddrSchema,
			)
			if err != nil {
				return err
			}

			schema, err = db.ScopeAddrSchemaFromWaddrmgr(manager.AddrSchema())
			if err != nil {
				return err
			}

			schemas[account.Scope] = schema
		}

		if account.AddrSchema != nil && *account.AddrSchema != schema {
			return fmt.Errorf("conflicting scope schema: %w",
				db.ErrInvalidParam)
		}
	}

	return nil
}

// initializeNativeDefault retains the fresh scope's actual account-zero key,
// while admitting its identity and persisting requested name and origin data.
func (s *Store) initializeNativeDefault(ctx context.Context,
	ns walletdb.ReadWriteBucket, account db.CreateDerivedAccountParams,
	deriveFn db.AccountDerivationFunc) error {

	manager, err := s.addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScope(account.Scope),
	)
	if err != nil {
		return err
	}

	initial, err := loadAccountInfo(ns, manager, 0, false)
	if err != nil {
		return err
	}

	fingerprint, err := s.checkInitialDefault(ctx, ns, initial, deriveFn)
	if err != nil {
		return err
	}

	if initial.AccountName != account.Name {
		err = manager.RenameAccount(ns, 0, account.Name)
		if err != nil {
			return err
		}
	}

	// Reserve zero only if the native cursor is still unset; an earlier
	// sparse account in this same input must keep its higher cursor intact.
	last, err := manager.LastAccount(ns)
	if err != nil {
		return err
	}

	if last == ^uint32(0) {
		_, err = manager.AllocateDerivedAccountNumber(ns)
		if err != nil {
			return err
		}
	}

	err = putAccountMasterFingerprint(
		ns, manager.Scope(), 0, fingerprint,
	)
	if err != nil {
		return err
	}

	return putAccountCreatedAt(ns, manager.Scope(), 0, time.Now().UTC(), nil)
}

// checkInitialDefault verifies the derived path still names the native key,
// then returns its fingerprint after shared cross-scope identity admission.
func (s *Store) checkInitialDefault(ctx context.Context,
	ns walletdb.ReadBucket, initial *db.AccountInfo,
	deriveFn db.AccountDerivationFunc) (uint32, error) {

	derived, err := deriveFn(ctx, initial.KeyScope, 0, false)
	if err != nil {
		return 0, err
	}

	if !bytes.Equal(
		db.AccountXPubPayload(initial.PublicKey),
		db.AccountXPubPayload(derived.PublicKey),
	) {

		return 0, db.ErrInvalidParam
	}

	var (
		identities []db.AccountInfo
		numbers    []uint32
	)

	for _, scoped := range s.addrStore.ActiveScopedKeyManagers() {
		err := collectScopedAccounts(
			ns, scoped, db.ListAccountsQuery{}, false,
			&identities, &numbers,
		)
		if err != nil {
			return 0, err
		}
	}

	return derived.MasterKeyFingerprint,
		db.CheckAccountIdentity(*initial, identities)
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

	scopedMgr, scopeIsNew, err := ensureLegacyScope(
		o.mgr, o.ns, scope, schema,
	)
	if err != nil {
		return 0, db.ScopeAddrSchema{}, err
	}

	o.scope = waddrmgr.KeyScope(scope)
	o.scopedMgr = scopedMgr
	o.scopeIsNew = scopeIsNew

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

// ensureLegacyScope reuses or seeds a native scope without loading account
// keys. Callers retain identity admission; initial creation can commit scope
// registration before any account cache is warmed.
func ensureLegacyScope(mgr waddrmgr.AddrStore, ns walletdb.ReadWriteBucket,
	scope db.KeyScope, schema *db.ScopeAddrSchema) (waddrmgr.AccountStore,
	bool, error) {

	manager, err := mgr.FetchScopedKeyManager(waddrmgr.KeyScope(scope))
	if !waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound) {
		return manager, false, translateAccountErr(err, db.ErrAccountNotFound)
	}

	// Unknown scopes need a caller schema; known scopes retain the existing
	// native defaults unless an explicit schema was supplied.
	selected, known := db.ScopeAddrMap[scope]
	if schema != nil {
		selected = *schema
	} else if !known {
		return nil, false, db.ErrInvalidParam
	}

	converted, err := db.ScopeAddrSchemaToWaddrmgr(selected)
	if err != nil {
		return nil, false, err
	}

	manager, err = mgr.NewScopedKeyManager(
		ns, waddrmgr.KeyScope(scope), converted,
	)
	if err != nil {
		return nil, false, translateAccountErr(err, db.ErrAccountNotFound)
	}

	return manager, true, nil
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
