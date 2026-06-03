package kvdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

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

	mgr := s.addrStore

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
}

type derivedAccountKeyDeriver interface {
	DeriveAccountKeys(ns walletdb.ReadBucket,
		account uint32) ([]byte, []byte, error)
}

// WalletWatchOnly implements db.CreateDerivedAccountOps.
func (o *createDerivedAccountOps) WalletWatchOnly(
	_ context.Context, _ uint32) (bool, error) {

	return o.mgr.WatchOnly(), nil
}

// EnsureScope implements db.CreateDerivedAccountOps. waddrmgr scopes are
// pre-registered; the call only fetches and caches the scoped manager.
func (o *createDerivedAccountOps) EnsureScope(_ context.Context, _ uint32,
	scope db.KeyScope) (int64, db.ScopeAddrSchema, error) {

	waddrScope := waddrmgr.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}

	scopedMgr, err := o.mgr.FetchScopedKeyManager(waddrScope)
	if err != nil {
		return 0, db.ScopeAddrSchema{}, translateAccountErr(
			err, db.ErrAccountNotFound,
		)
	}

	o.scope = waddrScope
	o.scopedMgr = scopedMgr

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

// AllocateAccountNumber implements db.CreateDerivedAccountOps.
func (o *createDerivedAccountOps) AllocateAccountNumber(_ context.Context,
	_ int64) (int64, error) {

	if o.scopedMgr == nil {
		return 0, errScopedMgrUninitialized
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
	_ int64, accountNumber int64, name string,
	derived *db.DerivedAccountData) (db.CreateDerivedAccountRow, error) {

	if o.scopedMgr == nil {
		return db.CreateDerivedAccountRow{}, errScopedMgrUninitialized
	}

	//nolint:gosec // accountNumber is bounded by MaxAccountNumber.
	err := o.scopedMgr.PutDerivedAccountWithKeys(
		o.ns, uint32(accountNumber), name,
		derived.PublicKey, derived.EncryptedPrivateKey,
	)
	if err != nil {
		return db.CreateDerivedAccountRow{}, fmt.Errorf(
			"put derived account: %w", err,
		)
	}

	// Persist the creation timestamp into the kvdb-owned side
	// bucket. Returning the same value to the caller keeps the
	// create return and the next read in sync.
	now := time.Now().UTC()
	scope := o.scopedMgr.Scope()

	//nolint:gosec // accountNumber is bounded by MaxAccountNumber.
	err = putAccountCreatedAt(
		o.ns, scope, uint32(accountNumber), now,
	)
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
	//nolint:gosec // accountNumber is bounded by MaxAccountNumber.
	err = putAccountMasterFingerprint(
		o.ns, scope, uint32(accountNumber),
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

	return &db.DerivedAccountData{
		PublicKey:           pubKey,
		EncryptedPrivateKey: encPrivKey,
	}, nil
}
