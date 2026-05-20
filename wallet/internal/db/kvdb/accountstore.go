package kvdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// errScopedMgrUninitialized is returned by the
	// CreateDerivedAccount ops adapter when an EnsureScope step has
	// not yet cached the scoped manager.
	errScopedMgrUninitialized = errors.New(
		"kvdb: scoped manager not initialized",
	)

	// errImportedAccountWithPriv is returned by CreateImportedAccount
	// when a spendable wallet tries to import an account with private
	// key material; waddrmgr's accountWatchOnly row has no priv-key
	// column.
	errImportedAccountWithPriv = errors.New(
		"kvdb: imported accounts with private key material are not " +
			"supported on waddrmgr-backed wallets",
	)
	// errNoDefaultSchema is returned when a scope import targets a
	// KeyScope without a registered default address schema.
	errNoDefaultSchema = errors.New(
		"kvdb: no default schema for scope",
	)

	// errScopedAccountDeriverUnsupported is returned when a mocked or
	// alternate scoped manager does not provide kvdb's native derivation
	// fallback.
	errScopedAccountDeriverUnsupported = errors.New(
		"kvdb: scoped account derivation unsupported",
	)
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
func (o *createDerivedAccountOps) EnsureScope(_ context.Context,
	_ uint32, scope db.KeyScope) (int64, error) {

	waddrScope := waddrmgr.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}

	scopedMgr, err := o.mgr.FetchScopedKeyManager(waddrScope)
	if err != nil {
		return 0, translateAccountErr(err, db.ErrAccountNotFound)
	}

	o.scope = waddrScope
	o.scopedMgr = scopedMgr

	return 0, nil
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

	err := params.ValidateBasic()
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

// GetAccount returns the account identified by the given query within the
// requested scope.
func (s *Store) GetAccount(_ context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	scope := waddrmgr.KeyScope{
		Purpose: query.Scope.Purpose,
		Coin:    query.Scope.Coin,
	}

	var info *db.AccountInfo

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		built, err := s.lookupAccount(tx, query, scope)
		if err != nil {
			return err
		}

		info = built

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}

	return info, nil
}

// lookupAccount performs the per-transaction work of GetAccount: scope
// resolution, account-number lookup, AccountInfo build, contract
// enforcement, and optional balance attachment.
func (s *Store) lookupAccount(tx walletdb.ReadTx,
	query db.GetAccountQuery,
	scope waddrmgr.KeyScope) (*db.AccountInfo, error) {

	ns := tx.ReadBucket(waddrmgr.NamespaceKey)
	if ns == nil {
		return nil, db.ErrAccountNotFound
	}

	scopedMgr, err := s.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, translateAccountErr(err, db.ErrAccountNotFound)
	}

	acctNum, err := resolveAccountNumber(ns, scopedMgr, query)
	if err != nil {
		return nil, err
	}

	built, err := loadAccountInfo(
		ns, scopedMgr, acctNum, s.addrStore.WatchOnly(),
	)
	if err != nil {
		return nil, err
	}

	// Imported accounts may only be looked up by Name; their
	// AccountNumber is masked to 0 in the contract, which would
	// otherwise collide with the default derived account. Reject
	// inbound number-based lookups that resolve to imported.
	if query.AccountNumber != nil &&
		built.Origin == db.ImportedAccount {

		return nil, db.ErrAccountNotFound
	}

	if query.SkipBalance {
		return built, nil
	}

	txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

	balances, err := s.fetchAccountBalances(ns, txmgrNs, &scope)
	if err != nil {
		return nil, err
	}

	key := accountBalanceKey{scope: scope, account: acctNum}
	if pair, ok := balances[key]; ok {
		built.ConfirmedBalance = pair.confirmed
		built.UnconfirmedBalance = pair.unconfirmed
	}

	return built, nil
}

// resolveAccountNumber turns a GetAccountQuery into the legacy account
// number, looking up by name when AccountNumber is nil.
func resolveAccountNumber(ns walletdb.ReadBucket,
	scopedMgr waddrmgr.AccountStore,
	query db.GetAccountQuery) (uint32, error) {

	if query.AccountNumber != nil {
		return sanitizeAccountNumber(*query.AccountNumber)
	}

	acctNum, err := scopedMgr.LookupAccount(ns, *query.Name)
	if err != nil {
		return 0, translateAccountErr(err, db.ErrAccountNotFound)
	}

	return acctNum, nil
}

// sanitizeAccountNumber rejects legacy pseudo-account slots for number-based
// lookups. The legacy imported-address pseudo-account is still queryable by
// name, but its public account number is masked to 0 at the AccountInfo
// boundary.
func sanitizeAccountNumber(acctNum uint32) (uint32, error) {
	if acctNum == waddrmgr.ImportedAddrAccount {
		return 0, db.ErrAccountNotFound
	}

	return acctNum, nil
}

// loadAccountInfo materializes a db.AccountInfo from waddrmgr's
// AccountProperties + IsImportedAccount classifier.
func loadAccountInfo(ns walletdb.ReadBucket,
	scopedMgr waddrmgr.AccountStore, accountNumber uint32,
	walletWatchOnly bool) (*db.AccountInfo, error) {

	props, err := scopedMgr.AccountProperties(ns, accountNumber)
	if err != nil {
		return nil, translateAccountErr(err, db.ErrAccountNotFound)
	}

	accountIsImported, err := scopedMgr.IsImportedAccount(
		ns, accountNumber,
	)
	if err != nil {
		return nil, fmt.Errorf("is imported account: %w", err)
	}

	origin := db.DerivedAccount
	if accountIsImported {
		origin = db.ImportedAccount
	}

	scope := scopedMgr.Scope()

	var pubKey []byte
	if props.AccountPubKey != nil {
		pubKey = []byte(props.AccountPubKey.String())
	}

	// waddrmgr's account row layout does not carry a creation
	// timestamp, so kvdb keeps one in a side bucket. A missing
	// entry (for rows written before the side bucket existed)
	// returns time.Time{} as "unknown".
	createdAt, err := readAccountCreatedAt(ns, scope, accountNumber)
	if err != nil {
		return nil, fmt.Errorf("read created-at: %w", err)
	}

	// For imported accounts the per-row master_fingerprint is the
	// parent xpub fingerprint persisted on the watch-only row. For
	// derived accounts waddrmgr's default-account row has no
	// fingerprint column; the kvdb side bucket
	// (accountMasterFingerprintBucketKey) holds it for new rows
	// written through this adapter. Legacy derived rows have no
	// side-bucket entry and props.MasterKeyFingerprint is 0; the
	// wallet-layer override fills in the cached value at the public
	// boundary for the legacy case.
	fingerprint := props.MasterKeyFingerprint

	persisted, ok, fpErr := getAccountMasterFingerprint(
		ns, scope, props.AccountNumber,
	)
	if fpErr != nil {
		return nil, fmt.Errorf("read master fingerprint: %w", fpErr)
	}

	if ok {
		fingerprint = persisted
	}

	// Imported accounts in kvdb share waddrmgr's per-scope counter
	// internally, but the AccountInfo contract masks their
	// AccountNumber to 0. Internal callers that need the real
	// waddrmgr number (e.g. attachAccountBalances) carry it
	// separately.
	accountNumberForContract := props.AccountNumber
	if origin == db.ImportedAccount {
		accountNumberForContract = 0
	}

	return &db.AccountInfo{
		AccountNumber:    accountNumberForContract,
		AccountName:      props.AccountName,
		Origin:           origin,
		ExternalKeyCount: props.ExternalKeyCount,
		InternalKeyCount: props.InternalKeyCount,
		ImportedKeyCount: props.ImportedKeyCount,
		IsWatchOnly:      walletWatchOnly || accountIsImported,
		KeyScope: db.KeyScope{
			Purpose: scope.Purpose,
			Coin:    scope.Coin,
		},
		PublicKey:            pubKey,
		MasterKeyFingerprint: fingerprint,
		CreatedAt:            createdAt,
	}, nil
}

// translateAccountErr maps waddrmgr account/scope not-found errors to their
// public db.* equivalents.
func translateAccountErr(err error, notFound error) error {
	if err == nil {
		return nil
	}

	switch {
	case waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound),
		waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound):

		return notFound
	}

	return fmt.Errorf("waddrmgr: %w", err)
}

// ListAccounts returns the accounts matching the given query. When
// query.Scope is nil, every active scoped key manager is walked.
func (s *Store) ListAccounts(_ context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	if query.Scope != nil && query.Name != nil {
		return nil, db.ErrInvalidAccountQuery
	}

	mgr := s.addrStore

	var (
		accounts        []db.AccountInfo
		internalNumbers []uint32
	)

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return nil
		}

		scopedMgrs, err := selectScopedManagers(mgr, query.Scope)
		if err != nil {
			return err
		}

		walletWatchOnly := mgr.WatchOnly()
		for _, scopedMgr := range scopedMgrs {
			err := collectScopedAccounts(
				ns, scopedMgr, query, walletWatchOnly,
				&accounts, &internalNumbers,
			)
			if err != nil {
				return err
			}

			if foundGlobalImported(query, accounts) {
				break
			}
		}

		return s.maybeAttachListBalances(
			ns, tx, query, accounts, internalNumbers,
		)
	})
	if err != nil {
		return nil, err
	}

	return accounts, nil
}

// foundGlobalImported returns true when a name-filtered query has found the
// legacy imported-address pseudo-account. waddrmgr exposes that account from
// every scoped manager, but the public account view treats it as global.
func foundGlobalImported(query db.ListAccountsQuery,
	accounts []db.AccountInfo) bool {

	if query.Name == nil || *query.Name != waddrmgr.ImportedAddrAccountName {
		return false
	}

	return len(accounts) > 0
}

// collectScopedAccounts walks the accounts under scopedMgr and appends
// matching entries to accounts. Entries that fail the optional Name filter are
// skipped.
func collectScopedAccounts(ns walletdb.ReadBucket,
	scopedMgr waddrmgr.AccountStore, query db.ListAccountsQuery,
	walletWatchOnly bool, accounts *[]db.AccountInfo,
	internalNumbers *[]uint32) error {

	type collectedAccount struct {
		info           db.AccountInfo
		internalNumber uint32
	}

	var collected []collectedAccount

	err := scopedMgr.ForEachAccount(ns, func(account uint32) error {
		if skipImportedPseudoAccount(account, query) {
			return nil
		}

		info, err := loadAccountInfo(
			ns, scopedMgr, account, walletWatchOnly,
		)
		if err != nil {
			return err
		}

		if query.Name != nil && *query.Name != info.AccountName {
			return nil
		}

		collected = append(collected, collectedAccount{
			info:           *info,
			internalNumber: account,
		})

		return nil
	})
	if err != nil {
		return err
	}

	// ForEachAccount walks little-endian bucket keys in raw byte order.
	// Sort by decoded account number before returning account snapshots.
	sort.Slice(collected, func(i, j int) bool {
		return collected[i].internalNumber < collected[j].internalNumber
	})

	for _, account := range collected {
		*accounts = append(*accounts, account.info)
		// Keep the waddrmgr internal account number aligned by
		// index with `accounts`. attachAccountBalances keys
		// balance lookups by the internal number because the
		// AccountInfo contract masks imported numbers to 0
		// (data_types.go), but waddrmgr's balance walker still
		// indexes by the internal number.
		*internalNumbers = append(
			*internalNumbers, account.internalNumber,
		)
	}

	return nil
}

// skipImportedPseudoAccount returns whether the legacy imported-address
// pseudo-account should be hidden from this list query. The pseudo-account is
// queryable by name, but full lists continue to walk derivable account rows.
func skipImportedPseudoAccount(account uint32,
	query db.ListAccountsQuery) bool {

	if account != waddrmgr.ImportedAddrAccount {
		return false
	}

	return query.Name == nil || *query.Name != waddrmgr.ImportedAddrAccountName
}

// maybeAttachListBalances populates ConfirmedBalance / UnconfirmedBalance on
// every entry in accounts unless query.SkipBalance is set or no accounts
// were collected.
func (s *Store) maybeAttachListBalances(ns walletdb.ReadBucket,
	tx walletdb.ReadTx, query db.ListAccountsQuery,
	accounts []db.AccountInfo, internalNumbers []uint32) error {

	if query.SkipBalance || len(accounts) == 0 {
		return nil
	}

	txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

	var scopeFilter *waddrmgr.KeyScope
	if query.Scope != nil {
		scopeFilter = &waddrmgr.KeyScope{
			Purpose: query.Scope.Purpose,
			Coin:    query.Scope.Coin,
		}
	}

	balances, err := s.fetchAccountBalances(ns, txmgrNs, scopeFilter)
	if err != nil {
		return err
	}

	attachAccountBalances(accounts, internalNumbers, balances)

	return nil
}

// selectScopedManagers narrows the set of scoped managers to walk based on
// an optional scope filter from the public query.
func selectScopedManagers(mgr waddrmgr.AddrStore, filter *db.KeyScope) (
	[]waddrmgr.AccountStore, error) {

	if filter == nil {
		return mgr.ActiveScopedKeyManagers(), nil
	}

	scope := waddrmgr.KeyScope{
		Purpose: filter.Purpose,
		Coin:    filter.Coin,
	}

	scopedMgr, err := mgr.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, translateAccountErr(err, db.ErrAccountNotFound)
	}

	return []waddrmgr.AccountStore{scopedMgr}, nil
}

// RenameAccount renames an existing account within a scope.
func (s *Store) RenameAccount(_ context.Context,
	params db.RenameAccountParams) error {

	err := params.Validate()
	if err != nil {
		return err
	}

	mgr := s.addrStore

	scope := waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}

	return walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return db.ErrAccountNotFound
		}

		scopedMgr, err := mgr.FetchScopedKeyManager(scope)
		if err != nil {
			return translateAccountErr(err, db.ErrAccountNotFound)
		}

		acctNum, err := resolveRenameAccountNumber(
			ns, scopedMgr, params,
		)
		if err != nil {
			return err
		}

		err = assertRenameableAccount(ns, scopedMgr, acctNum)
		if err != nil {
			return err
		}

		err = scopedMgr.RenameAccount(ns, acctNum, params.NewName)
		if err != nil {
			return translateAccountErr(err, db.ErrAccountNotFound)
		}

		return nil
	})
}

// resolveRenameAccountNumber turns a RenameAccountParams into the legacy
// account number, looking up by OldName when AccountNumber is nil.
func resolveRenameAccountNumber(ns walletdb.ReadBucket,
	scopedMgr waddrmgr.AccountStore,
	params db.RenameAccountParams) (uint32, error) {

	if params.AccountNumber != nil {
		return *params.AccountNumber, nil
	}

	acctNum, err := scopedMgr.LookupAccount(ns, params.OldName)
	if err != nil {
		return 0, translateAccountErr(err, db.ErrAccountNotFound)
	}

	return acctNum, nil
}

// assertRenameableAccount rejects imported accounts before calling
// waddrmgr.RenameAccount, which only knows about the legacy imported-address
// pseudo-account slot.
func assertRenameableAccount(ns walletdb.ReadBucket,
	scopedMgr waddrmgr.AccountStore, acctNum uint32) error {

	if acctNum == waddrmgr.ImportedAddrAccount {
		return db.ErrAccountNotFound
	}

	isImported, err := scopedMgr.IsImportedAccount(ns, acctNum)
	if err != nil {
		return translateAccountErr(err, db.ErrAccountNotFound)
	}

	if isImported {
		return db.ErrAccountNotFound
	}

	return nil
}

// accountBalanceKey identifies one (scope, account) bucket within the
// computed-balances map returned by fetchAccountBalances.
type accountBalanceKey struct {
	scope   waddrmgr.KeyScope
	account uint32
}

// accountBalancePair holds the confirmed/unconfirmed total for one
// account computed from the unspent-outputs walk.
type accountBalancePair struct {
	confirmed   btcutil.Amount
	unconfirmed btcutil.Amount
}

// fetchAccountBalances walks the wallet's unspent outputs once and
// returns confirmed/unconfirmed totals keyed by (scope, account).
// When scopeFilter is non-nil only outputs owned by that scope are
// accumulated.
func (s *Store) fetchAccountBalances(addrmgrNs,
	txmgrNs walletdb.ReadBucket,
	scopeFilter *waddrmgr.KeyScope) (
	map[accountBalanceKey]accountBalancePair, error) {

	balances := make(map[accountBalanceKey]accountBalancePair)

	err := s.walkAccountUTXOs(
		addrmgrNs, txmgrNs,
		func(key accountBalanceKey, amount btcutil.Amount,
			isConfirmed bool) {

			if scopeFilter != nil && *scopeFilter != key.scope {
				return
			}

			pair := balances[key]
			if isConfirmed {
				pair.confirmed += amount
			} else {
				pair.unconfirmed += amount
			}

			balances[key] = pair
		},
	)
	if err != nil {
		return nil, err
	}

	return balances, nil
}

// walkAccountUTXOs iterates the wallet's unspent outputs, resolves
// each to its owning (scope, account), and invokes fn for every
// output that maps to a wallet-managed address. Outputs whose script
// does not extract to a recognized address, or that the address
// manager cannot map to an account, are skipped.
func (s *Store) walkAccountUTXOs(addrmgrNs,
	txmgrNs walletdb.ReadBucket,
	fn func(key accountBalanceKey, amount btcutil.Amount,
		isConfirmed bool)) error {

	if s.txStore == nil || txmgrNs == nil {
		return nil
	}

	syncBlock := s.addrStore.SyncedTo()
	chainParams := s.addrStore.ChainParams()

	unspent, err := s.txStore.UnspentOutputsIncludingLocked(txmgrNs)
	if err != nil {
		return fmt.Errorf("unspent outputs: %w", err)
	}

	for i := range unspent {
		output := &unspent[i]

		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, chainParams,
		)
		if err != nil || len(addrs) == 0 {
			continue
		}

		owner, account, err := s.addrStore.AddrAccount(
			addrmgrNs, addrs[0],
		)
		if err != nil {
			continue
		}

		key := accountBalanceKey{
			scope:   owner.Scope(),
			account: account,
		}

		isConfirmed := output.Height > 0 &&
			output.Height <= syncBlock.Height

		fn(key, output.Amount, isConfirmed)
	}

	return nil
}

// attachAccountBalances merges per-account confirmed/unconfirmed
// totals back into the AccountInfo slice. Accounts that produced no
// unspent outputs retain their zero balance.
func attachAccountBalances(accounts []db.AccountInfo,
	internalNumbers []uint32,
	balances map[accountBalanceKey]accountBalancePair) {

	for i := range accounts {
		info := &accounts[i]
		// Key by the waddrmgr internal account number, NOT
		// info.AccountNumber. loadAccountInfo masks imported
		// AccountNumber to 0 at the contract boundary; if we
		// keyed by info.AccountNumber the balance lookup for
		// imported rows would collide with derived account 0
		// (silently zeroing or mis-attributing imported
		// balances). The internal number is preserved by
		// collectScopedAccounts in a parallel slice for exactly
		// this purpose.
		key := accountBalanceKey{
			scope: waddrmgr.KeyScope{
				Purpose: info.KeyScope.Purpose,
				Coin:    info.KeyScope.Coin,
			},
			account: internalNumbers[i],
		}

		pair := balances[key]
		info.ConfirmedBalance = pair.confirmed
		info.UnconfirmedBalance = pair.unconfirmed
	}
}
