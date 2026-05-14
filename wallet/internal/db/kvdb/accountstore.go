package kvdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// errKvdbScopedMgrUninitialized is returned by the
	// CreateDerivedAccount ops adapter when an EnsureScope step has
	// not yet cached the scoped manager.
	errKvdbScopedMgrUninitialized = errors.New(
		"kvdb: scoped manager not initialized",
	)

	// errKvdbImportedAccountWithPriv is returned by CreateImportedAccount
	// when a spendable wallet tries to import an account with private
	// key material; waddrmgr's accountWatchOnly row has no priv-key
	// column.
	errKvdbImportedAccountWithPriv = errors.New(
		"kvdb: imported accounts with private key material are not " +
			"supported on waddrmgr-backed wallets",
	)

	// errKvdbNoDefaultSchema is returned when a scope import targets a
	// key scope that has no default address schema registered in
	// waddrmgr.ScopeAddrMap.
	errKvdbNoDefaultSchema = errors.New(
		"kvdb: no default schema for scope",
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
		return 0, errKvdbScopedMgrUninitialized
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
		return db.CreateDerivedAccountRow{}, errKvdbScopedMgrUninitialized
	}

	err := o.scopedMgr.PutDerivedAccountWithKeys(
		o.ns, uint32(accountNumber), name, //nolint:gosec
		derived.PublicKey, derived.EncryptedPrivateKey,
	)
	if err != nil {
		return db.CreateDerivedAccountRow{}, fmt.Errorf(
			"put derived account: %w", err,
		)
	}

	// Persist creation timestamp in the kvdb-owned side bucket
	// inside the same walletdb transaction (see task 102). Returning
	// the same value to the caller keeps create and subsequent reads
	// consistent.
	now := time.Now().UTC()
	scope := o.scopedMgr.Scope()

	err = putAccountCreatedAt(
		o.ns, scope, uint32(accountNumber), now, //nolint:gosec
	)
	if err != nil {
		return db.CreateDerivedAccountRow{}, fmt.Errorf(
			"persist created-at: %w", err,
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

// CreateImportedAccount persists an imported account into waddrmgr as a
// watch-only row. kvdb does not persist an encrypted account private key
// for imported accounts; spendable wallets that supply one get an error.
func (s *Store) CreateImportedAccount(_ context.Context,
	params db.CreateImportedAccountParams) (*db.AccountInfo, error) {

	err := params.ValidateBasic()
	if err != nil {
		return nil, err
	}

	mgr := s.addrStore

	walletIsWatchOnly := mgr.WatchOnly()

	err = params.ValidateWatchOnly(walletIsWatchOnly)
	if err != nil {
		return nil, err
	}

	if len(params.EncryptedPrivateKey) > 0 && !walletIsWatchOnly {
		return nil, errKvdbImportedAccountWithPriv
	}

	pubKey, err := hdkeychain.NewKeyFromString(string(params.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("parse account public key: %w", err)
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

		return nil
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// putImportedAccount runs the kvdb-side persistence steps for a validated
// CreateImportedAccountParams under the caller-owned walletdb.ReadWriteTx.
// The caller is responsible for the surrounding walletdb.Update bracket and
// for surface-level validation (ValidateBasic / ValidateWatchOnly /
// watch-only-with-priv rejection) and for parsing the account public key.
func (s *Store) putImportedAccount(ns walletdb.ReadWriteBucket,
	scope waddrmgr.KeyScope, params db.CreateImportedAccountParams,
	pubKey *hdkeychain.ExtendedKey,
	walletIsWatchOnly bool) (*db.AccountInfo, error) {

	scopedMgr, err := s.scopedManagerOrCreate(ns, scope)
	if err != nil {
		return nil, err
	}

	accountNumber, err := scopedMgr.AllocateImportedAccountNumber(ns)
	if err != nil {
		return nil, fmt.Errorf("allocate account number: %w", err)
	}

	err = scopedMgr.PutWatchOnlyAccountWithKeys(
		ns, accountNumber, params.Name, pubKey,
		params.MasterFingerprint, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("put watch-only account: %w", err)
	}

	// Persist creation timestamp in the kvdb-owned side bucket
	// inside the same walletdb transaction (see task 102). The
	// subsequent loadAccountInfo call reads it back.
	err = putAccountCreatedAt(
		ns, scope, accountNumber, time.Now().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("persist created-at: %w", err)
	}

	walletMasterHDPubKey, err := readMasterHDPubKey(s.addrStore, ns)
	if err != nil {
		return nil, err
	}

	return loadAccountInfo(
		ns, scopedMgr, accountNumber, walletIsWatchOnly,
		walletMasterHDPubKey,
	)
}

// scopedManagerOrCreate returns the scoped key manager for the given scope,
// falling back to creating it on the fly (mirroring the legacy ImportAccount
// flow) when waddrmgr reports ErrScopeNotFound.
func (s *Store) scopedManagerOrCreate(ns walletdb.ReadWriteBucket,
	scope waddrmgr.KeyScope) (waddrmgr.AccountStore, error) {

	scopedMgr, err := s.addrStore.FetchScopedKeyManager(scope)
	if err == nil {
		return scopedMgr, nil
	}

	if !waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound) {
		return nil, translateAccountErr(err, db.ErrAccountNotFound)
	}

	defaultSchema, ok := waddrmgr.ScopeAddrMap[scope]
	if !ok {
		return nil, fmt.Errorf("%w %s", errKvdbNoDefaultSchema, scope)
	}

	scopedMgr, err = s.addrStore.NewScopedKeyManager(
		ns, scope, defaultSchema,
	)
	if err != nil {
		return nil, fmt.Errorf("new scoped key manager: %w", err)
	}

	return scopedMgr, nil
}

// GetAccount returns the account identified by the given query within the
// requested scope.
//
// path-mapping with origin classification; refactor blocked by task 105.
//
//nolint:cyclop // bridges waddrmgr's split account-by-number / account-by-name
func (s *Store) GetAccount(_ context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	mgr := s.addrStore

	scope := waddrmgr.KeyScope{
		Purpose: query.Scope.Purpose,
		Coin:    query.Scope.Coin,
	}

	var info *db.AccountInfo

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return db.ErrAccountNotFound
		}

		scopedMgr, err := mgr.FetchScopedKeyManager(scope)
		if err != nil {
			return translateAccountErr(err, db.ErrAccountNotFound)
		}

		acctNum, err := resolveAccountNumber(ns, scopedMgr, query)
		if err != nil {
			return err
		}

		walletMasterHDPubKey, err := readMasterHDPubKey(mgr, ns)
		if err != nil {
			return err
		}

		built, err := loadAccountInfo(
			ns, scopedMgr, acctNum, mgr.WatchOnly(),
			walletMasterHDPubKey,
		)
		if err != nil {
			return err
		}

		// Strict contract enforcement: imported accounts may only
		// be looked up by Name (the contract masks their
		// AccountNumber to 0, which would otherwise collide with
		// the default derived account). Reject inbound
		// number-based lookups that resolve to imported.
		if query.AccountNumber != nil &&
			built.Origin == db.ImportedAccount {

			return db.ErrAccountNotFound
		}

		if !query.SkipBalance {
			txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

			balances, err := s.fetchAccountBalances(
				ns, txmgrNs, &scope,
			)
			if err != nil {
				return err
			}

			key := accountBalanceKey{
				scope: scope, account: acctNum,
			}
			if pair, ok := balances[key]; ok {
				built.ConfirmedBalance = pair.confirmed
				built.UnconfirmedBalance = pair.unconfirmed
			}
		}

		info = built

		return nil
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// resolveAccountNumber turns a GetAccountQuery into the legacy account
// number, looking up by name when AccountNumber is nil.
func resolveAccountNumber(ns walletdb.ReadBucket,
	scopedMgr waddrmgr.AccountStore,
	query db.GetAccountQuery) (uint32, error) {

	if query.AccountNumber != nil {
		return *query.AccountNumber, nil
	}

	acctNum, err := scopedMgr.LookupAccount(ns, *query.Name)
	if err != nil {
		return 0, translateAccountErr(err, db.ErrAccountNotFound)
	}

	return acctNum, nil
}

// loadAccountInfo materializes a db.AccountInfo from waddrmgr's
// AccountProperties + IsWatchOnlyAccount classifier.
//
// and created-at metadata from independent waddrmgr sources; refactor
// blocked by task 105.
//
//nolint:cyclop // resolves origin, watch-only, fingerprint, key counts,
func loadAccountInfo(ns walletdb.ReadBucket,
	scopedMgr waddrmgr.AccountStore, accountNumber uint32,
	walletWatchOnly bool,
	walletMasterHDPubKey []byte) (*db.AccountInfo, error) {

	props, err := scopedMgr.AccountProperties(ns, accountNumber)
	if err != nil {
		return nil, translateAccountErr(err, db.ErrAccountNotFound)
	}

	accountIsWatchOnly, err := scopedMgr.IsWatchOnlyAccount(
		ns, accountNumber,
	)
	if err != nil {
		return nil, fmt.Errorf("is watch only account: %w", err)
	}

	origin := db.DerivedAccount
	if accountIsWatchOnly {
		origin = db.ImportedAccount
	}

	scope := scopedMgr.Scope()

	var pubKey []byte
	if props.AccountPubKey != nil {
		pubKey = []byte(props.AccountPubKey.String())
	}

	// Resolve the account's CreatedAt from the kvdb-owned side
	// bucket (waddrmgr's account row layout has no creation
	// timestamp; see task 102). Legacy rows that pre-date the shim
	// return time.Time{} which signals "unknown" — the bucket's
	// missing-key signal is the source of truth, not a sentinel
	// numeric value.
	createdAt, err := readAccountCreatedAt(ns, scope, accountNumber)
	if err != nil {
		return nil, fmt.Errorf("read created-at: %w", err)
	}

	// Resolve the BIP32 master-key fingerprint per origin (see
	// ADR 0012). Imported accounts carry their parent xpub
	// fingerprint on the waddrmgr watch-only row, so props is
	// authoritative. Derived accounts have no fingerprint on
	// waddrmgr's default-account row, so re-derive it from the
	// wallet's master HD pubkey via the shared helper. Returning
	// 0 here would silently break PSBT for kvdb wallets, so we
	// wrap and propagate the error instead.
	fingerprint := props.MasterKeyFingerprint
	if origin == db.DerivedAccount {
		if len(walletMasterHDPubKey) == 0 {
			return nil, fmt.Errorf(
				"%w: account %d",
				errMissingWalletMasterHDPubKey,
				accountNumber,
			)
		}

		fingerprint, err = db.MasterKeyFingerprintFromExtKeyBytes(
			walletMasterHDPubKey,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"derive master fingerprint: %w", err,
			)
		}
	}

	// Imported accounts in kvdb internally use waddrmgr's shared
	// per-scope counter for storage, but the AccountInfo contract
	// requires AccountNumber=0 for imported (see data_types.go).
	// Mask here so callers see the same value across backends.
	// Internal callers that need the real waddrmgr number (e.g.
	// attachAccountBalances) must carry it separately.
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
		IsWatchOnly:      walletWatchOnly || accountIsWatchOnly,
		KeyScope: db.KeyScope{
			Purpose: scope.Purpose,
			Coin:    scope.Coin,
		},
		PublicKey:            pubKey,
		MasterKeyFingerprint: fingerprint,
		CreatedAt:            createdAt,
	}, nil
}

// readMasterHDPubKey fetches the wallet's master HD public key bytes,
// translating waddrmgr.ErrNoExist into a nil result so callers can pass
// nil to loadAccountInfo for shell / imported-only wallets that have no
// master HD pubkey persisted. loadAccountInfo treats nil as "no derived
// fingerprint computation possible" and only errors if a derived row is
// actually encountered.
func readMasterHDPubKey(mgr waddrmgr.AddrStore,
	ns walletdb.ReadBucket) ([]byte, error) {

	pubKey, err := mgr.MasterHDPubKey(ns)
	if err == nil {
		return pubKey, nil
	}

	if waddrmgr.IsError(err, waddrmgr.ErrNoExist) {
		return nil, nil
	}

	return nil, fmt.Errorf("read master HD pubkey: %w", err)
}

// errMissingWalletMasterHDPubKey is returned when a derived account
// requires the wallet's master HD pubkey to derive its master-key
// fingerprint but the legacy adapter exposes no pubkey for the wallet.
var errMissingWalletMasterHDPubKey = errors.New(
	"missing wallet master HD pubkey for derived account fingerprint",
)

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

		walletMasterHDPubKey, err := readMasterHDPubKey(mgr, ns)
		if err != nil {
			return err
		}

		walletWatchOnly := mgr.WatchOnly()
		for _, scopedMgr := range scopedMgrs {
			err := collectScopedAccounts(
				ns, scopedMgr, query, walletWatchOnly,
				walletMasterHDPubKey,
				&accounts, &internalNumbers,
			)
			if err != nil {
				return err
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

// collectScopedAccounts walks the accounts under scopedMgr and appends
// matching entries to accounts. The reserved "imported addresses" pseudo-
// account and entries that fail the optional Name filter are skipped.
func collectScopedAccounts(ns walletdb.ReadBucket,
	scopedMgr waddrmgr.AccountStore, query db.ListAccountsQuery,
	walletWatchOnly bool, walletMasterHDPubKey []byte,
	accounts *[]db.AccountInfo,
	internalNumbers *[]uint32) error {

	return scopedMgr.ForEachAccount(ns, func(account uint32) error {
		if account == waddrmgr.ImportedAddrAccount {
			return nil
		}

		info, err := loadAccountInfo(
			ns, scopedMgr, account, walletWatchOnly,
			walletMasterHDPubKey,
		)
		if err != nil {
			return err
		}

		if query.Name != nil && *query.Name != info.AccountName {
			return nil
		}

		*accounts = append(*accounts, *info)
		// Keep the waddrmgr internal account number aligned by
		// index with `accounts`. attachAccountBalances keys
		// balance lookups by the internal number because the
		// AccountInfo contract masks imported numbers to 0
		// (data_types.go), but waddrmgr's balance walker still
		// indexes by the internal number.
		*internalNumbers = append(*internalNumbers, account)

		return nil
	})
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

	unspent, err := s.txStore.UnspentOutputs(txmgrNs)
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

		if account == waddrmgr.ImportedAddrAccount {
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
