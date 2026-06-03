package kvdb

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

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

// effectiveAddrSchema resolves the per-account schema from the legacy
// waddrmgr override when present, otherwise falls back to the
// scope-level persisted schema the scoped manager reports. The
// persisted schema covers custom (non-default) scopes that
// db.ScopeAddrMap does not enumerate, so derived accounts under a
// custom scope still get the correct address types instead of
// failing with ErrUnknownKeyScope or silently picking the default
// BIP49-plus shape.
func effectiveAddrSchema(scopeSchema waddrmgr.ScopeAddrSchema,
	override *waddrmgr.ScopeAddrSchema) (db.ScopeAddrSchema, error) {

	source := scopeSchema
	if override != nil {
		source = *override
	}

	schema, err := db.ScopeAddrSchemaFromWaddrmgr(source)
	if err != nil {
		return db.ScopeAddrSchema{}, fmt.Errorf("convert "+
			"scope schema: %w", err)
	}

	return schema, nil
}

// resolveMasterFingerprintForAccount returns the master-key fingerprint
// for the account at props.AccountNumber. For imported accounts the value
// lives on the waddrmgr watch-only row in props.MasterKeyFingerprint. For
// derived accounts waddrmgr's default-account row has no fingerprint
// column, so kvdb stores it in a side bucket; legacy derived rows have
// no side-bucket entry and the wallet layer fills in the cached value
// at the public boundary.
func resolveMasterFingerprintForAccount(ns walletdb.ReadBucket,
	scope waddrmgr.KeyScope,
	props *waddrmgr.AccountProperties) (uint32, error) {

	persisted, ok, err := getAccountMasterFingerprint(
		ns, scope, props.AccountNumber,
	)
	if err != nil {
		return 0, fmt.Errorf("read master fingerprint: %w", err)
	}

	if ok {
		return persisted, nil
	}

	return props.MasterKeyFingerprint, nil
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

	fingerprint, err := resolveMasterFingerprintForAccount(
		ns, scope, props,
	)
	if err != nil {
		return nil, err
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

	addrSchema, err := effectiveAddrSchema(
		scopedMgr.AddrSchema(), props.AddrSchema,
	)
	if err != nil {
		return nil, err
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
		AddrSchema:           addrSchema,
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
