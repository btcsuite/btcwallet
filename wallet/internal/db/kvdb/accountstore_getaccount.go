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
func (s *Store) GetAccount(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	scope := waddrmgr.KeyScope{
		Purpose: query.Scope.Purpose,
		Coin:    query.Scope.Coin,
	}

	var info *db.AccountInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ops := accountGetOps{
			store: s,
			tx:    tx,
			scope: scope,
		}

		built, err := db.GetAccountWithOps(ctx, query, &ops)
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

// accountGetOps adapts waddrmgr-backed kvdb reads to the shared GetAccount
// workflow. The same walletdb read tx covers account loading and optional
// balance attachment.
type accountGetOps struct {
	store *Store
	tx    walletdb.ReadTx
	scope waddrmgr.KeyScope

	ns walletdb.ReadBucket

	// internalAccountNumber caches the resolved waddrmgr account number from
	// loadAccountByNumber so AttachAccountBalance can use it for balance
	// lookups. Imported accounts expose no public AccountNumber, but kvdb
	// balance rows still key by the original waddrmgr number.
	internalAccountNumber uint32
}

// Verify accountGetOps implements GetAccountOps.
var _ db.GetAccountOps = (*accountGetOps)(nil)

// GetAccountByNumber implements db.GetAccountOps.
func (o *accountGetOps) GetAccountByNumber(_ context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	acctNum, err := sanitizeAccountNumber(*query.AccountNumber)
	if err != nil {
		return nil, err
	}

	return o.loadAccountByNumber(acctNum)
}

// GetAccountByName implements db.GetAccountOps.
func (o *accountGetOps) GetAccountByName(_ context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	ns, scopedMgr, err := o.resolveAccountNamespaceAndManager()
	if err != nil {
		return nil, err
	}

	acctNum, err := scopedMgr.LookupAccount(ns, *query.Name)
	if err != nil {
		return nil, translateAccountErr(err, db.ErrAccountNotFound)
	}

	return o.loadAccountByNumber(acctNum)
}

// AttachAccountBalance implements db.GetAccountOps.
func (o *accountGetOps) AttachAccountBalance(_ context.Context,
	_ db.GetAccountQuery, _ int64, built *db.AccountInfo) (*db.AccountInfo,
	error) {

	if o.ns == nil {
		return nil, db.ErrAccountNotFound
	}

	txmgrNs := o.tx.ReadBucket(wtxmgrNamespaceKey)

	balances, err := o.store.fetchAccountBalances(o.ns, txmgrNs, &o.scope)
	if err != nil {
		return nil, err
	}

	key := accountBalanceKey{
		scope:   o.scope,
		account: o.internalAccountNumber,
	}
	if pair, ok := balances[key]; ok {
		built.ConfirmedBalance = pair.confirmed
		built.UnconfirmedBalance = pair.unconfirmed
	}

	return built, nil
}

// loadAccountByNumber retrieves an account by already-resolved internal
// waddrmgr account number.
func (o *accountGetOps) loadAccountByNumber(
	accountNumber uint32) (*db.AccountInfo, error) {

	ns, scopedMgr, err := o.resolveAccountNamespaceAndManager()
	if err != nil {
		return nil, err
	}

	info, err := loadAccountInfo(
		ns, scopedMgr, accountNumber, o.store.addrStore.WatchOnly(),
	)
	if err != nil {
		return nil, err
	}

	o.ns = ns
	o.internalAccountNumber = accountNumber

	return info, nil
}

// resolveAccountNamespaceAndManager loads the account namespace bucket and
// scoped key manager for account reads.
func (o *accountGetOps) resolveAccountNamespaceAndManager() (
	walletdb.ReadBucket, waddrmgr.AccountStore, error) {

	ns := o.tx.ReadBucket(waddrmgr.NamespaceKey)
	if ns == nil {
		return nil, nil, db.ErrAccountNotFound
	}

	scopedMgr, err := o.store.addrStore.FetchScopedKeyManager(o.scope)
	if err != nil {
		return nil, nil, translateAccountErr(err, db.ErrAccountNotFound)
	}

	return ns, scopedMgr, nil
}

// sanitizeAccountNumber rejects legacy pseudo-account slots for number-based
// lookups. The legacy imported-address pseudo-account is still queryable by
// name, but it has no public account number.
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

	var accountNumberForContract *uint32
	if !accountIsImported {
		accountNumberForContract = &props.AccountNumber
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
		IsImported:       accountIsImported,
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
