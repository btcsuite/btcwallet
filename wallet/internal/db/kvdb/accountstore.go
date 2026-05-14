package kvdb

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

// CreateDerivedAccount is not yet implemented for kvdb.
func (s *Store) CreateDerivedAccount(ctx context.Context,
	_ db.CreateDerivedAccountParams,
	_ db.AccountDerivationFunc) (*db.AccountInfo, error) {

	return nil, notImplemented(ctx, "CreateDerivedAccount")
}

// CreateImportedAccount is not yet implemented for kvdb.
func (s *Store) CreateImportedAccount(ctx context.Context,
	_ db.CreateImportedAccountParams) (*db.AccountInfo, error) {

	return nil, notImplemented(ctx, "CreateImportedAccount")
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
	// derived accounts waddrmgr's default-account row stores 0;
	// Wallet.GetAccount and Wallet.assembleAccountsResult fill in
	// the cached master fingerprint after the read.
	fingerprint := props.MasterKeyFingerprint

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

// ListAccounts is not yet implemented for kvdb.
func (s *Store) ListAccounts(ctx context.Context,
	_ db.ListAccountsQuery) ([]db.AccountInfo, error) {

	return nil, notImplemented(ctx, "ListAccounts")
}

// RenameAccount is not yet implemented for kvdb.
func (s *Store) RenameAccount(ctx context.Context,
	_ db.RenameAccountParams) error {

	return notImplemented(ctx, "RenameAccount")
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
	balances map[accountBalanceKey]accountBalancePair) {

	for i := range accounts {
		info := &accounts[i]
		key := accountBalanceKey{
			scope: waddrmgr.KeyScope{
				Purpose: info.KeyScope.Purpose,
				Coin:    info.KeyScope.Coin,
			},
			account: info.AccountNumber,
		}

		pair := balances[key]
		info.ConfirmedBalance = pair.confirmed
		info.UnconfirmedBalance = pair.unconfirmed
	}
}
