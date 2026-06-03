package kvdb

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcutil"
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
