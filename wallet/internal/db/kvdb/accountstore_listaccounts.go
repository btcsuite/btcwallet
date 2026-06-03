package kvdb

import (
	"context"
	"sort"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
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
