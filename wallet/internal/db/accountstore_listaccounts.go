package db

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2"
)

// Validate checks that at most one optional account-list filter was set.
func (query ListAccountsQuery) Validate() error {
	if query.Scope != nil && query.Name != nil {
		return ErrInvalidAccountQuery
	}

	return nil
}

// ListAccountsFunc defines the selector callback shape used by legacy backend
// adapters while the shared list-accounts workflow is being introduced.
type ListAccountsFunc func(context.Context, ListAccountsQuery) ([]AccountInfo,
	error)

// ListAccountsByQuery validates query and dispatches to the matching list
// selector.
//
// This compatibility helper keeps the workflow commit buildable against the
// pre-ops backend adapters; the follow-up adapter commit switches those
// backends to ListAccountsWithOps directly.
func ListAccountsByQuery(ctx context.Context, query ListAccountsQuery,
	listByScope ListAccountsFunc, listByName ListAccountsFunc,
	listAll ListAccountsFunc) ([]AccountInfo, error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	switch {
	case query.Scope != nil:
		return listByScope(ctx, query)

	case query.Name != nil:
		return listByName(ctx, query)

	default:
		return listAll(ctx, query)
	}
}

// ListAccountsOps is the backend adapter the shared ListAccounts workflow uses.
//
// The shared account-list algorithm is intentionally ordered:
//   - validate the public query before any backend step runs
//   - choose exactly one list branch from the optional filters
//   - load matching accounts using backend-local query and row conversion
//   - attach account balances unless the query opted out
//
// The adapter methods map directly to those stages so the shared helper keeps
// sequencing and filter dispatch while each backend keeps sqlc query types,
// kvdb manager walks, ordering, row conversions, and balance-query shapes
// local. SQL-derived infos carry rowID for balance pairing; kvdb-internal
// identities stay adapter-local and are not exposed to the shared contract.
type ListAccountsOps interface {
	// ListByScope lists accounts for query.WalletID filtered by query.Scope.
	// Returns a slice of AccountInfo values with rowID populated for SQL
	// balance pairing or equivalent adapter-local state for kvdb.
	ListByScope(ctx context.Context,
		query ListAccountsQuery) ([]AccountInfo, error)

	// ListByName lists accounts for query.WalletID filtered by query.Name.
	// Returns a slice of AccountInfo values with rowID populated for SQL
	// balance pairing or equivalent adapter-local state for kvdb.
	ListByName(ctx context.Context,
		query ListAccountsQuery) ([]AccountInfo, error)

	// ListAll lists all accounts for query.WalletID.
	// Returns a slice of AccountInfo values with rowID populated for SQL
	// balance pairing or equivalent adapter-local state for kvdb.
	ListAll(ctx context.Context, query ListAccountsQuery) ([]AccountInfo,
		error)

	// AttachAccountBalances fills balance fields on accounts after the workflow
	// has already decided balance attachment is required. Modifies accounts
	// in-place to attach balances.
	AttachAccountBalances(ctx context.Context, walletID uint32,
		infos []AccountInfo) ([]AccountInfo, error)
}

// ListAccountsWithOps runs the backend-independent account-list workflow once
// the caller has opened a backend-specific read transaction.
//
// The helper owns the ordered sequencing so postgres, sqlite, and kvdb all
// validate before any backend step, dispatch exactly one filter branch,
// preserve backend-local ordering and row conversion, and attach balances only
// after the matching account list has been loaded.
func ListAccountsWithOps(ctx context.Context, query ListAccountsQuery,
	ops ListAccountsOps) ([]AccountInfo, error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	var infos []AccountInfo
	switch {
	case query.Scope != nil:
		infos, err = ops.ListByScope(ctx, query)

	case query.Name != nil:
		infos, err = ops.ListByName(ctx, query)

	default:
		infos, err = ops.ListAll(ctx, query)
	}

	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	if query.SkipBalance {
		return infos, nil
	}

	accounts, err := ops.AttachAccountBalances(ctx, query.WalletID, infos)
	if err != nil {
		return nil, fmt.Errorf("attach account balances: %w", err)
	}

	return accounts, nil
}

// ProcessAccountRows converts a batch of dialect-specific account rows into
// AccountInfo values (ordered as input). The convert closure produces both
// the AccountInfo and the SQL row ID for each row; ProcessAccountRows stores
// the row ID on each returned AccountInfo via the unexported rowID field so
// AttachAccountBalances can pair per-account balance rows back to their
// AccountInfo without threading a parallel ids slice.
func ProcessAccountRows[T any](rows []T,
	convert func(T) (*AccountInfo, int64, error)) ([]AccountInfo, error) {

	infos := make([]AccountInfo, len(rows))
	for i := range rows {
		info, id, err := convert(rows[i])
		if err != nil {
			return nil, err
		}

		infos[i] = *info
		infos[i].rowID = id
	}

	return infos, nil
}

// AccountBalance is the dialect-agnostic shape of a per-account balance row.
// Backends translate their sqlc balance rows into AccountBalance values when
// calling AttachAccountBalances; the wire-level AccountBalancesByIDs query
// lives in each backend, and AccountBalance is the common contract its results
// land in for the shared merge logic.
type AccountBalance struct {
	// AccountID is the SQL row ID of the account this balance belongs to;
	// it matches the rowID populated on AccountInfo by ProcessAccountRows.
	AccountID int64

	// Confirmed is the sum of UTXO amounts (in satoshis) that are
	// considered confirmed by the wallet's confirmation policy.
	Confirmed int64

	// Unconfirmed is the sum of UTXO amounts (in satoshis) that are
	// unconfirmed.
	Unconfirmed int64
}

// AttachAccountBalances merges per-account balances into a batch of AccountInfo
// values. The queryBalances callback executes the backend-specific
// AccountBalancesByIDs and returns its results as []AccountBalance. The
// merge step uses each AccountInfo's rowID (populated by ProcessAccountRows)
// to map balance rows back to their AccountInfo in a single pass. The
// returned slice preserves the input order of infos.
//
// When infos is empty, the query dispatch is skipped and every returned
// AccountInfo keeps zero balance fields. The query callback is invoked at most
// once per AttachAccountBalances call.
func AttachAccountBalances(ctx context.Context, walletID uint32,
	infos []AccountInfo,
	queryBalances func(ctx context.Context, walletID uint32,
		ids []int64) ([]AccountBalance, error)) ([]AccountInfo, error) {

	out := infos

	if len(infos) == 0 {
		return out, nil
	}

	indexByID := make(map[int64]int, len(infos))
	ids := make([]int64, len(infos))

	for i := range infos {
		indexByID[infos[i].rowID] = i
		ids[i] = infos[i].rowID
	}

	balances, err := queryBalances(ctx, walletID, ids)
	if err != nil {
		return nil, fmt.Errorf("account balances: %w", err)
	}

	for _, bal := range balances {
		idx, ok := indexByID[bal.AccountID]
		if !ok {
			continue
		}

		out[idx].ConfirmedBalance = btcutil.Amount(bal.Confirmed)
		out[idx].UnconfirmedBalance = btcutil.Amount(bal.Unconfirmed)
	}

	return out, nil
}
