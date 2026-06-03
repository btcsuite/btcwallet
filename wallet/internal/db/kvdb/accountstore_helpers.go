package kvdb

import (
	"errors"
	"fmt"

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
