package kvdb

import (
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// ResolvedScanTarget carries a legacy rescan target with its durable account
// name when one exists.
type ResolvedScanTarget struct {
	// Scope is the target key scope.
	Scope waddrmgr.KeyScope

	// Account is the legacy account number.
	Account uint32

	// AccountName is the durable account name. It is empty for the keyless
	// imported-address bucket.
	AccountName string
}

// ResolveScanTargets resolves legacy rescan targets into identity-aware scan
// targets using the address manager account names.
func ResolveScanTargets(dbConn walletdb.DB, addrStore waddrmgr.AddrStore,
	targets []waddrmgr.AccountScope) ([]ResolvedScanTarget, error) {

	resolved := make([]ResolvedScanTarget, 0, len(targets))

	err := walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		for _, target := range targets {
			if target.Account == waddrmgr.ImportedAddrAccount {
				resolved = append(resolved, ResolvedScanTarget{
					Scope:   target.Scope,
					Account: target.Account,
				})

				continue
			}

			scopedMgr, err := addrStore.FetchScopedKeyManager(
				target.Scope,
			)
			if err != nil {
				return fmt.Errorf("fetch scoped manager: %w", err)
			}

			name, err := scopedMgr.AccountName(ns, target.Account)
			if err != nil {
				return fmt.Errorf("scan target name: %w", err)
			}

			resolved = append(resolved, ResolvedScanTarget{
				Scope:       target.Scope,
				Account:     target.Account,
				AccountName: name,
			})
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("resolve scan targets: %w", err)
	}

	return resolved, nil
}

// ResolveScanTargets resolves legacy rescan targets into identity-aware scan
// targets using the address manager account names.
func (s *Store) ResolveScanTargets(addrStore waddrmgr.AddrStore,
	targets []waddrmgr.AccountScope) ([]ResolvedScanTarget, error) {

	return ResolveScanTargets(s.db, addrStore, targets)
}
