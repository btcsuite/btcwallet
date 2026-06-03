package kvdb

import (
	"context"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

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
