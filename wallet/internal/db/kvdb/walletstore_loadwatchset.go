package kvdb

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

// LoadWatchSet reads legacy address and output interests in one native view.
// The single-wallet adapter ignores walletID, as its other Wallet reads do.
func (s *Store) LoadWatchSet(ctx context.Context, _ uint32) (db.WatchSet,
	error) {

	// A walletdb view cannot be canceled once entered; reject expired work
	// before opening the transaction.
	err := ctx.Err()
	if err != nil {
		return db.WatchSet{}, err
	}

	var watches db.WatchSet

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		// The native walk preserves legacy default/custom-scope relevance.
		err := s.addrStore.ForEachRelevantActiveAddress(ns,
			func(addr address.Address) error {
				script, err := txscript.PayToAddrScript(addr)
				if err != nil {
					return fmt.Errorf("watch address script: %w", err)
				}

				watches.AddressScripts = append(
					watches.AddressScripts, script,
				)

				return nil
			},
		)
		if err != nil {
			return fmt.Errorf("read watch addresses: %w", err)
		}

		// Read outputs from the same view so the two collections describe
		// one persisted state rather than independently timed reads.
		txns := tx.ReadBucket(wtxmgrNamespaceKey)
		if txns == nil {
			return errMissingTxmgrNamespace
		}

		credits, err := s.txStore.OutputsToWatch(txns)
		if err != nil {
			return fmt.Errorf("read watch outputs: %w", err)
		}

		for _, credit := range credits {
			watches.OutPoints = append(watches.OutPoints, credit.OutPoint)
		}

		return nil
	})
	if err != nil {
		return db.WatchSet{}, fmt.Errorf("load watch set: %w", err)
	}

	return watches, nil
}
