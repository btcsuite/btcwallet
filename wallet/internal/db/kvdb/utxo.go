// Package kvdb provides a walletdb (kvdb) backed implementation of the
// wallet/internal/db UTXO store interface.
package kvdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// errNotImplemented is returned for unimplemented kvdb store methods.
	errNotImplemented = errors.New("not implemented")

	// errMissingTxmgrNamespace is returned when the `wtxmgr` namespace bucket
	// cannot be found in a walletdb transaction.
	errMissingTxmgrNamespace = errors.New("missing wtxmgr namespace")

	// wtxmgrNamespaceKey is the walletdb top-level bucket key used by the
	// transaction manager.
	//
	// NOTE: This must match the namespace used by the wallet package.
	wtxmgrNamespaceKey = []byte("wtxmgr")
)

func notImplemented(_ context.Context, method string) error {
	return fmt.Errorf("kvdb.Store.%s: %w", method, errNotImplemented)
}

// GetUtxo is not yet implemented for kvdb.
func (s *Store) GetUtxo(ctx context.Context,
	_ db.GetUtxoQuery) (*db.UtxoInfo, error) {

	return nil, notImplemented(ctx, "GetUtxo")
}

// ListUTXOs is not yet implemented for kvdb.
func (s *Store) ListUTXOs(ctx context.Context,
	_ db.ListUtxosQuery) ([]db.UtxoInfo, error) {

	return nil, notImplemented(ctx, "ListUTXOs")
}

// LeaseOutput is not yet implemented for kvdb.
func (s *Store) LeaseOutput(ctx context.Context,
	_ db.LeaseOutputParams) (*db.LeasedOutput, error) {

	return nil, notImplemented(ctx, "LeaseOutput")
}

// ReleaseOutput releases a previously leased output.
//
// How it works:
// The method executes a single walletdb update transaction that deletes the
// lock record associated with the specified outpoint.
//
// Database Actions:
//   - Performs exactly one write transaction (walletdb.Update).
//   - Writes to the `wtxmgr` namespace.
//
// NOTE: The legacy kvdb backend only supports a single wallet instance, so the
// WalletID field is ignored.
func (s *Store) ReleaseOutput(_ context.Context,
	params db.ReleaseOutputParams) error {

	lockID := wtxmgr.LockID(params.ID)
	op := params.OutPoint

	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return errMissingTxmgrNamespace
		}

		err := s.txStore.UnlockOutput(ns, lockID, op)
		if err != nil {
			return fmt.Errorf("unlock output: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.ReleaseOutput: %w", err)
	}

	return nil
}

// ListLeasedOutputs is not yet implemented for kvdb.
func (s *Store) ListLeasedOutputs(ctx context.Context,
	_ uint32) ([]db.LeasedOutput, error) {

	return nil, notImplemented(ctx, "ListLeasedOutputs")
}

// Balance is not yet implemented for kvdb.
func (s *Store) Balance(ctx context.Context,
	_ db.BalanceParams) (btcutil.Amount, error) {

	return 0, notImplemented(ctx, "Balance")
}
