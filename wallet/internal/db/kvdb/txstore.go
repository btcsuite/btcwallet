package kvdb

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// errLegacyHeightOverflow reports that one db height cannot fit into the
// signed legacy wtxmgr height domain.
var errLegacyHeightOverflow = errors.New("legacy height overflows int32")

// CreateTx is not yet implemented for kvdb.
func (s *Store) CreateTx(ctx context.Context, _ db.CreateTxParams) error {
	return notImplemented(ctx, "CreateTx")
}

// UpdateTx re-implements the legacy kvdb label update path through the
// transitional Store interface.
//
// This preserves the existing kvdb behavior: only label-only updates are
// supported here, and label validation remains owned by wtxmgr.PutTxLabel.
//
// NOTE: The legacy kvdb backend only supports a single wallet instance, so the
// WalletID field is ignored.
func (s *Store) UpdateTx(_ context.Context, params db.UpdateTxParams) error {
	label, err := validateUpdateTxParams(params)
	if err != nil {
		return err
	}

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return errMissingTxmgrNamespace
		}

		details, err := s.txStore.TxDetails(ns, &params.Txid)
		if err != nil {
			return fmt.Errorf("lookup transaction details: %w", err)
		}

		if details == nil {
			return db.ErrTxNotFound
		}

		err = s.txStore.PutTxLabel(ns, params.Txid, *label)
		if err != nil {
			return fmt.Errorf("put transaction label: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.UpdateTx: %w", err)
	}

	return nil
}

// GetTx retrieves one wallet-scoped transaction snapshot through the legacy
// wtxmgr query path.
func (s *Store) GetTx(_ context.Context, query db.GetTxQuery) (
	*db.TxInfo, error) {

	var info *db.TxInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return errMissingTxmgrNamespace
		}

		details, err := s.txStore.TxDetails(ns, &query.Txid)
		if err != nil {
			return fmt.Errorf("lookup transaction details: %w", err)
		}

		if details == nil {
			return db.ErrTxNotFound
		}

		info = kvdbTxInfo(details)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetTx: %w", err)
	}

	return info, nil
}

// ListTxns lists wallet-scoped transaction summaries through the legacy wtxmgr
// range query path.
func (s *Store) ListTxns(_ context.Context, query db.ListTxnsQuery) (
	[]db.TxInfo, error) {

	var infos []db.TxInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return errMissingTxmgrNamespace
		}

		if query.UnminedOnly {
			var err error

			infos, err = s.listTxnsRange(ns, -1, -1, nil)

			return err
		}

		begin, end, err := kvdbConfirmedTxnsRange(query)
		if err != nil {
			return err
		}

		infos, err = s.listTxnsRange(ns, begin, end, nil)

		return err
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.ListTxns: %w", err)
	}

	if len(infos) == 0 {
		return []db.TxInfo{}, nil
	}

	return infos, nil
}

// listTxnsRange appends one legacy wtxmgr range scan to the result set.
func (s *Store) listTxnsRange(ns walletdb.ReadBucket, begin, end int32,
	infos []db.TxInfo) ([]db.TxInfo, error) {

	err := s.txStore.RangeTransactions(
		ns, begin, end,
		func(txDetails []wtxmgr.TxDetails) (bool, error) {
			for i := range txDetails {
				infos = append(infos, *kvdbTxInfo(&txDetails[i]))
			}

			return false, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("range txns %d to %d: %w", begin, end, err)
	}

	return infos, nil
}

// DeleteTx is not yet implemented for kvdb.
func (s *Store) DeleteTx(ctx context.Context, _ db.DeleteTxParams) error {
	return notImplemented(ctx, "DeleteTx")
}

// InvalidateUnminedTx is not yet implemented for kvdb.
func (s *Store) InvalidateUnminedTx(ctx context.Context,
	_ db.InvalidateUnminedTxParams) error {

	return notImplemented(ctx, "InvalidateUnminedTx")
}

// RollbackToBlock is not yet implemented for kvdb.
func (s *Store) RollbackToBlock(ctx context.Context, _ uint32) error {
	return notImplemented(ctx, "RollbackToBlock")
}

// validateUpdateTxParams checks whether one UpdateTx request matches the legacy
// kvdb label-only behavior preserved by this adapter.
func validateUpdateTxParams(params db.UpdateTxParams) (*string, error) {
	if params.Label == nil && params.State == nil {
		return nil, fmt.Errorf("kvdb.Store.UpdateTx: %w: UpdateTx requires at "+
			"least one field", db.ErrInvalidParam)
	}

	if params.State != nil {
		return nil, fmt.Errorf("kvdb.Store.UpdateTx: state patch: %w",
			errNotImplemented)
	}

	if params.Label == nil {
		return nil, fmt.Errorf("kvdb.Store.UpdateTx: label patch required: %w",
			db.ErrInvalidParam)
	}

	return params.Label, nil
}

// kvdbTxInfo maps legacy wtxmgr detail data into the lightweight db-native
// transaction summary model.
func kvdbTxInfo(details *wtxmgr.TxDetails) *db.TxInfo {
	var block *db.Block
	if details.Block.Height >= 0 {
		block = &db.Block{
			Hash:      details.Block.Hash,
			Height:    nonNegativeInt32ToUint32(details.Block.Height),
			Timestamp: details.Block.Time,
		}
	}

	return &db.TxInfo{
		Hash:         details.Hash,
		SerializedTx: append([]byte(nil), details.SerializedTx...),
		Received:     details.Received.UTC(),
		Block:        block,

		// Legacy wtxmgr only exposes transactions it still treats as valid,
		// and it does not persist pending/replaced/failed/orphaned state.
		Status: db.TxStatusPublished,
		Label:  details.Label,
	}
}

// kvdbConfirmedTxnsRange converts the confirmed query heights into the legacy
// wtxmgr range arguments used by the kvdb adapter.
func kvdbConfirmedTxnsRange(query db.ListTxnsQuery) (int32, int32, error) {
	startHeight, err := uint32ToLegacyHeight(query.StartHeight)
	if err != nil {
		return 0, 0, fmt.Errorf("convert start height: %w", err)
	}

	endHeight, err := uint32ToLegacyHeight(query.EndHeight)
	if err != nil {
		return 0, 0, fmt.Errorf("convert end height: %w", err)
	}

	return startHeight, endHeight, nil
}

// uint32ToLegacyHeight converts a db height into the signed height domain used
// by the legacy wtxmgr range API.
func uint32ToLegacyHeight(height uint32) (int32, error) {
	if height > math.MaxInt32 {
		return 0, fmt.Errorf("%w: %d", errLegacyHeightOverflow, height)
	}

	return int32(height), nil
}

// nonNegativeInt32ToUint32 converts a non-negative int32 to uint32.
func nonNegativeInt32ToUint32(value int32) uint32 {
	if value < 0 {
		return 0
	}

	return uint32(value)
}
