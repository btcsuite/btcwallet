package kvdb

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

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

// GetTx is not yet implemented for kvdb.
func (s *Store) GetTx(ctx context.Context,
	_ db.GetTxQuery) (*db.TxInfo, error) {

	return nil, notImplemented(ctx, "GetTx")
}

// ListTxns is not yet implemented for kvdb.
func (s *Store) ListTxns(ctx context.Context,
	_ db.ListTxnsQuery) ([]db.TxInfo, error) {

	return nil, notImplemented(ctx, "ListTxns")
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
