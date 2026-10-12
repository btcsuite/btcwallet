package pg

import (
	"context"
	"errors"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// NewImportedAddress imports a new address, script, or private key.
// Admitted public/script duplicates return canonical metadata after a definite
// insert rejection; uncertain commits and private-key duplicates are errors.
func (s *Store) NewImportedAddress(ctx context.Context,
	params db.NewImportedAddressParams) (*db.AddressInfo, error) {

	var info *db.AddressInfo

	err := s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		var err error

		info, err = db.NewImportedAddressWithOps(
			ctx, params, newImportedAddressOps{q: qtx},
		)

		return err
	})
	if err == nil {
		return info, nil
	}

	// Uncertainty cannot enter duplicate readback, and private-key imports
	// retain their refusal rather than silently reusing key material.
	if errors.Is(err, db.ErrIndeterminateCommit) ||
		params.HasPrivateKey() ||
		!errors.Is(err, db.ErrAddressAlreadyExists) {

		return nil, err
	}

	// execWrite has rolled back the rejected insert. The unique constraint
	// selects the existing row, preserving its ownership and secrets.
	return s.GetAddress(ctx, db.GetAddressQuery{
		WalletID:     params.WalletID,
		ScriptPubKey: params.ScriptPubKey,
	})
}

// newImportedAddressOps adapts PostgreSQL sqlc queries to the shared
// NewImportedAddress workflow.
type newImportedAddressOps struct {
	q *sqlc.Queries
}

// Verify newImportedAddressOps implements db.NewImportedAddressOps.
var _ db.NewImportedAddressOps = newImportedAddressOps{}

// WalletWatchOnly implements db.NewImportedAddressOps.
func (o newImportedAddressOps) WalletWatchOnly(ctx context.Context,
	walletID uint32) (bool, error) {

	return getWalletWatchOnly(ctx, o.q, walletID)
}

// CreateImportedAddress implements db.NewImportedAddressOps.
func (o newImportedAddressOps) CreateImportedAddress(ctx context.Context,
	params db.NewImportedAddressParams) (db.CreateImportedAddressRow, error) {

	row, err := o.q.CreateImportedAddress(
		ctx, createImportedAddressParams(params),
	)
	if err != nil {
		return db.CreateImportedAddressRow{}, err
	}

	return db.CreateImportedAddressRow{
		ID:        row.ID,
		CreatedAt: row.CreatedAt,
	}, nil
}

// InsertAddressSecret implements db.NewImportedAddressOps.
func (o newImportedAddressOps) InsertAddressSecret(ctx context.Context,
	addressID int64, params db.NewImportedAddressParams) error {

	return o.q.InsertAddressSecret(
		ctx, insertAddressSecretParams(addressID, params),
	)
}

// createImportedAddressParams maps imported params to sqlc params.
func createImportedAddressParams(
	params db.NewImportedAddressParams) sqlc.CreateImportedAddressParams {

	return sqlc.CreateImportedAddressParams{
		WalletID:     int64(params.WalletID),
		ScriptPubKey: params.ScriptPubKey,
		ScriptTypeID: int16(params.AddressType),
		PubKey:       params.PubKey,
	}
}

// insertAddressSecretParams maps imported params to secret params.
func insertAddressSecretParams(addressID int64,
	params db.NewImportedAddressParams) sqlc.InsertAddressSecretParams {

	return sqlc.InsertAddressSecretParams{
		AddressID: addressID,
		EncryptedPrivKey: db.NilIfEmptyBytes(
			params.EncryptedPrivateKey,
		),
		EncryptedScript: db.NilIfEmptyBytes(
			params.EncryptedScript,
		),
	}
}
