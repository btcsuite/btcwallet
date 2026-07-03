package pg

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// NewImportedAddress imports a new address, script, or private key.
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
	if err != nil {
		return nil, err
	}

	return info, nil
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
