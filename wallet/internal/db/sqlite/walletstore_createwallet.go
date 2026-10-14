package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// Ensure Store satisfies the WalletStore interface.
var _ db.WalletStore = (*Store)(nil)

// CreateWallet creates a new wallet in the database with the provided
// parameters. It returns the created wallet info or an error if the
// creation fails. An occupied name returns db.ErrWalletExists without changing
// the existing wallet; other failures retain their original classification.
func (s *Store) CreateWallet(ctx context.Context,
	params db.CreateWalletParams) (*db.WalletInfo, error) {

	err := params.Validate()
	if err != nil {
		return nil, err
	}

	var info *db.WalletInfo

	err = s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		var errCreate error

		info, errCreate = db.CreateWalletWithOps(
			ctx, params, createWalletOps{q: qtx},
		)

		return errCreate
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// createWalletOps adapts SQLite sqlc queries to the shared CreateWallet
// workflow.
type createWalletOps struct {
	q *sqlc.Queries
}

// Ensure createWalletOps implements db.CreateWalletOps at compile time.
var _ db.CreateWalletOps = (*createWalletOps)(nil)

// CreateWallet inserts only a new name and classifies the targeted conflict
// result without mistaking other SQLite uniqueness failures for duplicates.
func (o createWalletOps) CreateWallet(ctx context.Context,
	params db.CreateWalletParams) (int64, error) {

	id, err := o.q.CreateWallet(ctx, sqlc.CreateWalletParams{
		WalletName:     params.Name,
		IsImported:     params.IsImported,
		ManagerVersion: int64(params.ManagerVersion),
		IsWatchOnly:    params.IsWatchOnly,
		MasterHdPubKey: params.MasterPubKey,
	})
	// The query suppresses only wallet-name conflicts, so an empty RETURNING
	// result identifies occupancy without inspecting generic constraint codes.
	if errors.Is(err, sql.ErrNoRows) {
		return 0, db.ErrWalletExists
	}

	return id, err
}

// InsertWalletSecrets implements db.CreateWalletOps.
func (o createWalletOps) InsertWalletSecrets(ctx context.Context,
	walletID int64, params db.CreateWalletParams) error {

	return o.q.InsertWalletSecrets(ctx, sqlc.InsertWalletSecretsParams{
		WalletID:         walletID,
		MasterPrivParams: params.MasterKeyPrivParams,
		EncryptedCryptoPrivKey: db.NilIfEmptyBytes(
			params.EncryptedCryptoPrivKey,
		),
		EncryptedCryptoScriptKey: params.EncryptedCryptoScriptKey,
		EncryptedMasterHdPrivKey: db.NilIfEmptyBytes(
			params.EncryptedMasterPrivKey,
		),
	})
}

// InsertWalletSyncState implements db.CreateWalletOps.
func (o createWalletOps) InsertWalletSyncState(ctx context.Context,
	walletID int64, birthday time.Time) error {

	birthdayTimestamp := sql.NullTime{}
	if !birthday.IsZero() {
		birthdayTimestamp = sql.NullTime{
			Time:  birthday,
			Valid: true,
		}
	}

	return o.q.InsertWalletSyncState(ctx, sqlc.InsertWalletSyncStateParams{
		WalletID:          walletID,
		SyncedHeight:      sql.NullInt64{},
		BirthdayHeight:    sql.NullInt64{},
		BirthdayTimestamp: birthdayTimestamp,
	})
}

// GetWalletByID implements db.CreateWalletOps.
func (o createWalletOps) GetWalletByID(ctx context.Context,
	walletID int64) (*db.WalletInfo, error) {

	row, err := o.q.GetWalletByID(ctx, walletID)
	if err != nil {
		return nil, err
	}

	return walletRowToInfo(row)
}
