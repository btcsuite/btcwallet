package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// Ensure Store satisfies the WalletStore interface.
var _ db.WalletStore = (*Store)(nil)

// CreateWallet creates a new wallet in the database with the provided
// parameters. It returns the created wallet info or an error if the
// creation fails.
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

// createWalletOps adapts PostgreSQL sqlc queries to the shared CreateWallet
// workflow.
type createWalletOps struct {
	q *sqlc.Queries
}

// CreateWallet implements db.CreateWalletOps.
func (o createWalletOps) CreateWallet(ctx context.Context,
	params db.CreateWalletParams) (int64, error) {

	return o.q.CreateWallet(ctx, sqlc.CreateWalletParams{
		WalletName:     params.Name,
		IsImported:     params.IsImported,
		ManagerVersion: params.ManagerVersion,
		IsWatchOnly:    params.IsWatchOnly,
		MasterHdPubKey: params.MasterPubKey,
	})
}

// InsertWalletSecrets implements db.CreateWalletOps.
func (o createWalletOps) InsertWalletSecrets(ctx context.Context,
	walletID int64, params db.CreateWalletParams) error {

	return o.q.InsertWalletSecrets(ctx, sqlc.InsertWalletSecretsParams{
		WalletID: walletID,
		MasterPrivParams: db.NilIfEmptyBytes(
			params.MasterKeyPrivParams,
		),
		EncryptedCryptoPrivKey: db.NilIfEmptyBytes(
			params.EncryptedCryptoPrivKey,
		),
		EncryptedCryptoScriptKey: db.NilIfEmptyBytes(
			params.EncryptedCryptoScriptKey,
		),
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
		SyncedHeight:      sql.NullInt32{},
		BirthdayHeight:    sql.NullInt32{},
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

// GetWallet retrieves information about a wallet given its name. It
// returns a WalletInfo struct containing the wallet's properties or an
// error if the wallet is not found.
func (s *Store) GetWallet(ctx context.Context,
	name string) (*db.WalletInfo, error) {

	var info *db.WalletInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetWalletByName(ctx, name)
		if err == nil {
			info, err = walletRowToInfo(row)
			return err
		}

		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("wallet %q: %w", name, db.ErrWalletNotFound)
		}

		return fmt.Errorf("get wallet: %w", err)
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// ListWallets returns a page of wallets matching the given query.
func (s *Store) ListWallets(ctx context.Context,
	query db.ListWalletsQuery) (page.Result[db.WalletInfo, uint32], error) {

	if query.Page.Limit() == 0 {
		return page.Result[db.WalletInfo, uint32]{}, db.ErrInvalidPageLimit
	}

	var items []db.WalletInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		rows, err := q.ListWallets(ctx, listWalletsParams(query.Page))
		if err != nil {
			return fmt.Errorf("list wallets page: %w", err)
		}

		items = make([]db.WalletInfo, len(rows))
		for i, row := range rows {
			item, errMap := walletRowToInfo(row)
			if errMap != nil {
				return fmt.Errorf("list wallets page: map row: %w", errMap)
			}

			items[i] = *item
		}

		return nil
	})
	if err != nil {
		return page.Result[db.WalletInfo, uint32]{}, err
	}

	result := page.BuildResult(
		query.Page, items,
		func(item db.WalletInfo) uint32 {
			return item.ID
		},
	)

	return result, nil
}

// IterWallets returns an iterator over paginated wallet results.
func (s *Store) IterWallets(ctx context.Context,
	query db.ListWalletsQuery) iter.Seq2[db.WalletInfo, error] {

	return page.Iter(
		ctx, query, s.ListWallets, db.NextListWalletsQuery,
	)
}

// UpdateWallet updates various properties of a wallet, such as its
// birthday, birthday block, or sync state. The specific fields to
// update are provided in the UpdateWalletParams struct. It returns an
// error if the update fails.
func (s *Store) UpdateWallet(ctx context.Context,
	params db.UpdateWalletParams) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		return db.UpdateWalletWithOps(
			ctx, params, updateWalletOps{q: qtx},
		)
	})
}

// updateWalletOps adapts PostgreSQL sqlc queries to the shared UpdateWallet
// workflow.
type updateWalletOps struct {
	q *sqlc.Queries
}

// EnsureBlock implements db.UpdateWalletOps.
func (o updateWalletOps) EnsureBlock(ctx context.Context,
	block *db.Block) error {

	return ensureBlockExists(ctx, o.q, block)
}

// UpdateWalletSyncState implements db.UpdateWalletOps.
func (o updateWalletOps) UpdateWalletSyncState(ctx context.Context,
	params db.UpdateWalletParams) error {

	syncParams, err := buildUpdateSyncParams(params)
	if err != nil {
		return err
	}

	rowsAffected, err := o.q.UpdateWalletSyncState(ctx, syncParams)
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("wallet sync state for wallet %d: %w",
			params.WalletID, db.ErrWalletNotFound)
	}

	return nil
}

// GetEncryptedHDSeed retrieves the encrypted Hierarchical
// Deterministic (HD) seed (the encrypted master HD private key) of
// the wallet. This seed is sensitive information and is returned in
// its encrypted form. It returns the encrypted seed as a byte slice
// or an error if the retrieval fails.
func (s *Store) GetEncryptedHDSeed(ctx context.Context,
	walletID uint32) ([]byte, error) {

	var encrypted []byte

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		secrets, err := q.GetWalletSecrets(ctx, int64(walletID))
		if err == nil {
			if len(secrets.EncryptedMasterHdPrivKey) == 0 {
				return fmt.Errorf("encrypted master privkey for wallet %d: %w",
					walletID, db.ErrSecretNotFound)
			}

			encrypted = secrets.EncryptedMasterHdPrivKey

			return nil
		}

		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("secrets for wallet %d: %w",
				walletID, db.ErrWalletNotFound)
		}

		return fmt.Errorf("get wallet secrets: %w", err)
	})
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// GetWalletSecrets retrieves the encrypted secret material for one wallet.
func (s *Store) GetWalletSecrets(ctx context.Context,
	walletID uint32) (*db.WalletSecrets, error) {

	var secretsInfo *db.WalletSecrets

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		secrets, err := q.GetWalletSecrets(ctx, int64(walletID))
		if err == nil {
			secretsInfo = &db.WalletSecrets{
				MasterPrivParams:         secrets.MasterPrivParams,
				EncryptedCryptoPrivKey:   secrets.EncryptedCryptoPrivKey,
				EncryptedCryptoScriptKey: secrets.EncryptedCryptoScriptKey,
				EncryptedMasterHdPrivKey: secrets.EncryptedMasterHdPrivKey,
			}

			return nil
		}

		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("secrets for wallet %d: %w", walletID,
				db.ErrWalletNotFound)
		}

		return fmt.Errorf("get wallet secrets: %w", err)
	})
	if err != nil {
		return nil, err
	}

	return secretsInfo, nil
}

// UpdateWalletSecrets updates the secrets for the wallet.
func (s *Store) UpdateWalletSecrets(ctx context.Context,
	params db.UpdateWalletSecretsParams) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		return db.UpdateWalletSecretsWithOps(
			ctx, params, updateWalletSecretsOps{q: qtx},
		)
	})
}

// updateWalletSecretsOps adapts PostgreSQL sqlc queries to the shared
// UpdateWalletSecrets workflow.
type updateWalletSecretsOps struct {
	q *sqlc.Queries
}

// WalletWatchOnly implements db.UpdateWalletSecretsOps.
func (o updateWalletSecretsOps) WalletWatchOnly(ctx context.Context,
	walletID uint32) (bool, error) {

	walletRow, err := o.q.GetWalletByID(ctx, int64(walletID))
	if err == nil {
		return walletRow.IsWatchOnly, nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("wallet %d: %w", walletID,
			db.ErrWalletNotFound)
	}

	return false, err
}

// UpdateWalletSecrets implements db.UpdateWalletSecretsOps.
func (o updateWalletSecretsOps) UpdateWalletSecrets(ctx context.Context,
	params db.UpdateWalletSecretsParams) error {

	rowsAffected, err := o.q.UpdateWalletSecrets(
		ctx, sqlc.UpdateWalletSecretsParams{
			MasterPrivParams: db.NilIfEmptyBytes(
				params.MasterPrivParams,
			),
			EncryptedCryptoPrivKey: db.NilIfEmptyBytes(
				params.EncryptedCryptoPrivKey,
			),
			EncryptedCryptoScriptKey: db.NilIfEmptyBytes(
				params.EncryptedCryptoScriptKey,
			),
			EncryptedMasterHdPrivKey: db.NilIfEmptyBytes(
				params.EncryptedMasterHdPrivKey,
			),
			WalletID: int64(params.WalletID),
		},
	)
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("wallet secrets for wallet %d: %w",
			params.WalletID, db.ErrWalletNotFound)
	}

	return nil
}

// walletInfoRow is a type constraint for PostgreSQL wallet info row types
// that share the same field structure. This enables a single generic conversion
// function to handle all wallet query result types.
type walletInfoRow interface {
	sqlc.GetWalletByIDRow | sqlc.GetWalletByNameRow | sqlc.ListWalletsRow
}

// walletRowParams holds the parameters needed to build a WalletInfo
// from a wallet row.
type walletRowParams struct {
	id                     int64
	name                   string
	isImported             bool
	managerVersion         int32
	isWatchOnly            bool
	syncedHeight           sql.NullInt32
	syncedBlockHash        []byte
	syncedBlockTimestamp   sql.NullInt64
	birthdayHeight         sql.NullInt32
	birthdayTimestamp      sql.NullTime
	birthdayBlockHash      []byte
	birthdayBlockTimestamp sql.NullInt64
	masterPubKey           []byte
}

// walletRowToInfo converts a wallet row to WalletInfo, handling type
// conversions across different sqlc row types.
func walletRowToInfo[T walletInfoRow](row T) (*db.WalletInfo, error) {
	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlc.GetWalletByIDRow(row)

	return buildWalletInfo(walletRowParams{
		id:                     base.ID,
		name:                   base.WalletName,
		isImported:             base.IsImported,
		managerVersion:         base.ManagerVersion,
		isWatchOnly:            base.IsWatchOnly,
		syncedHeight:           base.SyncedHeight,
		syncedBlockHash:        base.SyncedBlockHash,
		syncedBlockTimestamp:   base.SyncedBlockTimestamp,
		birthdayHeight:         base.BirthdayHeight,
		birthdayTimestamp:      base.BirthdayTimestamp,
		birthdayBlockHash:      base.BirthdayBlockHash,
		birthdayBlockTimestamp: base.BirthdayBlockTimestamp,
		masterPubKey:           base.MasterHdPubKey,
	})
}

// listWalletsParams translates a page request to ListWallets query
// parameters, handling optional cursor setup for pagination.
func listWalletsParams(
	req page.Request[uint32]) sqlc.ListWalletsParams {

	params := sqlc.ListWalletsParams{
		PageLimit: int64(req.Limit()) + 1,
	}

	if req.After != nil {
		params.CursorID = sql.NullInt64{
			Int64: int64(*req.After),
			Valid: true,
		}
	}

	return params
}

// buildWalletInfo constructs a WalletInfo from the given wallet row
// parameters.
func buildWalletInfo(row walletRowParams) (*db.WalletInfo, error) {
	walletID, err := db.Int64ToUint32(row.id)
	if err != nil {
		return nil, err
	}

	info := &db.WalletInfo{
		ID:             walletID,
		Name:           row.name,
		IsImported:     row.isImported,
		ManagerVersion: row.managerVersion,
		IsWatchOnly:    row.isWatchOnly,
		MasterPubKey:   row.masterPubKey,
	}

	if row.birthdayTimestamp.Valid {
		info.Birthday = row.birthdayTimestamp.Time
	}

	if row.syncedHeight.Valid {
		block, err := buildBlock(
			row.syncedHeight,
			row.syncedBlockHash,
			row.syncedBlockTimestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("synced block: %w", err)
		}

		info.SyncedTo = block
	}

	if row.birthdayHeight.Valid {
		block, err := buildBlock(
			row.birthdayHeight,
			row.birthdayBlockHash,
			row.birthdayBlockTimestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("birthday block: %w", err)
		}

		info.BirthdayBlock = block
	}

	return info, nil
}

// buildUpdateSyncParams constructs the UpdateWalletSyncStateParams from
// the given UpdateWalletParams.
func buildUpdateSyncParams(params db.UpdateWalletParams) (
	sqlc.UpdateWalletSyncStateParams, error) {

	syncParams := sqlc.UpdateWalletSyncStateParams{
		WalletID: int64(params.WalletID),
	}

	if params.SyncedTo != nil {
		syncedHeight, err := db.Uint32ToNullInt32(params.SyncedTo.Height)
		if err != nil {
			return syncParams, err
		}

		syncParams.SyncedHeight = syncedHeight
	}

	if params.Birthday != nil {
		syncParams.BirthdayTimestamp = sql.NullTime{
			Time:  *params.Birthday,
			Valid: true,
		}
	}

	if params.BirthdayBlock != nil {
		birthdayHeight, err := db.Uint32ToNullInt32(
			params.BirthdayBlock.Height,
		)
		if err != nil {
			return syncParams, err
		}

		syncParams.BirthdayHeight = birthdayHeight
	}

	return syncParams, nil
}
