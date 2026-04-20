package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"

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

	var info *db.WalletInfo

	err := s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		walletParams := sqlc.CreateWalletParams{
			WalletName:              params.Name,
			IsImported:              params.IsImported,
			ManagerVersion:          params.ManagerVersion,
			IsWatchOnly:             params.IsWatchOnly,
			MasterPubParams:         params.MasterKeyPubParams,
			EncryptedCryptoPubKey:   params.EncryptedCryptoPubKey,
			EncryptedMasterHdPubKey: params.EncryptedMasterPubKey,
		}

		id, err := qtx.CreateWallet(ctx, walletParams)
		if err != nil {
			return fmt.Errorf("create wallet: %w", err)
		}

		secretsParams := sqlc.InsertWalletSecretsParams{
			WalletID:               id,
			MasterPrivParams:       params.MasterKeyPrivParams,
			EncryptedCryptoPrivKey: params.EncryptedCryptoPrivKey,
			EncryptedCryptoScriptKey: params.
				EncryptedCryptoScriptKey,
			EncryptedMasterHdPrivKey: params.EncryptedMasterPrivKey,
		}

		err = qtx.InsertWalletSecrets(ctx, secretsParams)
		if err != nil {
			return fmt.Errorf(
				"insert wallet secrets: %w", err,
			)
		}

		birthdayTimestamp := sql.NullTime{}
		if !params.Birthday.IsZero() {
			birthdayTimestamp = sql.NullTime{
				Time:  params.Birthday,
				Valid: true,
			}
		}

		syncParams := sqlc.InsertWalletSyncStateParams{
			WalletID:          id,
			SyncedHeight:      sql.NullInt32{},
			BirthdayHeight:    sql.NullInt32{},
			BirthdayTimestamp: birthdayTimestamp,
		}

		err = qtx.InsertWalletSyncState(ctx, syncParams)
		if err != nil {
			return fmt.Errorf(
				"upsert wallet sync state: %w", err,
			)
		}

		row, err := qtx.GetWalletByID(ctx, id)
		if err != nil {
			return fmt.Errorf(
				"fetch created wallet: %w", err,
			)
		}

		info, err = buildWalletInfo(walletRowParams{
			id:                     row.ID,
			name:                   row.WalletName,
			isImported:             row.IsImported,
			managerVersion:         row.ManagerVersion,
			isWatchOnly:            row.IsWatchOnly,
			syncedHeight:           row.SyncedHeight,
			syncedBlockHash:        row.SyncedBlockHash,
			syncedBlockTimestamp:   row.SyncedBlockTimestamp,
			birthdayHeight:         row.BirthdayHeight,
			birthdayTimestamp:      row.BirthdayTimestamp,
			birthdayBlockHash:      row.BirthdayBlockHash,
			birthdayBlockTimestamp: row.BirthdayBlockTimestamp,
		})
		if err != nil {
			return fmt.Errorf("convert wallet row to info: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// GetWallet retrieves information about a wallet given its name. It
// returns a WalletInfo struct containing the wallet's properties or an
// error if the wallet is not found.
func (s *Store) GetWallet(ctx context.Context,
	name string) (*db.WalletInfo, error) {

	var info *db.WalletInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetWalletByName(ctx, name)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("wallet %q: %w", name,
					db.ErrWalletNotFound)
			}

			return fmt.Errorf("get wallet: %w", err)
		}

		info, err = buildWalletInfo(walletRowParams{
			id:                     row.ID,
			name:                   row.WalletName,
			isImported:             row.IsImported,
			managerVersion:         row.ManagerVersion,
			isWatchOnly:            row.IsWatchOnly,
			syncedHeight:           row.SyncedHeight,
			syncedBlockHash:        row.SyncedBlockHash,
			syncedBlockTimestamp:   row.SyncedBlockTimestamp,
			birthdayHeight:         row.BirthdayHeight,
			birthdayTimestamp:      row.BirthdayTimestamp,
			birthdayBlockHash:      row.BirthdayBlockHash,
			birthdayBlockTimestamp: row.BirthdayBlockTimestamp,
		})

		return err
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
			item, errMap := listWalletRowToInfo(row)
			if errMap != nil {
				return fmt.Errorf("list wallets page: map row: %w",
					errMap)
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
		// Insert blocks if needed.
		if params.SyncedTo != nil {
			err := ensureBlockExists(ctx, qtx, params.SyncedTo)
			if err != nil {
				return fmt.Errorf("ensure synced block: %w",
					err)
			}
		}

		if params.BirthdayBlock != nil {
			err := ensureBlockExists(
				ctx, qtx, params.BirthdayBlock,
			)
			if err != nil {
				return fmt.Errorf("ensure birthday block: %w",
					err)
			}
		}

		syncParams, err := buildUpdateSyncParams(params)
		if err != nil {
			return err
		}

		rowsAffected, err := qtx.UpdateWalletSyncState(ctx, syncParams)
		if err != nil {
			return fmt.Errorf("update wallet sync state: %w", err)
		}

		if rowsAffected == 0 {
			return fmt.Errorf("wallet sync state for wallet %d: %w",
				params.WalletID, db.ErrWalletNotFound)
		}

		return nil
	})
}

// GetEncryptedHDSeed retrieves the encrypted Hierarchical
// Deterministic (HD) seed of the wallet. This seed is sensitive
// information and is returned in its encrypted form. It returns the
// encrypted seed as a byte slice or an error if the retrieval fails.
func (s *Store) GetEncryptedHDSeed(ctx context.Context,
	walletID uint32) ([]byte, error) {

	var encrypted []byte

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		secrets, err := q.GetWalletSecrets(ctx, int64(walletID))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("secrets for wallet %d: %w",
					walletID, db.ErrWalletNotFound)
			}

			return fmt.Errorf("get wallet secrets: %w", err)
		}

		if len(secrets.EncryptedMasterHdPrivKey) == 0 {
			return fmt.Errorf(
				"encrypted master privkey for wallet %d: %w", walletID,
				db.ErrSecretNotFound)
		}

		encrypted = secrets.EncryptedMasterHdPrivKey

		return nil
	})
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// UpdateWalletSecrets updates the secrets for the wallet.
func (s *Store) UpdateWalletSecrets(ctx context.Context,
	params db.UpdateWalletSecretsParams) error {

	secretsParams := sqlc.UpdateWalletSecretsParams{
		MasterPrivParams:         params.MasterPrivParams,
		EncryptedCryptoPrivKey:   params.EncryptedCryptoPrivKey,
		EncryptedCryptoScriptKey: params.EncryptedCryptoScriptKey,
		EncryptedMasterHdPrivKey: params.EncryptedMasterHdPrivKey,
		WalletID:                 int64(params.WalletID),
	}

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		rowsAffected, err := qtx.UpdateWalletSecrets(ctx, secretsParams)
		if err != nil {
			return fmt.Errorf("update wallet secrets: %w", err)
		}

		if rowsAffected == 0 {
			return fmt.Errorf("wallet secrets for wallet %d: %w",
				params.WalletID, db.ErrWalletNotFound)
		}

		return nil
	})
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
}

// listWalletRowToInfo converts a ListWallets result row to a WalletInfo
// struct for pagination.
func listWalletRowToInfo(row sqlc.ListWalletsRow) (*db.WalletInfo, error) {
	return buildWalletInfo(walletRowParams{
		id:                     row.ID,
		name:                   row.WalletName,
		isImported:             row.IsImported,
		managerVersion:         row.ManagerVersion,
		isWatchOnly:            row.IsWatchOnly,
		syncedHeight:           row.SyncedHeight,
		syncedBlockHash:        row.SyncedBlockHash,
		syncedBlockTimestamp:   row.SyncedBlockTimestamp,
		birthdayHeight:         row.BirthdayHeight,
		birthdayTimestamp:      row.BirthdayTimestamp,
		birthdayBlockHash:      row.BirthdayBlockHash,
		birthdayBlockTimestamp: row.BirthdayBlockTimestamp,
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
