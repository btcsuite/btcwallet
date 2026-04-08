package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"

	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// Ensure SqliteStore satisfies the WalletStore interface.
var _ db.WalletStore = (*SqliteStore)(nil)

// CreateWallet creates a new wallet in the database with the provided
// parameters. It returns the created wallet info or an error if the
// creation fails.
func (s *SqliteStore) CreateWallet(ctx context.Context,
	params db.CreateWalletParams) (*db.WalletInfo, error) {

	var info *db.WalletInfo

	err := s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		walletParams := sqlcsqlite.CreateWalletParams{
			WalletName:              params.Name,
			IsImported:              params.IsImported,
			ManagerVersion:          int64(params.ManagerVersion),
			IsWatchOnly:             params.IsWatchOnly,
			MasterPubParams:         params.MasterKeyPubParams,
			EncryptedCryptoPubKey:   params.EncryptedCryptoPubKey,
			EncryptedMasterHdPubKey: params.EncryptedMasterPubKey,
		}

		id, err := qtx.CreateWallet(ctx, walletParams)
		if err != nil {
			return fmt.Errorf("create wallet: %w", err)
		}

		secretsParams := sqlcsqlite.InsertWalletSecretsParams{
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

		syncParams := sqlcsqlite.InsertWalletSyncStateParams{
			WalletID:          id,
			SyncedHeight:      sql.NullInt64{},
			BirthdayHeight:    sql.NullInt64{},
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

		info, err = buildSqliteWalletInfo(sqliteWalletRowParams{
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
func (s *SqliteStore) GetWallet(ctx context.Context,
	name string) (*db.WalletInfo, error) {

	row, err := s.queries.GetWalletByName(ctx, name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("wallet %q: %w", name,
				db.ErrWalletNotFound)
		}

		return nil, fmt.Errorf("get wallet: %w", err)
	}

	return buildSqliteWalletInfo(sqliteWalletRowParams{
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

// ListWallets returns a page of wallets matching the given query.
func (s *SqliteStore) ListWallets(ctx context.Context,
	query db.ListWalletsQuery) (page.Result[db.WalletInfo, uint32], error) {

	rows, err := s.queries.ListWallets(
		ctx, sqliteListWalletsParams(query.Page),
	)
	if err != nil {
		return page.Result[db.WalletInfo, uint32]{},
			fmt.Errorf("list wallets page: %w", err)
	}

	items := make([]db.WalletInfo, len(rows))
	for i, row := range rows {
		item, errMap := sqliteListWalletRowToInfo(row)
		if errMap != nil {
			return page.Result[db.WalletInfo, uint32]{},
				fmt.Errorf("list wallets page: map row: %w", errMap)
		}

		items[i] = *item
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
func (s *SqliteStore) IterWallets(ctx context.Context,
	query db.ListWalletsQuery) iter.Seq2[db.WalletInfo, error] {

	return page.Iter(
		ctx, query, s.ListWallets, db.NextListWalletsQuery,
	)
}

// UpdateWallet updates various properties of a wallet, such as its
// birthday, birthday block, or sync state. The specific fields to
// update are provided in the UpdateWalletParams struct. It returns an
// error if the update fails.
func (s *SqliteStore) UpdateWallet(ctx context.Context,
	params db.UpdateWalletParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		// Insert blocks if needed.
		if params.SyncedTo != nil {
			err := ensureBlockExistsSqlite(
				ctx, qtx, params.SyncedTo,
			)
			if err != nil {
				return fmt.Errorf("ensure synced block: %w",
					err)
			}
		}

		if params.BirthdayBlock != nil {
			err := ensureBlockExistsSqlite(
				ctx, qtx, params.BirthdayBlock,
			)
			if err != nil {
				return fmt.Errorf("ensure birthday block: %w",
					err)
			}
		}

		syncParams := buildUpdateSyncParamsSqlite(params)

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
func (s *SqliteStore) GetEncryptedHDSeed(ctx context.Context,
	walletID uint32) ([]byte, error) {

	secrets, err := s.queries.GetWalletSecrets(ctx, int64(walletID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("secrets for wallet %d: %w",
				walletID, db.ErrWalletNotFound)
		}

		return nil, fmt.Errorf("get wallet secrets: %w", err)
	}

	if len(secrets.EncryptedMasterHdPrivKey) == 0 {
		return nil, fmt.Errorf(
			"encrypted master privkey for wallet %d: %w", walletID,
			db.ErrSecretNotFound)
	}

	return secrets.EncryptedMasterHdPrivKey, nil
}

// UpdateWalletSecrets updates the secrets for the wallet.
func (s *SqliteStore) UpdateWalletSecrets(ctx context.Context,
	params db.UpdateWalletSecretsParams) error {

	secretsParams := sqlcsqlite.UpdateWalletSecretsParams{
		MasterPrivParams:         params.MasterPrivParams,
		EncryptedCryptoPrivKey:   params.EncryptedCryptoPrivKey,
		EncryptedCryptoScriptKey: params.EncryptedCryptoScriptKey,
		EncryptedMasterHdPrivKey: params.EncryptedMasterHdPrivKey,
		WalletID:                 int64(params.WalletID),
	}

	rowsAffected, err := s.queries.UpdateWalletSecrets(ctx, secretsParams)
	if err != nil {
		return fmt.Errorf("update wallet secrets: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("wallet secrets for wallet %d: %w",
			params.WalletID, db.ErrWalletNotFound)
	}

	return nil
}

// sqliteWalletRowParams holds the parameters needed to build a
// WalletInfo from a wallet row.
type sqliteWalletRowParams struct {
	id                     int64
	name                   string
	isImported             bool
	managerVersion         int64
	isWatchOnly            bool
	syncedHeight           sql.NullInt64
	syncedBlockHash        []byte
	syncedBlockTimestamp   sql.NullInt64
	birthdayHeight         sql.NullInt64
	birthdayTimestamp      sql.NullTime
	birthdayBlockHash      []byte
	birthdayBlockTimestamp sql.NullInt64
}

// sqliteListWalletRowToInfo converts a ListWallets result row to a WalletInfo
// struct for pagination.
func sqliteListWalletRowToInfo(
	row sqlcsqlite.ListWalletsRow) (*db.WalletInfo, error) {

	return buildSqliteWalletInfo(sqliteWalletRowParams{
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

// sqliteListWalletsParams translates a page request to ListWallets query
// parameters, handling optional cursor setup for pagination.
func sqliteListWalletsParams(
	req page.Request[uint32]) sqlcsqlite.ListWalletsParams {

	params := sqlcsqlite.ListWalletsParams{
		PageLimit: int64(req.QueryLimit()),
	}

	if cursor, ok := req.After(); ok {
		params.CursorID = int64(cursor)
	}

	return params
}

// buildSqliteWalletInfo constructs a WalletInfo from the given wallet
// row parameters.
func buildSqliteWalletInfo(row sqliteWalletRowParams) (*db.WalletInfo, error) {
	walletID, err := db.Int64ToUint32(row.id)
	if err != nil {
		return nil, err
	}

	mgrVer, err := db.Int64ToInt32(row.managerVersion)
	if err != nil {
		return nil, err
	}

	info := &db.WalletInfo{
		ID:             walletID,
		Name:           row.name,
		IsImported:     row.isImported,
		ManagerVersion: mgrVer,
		IsWatchOnly:    row.isWatchOnly,
	}

	if row.birthdayTimestamp.Valid {
		info.Birthday = row.birthdayTimestamp.Time
	}

	if row.syncedHeight.Valid {
		block, err := buildSqliteBlock(
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
		block, err := buildSqliteBlock(
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

// buildUpdateSyncParamsSqlite constructs the UpdateWalletSyncStateParams from
// the given UpdateWalletParams.
func buildUpdateSyncParamsSqlite(
	params db.UpdateWalletParams) sqlcsqlite.UpdateWalletSyncStateParams {

	syncParams := sqlcsqlite.UpdateWalletSyncStateParams{
		WalletID: int64(params.WalletID),
	}

	if params.SyncedTo != nil {
		syncParams.SyncedHeight = sql.NullInt64{
			Int64: int64(params.SyncedTo.Height),
			Valid: true,
		}
	}

	if params.Birthday != nil {
		syncParams.BirthdayTimestamp = sql.NullTime{
			Time:  *params.Birthday,
			Valid: true,
		}
	}

	if params.BirthdayBlock != nil {
		syncParams.BirthdayHeight = sql.NullInt64{
			Int64: int64(params.BirthdayBlock.Height),
			Valid: true,
		}
	}

	return syncParams
}
