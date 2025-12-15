package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// Ensure SQLiteWalletDB satisfies the WalletStore interface.
var _ WalletStore = (*SQLiteWalletDB)(nil)

// CreateWallet creates a new wallet in the database with the provided
// parameters. It returns the created wallet info or an error if the
// creation fails.
func (w *SQLiteWalletDB) CreateWallet(ctx context.Context,
	params CreateWalletParams) (*WalletInfo, error) {

	var info *WalletInfo

	err := w.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
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
func (w *SQLiteWalletDB) GetWallet(ctx context.Context,
	name string) (*WalletInfo, error) {

	row, err := w.queries.GetWalletByName(ctx, name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("wallet %q: %w", name,
				ErrWalletNotFound)
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

// ListWallets returns a slice of WalletInfo for all wallets stored in
// the database. It returns an empty slice if no wallets are found, or
// an error if the retrieval fails.
func (w *SQLiteWalletDB) ListWallets(ctx context.Context) ([]WalletInfo,
	error) {

	rows, err := w.queries.ListWallets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list wallets: %w", err)
	}

	wallets := make([]WalletInfo, len(rows))
	for i, row := range rows {
		info, err := buildSqliteWalletInfo(sqliteWalletRowParams{
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
			return nil, err
		}

		wallets[i] = *info
	}

	return wallets, nil
}

// UpdateWallet updates various properties of a wallet, such as its
// birthday, birthday block, or sync state. The specific fields to
// update are provided in the UpdateWalletParams struct. It returns an
// error if the update fails.
func (w *SQLiteWalletDB) UpdateWallet(ctx context.Context,
	params UpdateWalletParams) error {

	return w.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		// Build sync state update params directly from input.
		// Only set fields that are being updated (leave others as nil).
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

		rowsAffected, err := qtx.UpdateWalletSyncState(ctx, syncParams)
		if err != nil {
			return fmt.Errorf("update wallet sync state: %w", err)
		}

		if rowsAffected == 0 {
			return fmt.Errorf("wallet sync state for wallet %d: %w",
				params.WalletID, ErrWalletNotFound)
		}

		return nil
	})
}

// GetEncryptedHDSeed retrieves the encrypted Hierarchical
// Deterministic (HD) seed of the wallet. This seed is sensitive
// information and is returned in its encrypted form. It returns the
// encrypted seed as a byte slice or an error if the retrieval fails.
func (w *SQLiteWalletDB) GetEncryptedHDSeed(ctx context.Context,
	walletID uint32) ([]byte, error) {

	secrets, err := w.queries.GetWalletSecrets(ctx, int64(walletID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("secrets for wallet %d: %w",
				walletID, ErrWalletNotFound)
		}

		return nil, fmt.Errorf("get wallet secrets: %w", err)
	}

	if len(secrets.EncryptedMasterHdPrivKey) == 0 {
		return nil, fmt.Errorf(
			"encrypted master privkey for wallet %d: %w", walletID,
			ErrSecretNotFound)
	}

	return secrets.EncryptedMasterHdPrivKey, nil
}

// UpdateWalletSecrets updates the secrets for the wallet.
func (w *SQLiteWalletDB) UpdateWalletSecrets(ctx context.Context,
	params UpdateWalletSecretsParams) error {

	secretsParams := sqlcsqlite.UpdateWalletSecretsParams{
		MasterPrivParams:         params.MasterPrivParams,
		EncryptedCryptoPrivKey:   params.EncryptedCryptoPrivKey,
		EncryptedCryptoScriptKey: params.EncryptedCryptoScriptKey,
		EncryptedMasterHdPrivKey: params.EncryptedMasterHdPrivKey,
		WalletID:                 int64(params.WalletID),
	}

	rowsAffected, err := w.queries.UpdateWalletSecrets(ctx, secretsParams)
	if err != nil {
		return fmt.Errorf("update wallet secrets: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("wallet secrets for wallet %d: %w",
			params.WalletID, ErrWalletNotFound)
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

// buildSqliteWalletInfo constructs a WalletInfo from the given wallet
// row parameters.
func buildSqliteWalletInfo(row sqliteWalletRowParams) (*WalletInfo, error) {
	walletID, err := int64ToUint32(row.id)
	if err != nil {
		return nil, err
	}

	mgrVer, err := int64ToInt32(row.managerVersion)
	if err != nil {
		return nil, err
	}

	info := &WalletInfo{
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
